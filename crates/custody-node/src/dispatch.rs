//! The custody decision pipeline — pure, transport-independent.
//!
//! Given a prepared-spend lookup key + the prepare store + the replay store,
//! decide APPROVE/REJECT for a pending custody signature. The Turnkey
//! approver-watcher ([`crate::bin`]) is a thin shell over this: it observes a
//! `CONSENSUS_NEEDED` signing activity, supplies the activity's signing
//! `payload` (the sighash hex) as the lookup key, then maps the [`Decision`]
//! to `approveActivity` / `rejectActivity`. Everything security-relevant is
//! here and unit-tested without a network.
//!
//! Fail-safe by construction — APPROVE requires ALL of: a prepare-context
//! exists for the key (which only the executor creates when it submits the
//! spend), and the family decision core passes the k-of-n RIC bind. Any miss →
//! fail-closed REJECT.

use bitcoin::ScriptBuf;
use xindex_custody_core::gates::CustodyConfig;
use xindex_custody_core::replay::ReplayStore;

use crate::account::{decide_account_send, AccountSend};
use crate::btc::decide_redeem_spend;
use crate::evm::{decide_evm_deposit, EvmDeposit};
use crate::Decision;
use xindex_custody_core::prepare::{PrepareStore, PreparedSpend};

/// Decide a pending custody signature. Looks up the prepared spend by
/// `prepare_key` (the executor keys `prepare.put` by the signing-payload
/// sighash hex), runs the family decision core, maps to APPROVE/REJECT.
///
/// `btc_custody_spk` is this approver's own custody `scriptPubKey` (for the
/// BTC output bind); `None` rejects any BTC spend.
///
/// **SECURITY (dev-env reconciliation):** the prepared spend is bound to the
/// k-of-n RIC (destination / amount / memo) by the family core. The
/// approver-watcher correlates the activity to the prepared spend by the
/// signing `payload` itself (the sighash), so a coordinator cannot pair
/// prepared-context X with a signature over a different message Y under the
/// same key. Re-deriving the sighash from the prepared tx and asserting it
/// equals `prepare_key` is a follow-on hardening (`// RECONCILE AT DEV-ENV`,
/// pinned once the real `ACTIVITY_UPDATES` payload shape is captured).
pub async fn decide_callback<P, R>(
    prepare_key: &str,
    prepare: &P,
    replay: &R,
    config: CustodyConfig<'_>,
    btc_custody_spk: Option<&ScriptBuf>,
    now_unix: i64,
) -> Decision
where
    P: PrepareStore,
    R: ReplayStore,
{
    let spend = match prepare.get(prepare_key).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Decision::Reject {
                code: "no_prepare_context",
                message: "no prepared spend bound to this signing payload (fail-closed)"
                    .to_string(),
            };
        }
        Err(e) => {
            return Decision::Reject {
                code: "prepare_store_error",
                message: e.to_string(),
            };
        }
    };
    decide_prepared(&spend, replay, config, btc_custody_spk, now_unix).await
}

/// Dispatch a [`PreparedSpend`] to its family decision core.
async fn decide_prepared<R: ReplayStore>(
    spend: &PreparedSpend,
    replay: &R,
    config: CustodyConfig<'_>,
    btc_custody_spk: Option<&ScriptBuf>,
    now_unix: i64,
) -> Decision {
    match spend {
        PreparedSpend::Btc(ctx) => match btc_custody_spk {
            Some(spk) => decide_redeem_spend(ctx, replay, config, spk, now_unix).await,
            None => Decision::Reject {
                code: "btc_custody_unconfigured",
                message: "BTC custody scriptPubKey not configured on this approver".to_string(),
            },
        },
        PreparedSpend::Evm(e) => {
            let deposit = EvmDeposit {
                chain: e.chain,
                to: e.to,
                value: e.value,
                data: &e.data,
                ric: e.ric.as_ref(),
                spend_identity: &e.spend_identity,
            };
            decide_evm_deposit(&deposit, replay, config, now_unix).await
        }
        PreparedSpend::Account(a) => {
            let send = AccountSend {
                chain: a.chain,
                to_address: &a.to_address,
                amount_dec: &a.amount_dec,
                memo: &a.memo,
                ric: a.ric.as_ref(),
                spend_identity: &a.spend_identity,
            };
            decide_account_send(&send, replay, config, now_unix).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{keccak256, Address, U256};
    use alloy_sol_types::SolCall;
    use xindex_custody_core::replay::InMemoryReplayStore;
    use xindex_shared::chain_registry::ChainId;
    use xindex_shared::signer_wire::IntentProof;
    use xindex_shared::thorchain_router::depositWithExpiryCall;

    use crate::test_support::{oracle, policy, signed_ric, CHAIN_ID, NOW};
    use xindex_custody_core::prepare::{EvmPrepared, InMemoryPrepareStore, PreparedSpend};

    const CHAIN: ChainId = ChainId::Eth;
    const AMOUNT: u128 = 1_000_000_000_000_000_000;
    const MEMO: &str = "=:ETH.USDT:0xrecipient:990000";

    fn vault() -> Address {
        Address::repeat_byte(0x11)
    }

    fn router() -> Address {
        #[expect(clippy::expect_used, reason = "test code")]
        CHAIN
            .thorchain_router_address()
            .expect("EVM chain has a router")
    }

    fn calldata(amount: U256) -> Vec<u8> {
        depositWithExpiryCall {
            vault: vault(),
            asset: Address::ZERO,
            amount,
            memo: MEMO.to_string(),
            expiry: U256::from(1_750_007_200u64),
        }
        .abi_encode()
    }

    fn config(policy: &xindex_shared::intent::IntentPolicy) -> CustodyConfig<'_> {
        CustodyConfig {
            chain_id: CHAIN_ID,
            verifying_contract: oracle(),
            intent_policy: policy,
        }
    }

    fn evm_prepared(amount: U256, ric: IntentProof) -> PreparedSpend {
        PreparedSpend::Evm(EvmPrepared {
            chain: CHAIN,
            to: router(),
            value: amount,
            data: calldata(amount),
            ric: Some(ric),
            spend_identity: b"0".to_vec(),
        })
    }

    fn honest_ric() -> IntentProof {
        signed_ric(
            CHAIN,
            keccak256(vault().as_slice()),
            MEMO,
            U256::from(AMOUNT),
            &[1, 2, 3],
        )
    }

    fn is_reject(d: &Decision) -> bool {
        matches!(d, Decision::Reject { .. })
    }

    #[tokio::test]
    async fn honest_prepared_approves() {
        let policy = policy();
        let prepare = InMemoryPrepareStore::new();
        let _ = prepare
            .put(
                "sighash-1".to_string(),
                evm_prepared(U256::from(AMOUNT), honest_ric()),
            )
            .await;
        let replay = InMemoryReplayStore::new();
        let d = decide_callback("sighash-1", &prepare, &replay, config(&policy), None, NOW).await;
        assert_eq!(d, Decision::Approve, "honest prepared spend must APPROVE");
    }

    #[tokio::test]
    async fn missing_prepare_context_rejects() {
        let policy = policy();
        let prepare = InMemoryPrepareStore::new();
        let replay = InMemoryReplayStore::new();
        let d = decide_callback("absent", &prepare, &replay, config(&policy), None, NOW).await;
        assert!(is_reject(&d));
    }

    #[tokio::test]
    async fn tampered_spend_rejects() {
        // RIC certifies AMOUNT; the prepared tx deposits AMOUNT+1.
        let policy = policy();
        let prepare = InMemoryPrepareStore::new();
        let _ = prepare
            .put(
                "sighash-1".to_string(),
                evm_prepared(U256::from(AMOUNT + 1), honest_ric()),
            )
            .await;
        let replay = InMemoryReplayStore::new();
        let d = decide_callback("sighash-1", &prepare, &replay, config(&policy), None, NOW).await;
        assert!(is_reject(&d));
    }

    #[tokio::test]
    async fn btc_without_custody_spk_rejects() {
        use bitcoin::{absolute::LockTime, transaction::Version, Transaction};
        use xindex_custody_core::prepare::BindContext;
        let policy = policy();
        let prepare = InMemoryPrepareStore::new();
        #[expect(clippy::expect_used, reason = "test code")]
        let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        })
        .expect("psbt");
        let ctx = BindContext {
            chain: ChainId::Btc,
            psbt,
            ric: None,
            acc: None,
        };
        let _ = prepare
            .put("sighash-btc".to_string(), PreparedSpend::Btc(Box::new(ctx)))
            .await;
        let replay = InMemoryReplayStore::new();
        // btc_custody_spk = None → BTC spend must reject (fail-closed).
        let d = decide_callback("sighash-btc", &prepare, &replay, config(&policy), None, NOW).await;
        assert!(is_reject(&d));
    }
}
