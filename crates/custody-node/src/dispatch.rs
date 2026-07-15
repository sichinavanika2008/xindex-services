//! The custody decision pipeline — pure, transport-independent.
//!
//! Given a prepared-spend lookup key + the prepare store + the replay store,
//! decide APPROVE/REJECT for a pending custody signature. A provider-specific
//! callback supplies the requested signing payload as the lookup key and maps
//! the [`Decision`] into its signed response. Everything security-relevant is
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
/// **SECURITY (TK-01/TK-02):** the executor writes BOTH the store key and the
/// requested signing payload, so before binding to the RIC this core INDEPENDENTLY
/// reconstructs the unsigned tx from the prepared fields, recomputes its signing
/// hash, and asserts it equals `prepare_key`
/// ([`crate::recompute::verify_payload_and_fee`]) — a coordinator therefore
/// cannot pair an honest bound context with a signature over a different
/// message. The same pass caps the declared fee (TK-02). Then the family core
/// binds the certified destination / amount / memo to the k-of-n RIC. Any miss
/// is a fail-closed REJECT.
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
    // TK-01/TK-02: the signing payload MUST be the hash of a tx reconstructed
    // from these prepared fields, and the declared fee within the per-chain cap.
    if let Err((code, message)) = crate::recompute::verify_payload_and_fee(&spend, prepare_key) {
        return Decision::Reject { code, message };
    }
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
            signing: xindex_custody_core::prepare::EvmSigning {
                nonce: 0,
                gas_limit: 300_000,
                max_fee_per_gas: 50_000_000_000,
                max_priority_fee_per_gas: 1_500_000_000,
                gas_price: 5_000_000_000,
            },
            ric: Some(ric),
            spend_identity: b"0".to_vec(),
        })
    }

    /// The real signing-payload key for a prepared EVM spend (what the executor
    /// keys `prepare.put` by, and what the approver recomputes — TK-01).
    fn evm_key(spend: &PreparedSpend) -> String {
        let PreparedSpend::Evm(e) = spend else {
            unreachable!("evm_key on non-EVM spend")
        };
        #[expect(clippy::expect_used, reason = "test code")]
        let hash = xindex_custody_core::evm_tx::evm_signing_hash(
            &xindex_custody_core::evm_tx::EvmUnsignedParams {
                chain: e.chain,
                nonce: e.signing.nonce,
                gas_limit: e.signing.gas_limit,
                max_fee_per_gas: e.signing.max_fee_per_gas,
                max_priority_fee_per_gas: e.signing.max_priority_fee_per_gas,
                gas_price: e.signing.gas_price,
                to: e.to,
                value: e.value,
                data: &e.data,
            },
        )
        .expect("evm signing hash");
        format!("0x{}", alloy_primitives::hex::encode(hash))
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
        let spend = evm_prepared(U256::from(AMOUNT), honest_ric());
        let key = evm_key(&spend);
        let _ = prepare.put(key.clone(), spend).await;
        let replay = InMemoryReplayStore::new();
        let d = decide_callback(&key, &prepare, &replay, config(&policy), None, NOW).await;
        assert_eq!(d, Decision::Approve, "honest prepared spend must APPROVE");
    }

    #[tokio::test]
    async fn payload_binding_mismatch_rejects() {
        // TK-01: the prepared context is honest but the signing payload the
        // enclave is asked to sign is NOT its recomputed hash → fail-closed.
        let policy = policy();
        let prepare = InMemoryPrepareStore::new();
        let spend = evm_prepared(U256::from(AMOUNT), honest_ric());
        let _ = prepare.put("0xdeadbeef".to_string(), spend).await;
        let replay = InMemoryReplayStore::new();
        let d = decide_callback("0xdeadbeef", &prepare, &replay, config(&policy), None, NOW).await;
        assert!(
            matches!(&d, Decision::Reject { code, .. } if *code == "payload_binding_mismatch"),
            "unbound payload must REJECT, got {d:?}"
        );
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
        // RIC certifies AMOUNT; the prepared tx deposits AMOUNT+1. The payload
        // recompute passes (self-consistent) but the RIC amount bind fails.
        let policy = policy();
        let prepare = InMemoryPrepareStore::new();
        let spend = evm_prepared(U256::from(AMOUNT + 1), honest_ric());
        let key = evm_key(&spend);
        let _ = prepare.put(key.clone(), spend).await;
        let replay = InMemoryReplayStore::new();
        let d = decide_callback(&key, &prepare, &replay, config(&policy), None, NOW).await;
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
