//! The Cobo callback decision pipeline — pure, transport-independent.
//!
//! Given a parsed [`CallbackRequest`] + the prepare store + the replay store,
//! decide APPROVE/REJECT for a pending Cobo MPC signature. The JWT verify /
//! axum layer ([`crate::jwt`], [`crate::server`]) is a thin shell over this;
//! everything security-relevant is here and unit-tested without a network.
//!
//! Fail-safe by construction — APPROVE requires ALL of: the request is a
//! `KeySign`, a prepare-context exists for its `request_id` (which only the
//! executor creates when it submits the spend), and the family decision core
//! passes the k-of-n RIC bind. Any miss → fail-closed REJECT.

use bitcoin::ScriptBuf;
use xindex_custody_core::gates::CustodyConfig;
use xindex_custody_core::replay::ReplayStore;

use crate::account::{decide_account_send, AccountSend};
use crate::btc::decide_redeem_spend;
use crate::cobo_types::{CallbackRequest, CallbackResponse};
use crate::evm::{decide_evm_deposit, EvmDeposit};
use crate::prepare::{PrepareStore, PreparedSpend};
use crate::Decision;

/// Decide a Cobo TSS-Node callback. Looks up the prepared spend by
/// `request_id`, runs the family decision core, maps to APPROVE/REJECT.
///
/// `btc_custody_spk` is this callback's own custody `scriptPubKey` (for the
/// BTC output bind); `None` rejects any BTC spend.
///
/// **SECURITY (W3, dev-env reconciliation):** this binds the spend to the
/// k-of-n RIC via the prepare-context, but does NOT yet cross-check that the
/// message Cobo is about to sign (carried in `req.request_detail`, schema
/// non-public) equals the re-derived sighash of the prepared spend. Until that
/// cross-check is wired, [`crate::server`]'s production guard must refuse prod
/// (a coordinator that prepared ctx X but submitted tx Y under the same
/// `request_id` would otherwise pass). See `docs/runbooks/cobo-btc-gate.md`.
pub async fn decide_callback<P, R>(
    req: &CallbackRequest,
    prepare: &P,
    replay: &R,
    config: CustodyConfig<'_>,
    btc_custody_spk: Option<&ScriptBuf>,
    now_unix: i64,
) -> CallbackResponse
where
    P: PrepareStore,
    R: ReplayStore,
{
    if !req.is_key_sign() {
        return CallbackResponse::reject(
            "unsupported_request_type",
            "only key-sign spends are gated by this callback (fail-closed)",
        );
    }
    let spend = match prepare.get(&req.request_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return CallbackResponse::reject(
                "no_prepare_context",
                "no prepared spend bound to this request_id (fail-closed)",
            );
        }
        Err(e) => return CallbackResponse::reject("prepare_store_error", e.to_string()),
    };
    match decide_prepared(&spend, replay, config, btc_custody_spk, now_unix).await {
        Decision::Approve => CallbackResponse::approve(),
        Decision::Reject { code, message } => CallbackResponse::reject(code, message),
    }
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
                message: "BTC custody scriptPubKey not configured on this callback".to_string(),
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

    use crate::cobo_types::CallbackRequest;
    use crate::prepare::{EvmPrepared, InMemoryPrepareStore, PreparedSpend};
    use crate::test_support::{oracle, policy, signed_ric, CHAIN_ID, NOW};

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

    fn key_sign_req(request_id: &str) -> CallbackRequest {
        CallbackRequest {
            request_id: request_id.to_string(),
            request_type: serde_json::json!(2),
            request_detail: String::new(),
            extra_info: String::new(),
        }
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

    #[tokio::test]
    async fn honest_keysign_approves() {
        let policy = policy();
        let prepare = InMemoryPrepareStore::new();
        let _ = prepare
            .put(
                "req-1".to_string(),
                evm_prepared(U256::from(AMOUNT), honest_ric()),
            )
            .await;
        let replay = InMemoryReplayStore::new();
        let resp = decide_callback(
            &key_sign_req("req-1"),
            &prepare,
            &replay,
            config(&policy),
            None,
            NOW,
        )
        .await;
        assert!(
            resp.is_approve(),
            "honest prepared KeySign must APPROVE: {resp:?}"
        );
    }

    #[tokio::test]
    async fn missing_prepare_context_rejects() {
        let policy = policy();
        let prepare = InMemoryPrepareStore::new();
        let replay = InMemoryReplayStore::new();
        let resp = decide_callback(
            &key_sign_req("absent"),
            &prepare,
            &replay,
            config(&policy),
            None,
            NOW,
        )
        .await;
        assert!(!resp.is_approve());
    }

    #[tokio::test]
    async fn non_keysign_rejects() {
        let policy = policy();
        let prepare = InMemoryPrepareStore::new();
        // Even WITH a valid prepared spend, a non-KeySign request is rejected.
        let _ = prepare
            .put(
                "req-1".to_string(),
                evm_prepared(U256::from(AMOUNT), honest_ric()),
            )
            .await;
        let replay = InMemoryReplayStore::new();
        let mut req = key_sign_req("req-1");
        req.request_type = serde_json::json!(1); // KeyGen
        let resp = decide_callback(&req, &prepare, &replay, config(&policy), None, NOW).await;
        assert!(!resp.is_approve());
    }

    #[tokio::test]
    async fn tampered_spend_rejects() {
        // RIC certifies AMOUNT; the prepared tx deposits AMOUNT+1.
        let policy = policy();
        let prepare = InMemoryPrepareStore::new();
        let _ = prepare
            .put(
                "req-1".to_string(),
                evm_prepared(U256::from(AMOUNT + 1), honest_ric()),
            )
            .await;
        let replay = InMemoryReplayStore::new();
        let resp = decide_callback(
            &key_sign_req("req-1"),
            &prepare,
            &replay,
            config(&policy),
            None,
            NOW,
        )
        .await;
        assert!(!resp.is_approve());
    }

    #[tokio::test]
    async fn btc_without_custody_spk_rejects() {
        use crate::prepare::BindContext;
        use bitcoin::{absolute::LockTime, transaction::Version, Transaction};
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
            .put("req-btc".to_string(), PreparedSpend::Btc(Box::new(ctx)))
            .await;
        let replay = InMemoryReplayStore::new();
        // btc_custody_spk = None → BTC spend must reject (fail-closed).
        let resp = decide_callback(
            &key_sign_req("req-btc"),
            &prepare,
            &replay,
            config(&policy),
            None,
            NOW,
        )
        .await;
        assert!(!resp.is_approve());
    }
}
