//! The Turnkey approver core — observe a pending signing activity, decide, vote.
//!
//! This is the CTD-1 enforcement point under Turnkey custody: Turnkey holds the
//! key but signs a `CONSENSUS_NEEDED` activity only once our approver casts
//! `approveActivity`. [`process_activity`] is the pure, network-stubbable unit:
//! it reads the activity's signing `payload` (the sighash we computed), looks up
//! the prepared spend by that key, runs the family decision core ([`dispatch`]),
//! and votes `approveActivity` / `rejectActivity` — fail-closed (an activity
//! with no correlatable payload is rejected).
//!
//! The binary (`xindex-turnkey-approver`) is a thin shell: it polls Turnkey for
//! the watched activities (the `ACTIVITY_UPDATES` webhook is the production push
//! trigger) and calls this for each `CONSENSUS_NEEDED` one.

use bitcoin::ScriptBuf;
use xindex_custody_core::gates::CustodyConfig;
use xindex_custody_core::prepare::PrepareStore;
use xindex_custody_core::replay::ReplayStore;
use xindex_turnkey_client::{Activity, TurnkeyApi, TurnkeyError};

use crate::dispatch::decide_callback;
use crate::Decision;

/// Decide and vote on one `CONSENSUS_NEEDED` signing activity.
///
/// Returns the [`Decision`] cast (the vote outcome). The `Err` arm is a
/// transport/vote failure — the decision logic itself never errors, it only
/// produces APPROVE or a fail-closed REJECT. Voting fails closed: a missing
/// prepared spend, a tampered spend, or an activity with no signing payload all
/// produce `rejectActivity`.
///
/// `btc_custody_spk` is this approver's own BTC custody `scriptPubKey`; `None`
/// rejects any BTC spend.
///
/// # Errors
/// [`TurnkeyError`] if casting the `approveActivity` / `rejectActivity` vote
/// fails (transport / API error). The decision logic itself never errors.
pub async fn process_activity<A, P, R>(
    api: &A,
    prepare: &P,
    replay: &R,
    config: CustodyConfig<'_>,
    btc_custody_spk: Option<&ScriptBuf>,
    activity: &Activity,
    now_unix: i64,
) -> Result<Decision, TurnkeyError>
where
    A: TurnkeyApi,
    P: PrepareStore,
    R: ReplayStore,
{
    let decision = match activity.signed_payload() {
        Some(payload) => {
            decide_callback(payload, prepare, replay, config, btc_custody_spk, now_unix).await
        }
        None => Decision::Reject {
            code: "no_signed_payload",
            message: "activity carries no SIGN_RAW_PAYLOAD payload to correlate (fail-closed)"
                .to_string(),
        },
    };
    match &decision {
        Decision::Approve => {
            api.approve_activity(&activity.fingerprint).await?;
        }
        Decision::Reject { .. } => {
            api.reject_activity(&activity.fingerprint).await?;
        }
    }
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use alloy_primitives::{keccak256, Address, U256};
    use alloy_sol_types::SolCall;
    use xindex_custody_core::prepare::{EvmPrepared, InMemoryPrepareStore, PreparedSpend};
    use xindex_custody_core::replay::InMemoryReplayStore;
    use xindex_shared::chain_registry::ChainId;
    use xindex_shared::signer_wire::IntentProof;
    use xindex_shared::thorchain_router::depositWithExpiryCall;
    use xindex_turnkey_client::SignRawPayloadParams;

    use crate::test_support::{oracle, policy, signed_ric, CHAIN_ID, NOW};

    const CHAIN: ChainId = ChainId::Eth;
    const AMOUNT: u128 = 1_000_000_000_000_000_000;
    const MEMO: &str = "=:ETH.USDT:0xrecipient:990000";
    const PAYLOAD: &str = "0xfeedface";

    /// A `TurnkeyApi` stub that records the votes cast (no network).
    #[derive(Default)]
    struct StubApi {
        approved: Mutex<Vec<String>>,
        rejected: Mutex<Vec<String>>,
    }

    impl StubApi {
        #[expect(clippy::expect_used, reason = "test code")]
        fn approvals(&self) -> Vec<String> {
            self.approved.lock().expect("lock").clone()
        }
        #[expect(clippy::expect_used, reason = "test code")]
        fn rejections(&self) -> Vec<String> {
            self.rejected.lock().expect("lock").clone()
        }
    }

    /// A throwaway completed activity (the approver discards the vote result).
    #[expect(clippy::expect_used, reason = "test code")]
    fn stub_activity(fp: &str) -> Activity {
        serde_json::from_value(serde_json::json!({
            "id": "act-stub", "status": "ACTIVITY_STATUS_COMPLETED",
            "type": "ACTIVITY_TYPE_APPROVE_ACTIVITY", "fingerprint": fp
        }))
        .expect("stub activity")
    }

    impl TurnkeyApi for StubApi {
        // Not exercised by the approver.
        async fn sign_raw_payload(
            &self,
            _params: &SignRawPayloadParams,
        ) -> Result<Activity, TurnkeyError> {
            Err(TurnkeyError::Http("stub: sign_raw_payload unused".into()))
        }
        async fn get_activity(&self, _activity_id: &str) -> Result<Activity, TurnkeyError> {
            Err(TurnkeyError::Http("stub: get_activity unused".into()))
        }
        #[expect(clippy::expect_used, reason = "test code")]
        async fn approve_activity(&self, fingerprint: &str) -> Result<Activity, TurnkeyError> {
            self.approved
                .lock()
                .expect("lock")
                .push(fingerprint.to_string());
            Ok(stub_activity(fingerprint))
        }
        #[expect(clippy::expect_used, reason = "test code")]
        async fn reject_activity(&self, fingerprint: &str) -> Result<Activity, TurnkeyError> {
            self.rejected
                .lock()
                .expect("lock")
                .push(fingerprint.to_string());
            Ok(stub_activity(fingerprint))
        }
    }

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

    /// A `SIGN_RAW_PAYLOAD` activity whose signed payload is `PAYLOAD`.
    fn consensus_activity() -> Activity {
        #[expect(clippy::expect_used, reason = "test code")]
        serde_json::from_value(serde_json::json!({
            "id": "act-1",
            "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED",
            "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
            "fingerprint": "fp-1",
            "intent": { "signRawPayloadIntentV2": {
                "signWith": "custody-key", "payload": PAYLOAD,
                "encoding": "PAYLOAD_ENCODING_HEXADECIMAL", "hashFunction": "HASH_FUNCTION_NO_OP"
            }}
        }))
        .expect("activity")
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn honest_activity_is_approved() {
        let policy = policy();
        let prepare = InMemoryPrepareStore::new();
        let _ = prepare
            .put(
                PAYLOAD.to_string(),
                evm_prepared(U256::from(AMOUNT), honest_ric()),
            )
            .await;
        let replay = InMemoryReplayStore::new();
        let api = StubApi::default();

        let d = process_activity(
            &api,
            &prepare,
            &replay,
            config(&policy),
            None,
            &consensus_activity(),
            NOW,
        )
        .await
        .expect("vote");

        assert_eq!(d, Decision::Approve);
        assert_eq!(api.approvals(), vec!["fp-1".to_string()]);
        assert!(api.rejections().is_empty());
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn missing_prepared_spend_is_rejected() {
        // Activity references PAYLOAD but nothing was prepared under it.
        let policy = policy();
        let prepare = InMemoryPrepareStore::new();
        let replay = InMemoryReplayStore::new();
        let api = StubApi::default();

        let d = process_activity(
            &api,
            &prepare,
            &replay,
            config(&policy),
            None,
            &consensus_activity(),
            NOW,
        )
        .await
        .expect("vote");

        assert!(matches!(d, Decision::Reject { .. }));
        assert_eq!(api.rejections(), vec!["fp-1".to_string()]);
        assert!(api.approvals().is_empty());
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn tampered_spend_is_rejected() {
        // RIC certifies AMOUNT; the prepared tx deposits AMOUNT+1.
        let policy = policy();
        let prepare = InMemoryPrepareStore::new();
        let _ = prepare
            .put(
                PAYLOAD.to_string(),
                evm_prepared(U256::from(AMOUNT + 1), honest_ric()),
            )
            .await;
        let replay = InMemoryReplayStore::new();
        let api = StubApi::default();

        let d = process_activity(
            &api,
            &prepare,
            &replay,
            config(&policy),
            None,
            &consensus_activity(),
            NOW,
        )
        .await
        .expect("vote");

        assert!(matches!(d, Decision::Reject { .. }));
        assert_eq!(api.rejections(), vec!["fp-1".to_string()]);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn activity_without_payload_is_rejected() {
        let policy = policy();
        let prepare = InMemoryPrepareStore::new();
        let replay = InMemoryReplayStore::new();
        let api = StubApi::default();
        let no_payload: Activity = serde_json::from_value(serde_json::json!({
            "id": "act-2", "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED", "fingerprint": "fp-2"
        }))
        .expect("activity");

        let d = process_activity(
            &api,
            &prepare,
            &replay,
            config(&policy),
            None,
            &no_payload,
            NOW,
        )
        .await
        .expect("vote");

        assert!(matches!(d, Decision::Reject { code, .. } if code == "no_signed_payload"));
        assert_eq!(api.rejections(), vec!["fp-2".to_string()]);
    }
}
