//! XRP redeem leg under Turnkey enclave custody (`DL-CUSTODY-TURNKEY-1`).
//!
//! The Turnkey replacement for the k-of-n `SignerList` multisign flow
//! ([`crate::xrp_redeem`]). Under Turnkey the XRP custody key is a single
//! secp256k1 enclave key, so the redeem is a REGULAR (single-sign) `Payment`
//! — `SigningPubKey` + `TxnSignature`, no `Signers` array. Turnkey is a RAW
//! signer — *we* build the `Payment`, serialize the single-sign body, compute
//! its `SHA512Half(STX\0 ‖ body)` signing hash; Turnkey signs that hash via
//! `SIGN_RAW_PAYLOAD` (gated by the approver-watcher); *we* assemble the signed
//! tx-blob and submit. The flow:
//!
//! 1. Build the `Payment` body with the custody `SigningPubKey` populated.
//! 2. Compute the single-sign digest (`sequence` + `LastLedgerSequence`
//!    caller-supplied).
//! 3. Store the prepared spend in the SHARED prepare store keyed by the digest
//!    hex — the approver binds destination/amount/memo to the k-of-n RIC.
//! 4. `sign_raw_payload(payload = digest)` → consensus → `r,s`.
//! 5. Assemble the signed single-sign tx-blob (`TxnSignature` = DER low-S) and
//!    return it; the binary submits via `XrpChainClient::submit_tx_blob`
//!    (mirrors [`crate::xrp_redeem`], which also returns rather than submits).
//!
//! ## Deadline / replay rule (the XRP-specific nuance)
//!
//! `LastLedgerSequence` is bound into the body (hence the signing hash). A
//! retry at the SAME `Sequence` with a different deadline yields a different
//! hash → a different prepare key; the approver's one-shot RIC consume keys on
//! the `Sequence` so a re-drive at the same sequence cannot double-spend
//! (`KNOWN_FINDINGS` P4.4-2). The caller computes ONE deadline per leg.
//!
//! Fail-closed: a rejected/failed activity ⇒ no signature ⇒ no tx-blob.

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::B256;
use thiserror::Error;
use tracing::{debug, info};

use xindex_custody_core::prepare::{AccountPrepared, PrepareStore, PreparedSpend};
use xindex_shared::chain_registry::ChainId;
use xindex_turnkey_client::{Activity, SignRawPayloadParams, TurnkeyApi};
use xindex_xrp_tx::addr::decode_classic_address;
use xindex_xrp_tx::signing::single_sign_digest;
use xindex_xrp_tx::sigs::{der_low_s_from_rs, SigError};
use xindex_xrp_tx::tx::{build_signed_single_sig_tx, serialize_single_sign, PaymentBody, TxError};

use crate::xrp_redeem::XrpRedeemTask;

/// Errors surfaced by the Turnkey XRP redeem executor.
#[derive(Debug, Error)]
pub enum TurnkeyXrpError {
    /// The task's chain is not this executor's XRP chain.
    #[error("ChainId {0:?} is not this executor's XRP chain")]
    WrongChain(ChainId),
    /// A configured r-address (account / vault) did not decode.
    #[error("address: {0}")]
    Address(String),
    /// An amount / fee did not fit its on-wire width.
    #[error("out-of-range numeric: {0}")]
    Numeric(String),
    /// `STObject` serialization failed (e.g. memo too long).
    #[error("tx build: {0}")]
    Tx(#[from] TxError),
    /// Failed to persist the prepared spend (the approver would then fail
    /// closed, so we abort BEFORE signing).
    #[error("prepare store: {0}")]
    Prepare(String),
    /// A Turnkey API call failed.
    #[error("turnkey api: {0}")]
    Turnkey(String),
    /// The signing activity was rejected / failed — no signature, no tx.
    #[error("signing activity {activity_id} terminated without a signature")]
    Rejected {
        /// The Turnkey activity id.
        activity_id: String,
    },
    /// Polling exhausted before the activity reached a terminal state.
    #[error("signing activity {activity_id} did not complete after polling")]
    PollTimeout {
        /// The Turnkey activity id.
        activity_id: String,
    },
    /// The activity completed but carried no signature result.
    #[error("signing activity {activity_id} completed without a signature result")]
    NoSignature {
        /// The Turnkey activity id.
        activity_id: String,
    },
    /// DER-encoding the `TxnSignature` from `(r, s)` failed.
    #[error("signature assembly: {0}")]
    Signature(#[from] SigError),
}

/// Static per-executor configuration. One executor per Turnkey custody key.
#[derive(Debug, Clone)]
pub struct TurnkeyXrpRedeemConfig {
    /// The XRP custody chain this executor serves.
    pub chain: ChainId,
    /// The classic r-address of the single-key custody account. The caller
    /// derives it from `custody_pubkey`; they must agree.
    pub account_address: String,
    /// The compressed (33-byte) secp256k1 custody public key (the
    /// `SigningPubKey`).
    pub custody_pubkey: [u8; 33],
    /// The Turnkey `signWith` selector (private-key id / wallet-account
    /// address) for this custody key.
    pub sign_with: String,
    /// Fee in drops (caller-supplied; a single-sig `base_fee`).
    pub fee_drops: u128,
    /// Delay between activity status polls.
    pub poll_interval: Duration,
    /// Max status polls before [`TurnkeyXrpError::PollTimeout`].
    pub poll_max_attempts: u32,
}

/// Turnkey XRP redeem executor. Builds + signs (via Turnkey, gated by the
/// approver) + assembles the single-sign tx-blob; returns it for the caller to
/// submit. Performs NO chain I/O — `sequence` and `last_ledger_sequence` are
/// caller-supplied (mirrors [`crate::turnkey_evm_redeem`]).
pub struct TurnkeyXrpRedeemExecutor<T, P> {
    config: TurnkeyXrpRedeemConfig,
    turnkey: Arc<T>,
    prepare: Arc<P>,
}

impl<T, P> std::fmt::Debug for TurnkeyXrpRedeemExecutor<T, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnkeyXrpRedeemExecutor")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// The result of a completed Turnkey XRP redeem leg.
#[derive(Debug, Clone)]
pub struct TurnkeyXrpRedeemOutcome {
    /// Destination chain (for the dispatch-store `chain` column).
    pub chain: ChainId,
    /// Broadcast-ready single-signed tx-blob.
    pub tx_blob: Vec<u8>,
    /// The 32-byte single-sign digest the custody key signed (also the
    /// prepare-store key).
    pub signing_hash: [u8; 32],
    /// Account `Sequence` consumed by this leg.
    pub sequence: u32,
    /// The `LastLedgerSequence` deadline bound into the body.
    pub last_ledger_sequence: u32,
    /// Originating dispatch id (broadcast registry key).
    pub dispatch_id: B256,
    /// Originating redemption id (attestation correlation).
    pub redemption_id: B256,
    /// The Turnkey signing activity id.
    pub activity_id: String,
}

impl<T: TurnkeyApi, P: PrepareStore> TurnkeyXrpRedeemExecutor<T, P> {
    /// Construct.
    #[must_use]
    pub fn new(config: TurnkeyXrpRedeemConfig, turnkey: Arc<T>, prepare: Arc<P>) -> Self {
        Self {
            config,
            turnkey,
            prepare,
        }
    }

    /// Borrow the configuration.
    #[must_use]
    pub fn config(&self) -> &TurnkeyXrpRedeemConfig {
        &self.config
    }

    /// Execute one XRP redeem leg through Turnkey: build → digest → prepare →
    /// sign (gated) → assemble the single-sign tx-blob.
    ///
    /// `vault` is the live `THORChain` XRP Asgard inbound (classic r-address).
    /// `sequence` and `last_ledger_sequence` are computed fresh by the caller
    /// (DL-P3.2-7 — no chain I/O here; one deadline per leg).
    ///
    /// # Errors
    /// Any [`TurnkeyXrpError`] variant.
    pub async fn execute_leg(
        &self,
        task: &XrpRedeemTask,
        vault: &str,
        sequence: u32,
        last_ledger_sequence: u32,
    ) -> Result<TurnkeyXrpRedeemOutcome, TurnkeyXrpError> {
        if task.chain != self.config.chain {
            return Err(TurnkeyXrpError::WrongChain(task.chain));
        }

        let amount_drops = u64::try_from(task.send_amount).map_err(|_| {
            TurnkeyXrpError::Numeric(format!("amount > u64 drops: {}", task.send_amount))
        })?;
        let fee_drops = u64::try_from(self.config.fee_drops).map_err(|_| {
            TurnkeyXrpError::Numeric(format!("fee > u64 drops: {}", self.config.fee_drops))
        })?;
        let account = decode_classic_address(&self.config.account_address)
            .map_err(|e| TurnkeyXrpError::Address(format!("account {e}")))?;
        let destination = decode_classic_address(vault)
            .map_err(|e| TurnkeyXrpError::Address(format!("vault {e}")))?;

        let body = PaymentBody {
            account,
            destination,
            amount_drops,
            fee_drops,
            sequence,
            last_ledger_sequence: Some(last_ledger_sequence),
            network_id: None,
            memo: task.memo.clone().into_bytes(),
        };
        // The single-sign body carries the custody SigningPubKey; the signing
        // hash is SHA512Half(STX\0 ‖ body).
        let serialized = serialize_single_sign(&body, &self.config.custody_pubkey)?;
        let digest = single_sign_digest(&serialized);
        let payload_hex = format!("0x{}", alloy_primitives::hex::encode(digest));

        // Persist the prepared spend keyed by the digest BEFORE signing — the
        // approver binds destination/amount/memo to the RIC and fail-closes on
        // a missing context. spend_identity = the account Sequence (a re-drive
        // advances it → one-shot).
        self.prepare
            .put(
                payload_hex.clone(),
                PreparedSpend::Account(AccountPrepared {
                    chain: self.config.chain,
                    to_address: vault.to_string(),
                    amount_dec: amount_drops.to_string(),
                    memo: task.memo.clone(),
                    ric: task.intent_proof.clone(),
                    spend_identity: sequence.to_be_bytes().to_vec(),
                }),
            )
            .await
            .map_err(|e| TurnkeyXrpError::Prepare(e.to_string()))?;

        let activity = self
            .turnkey
            .sign_raw_payload(&SignRawPayloadParams::hex_no_op(
                &self.config.sign_with,
                &payload_hex,
            ))
            .await
            .map_err(|e| TurnkeyXrpError::Turnkey(e.to_string()))?;
        let completed = self.await_signature(activity).await?;
        let result = completed
            .sign_result()
            .ok_or_else(|| TurnkeyXrpError::NoSignature {
                activity_id: completed.id.clone(),
            })?;
        // XRPL TxnSignature is non-recoverable DER low-S; drop `v`.
        let (r, s, _v) = result
            .rsv()
            .map_err(|e| TurnkeyXrpError::Turnkey(e.to_string()))?;
        let der = der_low_s_from_rs(&r, &s)?;

        let tx_blob = build_signed_single_sig_tx(&body, &self.config.custody_pubkey, &der)?;
        info!(
            redemption_id = %task.redemption_id,
            activity = %completed.id,
            "XRP redeem tx-blob signed (Turnkey); ready to submit"
        );
        Ok(TurnkeyXrpRedeemOutcome {
            chain: self.config.chain,
            tx_blob,
            signing_hash: digest,
            sequence,
            last_ledger_sequence,
            dispatch_id: task.dispatch_id,
            redemption_id: task.redemption_id,
            activity_id: completed.id,
        })
    }

    /// Poll the signing activity to a signature. Fail-closed on reject /
    /// failure / timeout.
    async fn await_signature(&self, activity: Activity) -> Result<Activity, TurnkeyXrpError> {
        let mut current = activity;
        for _ in 0..self.config.poll_max_attempts {
            if current.status.is_completed() {
                return Ok(current);
            }
            if current.status.is_terminal() {
                return Err(TurnkeyXrpError::Rejected {
                    activity_id: current.id,
                });
            }
            debug!(activity = %current.id, status = ?current.status, "awaiting consensus");
            tokio::time::sleep(self.config.poll_interval).await;
            current = self
                .turnkey
                .get_activity(&current.id)
                .await
                .map_err(|e| TurnkeyXrpError::Turnkey(e.to_string()))?;
        }
        Err(TurnkeyXrpError::PollTimeout {
            activity_id: current.id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xindex_custody_core::prepare::InMemoryPrepareStore;
    use xindex_turnkey_client::TurnkeyError;
    use xindex_xrp_tx::addr::encode_classic_address;

    struct StubTurnkey {
        on_sign: Activity,
        on_get: Activity,
    }

    impl TurnkeyApi for StubTurnkey {
        async fn sign_raw_payload(
            &self,
            _params: &SignRawPayloadParams,
        ) -> Result<Activity, TurnkeyError> {
            Ok(self.on_sign.clone())
        }
        async fn get_activity(&self, _activity_id: &str) -> Result<Activity, TurnkeyError> {
            Ok(self.on_get.clone())
        }
        async fn approve_activity(&self, _fingerprint: &str) -> Result<Activity, TurnkeyError> {
            Err(TurnkeyError::Http("stub: approve unused".into()))
        }
        async fn reject_activity(&self, _fingerprint: &str) -> Result<Activity, TurnkeyError> {
            Err(TurnkeyError::Http("stub: reject unused".into()))
        }
    }

    fn config() -> TurnkeyXrpRedeemConfig {
        let mut pubkey = [0u8; 33];
        pubkey[0] = 0x02;
        pubkey[32] = 0x09;
        TurnkeyXrpRedeemConfig {
            chain: ChainId::Xrp,
            account_address: encode_classic_address(&[0xAB; 20]),
            custody_pubkey: pubkey,
            sign_with: "custody-key".to_string(),
            fee_drops: 12,
            poll_interval: Duration::ZERO,
            poll_max_attempts: 5,
        }
    }

    fn task() -> XrpRedeemTask {
        XrpRedeemTask {
            dispatch_id: B256::repeat_byte(0xd1),
            redemption_id: B256::repeat_byte(0xd2),
            chain: ChainId::Xrp,
            memo: "=:ETH.USDT:0xrecipient:990000".to_string(),
            send_amount: 5_000_000,
            intent_proof: None,
        }
    }

    fn vault() -> String {
        encode_classic_address(&[0xCD; 20])
    }

    fn completed_with_sig() -> Activity {
        #[expect(clippy::expect_used, reason = "test code")]
        serde_json::from_value(serde_json::json!({
            "id": "act-1", "status": "ACTIVITY_STATUS_COMPLETED",
            "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", "fingerprint": "fp-1",
            "result": { "signRawPayloadResult": {
                "r": &"11".repeat(32), "s": &"22".repeat(32), "v": "00"
            }}
        }))
        .expect("activity")
    }

    fn status_activity(status: &str) -> Activity {
        #[expect(clippy::expect_used, reason = "test code")]
        serde_json::from_value(serde_json::json!({
            "id": "act-1", "status": status,
            "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", "fingerprint": "fp-1"
        }))
        .expect("activity")
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn happy_path_signs_and_prepares() {
        let turnkey = Arc::new(StubTurnkey {
            on_sign: completed_with_sig(),
            on_get: completed_with_sig(),
        });
        let prepare = Arc::new(InMemoryPrepareStore::new());
        let exec = TurnkeyXrpRedeemExecutor::new(config(), turnkey, Arc::clone(&prepare));
        let outcome = exec
            .execute_leg(&task(), &vault(), 7, 9_000_075)
            .await
            .expect("leg");
        assert_eq!(outcome.activity_id, "act-1");
        assert_eq!(outcome.sequence, 7);
        assert_eq!(outcome.last_ledger_sequence, 9_000_075);
        // Assembled tx starts with TransactionType=Payment (12 0000).
        assert_eq!(&outcome.tx_blob[..3], &[0x12, 0x00, 0x00]);
        // Single-sig: no Signers array.
        let hex = alloy_primitives::hex::encode(&outcome.tx_blob);
        assert!(!hex.contains("f3e0"), "single-sig tx has no Signers array");
        // The prepared spend is keyed by the signing hash.
        let key = format!("0x{}", alloy_primitives::hex::encode(outcome.signing_hash));
        let stored = prepare.get(&key).await.expect("get");
        assert!(
            matches!(&stored, Some(PreparedSpend::Account(_))),
            "expected Account, got {stored:?}"
        );
        if let Some(PreparedSpend::Account(a)) = stored {
            assert_eq!(a.to_address, vault());
            assert_eq!(a.amount_dec, "5000000");
            assert_eq!(a.spend_identity, 7u32.to_be_bytes().to_vec());
        }
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rejected_activity_yields_no_tx() {
        let turnkey = Arc::new(StubTurnkey {
            on_sign: status_activity("ACTIVITY_STATUS_CONSENSUS_NEEDED"),
            on_get: status_activity("ACTIVITY_STATUS_REJECTED"),
        });
        let prepare = Arc::new(InMemoryPrepareStore::new());
        let exec = TurnkeyXrpRedeemExecutor::new(config(), turnkey, prepare);
        let err = exec
            .execute_leg(&task(), &vault(), 7, 9_000_075)
            .await
            .expect_err("rejected");
        assert!(matches!(err, TurnkeyXrpError::Rejected { .. }));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn wrong_chain_rejected() {
        let turnkey = Arc::new(StubTurnkey {
            on_sign: completed_with_sig(),
            on_get: completed_with_sig(),
        });
        let prepare = Arc::new(InMemoryPrepareStore::new());
        let exec = TurnkeyXrpRedeemExecutor::new(config(), turnkey, prepare);
        let mut t = task();
        t.chain = ChainId::Btc;
        let err = exec
            .execute_leg(&t, &vault(), 7, 9_000_075)
            .await
            .expect_err("wrong chain");
        assert!(matches!(err, TurnkeyXrpError::WrongChain(ChainId::Btc)));
    }
}
