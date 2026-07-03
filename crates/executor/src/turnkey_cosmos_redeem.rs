//! Cosmos redeem leg under Turnkey enclave custody (`DL-CUSTODY-TURNKEY-1`).
//!
//! The Turnkey replacement for the 3-of-5 `LegacyAminoPubKey` multisig flow
//! ([`crate::cosmos_redeem`]). Under Turnkey the Cosmos custody key is a single
//! secp256k1 enclave key, so the account is an ordinary single-sig account (not
//! a threshold multisig). Turnkey is a RAW signer — *we* build the `MsgSend`,
//! compute its `SIGN_MODE_LEGACY_AMINO_JSON` `SHA-256` sign-bytes; Turnkey signs
//! that hash via `SIGN_RAW_PAYLOAD` (gated by the approver-watcher); *we*
//! assemble the single-sig `TxRaw` and broadcast. The flow:
//!
//! 1. Build the amino `StdSignDoc` for the `MsgSend` (identical to the multisig
//!    path — the sign-bytes do not depend on the pubkey/`AuthInfo`).
//! 2. Compute its `SHA-256` sign-bytes (`account/sequence` caller-supplied).
//! 3. Store the prepared spend in the SHARED prepare store keyed by the sign
//!    -bytes hex — the approver looks it up by the activity payload and binds it
//!    to the k-of-n RIC.
//! 4. `sign_raw_payload(payload = sign_bytes)` → consensus → `r,s`.
//! 5. Assemble the single-sig `TxRaw` (secp256k1 `PubKey` `Any`, `Single`
//!    `AMINO_JSON` mode, the raw 64-byte compact low-S signature) and return the
//!    bytes; the binary broadcasts via `CosmosChainClient::broadcast_tx_sync`
//!    (mirrors [`crate::cosmos_redeem`], which also returns rather than submits).
//!
//! Fail-closed: a rejected/failed activity ⇒ no signature ⇒ no `TxRaw`.

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::B256;
use thiserror::Error;
use tracing::{debug, info};

use xindex_cosmos_tx::amino::CosmosSendSignDoc;
use xindex_cosmos_tx::sigs::to_cosmos_compact_low_s;
use xindex_cosmos_tx::tx::{build_single_sig_tx_raw, CosmosTxParams};
use xindex_custody_core::prepare::{AccountPrepared, AccountSigning, PrepareStore, PreparedSpend};
use xindex_shared::chain_registry::ChainId;
use xindex_turnkey_client::{Activity, SignRawPayloadParams, TurnkeyApi};

use crate::cosmos_redeem::CosmosRedeemTask;

/// Errors surfaced by the Turnkey Cosmos redeem executor.
#[derive(Debug, Error)]
pub enum TurnkeyCosmosError {
    /// The task's chain is not this executor's Cosmos chain.
    #[error("ChainId {0:?} is not this executor's Cosmos chain")]
    WrongChain(ChainId),
    /// Amino sign-doc construction failed (non-canonical numeric field).
    #[error("amino sign-bytes: {0}")]
    Amino(String),
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
    /// Assembling the 64-byte compact low-S signature from `(r, s)` failed.
    #[error("signature assembly: {0}")]
    Signature(String),
}

/// Static per-executor configuration. One executor per Turnkey custody key.
#[derive(Debug, Clone)]
pub struct TurnkeyCosmosRedeemConfig {
    /// The Cosmos custody chain this executor serves (`Gaia` first).
    pub chain: ChainId,
    /// The bech32 single-key custody account address (`MsgSend.from_address`).
    /// The caller derives it from `custody_pubkey`; they must agree.
    pub account_address: String,
    /// The compressed (33-byte) secp256k1 custody public key (the
    /// `SignerInfo.public_key`).
    pub custody_pubkey: [u8; 33],
    /// The Turnkey `signWith` selector (private-key id / wallet-account
    /// address) for this custody key.
    pub sign_with: String,
    /// Consensus chain-id bound into the sign-bytes (`"cosmoshub-4"`).
    pub cosmos_chain_id: String,
    /// Native micro-denom (`"uatom"`).
    pub denom: String,
    /// Fee amount in the micro-unit (caller-supplied per DL-P3.2-7).
    pub fee_amount: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Delay between activity status polls.
    pub poll_interval: Duration,
    /// Max status polls before [`TurnkeyCosmosError::PollTimeout`].
    pub poll_max_attempts: u32,
}

/// Turnkey Cosmos redeem executor. Builds + signs (via Turnkey, gated by the
/// approver) + assembles the single-sig `TxRaw`; returns it for the caller to
/// broadcast. Performs NO chain I/O — `account_number` / `sequence` are
/// caller-supplied (mirrors [`crate::turnkey_evm_redeem`]).
pub struct TurnkeyCosmosRedeemExecutor<T, P> {
    config: TurnkeyCosmosRedeemConfig,
    turnkey: Arc<T>,
    prepare: Arc<P>,
}

impl<T, P> std::fmt::Debug for TurnkeyCosmosRedeemExecutor<T, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnkeyCosmosRedeemExecutor")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// The result of a completed Turnkey Cosmos redeem leg.
#[derive(Debug, Clone)]
pub struct TurnkeyCosmosRedeemOutcome {
    /// Destination chain (for the dispatch-store `chain` column).
    pub chain: ChainId,
    /// Broadcast-ready proto `TxRaw` bytes.
    pub tx_raw: Vec<u8>,
    /// The 32-byte amino sign-bytes digest the custody key signed (also the
    /// prepare-store key).
    pub sign_doc_hash: [u8; 32],
    /// Account sequence consumed by this leg.
    pub sequence: u64,
    /// Originating dispatch id (broadcast registry key).
    pub dispatch_id: B256,
    /// Originating redemption id (attestation correlation).
    pub redemption_id: B256,
    /// The Turnkey signing activity id.
    pub activity_id: String,
}

impl<T: TurnkeyApi, P: PrepareStore> TurnkeyCosmosRedeemExecutor<T, P> {
    /// Construct.
    #[must_use]
    pub fn new(config: TurnkeyCosmosRedeemConfig, turnkey: Arc<T>, prepare: Arc<P>) -> Self {
        Self {
            config,
            turnkey,
            prepare,
        }
    }

    /// Borrow the configuration.
    #[must_use]
    pub fn config(&self) -> &TurnkeyCosmosRedeemConfig {
        &self.config
    }

    /// Execute one Cosmos redeem leg through Turnkey: build → sign-bytes →
    /// prepare → sign (gated) → assemble the single-sig `TxRaw`.
    ///
    /// `vault` is the live `THORChain` Cosmos Asgard inbound (bech32), resolved
    /// by the caller. `account_number` and `sequence` are fetched fresh by the
    /// caller (DL-P3.2-7 — no chain I/O here).
    ///
    /// # Errors
    /// Any [`TurnkeyCosmosError`] variant.
    pub async fn execute_leg(
        &self,
        task: &CosmosRedeemTask,
        vault: &str,
        account_number: u64,
        sequence: u64,
    ) -> Result<TurnkeyCosmosRedeemOutcome, TurnkeyCosmosError> {
        if task.chain != self.config.chain {
            return Err(TurnkeyCosmosError::WrongChain(task.chain));
        }

        // Canonical-decimal strings shared by the amino doc + the proto TxRaw,
        // built once so they cannot diverge.
        let account_number_dec = account_number.to_string();
        let sequence_dec = sequence.to_string();
        let send_amount_dec = task.send_amount.to_string();
        let fee_amount_dec = self.config.fee_amount.to_string();
        let gas_dec = self.config.gas_limit.to_string();

        let doc = CosmosSendSignDoc {
            account_number: &account_number_dec,
            chain_id: &self.config.cosmos_chain_id,
            fee_amount: &fee_amount_dec,
            gas: &gas_dec,
            memo: &task.memo,
            from_address: &self.config.account_address,
            to_address: vault,
            amount: &send_amount_dec,
            denom: &self.config.denom,
        };
        let digest = doc
            .sign_bytes_sha256(&sequence_dec)
            .map_err(|e| TurnkeyCosmosError::Amino(e.to_string()))?;
        let payload_hex = format!("0x{}", alloy_primitives::hex::encode(digest));

        // Persist the prepared spend keyed by the sign-bytes BEFORE signing —
        // the approver binds destination/amount/memo to the RIC and fail-closes
        // on a missing context. spend_identity = the account sequence (a
        // re-drive advances it → one-shot).
        self.prepare
            .put(
                payload_hex.clone(),
                PreparedSpend::Account(AccountPrepared {
                    chain: self.config.chain,
                    to_address: vault.to_string(),
                    amount_dec: send_amount_dec.clone(),
                    memo: task.memo.clone(),
                    signing: AccountSigning::Cosmos {
                        from_address: self.config.account_address.clone(),
                        cosmos_chain_id: self.config.cosmos_chain_id.clone(),
                        account_number,
                        sequence,
                        denom: self.config.denom.clone(),
                        fee_amount: self.config.fee_amount,
                        gas_limit: self.config.gas_limit,
                    },
                    ric: task.intent_proof.clone(),
                    spend_identity: sequence.to_be_bytes().to_vec(),
                }),
            )
            .await
            .map_err(|e| TurnkeyCosmosError::Prepare(e.to_string()))?;

        let activity = self
            .turnkey
            .sign_raw_payload(&SignRawPayloadParams::hex_no_op(
                &self.config.sign_with,
                &payload_hex,
            ))
            .await
            .map_err(|e| TurnkeyCosmosError::Turnkey(e.to_string()))?;
        let completed = self.await_signature(activity).await?;
        let result = completed
            .sign_result()
            .ok_or_else(|| TurnkeyCosmosError::NoSignature {
                activity_id: completed.id.clone(),
            })?;
        // Cosmos signatures are non-recoverable compact `r ‖ s`; drop `v`.
        let (r, s, _v) = result
            .rsv()
            .map_err(|e| TurnkeyCosmosError::Turnkey(e.to_string()))?;
        let sig64 = to_cosmos_compact_low_s(&r, &s)
            .map_err(|e| TurnkeyCosmosError::Signature(e.to_string()))?;

        let params = CosmosTxParams {
            from_address: &self.config.account_address,
            to_address: vault,
            denom: &self.config.denom,
            send_amount: &send_amount_dec,
            fee_amount: &fee_amount_dec,
            gas_limit: self.config.gas_limit,
            memo: &task.memo,
            sequence,
        };
        let tx_raw = build_single_sig_tx_raw(&self.config.custody_pubkey, &params, &sig64);

        info!(
            redemption_id = %task.redemption_id,
            activity = %completed.id,
            "Cosmos redeem TxRaw signed (Turnkey); ready to broadcast"
        );
        Ok(TurnkeyCosmosRedeemOutcome {
            chain: self.config.chain,
            tx_raw,
            sign_doc_hash: digest,
            sequence,
            dispatch_id: task.dispatch_id,
            redemption_id: task.redemption_id,
            activity_id: completed.id,
        })
    }

    /// Poll the signing activity to a signature. Fail-closed on reject /
    /// failure / timeout.
    async fn await_signature(&self, activity: Activity) -> Result<Activity, TurnkeyCosmosError> {
        let mut current = activity;
        for _ in 0..self.config.poll_max_attempts {
            if current.status.is_completed() {
                return Ok(current);
            }
            if current.status.is_terminal() {
                return Err(TurnkeyCosmosError::Rejected {
                    activity_id: current.id,
                });
            }
            debug!(activity = %current.id, status = ?current.status, "awaiting consensus");
            tokio::time::sleep(self.config.poll_interval).await;
            current = self
                .turnkey
                .get_activity(&current.id)
                .await
                .map_err(|e| TurnkeyCosmosError::Turnkey(e.to_string()))?;
        }
        Err(TurnkeyCosmosError::PollTimeout {
            activity_id: current.id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xindex_custody_core::prepare::InMemoryPrepareStore;
    use xindex_turnkey_client::TurnkeyError;

    /// Stub Turnkey: `sign_raw_payload` returns `on_sign`; `get_activity`
    /// returns `on_get`.
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

    fn config() -> TurnkeyCosmosRedeemConfig {
        let mut pubkey = [0u8; 33];
        pubkey[0] = 0x02;
        pubkey[32] = 0x09;
        TurnkeyCosmosRedeemConfig {
            chain: ChainId::Gaia,
            account_address: "cosmos1custody".to_string(),
            custody_pubkey: pubkey,
            sign_with: "custody-key".to_string(),
            cosmos_chain_id: "cosmoshub-4".to_string(),
            denom: "uatom".to_string(),
            fee_amount: 5_000,
            gas_limit: 200_000,
            poll_interval: Duration::ZERO,
            poll_max_attempts: 5,
        }
    }

    fn task() -> CosmosRedeemTask {
        CosmosRedeemTask {
            dispatch_id: B256::repeat_byte(0xd1),
            redemption_id: B256::repeat_byte(0xd2),
            chain: ChainId::Gaia,
            memo: "=:ETH.USDT:0xrecipient:990000".to_string(),
            send_amount: 5_000_000,
            intent_proof: None,
        }
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
        let exec = TurnkeyCosmosRedeemExecutor::new(config(), turnkey, Arc::clone(&prepare));
        let outcome = exec
            .execute_leg(&task(), "cosmos1asgard", 42, 7)
            .await
            .expect("leg");
        assert_eq!(outcome.activity_id, "act-1");
        assert_eq!(outcome.sequence, 7);
        assert_eq!(outcome.chain, ChainId::Gaia);
        // TxRaw starts with field 1 (body) len-delim tag 0x0a.
        assert_eq!(outcome.tx_raw[0], 0x0a);
        // The prepared spend is keyed by the sign-bytes hex.
        let key = format!("0x{}", alloy_primitives::hex::encode(outcome.sign_doc_hash));
        let stored = prepare.get(&key).await.expect("get");
        assert!(
            matches!(&stored, Some(PreparedSpend::Account(_))),
            "expected Account, got {stored:?}"
        );
        if let Some(PreparedSpend::Account(a)) = stored {
            assert_eq!(a.to_address, "cosmos1asgard");
            assert_eq!(a.amount_dec, "5000000");
            assert_eq!(a.spend_identity, 7u64.to_be_bytes().to_vec());
        }
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn consensus_then_completed_returns_tx() {
        let turnkey = Arc::new(StubTurnkey {
            on_sign: status_activity("ACTIVITY_STATUS_CONSENSUS_NEEDED"),
            on_get: completed_with_sig(),
        });
        let prepare = Arc::new(InMemoryPrepareStore::new());
        let exec = TurnkeyCosmosRedeemExecutor::new(config(), turnkey, prepare);
        let outcome = exec
            .execute_leg(&task(), "cosmos1asgard", 42, 7)
            .await
            .expect("leg");
        assert!(!outcome.tx_raw.is_empty());
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rejected_activity_yields_no_tx() {
        let turnkey = Arc::new(StubTurnkey {
            on_sign: status_activity("ACTIVITY_STATUS_CONSENSUS_NEEDED"),
            on_get: status_activity("ACTIVITY_STATUS_REJECTED"),
        });
        let prepare = Arc::new(InMemoryPrepareStore::new());
        let exec = TurnkeyCosmosRedeemExecutor::new(config(), turnkey, prepare);
        let err = exec
            .execute_leg(&task(), "cosmos1asgard", 42, 7)
            .await
            .expect_err("rejected");
        assert!(matches!(err, TurnkeyCosmosError::Rejected { .. }));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn wrong_chain_rejected() {
        let turnkey = Arc::new(StubTurnkey {
            on_sign: completed_with_sig(),
            on_get: completed_with_sig(),
        });
        let prepare = Arc::new(InMemoryPrepareStore::new());
        let exec = TurnkeyCosmosRedeemExecutor::new(config(), turnkey, prepare);
        let mut t = task();
        t.chain = ChainId::Btc;
        let err = exec
            .execute_leg(&t, "cosmos1asgard", 42, 7)
            .await
            .expect_err("wrong chain");
        assert!(matches!(err, TurnkeyCosmosError::WrongChain(ChainId::Btc)));
    }
}
