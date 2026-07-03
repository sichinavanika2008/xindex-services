//! Solana redeem leg under Turnkey enclave custody (`DL-CUSTODY-TURNKEY-1`).
//!
//! The Turnkey replacement for the Squads V4 program-multisig choreography
//! ([`crate::solana_redeem`]). Under Turnkey the Solana custody key is a single
//! **ed25519** enclave key (the first ed25519 custody family), so a redeem is a
//! single legacy transaction — a native-SOL `System::transfer` from the custody
//! key to the `THORChain` Solana inbound, plus an SPL-Memo instruction carrying
//! the swap memo — signed ONCE, NOT a propose→approve→execute choreography.
//!
//! ed25519 signs the FULL serialized message bytes (no pre-hash), so Turnkey
//! signs the message bytes via `SIGN_RAW_PAYLOAD` (`HASH_FUNCTION_NO_OP`); the
//! 64-byte ed25519 signature comes back as `R ‖ S` (see
//! [`xindex_turnkey_client::SignRawPayloadResult::ed25519_sig`]). The flow:
//!
//! 1. Build the legacy message `[transfer(custody → vault, lamports), memo]`
//!    (custody key = fee payer + sole signer), with the live `recent_blockhash`.
//! 2. Serialize it — those bytes ARE the signing payload.
//! 3. Store the prepared spend in the SHARED prepare store keyed by the message
//!    -bytes hex — the approver binds destination/amount/memo to the k-of-n RIC
//!    (Solana reuses the account-family decision core: the bind is
//!    `keccak256(to_address)`-based and chain-agnostic).
//! 4. `sign_raw_payload(payload = message_bytes)` → consensus → 64-byte sig.
//! 5. Wrap `shortvec(1) ‖ sig ‖ message` into the broadcast tx and return it;
//!    the binary submits via `SolanaChainClient::send_transaction`.
//!
//! ## Replay one-shot (the Solana-specific nuance)
//!
//! `spend_identity` = `keccak256(message_bytes)`, a per-transaction value (TK-03).
//! Like EVM's nonce / Cosmos+XRP's sequence / TRON's `txID`, it must differ for
//! any two distinct signable messages so the RIC one-shot rejects a re-drive: a
//! Solana message varies by `recent_blockhash`, so a CONSTANT identity (e.g. the
//! redemption id) would make two distinct blockhash messages share one identity
//! and both pass the `Idempotent→Ok` one-shot — a double-spend. Hashing the
//! message bytes makes the certificate strictly single-message per redemption.
//! Tighter on-chain replay binding (a durable-nonce account, or a Solana CTD-1
//! light-client proof) is post-v1 — `KNOWN_FINDINGS` P-SOL-7; Solana is not in
//! mainnet v1 scope.
//!
//! Fail-closed: a rejected/failed activity ⇒ no signature ⇒ no tx.

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::B256;
use thiserror::Error;
use tracing::{debug, info};

use xindex_custody_core::prepare::{AccountPrepared, AccountSigning, PrepareStore, PreparedSpend};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::IntentProof;
use xindex_solana_tx::message::{build_transfer_message, serialize_transaction};
use xindex_solana_tx::{Pubkey, SolanaTxError};
use xindex_turnkey_client::{Activity, SignRawPayloadParams, TurnkeyApi};

/// A Solana redeem leg awaiting a Turnkey single-key signature.
#[derive(Debug, Clone)]
pub struct TurnkeySolanaRedeemTask {
    /// Per-adapter dispatch id (broadcast registry key).
    pub dispatch_id: B256,
    /// `IntentQueue` redemption id (correlation key + RIC one-shot identity).
    pub redemption_id: B256,
    /// Destination chain (Solana family).
    pub chain: ChainId,
    /// `THORChain` swap memo, trusted verbatim from the contract event.
    pub memo: String,
    /// Native send amount in lamports.
    pub send_amount: u128,
    /// CTD-1 (`DL-CTD-2`): the leg's k-of-n RIC proof, attached by the binary
    /// (Slice B). `None` is forwarded as-is and refused at the approver.
    pub intent_proof: Option<IntentProof>,
}

/// Errors surfaced by the Turnkey Solana redeem executor.
#[derive(Debug, Error)]
pub enum TurnkeySolanaError {
    /// The task's chain is not this executor's Solana chain.
    #[error("ChainId {0:?} is not this executor's Solana chain")]
    WrongChain(ChainId),
    /// The send amount did not fit `u64` lamports.
    #[error("out-of-range numeric: {0}")]
    Numeric(String),
    /// Building / serializing the transaction failed (bad vault address, etc.).
    #[error("solana tx: {0}")]
    Solana(#[from] SolanaTxError),
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
}

/// Static per-executor configuration. One executor per Turnkey custody key.
#[derive(Debug, Clone)]
pub struct TurnkeySolanaRedeemConfig {
    /// The Solana custody chain this executor serves.
    pub chain: ChainId,
    /// The 32-byte ed25519 custody public key (the fee payer + transfer source
    /// + sole signer). Its base58 form is the custody address.
    pub custody_pubkey: [u8; 32],
    /// The Turnkey `signWith` selector (private-key id / wallet-account
    /// address) for this custody key.
    pub sign_with: String,
    /// Delay between activity status polls.
    pub poll_interval: Duration,
    /// Max status polls before [`TurnkeySolanaError::PollTimeout`].
    pub poll_max_attempts: u32,
}

/// Turnkey Solana redeem executor. Builds + signs (via Turnkey, gated by the
/// approver) + assembles the signed transaction; returns it for the caller to
/// submit. Performs NO chain I/O — the `recent_blockhash` is caller-supplied
/// (mirrors [`crate::turnkey_evm_redeem`]).
pub struct TurnkeySolanaRedeemExecutor<T, P> {
    config: TurnkeySolanaRedeemConfig,
    turnkey: Arc<T>,
    prepare: Arc<P>,
}

impl<T, P> std::fmt::Debug for TurnkeySolanaRedeemExecutor<T, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnkeySolanaRedeemExecutor")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// The result of a completed Turnkey Solana redeem leg.
#[derive(Debug, Clone)]
pub struct TurnkeySolanaRedeemOutcome {
    /// Destination chain (for the dispatch-store `chain` column).
    pub chain: ChainId,
    /// Broadcast-ready signed transaction (`shortvec(1) ‖ sig ‖ message`).
    pub signed_tx: Vec<u8>,
    /// The serialized message bytes the custody key signed (also the
    /// prepare-store key, hex-encoded).
    pub message_bytes: Vec<u8>,
    /// Originating dispatch id (broadcast registry key).
    pub dispatch_id: B256,
    /// Originating redemption id (attestation correlation).
    pub redemption_id: B256,
    /// The Turnkey signing activity id.
    pub activity_id: String,
}

impl<T: TurnkeyApi, P: PrepareStore> TurnkeySolanaRedeemExecutor<T, P> {
    /// Construct.
    #[must_use]
    pub fn new(config: TurnkeySolanaRedeemConfig, turnkey: Arc<T>, prepare: Arc<P>) -> Self {
        Self {
            config,
            turnkey,
            prepare,
        }
    }

    /// Borrow the configuration.
    #[must_use]
    pub fn config(&self) -> &TurnkeySolanaRedeemConfig {
        &self.config
    }

    /// Execute one Solana redeem leg through Turnkey: build message → prepare →
    /// sign (gated) → assemble the signed transaction.
    ///
    /// `vault` is the live `THORChain` Solana Asgard inbound (base58 pubkey).
    /// `recent_blockhash` is fetched fresh by the caller (DL-P3.2-7 — no chain
    /// I/O here).
    ///
    /// # Errors
    /// Any [`TurnkeySolanaError`] variant.
    pub async fn execute_leg(
        &self,
        task: &TurnkeySolanaRedeemTask,
        vault: &str,
        recent_blockhash: [u8; 32],
    ) -> Result<TurnkeySolanaRedeemOutcome, TurnkeySolanaError> {
        if task.chain != self.config.chain {
            return Err(TurnkeySolanaError::WrongChain(task.chain));
        }
        let lamports = u64::try_from(task.send_amount).map_err(|_| {
            TurnkeySolanaError::Numeric(format!("amount > u64 lamports: {}", task.send_amount))
        })?;
        let from = Pubkey::new(self.config.custody_pubkey);
        let destination = Pubkey::from_base58(vault)?;

        let (_message, message_bytes) =
            build_transfer_message(from, destination, lamports, &task.memo, recent_blockhash)?;
        let payload_hex = format!("0x{}", alloy_primitives::hex::encode(&message_bytes));

        // Persist the prepared spend keyed by the message bytes BEFORE signing —
        // the approver binds destination/amount/memo to the RIC and fail-closes
        // on a missing context. spend_identity = keccak256(message) — a per-tx
        // one-shot key so a different-blockhash re-drive conflicts (TK-03).
        let spend_identity = alloy_primitives::keccak256(&message_bytes).to_vec();
        self.prepare
            .put(
                payload_hex.clone(),
                PreparedSpend::Account(AccountPrepared {
                    chain: self.config.chain,
                    to_address: vault.to_string(),
                    amount_dec: lamports.to_string(),
                    memo: task.memo.clone(),
                    signing: AccountSigning::Solana {
                        from_pubkey: self.config.custody_pubkey,
                        recent_blockhash,
                    },
                    ric: task.intent_proof.clone(),
                    spend_identity,
                }),
            )
            .await
            .map_err(|e| TurnkeySolanaError::Prepare(e.to_string()))?;

        let activity = self
            .turnkey
            .sign_raw_payload(&SignRawPayloadParams::hex_no_op(
                &self.config.sign_with,
                &payload_hex,
            ))
            .await
            .map_err(|e| TurnkeySolanaError::Turnkey(e.to_string()))?;
        let completed = self.await_signature(activity).await?;
        let result = completed
            .sign_result()
            .ok_or_else(|| TurnkeySolanaError::NoSignature {
                activity_id: completed.id.clone(),
            })?;
        let sig = result
            .ed25519_sig()
            .map_err(|e| TurnkeySolanaError::Turnkey(e.to_string()))?;
        let signed_tx = serialize_transaction(&message_bytes, &[sig])?;

        info!(
            redemption_id = %task.redemption_id,
            activity = %completed.id,
            "Solana redeem tx signed (Turnkey); ready to submit"
        );
        Ok(TurnkeySolanaRedeemOutcome {
            chain: self.config.chain,
            signed_tx,
            message_bytes,
            dispatch_id: task.dispatch_id,
            redemption_id: task.redemption_id,
            activity_id: completed.id,
        })
    }

    /// Poll the signing activity to a signature. Fail-closed on reject /
    /// failure / timeout.
    async fn await_signature(&self, activity: Activity) -> Result<Activity, TurnkeySolanaError> {
        let mut current = activity;
        for _ in 0..self.config.poll_max_attempts {
            if current.status.is_completed() {
                return Ok(current);
            }
            if current.status.is_terminal() {
                return Err(TurnkeySolanaError::Rejected {
                    activity_id: current.id,
                });
            }
            debug!(activity = %current.id, status = ?current.status, "awaiting consensus");
            tokio::time::sleep(self.config.poll_interval).await;
            current = self
                .turnkey
                .get_activity(&current.id)
                .await
                .map_err(|e| TurnkeySolanaError::Turnkey(e.to_string()))?;
        }
        Err(TurnkeySolanaError::PollTimeout {
            activity_id: current.id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xindex_custody_core::prepare::InMemoryPrepareStore;
    use xindex_turnkey_client::TurnkeyError;

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

    fn config() -> TurnkeySolanaRedeemConfig {
        TurnkeySolanaRedeemConfig {
            chain: ChainId::Sol,
            custody_pubkey: [0x07; 32],
            sign_with: "custody-key".to_string(),
            poll_interval: Duration::ZERO,
            poll_max_attempts: 5,
        }
    }

    fn task() -> TurnkeySolanaRedeemTask {
        TurnkeySolanaRedeemTask {
            dispatch_id: B256::repeat_byte(0xd1),
            redemption_id: B256::repeat_byte(0xd2),
            chain: ChainId::Sol,
            memo: "=:ETH.USDT:0xrecipient:990000".to_string(),
            send_amount: 5_000_000_000,
            intent_proof: None,
        }
    }

    fn vault() -> String {
        Pubkey::new([0x22; 32]).to_base58()
    }

    fn completed_with_sig() -> Activity {
        #[expect(clippy::expect_used, reason = "test code")]
        serde_json::from_value(serde_json::json!({
            "id": "act-1", "status": "ACTIVITY_STATUS_COMPLETED",
            "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", "fingerprint": "fp-1",
            "result": { "signRawPayloadResult": {
                "r": &"11".repeat(32), "s": &"22".repeat(32), "v": ""
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
        let exec = TurnkeySolanaRedeemExecutor::new(config(), turnkey, Arc::clone(&prepare));
        let outcome = exec
            .execute_leg(&task(), &vault(), [0x33; 32])
            .await
            .expect("leg");
        assert_eq!(outcome.activity_id, "act-1");
        // Signed tx = shortvec(1) ‖ 64-byte sig ‖ message.
        assert_eq!(outcome.signed_tx[0], 1, "one signature");
        assert_eq!(&outcome.signed_tx[1..33], &[0x11; 32], "sig R half");
        assert_eq!(&outcome.signed_tx[33..65], &[0x22; 32], "sig S half");
        assert_eq!(&outcome.signed_tx[65..], &outcome.message_bytes[..]);
        // Prepared spend keyed by the message-bytes hex.
        let key = format!(
            "0x{}",
            alloy_primitives::hex::encode(&outcome.message_bytes)
        );
        let stored = prepare.get(&key).await.expect("get");
        assert!(
            matches!(&stored, Some(PreparedSpend::Account(_))),
            "expected Account, got {stored:?}"
        );
        if let Some(PreparedSpend::Account(a)) = stored {
            assert_eq!(a.to_address, vault());
            assert_eq!(a.amount_dec, "5000000000");
            // TK-03: spend_identity = keccak256(message) — a per-tx one-shot key
            // (varies with recent_blockhash), NOT the constant redemption id.
            assert_eq!(
                a.spend_identity,
                alloy_primitives::keccak256(&outcome.message_bytes).to_vec()
            );
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
        let exec = TurnkeySolanaRedeemExecutor::new(config(), turnkey, prepare);
        let err = exec
            .execute_leg(&task(), &vault(), [0x33; 32])
            .await
            .expect_err("rejected");
        assert!(matches!(err, TurnkeySolanaError::Rejected { .. }));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn wrong_chain_rejected() {
        let turnkey = Arc::new(StubTurnkey {
            on_sign: completed_with_sig(),
            on_get: completed_with_sig(),
        });
        let prepare = Arc::new(InMemoryPrepareStore::new());
        let exec = TurnkeySolanaRedeemExecutor::new(config(), turnkey, prepare);
        let mut t = task();
        t.chain = ChainId::Btc;
        let err = exec
            .execute_leg(&t, &vault(), [0x33; 32])
            .await
            .expect_err("wrong chain");
        assert!(matches!(err, TurnkeySolanaError::WrongChain(ChainId::Btc)));
    }
}
