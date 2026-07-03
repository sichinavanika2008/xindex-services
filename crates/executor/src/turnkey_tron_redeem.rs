//! TRON redeem leg under Turnkey enclave custody (`DL-CUSTODY-TURNKEY-1`).
//!
//! The Turnkey replacement for the account-permission k-of-n multisig flow
//! ([`crate::tron_redeem`]). Under Turnkey the TRON custody key is a single
//! secp256k1 enclave key signing on the account's `Owner` permission
//! (`permission_id = 0`), so a redeem carries one 65-byte recoverable
//! signature. Turnkey is a RAW signer — *we* build the `raw_data`, compute its
//! `txID = SHA-256(raw_data)`; Turnkey signs that hash via `SIGN_RAW_PAYLOAD`
//! (gated by the approver-watcher); *we* assemble the `r‖s‖v` signature and the
//! broadcast `Transaction` protobuf. The flow:
//!
//! 1. Build the `raw_data` protobuf (TRX `TransferContract` or TRC20
//!    `TriggerSmartContract`) with the live TAPOS block reference.
//! 2. Compute `txID = SHA-256(raw_data)`.
//! 3. Store the prepared spend in the SHARED prepare store keyed by the `txID`
//!    hex — the approver binds destination/amount/memo to the k-of-n RIC.
//! 4. `sign_raw_payload(payload = txID)` → consensus → `r,s,v`.
//! 5. Assemble the 65-byte recoverable signature (`r‖s‖v`, `v` the 0/1 recovery
//!    id) and the signed `Transaction`, return its hex; the binary broadcasts
//!    via `TronChainClient::broadcast_hex` (mirrors [`crate::tron_redeem`]).
//!
//! Fail-closed: a rejected/failed activity ⇒ no signature ⇒ no tx.

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::B256;
use thiserror::Error;
use tracing::{debug, info};

use xindex_chain_tron::TronBlockRef;
use xindex_custody_core::prepare::{AccountPrepared, AccountSigning, PrepareStore, PreparedSpend};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::TronAssetKind;
use xindex_tron_tx::addr::{decode_base58check, decode_to_evm20};
use xindex_tron_tx::tx::{
    build_signed_transaction, build_trx_raw_data, build_usdt_raw_data, txid, Tapos, TrxTransfer,
    UsdtTransfer,
};
use xindex_turnkey_client::{Activity, SignRawPayloadParams, TurnkeyApi};

use crate::tron_redeem::TronRedeemTask;

/// Errors surfaced by the Turnkey TRON redeem executor.
#[derive(Debug, Error)]
pub enum TurnkeyTronError {
    /// The task's chain is not this executor's TRON chain.
    #[error("ChainId {0:?} is not this executor's TRON chain")]
    WrongChain(ChainId),
    /// A configured `T…` address (owner / vault / contract) did not decode.
    #[error("address: {0}")]
    Address(String),
    /// An amount did not fit its on-wire width.
    #[error("out-of-range numeric: {0}")]
    Numeric(String),
    /// USDT leg config is missing the TRC20 contract address.
    #[error("USDT leg requires a contract_address")]
    MissingContract,
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

/// Static per-executor configuration. One executor per (custody key, asset).
#[derive(Debug, Clone)]
pub struct TurnkeyTronRedeemConfig {
    /// The TRON custody chain this executor serves.
    pub chain: ChainId,
    /// The Turnkey `signWith` selector (private-key id / wallet-account
    /// address) for the custody key.
    pub sign_with: String,
    /// The base58check `T…` custody account address (`owner_address`). The
    /// caller derives it from the Turnkey key; they must agree.
    pub owner_address: String,
    /// Which asset this executor moves (TRX or TRC20 USDT).
    pub asset: TronAssetKind,
    /// `Usdt` only: the TRC20 contract address (`T…`).
    pub contract_address: Option<String>,
    /// `Usdt` only: the `fee_limit` (energy cap) in `sun`.
    pub fee_limit: u64,
    /// Milliseconds added to the block timestamp for `expiration` (the TAPOS
    /// deadline window).
    pub expiration_window_ms: u64,
    /// `Contract.Permission_id` — `0` (Owner permission) for a single Turnkey
    /// key; set to an `Active` permission id only if the key is configured
    /// under one.
    pub permission_id: u32,
    /// Delay between activity status polls.
    pub poll_interval: Duration,
    /// Max status polls before [`TurnkeyTronError::PollTimeout`].
    pub poll_max_attempts: u32,
}

/// Turnkey TRON redeem executor. Builds + signs (via Turnkey, gated by the
/// approver) + assembles the signed `Transaction`; returns its hex for the
/// caller to broadcast. Performs NO chain I/O — the TAPOS block reference is
/// caller-supplied (mirrors [`crate::turnkey_evm_redeem`]).
pub struct TurnkeyTronRedeemExecutor<T, P> {
    config: TurnkeyTronRedeemConfig,
    turnkey: Arc<T>,
    prepare: Arc<P>,
}

impl<T, P> std::fmt::Debug for TurnkeyTronRedeemExecutor<T, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnkeyTronRedeemExecutor")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// The result of a completed Turnkey TRON redeem leg.
#[derive(Debug, Clone)]
pub struct TurnkeyTronRedeemOutcome {
    /// Destination chain (for the dispatch-store `chain` column).
    pub chain: ChainId,
    /// Broadcast-ready signed `Transaction` protobuf, hex-encoded (no `0x`).
    pub tx_hex: String,
    /// The `txID` (`0x`-prefixed) — the dispatch `inbound_txid` + prepare key.
    pub txid: String,
    /// Originating dispatch id (broadcast registry key).
    pub dispatch_id: B256,
    /// Originating redemption id (attestation correlation).
    pub redemption_id: B256,
    /// The Turnkey signing activity id.
    pub activity_id: String,
}

impl<T: TurnkeyApi, P: PrepareStore> TurnkeyTronRedeemExecutor<T, P> {
    /// Construct. Rejects a USDT config without a contract address.
    ///
    /// # Errors
    /// [`TurnkeyTronError::MissingContract`] for a USDT config with no
    /// `contract_address`.
    pub fn new(
        config: TurnkeyTronRedeemConfig,
        turnkey: Arc<T>,
        prepare: Arc<P>,
    ) -> Result<Self, TurnkeyTronError> {
        if config.asset == TronAssetKind::Usdt && config.contract_address.is_none() {
            return Err(TurnkeyTronError::MissingContract);
        }
        Ok(Self {
            config,
            turnkey,
            prepare,
        })
    }

    /// Borrow the configuration.
    #[must_use]
    pub fn config(&self) -> &TurnkeyTronRedeemConfig {
        &self.config
    }

    /// Execute one TRON redeem leg through Turnkey: build `raw_data` → txID →
    /// prepare → sign (gated) → assemble the signed `Transaction`.
    ///
    /// `vault` is the live `THORChain` TRON Asgard inbound (`T…`). `block` is
    /// the current TAPOS block reference, fetched fresh by the caller
    /// (DL-P3.2-7 — no chain I/O here).
    ///
    /// # Errors
    /// Any [`TurnkeyTronError`] variant.
    pub async fn execute_leg(
        &self,
        task: &TronRedeemTask,
        vault: &str,
        block: &TronBlockRef,
    ) -> Result<TurnkeyTronRedeemOutcome, TurnkeyTronError> {
        if task.chain != self.config.chain {
            return Err(TurnkeyTronError::WrongChain(task.chain));
        }

        let expiration = block
            .timestamp_ms
            .saturating_add(self.config.expiration_window_ms);
        let amount = u64::try_from(task.send_amount).map_err(|_| {
            TurnkeyTronError::Numeric(format!("amount > u64: {}", task.send_amount))
        })?;
        let owner = decode_base58check(&self.config.owner_address)
            .map_err(|e| TurnkeyTronError::Address(format!("owner {e}")))?;

        // TRX carries no energy fee; a TRC20 trigger caps energy at fee_limit.
        // Record the SAME effective value the approver must reconstruct.
        let effective_fee_limit = match self.config.asset {
            TronAssetKind::Trx => 0,
            TronAssetKind::Usdt => self.config.fee_limit,
        };
        let raw_data = match self.config.asset {
            TronAssetKind::Trx => {
                let to = decode_base58check(vault)
                    .map_err(|e| TurnkeyTronError::Address(format!("vault {e}")))?;
                let tapos = self.tapos(block, expiration, effective_fee_limit);
                build_trx_raw_data(&TrxTransfer { owner, to, amount }, &tapos)
            }
            TronAssetKind::Usdt => {
                let contract_str = self
                    .config
                    .contract_address
                    .as_deref()
                    .ok_or(TurnkeyTronError::MissingContract)?;
                let contract = decode_base58check(contract_str)
                    .map_err(|e| TurnkeyTronError::Address(format!("contract {e}")))?;
                let to_evm20 = decode_to_evm20(vault)
                    .map_err(|e| TurnkeyTronError::Address(format!("vault {e}")))?;
                let tapos = self.tapos(block, expiration, effective_fee_limit);
                build_usdt_raw_data(
                    &UsdtTransfer {
                        owner,
                        contract,
                        to_evm20,
                        amount,
                    },
                    &tapos,
                )
            }
        };

        let tx_id = txid(&raw_data);
        let payload_hex = format!("0x{}", alloy_primitives::hex::encode(tx_id));

        // Persist the prepared spend keyed by the txID BEFORE signing — the
        // approver binds destination/amount/memo to the RIC and fail-closes on
        // a missing context. spend_identity = the txID (TRON has no account
        // nonce; the txID is the one-shot identity).
        self.prepare
            .put(
                payload_hex.clone(),
                PreparedSpend::Account(AccountPrepared {
                    chain: self.config.chain,
                    to_address: vault.to_string(),
                    amount_dec: amount.to_string(),
                    memo: task.memo.clone(),
                    signing: self.tron_signing(block, expiration, effective_fee_limit),
                    ric: task.intent_proof.clone(),
                    spend_identity: tx_id.to_vec(),
                }),
            )
            .await
            .map_err(|e| TurnkeyTronError::Prepare(e.to_string()))?;

        let activity = self
            .turnkey
            .sign_raw_payload(&SignRawPayloadParams::hex_no_op(
                &self.config.sign_with,
                &payload_hex,
            ))
            .await
            .map_err(|e| TurnkeyTronError::Turnkey(e.to_string()))?;
        let completed = self.await_signature(activity).await?;
        let result = completed
            .sign_result()
            .ok_or_else(|| TurnkeyTronError::NoSignature {
                activity_id: completed.id.clone(),
            })?;
        let (r, s, v) = result
            .rsv()
            .map_err(|e| TurnkeyTronError::Turnkey(e.to_string()))?;
        let sig65 = assemble_recoverable(r, s, v);
        let tx_bytes = build_signed_transaction(&raw_data, &[sig65]);

        info!(
            redemption_id = %task.redemption_id,
            activity = %completed.id,
            txid = %payload_hex,
            "TRON redeem tx signed (Turnkey); ready to broadcast"
        );
        Ok(TurnkeyTronRedeemOutcome {
            chain: self.config.chain,
            tx_hex: alloy_primitives::hex::encode(&tx_bytes),
            txid: payload_hex,
            dispatch_id: task.dispatch_id,
            redemption_id: task.redemption_id,
            activity_id: completed.id,
        })
    }

    /// The approver's TRON reconstruction inputs (TK-01/TK-02) — must mirror the
    /// exact TAPOS + asset fields used to build `raw_data`.
    fn tron_signing(
        &self,
        block: &TronBlockRef,
        expiration: u64,
        fee_limit: u64,
    ) -> AccountSigning {
        AccountSigning::Tron {
            owner_address: self.config.owner_address.clone(),
            asset: self.config.asset,
            contract_address: self.config.contract_address.clone(),
            ref_block_bytes: block.ref_block_bytes,
            ref_block_hash: block.ref_block_hash,
            expiration,
            timestamp: block.timestamp_ms,
            fee_limit,
            permission_id: self.config.permission_id,
        }
    }

    /// Build the shared TAPOS envelope from the block reference.
    fn tapos(&self, block: &TronBlockRef, expiration: u64, fee_limit: u64) -> Tapos {
        Tapos {
            ref_block_bytes: block.ref_block_bytes,
            ref_block_hash: block.ref_block_hash,
            expiration,
            timestamp: block.timestamp_ms,
            fee_limit,
            memo: Vec::new(),
            permission_id: self.config.permission_id,
        }
    }

    /// Poll the signing activity to a signature. Fail-closed on reject /
    /// failure / timeout.
    async fn await_signature(&self, activity: Activity) -> Result<Activity, TurnkeyTronError> {
        let mut current = activity;
        for _ in 0..self.config.poll_max_attempts {
            if current.status.is_completed() {
                return Ok(current);
            }
            if current.status.is_terminal() {
                return Err(TurnkeyTronError::Rejected {
                    activity_id: current.id,
                });
            }
            debug!(activity = %current.id, status = ?current.status, "awaiting consensus");
            tokio::time::sleep(self.config.poll_interval).await;
            current = self
                .turnkey
                .get_activity(&current.id)
                .await
                .map_err(|e| TurnkeyTronError::Turnkey(e.to_string()))?;
        }
        Err(TurnkeyTronError::PollTimeout {
            activity_id: current.id,
        })
    }
}

/// Assemble the 65-byte TRON recoverable signature `r ‖ s ‖ v`. Turnkey
/// returns `v` as the 0/1 recovery id (`SIGN_RAW_PAYLOAD`); a `27/28` form is
/// normalized to `0/1` (java-tron accepts either, but `0/1` is the canonical
/// wire form `tron-tx` produces). RECONCILE AT DEV-ENV: confirm Turnkey's
/// recovery-id convention for secp256k1 raw payloads.
fn assemble_recoverable(r: [u8; 32], s: [u8; 32], v: u8) -> [u8; 65] {
    let recid = if v >= 27 { v - 27 } else { v };
    let mut sig = [0u8; 65];
    sig[..32].copy_from_slice(&r);
    sig[32..64].copy_from_slice(&s);
    sig[64] = recid;
    sig
}

#[cfg(test)]
mod tests {
    use super::*;
    use xindex_custody_core::prepare::InMemoryPrepareStore;
    use xindex_tron_tx::addr::pubkey_to_address;
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

    fn pubkey(seed: u8) -> [u8; 33] {
        #[expect(clippy::expect_used, reason = "test code")]
        let sk = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("key");
        let ep = sk.verifying_key().to_encoded_point(true);
        let mut pk = [0u8; 33];
        pk.copy_from_slice(ep.as_bytes());
        pk
    }

    fn config() -> TurnkeyTronRedeemConfig {
        #[expect(clippy::expect_used, reason = "test code")]
        let owner = pubkey_to_address(&pubkey(50)).expect("owner");
        TurnkeyTronRedeemConfig {
            chain: ChainId::Tron,
            sign_with: "custody-key".to_string(),
            owner_address: owner,
            asset: TronAssetKind::Trx,
            contract_address: None,
            fee_limit: 0,
            expiration_window_ms: 1_200_000,
            permission_id: 0,
            poll_interval: Duration::ZERO,
            poll_max_attempts: 5,
        }
    }

    fn vault() -> String {
        #[expect(clippy::expect_used, reason = "test code")]
        pubkey_to_address(&pubkey(60)).expect("vault")
    }

    fn block() -> TronBlockRef {
        TronBlockRef {
            number: 176,
            ref_block_bytes: [0x00, 0xb0],
            ref_block_hash: [0x3f, 0x1b, 0xc9, 0x6d, 0xc8, 0x0e, 0x7f, 0x61],
            timestamp_ms: 1_548_974_072_663,
        }
    }

    fn task() -> TronRedeemTask {
        TronRedeemTask {
            dispatch_id: B256::repeat_byte(0xd1),
            redemption_id: B256::repeat_byte(0xd2),
            chain: ChainId::Tron,
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
                "r": &"11".repeat(32), "s": &"22".repeat(32), "v": "01"
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
        let exec =
            TurnkeyTronRedeemExecutor::new(config(), turnkey, Arc::clone(&prepare)).expect("exec");
        let outcome = exec
            .execute_leg(&task(), &vault(), &block())
            .await
            .expect("leg");
        assert_eq!(outcome.activity_id, "act-1");
        assert!(outcome.txid.starts_with("0x"));
        // Signed Transaction: raw_data (field 1) tag 0x0a, one signature
        // (field 2) block 0x12 0x41.
        let tx = alloy_primitives::hex::decode(&outcome.tx_hex).expect("hex");
        assert_eq!(tx[0], 0x0a);
        let sig_fields = tx.windows(2).filter(|w| *w == b"\x12\x41").count();
        assert_eq!(sig_fields, 1, "single Turnkey signature");
        // Prepared spend keyed by the txID.
        let stored = prepare.get(&outcome.txid).await.expect("get");
        assert!(
            matches!(&stored, Some(PreparedSpend::Account(_))),
            "expected Account, got {stored:?}"
        );
        if let Some(PreparedSpend::Account(a)) = stored {
            assert_eq!(a.to_address, vault());
            assert_eq!(a.amount_dec, "5000000");
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
        let exec = TurnkeyTronRedeemExecutor::new(config(), turnkey, prepare).expect("exec");
        let err = exec
            .execute_leg(&task(), &vault(), &block())
            .await
            .expect_err("rejected");
        assert!(matches!(err, TurnkeyTronError::Rejected { .. }));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn wrong_chain_rejected() {
        let turnkey = Arc::new(StubTurnkey {
            on_sign: completed_with_sig(),
            on_get: completed_with_sig(),
        });
        let prepare = Arc::new(InMemoryPrepareStore::new());
        let exec = TurnkeyTronRedeemExecutor::new(config(), turnkey, prepare).expect("exec");
        let mut t = task();
        t.chain = ChainId::Xrp;
        let err = exec
            .execute_leg(&t, &vault(), &block())
            .await
            .expect_err("wrong chain");
        assert!(matches!(err, TurnkeyTronError::WrongChain(ChainId::Xrp)));
    }

    #[test]
    fn assemble_recoverable_normalizes_v() {
        let r = [0x11u8; 32];
        let s = [0x22u8; 32];
        assert_eq!(assemble_recoverable(r, s, 0)[64], 0);
        assert_eq!(assemble_recoverable(r, s, 1)[64], 1);
        assert_eq!(assemble_recoverable(r, s, 27)[64], 0);
        assert_eq!(assemble_recoverable(r, s, 28)[64], 1);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn missing_contract_rejected_for_usdt() {
        let turnkey = Arc::new(StubTurnkey {
            on_sign: completed_with_sig(),
            on_get: completed_with_sig(),
        });
        let prepare = Arc::new(InMemoryPrepareStore::new());
        let mut cfg = config();
        cfg.asset = TronAssetKind::Usdt;
        cfg.contract_address = None;
        let err = TurnkeyTronRedeemExecutor::new(cfg, turnkey, prepare).expect_err("construct");
        assert!(matches!(err, TurnkeyTronError::MissingContract));
    }
}
