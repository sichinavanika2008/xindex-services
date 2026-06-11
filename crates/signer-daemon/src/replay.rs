//! Replay / slashing store (PART 5 / DL-M5-4).
//!
//! The daemon's #1 security primitive after the HSM itself. Refuses to
//! sign a SECOND-DIFFERENT message under the same identity tuple,
//! before the request ever reaches the HSM. Idempotent under exact
//! retry — the same `(tuple, payload_hash)` returns the cached
//! signature bytes verbatim.
//!
//! Same `*Store` AFIT + `InMemory*` + `Sqlite*` shape as
//! [`xindex_shared::redemption_dispatch`] /
//! `xindex-relayer::IntentTrackerStore` /
//! `xindex-executor::BroadcastRegistry`. Static dispatch, no
//! `async-trait` on the trait itself.

use std::collections::HashMap;

use alloy_primitives::{B256, U256};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use thiserror::Error;
use tokio::sync::Mutex;

/// Errors surfaced by the replay store.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// Underlying `sqlx` failure (connect / query / decode).
    #[error("sqlite error: {0}")]
    Sqlite(#[from] sqlx::Error),

    /// Migration application failed.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// Stored row malformed (wrong length / out-of-range integer). Fail
    /// loud — corrupt rows signal data damage that must surface.
    #[error("decode error: {0}")]
    Decode(String),

    /// A concurrent request already recorded this exact identity tuple — the
    /// write-side race the `check_*` pre-flight cannot fully close (two
    /// identical requests both observe `FirstTime`, both sign deterministically,
    /// both attempt to `record_*`). The PK admits exactly one row, so the
    /// second `record_*` surfaces this instead of a generic error; the handler
    /// recovers by re-reading the now-present row and returning the cached
    /// signature idempotently — deterministic ECDSA means the bytes are
    /// identical anyway, so the race-loser never gets a spurious 4xx/5xx
    /// (audit L10).
    #[error("duplicate record (concurrent write race)")]
    Duplicate,
}

/// One previously-signed record. Returned on an idempotent re-query so
/// the daemon can hand back the cached signature without touching the
/// HSM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRecord {
    /// SHA-256 of the canonical request payload bytes.
    pub payload_hash: [u8; 32],
    /// Signature bytes the daemon returned the first time (65 bytes for
    /// EIP-712 secp256k1; variable for PSBT DER).
    pub signature: Vec<u8>,
    /// When the daemon first signed it. Operator-visible.
    pub signed_at_unix: i64,
}

/// Outcome of a "may I sign this?" pre-flight check.
///
/// The handler runs this BEFORE invoking the HSM. If `FirstTime`, the
/// handler proceeds to compute the digest and call the HSM, then
/// `record_*` to commit the result. If `Idempotent`, the cached sig is
/// returned verbatim. If `Conflict`, the daemon refuses with 409 and
/// the HSM is never touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// No prior record for this identity tuple. Caller proceeds to sign.
    FirstTime,
    /// Prior record with the SAME `payload_hash`. Caller returns the
    /// cached signature; the HSM is not invoked again (deterministic
    /// re-sign would yield the same bytes anyway).
    Idempotent(SignedRecord),
    /// Prior record with a DIFFERENT `payload_hash`. The daemon refuses
    /// to sign; the previous payload's hash is included so the operator
    /// can audit the divergence.
    Conflict {
        /// The hash of the payload that was signed first.
        previous_payload_hash: [u8; 32],
        /// When the previous payload was signed.
        previous_signed_at_unix: i64,
    },
}

/// Distinguishes delivery vs refund on the burn side. The
/// `signed_redemptions` table holds at most one row per
/// `(redemption_id, leg_index)` (audit H2); the per-leg
/// delivery-XOR-refund mutex (DL-M5-3) is enforced by the composite PK +
/// this `kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedemptionKind {
    /// Burn → USDT delivery attestation.
    Delivery,
    /// Burn → BTC refund attestation.
    Refund,
    /// Burn → combined streamed-settlement attestation (re-audit-gated
    /// burn-side streaming): a partially-filled streaming redeem swap that
    /// delivered USDT AND refunded native on one leg. A DISTINCT third kind
    /// so the per-leg mutex rejects a `Delivery`/`Refund` after a
    /// `Streamed` (and vice versa) — a streamed leg is one-shot.
    Streamed,
}

impl RedemptionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Delivery => "delivery",
            Self::Refund => "refund",
            Self::Streamed => "streamed",
        }
    }
}

/// Same-tuple conflict that distinguishes the regular
/// same-kind-different-payload vs the burn-side delivery↔refund mutex.
/// Returned by [`ReplayStore::check_redemption`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedemptionCheckOutcome {
    /// First sign for this redemption id (of any kind).
    FirstTime,
    /// Same id + same kind + same `payload_hash` → idempotent.
    Idempotent(SignedRecord),
    /// Same id + same kind + different `payload_hash` → regular conflict.
    Conflict {
        previous_payload_hash: [u8; 32],
        previous_signed_at_unix: i64,
    },
    /// Same id + DIFFERENT kind → delivery↔refund mutex violation.
    /// On-chain this is `IntentQueue_RedemptionAlreadyDelivered` /
    /// `IntentQueue_RedemptionRefundAlreadyAttested`; the daemon
    /// refuses pre-flight.
    MutexViolation {
        /// The kind that was signed first.
        previous_kind: RedemptionKind,
        previous_signed_at_unix: i64,
    },
}

/// Store API. The daemon owns its concurrency via the chosen impl
/// (Mutex / connection pool); callers do NOT wrap.
pub trait ReplayStore: Send + Sync {
    fn check_attestation(
        &self,
        intent_id: B256,
        slot_index: U256,
        payload_hash: [u8; 32],
    ) -> impl std::future::Future<Output = Result<CheckOutcome, ReplayError>> + Send;

    /// Insert a fresh attestation record. Fails with the underlying
    /// uniqueness error if the tuple already exists — the handler
    /// would normally have caught that via [`Self::check_attestation`],
    /// but this is the second line of defense against a race where two
    /// concurrent identical requests both see `FirstTime`.
    fn record_attestation(
        &self,
        intent_id: B256,
        slot_index: U256,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> impl std::future::Future<Output = Result<(), ReplayError>> + Send;

    /// Keyed by `(redemption_id, leg_index)` (audit H2) — mirrors the
    /// on-chain per-leg mutex (`IntentQueue::_legForUpdate`). Each leg of
    /// a redemption is an independent delivery-XOR-refund slot; keying on
    /// `redemption_id` alone would falsely flag leg ≥ 1 as a `Conflict` /
    /// `MutexViolation` against leg 0.
    fn check_redemption(
        &self,
        redemption_id: B256,
        leg_index: u32,
        kind: RedemptionKind,
        payload_hash: [u8; 32],
    ) -> impl std::future::Future<Output = Result<RedemptionCheckOutcome, ReplayError>> + Send;

    fn record_redemption(
        &self,
        redemption_id: B256,
        leg_index: u32,
        kind: RedemptionKind,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> impl std::future::Future<Output = Result<(), ReplayError>> + Send;

    /// Keyed by `(chain_id, input_txid, input_vout)`. The `chain_id` (audit
    /// AUD-PSBT-REPLAY-CHAINID) prevents a daemon serving multiple UTXO chains
    /// (BTC / LTC / …) from false-conflicting on a same-outpoint collision
    /// across chains — outpoints are only unique within a chain.
    fn check_psbt_input(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        input_txid: [u8; 32],
        input_vout: u32,
        payload_hash: [u8; 32],
    ) -> impl std::future::Future<Output = Result<CheckOutcome, ReplayError>> + Send;

    fn record_psbt_input(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        input_txid: [u8; 32],
        input_vout: u32,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> impl std::future::Future<Output = Result<(), ReplayError>> + Send;

    /// P-SOL-6 (Phase 4.5): pre-flight a Solana Squads signing step. Keyed by
    /// `(chain_id, multisig, transaction_index, kind, member)` — a member signs
    /// each `(transaction_index, kind)` step (create / approve / execute) once.
    /// `payload_hash` is the SEMANTIC intent (kind + index + destination +
    /// amount + memo), deliberately EXCLUDING the volatile `recent_blockhash`:
    /// a re-sign with a fresh blockhash for the same intent is `Idempotent`
    /// (the caller re-signs the fresh message — ed25519 is deterministic and
    /// local), while a DIFFERENT destination/amount at an already-used step is
    /// a `Conflict` (the defense). Defense-in-depth on top of the on-chain
    /// Squads program (which already rejects a duplicate create/approve/execute).
    fn check_solana_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        multisig: String,
        transaction_index: u64,
        kind: &'static str,
        member: String,
        payload_hash: [u8; 32],
    ) -> impl std::future::Future<Output = Result<CheckOutcome, ReplayError>> + Send;

    /// P-SOL-6: record a fresh Solana signing step.
    #[expect(
        clippy::too_many_arguments,
        reason = "Solana replay identity is a 5-tuple (chain/multisig/index/kind/member) + payload + sig + timestamp; a struct would obscure the key shape shared with the sibling record_* methods"
    )]
    fn record_solana_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        multisig: String,
        transaction_index: u64,
        kind: &'static str,
        member: String,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> impl std::future::Future<Output = Result<(), ReplayError>> + Send;

    /// V5: Safe v1.4.1 `execTransaction` digest replay check. Keyed by
    /// `(chain_id, safe_address, nonce)` — Safe nonces are monotonic
    /// per Safe, so a second-different request at the same nonce is
    /// a coordinator bug or attack. `payload_hash` is the daemon's
    /// recomputed `safeTxHash` (32 bytes; same value the HSM signs).
    fn check_safe_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        safe_address: alloy_primitives::Address,
        nonce: u64,
        payload_hash: [u8; 32],
    ) -> impl std::future::Future<Output = Result<CheckOutcome, ReplayError>> + Send;

    /// V5: record a fresh Safe-tx signature.
    fn record_safe_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        safe_address: alloy_primitives::Address,
        nonce: u64,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> impl std::future::Future<Output = Result<(), ReplayError>> + Send;

    /// C5 (Phase 3.3): Cosmos `LegacyAminoPubKey` multisig sign-doc replay
    /// check. Keyed by `(chain_id, account_address, sequence)` — the
    /// Cosmos sequence is monotonic per account, so a second-different
    /// request at the same sequence is a coordinator bug or attack.
    /// `payload_hash` is the daemon's recomputed amino sign-bytes hash.
    fn check_cosmos_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
    ) -> impl std::future::Future<Output = Result<CheckOutcome, ReplayError>> + Send;

    /// C5: record a fresh Cosmos sign-doc signature.
    fn record_cosmos_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> impl std::future::Future<Output = Result<(), ReplayError>> + Send;

    /// C5 (Phase 4.4): pre-flight an XRP multi-signing partial-signature.
    /// Keyed by `(chain_id, account_address, sequence)` — the XRPL
    /// `Sequence` is monotonic per account. `payload_hash` is THIS
    /// daemon's recomputed per-signer digest
    /// (`SHA512Half(SMT\0 ‖ body ‖ my_account_id)`), so a retry at the
    /// same sequence with a different body (e.g. a later
    /// `LastLedgerSequence`) is a `Conflict`.
    fn check_xrp_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
    ) -> impl std::future::Future<Output = Result<CheckOutcome, ReplayError>> + Send;

    /// C5 (Phase 4.4): record a fresh XRP multi-signing partial-signature.
    fn record_xrp_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> impl std::future::Future<Output = Result<(), ReplayError>> + Send;

    /// Phase 4.6: pre-flight a TRON multisig partial-signature. Keyed by
    /// `(chain_id, owner_address, txid)` — TRON has NO account nonce, so the
    /// `txID = sha256(raw_data)` IS the full payload identity (distinct
    /// redemptions yield distinct `txID`s and never collide). `payload_hash`
    /// equals `txid`; an identical retry is `Idempotent`. Because the key
    /// already includes the whole-payload `txID`, a `Conflict` cannot arise.
    fn check_tron_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        owner_address: String,
        txid: [u8; 32],
        payload_hash: [u8; 32],
    ) -> impl std::future::Future<Output = Result<CheckOutcome, ReplayError>> + Send;

    /// Phase 4.6: record a fresh TRON multisig partial-signature.
    fn record_tron_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        owner_address: String,
        txid: [u8; 32],
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> impl std::future::Future<Output = Result<(), ReplayError>> + Send;

    /// CTD-1 (`DL-CTD-2`): ONE-SHOT Redemption Intent Certificate pre-flight,
    /// keyed `(chain_id, redemption_id, leg_index)`. The custody spend for a
    /// given redemption leg is authorized exactly ONCE — a single valid RIC
    /// cannot be re-driven into N payouts across the family-specific spend keys
    /// (the RA-1 killer). `payload_hash` is the RIC digest: an identical retry
    /// is `Idempotent`, a DIFFERENT RIC for the same leg is a `Conflict`.
    fn check_ric_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
    ) -> impl std::future::Future<Output = Result<CheckOutcome, ReplayError>> + Send;

    /// CTD-1: record a consumed RIC one-shot authorization.
    fn record_ric_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> impl std::future::Future<Output = Result<(), ReplayError>> + Send;

    /// CTD-1 Slice A.7 — Set-B NON-EQUIVOCATION pre-flight for SIGNING a
    /// Redemption Intent Certificate, keyed `(chain_id, redemption_id,
    /// leg_index)`. SEPARATE from the custody-side `*_ric_intent` one-shot:
    /// a multi-role daemon must never conflate "I certified this intent"
    /// (this arm — stores the RIC signature) with "I authorized the spend"
    /// (the intent arm — stores the spend authorization). `payload_hash`
    /// is the RIC digest: an identical retry is `Idempotent` (cached RIC
    /// signature), a DIFFERENT certificate for the same leg is a
    /// `Conflict` — this daemon refuses to equivocate.
    fn check_ric_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
    ) -> impl std::future::Future<Output = Result<CheckOutcome, ReplayError>> + Send;

    /// CTD-1 Slice A.7: record a signed Redemption Intent Certificate.
    fn record_ric_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> impl std::future::Future<Output = Result<(), ReplayError>> + Send;

    /// CTD-1 Slice C: ONE-SHOT Acquire-Cancel Certificate pre-flight for the
    /// MINT-CANCEL BTC swap-back, keyed `(chain_id, cancel_id)`. Sibling of
    /// [`check_ric_intent`](Self::check_ric_intent) for the cancel path — a
    /// single valid ACC authorizes exactly ONE swap-back. `cancel_id` is
    /// unique per `AcquireCancelled`, so no leg/slot sub-key. `payload_hash`
    /// is the ACC digest: identical retry `Idempotent`, DIFFERENT cert a
    /// `Conflict`.
    fn check_ac_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
    ) -> impl std::future::Future<Output = Result<CheckOutcome, ReplayError>> + Send;

    /// CTD-1 Slice C: record a consumed ACC one-shot authorization.
    fn record_ac_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> impl std::future::Future<Output = Result<(), ReplayError>> + Send;

    /// CTD-1 Slice C — Set-B NON-EQUIVOCATION pre-flight for SIGNING an
    /// Acquire-Cancel Certificate, keyed `(chain_id, cancel_id)`. SEPARATE
    /// from the custody-side `*_ac_intent` one-shot (same role split as
    /// `ric_certs` vs `ric_intents`). Identical retry `Idempotent` (cached
    /// ACC signature), a DIFFERENT certificate for the same cancel a
    /// `Conflict` — this daemon refuses to equivocate.
    fn check_ac_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
    ) -> impl std::future::Future<Output = Result<CheckOutcome, ReplayError>> + Send;

    /// CTD-1 Slice C: record a signed Acquire-Cancel Certificate.
    fn record_ac_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> impl std::future::Future<Output = Result<(), ReplayError>> + Send;
}

// ────────────────────────────────────────────────────────────────────
// In-memory impl (tests / dev — loses state on restart, mark loud).
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct InMemoryInner {
    attestations: HashMap<(B256, U256), SignedRecord>,
    redemptions: HashMap<(B256, u32), (RedemptionKind, SignedRecord)>,
    /// PSBT replay key — `(chain_id_str, input_txid, input_vout)` (`chain_id`
    /// added per AUD-PSBT-REPLAY-CHAINID).
    psbt_inputs: HashMap<(&'static str, [u8; 32], u32), SignedRecord>,
    /// V5: Safe-tx replay key — `(chain_id_str, safe_address_bytes, nonce)`.
    safe_txs: HashMap<(&'static str, [u8; 20], u64), SignedRecord>,
    /// C5: Cosmos sign-doc replay key — `(chain_id_str, account_bech32, sequence)`.
    cosmos_txs: HashMap<(&'static str, String, u64), SignedRecord>,
    /// C5 (Phase 4.4): XRP body replay key — `(chain_id_str, r_address, sequence)`.
    xrp_txs: HashMap<(&'static str, String, u64), SignedRecord>,
    /// Phase 4.6: TRON tx replay key — `(chain_id_str, t_address, txid)`.
    tron_txs: HashMap<(&'static str, String, [u8; 32]), SignedRecord>,
    /// P-SOL-6: Solana replay key —
    /// `(chain_id_str, multisig, transaction_index, kind, member)`.
    solana_txs: HashMap<(&'static str, String, u64, &'static str, String), SignedRecord>,
    /// CTD-1 (`DL-CTD-2`): RIC one-shot key — `(chain_id_str, redemption_id, leg_index)`.
    ric_intents: HashMap<(&'static str, B256, u32), SignedRecord>,
    /// CTD-1 Slice A.7: Set-B signed-certificate key (non-equivocation) —
    /// same tuple shape as `ric_intents` but a SEPARATE namespace.
    ric_certs: HashMap<(&'static str, B256, u32), SignedRecord>,
    /// CTD-1 Slice C: ACC one-shot key — `(chain_id_str, cancel_id)` (the
    /// mint-cancel swap-back; `cancel_id` is unique per `AcquireCancelled`).
    ac_intents: HashMap<(&'static str, B256), SignedRecord>,
    /// CTD-1 Slice C: Set-B signed-ACC key (non-equivocation) — same tuple
    /// shape as `ac_intents`, a SEPARATE namespace.
    ac_certs: HashMap<(&'static str, B256), SignedRecord>,
}

/// `InMemoryReplayStore` — dev / test only. Loses every guarantee on
/// restart. Production daemons MUST use [`SqliteReplayStore`].
#[derive(Debug, Default)]
pub struct InMemoryReplayStore {
    inner: Mutex<InMemoryInner>,
}

impl InMemoryReplayStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReplayStore for InMemoryReplayStore {
    async fn check_attestation(
        &self,
        intent_id: B256,
        slot_index: U256,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let g = self.inner.lock().await;
        Ok(match g.attestations.get(&(intent_id, slot_index)) {
            None => CheckOutcome::FirstTime,
            Some(rec) if rec.payload_hash == payload_hash => CheckOutcome::Idempotent(rec.clone()),
            Some(rec) => CheckOutcome::Conflict {
                previous_payload_hash: rec.payload_hash,
                previous_signed_at_unix: rec.signed_at_unix,
            },
        })
    }

    async fn record_attestation(
        &self,
        intent_id: B256,
        slot_index: U256,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let mut g = self.inner.lock().await;
        if let std::collections::hash_map::Entry::Vacant(e) =
            g.attestations.entry((intent_id, slot_index))
        {
            e.insert(SignedRecord {
                payload_hash,
                signature,
                signed_at_unix: now_unix,
            });
            Ok(())
        } else {
            // Mirror the SQLite UNIQUE violation surface (audit L10).
            Err(ReplayError::Duplicate)
        }
    }

    async fn check_redemption(
        &self,
        redemption_id: B256,
        leg_index: u32,
        kind: RedemptionKind,
        payload_hash: [u8; 32],
    ) -> Result<RedemptionCheckOutcome, ReplayError> {
        let g = self.inner.lock().await;
        Ok(match g.redemptions.get(&(redemption_id, leg_index)) {
            None => RedemptionCheckOutcome::FirstTime,
            Some((prev_kind, rec)) if *prev_kind != kind => {
                RedemptionCheckOutcome::MutexViolation {
                    previous_kind: *prev_kind,
                    previous_signed_at_unix: rec.signed_at_unix,
                }
            }
            Some((_, rec)) if rec.payload_hash == payload_hash => {
                RedemptionCheckOutcome::Idempotent(rec.clone())
            }
            Some((_, rec)) => RedemptionCheckOutcome::Conflict {
                previous_payload_hash: rec.payload_hash,
                previous_signed_at_unix: rec.signed_at_unix,
            },
        })
    }

    async fn record_redemption(
        &self,
        redemption_id: B256,
        leg_index: u32,
        kind: RedemptionKind,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let mut g = self.inner.lock().await;
        if let std::collections::hash_map::Entry::Vacant(e) =
            g.redemptions.entry((redemption_id, leg_index))
        {
            e.insert((
                kind,
                SignedRecord {
                    payload_hash,
                    signature,
                    signed_at_unix: now_unix,
                },
            ));
            Ok(())
        } else {
            Err(ReplayError::Duplicate)
        }
    }

    async fn check_psbt_input(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        input_txid: [u8; 32],
        input_vout: u32,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let key = (chain_id.thor_asset(), input_txid, input_vout);
        let g = self.inner.lock().await;
        Ok(match g.psbt_inputs.get(&key) {
            None => CheckOutcome::FirstTime,
            Some(rec) if rec.payload_hash == payload_hash => CheckOutcome::Idempotent(rec.clone()),
            Some(rec) => CheckOutcome::Conflict {
                previous_payload_hash: rec.payload_hash,
                previous_signed_at_unix: rec.signed_at_unix,
            },
        })
    }

    async fn record_psbt_input(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        input_txid: [u8; 32],
        input_vout: u32,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let key = (chain_id.thor_asset(), input_txid, input_vout);
        let mut g = self.inner.lock().await;
        if let std::collections::hash_map::Entry::Vacant(e) = g.psbt_inputs.entry(key) {
            e.insert(SignedRecord {
                payload_hash,
                signature,
                signed_at_unix: now_unix,
            });
            Ok(())
        } else {
            Err(ReplayError::Duplicate)
        }
    }

    async fn check_solana_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        multisig: String,
        transaction_index: u64,
        kind: &'static str,
        member: String,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let key = (
            chain_id.thor_asset(),
            multisig,
            transaction_index,
            kind,
            member,
        );
        let g = self.inner.lock().await;
        Ok(match g.solana_txs.get(&key) {
            None => CheckOutcome::FirstTime,
            Some(rec) if rec.payload_hash == payload_hash => CheckOutcome::Idempotent(rec.clone()),
            Some(rec) => CheckOutcome::Conflict {
                previous_payload_hash: rec.payload_hash,
                previous_signed_at_unix: rec.signed_at_unix,
            },
        })
    }

    async fn record_solana_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        multisig: String,
        transaction_index: u64,
        kind: &'static str,
        member: String,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let key = (
            chain_id.thor_asset(),
            multisig,
            transaction_index,
            kind,
            member,
        );
        let mut g = self.inner.lock().await;
        if let std::collections::hash_map::Entry::Vacant(e) = g.solana_txs.entry(key) {
            e.insert(SignedRecord {
                payload_hash,
                signature,
                signed_at_unix: now_unix,
            });
            Ok(())
        } else {
            Err(ReplayError::Duplicate)
        }
    }

    async fn check_safe_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        safe_address: alloy_primitives::Address,
        nonce: u64,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let key = (chain_id.thor_asset(), <[u8; 20]>::from(safe_address), nonce);
        let g = self.inner.lock().await;
        Ok(match g.safe_txs.get(&key) {
            None => CheckOutcome::FirstTime,
            Some(rec) if rec.payload_hash == payload_hash => CheckOutcome::Idempotent(rec.clone()),
            Some(rec) => CheckOutcome::Conflict {
                previous_payload_hash: rec.payload_hash,
                previous_signed_at_unix: rec.signed_at_unix,
            },
        })
    }

    async fn record_safe_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        safe_address: alloy_primitives::Address,
        nonce: u64,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let key = (chain_id.thor_asset(), <[u8; 20]>::from(safe_address), nonce);
        let mut g = self.inner.lock().await;
        if let std::collections::hash_map::Entry::Vacant(e) = g.safe_txs.entry(key) {
            e.insert(SignedRecord {
                payload_hash,
                signature,
                signed_at_unix: now_unix,
            });
            Ok(())
        } else {
            Err(ReplayError::Duplicate)
        }
    }

    async fn check_cosmos_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let key = (chain_id.thor_asset(), account_address, sequence);
        let g = self.inner.lock().await;
        Ok(match g.cosmos_txs.get(&key) {
            None => CheckOutcome::FirstTime,
            Some(rec) if rec.payload_hash == payload_hash => CheckOutcome::Idempotent(rec.clone()),
            Some(rec) => CheckOutcome::Conflict {
                previous_payload_hash: rec.payload_hash,
                previous_signed_at_unix: rec.signed_at_unix,
            },
        })
    }

    async fn record_cosmos_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let key = (chain_id.thor_asset(), account_address, sequence);
        let mut g = self.inner.lock().await;
        if let std::collections::hash_map::Entry::Vacant(e) = g.cosmos_txs.entry(key) {
            e.insert(SignedRecord {
                payload_hash,
                signature,
                signed_at_unix: now_unix,
            });
            Ok(())
        } else {
            Err(ReplayError::Duplicate)
        }
    }

    async fn check_xrp_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let key = (chain_id.thor_asset(), account_address, sequence);
        let g = self.inner.lock().await;
        Ok(match g.xrp_txs.get(&key) {
            None => CheckOutcome::FirstTime,
            Some(rec) if rec.payload_hash == payload_hash => CheckOutcome::Idempotent(rec.clone()),
            Some(rec) => CheckOutcome::Conflict {
                previous_payload_hash: rec.payload_hash,
                previous_signed_at_unix: rec.signed_at_unix,
            },
        })
    }

    async fn record_xrp_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let key = (chain_id.thor_asset(), account_address, sequence);
        let mut g = self.inner.lock().await;
        if let std::collections::hash_map::Entry::Vacant(e) = g.xrp_txs.entry(key) {
            e.insert(SignedRecord {
                payload_hash,
                signature,
                signed_at_unix: now_unix,
            });
            Ok(())
        } else {
            Err(ReplayError::Duplicate)
        }
    }

    async fn check_tron_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        owner_address: String,
        txid: [u8; 32],
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let key = (chain_id.thor_asset(), owner_address, txid);
        let g = self.inner.lock().await;
        Ok(match g.tron_txs.get(&key) {
            None => CheckOutcome::FirstTime,
            Some(rec) if rec.payload_hash == payload_hash => CheckOutcome::Idempotent(rec.clone()),
            Some(rec) => CheckOutcome::Conflict {
                previous_payload_hash: rec.payload_hash,
                previous_signed_at_unix: rec.signed_at_unix,
            },
        })
    }

    async fn record_tron_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        owner_address: String,
        txid: [u8; 32],
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let key = (chain_id.thor_asset(), owner_address, txid);
        let mut g = self.inner.lock().await;
        if let std::collections::hash_map::Entry::Vacant(e) = g.tron_txs.entry(key) {
            e.insert(SignedRecord {
                payload_hash,
                signature,
                signed_at_unix: now_unix,
            });
            Ok(())
        } else {
            Err(ReplayError::Duplicate)
        }
    }

    async fn check_ric_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let key = (chain_id.thor_asset(), redemption_id, leg_index);
        let g = self.inner.lock().await;
        Ok(match g.ric_intents.get(&key) {
            None => CheckOutcome::FirstTime,
            Some(rec) if rec.payload_hash == payload_hash => CheckOutcome::Idempotent(rec.clone()),
            Some(rec) => CheckOutcome::Conflict {
                previous_payload_hash: rec.payload_hash,
                previous_signed_at_unix: rec.signed_at_unix,
            },
        })
    }

    async fn record_ric_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let key = (chain_id.thor_asset(), redemption_id, leg_index);
        let mut g = self.inner.lock().await;
        if let std::collections::hash_map::Entry::Vacant(e) = g.ric_intents.entry(key) {
            e.insert(SignedRecord {
                payload_hash,
                signature,
                signed_at_unix: now_unix,
            });
            Ok(())
        } else {
            Err(ReplayError::Duplicate)
        }
    }

    async fn check_ric_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let key = (chain_id.thor_asset(), redemption_id, leg_index);
        let g = self.inner.lock().await;
        Ok(match g.ric_certs.get(&key) {
            None => CheckOutcome::FirstTime,
            Some(rec) if rec.payload_hash == payload_hash => CheckOutcome::Idempotent(rec.clone()),
            Some(rec) => CheckOutcome::Conflict {
                previous_payload_hash: rec.payload_hash,
                previous_signed_at_unix: rec.signed_at_unix,
            },
        })
    }

    async fn record_ric_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let key = (chain_id.thor_asset(), redemption_id, leg_index);
        let mut g = self.inner.lock().await;
        if let std::collections::hash_map::Entry::Vacant(e) = g.ric_certs.entry(key) {
            e.insert(SignedRecord {
                payload_hash,
                signature,
                signed_at_unix: now_unix,
            });
            Ok(())
        } else {
            Err(ReplayError::Duplicate)
        }
    }

    async fn check_ac_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let key = (chain_id.thor_asset(), cancel_id);
        let g = self.inner.lock().await;
        Ok(match g.ac_intents.get(&key) {
            None => CheckOutcome::FirstTime,
            Some(rec) if rec.payload_hash == payload_hash => CheckOutcome::Idempotent(rec.clone()),
            Some(rec) => CheckOutcome::Conflict {
                previous_payload_hash: rec.payload_hash,
                previous_signed_at_unix: rec.signed_at_unix,
            },
        })
    }

    async fn record_ac_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let key = (chain_id.thor_asset(), cancel_id);
        let mut g = self.inner.lock().await;
        if let std::collections::hash_map::Entry::Vacant(e) = g.ac_intents.entry(key) {
            e.insert(SignedRecord {
                payload_hash,
                signature,
                signed_at_unix: now_unix,
            });
            Ok(())
        } else {
            Err(ReplayError::Duplicate)
        }
    }

    async fn check_ac_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let key = (chain_id.thor_asset(), cancel_id);
        let g = self.inner.lock().await;
        Ok(match g.ac_certs.get(&key) {
            None => CheckOutcome::FirstTime,
            Some(rec) if rec.payload_hash == payload_hash => CheckOutcome::Idempotent(rec.clone()),
            Some(rec) => CheckOutcome::Conflict {
                previous_payload_hash: rec.payload_hash,
                previous_signed_at_unix: rec.signed_at_unix,
            },
        })
    }

    async fn record_ac_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let key = (chain_id.thor_asset(), cancel_id);
        let mut g = self.inner.lock().await;
        if let std::collections::hash_map::Entry::Vacant(e) = g.ac_certs.entry(key) {
            e.insert(SignedRecord {
                payload_hash,
                signature,
                signed_at_unix: now_unix,
            });
            Ok(())
        } else {
            Err(ReplayError::Duplicate)
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// SQLite-backed impl (production — survives restart).
// ────────────────────────────────────────────────────────────────────

/// Persistent `ReplayStore` backed by `sqlx` + `SQLite`. Survives daemon
/// restarts — the production choice. Applies the `migrations/` schema
/// on connect.
pub struct SqliteReplayStore {
    pool: SqlitePool,
}

impl std::fmt::Debug for SqliteReplayStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Omit pool internals so a printed Debug never leaks a file
        // path or URL into logs / panics / crash dumps.
        f.debug_struct("SqliteReplayStore").finish_non_exhaustive()
    }
}

impl SqliteReplayStore {
    /// Connect, apply migrations.
    ///
    /// # Errors
    /// [`ReplayError::Sqlite`] on pool/connect failure;
    /// [`ReplayError::Migrate`] if a migration fails to apply.
    pub async fn connect(database_url: &str) -> Result<Self, ReplayError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    fn slot_index_to_bytes(slot_index: U256) -> [u8; 32] {
        slot_index.to_be_bytes()
    }

    /// Map an INSERT result, translating a UNIQUE-constraint violation (the
    /// write-side race two identical concurrent requests hit) into
    /// [`ReplayError::Duplicate`] so the handler recovers idempotently rather
    /// than surface a 5xx to the race-loser (audit L10). Any other DB error
    /// propagates unchanged.
    fn map_insert(
        res: Result<sqlx::sqlite::SqliteQueryResult, sqlx::Error>,
    ) -> Result<(), ReplayError> {
        match res {
            Ok(_) => Ok(()),
            Err(e)
                if e.as_database_error()
                    .is_some_and(sqlx::error::DatabaseError::is_unique_violation) =>
            {
                Err(ReplayError::Duplicate)
            }
            Err(e) => Err(ReplayError::Sqlite(e)),
        }
    }
}

impl ReplayStore for SqliteReplayStore {
    async fn check_attestation(
        &self,
        intent_id: B256,
        slot_index: U256,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let slot_bytes = Self::slot_index_to_bytes(slot_index);
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT payload_hash, signature, signed_at_unix
             FROM signed_attestations WHERE intent_id = ? AND slot_index = ?",
        )
        .bind(intent_id.as_slice())
        .bind(slot_bytes.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            None => CheckOutcome::FirstTime,
            Some((ph, sig, at)) => {
                let prev_hash: [u8; 32] = ph.as_slice().try_into().map_err(|_| {
                    ReplayError::Decode("stored payload_hash not 32 bytes".to_string())
                })?;
                if prev_hash == payload_hash {
                    CheckOutcome::Idempotent(SignedRecord {
                        payload_hash: prev_hash,
                        signature: sig,
                        signed_at_unix: at,
                    })
                } else {
                    CheckOutcome::Conflict {
                        previous_payload_hash: prev_hash,
                        previous_signed_at_unix: at,
                    }
                }
            }
        })
    }

    async fn record_attestation(
        &self,
        intent_id: B256,
        slot_index: U256,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let slot_bytes = Self::slot_index_to_bytes(slot_index);
        let res = sqlx::query(
            "INSERT INTO signed_attestations
                (intent_id, slot_index, payload_hash, signature, signed_at_unix)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(intent_id.as_slice())
        .bind(slot_bytes.as_slice())
        .bind(payload_hash.as_slice())
        .bind(&signature)
        .bind(now_unix)
        .execute(&self.pool)
        .await;
        Self::map_insert(res)
    }

    async fn check_redemption(
        &self,
        redemption_id: B256,
        leg_index: u32,
        kind: RedemptionKind,
        payload_hash: [u8; 32],
    ) -> Result<RedemptionCheckOutcome, ReplayError> {
        let row: Option<(String, Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT kind, payload_hash, signature, signed_at_unix
             FROM signed_redemptions WHERE redemption_id = ? AND leg_index = ?",
        )
        .bind(redemption_id.as_slice())
        .bind(i64::from(leg_index))
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            None => RedemptionCheckOutcome::FirstTime,
            Some((prev_kind_s, ph, sig, at)) => {
                let prev_kind = match prev_kind_s.as_str() {
                    "delivery" => RedemptionKind::Delivery,
                    "refund" => RedemptionKind::Refund,
                    "streamed" => RedemptionKind::Streamed,
                    other => {
                        return Err(ReplayError::Decode(format!(
                            "unknown redemption kind '{other}' in row"
                        )));
                    }
                };
                if prev_kind == kind {
                    let prev_hash: [u8; 32] = ph.as_slice().try_into().map_err(|_| {
                        ReplayError::Decode("stored payload_hash not 32 bytes".to_string())
                    })?;
                    if prev_hash == payload_hash {
                        RedemptionCheckOutcome::Idempotent(SignedRecord {
                            payload_hash: prev_hash,
                            signature: sig,
                            signed_at_unix: at,
                        })
                    } else {
                        RedemptionCheckOutcome::Conflict {
                            previous_payload_hash: prev_hash,
                            previous_signed_at_unix: at,
                        }
                    }
                } else {
                    RedemptionCheckOutcome::MutexViolation {
                        previous_kind: prev_kind,
                        previous_signed_at_unix: at,
                    }
                }
            }
        })
    }

    async fn record_redemption(
        &self,
        redemption_id: B256,
        leg_index: u32,
        kind: RedemptionKind,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let res = sqlx::query(
            "INSERT INTO signed_redemptions
                (redemption_id, leg_index, kind, payload_hash, signature, signed_at_unix)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(redemption_id.as_slice())
        .bind(i64::from(leg_index))
        .bind(kind.as_str())
        .bind(payload_hash.as_slice())
        .bind(&signature)
        .bind(now_unix)
        .execute(&self.pool)
        .await;
        Self::map_insert(res)
    }

    async fn check_psbt_input(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        input_txid: [u8; 32],
        input_vout: u32,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let vout = i64::from(input_vout);
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT payload_hash, signature, signed_at_unix
             FROM signed_psbt_inputs WHERE chain_id = ? AND input_txid = ? AND input_vout = ?",
        )
        .bind(chain_id.thor_asset())
        .bind(input_txid.as_slice())
        .bind(vout)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            None => CheckOutcome::FirstTime,
            Some((ph, sig, at)) => {
                let prev_hash: [u8; 32] = ph.as_slice().try_into().map_err(|_| {
                    ReplayError::Decode("stored payload_hash not 32 bytes".to_string())
                })?;
                if prev_hash == payload_hash {
                    CheckOutcome::Idempotent(SignedRecord {
                        payload_hash: prev_hash,
                        signature: sig,
                        signed_at_unix: at,
                    })
                } else {
                    CheckOutcome::Conflict {
                        previous_payload_hash: prev_hash,
                        previous_signed_at_unix: at,
                    }
                }
            }
        })
    }

    async fn record_psbt_input(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        input_txid: [u8; 32],
        input_vout: u32,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let vout = i64::from(input_vout);
        let res = sqlx::query(
            "INSERT INTO signed_psbt_inputs
                (chain_id, input_txid, input_vout, payload_hash, signature, signed_at_unix)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(chain_id.thor_asset())
        .bind(input_txid.as_slice())
        .bind(vout)
        .bind(payload_hash.as_slice())
        .bind(&signature)
        .bind(now_unix)
        .execute(&self.pool)
        .await;
        Self::map_insert(res)
    }

    async fn check_solana_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        multisig: String,
        transaction_index: u64,
        kind: &'static str,
        member: String,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        #[expect(
            clippy::cast_possible_wrap,
            reason = "Squads transaction_index cannot reach i64::MAX in practice"
        )]
        let index_i = transaction_index as i64;
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT payload_hash, signature, signed_at_unix
             FROM signed_solana_txs
             WHERE chain_id = ? AND multisig = ? AND transaction_index = ? AND kind = ? AND member = ?",
        )
        .bind(chain_id.thor_asset())
        .bind(&multisig)
        .bind(index_i)
        .bind(kind)
        .bind(&member)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            None => CheckOutcome::FirstTime,
            Some((ph, sig, at)) => {
                let prev_hash: [u8; 32] = ph.as_slice().try_into().map_err(|_| {
                    ReplayError::Decode("stored payload_hash not 32 bytes".to_string())
                })?;
                if prev_hash == payload_hash {
                    CheckOutcome::Idempotent(SignedRecord {
                        payload_hash: prev_hash,
                        signature: sig,
                        signed_at_unix: at,
                    })
                } else {
                    CheckOutcome::Conflict {
                        previous_payload_hash: prev_hash,
                        previous_signed_at_unix: at,
                    }
                }
            }
        })
    }

    async fn record_solana_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        multisig: String,
        transaction_index: u64,
        kind: &'static str,
        member: String,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        #[expect(
            clippy::cast_possible_wrap,
            reason = "Squads transaction_index cannot reach i64::MAX in practice"
        )]
        let index_i = transaction_index as i64;
        let res = sqlx::query(
            "INSERT INTO signed_solana_txs
                (chain_id, multisig, transaction_index, kind, member, payload_hash, signature, signed_at_unix)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(chain_id.thor_asset())
        .bind(&multisig)
        .bind(index_i)
        .bind(kind)
        .bind(&member)
        .bind(payload_hash.as_slice())
        .bind(&signature)
        .bind(now_unix)
        .execute(&self.pool)
        .await;
        Self::map_insert(res)
    }

    async fn check_safe_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        safe_address: alloy_primitives::Address,
        nonce: u64,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        // Safe nonces fit in `u64` in any realistic horizon; bind as
        // `i64` so sqlite can sort the PK column natively.
        #[expect(
            clippy::cast_possible_wrap,
            reason = "Safe nonce cannot reach i64::MAX in practice"
        )]
        let nonce_i = nonce as i64;
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT payload_hash, signature, signed_at_unix
             FROM signed_safe_txs
             WHERE chain_id = ? AND safe_address = ? AND nonce = ?",
        )
        .bind(chain_id.thor_asset())
        .bind(safe_address.as_slice())
        .bind(nonce_i)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            None => CheckOutcome::FirstTime,
            Some((ph, sig, at)) => {
                let prev_hash: [u8; 32] = ph.as_slice().try_into().map_err(|_| {
                    ReplayError::Decode("stored payload_hash not 32 bytes".to_string())
                })?;
                if prev_hash == payload_hash {
                    CheckOutcome::Idempotent(SignedRecord {
                        payload_hash: prev_hash,
                        signature: sig,
                        signed_at_unix: at,
                    })
                } else {
                    CheckOutcome::Conflict {
                        previous_payload_hash: prev_hash,
                        previous_signed_at_unix: at,
                    }
                }
            }
        })
    }

    async fn record_safe_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        safe_address: alloy_primitives::Address,
        nonce: u64,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        #[expect(
            clippy::cast_possible_wrap,
            reason = "Safe nonce cannot reach i64::MAX in practice"
        )]
        let nonce_i = nonce as i64;
        let res = sqlx::query(
            "INSERT INTO signed_safe_txs
                (chain_id, safe_address, nonce, payload_hash, signature, signed_at_unix)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(chain_id.thor_asset())
        .bind(safe_address.as_slice())
        .bind(nonce_i)
        .bind(payload_hash.as_slice())
        .bind(&signature)
        .bind(now_unix)
        .execute(&self.pool)
        .await;
        Self::map_insert(res)
    }

    async fn check_cosmos_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        #[expect(
            clippy::cast_possible_wrap,
            reason = "Cosmos sequence cannot reach i64::MAX in practice"
        )]
        let seq_i = sequence as i64;
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT payload_hash, signature, signed_at_unix
             FROM signed_cosmos_txs
             WHERE chain_id = ? AND account_address = ? AND sequence = ?",
        )
        .bind(chain_id.thor_asset())
        .bind(&account_address)
        .bind(seq_i)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            None => CheckOutcome::FirstTime,
            Some((ph, sig, at)) => {
                let prev_hash: [u8; 32] = ph.as_slice().try_into().map_err(|_| {
                    ReplayError::Decode("stored payload_hash not 32 bytes".to_string())
                })?;
                if prev_hash == payload_hash {
                    CheckOutcome::Idempotent(SignedRecord {
                        payload_hash: prev_hash,
                        signature: sig,
                        signed_at_unix: at,
                    })
                } else {
                    CheckOutcome::Conflict {
                        previous_payload_hash: prev_hash,
                        previous_signed_at_unix: at,
                    }
                }
            }
        })
    }

    async fn record_cosmos_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        #[expect(
            clippy::cast_possible_wrap,
            reason = "Cosmos sequence cannot reach i64::MAX in practice"
        )]
        let seq_i = sequence as i64;
        let res = sqlx::query(
            "INSERT INTO signed_cosmos_txs
                (chain_id, account_address, sequence, payload_hash, signature, signed_at_unix)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(chain_id.thor_asset())
        .bind(&account_address)
        .bind(seq_i)
        .bind(payload_hash.as_slice())
        .bind(&signature)
        .bind(now_unix)
        .execute(&self.pool)
        .await;
        Self::map_insert(res)
    }

    async fn check_xrp_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        #[expect(
            clippy::cast_possible_wrap,
            reason = "XRPL sequence is u32; cannot reach i64::MAX"
        )]
        let seq_i = sequence as i64;
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT payload_hash, signature, signed_at_unix
             FROM signed_xrp_txs
             WHERE chain_id = ? AND account_address = ? AND sequence = ?",
        )
        .bind(chain_id.thor_asset())
        .bind(&account_address)
        .bind(seq_i)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            None => CheckOutcome::FirstTime,
            Some((ph, sig, at)) => {
                let prev_hash: [u8; 32] = ph.as_slice().try_into().map_err(|_| {
                    ReplayError::Decode("stored payload_hash not 32 bytes".to_string())
                })?;
                if prev_hash == payload_hash {
                    CheckOutcome::Idempotent(SignedRecord {
                        payload_hash: prev_hash,
                        signature: sig,
                        signed_at_unix: at,
                    })
                } else {
                    CheckOutcome::Conflict {
                        previous_payload_hash: prev_hash,
                        previous_signed_at_unix: at,
                    }
                }
            }
        })
    }

    async fn record_xrp_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        #[expect(
            clippy::cast_possible_wrap,
            reason = "XRPL sequence is u32; cannot reach i64::MAX"
        )]
        let seq_i = sequence as i64;
        let res = sqlx::query(
            "INSERT INTO signed_xrp_txs
                (chain_id, account_address, sequence, payload_hash, signature, signed_at_unix)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(chain_id.thor_asset())
        .bind(&account_address)
        .bind(seq_i)
        .bind(payload_hash.as_slice())
        .bind(&signature)
        .bind(now_unix)
        .execute(&self.pool)
        .await;
        Self::map_insert(res)
    }

    async fn check_tron_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        owner_address: String,
        txid: [u8; 32],
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT payload_hash, signature, signed_at_unix
             FROM signed_tron_txs
             WHERE chain_id = ? AND owner_address = ? AND txid = ?",
        )
        .bind(chain_id.thor_asset())
        .bind(&owner_address)
        .bind(txid.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            None => CheckOutcome::FirstTime,
            Some((ph, sig, at)) => {
                let prev_hash: [u8; 32] = ph.as_slice().try_into().map_err(|_| {
                    ReplayError::Decode("stored payload_hash not 32 bytes".to_string())
                })?;
                if prev_hash == payload_hash {
                    CheckOutcome::Idempotent(SignedRecord {
                        payload_hash: prev_hash,
                        signature: sig,
                        signed_at_unix: at,
                    })
                } else {
                    CheckOutcome::Conflict {
                        previous_payload_hash: prev_hash,
                        previous_signed_at_unix: at,
                    }
                }
            }
        })
    }

    async fn record_tron_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        owner_address: String,
        txid: [u8; 32],
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let res = sqlx::query(
            "INSERT INTO signed_tron_txs
                (chain_id, owner_address, txid, payload_hash, signature, signed_at_unix)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(chain_id.thor_asset())
        .bind(&owner_address)
        .bind(txid.as_slice())
        .bind(payload_hash.as_slice())
        .bind(&signature)
        .bind(now_unix)
        .execute(&self.pool)
        .await;
        Self::map_insert(res)
    }

    async fn check_ric_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let leg_i = i64::from(leg_index);
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT payload_hash, signature, signed_at_unix
             FROM ric_intents
             WHERE chain_id = ? AND redemption_id = ? AND leg_index = ?",
        )
        .bind(chain_id.thor_asset())
        .bind(redemption_id.as_slice())
        .bind(leg_i)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            None => CheckOutcome::FirstTime,
            Some((ph, sig, at)) => {
                let prev_hash: [u8; 32] = ph.as_slice().try_into().map_err(|_| {
                    ReplayError::Decode("stored payload_hash not 32 bytes".to_string())
                })?;
                if prev_hash == payload_hash {
                    CheckOutcome::Idempotent(SignedRecord {
                        payload_hash: prev_hash,
                        signature: sig,
                        signed_at_unix: at,
                    })
                } else {
                    CheckOutcome::Conflict {
                        previous_payload_hash: prev_hash,
                        previous_signed_at_unix: at,
                    }
                }
            }
        })
    }

    async fn record_ric_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let leg_i = i64::from(leg_index);
        let res = sqlx::query(
            "INSERT INTO ric_intents
                (chain_id, redemption_id, leg_index, payload_hash, signature, signed_at_unix)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(chain_id.thor_asset())
        .bind(redemption_id.as_slice())
        .bind(leg_i)
        .bind(payload_hash.as_slice())
        .bind(&signature)
        .bind(now_unix)
        .execute(&self.pool)
        .await;
        Self::map_insert(res)
    }

    async fn check_ric_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let leg_i = i64::from(leg_index);
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT payload_hash, signature, signed_at_unix
             FROM ric_certs
             WHERE chain_id = ? AND redemption_id = ? AND leg_index = ?",
        )
        .bind(chain_id.thor_asset())
        .bind(redemption_id.as_slice())
        .bind(leg_i)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            None => CheckOutcome::FirstTime,
            Some((ph, sig, at)) => {
                let prev_hash: [u8; 32] = ph.as_slice().try_into().map_err(|_| {
                    ReplayError::Decode("stored payload_hash not 32 bytes".to_string())
                })?;
                if prev_hash == payload_hash {
                    CheckOutcome::Idempotent(SignedRecord {
                        payload_hash: prev_hash,
                        signature: sig,
                        signed_at_unix: at,
                    })
                } else {
                    CheckOutcome::Conflict {
                        previous_payload_hash: prev_hash,
                        previous_signed_at_unix: at,
                    }
                }
            }
        })
    }

    async fn record_ric_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let leg_i = i64::from(leg_index);
        let res = sqlx::query(
            "INSERT INTO ric_certs
                (chain_id, redemption_id, leg_index, payload_hash, signature, signed_at_unix)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(chain_id.thor_asset())
        .bind(redemption_id.as_slice())
        .bind(leg_i)
        .bind(payload_hash.as_slice())
        .bind(&signature)
        .bind(now_unix)
        .execute(&self.pool)
        .await;
        Self::map_insert(res)
    }

    async fn check_ac_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT payload_hash, signature, signed_at_unix
             FROM ac_intents
             WHERE chain_id = ? AND cancel_id = ?",
        )
        .bind(chain_id.thor_asset())
        .bind(cancel_id.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            None => CheckOutcome::FirstTime,
            Some((ph, sig, at)) => {
                let prev_hash: [u8; 32] = ph.as_slice().try_into().map_err(|_| {
                    ReplayError::Decode("stored payload_hash not 32 bytes".to_string())
                })?;
                if prev_hash == payload_hash {
                    CheckOutcome::Idempotent(SignedRecord {
                        payload_hash: prev_hash,
                        signature: sig,
                        signed_at_unix: at,
                    })
                } else {
                    CheckOutcome::Conflict {
                        previous_payload_hash: prev_hash,
                        previous_signed_at_unix: at,
                    }
                }
            }
        })
    }

    async fn record_ac_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let res = sqlx::query(
            "INSERT INTO ac_intents
                (chain_id, cancel_id, payload_hash, signature, signed_at_unix)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(chain_id.thor_asset())
        .bind(cancel_id.as_slice())
        .bind(payload_hash.as_slice())
        .bind(&signature)
        .bind(now_unix)
        .execute(&self.pool)
        .await;
        Self::map_insert(res)
    }

    async fn check_ac_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT payload_hash, signature, signed_at_unix
             FROM ac_certs
             WHERE chain_id = ? AND cancel_id = ?",
        )
        .bind(chain_id.thor_asset())
        .bind(cancel_id.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            None => CheckOutcome::FirstTime,
            Some((ph, sig, at)) => {
                let prev_hash: [u8; 32] = ph.as_slice().try_into().map_err(|_| {
                    ReplayError::Decode("stored payload_hash not 32 bytes".to_string())
                })?;
                if prev_hash == payload_hash {
                    CheckOutcome::Idempotent(SignedRecord {
                        payload_hash: prev_hash,
                        signature: sig,
                        signed_at_unix: at,
                    })
                } else {
                    CheckOutcome::Conflict {
                        previous_payload_hash: prev_hash,
                        previous_signed_at_unix: at,
                    }
                }
            }
        })
    }

    async fn record_ac_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let res = sqlx::query(
            "INSERT INTO ac_certs
                (chain_id, cancel_id, payload_hash, signature, signed_at_unix)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(chain_id.thor_asset())
        .bind(cancel_id.as_slice())
        .bind(payload_hash.as_slice())
        .bind(&signature)
        .bind(now_unix)
        .execute(&self.pool)
        .await;
        Self::map_insert(res)
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    fn id1() -> B256 {
        b256!("0000000000000000000000000000000000000000000000000000000000000001")
    }
    fn id2() -> B256 {
        b256!("0000000000000000000000000000000000000000000000000000000000000002")
    }
    fn hash_a() -> [u8; 32] {
        [0xAAu8; 32]
    }
    fn hash_b() -> [u8; 32] {
        [0xBBu8; 32]
    }

    async fn run_attestation_lifecycle<S: ReplayStore>(store: &S) {
        #[expect(clippy::expect_used, reason = "test code")]
        {
            // First check: empty store.
            assert_eq!(
                store
                    .check_attestation(id1(), U256::from(0u8), hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            // Record.
            store
                .record_attestation(id1(), U256::from(0u8), hash_a(), vec![1, 2, 3], 100)
                .await
                .expect("record");
            // Same tuple + same payload_hash → idempotent.
            let out = store
                .check_attestation(id1(), U256::from(0u8), hash_a())
                .await
                .expect("check");
            assert!(matches!(out, CheckOutcome::Idempotent(rec) if rec.signature == vec![1,2,3]));
            // Same tuple + DIFFERENT payload_hash → conflict.
            let out = store
                .check_attestation(id1(), U256::from(0u8), hash_b())
                .await
                .expect("check");
            assert!(matches!(out, CheckOutcome::Conflict { .. }));
            // Different tuple (different intent) → FirstTime.
            assert_eq!(
                store
                    .check_attestation(id2(), U256::from(0u8), hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            // Different slot_index of same intent → FirstTime.
            assert_eq!(
                store
                    .check_attestation(id1(), U256::from(1u8), hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            // Second record on same tuple errors (race-safety net).
            assert!(store
                .record_attestation(id1(), U256::from(0u8), hash_a(), vec![9, 9, 9], 200)
                .await
                .is_err());
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "test code: one cohesive per-leg redemption replay lifecycle (H2)"
    )]
    async fn run_redemption_lifecycle<S: ReplayStore>(store: &S) {
        #[expect(clippy::expect_used, reason = "test code")]
        {
            // First time delivery on leg 0.
            assert_eq!(
                store
                    .check_redemption(id1(), 0, RedemptionKind::Delivery, hash_a())
                    .await
                    .expect("check"),
                RedemptionCheckOutcome::FirstTime
            );
            store
                .record_redemption(
                    id1(),
                    0,
                    RedemptionKind::Delivery,
                    hash_a(),
                    vec![7, 7, 7],
                    100,
                )
                .await
                .expect("record");
            // Same id + leg + kind + payload → idempotent.
            let out = store
                .check_redemption(id1(), 0, RedemptionKind::Delivery, hash_a())
                .await
                .expect("check");
            assert!(
                matches!(out, RedemptionCheckOutcome::Idempotent(rec) if rec.signature == vec![7,7,7])
            );
            // Same id + leg + kind + DIFFERENT payload → regular conflict.
            let out = store
                .check_redemption(id1(), 0, RedemptionKind::Delivery, hash_b())
                .await
                .expect("check");
            assert!(matches!(out, RedemptionCheckOutcome::Conflict { .. }));
            // Same id + leg + DIFFERENT kind (refund after delivery) → mutex.
            let out = store
                .check_redemption(id1(), 0, RedemptionKind::Refund, hash_a())
                .await
                .expect("check");
            assert!(matches!(
                out,
                RedemptionCheckOutcome::MutexViolation {
                    previous_kind: RedemptionKind::Delivery,
                    ..
                }
            ));

            // Audit H2: a DIFFERENT leg of the SAME redemption is an
            // independent slot. Leg 1 MUST be FirstTime for both a
            // delivery (different payload than leg 0) and a refund — NOT
            // falsely flagged as a Conflict / MutexViolation against leg
            // 0. (Pre-H2, keyed on redemption_id alone, both were 409.)
            assert_eq!(
                store
                    .check_redemption(id1(), 1, RedemptionKind::Delivery, hash_b())
                    .await
                    .expect("leg1 delivery"),
                RedemptionCheckOutcome::FirstTime
            );
            assert_eq!(
                store
                    .check_redemption(id1(), 1, RedemptionKind::Refund, hash_a())
                    .await
                    .expect("leg1 refund"),
                RedemptionCheckOutcome::FirstTime
            );
            store
                .record_redemption(
                    id1(),
                    1,
                    RedemptionKind::Delivery,
                    hash_b(),
                    vec![8, 8, 8],
                    150,
                )
                .await
                .expect("record leg1");
            // Within leg 1, the per-leg mutex still applies.
            let out = store
                .check_redemption(id1(), 1, RedemptionKind::Refund, hash_a())
                .await
                .expect("check");
            assert!(matches!(
                out,
                RedemptionCheckOutcome::MutexViolation {
                    previous_kind: RedemptionKind::Delivery,
                    ..
                }
            ));
            // Leg 0 is untouched by leg 1's record (still idempotent).
            let out = store
                .check_redemption(id1(), 0, RedemptionKind::Delivery, hash_a())
                .await
                .expect("check");
            assert!(matches!(out, RedemptionCheckOutcome::Idempotent(_)));

            // Different redemption → independent FirstTime.
            assert_eq!(
                store
                    .check_redemption(id2(), 0, RedemptionKind::Refund, hash_a())
                    .await
                    .expect("check"),
                RedemptionCheckOutcome::FirstTime
            );
            // Record refund on id2; check mutex from the other direction.
            store
                .record_redemption(id2(), 0, RedemptionKind::Refund, hash_a(), vec![1], 200)
                .await
                .expect("record");
            let out = store
                .check_redemption(id2(), 0, RedemptionKind::Delivery, hash_a())
                .await
                .expect("check");
            assert!(matches!(
                out,
                RedemptionCheckOutcome::MutexViolation {
                    previous_kind: RedemptionKind::Refund,
                    ..
                }
            ));

            // Streamed-settlement kind (re-audit-gated burn streaming): a
            // fresh leg records `Streamed`; a later `Delivery` or `Refund`
            // on that leg is a one-shot mutex violation (and vice versa).
            assert_eq!(
                store
                    .check_redemption(id2(), 5, RedemptionKind::Streamed, hash_a())
                    .await
                    .expect("leg5 streamed"),
                RedemptionCheckOutcome::FirstTime
            );
            store
                .record_redemption(id2(), 5, RedemptionKind::Streamed, hash_a(), vec![9], 250)
                .await
                .expect("record streamed");
            // Same kind + payload → idempotent.
            assert!(matches!(
                store
                    .check_redemption(id2(), 5, RedemptionKind::Streamed, hash_a())
                    .await
                    .expect("check"),
                RedemptionCheckOutcome::Idempotent(_)
            ));
            // Delivery after streamed → mutex.
            assert!(matches!(
                store
                    .check_redemption(id2(), 5, RedemptionKind::Delivery, hash_a())
                    .await
                    .expect("check"),
                RedemptionCheckOutcome::MutexViolation {
                    previous_kind: RedemptionKind::Streamed,
                    ..
                }
            ));
            // Streamed after a prior delivery (id2 leg 6) → mutex.
            store
                .record_redemption(id2(), 6, RedemptionKind::Delivery, hash_a(), vec![1], 260)
                .await
                .expect("record delivery leg6");
            assert!(matches!(
                store
                    .check_redemption(id2(), 6, RedemptionKind::Streamed, hash_a())
                    .await
                    .expect("check"),
                RedemptionCheckOutcome::MutexViolation {
                    previous_kind: RedemptionKind::Delivery,
                    ..
                }
            ));

            // Second record on same (id, leg) errors (race-safety net).
            assert!(store
                .record_redemption(id1(), 0, RedemptionKind::Delivery, hash_a(), vec![], 300)
                .await
                .is_err());
        }
    }

    async fn run_psbt_input_lifecycle<S: ReplayStore>(store: &S) {
        use xindex_shared::chain_registry::ChainId;
        #[expect(clippy::expect_used, reason = "test code")]
        {
            let outpoint = [0x55u8; 32];
            assert_eq!(
                store
                    .check_psbt_input(ChainId::Btc, outpoint, 0, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            store
                .record_psbt_input(ChainId::Btc, outpoint, 0, hash_a(), vec![0xDE, 0xAD], 100)
                .await
                .expect("record");
            // Same outpoint + same payload → idempotent.
            let out = store
                .check_psbt_input(ChainId::Btc, outpoint, 0, hash_a())
                .await
                .expect("check");
            assert!(
                matches!(out, CheckOutcome::Idempotent(rec) if rec.signature == vec![0xDE,0xAD])
            );
            // Same outpoint + DIFFERENT payload → conflict.
            let out = store
                .check_psbt_input(ChainId::Btc, outpoint, 0, hash_b())
                .await
                .expect("check");
            assert!(matches!(out, CheckOutcome::Conflict { .. }));
            // Different vout of same txid → independent FirstTime.
            assert_eq!(
                store
                    .check_psbt_input(ChainId::Btc, outpoint, 1, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            // Different txid → independent FirstTime.
            let other = [0x66u8; 32];
            assert_eq!(
                store
                    .check_psbt_input(ChainId::Btc, other, 0, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            // AUD-PSBT-REPLAY-CHAINID: the SAME outpoint on a DIFFERENT UTXO
            // chain is an independent slot — NOT a false Conflict against the
            // BTC row recorded above.
            assert_eq!(
                store
                    .check_psbt_input(ChainId::Ltc, outpoint, 0, hash_b())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            store
                .record_psbt_input(ChainId::Ltc, outpoint, 0, hash_b(), vec![0x11], 110)
                .await
                .expect("record ltc");
            // The BTC row is untouched by the LTC record (still idempotent).
            assert!(matches!(
                store
                    .check_psbt_input(ChainId::Btc, outpoint, 0, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::Idempotent(_)
            ));
        }
    }

    /// P-SOL-6: Solana replay keyed by `(chain, multisig, transaction_index,
    /// kind, member)`. The same step + same semantic payload → idempotent; a
    /// DIFFERENT payload at the same step → Conflict; a different kind / index
    /// / member is an independent slot.
    async fn run_solana_tx_lifecycle<S: ReplayStore>(store: &S) {
        use xindex_shared::chain_registry::ChainId;
        #[expect(clippy::expect_used, reason = "test code")]
        {
            let ms = "msig111".to_string();
            let mem = "member1".to_string();
            assert_eq!(
                store
                    .check_solana_tx(ChainId::Sol, ms.clone(), 7, "create", mem.clone(), hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            store
                .record_solana_tx(
                    ChainId::Sol,
                    ms.clone(),
                    7,
                    "create",
                    mem.clone(),
                    hash_a(),
                    vec![1, 2, 3],
                    100,
                )
                .await
                .expect("record");
            // Same step + same semantic payload → idempotent (a blockhash-
            // refresh re-sign of the same intent).
            assert!(matches!(
                store
                    .check_solana_tx(ChainId::Sol, ms.clone(), 7, "create", mem.clone(), hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::Idempotent(rec) if rec.signature == vec![1, 2, 3]
            ));
            // Same step + DIFFERENT semantic payload (e.g. a different
            // destination at an already-used transaction_index) → Conflict.
            assert!(matches!(
                store
                    .check_solana_tx(ChainId::Sol, ms.clone(), 7, "create", mem.clone(), hash_b())
                    .await
                    .expect("check"),
                CheckOutcome::Conflict { .. }
            ));
            // Different kind (approve vs create) at the same step → independent.
            assert_eq!(
                store
                    .check_solana_tx(
                        ChainId::Sol,
                        ms.clone(),
                        7,
                        "approve",
                        mem.clone(),
                        hash_a()
                    )
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            // Different transaction_index → independent.
            assert_eq!(
                store
                    .check_solana_tx(ChainId::Sol, ms.clone(), 8, "create", mem.clone(), hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            // Different member → independent.
            assert_eq!(
                store
                    .check_solana_tx(
                        ChainId::Sol,
                        ms,
                        7,
                        "create",
                        "member2".to_string(),
                        hash_a()
                    )
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
        }
    }

    /// Phase 4.6: TRON tx replay keyed by `(chain, owner, txid)`. Identical
    /// retry → idempotent; a different `txID` (= different payload) is an
    /// independent `FirstTime`; a different owner is independent too.
    async fn run_tron_tx_lifecycle<S: ReplayStore>(store: &S) {
        use xindex_shared::chain_registry::ChainId;
        #[expect(clippy::expect_used, reason = "test code")]
        {
            let owner = "TU6nEM4GTca2L5AuDTnY1qp1rkQ2t8NxvM".to_string();
            let txid = [0x71u8; 32];
            assert_eq!(
                store
                    .check_tron_tx(ChainId::Tron, owner.clone(), txid, txid)
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            store
                .record_tron_tx(ChainId::Tron, owner.clone(), txid, txid, vec![1, 2, 3], 100)
                .await
                .expect("record");
            // Same (chain, owner, txid) → idempotent cached sig.
            let out = store
                .check_tron_tx(ChainId::Tron, owner.clone(), txid, txid)
                .await
                .expect("check");
            assert!(matches!(out, CheckOutcome::Idempotent(rec) if rec.signature == vec![1,2,3]));
            // Different txID (a different redemption) → independent FirstTime.
            let other = [0x72u8; 32];
            assert_eq!(
                store
                    .check_tron_tx(ChainId::Tron, owner, other, other)
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            // Different owner, same txid → independent FirstTime.
            assert_eq!(
                store
                    .check_tron_tx(ChainId::Tron, "TOther".to_string(), txid, txid)
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
        }
    }

    /// CTD-1 (`DL-CTD-2`): RIC one-shot keyed `(chain, redemption_id, leg)`.
    /// Same leg + same RIC → idempotent; same leg + a DIFFERENT RIC (a re-drive
    /// with a forged/rotated cert) → Conflict; a different leg / redemption /
    /// chain is independent. This is the RA-1 anti-re-drive guard.
    async fn run_ric_intent_lifecycle<S: ReplayStore>(store: &S) {
        use xindex_shared::chain_registry::ChainId;
        #[expect(clippy::expect_used, reason = "test code")]
        {
            let rid = id1();
            assert_eq!(
                store
                    .check_ric_intent(ChainId::Btc, rid, 0, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            store
                .record_ric_intent(ChainId::Btc, rid, 0, hash_a(), vec![1, 2, 3], 100)
                .await
                .expect("record");
            // Same leg + same RIC → idempotent.
            assert!(matches!(
                store
                    .check_ric_intent(ChainId::Btc, rid, 0, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::Idempotent(rec) if rec.signature == vec![1, 2, 3]
            ));
            // Same leg + DIFFERENT RIC (re-drive / forged cert) → Conflict.
            assert!(matches!(
                store
                    .check_ric_intent(ChainId::Btc, rid, 0, hash_b())
                    .await
                    .expect("check"),
                CheckOutcome::Conflict { .. }
            ));
            // Different leg → independent.
            assert_eq!(
                store
                    .check_ric_intent(ChainId::Btc, rid, 1, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            // Different redemption → independent.
            assert_eq!(
                store
                    .check_ric_intent(ChainId::Btc, id2(), 0, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            // Different chain (LTC), same redemption+leg → independent.
            assert_eq!(
                store
                    .check_ric_intent(ChainId::Ltc, rid, 0, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
        }
    }

    #[tokio::test]
    async fn in_memory_attestation_lifecycle() {
        let store = InMemoryReplayStore::new();
        run_attestation_lifecycle(&store).await;
    }

    #[tokio::test]
    async fn in_memory_tron_tx_lifecycle() {
        let store = InMemoryReplayStore::new();
        run_tron_tx_lifecycle(&store).await;
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_tron_tx_lifecycle_matches_in_memory() {
        let store = SqliteReplayStore::connect("sqlite::memory:")
            .await
            .expect("connect");
        run_tron_tx_lifecycle(&store).await;
    }

    #[tokio::test]
    async fn in_memory_ric_intent_lifecycle() {
        let store = InMemoryReplayStore::new();
        run_ric_intent_lifecycle(&store).await;
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_ric_intent_lifecycle_matches_in_memory() {
        let store = SqliteReplayStore::connect("sqlite::memory:")
            .await
            .expect("connect");
        run_ric_intent_lifecycle(&store).await;
    }

    /// CTD-1 Slice A.7: the Set-B cert arm has the same lifecycle shape
    /// as the custody one-shot — idempotent on the same digest, Conflict
    /// (equivocation refusal) on a different digest for the same leg.
    async fn run_ric_cert_lifecycle<S: ReplayStore>(store: &S) {
        use xindex_shared::chain_registry::ChainId;
        #[expect(clippy::expect_used, reason = "test code")]
        {
            let rid = id1();
            assert_eq!(
                store
                    .check_ric_cert(ChainId::Btc, rid, 0, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            store
                .record_ric_cert(ChainId::Btc, rid, 0, hash_a(), vec![9, 9], 100)
                .await
                .expect("record");
            assert!(matches!(
                store
                    .check_ric_cert(ChainId::Btc, rid, 0, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::Idempotent(rec) if rec.signature == vec![9, 9]
            ));
            // A DIFFERENT certificate for the same leg → equivocation
            // refusal.
            assert!(matches!(
                store
                    .check_ric_cert(ChainId::Btc, rid, 0, hash_b())
                    .await
                    .expect("check"),
                CheckOutcome::Conflict { .. }
            ));
            // Double-record is a Duplicate error.
            assert!(matches!(
                store
                    .record_ric_cert(ChainId::Btc, rid, 0, hash_a(), vec![9, 9], 101)
                    .await,
                Err(ReplayError::Duplicate)
            ));
        }
    }

    /// CTD-1 Slice A.7: the cert arm and the custody one-shot arm are
    /// SEPARATE namespaces — certifying a leg must not consume (or be
    /// consumed by) the custody-spend authorization for the same
    /// `(chain, redemption, leg)` key. A multi-role daemon that both
    /// certifies (Set-B) and spends (custody key) depends on this.
    async fn run_ric_cert_vs_intent_independence<S: ReplayStore>(store: &S) {
        use xindex_shared::chain_registry::ChainId;
        #[expect(clippy::expect_used, reason = "test code")]
        {
            let rid = id1();
            store
                .record_ric_cert(ChainId::Btc, rid, 0, hash_a(), vec![1], 100)
                .await
                .expect("record cert");
            // The custody one-shot for the same key is untouched.
            assert_eq!(
                store
                    .check_ric_intent(ChainId::Btc, rid, 0, hash_a())
                    .await
                    .expect("check intent"),
                CheckOutcome::FirstTime
            );
            store
                .record_ric_intent(ChainId::Btc, rid, 0, hash_a(), vec![2], 101)
                .await
                .expect("record intent");
            // And the cert record is unchanged by the intent record.
            assert!(matches!(
                store
                    .check_ric_cert(ChainId::Btc, rid, 0, hash_a())
                    .await
                    .expect("check cert"),
                CheckOutcome::Idempotent(rec) if rec.signature == vec![1]
            ));
        }
    }

    #[tokio::test]
    async fn in_memory_ric_cert_lifecycle() {
        let store = InMemoryReplayStore::new();
        run_ric_cert_lifecycle(&store).await;
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_ric_cert_lifecycle_matches_in_memory() {
        let store = SqliteReplayStore::connect("sqlite::memory:")
            .await
            .expect("connect");
        run_ric_cert_lifecycle(&store).await;
    }

    #[tokio::test]
    async fn in_memory_ric_cert_independent_of_ric_intent() {
        let store = InMemoryReplayStore::new();
        run_ric_cert_vs_intent_independence(&store).await;
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_ric_cert_independent_of_ric_intent() {
        let store = SqliteReplayStore::connect("sqlite::memory:")
            .await
            .expect("connect");
        run_ric_cert_vs_intent_independence(&store).await;
    }

    /// CTD-1 Slice C: the ACC custody one-shot — keyed `(chain, cancel_id)`
    /// (no leg). Idempotent on the same digest, Conflict on a different
    /// cert for the same cancel, independent across cancel ids + chains.
    async fn run_ac_intent_lifecycle<S: ReplayStore>(store: &S) {
        use xindex_shared::chain_registry::ChainId;
        #[expect(clippy::expect_used, reason = "test code")]
        {
            let cid = id1();
            assert_eq!(
                store
                    .check_ac_intent(ChainId::Btc, cid, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            store
                .record_ac_intent(ChainId::Btc, cid, hash_a(), vec![1, 2, 3], 100)
                .await
                .expect("record");
            // Same cancel + same ACC → idempotent.
            assert!(matches!(
                store
                    .check_ac_intent(ChainId::Btc, cid, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::Idempotent(rec) if rec.signature == vec![1, 2, 3]
            ));
            // Same cancel + DIFFERENT ACC (re-drive / forged) → Conflict.
            assert!(matches!(
                store
                    .check_ac_intent(ChainId::Btc, cid, hash_b())
                    .await
                    .expect("check"),
                CheckOutcome::Conflict { .. }
            ));
            // Different cancel id → independent.
            assert_eq!(
                store
                    .check_ac_intent(ChainId::Btc, id2(), hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            // Different chain, same cancel id → independent.
            assert_eq!(
                store
                    .check_ac_intent(ChainId::Ltc, cid, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
        }
    }

    /// CTD-1 Slice C: the Set-B ACC arm — equivocation refusal on a
    /// different digest for the same cancel.
    async fn run_ac_cert_lifecycle<S: ReplayStore>(store: &S) {
        use xindex_shared::chain_registry::ChainId;
        #[expect(clippy::expect_used, reason = "test code")]
        {
            let cid = id1();
            store
                .record_ac_cert(ChainId::Btc, cid, hash_a(), vec![9, 9], 100)
                .await
                .expect("record");
            assert!(matches!(
                store
                    .check_ac_cert(ChainId::Btc, cid, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::Idempotent(rec) if rec.signature == vec![9, 9]
            ));
            assert!(matches!(
                store
                    .check_ac_cert(ChainId::Btc, cid, hash_b())
                    .await
                    .expect("check"),
                CheckOutcome::Conflict { .. }
            ));
            assert!(matches!(
                store
                    .record_ac_cert(ChainId::Btc, cid, hash_a(), vec![9, 9], 101)
                    .await,
                Err(ReplayError::Duplicate)
            ));
        }
    }

    /// CTD-1 Slice C: the ACC cert arm and the ACC custody one-shot are
    /// SEPARATE namespaces (same role split as RIC) — and the ACC arms
    /// are independent of the RIC arms for the same id (a redeem and a
    /// mint-cancel can never consume each other's authorization).
    async fn run_ac_independence<S: ReplayStore>(store: &S) {
        use xindex_shared::chain_registry::ChainId;
        #[expect(clippy::expect_used, reason = "test code")]
        {
            let id = id1();
            store
                .record_ac_cert(ChainId::Btc, id, hash_a(), vec![1], 100)
                .await
                .expect("record ac cert");
            // The ACC custody one-shot for the same key is untouched.
            assert_eq!(
                store
                    .check_ac_intent(ChainId::Btc, id, hash_a())
                    .await
                    .expect("check ac intent"),
                CheckOutcome::FirstTime
            );
            // The RIC arms keyed (chain, id, leg=0) are independent of ACC.
            assert_eq!(
                store
                    .check_ric_intent(ChainId::Btc, id, 0, hash_a())
                    .await
                    .expect("check ric intent"),
                CheckOutcome::FirstTime
            );
            store
                .record_ac_intent(ChainId::Btc, id, hash_a(), vec![2], 101)
                .await
                .expect("record ac intent");
            assert!(matches!(
                store
                    .check_ac_cert(ChainId::Btc, id, hash_a())
                    .await
                    .expect("check ac cert"),
                CheckOutcome::Idempotent(rec) if rec.signature == vec![1]
            ));
        }
    }

    #[tokio::test]
    async fn in_memory_ac_intent_lifecycle() {
        let store = InMemoryReplayStore::new();
        run_ac_intent_lifecycle(&store).await;
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_ac_intent_lifecycle_matches_in_memory() {
        let store = SqliteReplayStore::connect("sqlite::memory:")
            .await
            .expect("connect");
        run_ac_intent_lifecycle(&store).await;
    }

    #[tokio::test]
    async fn in_memory_ac_cert_lifecycle() {
        let store = InMemoryReplayStore::new();
        run_ac_cert_lifecycle(&store).await;
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_ac_cert_lifecycle_matches_in_memory() {
        let store = SqliteReplayStore::connect("sqlite::memory:")
            .await
            .expect("connect");
        run_ac_cert_lifecycle(&store).await;
    }

    #[tokio::test]
    async fn in_memory_ac_arms_independent() {
        let store = InMemoryReplayStore::new();
        run_ac_independence(&store).await;
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_ac_arms_independent() {
        let store = SqliteReplayStore::connect("sqlite::memory:")
            .await
            .expect("connect");
        run_ac_independence(&store).await;
    }

    #[tokio::test]
    async fn in_memory_redemption_lifecycle() {
        let store = InMemoryReplayStore::new();
        run_redemption_lifecycle(&store).await;
    }

    #[tokio::test]
    async fn in_memory_psbt_input_lifecycle() {
        let store = InMemoryReplayStore::new();
        run_psbt_input_lifecycle(&store).await;
    }

    #[tokio::test]
    async fn in_memory_solana_tx_lifecycle() {
        let store = InMemoryReplayStore::new();
        run_solana_tx_lifecycle(&store).await;
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_solana_tx_lifecycle_matches_in_memory() {
        let store = SqliteReplayStore::connect("sqlite::memory:")
            .await
            .expect("connect");
        run_solana_tx_lifecycle(&store).await;
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_attestation_lifecycle_matches_in_memory() {
        let store = SqliteReplayStore::connect("sqlite::memory:")
            .await
            .expect("connect");
        run_attestation_lifecycle(&store).await;
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_redemption_lifecycle_matches_in_memory() {
        let store = SqliteReplayStore::connect("sqlite::memory:")
            .await
            .expect("connect");
        run_redemption_lifecycle(&store).await;
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_psbt_input_lifecycle_matches_in_memory() {
        let store = SqliteReplayStore::connect("sqlite::memory:")
            .await
            .expect("connect");
        run_psbt_input_lifecycle(&store).await;
    }
}
