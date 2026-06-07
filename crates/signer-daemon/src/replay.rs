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
}

impl RedemptionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Delivery => "delivery",
            Self::Refund => "refund",
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

    fn check_psbt_input(
        &self,
        input_txid: [u8; 32],
        input_vout: u32,
        payload_hash: [u8; 32],
    ) -> impl std::future::Future<Output = Result<CheckOutcome, ReplayError>> + Send;

    fn record_psbt_input(
        &self,
        input_txid: [u8; 32],
        input_vout: u32,
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
}

// ────────────────────────────────────────────────────────────────────
// In-memory impl (tests / dev — loses state on restart, mark loud).
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct InMemoryInner {
    attestations: HashMap<(B256, U256), SignedRecord>,
    redemptions: HashMap<(B256, u32), (RedemptionKind, SignedRecord)>,
    psbt_inputs: HashMap<([u8; 32], u32), SignedRecord>,
    /// V5: Safe-tx replay key — `(chain_id_str, safe_address_bytes, nonce)`.
    safe_txs: HashMap<(&'static str, [u8; 20], u64), SignedRecord>,
    /// C5: Cosmos sign-doc replay key — `(chain_id_str, account_bech32, sequence)`.
    cosmos_txs: HashMap<(&'static str, String, u64), SignedRecord>,
    /// C5 (Phase 4.4): XRP body replay key — `(chain_id_str, r_address, sequence)`.
    xrp_txs: HashMap<(&'static str, String, u64), SignedRecord>,
    /// Phase 4.6: TRON tx replay key — `(chain_id_str, t_address, txid)`.
    tron_txs: HashMap<(&'static str, String, [u8; 32]), SignedRecord>,
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
        input_txid: [u8; 32],
        input_vout: u32,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let g = self.inner.lock().await;
        Ok(match g.psbt_inputs.get(&(input_txid, input_vout)) {
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
        input_txid: [u8; 32],
        input_vout: u32,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let mut g = self.inner.lock().await;
        if let std::collections::hash_map::Entry::Vacant(e) =
            g.psbt_inputs.entry((input_txid, input_vout))
        {
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
        input_txid: [u8; 32],
        input_vout: u32,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        let vout = i64::from(input_vout);
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT payload_hash, signature, signed_at_unix
             FROM signed_psbt_inputs WHERE input_txid = ? AND input_vout = ?",
        )
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
        input_txid: [u8; 32],
        input_vout: u32,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let vout = i64::from(input_vout);
        let res = sqlx::query(
            "INSERT INTO signed_psbt_inputs
                (input_txid, input_vout, payload_hash, signature, signed_at_unix)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(input_txid.as_slice())
        .bind(vout)
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
            // Second record on same (id, leg) errors (race-safety net).
            assert!(store
                .record_redemption(id1(), 0, RedemptionKind::Delivery, hash_a(), vec![], 300)
                .await
                .is_err());
        }
    }

    async fn run_psbt_input_lifecycle<S: ReplayStore>(store: &S) {
        #[expect(clippy::expect_used, reason = "test code")]
        {
            let outpoint = [0x55u8; 32];
            assert_eq!(
                store
                    .check_psbt_input(outpoint, 0, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            store
                .record_psbt_input(outpoint, 0, hash_a(), vec![0xDE, 0xAD], 100)
                .await
                .expect("record");
            // Same outpoint + same payload → idempotent.
            let out = store
                .check_psbt_input(outpoint, 0, hash_a())
                .await
                .expect("check");
            assert!(
                matches!(out, CheckOutcome::Idempotent(rec) if rec.signature == vec![0xDE,0xAD])
            );
            // Same outpoint + DIFFERENT payload → conflict.
            let out = store
                .check_psbt_input(outpoint, 0, hash_b())
                .await
                .expect("check");
            assert!(matches!(out, CheckOutcome::Conflict { .. }));
            // Different vout of same txid → independent FirstTime.
            assert_eq!(
                store
                    .check_psbt_input(outpoint, 1, hash_a())
                    .await
                    .expect("check"),
                CheckOutcome::FirstTime
            );
            // Different txid → independent FirstTime.
            let other = [0x66u8; 32];
            assert_eq!(
                store
                    .check_psbt_input(other, 0, hash_a())
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
