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
/// `signed_redemptions` table holds at most one row per redemption id;
/// the daemon-level mutex (DL-M5-3) is enforced by the PK + this `kind`.
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

    fn check_redemption(
        &self,
        redemption_id: B256,
        kind: RedemptionKind,
        payload_hash: [u8; 32],
    ) -> impl std::future::Future<Output = Result<RedemptionCheckOutcome, ReplayError>> + Send;

    fn record_redemption(
        &self,
        redemption_id: B256,
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
}

// ────────────────────────────────────────────────────────────────────
// In-memory impl (tests / dev — loses state on restart, mark loud).
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct InMemoryInner {
    attestations: HashMap<(B256, U256), SignedRecord>,
    redemptions: HashMap<B256, (RedemptionKind, SignedRecord)>,
    psbt_inputs: HashMap<([u8; 32], u32), SignedRecord>,
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
            // Mirror the SQLite UNIQUE violation surface.
            Err(ReplayError::Decode(
                "duplicate attestation record (race)".to_string(),
            ))
        }
    }

    async fn check_redemption(
        &self,
        redemption_id: B256,
        kind: RedemptionKind,
        payload_hash: [u8; 32],
    ) -> Result<RedemptionCheckOutcome, ReplayError> {
        let g = self.inner.lock().await;
        Ok(match g.redemptions.get(&redemption_id) {
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
        kind: RedemptionKind,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        let mut g = self.inner.lock().await;
        if let std::collections::hash_map::Entry::Vacant(e) = g.redemptions.entry(redemption_id) {
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
            Err(ReplayError::Decode(
                "duplicate redemption record (race)".to_string(),
            ))
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
            Err(ReplayError::Decode(
                "duplicate PSBT-input record (race)".to_string(),
            ))
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
        sqlx::query(
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
        .await?;
        Ok(())
    }

    async fn check_redemption(
        &self,
        redemption_id: B256,
        kind: RedemptionKind,
        payload_hash: [u8; 32],
    ) -> Result<RedemptionCheckOutcome, ReplayError> {
        let row: Option<(String, Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT kind, payload_hash, signature, signed_at_unix
             FROM signed_redemptions WHERE redemption_id = ?",
        )
        .bind(redemption_id.as_slice())
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
        kind: RedemptionKind,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        sqlx::query(
            "INSERT INTO signed_redemptions
                (redemption_id, kind, payload_hash, signature, signed_at_unix)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(redemption_id.as_slice())
        .bind(kind.as_str())
        .bind(payload_hash.as_slice())
        .bind(&signature)
        .bind(now_unix)
        .execute(&self.pool)
        .await?;
        Ok(())
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
        sqlx::query(
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
        .await?;
        Ok(())
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

    async fn run_redemption_lifecycle<S: ReplayStore>(store: &S) {
        #[expect(clippy::expect_used, reason = "test code")]
        {
            // First time delivery.
            assert_eq!(
                store
                    .check_redemption(id1(), RedemptionKind::Delivery, hash_a())
                    .await
                    .expect("check"),
                RedemptionCheckOutcome::FirstTime
            );
            store
                .record_redemption(
                    id1(),
                    RedemptionKind::Delivery,
                    hash_a(),
                    vec![7, 7, 7],
                    100,
                )
                .await
                .expect("record");
            // Same id + same kind + same payload → idempotent.
            let out = store
                .check_redemption(id1(), RedemptionKind::Delivery, hash_a())
                .await
                .expect("check");
            assert!(
                matches!(out, RedemptionCheckOutcome::Idempotent(rec) if rec.signature == vec![7,7,7])
            );
            // Same id + same kind + DIFFERENT payload → regular conflict.
            let out = store
                .check_redemption(id1(), RedemptionKind::Delivery, hash_b())
                .await
                .expect("check");
            assert!(matches!(out, RedemptionCheckOutcome::Conflict { .. }));
            // Same id + DIFFERENT kind (refund after delivery) → mutex violation.
            let out = store
                .check_redemption(id1(), RedemptionKind::Refund, hash_a())
                .await
                .expect("check");
            assert!(matches!(
                out,
                RedemptionCheckOutcome::MutexViolation {
                    previous_kind: RedemptionKind::Delivery,
                    ..
                }
            ));
            // Different redemption → independent FirstTime.
            assert_eq!(
                store
                    .check_redemption(id2(), RedemptionKind::Refund, hash_a())
                    .await
                    .expect("check"),
                RedemptionCheckOutcome::FirstTime
            );
            // Record refund on id2; check mutex from the other direction.
            store
                .record_redemption(id2(), RedemptionKind::Refund, hash_a(), vec![1], 200)
                .await
                .expect("record");
            let out = store
                .check_redemption(id2(), RedemptionKind::Delivery, hash_a())
                .await
                .expect("check");
            assert!(matches!(
                out,
                RedemptionCheckOutcome::MutexViolation {
                    previous_kind: RedemptionKind::Refund,
                    ..
                }
            ));
            // Second record on same id errors (race-safety net).
            assert!(store
                .record_redemption(id1(), RedemptionKind::Delivery, hash_a(), vec![], 300)
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

    #[tokio::test]
    async fn in_memory_attestation_lifecycle() {
        let store = InMemoryReplayStore::new();
        run_attestation_lifecycle(&store).await;
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
