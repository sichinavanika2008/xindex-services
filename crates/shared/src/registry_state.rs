//! Durable anti-equivocation and quote-nonce state for the `THORChain` registry
//! services.
//!
//! Two safety boundaries live here:
//!
//! - an operator reserves an inbound sequence or `(originator, quote_nonce)`
//!   **before** asking its HSM to sign; a crash leaves a visible pending row
//!   rather than silently reopening the identity for another payload; and
//! - quote nonce allocation is serialized by a partial unique index, reconciles
//!   against the finalized on-chain nonce, and requires an explicit expiry
//!   transition before a different payload can reuse the still-unconsumed next
//!   nonce.
//!
//! The store contains signatures and public hashes only. It never stores key
//! material, HSM credentials, provider credentials, or raw API secrets.

use alloy_primitives::{Address, B256};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use thiserror::Error;

/// Durable registry-state failure. All variants are fail-closed at callers.
#[derive(Debug, Error)]
pub enum RegistryStateError {
    /// Underlying `SQLite` failure.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] sqlx::Error),
    /// Schema migration failure.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// Stored bytes or integers violate the expected schema.
    #[error("decode error: {0}")]
    Decode(String),
    /// A requested state transition is not safe from the current state.
    #[error("invalid transition: {0}")]
    InvalidTransition(String),
}

/// The registry EIP-712 family being protected from equivocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrySignatureKind {
    /// `InboundState`, keyed by its monotonic sequence.
    Inbound,
    /// `QuoteAuthorization`, keyed by originator + quote nonce.
    Quote,
}

impl RegistrySignatureKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Quote => "quote",
        }
    }
}

/// Result of reserving one EIP-712 identity before HSM use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureReservation {
    /// This caller created the durable pending row and may invoke the HSM.
    Reserved,
    /// The exact payload was already signed; return these cached bytes.
    Signed([u8; 65]),
    /// The exact payload is pending, normally because another request is
    /// signing or a prior process crashed. Do not invoke the HSM again until
    /// an operator explicitly resolves the pending record.
    Pending { reserved_at: u64 },
    /// This identity is already bound to a different payload.
    Conflict {
        previous_payload_hash: B256,
        reserved_at: u64,
    },
}

/// Result of transactionally reserving the next on-chain quote nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuoteNonceReservation {
    /// A new reservation was created for `nonce`.
    Reserved { nonce: u64 },
    /// The same payload already owns the active reservation.
    Idempotent { nonce: u64 },
    /// A different payload owns the next nonce. It must be consumed or
    /// explicitly expired before another quote can proceed.
    Busy {
        nonce: u64,
        expires_at: u64,
        payload_hash: B256,
    },
    /// Durable state proves a nonce was consumed beyond the finalized value
    /// supplied by the caller. Treat this as an RPC/reorg/state-loss anomaly.
    OnchainBehind {
        finalized_onchain_nonce: u64,
        durable_consumed_nonce: u64,
    },
    /// The on-chain `uint64` nonce has no successor.
    Exhausted,
}

/// SQLite-backed registry state. Production callers must use a durable volume
/// and a backup/restore policy; there is intentionally no in-memory production
/// fallback.
#[derive(Clone)]
pub struct SqliteRegistryState {
    pool: SqlitePool,
}

impl std::fmt::Debug for SqliteRegistryState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteRegistryState")
            .finish_non_exhaustive()
    }
}

impl SqliteRegistryState {
    /// Open the durable database and apply the shared schema migrations.
    ///
    /// # Errors
    /// [`RegistryStateError`] on connection or migration failure.
    pub async fn connect(database_url: &str) -> Result<Self, RegistryStateError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    /// Reserve an inbound sequence before requesting its HSM signature.
    ///
    /// # Errors
    /// Returns [`RegistryStateError`] if durable state cannot be read, decoded,
    /// or updated.
    pub async fn reserve_inbound_signature(
        &self,
        sequence: u64,
        payload_hash: B256,
        now: u64,
    ) -> Result<SignatureReservation, RegistryStateError> {
        self.reserve_signature(
            RegistrySignatureKind::Inbound,
            sequence.to_be_bytes().to_vec(),
            payload_hash,
            now,
        )
        .await
    }

    /// Reserve one originator/nonce quote identity before requesting its HSM
    /// signature.
    ///
    /// # Errors
    /// Returns [`RegistryStateError`] if durable state cannot be read, decoded,
    /// or updated.
    pub async fn reserve_quote_signature(
        &self,
        originator: Address,
        nonce: u64,
        payload_hash: B256,
        now: u64,
    ) -> Result<SignatureReservation, RegistryStateError> {
        self.reserve_signature(
            RegistrySignatureKind::Quote,
            quote_identity(originator, nonce),
            payload_hash,
            now,
        )
        .await
    }

    /// Complete a previously reserved inbound signature. The signature is
    /// durably committed before the caller may publish it.
    ///
    /// # Errors
    /// Returns [`RegistryStateError`] if the reservation does not match or the
    /// durable commit fails.
    pub async fn complete_inbound_signature(
        &self,
        sequence: u64,
        payload_hash: B256,
        signature: [u8; 65],
        now: u64,
    ) -> Result<(), RegistryStateError> {
        self.complete_signature(
            RegistrySignatureKind::Inbound,
            sequence.to_be_bytes().to_vec(),
            payload_hash,
            signature,
            now,
        )
        .await
    }

    /// Complete a previously reserved quote signature.
    ///
    /// # Errors
    /// Returns [`RegistryStateError`] if the reservation does not match or the
    /// durable commit fails.
    pub async fn complete_quote_signature(
        &self,
        originator: Address,
        nonce: u64,
        payload_hash: B256,
        signature: [u8; 65],
        now: u64,
    ) -> Result<(), RegistryStateError> {
        self.complete_signature(
            RegistrySignatureKind::Quote,
            quote_identity(originator, nonce),
            payload_hash,
            signature,
            now,
        )
        .await
    }

    /// Explicitly abandon a pending signature after an HSM failure was
    /// investigated. Signed rows and different-payload rows cannot be removed.
    ///
    /// # Errors
    /// Returns [`RegistryStateError`] if the durable delete cannot be applied.
    pub async fn abandon_pending_signature(
        &self,
        kind: RegistrySignatureKind,
        identity: &[u8],
        payload_hash: B256,
    ) -> Result<bool, RegistryStateError> {
        let result = sqlx::query(
            "DELETE FROM registry_signature_reservations
             WHERE kind = ? AND identity = ? AND payload_hash = ? AND signature IS NULL",
        )
        .bind(kind.as_str())
        .bind(identity)
        .bind(payload_hash.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Reserve `finalized_onchain_nonce + 1` for this originator. An active
    /// same-payload reservation is idempotent; a different payload is busy.
    /// If the finalized chain has consumed the active reservation, this method
    /// reconciles it to `consumed` before allocating the next one.
    ///
    /// # Errors
    /// Returns [`RegistryStateError`] on invalid transitions, corrupt durable
    /// state, or database failure.
    pub async fn reserve_quote_nonce(
        &self,
        originator: Address,
        finalized_onchain_nonce: u64,
        payload_hash: B256,
        expires_at: u64,
        now: u64,
    ) -> Result<QuoteNonceReservation, RegistryStateError> {
        if expires_at <= now {
            return Err(RegistryStateError::InvalidTransition(
                "cannot reserve an already-expired quote".to_string(),
            ));
        }
        let onchain_i = to_i64(finalized_onchain_nonce, "on-chain nonce")?;
        let durable_consumed: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(nonce) FROM quote_nonce_reservations
             WHERE originator = ? AND state = 'consumed'",
        )
        .bind(originator.as_slice())
        .fetch_one(&self.pool)
        .await?;
        if let Some(durable) = durable_consumed {
            if durable > onchain_i {
                return Ok(QuoteNonceReservation::OnchainBehind {
                    finalized_onchain_nonce,
                    durable_consumed_nonce: from_i64(durable, "durable consumed nonce")?,
                });
            }
        }

        if let Some((id, nonce_i, existing_hash, existing_expiry)) =
            self.active_quote_reservation(originator).await?
        {
            let nonce = from_i64(nonce_i, "active quote nonce")?;
            if nonce <= finalized_onchain_nonce {
                sqlx::query(
                    "UPDATE quote_nonce_reservations
                     SET state = 'consumed', updated_at = ?
                     WHERE id = ? AND state = 'reserved'",
                )
                .bind(to_i64(now, "current time")?)
                .bind(id)
                .execute(&self.pool)
                .await?;
            } else {
                let expected = finalized_onchain_nonce.checked_add(1).ok_or(
                    RegistryStateError::InvalidTransition(
                        "on-chain quote nonce exhausted".to_string(),
                    ),
                )?;
                if nonce != expected {
                    return Err(RegistryStateError::InvalidTransition(format!(
                        "active quote nonce {nonce} is not finalized nonce {finalized_onchain_nonce} + 1"
                    )));
                }
                let existing_hash = decode_b256(&existing_hash, "active quote payload hash")?;
                if existing_hash == payload_hash {
                    return Ok(QuoteNonceReservation::Idempotent { nonce });
                }
                return Ok(QuoteNonceReservation::Busy {
                    nonce,
                    expires_at: from_i64(existing_expiry, "active quote expiry")?,
                    payload_hash: existing_hash,
                });
            }
        }

        let Some(next) = finalized_onchain_nonce.checked_add(1) else {
            return Ok(QuoteNonceReservation::Exhausted);
        };
        let result = sqlx::query(
            "INSERT OR IGNORE INTO quote_nonce_reservations
                (originator, nonce, payload_hash, expires_at, state, created_at, updated_at)
             VALUES (?, ?, ?, ?, 'reserved', ?, ?)",
        )
        .bind(originator.as_slice())
        .bind(to_i64(next, "next quote nonce")?)
        .bind(payload_hash.as_slice())
        .bind(to_i64(expires_at, "quote expiry")?)
        .bind(to_i64(now, "current time")?)
        .bind(to_i64(now, "current time")?)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 1 {
            return Ok(QuoteNonceReservation::Reserved { nonce: next });
        }

        // A concurrent process won the partial-unique-index race. Read and
        // report the winner rather than retrying with a later nonce.
        let (_, nonce_i, existing_hash, existing_expiry) = self
            .active_quote_reservation(originator)
            .await?
            .ok_or_else(|| {
                RegistryStateError::Decode(
                    "quote reservation insert lost a race but no active winner exists".to_string(),
                )
            })?;
        let nonce = from_i64(nonce_i, "active quote nonce")?;
        let existing_hash = decode_b256(&existing_hash, "active quote payload hash")?;
        if existing_hash == payload_hash {
            Ok(QuoteNonceReservation::Idempotent { nonce })
        } else {
            Ok(QuoteNonceReservation::Busy {
                nonce,
                expires_at: from_i64(existing_expiry, "active quote expiry")?,
                payload_hash: existing_hash,
            })
        }
    }

    /// Mark the active reservation consumed after the supplied finalized
    /// on-chain nonce proves inclusion.
    ///
    /// # Errors
    /// Returns [`RegistryStateError`] when finalized state does not prove
    /// consumption, the reservation differs, or the durable update fails.
    pub async fn mark_quote_nonce_consumed(
        &self,
        originator: Address,
        nonce: u64,
        payload_hash: B256,
        finalized_onchain_nonce: u64,
        now: u64,
    ) -> Result<(), RegistryStateError> {
        if finalized_onchain_nonce < nonce {
            return Err(RegistryStateError::InvalidTransition(format!(
                "finalized on-chain nonce {finalized_onchain_nonce} has not consumed reservation {nonce}"
            )));
        }
        let result = sqlx::query(
            "UPDATE quote_nonce_reservations
             SET state = 'consumed', updated_at = ?
             WHERE originator = ? AND nonce = ? AND payload_hash = ? AND state = 'reserved'",
        )
        .bind(to_i64(now, "current time")?)
        .bind(originator.as_slice())
        .bind(to_i64(nonce, "quote nonce")?)
        .bind(payload_hash.as_slice())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 1 {
            return Ok(());
        }
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT state FROM quote_nonce_reservations
             WHERE originator = ? AND nonce = ? AND payload_hash = ?
             ORDER BY id DESC LIMIT 1",
        )
        .bind(originator.as_slice())
        .bind(to_i64(nonce, "quote nonce")?)
        .bind(payload_hash.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        if existing.as_deref() == Some("consumed") {
            Ok(())
        } else {
            Err(RegistryStateError::InvalidTransition(
                "no matching active quote reservation to consume".to_string(),
            ))
        }
    }

    /// Explicitly retire an expired, unconsumed quote reservation. The row is
    /// retained as evidence; the next call may reserve the same on-chain next
    /// nonce for a freshly signed payload.
    ///
    /// # Errors
    /// Returns [`RegistryStateError`] when the row is absent/not expired or the
    /// durable update fails.
    pub async fn expire_quote_nonce(
        &self,
        originator: Address,
        nonce: u64,
        payload_hash: B256,
        now: u64,
    ) -> Result<(), RegistryStateError> {
        let result = sqlx::query(
            "UPDATE quote_nonce_reservations
             SET state = 'expired', updated_at = ?
             WHERE originator = ? AND nonce = ? AND payload_hash = ?
               AND state = 'reserved' AND expires_at <= ?",
        )
        .bind(to_i64(now, "current time")?)
        .bind(originator.as_slice())
        .bind(to_i64(nonce, "quote nonce")?)
        .bind(payload_hash.as_slice())
        .bind(to_i64(now, "current time")?)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(RegistryStateError::InvalidTransition(
                "quote reservation is absent, already retired, or not yet expired".to_string(),
            ))
        }
    }

    async fn reserve_signature(
        &self,
        kind: RegistrySignatureKind,
        identity: Vec<u8>,
        payload_hash: B256,
        now: u64,
    ) -> Result<SignatureReservation, RegistryStateError> {
        let result = sqlx::query(
            "INSERT OR IGNORE INTO registry_signature_reservations
                (kind, identity, payload_hash, signature, reserved_at, signed_at)
             VALUES (?, ?, ?, NULL, ?, NULL)",
        )
        .bind(kind.as_str())
        .bind(&identity)
        .bind(payload_hash.as_slice())
        .bind(to_i64(now, "reservation time")?)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 1 {
            return Ok(SignatureReservation::Reserved);
        }
        let row: Option<(Vec<u8>, Option<Vec<u8>>, i64)> = sqlx::query_as(
            "SELECT payload_hash, signature, reserved_at
             FROM registry_signature_reservations
             WHERE kind = ? AND identity = ?",
        )
        .bind(kind.as_str())
        .bind(&identity)
        .fetch_optional(&self.pool)
        .await?;
        let (previous_hash, signature, reserved_at) = row.ok_or_else(|| {
            RegistryStateError::Decode(
                "signature reservation insert lost a race but no winner exists".to_string(),
            )
        })?;
        let previous_hash = decode_b256(&previous_hash, "signature payload hash")?;
        let reserved_at = from_i64(reserved_at, "signature reservation time")?;
        if previous_hash != payload_hash {
            return Ok(SignatureReservation::Conflict {
                previous_payload_hash: previous_hash,
                reserved_at,
            });
        }
        match signature {
            Some(bytes) => Ok(SignatureReservation::Signed(decode_signature(&bytes)?)),
            None => Ok(SignatureReservation::Pending { reserved_at }),
        }
    }

    async fn complete_signature(
        &self,
        kind: RegistrySignatureKind,
        identity: Vec<u8>,
        payload_hash: B256,
        signature: [u8; 65],
        now: u64,
    ) -> Result<(), RegistryStateError> {
        let result = sqlx::query(
            "UPDATE registry_signature_reservations
             SET signature = ?, signed_at = ?
             WHERE kind = ? AND identity = ? AND payload_hash = ? AND signature IS NULL",
        )
        .bind(signature.as_slice())
        .bind(to_i64(now, "signature time")?)
        .bind(kind.as_str())
        .bind(&identity)
        .bind(payload_hash.as_slice())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 1 {
            return Ok(());
        }
        let existing: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT signature FROM registry_signature_reservations
             WHERE kind = ? AND identity = ? AND payload_hash = ?",
        )
        .bind(kind.as_str())
        .bind(&identity)
        .bind(payload_hash.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        match existing {
            Some(bytes) if decode_signature(&bytes)? == signature => Ok(()),
            Some(_) => Err(RegistryStateError::InvalidTransition(
                "a different signature already completed this payload".to_string(),
            )),
            None => Err(RegistryStateError::InvalidTransition(
                "signature was not reserved for this payload".to_string(),
            )),
        }
    }

    async fn active_quote_reservation(
        &self,
        originator: Address,
    ) -> Result<Option<(i64, i64, Vec<u8>, i64)>, RegistryStateError> {
        Ok(sqlx::query_as(
            "SELECT id, nonce, payload_hash, expires_at
             FROM quote_nonce_reservations
             WHERE originator = ? AND state = 'reserved'",
        )
        .bind(originator.as_slice())
        .fetch_optional(&self.pool)
        .await?)
    }
}

/// Canonical identity bytes for one quote signature.
#[must_use]
pub fn quote_signature_identity(originator: Address, nonce: u64) -> Vec<u8> {
    quote_identity(originator, nonce)
}

/// Canonical identity bytes for one inbound signature.
#[must_use]
pub fn inbound_signature_identity(sequence: u64) -> [u8; 8] {
    sequence.to_be_bytes()
}

fn quote_identity(originator: Address, nonce: u64) -> Vec<u8> {
    let mut identity = Vec::with_capacity(28);
    identity.extend_from_slice(originator.as_slice());
    identity.extend_from_slice(&nonce.to_be_bytes());
    identity
}

fn to_i64(value: u64, field: &str) -> Result<i64, RegistryStateError> {
    i64::try_from(value).map_err(|error| {
        RegistryStateError::Decode(format!("{field} does not fit SQLite: {error}"))
    })
}

fn from_i64(value: i64, field: &str) -> Result<u64, RegistryStateError> {
    u64::try_from(value)
        .map_err(|error| RegistryStateError::Decode(format!("{field} is negative: {error}")))
}

fn decode_b256(bytes: &[u8], field: &str) -> Result<B256, RegistryStateError> {
    B256::try_from(bytes)
        .map_err(|error| RegistryStateError::Decode(format!("{field} is not 32 bytes: {error}")))
}

fn decode_signature(bytes: &[u8]) -> Result<[u8; 65], RegistryStateError> {
    bytes.try_into().map_err(|_| {
        RegistryStateError::Decode(format!(
            "registry signature is {} bytes instead of 65",
            bytes.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]

    use super::*;

    async fn store(label: &str) -> (SqliteRegistryState, String) {
        let path = std::env::temp_dir().join(format!(
            "xindex-registry-state-{label}-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let store = SqliteRegistryState::connect(&url)
            .await
            .expect("connect registry state");
        (store, path.to_string_lossy().into_owned())
    }

    #[tokio::test]
    async fn signature_reservation_survives_restart_and_conflicts() {
        let (state, path) = store("signature").await;
        let hash = B256::repeat_byte(0x11);
        assert_eq!(
            state
                .reserve_inbound_signature(7, hash, 100)
                .await
                .expect("reserve"),
            SignatureReservation::Reserved
        );
        assert_eq!(
            state
                .reserve_inbound_signature(7, hash, 101)
                .await
                .expect("pending"),
            SignatureReservation::Pending { reserved_at: 100 }
        );
        assert!(matches!(
            state
                .reserve_inbound_signature(7, B256::repeat_byte(0x22), 101)
                .await
                .expect("conflict"),
            SignatureReservation::Conflict { .. }
        ));
        let signature = [0xabu8; 65];
        state
            .complete_inbound_signature(7, hash, signature, 102)
            .await
            .expect("complete");
        drop(state);
        let url = format!("sqlite://{path}?mode=rwc");
        let reopened = SqliteRegistryState::connect(&url).await.expect("reopen");
        assert_eq!(
            reopened
                .reserve_inbound_signature(7, hash, 200)
                .await
                .expect("cached"),
            SignatureReservation::Signed(signature)
        );
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn quote_nonce_concurrency_has_one_winner() {
        let (state, path) = store("nonce-race").await;
        let originator = Address::repeat_byte(0x33);
        let left = state.clone();
        let right = state.clone();
        let (a, b) = tokio::join!(
            left.reserve_quote_nonce(originator, 0, B256::repeat_byte(0x44), 200, 100),
            right.reserve_quote_nonce(originator, 0, B256::repeat_byte(0x55), 200, 100)
        );
        let outcomes = [a.expect("left"), b.expect("right")];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, QuoteNonceReservation::Reserved { nonce: 1 }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, QuoteNonceReservation::Busy { nonce: 1, .. }))
                .count(),
            1
        );
        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn quote_nonce_requires_explicit_expiry_before_reuse() {
        let (state, path) = store("nonce-expiry").await;
        let originator = Address::repeat_byte(0x66);
        let old = B256::repeat_byte(0x77);
        let new = B256::repeat_byte(0x88);
        assert_eq!(
            state
                .reserve_quote_nonce(originator, 4, old, 120, 100)
                .await
                .expect("reserve"),
            QuoteNonceReservation::Reserved { nonce: 5 }
        );
        assert!(matches!(
            state
                .reserve_quote_nonce(originator, 4, new, 180, 121)
                .await
                .expect("still busy"),
            QuoteNonceReservation::Busy { nonce: 5, .. }
        ));
        state
            .expire_quote_nonce(originator, 5, old, 121)
            .await
            .expect("explicit expiry");
        assert_eq!(
            state
                .reserve_quote_nonce(originator, 4, new, 180, 121)
                .await
                .expect("replacement"),
            QuoteNonceReservation::Reserved { nonce: 5 }
        );
        state
            .mark_quote_nonce_consumed(originator, 5, new, 5, 130)
            .await
            .expect("consume");
        assert_eq!(
            state
                .reserve_quote_nonce(originator, 5, B256::repeat_byte(0x99), 200, 140)
                .await
                .expect("next"),
            QuoteNonceReservation::Reserved { nonce: 6 }
        );
        drop(state);
        let _ = std::fs::remove_file(path);
    }
}
