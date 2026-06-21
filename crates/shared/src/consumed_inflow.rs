//! RUST-004 consumed-inflow ledger: `(tx_hash, log_index) → (redemption_id, leg_index)`.
//!
//! The burn → USDT redemption cross-check confirms the USDT `THORChain`
//! swapped actually landed at the GLOBAL `IndexToken` address. Binding only
//! `(redemption_id, leg_index)` (as the F2 [`crate::redemption_dispatch`]
//! store does) is NOT enough: two redemptions can cite the SAME physical
//! on-chain `Transfer` and both be credited (double-credit, basket short one
//! payout). This ledger records, per physical inflow `(tx_hash, log_index)`,
//! the ONE `(redemption_id, leg_index)` that consumed it; a second leg
//! presenting the same inflow is refused.
//!
//! `THORChain` can batch several outbound deliveries into one transaction, so
//! the key MUST include `log_index` — `tx_hash` alone would collide two
//! distinct `Transfer` logs in the same outbound tx.
//!
//! Same `*Store` shape as [`crate::redemption_dispatch`]: one AFIT trait +
//! `InMemory*` (tests / dev) + `Sqlite*` (prod, survives restarts) +
//! `Any*` enum branch, static dispatch, no `async-trait`. The Sqlite impl
//! shares the same `migrations/` directory and is selected by the same
//! `REDEMPTION_DATABASE_URL` so both tables live in one database file.

use std::collections::HashMap;

use alloy_primitives::B256;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use thiserror::Error;
use tokio::sync::Mutex;

/// Errors surfaced by consumed-inflow operations.
#[derive(Debug, Error)]
pub enum ConsumedInflowError {
    /// Underlying `sqlx` failure (connect, query, decode).
    #[error("sqlite error: {0}")]
    Sqlite(#[from] sqlx::Error),

    /// Migration application failed.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// A stored row was malformed (wrong byte length / range), or an
    /// `INSERT OR IGNORE` was ignored yet the conflicting row could not be
    /// read back. Fail loud — these signal data damage.
    #[error("decode error: {0}")]
    Decode(String),
}

/// Outcome of trying to claim a physical inflow for a redemption leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InflowConsumeOutcome {
    /// The inflow was previously unclaimed and is now recorded as consumed
    /// by the calling `(redemption_id, leg_index)`. Credit it.
    Consumed,
    /// The inflow was already consumed by the SAME `(redemption_id,
    /// leg_index)` — an idempotent retry (e.g. a backfill re-run). Credit it.
    AlreadyByThisLeg,
    /// The inflow was already consumed by a DIFFERENT `(redemption_id,
    /// leg_index)` — the double-credit attempt RUST-004 closes. Refuse it.
    ConflictByOtherLeg {
        /// The redemption that first consumed this inflow.
        existing_redemption_id: B256,
        /// The leg of that redemption.
        existing_leg_index: u32,
    },
}

/// Operations the redemption cross-check needs to make each physical inflow
/// single-use.
///
/// Internal sync: implementations own their concurrency (Mutex / connection
/// pool). Callers do NOT wrap with an external lock.
pub trait ConsumedInflowStore: Send + Sync {
    /// Claim the physical inflow `(tx_hash, log_index)` for `(redemption_id,
    /// leg_index)`. The first claimant wins ([`InflowConsumeOutcome::Consumed`]);
    /// the same leg re-claiming is idempotent ([`InflowConsumeOutcome::AlreadyByThisLeg`]);
    /// any other leg is refused ([`InflowConsumeOutcome::ConflictByOtherLeg`]).
    /// The claim is atomic (Mutex / `INSERT OR IGNORE` on the PK), so a race
    /// between two legs for the same inflow yields exactly one winner.
    fn consume_inflow(
        &self,
        redemption_id: B256,
        leg_index: u32,
        tx_hash: B256,
        log_index: u64,
    ) -> impl std::future::Future<Output = Result<InflowConsumeOutcome, ConsumedInflowError>> + Send;
}

/// In-memory store. Loses state on restart — tests / dev only.
#[derive(Debug, Default)]
pub struct InMemoryConsumedInflow {
    inner: Mutex<HashMap<(B256, u64), (B256, u32)>>,
}

impl InMemoryConsumedInflow {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ConsumedInflowStore for InMemoryConsumedInflow {
    async fn consume_inflow(
        &self,
        redemption_id: B256,
        leg_index: u32,
        tx_hash: B256,
        log_index: u64,
    ) -> Result<InflowConsumeOutcome, ConsumedInflowError> {
        let mut guard = self.inner.lock().await;
        match guard.get(&(tx_hash, log_index)) {
            None => {
                guard.insert((tx_hash, log_index), (redemption_id, leg_index));
                Ok(InflowConsumeOutcome::Consumed)
            }
            Some(&(existing_redemption_id, existing_leg_index)) => {
                if existing_redemption_id == redemption_id && existing_leg_index == leg_index {
                    Ok(InflowConsumeOutcome::AlreadyByThisLeg)
                } else {
                    Ok(InflowConsumeOutcome::ConflictByOtherLeg {
                        existing_redemption_id,
                        existing_leg_index,
                    })
                }
            }
        }
    }
}

/// `sqlx`-backed persistent store. Survives daemon restarts.
///
/// On startup [`SqliteConsumedInflow::connect`] applies the `migrations/`
/// schema (shared with [`crate::redemption_dispatch`]); subsequent restarts
/// are idempotent.
pub struct SqliteConsumedInflow {
    pool: SqlitePool,
}

impl std::fmt::Debug for SqliteConsumedInflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Omit pool internals — they would leak a path/URL into logs.
        f.debug_struct("SqliteConsumedInflow")
            .finish_non_exhaustive()
    }
}

impl SqliteConsumedInflow {
    /// Open a `SQLite` connection and apply pending migrations.
    ///
    /// # Errors
    /// [`ConsumedInflowError::Sqlite`] on connect / pool failure;
    /// [`ConsumedInflowError::Migrate`] if a migration fails to apply.
    pub async fn connect(database_url: &str) -> Result<Self, ConsumedInflowError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }
}

impl ConsumedInflowStore for SqliteConsumedInflow {
    async fn consume_inflow(
        &self,
        redemption_id: B256,
        leg_index: u32,
        tx_hash: B256,
        log_index: u64,
    ) -> Result<InflowConsumeOutcome, ConsumedInflowError> {
        let log_i = i64::try_from(log_index).map_err(|e| {
            ConsumedInflowError::Decode(format!("u64→i64 overflow on log_index: {e}"))
        })?;
        // Atomic claim: the PK (tx_hash, log_index) makes INSERT OR IGNORE
        // resolve a concurrent race to exactly one winner (rows_affected == 1).
        let res = sqlx::query(
            r"
            INSERT OR IGNORE INTO consumed_inflow
                (tx_hash, log_index, redemption_id, leg_index)
            VALUES (?, ?, ?, ?)
            ",
        )
        .bind(tx_hash.as_slice())
        .bind(log_i)
        .bind(redemption_id.as_slice())
        .bind(i64::from(leg_index))
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 1 {
            return Ok(InflowConsumeOutcome::Consumed);
        }
        // Ignored ⇒ a row for this inflow already exists. Read who owns it.
        let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT redemption_id, leg_index FROM consumed_inflow
             WHERE tx_hash = ? AND log_index = ?",
        )
        .bind(tx_hash.as_slice())
        .bind(log_i)
        .fetch_optional(&self.pool)
        .await?;
        let (existing_id_bytes, existing_leg) = row.ok_or_else(|| {
            ConsumedInflowError::Decode(
                "INSERT OR IGNORE was ignored but no conflicting row was found".to_string(),
            )
        })?;
        let existing_redemption_id = B256::try_from(existing_id_bytes.as_slice()).map_err(|e| {
            ConsumedInflowError::Decode(format!("stored redemption_id not 32 bytes: {e}"))
        })?;
        let existing_leg_index = u32::try_from(existing_leg).map_err(|e| {
            ConsumedInflowError::Decode(format!("stored leg_index out of u32: {e}"))
        })?;
        if existing_redemption_id == redemption_id && existing_leg_index == leg_index {
            Ok(InflowConsumeOutcome::AlreadyByThisLeg)
        } else {
            Ok(InflowConsumeOutcome::ConflictByOtherLeg {
                existing_redemption_id,
                existing_leg_index,
            })
        }
    }
}

/// Concrete store dispatch shared by the redemption-attest binary and the
/// cross-check policies. The trait is AFIT (not dyn-compatible), so rather
/// than explode every policy's generics we branch once here and delegate.
/// `connect(None)` = in-memory (dev / tests, lost on restart);
/// `connect(Some(url))` = persistent `SQLite`.
#[derive(Debug)]
pub enum AnyConsumedInflow {
    Mem(InMemoryConsumedInflow),
    Sql(SqliteConsumedInflow),
}

impl AnyConsumedInflow {
    /// `Some(url)` → `SQLite` (applies migrations); `None` → in-memory.
    ///
    /// # Errors
    /// [`ConsumedInflowError`] if the `SQLite` connect / migration fails.
    pub async fn connect(database_url: Option<&str>) -> Result<Self, ConsumedInflowError> {
        match database_url {
            Some(url) => Ok(Self::Sql(SqliteConsumedInflow::connect(url).await?)),
            None => Ok(Self::Mem(InMemoryConsumedInflow::new())),
        }
    }
}

impl ConsumedInflowStore for AnyConsumedInflow {
    async fn consume_inflow(
        &self,
        redemption_id: B256,
        leg_index: u32,
        tx_hash: B256,
        log_index: u64,
    ) -> Result<InflowConsumeOutcome, ConsumedInflowError> {
        match self {
            Self::Mem(s) => {
                s.consume_inflow(redemption_id, leg_index, tx_hash, log_index)
                    .await
            }
            Self::Sql(s) => {
                s.consume_inflow(redemption_id, leg_index, tx_hash, log_index)
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    const TXH: B256 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
    const RID_A: B256 = b256!("00000000000000000000000000000000000000000000000000000000000000a1");
    const RID_B: B256 = b256!("00000000000000000000000000000000000000000000000000000000000000b2");

    async fn assert_consume_semantics<S: ConsumedInflowStore>(store: &S) {
        // First claim wins.
        assert_eq!(
            store
                .consume_inflow(RID_A, 0, TXH, 7)
                .await
                .unwrap_or_else(|e| unreachable!("{e}")),
            InflowConsumeOutcome::Consumed
        );
        // Same leg re-claiming is idempotent.
        assert_eq!(
            store
                .consume_inflow(RID_A, 0, TXH, 7)
                .await
                .unwrap_or_else(|e| unreachable!("{e}")),
            InflowConsumeOutcome::AlreadyByThisLeg
        );
        // A different redemption claiming the SAME inflow is refused.
        assert_eq!(
            store
                .consume_inflow(RID_B, 0, TXH, 7)
                .await
                .unwrap_or_else(|e| unreachable!("{e}")),
            InflowConsumeOutcome::ConflictByOtherLeg {
                existing_redemption_id: RID_A,
                existing_leg_index: 0,
            }
        );
        // A different leg of the SAME redemption is also refused (the inflow
        // is physically one delivery; only one leg may consume it).
        assert_eq!(
            store
                .consume_inflow(RID_A, 1, TXH, 7)
                .await
                .unwrap_or_else(|e| unreachable!("{e}")),
            InflowConsumeOutcome::ConflictByOtherLeg {
                existing_redemption_id: RID_A,
                existing_leg_index: 0,
            }
        );
        // A different log_index in the same tx is an independent inflow.
        assert_eq!(
            store
                .consume_inflow(RID_B, 0, TXH, 9)
                .await
                .unwrap_or_else(|e| unreachable!("{e}")),
            InflowConsumeOutcome::Consumed
        );
    }

    #[tokio::test]
    async fn in_memory_consume_semantics() {
        assert_consume_semantics(&InMemoryConsumedInflow::new()).await;
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_consume_semantics() {
        let store = SqliteConsumedInflow::connect("sqlite::memory:")
            .await
            .expect("connect + migrate");
        assert_consume_semantics(&store).await;
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn any_delegates_both_backends() {
        let mem = AnyConsumedInflow::connect(None).await.expect("mem");
        assert_consume_semantics(&mem).await;
        let sql = AnyConsumedInflow::connect(Some("sqlite::memory:"))
            .await
            .expect("sql");
        assert_consume_semantics(&sql).await;
    }
}
