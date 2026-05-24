//! Persistence layer for the deadline-relayer.
//!
//! Closes Rust-audit finding L-R4 / M-R12: the in-memory `HashMap`
//! used by [`crate::tracker::IntentTracker`] lost all tracked intents
//! on daemon restart, requiring `--from-block` backfill for recovery.
//!
//! ## Design
//!
//! A single trait — [`IntentTrackerStore`] — describes the operations
//! the binary needs (`observe`, `mark_resolved`, `len`, `scan`). Two
//! implementations:
//!
//! 1. [`InMemoryIntentTracker`] — wraps the legacy
//!    [`crate::tracker::IntentTracker`] behind a `tokio::sync::Mutex`.
//!    Used by tests + dev environments where persistence isn't
//!    required.
//! 2. [`SqliteIntentTracker`] — `sqlx`-backed; survives daemon
//!    restarts. Used in production (selected by setting `DATABASE_URL`
//!    in `xindex-cancel`).
//!
//! Static dispatch: the binary monomorphises over `T:
//! IntentTrackerStore` so we avoid `Box<dyn>` and the `async-trait`
//! macro dependency. AFIT (async fn in traits) is stable as of Rust
//! 1.75 and the workspace pins 1.85.

use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::{Address, B256};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::tracker::{IntentTracker, RelayDecision, TrackedIntent};

/// Errors surfaced by store operations.
#[derive(Debug, Error)]
pub enum TrackerError {
    /// Underlying `sqlx` failure (connect, query, decode).
    #[error("sqlite error: {0}")]
    Sqlite(#[from] sqlx::Error),

    /// Migration application failed.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// Decoding a stored row produced an invalid value (wrong byte
    /// length, integer out of range). Fail loud rather than silently
    /// substitute — corrupt rows signal data damage we want surfaced.
    #[error("decode error: {0}")]
    Decode(String),
}

/// Operations the relayer binary needs from its tracker store.
///
/// Internal sync: implementations own their concurrency (Mutex /
/// connection pool). Callers do NOT wrap with an external lock.
pub trait IntentTrackerStore: Send + Sync {
    /// Record a freshly-observed intent. Idempotent: re-observing the
    /// same `id` overwrites the previous entry.
    fn observe(
        &self,
        id: B256,
        intent: TrackedIntent,
    ) -> impl std::future::Future<Output = Result<(), TrackerError>> + Send;

    /// Drop the intent — called on `MintIntentFinalized` /
    /// `MintIntentCancelled`. Idempotent.
    fn mark_resolved(
        &self,
        id: &B256,
    ) -> impl std::future::Future<Output = Result<(), TrackerError>> + Send;

    /// Number of tracked (unresolved) intents.
    fn len(&self) -> impl std::future::Future<Output = Result<usize, TrackerError>> + Send;

    /// `true` if no intents are currently tracked. Default impl asks
    /// `len() == 0`; override if a backend can answer this cheaper than
    /// a full count.
    fn is_empty(&self) -> impl std::future::Future<Output = Result<bool, TrackerError>> + Send {
        async { Ok(self.len().await? == 0) }
    }

    /// Intents whose deadline has crossed `now_unix`. Sorted by
    /// `intent_id` for deterministic test + replay output.
    fn scan(
        &self,
        now_unix: u64,
    ) -> impl std::future::Future<Output = Result<RelayDecision, TrackerError>> + Send;
}

/// In-memory store wrapping the legacy [`IntentTracker`].
///
/// Equivalent to the pre-persistence behaviour. Use for tests + dev.
#[derive(Debug, Default)]
pub struct InMemoryIntentTracker {
    inner: Mutex<IntentTracker>,
}

impl InMemoryIntentTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl IntentTrackerStore for InMemoryIntentTracker {
    async fn observe(&self, id: B256, intent: TrackedIntent) -> Result<(), TrackerError> {
        self.inner.lock().await.observe(id, intent);
        Ok(())
    }

    async fn mark_resolved(&self, id: &B256) -> Result<(), TrackerError> {
        self.inner.lock().await.mark_resolved(id);
        Ok(())
    }

    async fn len(&self) -> Result<usize, TrackerError> {
        Ok(self.inner.lock().await.len())
    }

    async fn scan(&self, now_unix: u64) -> Result<RelayDecision, TrackerError> {
        Ok(self.inner.lock().await.scan(now_unix))
    }
}

/// `sqlx`-backed persistent store. Survives daemon restarts.
///
/// On startup [`SqliteIntentTracker::connect`] applies the
/// `migrations/` schema; subsequent restarts are idempotent.
///
/// Concurrency: the underlying `SqlitePool` (5 connections) handles
/// concurrent access. No external lock required.
pub struct SqliteIntentTracker {
    pool: SqlitePool,
}

impl std::fmt::Debug for SqliteIntentTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // SqlitePool deliberately omits its connection details (pointers,
        // open connections) from any output — surfacing them would leak
        // a path/URL into logs.
        f.debug_struct("SqliteIntentTracker")
            .finish_non_exhaustive()
    }
}

impl SqliteIntentTracker {
    /// Open a `SQLite` connection at `database_url` and apply pending
    /// migrations. Common URLs:
    ///
    /// - `sqlite::memory:` — ephemeral, for tests
    /// - `sqlite:./xindex-relayer.db` — file-backed, for prod
    /// - `sqlite:./xindex-relayer.db?mode=rwc` — file, create if missing
    ///
    /// # Errors
    /// [`TrackerError::Sqlite`] on connect / pool failure;
    /// [`TrackerError::Migrate`] if a migration fails to apply.
    pub async fn connect(database_url: &str) -> Result<Self, TrackerError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    /// Cast a `u64` unix timestamp to the `i64` `SQLite` INTEGER stores.
    /// Reject values that exceed `i64::MAX` rather than wrapping —
    /// silent overflow would corrupt the deadline column.
    fn cast_secs(unix_secs: u64) -> Result<i64, TrackerError> {
        i64::try_from(unix_secs)
            .map_err(|e| TrackerError::Decode(format!("u64→i64 overflow on unix secs: {e}")))
    }

    /// Best-effort wall-clock for `observed_at_unix_secs`. On clock
    /// failure (pre-1970) we record `0` rather than reject the insert
    /// — the column is metadata for ops sweeps, not load-bearing.
    fn observed_at_now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .unwrap_or(0)
    }
}

impl IntentTrackerStore for SqliteIntentTracker {
    async fn observe(&self, id: B256, intent: TrackedIntent) -> Result<(), TrackerError> {
        let deadline = Self::cast_secs(intent.deadline_unix_secs)?;
        let observed_at = Self::observed_at_now();
        let id_bytes = id.as_slice();
        let token_bytes = intent.index_token.as_slice();
        sqlx::query(
            r"
            INSERT INTO intents (intent_id, deadline_unix_secs, index_token, observed_at_unix_secs)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(intent_id) DO UPDATE SET
                deadline_unix_secs = excluded.deadline_unix_secs,
                index_token = excluded.index_token
            ",
        )
        .bind(id_bytes)
        .bind(deadline)
        .bind(token_bytes)
        .bind(observed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn mark_resolved(&self, id: &B256) -> Result<(), TrackerError> {
        let id_bytes = id.as_slice();
        sqlx::query("DELETE FROM intents WHERE intent_id = ?")
            .bind(id_bytes)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn len(&self) -> Result<usize, TrackerError> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM intents")
            .fetch_one(&self.pool)
            .await?;
        usize::try_from(row.0)
            .map_err(|e| TrackerError::Decode(format!("count→usize overflow: {e}")))
    }

    async fn scan(&self, now_unix: u64) -> Result<RelayDecision, TrackerError> {
        let now = Self::cast_secs(now_unix)?;
        let rows: Vec<(Vec<u8>, i64, Vec<u8>)> = sqlx::query_as(
            "SELECT intent_id, deadline_unix_secs, index_token
             FROM intents
             WHERE deadline_unix_secs < ?
             ORDER BY intent_id",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        let mut expired = Vec::with_capacity(rows.len());
        for (id_bytes, deadline, token_bytes) in rows {
            let id_arr: [u8; 32] = id_bytes
                .as_slice()
                .try_into()
                .map_err(|_| TrackerError::Decode("intent_id != 32 bytes".to_string()))?;
            let token_arr: [u8; 20] = token_bytes
                .as_slice()
                .try_into()
                .map_err(|_| TrackerError::Decode("index_token != 20 bytes".to_string()))?;
            let deadline_u64 = u64::try_from(deadline)
                .map_err(|e| TrackerError::Decode(format!("stored deadline negative: {e}")))?;
            expired.push((
                B256::from(id_arr),
                TrackedIntent {
                    deadline_unix_secs: deadline_u64,
                    index_token: Address::from(token_arr),
                },
            ));
        }
        Ok(RelayDecision { expired })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};

    fn ti(deadline: u64) -> TrackedIntent {
        TrackedIntent {
            deadline_unix_secs: deadline,
            index_token: address!("00000000000000000000000000000000000000aa"),
        }
    }

    /// In-memory variant — mirrors the legacy `IntentTracker` behaviour.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn in_memory_observe_scan_resolve() {
        let store = InMemoryIntentTracker::new();
        let id_a = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let id_b = b256!("0000000000000000000000000000000000000000000000000000000000000002");
        store.observe(id_a, ti(100)).await.expect("observe");
        store.observe(id_b, ti(200)).await.expect("observe");
        assert_eq!(store.len().await.expect("len"), 2);

        let decision = store.scan(150).await.expect("scan");
        assert_eq!(decision.expired.len(), 1);
        assert_eq!(decision.expired[0].0, id_a);

        store.mark_resolved(&id_a).await.expect("resolve");
        assert_eq!(store.len().await.expect("len"), 1);
    }

    /// `SQLite` variant against an in-memory database. Closes
    /// L-R4 / M-R12: the persisted shape matches the in-memory one,
    /// so swapping impls in the binary preserves semantics.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_observe_scan_resolve() {
        let store = SqliteIntentTracker::connect("sqlite::memory:")
            .await
            .expect("sqlite connect + migrate");
        let id_a = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let id_b = b256!("0000000000000000000000000000000000000000000000000000000000000002");
        store.observe(id_a, ti(100)).await.expect("observe");
        store.observe(id_b, ti(200)).await.expect("observe");
        assert_eq!(store.len().await.expect("len"), 2);

        let decision = store.scan(150).await.expect("scan");
        assert_eq!(decision.expired.len(), 1);
        assert_eq!(decision.expired[0].0, id_a);
        assert_eq!(decision.expired[0].1.deadline_unix_secs, 100);

        store.mark_resolved(&id_a).await.expect("resolve");
        assert_eq!(store.len().await.expect("len"), 1);

        // Idempotent re-resolve.
        store
            .mark_resolved(&id_a)
            .await
            .expect("resolve idempotent");
        assert_eq!(store.len().await.expect("len"), 1);
    }

    /// Re-observing the same intent updates its deadline (the
    /// `ON CONFLICT DO UPDATE` clause). Mirrors the in-memory
    /// `observe_replaces_existing` test.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_observe_replaces_existing() {
        let store = SqliteIntentTracker::connect("sqlite::memory:")
            .await
            .expect("sqlite connect + migrate");
        let id = b256!("00000000000000000000000000000000000000000000000000000000000000bb");
        store.observe(id, ti(100)).await.expect("observe");
        store.observe(id, ti(500)).await.expect("re-observe");

        // Old deadline 100 expired at scan(200); new deadline 500 is
        // still in the future, so the re-observed row dominates.
        let decision = store.scan(200).await.expect("scan");
        assert!(decision.expired.is_empty());

        let later = store.scan(600).await.expect("scan");
        assert_eq!(later.expired.len(), 1);
        assert_eq!(later.expired[0].1.deadline_unix_secs, 500);
    }

    /// Scan output is deterministically sorted by `intent_id` —
    /// matters for replay + diff-style operator dashboards.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_scan_sorted_by_id() {
        let store = SqliteIntentTracker::connect("sqlite::memory:")
            .await
            .expect("sqlite connect + migrate");
        // Insert in reverse-sorted order; expect sorted-asc output.
        let id_c = b256!("0000000000000000000000000000000000000000000000000000000000000003");
        let id_a = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let id_b = b256!("0000000000000000000000000000000000000000000000000000000000000002");
        store.observe(id_c, ti(50)).await.expect("c");
        store.observe(id_a, ti(50)).await.expect("a");
        store.observe(id_b, ti(50)).await.expect("b");

        let decision = store.scan(100).await.expect("scan");
        assert_eq!(decision.expired.len(), 3);
        assert_eq!(decision.expired[0].0, id_a);
        assert_eq!(decision.expired[1].0, id_b);
        assert_eq!(decision.expired[2].0, id_c);
    }
}
