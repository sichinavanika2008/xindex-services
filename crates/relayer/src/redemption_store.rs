//! Persistent tracker for in-flight burn → USDT redemptions.
//!
//! Unlike the mint relayer (deadline-driven `cancelMint`), finalize and
//! cancel here are EVENT-driven: `RedemptionAttested` →
//! `IndexToken.finalizeBurn`; `RedemptionRefundAttested` →
//! `IndexToken.cancelBurn`. This tracker exists solely for **SD-B
//! stuck-detection**: a redemption still tracked past its deadline (no
//! delivery, no refund — e.g. `THORChain` vault halted) is flagged for an
//! operator alert. There is deliberately NO on-chain auto-action for the
//! stuck case (no admin/timelock backdoor — SD-B).
//!
//! Same `*Store` shape as [`crate::store::IntentTrackerStore`]: one AFIT
//! trait + `InMemory*` (tests/dev) + `Sqlite*` (prod, survives restart
//! — closes the same persistence gap the mint side's L-R4/M-R12 fixed).

use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::{Address, B256};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum RedemptionTrackerError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("decode error: {0}")]
    Decode(String),
}

/// State held about one in-flight redemption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackedRedemption {
    /// `block.timestamp` past which, with NO delivery/refund attestation,
    /// the redemption is considered stuck (SD-B alert only).
    pub deadline_unix_secs: u64,
    /// `IndexToken` that owns the redemption (target of finalize/cancel).
    pub index_token: Address,
}

/// Output of [`RedemptionTrackerStore::scan`]: redemptions past deadline
/// still unresolved (no delivery, no refund) — operator must
/// investigate (`THORChain` halt / orphaned inbound). Sorted by id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StuckDecision {
    pub stuck: Vec<(B256, TrackedRedemption)>,
}

pub trait RedemptionTrackerStore: Send + Sync {
    /// Record a `RedemptionIntentCreated`. Idempotent (re-observe
    /// overwrites — identical data on replay).
    fn observe(
        &self,
        id: B256,
        r: TrackedRedemption,
    ) -> impl std::future::Future<Output = Result<(), RedemptionTrackerError>> + Send;

    /// Drop on `RedemptionIntentFinalized`/`Cancelled`. Idempotent.
    fn mark_resolved(
        &self,
        id: &B256,
    ) -> impl std::future::Future<Output = Result<(), RedemptionTrackerError>> + Send;

    /// Look up a tracked redemption (its `index_token` is the
    /// finalize/cancel target, resolved at delivery/refund-attested
    /// time). `None` if never observed / already resolved.
    fn get(
        &self,
        id: &B256,
    ) -> impl std::future::Future<Output = Result<Option<TrackedRedemption>, RedemptionTrackerError>>
           + Send;

    fn len(
        &self,
    ) -> impl std::future::Future<Output = Result<usize, RedemptionTrackerError>> + Send;

    fn is_empty(
        &self,
    ) -> impl std::future::Future<Output = Result<bool, RedemptionTrackerError>> + Send {
        async { Ok(self.len().await? == 0) }
    }

    /// Redemptions past `now_unix` still tracked = stuck (SD-B).
    fn scan(
        &self,
        now_unix: u64,
    ) -> impl std::future::Future<Output = Result<StuckDecision, RedemptionTrackerError>> + Send;
}

#[derive(Debug, Default)]
pub struct InMemoryRedemptionTracker {
    inner: Mutex<std::collections::HashMap<B256, TrackedRedemption>>,
}

impl InMemoryRedemptionTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl RedemptionTrackerStore for InMemoryRedemptionTracker {
    async fn observe(&self, id: B256, r: TrackedRedemption) -> Result<(), RedemptionTrackerError> {
        self.inner.lock().await.insert(id, r);
        Ok(())
    }
    async fn mark_resolved(&self, id: &B256) -> Result<(), RedemptionTrackerError> {
        self.inner.lock().await.remove(id);
        Ok(())
    }
    async fn get(&self, id: &B256) -> Result<Option<TrackedRedemption>, RedemptionTrackerError> {
        Ok(self.inner.lock().await.get(id).copied())
    }
    async fn len(&self) -> Result<usize, RedemptionTrackerError> {
        Ok(self.inner.lock().await.len())
    }
    async fn scan(&self, now_unix: u64) -> Result<StuckDecision, RedemptionTrackerError> {
        let g = self.inner.lock().await;
        let mut stuck: Vec<(B256, TrackedRedemption)> = g
            .iter()
            .filter(|(_, r)| now_unix > r.deadline_unix_secs)
            .map(|(id, r)| (*id, *r))
            .collect();
        stuck.sort_by_key(|(id, _)| *id);
        Ok(StuckDecision { stuck })
    }
}

/// `sqlx`-backed; survives daemon restarts.
pub struct SqliteRedemptionTracker {
    pool: SqlitePool,
}

impl std::fmt::Debug for SqliteRedemptionTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteRedemptionTracker")
            .finish_non_exhaustive()
    }
}

impl SqliteRedemptionTracker {
    /// Open + apply migrations.
    ///
    /// # Errors
    /// [`RedemptionTrackerError::Sqlite`] / `Migrate` on failure.
    pub async fn connect(database_url: &str) -> Result<Self, RedemptionTrackerError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    fn cast_secs(unix_secs: u64) -> Result<i64, RedemptionTrackerError> {
        i64::try_from(unix_secs)
            .map_err(|e| RedemptionTrackerError::Decode(format!("u64→i64 overflow: {e}")))
    }

    fn observed_at_now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .unwrap_or(0)
    }
}

impl RedemptionTrackerStore for SqliteRedemptionTracker {
    async fn observe(&self, id: B256, r: TrackedRedemption) -> Result<(), RedemptionTrackerError> {
        let deadline = Self::cast_secs(r.deadline_unix_secs)?;
        let observed_at = Self::observed_at_now();
        sqlx::query(
            r"
            INSERT INTO redemptions (redemption_id, deadline_unix_secs, index_token, observed_at_unix_secs)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(redemption_id) DO UPDATE SET
                deadline_unix_secs = excluded.deadline_unix_secs,
                index_token = excluded.index_token
            ",
        )
        .bind(id.as_slice())
        .bind(deadline)
        .bind(r.index_token.as_slice())
        .bind(observed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn mark_resolved(&self, id: &B256) -> Result<(), RedemptionTrackerError> {
        sqlx::query("DELETE FROM redemptions WHERE redemption_id = ?")
            .bind(id.as_slice())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get(&self, id: &B256) -> Result<Option<TrackedRedemption>, RedemptionTrackerError> {
        let row: Option<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT deadline_unix_secs, index_token FROM redemptions WHERE redemption_id = ?",
        )
        .bind(id.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some((deadline, token_bytes)) => {
                let token_arr: [u8; 20] = token_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| RedemptionTrackerError::Decode("index_token != 20".into()))?;
                let deadline_u64 = u64::try_from(deadline).map_err(|e| {
                    RedemptionTrackerError::Decode(format!("deadline negative: {e}"))
                })?;
                Ok(Some(TrackedRedemption {
                    deadline_unix_secs: deadline_u64,
                    index_token: Address::from(token_arr),
                }))
            }
        }
    }

    async fn len(&self) -> Result<usize, RedemptionTrackerError> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM redemptions")
            .fetch_one(&self.pool)
            .await?;
        usize::try_from(row.0)
            .map_err(|e| RedemptionTrackerError::Decode(format!("count→usize: {e}")))
    }

    async fn scan(&self, now_unix: u64) -> Result<StuckDecision, RedemptionTrackerError> {
        let now = Self::cast_secs(now_unix)?;
        let rows: Vec<(Vec<u8>, i64, Vec<u8>)> = sqlx::query_as(
            "SELECT redemption_id, deadline_unix_secs, index_token
             FROM redemptions WHERE deadline_unix_secs < ? ORDER BY redemption_id",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        let mut stuck = Vec::with_capacity(rows.len());
        for (id_bytes, deadline, token_bytes) in rows {
            let id_arr: [u8; 32] = id_bytes
                .as_slice()
                .try_into()
                .map_err(|_| RedemptionTrackerError::Decode("redemption_id != 32".into()))?;
            let token_arr: [u8; 20] = token_bytes
                .as_slice()
                .try_into()
                .map_err(|_| RedemptionTrackerError::Decode("index_token != 20".into()))?;
            let deadline_u64 = u64::try_from(deadline)
                .map_err(|e| RedemptionTrackerError::Decode(format!("deadline negative: {e}")))?;
            stuck.push((
                B256::from(id_arr),
                TrackedRedemption {
                    deadline_unix_secs: deadline_u64,
                    index_token: Address::from(token_arr),
                },
            ));
        }
        Ok(StuckDecision { stuck })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};

    fn tr(deadline: u64) -> TrackedRedemption {
        TrackedRedemption {
            deadline_unix_secs: deadline,
            index_token: address!("00000000000000000000000000000000000000aa"),
        }
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn in_memory_observe_scan_resolve() {
        let s = InMemoryRedemptionTracker::new();
        let a = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let b = b256!("0000000000000000000000000000000000000000000000000000000000000002");
        s.observe(a, tr(100)).await.expect("obs");
        s.observe(b, tr(200)).await.expect("obs");
        let d = s.scan(150).await.expect("scan");
        assert_eq!(d.stuck.len(), 1);
        assert_eq!(d.stuck[0].0, a);
        s.mark_resolved(&a).await.expect("resolve");
        assert_eq!(s.len().await.expect("len"), 1);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_matches_in_memory_semantics() {
        let s = SqliteRedemptionTracker::connect("sqlite::memory:")
            .await
            .expect("connect");
        let a = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        s.observe(a, tr(100)).await.expect("obs");
        assert!(s.scan(50).await.expect("scan").stuck.is_empty());
        let d = s.scan(150).await.expect("scan");
        assert_eq!(d.stuck.len(), 1);
        assert_eq!(d.stuck[0].1.deadline_unix_secs, 100);
        s.mark_resolved(&a).await.expect("res");
        s.mark_resolved(&a).await.expect("res idempotent");
        assert!(s.is_empty().await.expect("empty"));
    }
}
