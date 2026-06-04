//! Crash-recovery store for the Solana (Squads V4) redeem leg (Phase 4.5).
//!
//! A Squads redemption is `1 + threshold + 1` separate on-chain
//! transactions, so — unlike the single-tx XRP / Cosmos legs — it needs
//! persistence to survive a mid-flight restart without double-spending.
//! Two pieces of state, modelled on [`crate::broadcast_registry`]:
//!
//! 1. The `redemption_id → transaction_index` binding, allocated **once,
//!    write-ahead**, before the first broadcast ([`SolanaRedeemStore::reserve`]).
//!    Re-deriving the index on resume could create a second proposal that
//!    also pays the user — the atomic insert prevents it.
//! 2. The per-step signer cache (the 2h `signerCacheExpiry` defense):
//!    `cache_get` / `cache_set` / `cache_clear`.
//!
//! Step progress is derived from the on-chain proposal account (the chain
//! is the witness), NOT from local state. Two impls — [`InMemorySolanaRedeemStore`]
//! (tests/dev) and [`SqliteSolanaRedeemStore`] (prod) — selected by
//! `DATABASE_URL`, static-dispatched (AFIT, no `async-trait`).

use std::collections::HashMap;
use std::future::Future;

use alloy_primitives::B256;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use thiserror::Error;
use tokio::sync::Mutex;
use xindex_solana_tx::Pubkey;

/// Errors surfaced by the Solana redeem store.
#[derive(Debug, Error)]
pub enum SolanaStoreError {
    /// `SQLite` error.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] sqlx::Error),
    /// Migration error.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// A stored row decoded to an invalid value.
    #[error("decode error: {0}")]
    Decode(String),
}

/// Persisted progress for one redemption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemProgress {
    /// The allocated Squads transaction index this redemption owns.
    pub transaction_index: u64,
    /// The execute-tx signature, once the proposal has executed.
    pub execute_signature: Option<String>,
}

/// A cached step broadcast (the 2h `signerCacheExpiry` defense).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedBroadcast {
    /// The base58 transaction signature that was broadcast.
    pub signature: String,
    /// Unix seconds at broadcast time.
    pub broadcast_at_unix: u64,
}

/// Persistence the Solana redeem executor needs. Implementations own their
/// concurrency; callers must NOT wrap with an external lock.
pub trait SolanaRedeemStore: Send + Sync {
    /// Allocate `transaction_index` for `redemption_id`, write-ahead.
    /// Returns `true` if this call created the binding, `false` if one
    /// already exists (resume — re-use the stored index, NEVER re-allocate).
    fn reserve(
        &self,
        redemption_id: &B256,
        multisig: &Pubkey,
        transaction_index: u64,
    ) -> impl Future<Output = Result<bool, SolanaStoreError>> + Send;

    /// Load a redemption's progress, if any.
    fn load(
        &self,
        redemption_id: &B256,
    ) -> impl Future<Output = Result<Option<RedeemProgress>, SolanaStoreError>> + Send;

    /// Record the execute-tx signature once the proposal has executed.
    fn mark_executed(
        &self,
        redemption_id: &B256,
        execute_signature: &str,
    ) -> impl Future<Output = Result<(), SolanaStoreError>> + Send;

    /// Read the cached broadcast for `(redemption_id, transaction_index, step)`.
    fn cache_get(
        &self,
        redemption_id: &B256,
        transaction_index: u64,
        step: &str,
    ) -> impl Future<Output = Result<Option<CachedBroadcast>, SolanaStoreError>> + Send;

    /// Cache a step broadcast (write-ahead, before the irreversible send).
    fn cache_set(
        &self,
        redemption_id: &B256,
        transaction_index: u64,
        step: &str,
        signature: &str,
        at_unix: u64,
    ) -> impl Future<Output = Result<(), SolanaStoreError>> + Send;

    /// Clear a cached step (after the 2h window expires and an on-chain
    /// lookup confirms the tx did NOT land).
    fn cache_clear(
        &self,
        redemption_id: &B256,
        transaction_index: u64,
        step: &str,
    ) -> impl Future<Output = Result<(), SolanaStoreError>> + Send;
}

// ─── in-memory impl (tests / dev) ───────────────────────────────────────────

/// In-memory store. Loses state on restart; for tests + dev only.
#[derive(Debug, Default)]
pub struct InMemorySolanaRedeemStore {
    inner: Mutex<InnerState>,
}

#[derive(Debug, Default)]
struct InnerState {
    progress: HashMap<B256, RedeemProgress>,
    cache: HashMap<(B256, u64, String), CachedBroadcast>,
}

impl InMemorySolanaRedeemStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl SolanaRedeemStore for InMemorySolanaRedeemStore {
    async fn reserve(
        &self,
        redemption_id: &B256,
        _multisig: &Pubkey,
        transaction_index: u64,
    ) -> Result<bool, SolanaStoreError> {
        let mut g = self.inner.lock().await;
        if g.progress.contains_key(redemption_id) {
            return Ok(false);
        }
        g.progress.insert(
            *redemption_id,
            RedeemProgress {
                transaction_index,
                execute_signature: None,
            },
        );
        Ok(true)
    }

    async fn load(&self, redemption_id: &B256) -> Result<Option<RedeemProgress>, SolanaStoreError> {
        Ok(self.inner.lock().await.progress.get(redemption_id).cloned())
    }

    async fn mark_executed(
        &self,
        redemption_id: &B256,
        execute_signature: &str,
    ) -> Result<(), SolanaStoreError> {
        if let Some(p) = self.inner.lock().await.progress.get_mut(redemption_id) {
            p.execute_signature = Some(execute_signature.to_string());
        }
        Ok(())
    }

    async fn cache_get(
        &self,
        redemption_id: &B256,
        transaction_index: u64,
        step: &str,
    ) -> Result<Option<CachedBroadcast>, SolanaStoreError> {
        Ok(self
            .inner
            .lock()
            .await
            .cache
            .get(&(*redemption_id, transaction_index, step.to_string()))
            .cloned())
    }

    async fn cache_set(
        &self,
        redemption_id: &B256,
        transaction_index: u64,
        step: &str,
        signature: &str,
        at_unix: u64,
    ) -> Result<(), SolanaStoreError> {
        self.inner.lock().await.cache.insert(
            (*redemption_id, transaction_index, step.to_string()),
            CachedBroadcast {
                signature: signature.to_string(),
                broadcast_at_unix: at_unix,
            },
        );
        Ok(())
    }

    async fn cache_clear(
        &self,
        redemption_id: &B256,
        transaction_index: u64,
        step: &str,
    ) -> Result<(), SolanaStoreError> {
        self.inner.lock().await.cache.remove(&(
            *redemption_id,
            transaction_index,
            step.to_string(),
        ));
        Ok(())
    }
}

// ─── sqlite impl (prod) ─────────────────────────────────────────────────────

/// `sqlx`-backed persistent store. [`SqliteSolanaRedeemStore::connect`]
/// applies the executor `migrations/` on startup.
pub struct SqliteSolanaRedeemStore {
    pool: SqlitePool,
}

impl std::fmt::Debug for SqliteSolanaRedeemStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteSolanaRedeemStore")
            .finish_non_exhaustive()
    }
}

impl SqliteSolanaRedeemStore {
    /// Open a `SQLite` connection and apply migrations.
    ///
    /// # Errors
    /// [`SolanaStoreError::Sqlite`] / [`SolanaStoreError::Migrate`].
    pub async fn connect(database_url: &str) -> Result<Self, SolanaStoreError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    fn cast_index(transaction_index: u64) -> Result<i64, SolanaStoreError> {
        i64::try_from(transaction_index)
            .map_err(|e| SolanaStoreError::Decode(format!("transaction_index overflow: {e}")))
    }

    fn cast_secs(at_unix: u64) -> Result<i64, SolanaStoreError> {
        i64::try_from(at_unix)
            .map_err(|e| SolanaStoreError::Decode(format!("unix secs overflow: {e}")))
    }
}

impl SolanaRedeemStore for SqliteSolanaRedeemStore {
    async fn reserve(
        &self,
        redemption_id: &B256,
        multisig: &Pubkey,
        transaction_index: u64,
    ) -> Result<bool, SolanaStoreError> {
        let idx = Self::cast_index(transaction_index)?;
        let res = sqlx::query(
            r"
            INSERT INTO solana_redeem_progress
                (redemption_id, multisig_pda, transaction_index, execute_signature)
            VALUES (?, ?, ?, NULL)
            ON CONFLICT(redemption_id) DO NOTHING
            ",
        )
        .bind(redemption_id.as_slice())
        .bind(&multisig.as_bytes()[..])
        .bind(idx)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn load(&self, redemption_id: &B256) -> Result<Option<RedeemProgress>, SolanaStoreError> {
        let row: Option<(i64, Option<String>)> = sqlx::query_as(
            "SELECT transaction_index, execute_signature
             FROM solana_redeem_progress WHERE redemption_id = ?",
        )
        .bind(redemption_id.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(idx, sig)| {
            let transaction_index = u64::try_from(idx)
                .map_err(|e| SolanaStoreError::Decode(format!("stored index negative: {e}")))?;
            Ok(RedeemProgress {
                transaction_index,
                execute_signature: sig,
            })
        })
        .transpose()
    }

    async fn mark_executed(
        &self,
        redemption_id: &B256,
        execute_signature: &str,
    ) -> Result<(), SolanaStoreError> {
        sqlx::query(
            "UPDATE solana_redeem_progress SET execute_signature = ? WHERE redemption_id = ?",
        )
        .bind(execute_signature)
        .bind(redemption_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn cache_get(
        &self,
        redemption_id: &B256,
        transaction_index: u64,
        step: &str,
    ) -> Result<Option<CachedBroadcast>, SolanaStoreError> {
        let idx = Self::cast_index(transaction_index)?;
        let row: Option<(String, i64)> = sqlx::query_as(
            "SELECT broadcast_signature, broadcast_at_unix FROM solana_signer_cache
             WHERE redemption_id = ? AND transaction_index = ? AND step = ?",
        )
        .bind(redemption_id.as_slice())
        .bind(idx)
        .bind(step)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(signature, at)| {
            let broadcast_at_unix = u64::try_from(at)
                .map_err(|e| SolanaStoreError::Decode(format!("stored ts negative: {e}")))?;
            Ok(CachedBroadcast {
                signature,
                broadcast_at_unix,
            })
        })
        .transpose()
    }

    async fn cache_set(
        &self,
        redemption_id: &B256,
        transaction_index: u64,
        step: &str,
        signature: &str,
        at_unix: u64,
    ) -> Result<(), SolanaStoreError> {
        let idx = Self::cast_index(transaction_index)?;
        let at = Self::cast_secs(at_unix)?;
        sqlx::query(
            r"
            INSERT INTO solana_signer_cache
                (redemption_id, transaction_index, step, broadcast_signature, broadcast_at_unix)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(redemption_id, transaction_index, step) DO UPDATE SET
                broadcast_signature = excluded.broadcast_signature,
                broadcast_at_unix = excluded.broadcast_at_unix
            ",
        )
        .bind(redemption_id.as_slice())
        .bind(idx)
        .bind(step)
        .bind(signature)
        .bind(at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn cache_clear(
        &self,
        redemption_id: &B256,
        transaction_index: u64,
        step: &str,
    ) -> Result<(), SolanaStoreError> {
        let idx = Self::cast_index(transaction_index)?;
        sqlx::query(
            "DELETE FROM solana_signer_cache
             WHERE redemption_id = ? AND transaction_index = ? AND step = ?",
        )
        .bind(redemption_id.as_slice())
        .bind(idx)
        .bind(step)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    fn id() -> B256 {
        b256!("00000000000000000000000000000000000000000000000000000000000000f5")
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn in_memory_reserve_is_idempotent_and_load_returns_index() {
        let s = InMemorySolanaRedeemStore::new();
        let ms = Pubkey::new([1u8; 32]);
        assert!(s.reserve(&id(), &ms, 42).await.expect("reserve"));
        // A second reserve does NOT re-allocate (resume re-uses the index).
        assert!(!s.reserve(&id(), &ms, 99).await.expect("re-reserve"));
        let p = s.load(&id()).await.expect("load").expect("present");
        assert_eq!(p.transaction_index, 42);
        assert_eq!(p.execute_signature, None);
        s.mark_executed(&id(), "EXECSIG").await.expect("executed");
        assert_eq!(
            s.load(&id())
                .await
                .expect("load")
                .expect("present")
                .execute_signature,
            Some("EXECSIG".to_string())
        );
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_reserve_round_trip_and_cache() {
        let s = SqliteSolanaRedeemStore::connect("sqlite::memory:")
            .await
            .expect("connect");
        let ms = Pubkey::new([2u8; 32]);
        assert!(s.reserve(&id(), &ms, 7).await.expect("reserve"));
        assert!(!s.reserve(&id(), &ms, 8).await.expect("re-reserve"));
        assert_eq!(
            s.load(&id())
                .await
                .expect("load")
                .expect("present")
                .transaction_index,
            7
        );
        // Cache round-trip.
        assert_eq!(s.cache_get(&id(), 7, "create").await.expect("get"), None);
        s.cache_set(&id(), 7, "create", "SiG", 1_700_000_000)
            .await
            .expect("set");
        assert_eq!(
            s.cache_get(&id(), 7, "create").await.expect("get"),
            Some(CachedBroadcast {
                signature: "SiG".to_string(),
                broadcast_at_unix: 1_700_000_000
            })
        );
        s.cache_clear(&id(), 7, "create").await.expect("clear");
        assert_eq!(s.cache_get(&id(), 7, "create").await.expect("get"), None);
    }
}
