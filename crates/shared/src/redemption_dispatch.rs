//! F2 correlation store: `(redemption_id, leg_index) → { inbound_txid, dispatched_at }`.
//!
//! The burn → USDT flow needs the SIGNER's `THORChain` cross-check to
//! query `/thorchain/tx/{inbound_txid}` for the exact inbound the
//! EXECUTOR broadcast to the Asgard vault. Fuzzy amount/destination
//! matching is unsafe for a custody attestation; exact-txid correlation
//! is required. The executor records the mapping AFTER it broadcasts the
//! inbound tx; the signer reads it (polling until present — no
//! attestation before broadcast, the safe order).
//!
//! ## Per-leg keying (H1 / Phase 3.0.1)
//!
//! Key is `(redemption_id, leg_index)`, not `redemption_id` alone. A
//! single redemption may dispatch multiple legs across different chains
//! (Phase 3.1+: mixed BTC + LTC + ... baskets); each leg gets its own
//! row. Under the previous single-key schema, a second leg's
//! `record()` hit `INSERT OR IGNORE` on the PK and was silently
//! dropped — the signer then could never correlate its `inbound_txid`.
//! For the current single-async-slot `THORChain` rail, `leg_index` is
//! always 0 and behavior is unchanged.
//!
//! ## Per-chain field (U9 / Phase 3.1)
//!
//! Each row also carries the `ChainId` of the recorded inbound — the
//! signer's cross-check needs to know which chain to query for the
//! `inbound_txid` (BTC mainnet, LTC mainnet, etc.). Stored as lowercase
//! string in `SQLite` matching `ChainId`'s Display + Serde form. The
//! schema's CHECK constraint locks the value set to the Phase 3.1
//! UTXO family; Phase 3.2+ chains require a follow-on migration.
//!
//! Lives in `xindex-shared` because both `xindex-executor` (writer) and
//! `xindex-signer` (reader) depend on `shared` but not on each other.
//!
//! Same `*Store` shape as `relayer::IntentTrackerStore` /
//! `executor::BroadcastRegistry`: one AFIT trait + `InMemory*` (tests /
//! dev) + `Sqlite*` (prod, survives restarts), static dispatch, no
//! `async-trait`. AFIT is stable since Rust 1.75; the workspace pins
//! 1.85.

use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::B256;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::chain_registry::ChainId;

/// Errors surfaced by dispatch-store operations.
#[derive(Debug, Error)]
pub enum DispatchError {
    /// Underlying `sqlx` failure (connect, query, decode).
    #[error("sqlite error: {0}")]
    Sqlite(#[from] sqlx::Error),

    /// Migration application failed.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// A stored row was malformed (wrong byte length / range). Fail
    /// loud — corrupt rows signal data damage we want surfaced.
    #[error("decode error: {0}")]
    Decode(String),
}

/// The recorded inbound dispatch for one redemption leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchRecord {
    /// Per-leg index within the redemption (matches the on-chain
    /// `RedemptionLegRecord` array position; 0 for single-async-slot
    /// baskets).
    pub leg_index: u32,
    /// Which UTXO chain this dispatch hit. The signer's cross-check
    /// uses this to pick the right `THORChain` chain-query endpoint
    /// and the right Esplora client. BTC for the current rail;
    /// LTC/BCH/DOGE/ZEC after U10 wires the per-chain executor.
    pub chain: ChainId,
    /// Inbound txid (display hex) of the deposit the executor broadcast
    /// to the leg's `THORChain` Asgard vault. Passed verbatim to
    /// `ThorClient::tx_status` for the chain identified by `chain`.
    pub inbound_txid: String,
    /// Unix seconds at which the executor recorded the dispatch.
    pub dispatched_at_unix_secs: u64,
}

/// Operations the executor (writer) and signer (reader) need.
///
/// Internal sync: implementations own their concurrency (Mutex /
/// connection pool). Callers do NOT wrap with an external lock.
pub trait RedemptionDispatchStore: Send + Sync {
    /// Record the inbound dispatch for `(redemption_id, leg_index)`.
    /// Idempotent per leg: the FIRST write wins (a re-broadcast must
    /// not overwrite the original `inbound_txid` the signer correlates
    /// against). `chain` is persisted alongside the txid so the
    /// signer's cross-check can pick the right per-chain Esplora /
    /// `THORChain` query path.
    fn record(
        &self,
        redemption_id: B256,
        leg_index: u32,
        chain: ChainId,
        inbound_txid: String,
        now_unix_secs: u64,
    ) -> impl std::future::Future<Output = Result<(), DispatchError>> + Send;

    /// Fetch the dispatch for `(redemption_id, leg_index)`, or `None`
    /// if the executor has not broadcast this leg yet (signer polls
    /// until `Some`).
    fn get(
        &self,
        redemption_id: &B256,
        leg_index: u32,
    ) -> impl std::future::Future<Output = Result<Option<DispatchRecord>, DispatchError>> + Send;

    /// `true` iff a dispatch for `(redemption_id, leg_index)` is already
    /// recorded. Default: `get(..).is_some()`; backends may override if
    /// cheaper.
    fn has(
        &self,
        redemption_id: &B256,
        leg_index: u32,
    ) -> impl std::future::Future<Output = Result<bool, DispatchError>> + Send {
        async move { Ok(self.get(redemption_id, leg_index).await?.is_some()) }
    }
}

/// In-memory store. Loses state on restart — tests / dev only.
#[derive(Debug, Default)]
pub struct InMemoryRedemptionDispatch {
    inner: Mutex<std::collections::HashMap<(B256, u32), DispatchRecord>>,
}

impl InMemoryRedemptionDispatch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl RedemptionDispatchStore for InMemoryRedemptionDispatch {
    async fn record(
        &self,
        redemption_id: B256,
        leg_index: u32,
        chain: ChainId,
        inbound_txid: String,
        now_unix_secs: u64,
    ) -> Result<(), DispatchError> {
        // First-write-wins per leg: a re-broadcast of the same leg keeps
        // the original txid the signer correlates against.
        self.inner
            .lock()
            .await
            .entry((redemption_id, leg_index))
            .or_insert(DispatchRecord {
                leg_index,
                chain,
                inbound_txid,
                dispatched_at_unix_secs: now_unix_secs,
            });
        Ok(())
    }

    async fn get(
        &self,
        redemption_id: &B256,
        leg_index: u32,
    ) -> Result<Option<DispatchRecord>, DispatchError> {
        Ok(self
            .inner
            .lock()
            .await
            .get(&(*redemption_id, leg_index))
            .cloned())
    }
}

/// `sqlx`-backed persistent store. Survives daemon restarts.
///
/// On startup [`SqliteRedemptionDispatch::connect`] applies the
/// `migrations/` schema; subsequent restarts are idempotent.
pub struct SqliteRedemptionDispatch {
    pool: SqlitePool,
}

impl std::fmt::Debug for SqliteRedemptionDispatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Omit pool internals — they would leak a path/URL into logs.
        f.debug_struct("SqliteRedemptionDispatch")
            .finish_non_exhaustive()
    }
}

impl SqliteRedemptionDispatch {
    /// Open a `SQLite` connection and apply pending migrations.
    ///
    /// # Errors
    /// [`DispatchError::Sqlite`] on connect / pool failure;
    /// [`DispatchError::Migrate`] if a migration fails to apply.
    pub async fn connect(database_url: &str) -> Result<Self, DispatchError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    /// Cast a `u64` unix timestamp to the `i64` `SQLite` INTEGER stores.
    /// Reject values above `i64::MAX` rather than wrapping.
    fn cast_secs(unix_secs: u64) -> Result<i64, DispatchError> {
        i64::try_from(unix_secs)
            .map_err(|e| DispatchError::Decode(format!("u64→i64 overflow on unix secs: {e}")))
    }
}

impl RedemptionDispatchStore for SqliteRedemptionDispatch {
    async fn record(
        &self,
        redemption_id: B256,
        leg_index: u32,
        chain: ChainId,
        inbound_txid: String,
        now_unix_secs: u64,
    ) -> Result<(), DispatchError> {
        let at = Self::cast_secs(now_unix_secs)?;
        // `INSERT OR IGNORE` = first-write-wins PER LEG (idempotent
        // re-broadcast). PK is (redemption_id, leg_index) so distinct
        // legs of the same rid never collide. `chain` stored as
        // lowercase string (ChainId Display form) — CHECK constraint
        // in the migration enforces the value set.
        sqlx::query(
            r"
            INSERT OR IGNORE INTO redemption_dispatch
                (redemption_id, leg_index, chain, inbound_txid, dispatched_at_unix_secs)
            VALUES (?, ?, ?, ?, ?)
            ",
        )
        .bind(redemption_id.as_slice())
        .bind(i64::from(leg_index))
        .bind(chain.to_string())
        .bind(&inbound_txid)
        .bind(at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(
        &self,
        redemption_id: &B256,
        leg_index: u32,
    ) -> Result<Option<DispatchRecord>, DispatchError> {
        let row: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT chain, inbound_txid, dispatched_at_unix_secs
             FROM redemption_dispatch
             WHERE redemption_id = ? AND leg_index = ?",
        )
        .bind(redemption_id.as_slice())
        .bind(i64::from(leg_index))
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some((chain_str, inbound_txid, at)) => {
                let dispatched_at_unix_secs = u64::try_from(at).map_err(|e| {
                    DispatchError::Decode(format!("stored dispatched_at negative: {e}"))
                })?;
                let chain: ChainId = chain_str.parse().map_err(|e| {
                    DispatchError::Decode(format!("stored chain {chain_str:?} unknown: {e}"))
                })?;
                Ok(Some(DispatchRecord {
                    leg_index,
                    chain,
                    inbound_txid,
                    dispatched_at_unix_secs,
                }))
            }
        }
    }
}

/// Concrete store dispatch shared by the executor (writer) and the
/// redemption-attest binary (reader). The trait is AFIT (not
/// dyn-compatible), so rather than explode every binary's generics we
/// branch once here and delegate. `connect(None)` = in-memory (dev /
/// tests, lost on restart); `connect(Some(url))` = persistent `SQLite`.
#[derive(Debug)]
pub enum AnyRedemptionDispatch {
    Mem(InMemoryRedemptionDispatch),
    Sql(SqliteRedemptionDispatch),
}

impl AnyRedemptionDispatch {
    /// `Some(url)` → `SQLite` (applies migrations); `None` → in-memory.
    ///
    /// # Errors
    /// [`DispatchError`] if the `SQLite` connect / migration fails.
    pub async fn connect(database_url: Option<&str>) -> Result<Self, DispatchError> {
        match database_url {
            Some(url) => Ok(Self::Sql(SqliteRedemptionDispatch::connect(url).await?)),
            None => Ok(Self::Mem(InMemoryRedemptionDispatch::new())),
        }
    }
}

impl RedemptionDispatchStore for AnyRedemptionDispatch {
    async fn record(
        &self,
        redemption_id: B256,
        leg_index: u32,
        chain: ChainId,
        inbound_txid: String,
        now_unix_secs: u64,
    ) -> Result<(), DispatchError> {
        match self {
            Self::Mem(s) => {
                s.record(redemption_id, leg_index, chain, inbound_txid, now_unix_secs)
                    .await
            }
            Self::Sql(s) => {
                s.record(redemption_id, leg_index, chain, inbound_txid, now_unix_secs)
                    .await
            }
        }
    }

    async fn get(
        &self,
        redemption_id: &B256,
        leg_index: u32,
    ) -> Result<Option<DispatchRecord>, DispatchError> {
        match self {
            Self::Mem(s) => s.get(redemption_id, leg_index).await,
            Self::Sql(s) => s.get(redemption_id, leg_index).await,
        }
    }
}

/// Best-effort wall clock (unix secs); `0` on a pre-1970 clock failure.
#[must_use]
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn in_memory_record_get_idempotent_per_leg() {
        let store = InMemoryRedemptionDispatch::new();
        let id = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        assert!(!store.has(&id, 0).await.expect("has"));
        store
            .record(id, 0, ChainId::Btc, "txid-aaa".into(), 100)
            .await
            .expect("record");
        assert!(store.has(&id, 0).await.expect("has"));
        // First-write-wins PER LEG: a re-broadcast must not clobber.
        store
            .record(id, 0, ChainId::Btc, "txid-bbb".into(), 200)
            .await
            .expect("re-record");
        let got = store.get(&id, 0).await.expect("get").expect("present");
        assert_eq!(got.inbound_txid, "txid-aaa");
        assert_eq!(got.leg_index, 0);
        assert_eq!(got.dispatched_at_unix_secs, 100);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_record_get_idempotent_matches_in_memory() {
        let store = SqliteRedemptionDispatch::connect("sqlite::memory:")
            .await
            .expect("connect + migrate");
        let id = b256!("00000000000000000000000000000000000000000000000000000000000000bb");
        assert_eq!(store.get(&id, 0).await.expect("get"), None);
        store
            .record(id, 0, ChainId::Btc, "txid-aaa".into(), 100)
            .await
            .expect("record");
        store
            .record(id, 0, ChainId::Btc, "txid-bbb".into(), 200)
            .await
            .expect("re-record");
        let got = store.get(&id, 0).await.expect("get").expect("present");
        assert_eq!(got.inbound_txid, "txid-aaa", "first-write-wins (sqlite)");
        assert_eq!(got.leg_index, 0);
        assert_eq!(got.dispatched_at_unix_secs, 100);
        assert!(store.has(&id, 0).await.expect("has"));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn any_dispatch_delegates_record_and_get() {
        // Exercises the AnyRedemptionDispatch enum delegate (the path
        // the binaries actually use) end to end, not just the concrete
        // impls.
        let store = AnyRedemptionDispatch::connect(None)
            .await
            .expect("connect mem");
        let id = b256!("00000000000000000000000000000000000000000000000000000000000000ce");
        assert_eq!(store.get(&id, 0).await.expect("get"), None);
        assert!(!store.has(&id, 0).await.expect("has"));
        store
            .record(id, 0, ChainId::Btc, "txid-any".into(), 314)
            .await
            .expect("record");
        // First-write-wins survives the delegate.
        store
            .record(id, 0, ChainId::Btc, "txid-other".into(), 999)
            .await
            .expect("re-record");
        let got = store.get(&id, 0).await.expect("get").expect("present");
        assert_eq!(got.inbound_txid, "txid-any");
        assert_eq!(got.dispatched_at_unix_secs, 314);
        assert!(store.has(&id, 0).await.expect("has"));

        let sql = AnyRedemptionDispatch::connect(Some("sqlite::memory:"))
            .await
            .expect("connect sql");
        assert_eq!(sql.get(&id, 0).await.expect("get"), None);
        sql.record(id, 0, ChainId::Btc, "s".into(), 7)
            .await
            .expect("record sql");
        assert_eq!(
            sql.get(&id, 0)
                .await
                .expect("get")
                .expect("present")
                .inbound_txid,
            "s"
        );
    }

    /// H1 regression: under the old single-key PK schema, a second leg
    /// of the same `redemption_id` was silently dropped by
    /// `INSERT OR IGNORE`. With per-leg keying, both legs persist as
    /// distinct rows and first-write-wins applies PER LEG independently.
    /// Covers both the in-memory and sqlite paths.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn multi_leg_same_rid_records_each_leg_independently_in_memory() {
        let store = InMemoryRedemptionDispatch::new();
        let id = b256!("0000000000000000000000000000000000000000000000000000000000000aa1");

        store
            .record(id, 0, ChainId::Btc, "txid-leg0".into(), 100)
            .await
            .expect("leg 0");
        store
            .record(id, 1, ChainId::Btc, "txid-leg1".into(), 200)
            .await
            .expect("leg 1");

        let leg0 = store.get(&id, 0).await.expect("get").expect("present");
        let leg1 = store.get(&id, 1).await.expect("get").expect("present");
        assert_eq!(leg0.inbound_txid, "txid-leg0");
        assert_eq!(leg0.leg_index, 0);
        assert_eq!(leg1.inbound_txid, "txid-leg1");
        assert_eq!(leg1.leg_index, 1);

        // Per-leg first-write-wins: re-record leg 0, leg 1 untouched.
        store
            .record(id, 0, ChainId::Btc, "txid-leg0-redo".into(), 999)
            .await
            .expect("re-leg0");
        let leg0_again = store.get(&id, 0).await.expect("get").expect("present");
        assert_eq!(leg0_again.inbound_txid, "txid-leg0");
        let leg1_still = store.get(&id, 1).await.expect("get").expect("present");
        assert_eq!(leg1_still.inbound_txid, "txid-leg1");

        // Unrelated leg index for the same rid: absent until recorded.
        assert!(!store.has(&id, 2).await.expect("has"));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn multi_leg_same_rid_records_each_leg_independently_sqlite() {
        let store = SqliteRedemptionDispatch::connect("sqlite::memory:")
            .await
            .expect("connect + migrate");
        let id = b256!("0000000000000000000000000000000000000000000000000000000000000aa2");

        store
            .record(id, 0, ChainId::Btc, "txid-leg0".into(), 100)
            .await
            .expect("leg 0");
        store
            .record(id, 1, ChainId::Btc, "txid-leg1".into(), 200)
            .await
            .expect("leg 1");

        let leg0 = store.get(&id, 0).await.expect("get").expect("present");
        let leg1 = store.get(&id, 1).await.expect("get").expect("present");
        assert_eq!(leg0.inbound_txid, "txid-leg0");
        assert_eq!(leg0.leg_index, 0);
        assert_eq!(leg1.inbound_txid, "txid-leg1");
        assert_eq!(leg1.leg_index, 1);

        // Per-leg first-write-wins under SQLite's INSERT OR IGNORE.
        store
            .record(id, 0, ChainId::Btc, "txid-leg0-redo".into(), 999)
            .await
            .expect("re-leg0");
        let leg0_again = store.get(&id, 0).await.expect("get").expect("present");
        assert_eq!(
            leg0_again.inbound_txid, "txid-leg0",
            "per-leg first-write-wins (sqlite)"
        );
    }

    /// V8 / Phase 3.2: every EVM family chain is admitted by the widened
    /// CHECK constraint on the sqlite store. Pre-existing UTXO rows still
    /// insert cleanly (post-migration regression).
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_accepts_every_evm_chain_post_v8_migration() {
        let store = SqliteRedemptionDispatch::connect("sqlite::memory:")
            .await
            .expect("connect + migrate");
        // Pre-existing UTXO regression: btc still records.
        let utxo_id = b256!("00000000000000000000000000000000000000000000000000000000000000e0");
        store
            .record(utxo_id, 0, ChainId::Btc, "btc-txid".into(), 1)
            .await
            .expect("btc record");
        // Each EVM chain records its own row.
        for (idx, chain) in [
            ChainId::Eth,
            ChainId::Bsc,
            ChainId::Avax,
            ChainId::Base,
            ChainId::Pol,
        ]
        .into_iter()
        .enumerate()
        {
            let id = b256!("00000000000000000000000000000000000000000000000000000000000000e1");
            let leg = u32::try_from(idx).expect("idx fits u32");
            store
                .record(
                    id,
                    leg,
                    chain,
                    format!("evm-tx-{chain}"),
                    100 + u64::from(leg),
                )
                .await
                .unwrap_or_else(|e| unreachable!("record {chain}: {e}"));
            let got = store
                .get(&id, leg)
                .await
                .expect("get")
                .expect("recorded row");
            assert_eq!(got.chain, chain, "{chain} round-trips");
            assert_eq!(got.inbound_txid, format!("evm-tx-{chain}"));
        }
    }

    /// C8 / Phase 3.3: the Cosmos family chain (gaia) is admitted by the
    /// widened CHECK constraint; pre-existing UTXO + EVM rows still insert.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_accepts_gaia_post_v9_migration() {
        let store = SqliteRedemptionDispatch::connect("sqlite::memory:")
            .await
            .expect("connect + migrate");
        // Regression: a UTXO + an EVM chain still record post-migration.
        let id = b256!("00000000000000000000000000000000000000000000000000000000000000e2");
        store
            .record(id, 0, ChainId::Btc, "btc-txid".into(), 1)
            .await
            .expect("btc record");
        store
            .record(id, 1, ChainId::Eth, "eth-txid".into(), 2)
            .await
            .expect("eth record");
        // The Cosmos chain records its own leg.
        store
            .record(id, 2, ChainId::Gaia, "gaia-txhash".into(), 3)
            .await
            .expect("gaia record");
        let got = store.get(&id, 2).await.expect("get").expect("recorded row");
        assert_eq!(got.chain, ChainId::Gaia);
        assert_eq!(got.inbound_txid, "gaia-txhash");
    }
}
