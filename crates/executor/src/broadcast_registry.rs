//! Persistence layer for in-flight Bitcoin broadcasts.
//!
//! Closes Rust-audit finding L-R2: `xindex-redeem` previously broadcast
//! a finalized Bitcoin transaction once and moved on. Mempool eviction
//! (fee competition, reorg, network split) silently lost the redemption
//! — shares already burned on Ethereum with no BTC delivered.
//!
//! ## Design
//!
//! A single trait — [`BroadcastRegistry`] — describes the operations
//! the executor + watcher need. Two implementations:
//!
//! 1. [`InMemoryBroadcastRegistry`] — `tokio::sync::Mutex<HashMap>`.
//!    For tests + dev environments where persistence isn't required.
//! 2. [`SqliteBroadcastRegistry`] — `sqlx`-backed; survives daemon
//!    restarts. Used in production (selected by setting `DATABASE_URL`
//!    in `xindex-redeem`).
//!
//! Static dispatch: the binary monomorphises over
//! `T: BroadcastRegistry`, avoiding `Box<dyn>` and the `async-trait`
//! macro dependency (rust >= 1.75 has AFIT; workspace pins 1.85).
//!
//! ## Lifecycle
//!
//! ```text
//! executor.broadcast() → registry.register(pending) ─┐
//!                                                    ▼
//!     watcher tick (every N secs):                  pending row
//!       │ chain.get_tx_status(txid)
//!       │   confirmed AND confs >= MIN  → registry.mark_confirmed()
//!       │   not seen AND stuck-timeout  → chain.broadcast(tx) again
//!       │                                  registry.touch_attempt()
//!       │   neither                      → leave for next tick
//!       └─────────────────────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::B256;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use thiserror::Error;
use tokio::sync::Mutex;

/// Status of a broadcast in the registry. Persisted as a discriminator
/// string in the `SQLite` `status` column (`'pending'`, `'confirmed'`,
/// `'failed'`); the SQL CHECK constraint pins the allowed values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastStatus {
    /// Write-ahead reservation claimed BEFORE the irreversible broadcast
    /// (audit H1). Excluded from `list_pending` (the watcher never
    /// re-broadcasts a placeholder); `register` promotes it to `Pending`
    /// once the real tx is broadcast. A row stuck in `Reserved` (crash
    /// between reserve and broadcast) is surfaced to the operator, never
    /// silently re-broadcast.
    Reserved,
    /// Transaction broadcast; awaiting confirmations.
    Pending,
    /// Transaction confirmed at least `MIN_CONFIRMATIONS` deep.
    Confirmed,
    /// Operator-marked terminal failure (e.g., persistent rejection).
    /// The watcher never sets this on its own — only ops tooling does.
    Failed,
}

/// One pending broadcast tracked by the registry. Carries everything the
/// watcher needs to re-broadcast on stuck-timeout without rebuilding
/// from chain state (which would risk a different txid if UTXO set has
/// changed).
#[derive(Debug, Clone)]
pub struct PendingBroadcast {
    pub intent_id: B256,
    pub txid: Txid,
    pub tx_bytes: Vec<u8>,
    pub recipient_addr: String,
    pub amount_sats: u64,
    pub broadcast_at_unix_secs: u64,
    pub last_attempt_unix_secs: u64,
}

/// Errors surfaced by registry operations.
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] sqlx::Error),

    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// Decoding a stored row produced an invalid value. Fail loud
    /// rather than silently substitute — corrupt rows signal data
    /// damage we want surfaced.
    #[error("decode error: {0}")]
    Decode(String),
}

/// Operations the executor + watcher need on the broadcast registry.
///
/// Internal sync: implementations own their concurrency. Callers must
/// NOT wrap with an external lock.
pub trait BroadcastRegistry: Send + Sync {
    /// Insert a newly-broadcast transaction. Idempotent on `intent_id`
    /// (re-broadcasting the SAME `intent_id` overwrites the previous
    /// row's `tx_bytes` and resets `last_attempt_unix_secs`).
    fn register(
        &self,
        entry: PendingBroadcast,
    ) -> impl std::future::Future<Output = Result<(), RegistryError>> + Send;

    /// Write-ahead reservation keyed by `intent_id`, claimed BEFORE the
    /// irreversible broadcast (audit H1). Returns `true` if this call
    /// created the reservation, `false` if one already exists (a replay
    /// or concurrent attempt) — the caller MUST skip the broadcast on
    /// `false`. Closes the H-R1 double-pay ordering: a crash or transient
    /// `register` error between broadcast and record can no longer leave
    /// NO row, so a `--from-block` replay can't pick a fresh UTXO and
    /// broadcast a second valid Asgard deposit for one burn.
    fn reserve(
        &self,
        intent_id: &B256,
    ) -> impl std::future::Future<Output = Result<bool, RegistryError>> + Send;

    /// All currently-pending broadcasts the watcher should poll. Ordered
    /// by `broadcast_at_unix_secs` ASC so older entries get attention
    /// first.
    fn list_pending(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<PendingBroadcast>, RegistryError>> + Send;

    /// Bump `last_attempt_unix_secs` after a re-broadcast attempt.
    fn touch_attempt(
        &self,
        intent_id: &B256,
        now_unix_secs: u64,
    ) -> impl std::future::Future<Output = Result<(), RegistryError>> + Send;

    /// Mark an intent's broadcast confirmed. After this the watcher
    /// stops polling it; operator sweeps confirmed rows on cron.
    fn mark_confirmed(
        &self,
        intent_id: &B256,
    ) -> impl std::future::Future<Output = Result<(), RegistryError>> + Send;

    /// Count of pending entries — used by metrics + the binary's
    /// startup log.
    fn pending_count(
        &self,
    ) -> impl std::future::Future<Output = Result<usize, RegistryError>> + Send;

    /// True iff ANY record (pending OR confirmed) exists for `intent_id`.
    /// Used by `xindex-redeem` to gate against re-executing an
    /// already-broadcast intent during `--from-block` backfill — a
    /// duplicate execute would pick a different UTXO (the original is
    /// mempool-spent in Esplora) and broadcast a second valid payout
    /// that the Bitcoin chain has no reason to reject. Result: user
    /// receives 2× their pro-rata for one share burn.
    fn has_record(
        &self,
        intent_id: &B256,
    ) -> impl std::future::Future<Output = Result<bool, RegistryError>> + Send;
}

/// Placeholder row for a write-ahead [`BroadcastRegistry::reserve`]
/// (audit H1). Carries no real broadcast data — `register` overwrites it
/// once the tx is sent. Status is `Reserved`, so `list_pending` never
/// surfaces it for re-broadcast.
fn reserved_placeholder(intent_id: B256) -> PendingBroadcast {
    PendingBroadcast {
        intent_id,
        txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32])),
        tx_bytes: Vec::new(),
        recipient_addr: String::new(),
        amount_sats: 0,
        broadcast_at_unix_secs: 0,
        last_attempt_unix_secs: 0,
    }
}

/// In-memory store. Loses state on restart; for tests + dev only.
#[derive(Debug, Default)]
pub struct InMemoryBroadcastRegistry {
    inner: Mutex<InnerState>,
}

#[derive(Debug, Default)]
struct InnerState {
    entries: HashMap<B256, (PendingBroadcast, BroadcastStatus)>,
}

impl InMemoryBroadcastRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl BroadcastRegistry for InMemoryBroadcastRegistry {
    async fn register(&self, entry: PendingBroadcast) -> Result<(), RegistryError> {
        self.inner
            .lock()
            .await
            .entries
            .insert(entry.intent_id, (entry, BroadcastStatus::Pending));
        Ok(())
    }

    async fn reserve(&self, intent_id: &B256) -> Result<bool, RegistryError> {
        let mut g = self.inner.lock().await;
        if g.entries.contains_key(intent_id) {
            return Ok(false);
        }
        g.entries.insert(
            *intent_id,
            (reserved_placeholder(*intent_id), BroadcastStatus::Reserved),
        );
        Ok(true)
    }

    async fn list_pending(&self) -> Result<Vec<PendingBroadcast>, RegistryError> {
        let guard = self.inner.lock().await;
        let mut out: Vec<PendingBroadcast> = guard
            .entries
            .values()
            .filter(|(_, st)| *st == BroadcastStatus::Pending)
            .map(|(e, _)| e.clone())
            .collect();
        out.sort_by_key(|e| e.broadcast_at_unix_secs);
        Ok(out)
    }

    async fn touch_attempt(
        &self,
        intent_id: &B256,
        now_unix_secs: u64,
    ) -> Result<(), RegistryError> {
        if let Some((entry, _)) = self.inner.lock().await.entries.get_mut(intent_id) {
            entry.last_attempt_unix_secs = now_unix_secs;
        }
        Ok(())
    }

    async fn mark_confirmed(&self, intent_id: &B256) -> Result<(), RegistryError> {
        if let Some((_, status)) = self.inner.lock().await.entries.get_mut(intent_id) {
            *status = BroadcastStatus::Confirmed;
        }
        Ok(())
    }

    async fn pending_count(&self) -> Result<usize, RegistryError> {
        Ok(self
            .inner
            .lock()
            .await
            .entries
            .values()
            .filter(|(_, st)| *st == BroadcastStatus::Pending)
            .count())
    }

    async fn has_record(&self, intent_id: &B256) -> Result<bool, RegistryError> {
        Ok(self.inner.lock().await.entries.contains_key(intent_id))
    }
}

/// `sqlx`-backed persistent broadcast registry.
///
/// On startup [`SqliteBroadcastRegistry::connect`] applies the
/// `migrations/` schema; subsequent restarts are idempotent.
pub struct SqliteBroadcastRegistry {
    pool: SqlitePool,
}

impl std::fmt::Debug for SqliteBroadcastRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteBroadcastRegistry")
            .finish_non_exhaustive()
    }
}

/// Raw row shape pulled by `list_pending`. Named alias keeps the
/// `query_as::<RawBroadcastRow>` site readable instead of inlining a
/// 7-tuple type that clippy's `type-complexity` lint rejects.
type RawBroadcastRow = (Vec<u8>, Vec<u8>, Vec<u8>, String, i64, i64, i64);

impl SqliteBroadcastRegistry {
    /// Open a `SQLite` connection at `database_url` and apply migrations.
    ///
    /// # Errors
    /// [`RegistryError::Sqlite`] on connect / pool failure;
    /// [`RegistryError::Migrate`] if a migration fails to apply.
    pub async fn connect(database_url: &str) -> Result<Self, RegistryError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    fn cast_secs(unix_secs: u64) -> Result<i64, RegistryError> {
        i64::try_from(unix_secs)
            .map_err(|e| RegistryError::Decode(format!("u64→i64 overflow on unix secs: {e}")))
    }

    fn cast_sats(sats: u64) -> Result<i64, RegistryError> {
        i64::try_from(sats)
            .map_err(|e| RegistryError::Decode(format!("u64→i64 overflow on sats: {e}")))
    }
}

impl BroadcastRegistry for SqliteBroadcastRegistry {
    async fn register(&self, entry: PendingBroadcast) -> Result<(), RegistryError> {
        let broadcast_at = Self::cast_secs(entry.broadcast_at_unix_secs)?;
        let last_attempt = Self::cast_secs(entry.last_attempt_unix_secs)?;
        let amount = Self::cast_sats(entry.amount_sats)?;
        let id_bytes = entry.intent_id.as_slice();
        let txid_bytes: [u8; 32] = entry.txid.to_raw_hash().to_byte_array();
        sqlx::query(
            r"
            INSERT INTO broadcasts
                (intent_id, txid, tx_bytes, recipient_addr, amount_sats,
                 broadcast_at_unix_secs, last_attempt_unix_secs, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
            ON CONFLICT(intent_id) DO UPDATE SET
                txid = excluded.txid,
                tx_bytes = excluded.tx_bytes,
                recipient_addr = excluded.recipient_addr,
                amount_sats = excluded.amount_sats,
                broadcast_at_unix_secs = excluded.broadcast_at_unix_secs,
                last_attempt_unix_secs = excluded.last_attempt_unix_secs,
                status = 'pending'
            ",
        )
        .bind(id_bytes)
        .bind(&txid_bytes[..])
        .bind(&entry.tx_bytes)
        .bind(&entry.recipient_addr)
        .bind(amount)
        .bind(broadcast_at)
        .bind(last_attempt)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn reserve(&self, intent_id: &B256) -> Result<bool, RegistryError> {
        // Insert a 'reserved' placeholder BEFORE the irreversible
        // broadcast (audit H1). ON CONFLICT DO NOTHING makes this an
        // atomic claim — rows_affected() == 0 means a row already exists
        // (replay / concurrent attempt) and the caller must NOT broadcast.
        let zero_txid = [0u8; 32];
        let res = sqlx::query(
            r"
            INSERT INTO broadcasts
                (intent_id, txid, tx_bytes, recipient_addr, amount_sats,
                 broadcast_at_unix_secs, last_attempt_unix_secs, status)
            VALUES (?, ?, X'', '', 0, 0, 0, 'reserved')
            ON CONFLICT(intent_id) DO NOTHING
            ",
        )
        .bind(intent_id.as_slice())
        .bind(&zero_txid[..])
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn list_pending(&self) -> Result<Vec<PendingBroadcast>, RegistryError> {
        let rows: Vec<RawBroadcastRow> = sqlx::query_as(
            "SELECT intent_id, txid, tx_bytes, recipient_addr, amount_sats,
                    broadcast_at_unix_secs, last_attempt_unix_secs
             FROM broadcasts
             WHERE status = 'pending'
             ORDER BY broadcast_at_unix_secs ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for (id_bytes, txid_bytes, tx_bytes, recipient, amount, broadcast_at, last_attempt) in rows
        {
            let id_arr: [u8; 32] = id_bytes
                .as_slice()
                .try_into()
                .map_err(|_| RegistryError::Decode("intent_id != 32 bytes".to_string()))?;
            let txid_arr: [u8; 32] = txid_bytes
                .as_slice()
                .try_into()
                .map_err(|_| RegistryError::Decode("txid != 32 bytes".to_string()))?;
            let txid =
                Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(txid_arr));
            let amount_u64 = u64::try_from(amount)
                .map_err(|e| RegistryError::Decode(format!("stored amount negative: {e}")))?;
            let broadcast_at_u64 = u64::try_from(broadcast_at)
                .map_err(|e| RegistryError::Decode(format!("stored broadcast_at negative: {e}")))?;
            let last_attempt_u64 = u64::try_from(last_attempt)
                .map_err(|e| RegistryError::Decode(format!("stored last_attempt negative: {e}")))?;
            out.push(PendingBroadcast {
                intent_id: B256::from(id_arr),
                txid,
                tx_bytes,
                recipient_addr: recipient,
                amount_sats: amount_u64,
                broadcast_at_unix_secs: broadcast_at_u64,
                last_attempt_unix_secs: last_attempt_u64,
            });
        }
        Ok(out)
    }

    async fn touch_attempt(
        &self,
        intent_id: &B256,
        now_unix_secs: u64,
    ) -> Result<(), RegistryError> {
        let now = Self::cast_secs(now_unix_secs)?;
        let id_bytes = intent_id.as_slice();
        sqlx::query("UPDATE broadcasts SET last_attempt_unix_secs = ? WHERE intent_id = ?")
            .bind(now)
            .bind(id_bytes)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn mark_confirmed(&self, intent_id: &B256) -> Result<(), RegistryError> {
        let id_bytes = intent_id.as_slice();
        sqlx::query("UPDATE broadcasts SET status = 'confirmed' WHERE intent_id = ?")
            .bind(id_bytes)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn pending_count(&self) -> Result<usize, RegistryError> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM broadcasts WHERE status = 'pending'")
                .fetch_one(&self.pool)
                .await?;
        usize::try_from(row.0)
            .map_err(|e| RegistryError::Decode(format!("count→usize overflow: {e}")))
    }

    async fn has_record(&self, intent_id: &B256) -> Result<bool, RegistryError> {
        let id_bytes = intent_id.as_slice();
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM broadcasts WHERE intent_id = ? LIMIT 1")
                .bind(id_bytes)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.is_some())
    }
}

/// Wall-clock unix seconds. Returns `None` on clock failure (pre-1970)
/// per the same `now_unix_secs` contract used by `xindex-cancel` —
/// callers MUST treat `None` as "skip this tick" rather than substituting
/// 0 (which would mark every broadcast as stuck and re-broadcast the
/// entire registry in a loop).
#[must_use]
pub fn now_unix_secs() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;
    use bitcoin::hashes::Hash;

    fn entry(intent_id: B256, broadcast_at: u64) -> PendingBroadcast {
        // Construct a synthetic txid + tx_bytes. Real values arrive from
        // bitcoin::Transaction::compute_txid() and consensus::encode in
        // production; tests only care about round-tripping the bytes.
        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xaa; 32]));
        PendingBroadcast {
            intent_id,
            txid,
            tx_bytes: vec![0x01, 0x02, 0x03, 0x04],
            recipient_addr: "bc1qfaketestaddr".to_string(),
            amount_sats: 100_000,
            broadcast_at_unix_secs: broadcast_at,
            last_attempt_unix_secs: broadcast_at,
        }
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn in_memory_register_list_confirm() {
        let r = InMemoryBroadcastRegistry::new();
        let id_a = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let id_b = b256!("0000000000000000000000000000000000000000000000000000000000000002");

        r.register(entry(id_a, 100)).await.expect("register a");
        r.register(entry(id_b, 200)).await.expect("register b");
        assert_eq!(r.pending_count().await.expect("count"), 2);

        let pending = r.list_pending().await.expect("list");
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].intent_id, id_a, "ordered by broadcast_at ASC");

        r.mark_confirmed(&id_a).await.expect("confirm");
        assert_eq!(r.pending_count().await.expect("count"), 1);

        let pending = r.list_pending().await.expect("list");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].intent_id, id_b);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn in_memory_touch_attempt_updates_timestamp() {
        let r = InMemoryBroadcastRegistry::new();
        let id = b256!("00000000000000000000000000000000000000000000000000000000000000aa");
        r.register(entry(id, 100)).await.expect("register");
        r.touch_attempt(&id, 500).await.expect("touch");

        let pending = r.list_pending().await.expect("list");
        assert_eq!(pending[0].last_attempt_unix_secs, 500);
        assert_eq!(
            pending[0].broadcast_at_unix_secs, 100,
            "broadcast_at preserved"
        );
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_register_list_confirm_round_trip() {
        let r = SqliteBroadcastRegistry::connect("sqlite::memory:")
            .await
            .expect("connect + migrate");
        let id = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let original = entry(id, 100);
        r.register(original.clone()).await.expect("register");

        let pending = r.list_pending().await.expect("list");
        assert_eq!(pending.len(), 1);
        let restored = &pending[0];
        assert_eq!(restored.intent_id, original.intent_id);
        assert_eq!(restored.txid, original.txid);
        assert_eq!(restored.tx_bytes, original.tx_bytes);
        assert_eq!(restored.recipient_addr, original.recipient_addr);
        assert_eq!(restored.amount_sats, original.amount_sats);
        assert_eq!(
            restored.broadcast_at_unix_secs,
            original.broadcast_at_unix_secs
        );

        r.mark_confirmed(&id).await.expect("confirm");
        assert_eq!(r.pending_count().await.expect("count"), 0);
    }

    /// Re-registering the same intent overwrites `tx_bytes` + resets
    /// `last_attempt_unix_secs` (used when the operator manually
    /// rebuilds + re-broadcasts a stuck intent with a higher fee).
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_register_overwrites_existing() {
        let r = SqliteBroadcastRegistry::connect("sqlite::memory:")
            .await
            .expect("connect");
        let id = b256!("0000000000000000000000000000000000000000000000000000000000000099");

        let mut original = entry(id, 100);
        original.tx_bytes = vec![0xaa, 0xbb];
        r.register(original.clone()).await.expect("register");

        let mut replacement = entry(id, 100);
        replacement.tx_bytes = vec![0xcc, 0xdd, 0xee];
        replacement.last_attempt_unix_secs = 500;
        r.register(replacement.clone()).await.expect("re-register");

        let pending = r.list_pending().await.expect("list");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tx_bytes, vec![0xcc, 0xdd, 0xee]);
        assert_eq!(pending[0].last_attempt_unix_secs, 500);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn in_memory_has_record_distinguishes_present_from_absent() {
        let r = InMemoryBroadcastRegistry::new();
        let id_present = b256!("00000000000000000000000000000000000000000000000000000000000000a1");
        let id_absent = b256!("00000000000000000000000000000000000000000000000000000000000000a2");
        r.register(entry(id_present, 100)).await.expect("register");
        assert!(r.has_record(&id_present).await.expect("has"));
        assert!(!r.has_record(&id_absent).await.expect("has"));
        // After mark_confirmed, the record still exists (status changed,
        // entry retained) — has_record covers both pending and confirmed
        // so backfill replay can't double-execute a previously settled
        // intent either.
        r.mark_confirmed(&id_present).await.expect("confirm");
        assert!(r.has_record(&id_present).await.expect("post-confirm"));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_has_record_distinguishes_present_from_absent() {
        let r = SqliteBroadcastRegistry::connect("sqlite::memory:")
            .await
            .expect("connect");
        let id_present = b256!("00000000000000000000000000000000000000000000000000000000000000b1");
        let id_absent = b256!("00000000000000000000000000000000000000000000000000000000000000b2");
        r.register(entry(id_present, 100)).await.expect("register");
        assert!(r.has_record(&id_present).await.expect("has"));
        assert!(!r.has_record(&id_absent).await.expect("has"));
        r.mark_confirmed(&id_present).await.expect("confirm");
        assert!(r.has_record(&id_present).await.expect("post-confirm"));
    }

    /// Audit H1: reserve-before-broadcast. A reservation dedups a replay
    /// (the second reserve is a no-op) and is excluded from the watcher's
    /// pending list until `register` promotes it with the real tx.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn in_memory_reserve_dedups_then_register_promotes() {
        let r = InMemoryBroadcastRegistry::new();
        let id = b256!("00000000000000000000000000000000000000000000000000000000000000c1");
        assert!(r.reserve(&id).await.expect("reserve"));
        assert!(!r.reserve(&id).await.expect("second reserve is a no-op"));
        assert!(r.has_record(&id).await.expect("has"));
        assert_eq!(
            r.pending_count().await.expect("count"),
            0,
            "a reserved row is not pending"
        );
        r.register(entry(id, 100)).await.expect("register");
        assert_eq!(r.pending_count().await.expect("count"), 1);
        let pending = r.list_pending().await.expect("list");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tx_bytes, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_reserve_dedups_then_register_promotes() {
        let r = SqliteBroadcastRegistry::connect("sqlite::memory:")
            .await
            .expect("connect");
        let id = b256!("00000000000000000000000000000000000000000000000000000000000000c2");
        assert!(r.reserve(&id).await.expect("reserve"));
        assert!(!r.reserve(&id).await.expect("second reserve is a no-op"));
        assert!(r.has_record(&id).await.expect("has"));
        assert_eq!(r.pending_count().await.expect("count"), 0);
        // register promotes the reserved placeholder and fills the real
        // recipient/amount (the upsert covers all columns, not just txid).
        r.register(entry(id, 100)).await.expect("register");
        assert_eq!(r.pending_count().await.expect("count"), 1);
        let pending = r.list_pending().await.expect("list");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].txid, entry(id, 100).txid);
        assert_eq!(pending[0].recipient_addr, "bc1qfaketestaddr");
        assert_eq!(pending[0].amount_sats, 100_000);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_touch_attempt_updates_timestamp() {
        let r = SqliteBroadcastRegistry::connect("sqlite::memory:")
            .await
            .expect("connect");
        let id = b256!("00000000000000000000000000000000000000000000000000000000000000ab");
        r.register(entry(id, 100)).await.expect("register");
        r.touch_attempt(&id, 9999).await.expect("touch");

        let pending = r.list_pending().await.expect("list");
        assert_eq!(pending[0].last_attempt_unix_secs, 9999);
        assert_eq!(pending[0].broadcast_at_unix_secs, 100, "preserved");
    }
}
