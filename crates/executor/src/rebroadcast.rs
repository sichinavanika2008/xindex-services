//! Reorg-aware re-broadcast watcher.
//!
//! Closes Rust-audit finding L-R2. Runs as a long-lived task spawned by
//! `xindex-redeem`; every `interval` it walks the pending broadcasts
//! and decides per-entry:
//!
//! - **Confirmed deep enough** (`confirmations >= min_confirmations`):
//!   call [`BroadcastRegistry::mark_confirmed`]. Watcher stops polling
//!   it; the on-chain `RedeemSettled` flow takes over.
//!
//! - **Not seen on chain AND stuck-timeout exceeded** — when
//!   `(now - last_attempt)` exceeds `stuck_timeout`, re-call
//!   `chain.broadcast(tx)` with the stored `tx_bytes`. Same txid (we
//!   never change the tx) so Bitcoin treats the re-broadcast as a
//!   no-op if the original is somewhere in the mempool — but kicks any
//!   node that dropped it back into propagation. Bump
//!   `last_attempt_unix_secs`.
//!
//! - **Shallow reorg** (depth < `min_confirmations`): the entry is still
//!   `Pending` (it never reached `mark_confirmed`), so the stuck-timeout
//!   path re-broadcasts it; Bitcoin no-ops if the tx is still in a block.
//!
//! - **Deep reorg of a `Confirmed` entry** (audit M8): `mark_confirmed`
//!   records the confirming `block_hash`/`block_height`, and every tick the
//!   watcher RE-VALIDATES each `Confirmed` row against the chain. If the tx
//!   is no longer confirmed (its recorded block was orphaned and the tx is
//!   not in another block), it is demoted back to `Pending` (`mark_pending`,
//!   which zeroes `last_attempt` so the next tick re-broadcasts it). If it
//!   re-confirmed in a DIFFERENT block (survived the reorg), the recorded
//!   block is updated. Once buried `final_depth` deep — beyond any plausible
//!   reorg — it graduates to terminal `Final` and is no longer re-validated.
//!
//! - **Anything else (RPC error, still in mempool, still confirming)**:
//!   leave for the next tick. Don't re-broadcast without evidence the
//!   prior attempt is gone.
//!
//! ## Why the same tx (not RBF / fee bump)
//!
//! Re-broadcasting the same tx is safe under all conditions:
//! - If the original is in some node's mempool → no-op
//! - If the original is in a block → no-op
//! - If the original was dropped → propagates fresh
//!
//! RBF (replace-by-fee) with a higher fee is a v2 hardening when we
//! have dynamic fee estimation (Rust-audit L-R5). Today we accept that
//! a stuck low-fee tx may take longer to confirm; it won't lose funds.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::Transaction;
use thiserror::Error;
use tokio::time::interval;
use tracing::{error, info, warn};
use xindex_chain_utxo::{UtxoChainClient, UtxoError};
use xindex_ops::Metrics;

use crate::broadcast_registry::{now_unix_secs, BroadcastRegistry, RegistryError};

/// Errors surfaced by the watcher. Most are non-fatal — the watcher
/// logs and continues — but the type lets a caller stop on certain
/// classes if desired.
#[derive(Debug, Error)]
pub enum WatcherError {
    #[error("registry error: {0}")]
    Registry(#[from] RegistryError),
    #[error("decode stored tx_bytes failed: {0}")]
    DecodeTx(String),
}

/// Tunables for the watcher. Defaults chosen for signet + Phase 2.A
/// staging; mainnet may want different values.
#[derive(Debug, Clone, Copy)]
pub struct WatcherConfig {
    /// How often to poll the chain. 60 s is granular enough that no
    /// stuck tx waits more than a minute beyond `stuck_timeout`.
    pub interval: Duration,
    /// Stuck-timeout: re-broadcast if `now - last_attempt` exceeds
    /// this and the tx isn't visible on chain. 1 hour is conservative
    /// — far longer than normal mempool retention, short enough that a
    /// dropped tx doesn't sit unaddressed all day.
    pub stuck_timeout: Duration,
    /// Confirmation depth at which we consider the broadcast settled (move
    /// from `Pending` to `Confirmed`). Defaults to BTC `conf_depth` (6) — the
    /// protocol's finality bar (audit M8/M9). The prior default of 3 declared
    /// settlement three blocks BELOW finality; the signer cross-check policy
    /// uses 6 (`BTC_MIN_CONFIRMATIONS`), not 3.
    pub min_confirmations: u32,
    /// Depth at which a `Confirmed` broadcast is considered FINAL — beyond any
    /// plausible re-org — and the watcher stops re-validating it (audit M8).
    /// 100 blocks (~16 h on BTC) is astronomically beyond the deepest observed
    /// mainnet re-org; until then every `Confirmed` row is re-checked each tick
    /// so a deep re-org that orphans the payout is caught and re-broadcast.
    pub final_depth: u32,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            stuck_timeout: Duration::from_secs(3600),
            min_confirmations: 6,
            final_depth: 100,
        }
    }
}

/// Long-lived watcher task. The future runs forever unless cancelled by the
/// caller. Production callers should supervise it alongside their event source
/// and metrics server so an unexpected exit terminates the process.
///
/// # Errors
/// Returns only if the outer loop itself fails. Per-tick registry and chain
/// errors are logged and retried. Passing metrics keeps the pending-broadcast
/// gauge synchronized with the durable registry and records rebroadcast
/// outcomes.
pub async fn run_watcher<R, C>(
    registry: Arc<R>,
    chain: Arc<C>,
    cfg: WatcherConfig,
    metrics: Option<Metrics>,
) -> Result<(), WatcherError>
where
    R: BroadcastRegistry + 'static,
    C: UtxoChainClient + Send + Sync + 'static,
{
    let mut ticker = interval(cfg.interval);
    // First tick fires immediately; skip it so the watcher doesn't
    // re-broadcast the entire registry on startup.
    ticker.tick().await;
    info!(
        interval_secs = cfg.interval.as_secs(),
        stuck_timeout_secs = cfg.stuck_timeout.as_secs(),
        min_confirmations = cfg.min_confirmations,
        "rebroadcast watcher started"
    );

    loop {
        ticker.tick().await;
        if let Err(e) =
            tick_once_with_metrics(registry.as_ref(), chain.as_ref(), cfg, metrics.as_ref()).await
        {
            // Tick-level errors are non-fatal: log + retry next tick.
            warn!(error = %e, "watcher tick failed; will retry");
        }
        if let Some(metrics) = &metrics {
            match registry.pending_count().await {
                Ok(pending) => metrics
                    .executor_pending_broadcasts
                    .set(i64::try_from(pending).unwrap_or(i64::MAX)),
                Err(error) => warn!(%error, "pending broadcast metric refresh failed"),
            }
        }
    }
}

/// One pass of the watcher loop. Extracted for testability. Processes the
/// pending set (confirm-or-rebroadcast) and then RE-VALIDATES the confirmed
/// set against re-org (audit M8).
#[cfg(test)]
async fn tick_once<R, C>(registry: &R, chain: &C, cfg: WatcherConfig) -> Result<(), WatcherError>
where
    R: BroadcastRegistry,
    C: UtxoChainClient,
{
    tick_once_with_metrics(registry, chain, cfg, None).await
}

async fn tick_once_with_metrics<R, C>(
    registry: &R,
    chain: &C,
    cfg: WatcherConfig,
    metrics: Option<&Metrics>,
) -> Result<(), WatcherError>
where
    R: BroadcastRegistry,
    C: UtxoChainClient,
{
    let Some(now) = now_unix_secs() else {
        warn!("system clock failure (pre-1970); skipping watcher tick");
        return Ok(());
    };
    process_pending(registry, chain, cfg, now, metrics).await?;
    revalidate_confirmed(registry, chain, cfg, metrics).await?;
    Ok(())
}

/// Walk the pending broadcasts: mark deep-enough confirmations `Confirmed`
/// (recording the confirming block — audit M8), and re-broadcast any tx past
/// its stuck-timeout.
async fn process_pending<R, C>(
    registry: &R,
    chain: &C,
    cfg: WatcherConfig,
    now: u64,
    metrics: Option<&Metrics>,
) -> Result<(), WatcherError>
where
    R: BroadcastRegistry,
    C: UtxoChainClient,
{
    let pending = registry.list_pending().await?;
    for entry in pending {
        match chain.get_tx_status(&entry.txid) {
            Ok(status) if status.confirmed && status.confirmations >= cfg.min_confirmations => {
                let (Some(block_hash), Some(block_height)) =
                    (status.block_hash, status.block_height)
                else {
                    warn!(
                        intent_id = %entry.intent_id, txid = %entry.txid,
                        "confirmed but chain returned no block hash/height; deferring mark_confirmed"
                    );
                    continue;
                };
                if let Err(e) = registry
                    .mark_confirmed(&entry.intent_id, &block_hash, block_height)
                    .await
                {
                    error!(intent_id = %entry.intent_id, error = %e,
                           "mark_confirmed failed; will retry next tick");
                } else {
                    if let Some(metrics) = metrics {
                        metrics
                            .custody_dispatches
                            .with_label_values(&["btc", "confirmed"])
                            .inc();
                    }
                    info!(
                        intent_id = %entry.intent_id,
                        txid = %entry.txid,
                        confirmations = status.confirmations,
                        "broadcast confirmed; now re-validated against reorg each tick"
                    );
                }
            }
            Ok(_) => {
                let elapsed = now.saturating_sub(entry.last_attempt_unix_secs);
                if elapsed <= cfg.stuck_timeout.as_secs() {
                    // Still within stuck-timeout: leave it, next tick.
                    continue;
                }
                // Stuck. Decode + re-broadcast.
                let tx = match bitcoin::consensus::deserialize::<Transaction>(&entry.tx_bytes) {
                    Ok(t) => t,
                    Err(e) => {
                        error!(
                            intent_id = %entry.intent_id,
                            error = %e,
                            "stored tx_bytes won't deserialize — MANUAL INTERVENTION REQUIRED"
                        );
                        continue;
                    }
                };
                match chain.broadcast(&tx) {
                    Ok(_) => {
                        if let Err(e) = registry.touch_attempt(&entry.intent_id, now).await {
                            error!(intent_id = %entry.intent_id, error = %e,
                                   "touch_attempt failed after successful re-broadcast");
                        } else {
                            record_rebroadcast(metrics, "success");
                            info!(
                                intent_id = %entry.intent_id,
                                txid = %entry.txid,
                                stuck_for_secs = elapsed,
                                "re-broadcast (was stuck)"
                            );
                        }
                    }
                    Err(UtxoError::Upstream(msg)) if is_already_known(&msg) => {
                        // Node already has the tx — count this as a
                        // successful re-broadcast attempt. Bumping
                        // last_attempt avoids hammering Esplora on
                        // every tick.
                        if let Err(e) = registry.touch_attempt(&entry.intent_id, now).await {
                            warn!(intent_id = %entry.intent_id, error = %e,
                                  "touch_attempt failed after already-known re-broadcast");
                        } else {
                            record_rebroadcast(metrics, "already_known");
                            info!(
                                intent_id = %entry.intent_id,
                                "re-broadcast no-op (node already has tx)"
                            );
                        }
                    }
                    Err(e) => {
                        record_rebroadcast(metrics, "error");
                        warn!(intent_id = %entry.intent_id, error = %e,
                              "re-broadcast failed; will retry next tick");
                    }
                }
            }
            Err(UtxoError::Transport(msg)) => {
                // RPC-side flake. Don't act on this entry — pretending
                // the tx is gone when we just can't see it would cause
                // a spurious re-broadcast loop while Esplora is down.
                warn!(intent_id = %entry.intent_id, error = %msg,
                      "get_tx_status transport failure; deferring");
            }
            Err(e) => {
                warn!(intent_id = %entry.intent_id, error = %e,
                      "get_tx_status failed; deferring");
            }
        }
    }
    Ok(())
}

fn record_rebroadcast(metrics: Option<&Metrics>, outcome: &str) {
    if let Some(metrics) = metrics {
        metrics
            .executor_rebroadcasts
            .with_label_values(&[outcome])
            .inc();
    }
}

/// Re-validate each `Confirmed` broadcast against re-org (audit M8). For each
/// confirmed row the watcher re-queries the chain:
///
/// - **Still confirmed, `final_depth` deep** → graduate to terminal `Final`
///   (stop re-validating; beyond any plausible re-org).
/// - **Still confirmed in a DIFFERENT block** → the tx survived a re-org in a
///   new block; update the recorded block, keep watching.
/// - **No longer confirmed** → the recorded block was orphaned and the tx is
///   in no block now: demote to `Pending` (`mark_pending` zeroes
///   `last_attempt`) so the next tick re-broadcasts the stored tx.
/// - **Same block, still confirming** → no-op; re-validate next tick.
/// - **RPC error** → defer (acting on a flake would spuriously demote a good
///   payout).
async fn revalidate_confirmed<R, C>(
    registry: &R,
    chain: &C,
    cfg: WatcherConfig,
    metrics: Option<&Metrics>,
) -> Result<(), WatcherError>
where
    R: BroadcastRegistry,
    C: UtxoChainClient,
{
    let confirmed = registry.list_confirmed().await?;
    for c in confirmed {
        match chain.get_tx_status(&c.entry.txid) {
            Ok(status) if status.confirmed => {
                if status.confirmations >= cfg.final_depth {
                    if let Err(e) = registry.mark_final(&c.entry.intent_id).await {
                        error!(intent_id = %c.entry.intent_id, error = %e,
                               "mark_final failed; will retry next tick");
                    } else {
                        info!(
                            intent_id = %c.entry.intent_id,
                            confirmations = status.confirmations,
                            "broadcast final ({final_depth}+ deep); no longer re-validated",
                            final_depth = cfg.final_depth
                        );
                    }
                } else if status.block_hash != Some(c.block_hash) {
                    // Re-confirmed in a different block — survived a re-org.
                    let (Some(new_hash), Some(new_height)) =
                        (status.block_hash, status.block_height)
                    else {
                        // confirmed but no block hash (Esplora quirk): leave
                        // the recorded block as-is, re-check next tick.
                        continue;
                    };
                    if let Err(e) = registry
                        .mark_confirmed(&c.entry.intent_id, &new_hash, new_height)
                        .await
                    {
                        error!(intent_id = %c.entry.intent_id, error = %e,
                               "reorg re-confirm update failed; will retry next tick");
                    } else {
                        warn!(
                            intent_id = %c.entry.intent_id,
                            old_block = %c.block_hash,
                            new_block = %new_hash,
                            "confirmed tx re-confirmed in a new block (survived reorg)"
                        );
                    }
                }
                // else: same block, still confirming → no-op.
            }
            Ok(_unconfirmed) => {
                // The recorded confirming block was orphaned and the tx is in
                // NO block now — the payout disappeared from the canonical
                // chain. Demote to pending so the next tick re-broadcasts it.
                if let Err(e) = registry.mark_pending(&c.entry.intent_id).await {
                    error!(intent_id = %c.entry.intent_id, error = %e,
                           "mark_pending failed after reorg orphan; will retry next tick");
                } else {
                    if let Some(metrics) = metrics {
                        metrics.executor_pending_broadcasts.inc();
                    }
                    warn!(
                        intent_id = %c.entry.intent_id,
                        txid = %c.entry.txid,
                        orphaned_block = %c.block_hash,
                        "REORG: confirmed payout orphaned; demoted to pending for re-broadcast"
                    );
                }
            }
            Err(UtxoError::Transport(msg)) => {
                warn!(intent_id = %c.entry.intent_id, error = %msg,
                      "get_tx_status transport failure during reorg re-validation; deferring");
            }
            Err(e) => {
                warn!(intent_id = %c.entry.intent_id, error = %e,
                      "get_tx_status failed during reorg re-validation; deferring");
            }
        }
    }
    Ok(())
}

/// Esplora returns "already known" / "already in block chain" style
/// errors for txs the node has seen. Treat these as a successful
/// re-broadcast no-op rather than a failure.
fn is_already_known(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("already") || lower.contains("txn-already-in-mempool")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broadcast_registry::{InMemoryBroadcastRegistry, PendingBroadcast};
    use alloy_primitives::{b256, B256};
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, BlockHash, Txid};
    use std::sync::Mutex as StdMutex;
    use xindex_chain_utxo::UtxoTxStatus;
    use xindex_chain_utxo::{UtxoEntry, UtxoError};

    /// In-memory fake of `UtxoChainClient`. Each call resolves to a
    /// scripted response stored in `Vec<...>` so tests can express
    /// "first call says not-confirmed, second call says confirmed."
    #[derive(Default)]
    struct FakeChain {
        statuses: StdMutex<Vec<Result<UtxoTxStatus, UtxoError>>>,
        broadcast_results: StdMutex<Vec<Result<Txid, UtxoError>>>,
        broadcasts: StdMutex<Vec<Txid>>,
    }

    impl FakeChain {
        fn push_status(&self, r: Result<UtxoTxStatus, UtxoError>) {
            self.statuses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(r);
        }
        fn push_broadcast(&self, r: Result<Txid, UtxoError>) {
            self.broadcast_results
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(r);
        }
        fn broadcast_count(&self) -> usize {
            self.broadcasts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len()
        }
    }

    impl UtxoChainClient for FakeChain {
        fn get_address_utxos(
            &self,
            _address: &bitcoin::Address,
        ) -> Result<Vec<UtxoEntry>, UtxoError> {
            Ok(vec![])
        }
        fn get_tx_status(&self, _txid: &Txid) -> Result<UtxoTxStatus, UtxoError> {
            self.statuses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop()
                .unwrap_or_else(|| {
                    // Default = "not confirmed" so tests that only need
                    // happy-path confirmations don't need to push the
                    // not-confirmed cases explicitly.
                    Ok(UtxoTxStatus {
                        txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                            [0; 32],
                        )),
                        confirmed: false,
                        block_height: None,
                        block_hash: None,
                        confirmations: 0,
                    })
                })
        }
        fn get_tip_height(&self) -> Result<u32, UtxoError> {
            Ok(800_000)
        }
        fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<Txid, UtxoError> {
            let txid = tx.compute_txid();
            self.broadcasts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(txid);
            self.broadcast_results
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop()
                .unwrap_or(Ok(txid))
        }
    }

    /// Build a synthetic `PendingBroadcast` whose `tx_bytes` is a real,
    /// consensus-encodable `Transaction` (otherwise re-broadcast's
    /// deserialize step would fail in tests).
    fn synthetic_pending(intent_id: B256, broadcast_at: u64) -> (PendingBroadcast, Txid) {
        use bitcoin::transaction::Version;
        use bitcoin::{absolute, Sequence, TxIn, TxOut, Witness};

        let tx = bitcoin::Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let tx_bytes = bitcoin::consensus::serialize(&tx);
        let txid = tx.compute_txid();
        (
            PendingBroadcast {
                intent_id,
                txid,
                tx_bytes,
                recipient_addr: "bc1qfaketestaddr".to_string(),
                amount_sats: 100_000,
                broadcast_at_unix_secs: broadcast_at,
                last_attempt_unix_secs: broadcast_at,
            },
            txid,
        )
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn tick_marks_confirmed_when_deep_enough() {
        let registry = InMemoryBroadcastRegistry::new();
        let id = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let (entry, txid) = synthetic_pending(id, 100);
        registry.register(entry).await.expect("register");

        let chain = FakeChain::default();
        let confirmed = UtxoTxStatus {
            txid,
            confirmed: true,
            block_height: Some(800_000),
            block_hash: Some(BlockHash::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0xab; 32]),
            )),
            confirmations: 6,
        };
        // The same status is consumed by BOTH tick passes: process_pending
        // (→ mark_confirmed) and revalidate_confirmed (→ same block, no-op).
        chain.push_status(Ok(confirmed.clone()));
        chain.push_status(Ok(confirmed));

        let cfg = WatcherConfig {
            interval: Duration::from_secs(60),
            stuck_timeout: Duration::from_secs(3600),
            min_confirmations: 3,
            final_depth: 100,
        };
        tick_once(&registry, &chain, cfg).await.expect("tick");

        // After tick: confirmed entry is dropped from pending and stays
        // confirmed (same block on re-validation — not demoted, not final).
        assert_eq!(registry.pending_count().await.expect("count"), 0);
        assert_eq!(registry.list_confirmed().await.expect("confirmed").len(), 1);
        // We did NOT broadcast — only mark_confirmed.
        assert_eq!(chain.broadcast_count(), 0);
    }

    /// Helper: a confirmed-in-`block` status for `txid` at `confs` depth.
    fn confirmed_status(txid: Txid, block: [u8; 32], confs: u32) -> UtxoTxStatus {
        UtxoTxStatus {
            txid,
            confirmed: true,
            block_height: Some(800_000),
            block_hash: Some(BlockHash::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array(block),
            )),
            confirmations: confs,
        }
    }

    /// M8: a confirmed payout whose recorded block is orphaned by a deep
    /// re-org (the tx is no longer confirmed) is demoted back to pending so
    /// the next tick re-broadcasts it.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn tick_demotes_orphaned_confirmed_to_pending() {
        let registry = InMemoryBroadcastRegistry::new();
        let id = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let (entry, txid) = synthetic_pending(id, 100);
        registry.register(entry).await.expect("register");
        // Drive it to Confirmed in block 0xaa directly.
        let block_a =
            BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xaa; 32]));
        registry
            .mark_confirmed(&id, &block_a, 800_000)
            .await
            .expect("confirm");
        assert_eq!(registry.list_confirmed().await.expect("c").len(), 1);

        // The chain now reports the tx UNCONFIRMED (its block was orphaned).
        let chain = FakeChain::default();
        chain.push_status(Ok(UtxoTxStatus {
            txid,
            confirmed: false,
            block_height: None,
            block_hash: None,
            confirmations: 0,
        }));

        tick_once(&registry, &chain, WatcherConfig::default())
            .await
            .expect("tick");

        // Demoted: back in the pending set, no longer confirmed, last_attempt
        // zeroed so the next tick re-broadcasts it.
        assert_eq!(registry.list_confirmed().await.expect("c").len(), 0);
        let pending = registry.list_pending().await.expect("p");
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].last_attempt_unix_secs, 0,
            "reset for re-broadcast"
        );
    }

    /// M8: a confirmed payout buried `final_depth` deep graduates to terminal
    /// `Final` and is no longer re-validated.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn tick_marks_final_when_deep() {
        let registry = InMemoryBroadcastRegistry::new();
        let id = b256!("0000000000000000000000000000000000000000000000000000000000000002");
        let (entry, txid) = synthetic_pending(id, 100);
        registry.register(entry).await.expect("register");
        let block_a =
            BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xaa; 32]));
        registry
            .mark_confirmed(&id, &block_a, 800_000)
            .await
            .expect("confirm");

        let chain = FakeChain::default();
        // 150 confs ≥ default final_depth (100).
        chain.push_status(Ok(confirmed_status(txid, [0xaa; 32], 150)));

        tick_once(&registry, &chain, WatcherConfig::default())
            .await
            .expect("tick");

        // Final: no longer confirmed (re-validated set), not pending, record
        // retained (so backfill replay still sees it).
        assert_eq!(registry.list_confirmed().await.expect("c").len(), 0);
        assert_eq!(registry.pending_count().await.expect("p"), 0);
        assert!(registry.has_record(&id).await.expect("has"));
    }

    /// M8: a confirmed payout re-confirmed in a DIFFERENT block (survived a
    /// re-org) updates its recorded block and stays confirmed (no demotion).
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn tick_updates_block_on_survived_reorg() {
        let registry = InMemoryBroadcastRegistry::new();
        let id = b256!("0000000000000000000000000000000000000000000000000000000000000003");
        let (entry, txid) = synthetic_pending(id, 100);
        registry.register(entry).await.expect("register");
        let block_a =
            BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xaa; 32]));
        registry
            .mark_confirmed(&id, &block_a, 800_000)
            .await
            .expect("confirm");

        let chain = FakeChain::default();
        // Re-confirmed in a NEW block 0xbb, still shallow (< final_depth).
        chain.push_status(Ok(confirmed_status(txid, [0xbb; 32], 4)));

        tick_once(&registry, &chain, WatcherConfig::default())
            .await
            .expect("tick");

        // Still confirmed, recorded block updated to 0xbb; not demoted.
        let confirmed = registry.list_confirmed().await.expect("c");
        assert_eq!(confirmed.len(), 1);
        let block_b =
            BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xbb; 32]));
        assert_eq!(confirmed[0].block_hash, block_b, "recorded block updated");
        assert_eq!(registry.pending_count().await.expect("p"), 0);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn tick_leaves_unconfirmed_within_stuck_timeout_alone() {
        let registry = InMemoryBroadcastRegistry::new();
        let id = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        // last_attempt = now (fresh broadcast): inside the stuck window.
        let now = now_unix_secs().expect("clock");
        let (mut entry, _txid) = synthetic_pending(id, now);
        entry.last_attempt_unix_secs = now;
        registry.register(entry).await.expect("register");

        let chain = FakeChain::default();
        chain.push_status(Ok(UtxoTxStatus {
            txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0; 32])),
            confirmed: false,
            block_height: None,
            block_hash: None,
            confirmations: 0,
        }));

        tick_once(&registry, &chain, WatcherConfig::default())
            .await
            .expect("tick");

        // Not confirmed AND inside stuck window → leave alone.
        assert_eq!(registry.pending_count().await.expect("count"), 1);
        assert_eq!(chain.broadcast_count(), 0);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn tick_rebroadcasts_when_stuck() {
        let registry = InMemoryBroadcastRegistry::new();
        let id = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        // last_attempt 2 hours ago → past the 1-hour stuck_timeout.
        let now = now_unix_secs().expect("clock");
        let two_hours_ago = now.saturating_sub(7200);
        let (mut entry, txid) = synthetic_pending(id, two_hours_ago);
        entry.last_attempt_unix_secs = two_hours_ago;
        registry.register(entry).await.expect("register");

        let chain = FakeChain::default();
        chain.push_status(Ok(UtxoTxStatus {
            txid,
            confirmed: false,
            block_height: None,
            block_hash: None,
            confirmations: 0,
        }));

        tick_once(&registry, &chain, WatcherConfig::default())
            .await
            .expect("tick");

        // Re-broadcast happened.
        assert_eq!(chain.broadcast_count(), 1);
        // Entry is still pending (we re-broadcast, didn't mark confirmed).
        assert_eq!(registry.pending_count().await.expect("count"), 1);
        // last_attempt got bumped close to now.
        let pending = registry.list_pending().await.expect("list");
        assert!(
            pending[0].last_attempt_unix_secs > two_hours_ago,
            "last_attempt should be updated past the old timestamp"
        );
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn tick_treats_already_known_as_successful_rebroadcast() {
        let registry = InMemoryBroadcastRegistry::new();
        let id = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let now = now_unix_secs().expect("clock");
        let two_hours_ago = now.saturating_sub(7200);
        let (mut entry, txid) = synthetic_pending(id, two_hours_ago);
        entry.last_attempt_unix_secs = two_hours_ago;
        registry.register(entry).await.expect("register");

        let chain = FakeChain::default();
        chain.push_status(Ok(UtxoTxStatus {
            txid,
            confirmed: false,
            block_height: None,
            block_hash: None,
            confirmations: 0,
        }));
        chain.push_broadcast(Err(UtxoError::Upstream(
            "txn-already-in-mempool".to_string(),
        )));

        tick_once(&registry, &chain, WatcherConfig::default())
            .await
            .expect("tick");

        // last_attempt got bumped despite the "error".
        let pending = registry.list_pending().await.expect("list");
        assert!(pending[0].last_attempt_unix_secs > two_hours_ago);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn tick_defers_on_transport_error() {
        let registry = InMemoryBroadcastRegistry::new();
        let id = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let now = now_unix_secs().expect("clock");
        let two_hours_ago = now.saturating_sub(7200);
        let (mut entry, _) = synthetic_pending(id, two_hours_ago);
        entry.last_attempt_unix_secs = two_hours_ago;
        registry.register(entry).await.expect("register");

        let chain = FakeChain::default();
        chain.push_status(Err(UtxoError::Transport("network down".to_string())));

        tick_once(&registry, &chain, WatcherConfig::default())
            .await
            .expect("tick");

        // Transport error → no broadcast attempt.
        assert_eq!(chain.broadcast_count(), 0);
        // Entry still pending.
        assert_eq!(registry.pending_count().await.expect("count"), 1);
    }
}
