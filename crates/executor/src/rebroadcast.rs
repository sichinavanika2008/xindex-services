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
//!   NOTE (audit M8): a DEEP reorg of an already-`Confirmed` entry is NOT
//!   detected — `mark_confirmed` is one-way and `list_pending` no longer
//!   returns it. That orphan is operator-recoverable (the tx usually
//!   re-confirms from mempool); block-hash re-validation + a `mark_pending`
//!   transition is a documented follow-on, not implemented here.
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
    /// Confirmation depth at which we consider the broadcast settled and
    /// stop polling. Defaults to BTC `conf_depth` (6) — the protocol's
    /// finality bar (audit M8/M9). The prior default of 3 declared
    /// settlement three blocks BELOW finality; the signer cross-check
    /// policy uses 6 (`BTC_MIN_CONFIRMATIONS`), not 3.
    pub min_confirmations: u32,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            stuck_timeout: Duration::from_secs(3600),
            min_confirmations: 6,
        }
    }
}

/// Long-lived watcher task. Spawn via `tokio::spawn`; the future runs
/// forever unless cancelled by the caller (drop the `JoinHandle` to stop).
///
/// # Errors
/// Returns only if the registry returns a fatal error AND the caller
/// chose to propagate. Default behaviour: log + continue. The function
/// returns `Result<()>` for testing — production usage spawns it via
/// `tokio::spawn(async move { let _ = run_watcher(...).await; })`.
pub async fn run_watcher<R, C>(
    registry: Arc<R>,
    chain: Arc<C>,
    cfg: WatcherConfig,
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
        if let Err(e) = tick_once(registry.as_ref(), chain.as_ref(), cfg).await {
            // Tick-level errors are non-fatal: log + retry next tick.
            warn!(error = %e, "watcher tick failed; will retry");
        }
    }
}

/// One pass of the watcher loop. Extracted for testability.
async fn tick_once<R, C>(registry: &R, chain: &C, cfg: WatcherConfig) -> Result<(), WatcherError>
where
    R: BroadcastRegistry,
    C: UtxoChainClient,
{
    let pending = registry.list_pending().await?;
    if pending.is_empty() {
        return Ok(());
    }
    let Some(now) = now_unix_secs() else {
        warn!("system clock failure (pre-1970); skipping watcher tick");
        return Ok(());
    };

    for entry in pending {
        match chain.get_tx_status(&entry.txid) {
            Ok(status) if status.confirmed && status.confirmations >= cfg.min_confirmations => {
                if let Err(e) = registry.mark_confirmed(&entry.intent_id).await {
                    error!(intent_id = %entry.intent_id, error = %e,
                           "mark_confirmed failed; will retry next tick");
                } else {
                    info!(
                        intent_id = %entry.intent_id,
                        txid = %entry.txid,
                        confirmations = status.confirmations,
                        "broadcast confirmed; dropping from pending set"
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
                            info!(
                                intent_id = %entry.intent_id,
                                "re-broadcast no-op (node already has tx)"
                            );
                        }
                    }
                    Err(e) => {
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
        chain.push_status(Ok(UtxoTxStatus {
            txid,
            confirmed: true,
            block_height: Some(800_000),
            block_hash: Some(BlockHash::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0xab; 32]),
            )),
            confirmations: 6,
        }));

        let cfg = WatcherConfig {
            interval: Duration::from_secs(60),
            stuck_timeout: Duration::from_secs(3600),
            min_confirmations: 3,
        };
        tick_once(&registry, &chain, cfg).await.expect("tick");

        // After tick: confirmed entry is dropped from pending.
        assert_eq!(registry.pending_count().await.expect("count"), 0);
        // We did NOT broadcast — only mark_confirmed.
        assert_eq!(chain.broadcast_count(), 0);
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
