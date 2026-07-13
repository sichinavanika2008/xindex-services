//! `xindex-cancel` — production deadline relayer (M3 deliverable).
//!
//! Watches a deployed `IntentQueue` for `MintIntentCreated`,
//! `MintIntentFinalized`, and `MintIntentCancelled` events. Tracks every
//! pending intent in memory ([`IntentTracker`]); on each tick (default
//! 60 s) scans for intents whose `deadline` has passed and calls
//! `IndexToken.cancelMint(intentId)` on the originating clone.
//!
//! ## Trust posture
//!
//! `cancelMint` is permissionless on the contract side — anyone may call
//! it for any expired intent. We don't authoritatively decide anything;
//! we just nudge the chain. A missed dispatch is recoverable: the next
//! poll catches it. Re-attempting an already-cancelled intent reverts
//! cleanly with `IndexToken_AsyncIntentAlreadyResolved`, which we log
//! and skip.
//!
//! ## H-A1 interaction (important)
//!
//! Since the H-A1 fix shipped in `IndexToken.cancelMint`, the contract
//! REJECTS cancel for any fully-attested intent whose attestations all
//! landed before the deadline. That intent must be finalized, not
//! cancelled — and `xindex-attest` is the actor that finalizes. The
//! relayer's `cancelMint` call in that case reverts with
//! `IndexToken_FinalizableMustBeFinalized`. We log and skip; a finalize
//! tx posted by the attest daemon (or any user) settles the intent.
//!
//! ## Replay-after-restart
//!
//! Optional `--from-block` backfills missed events between the supplied
//! block and the latest tip before subscribing live. Re-tracking an
//! already-resolved intent is fine: the tracker's `mark_resolved` runs
//! when we see the corresponding `MintIntentFinalized` /
//! `MintIntentCancelled` event in the same backfill batch.

use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use clap::Parser;
use futures_util::StreamExt;
use prometheus::Registry;
use tokio::time::interval;
use tracing::{info, warn};
use xindex_chain_eth::bindings::{IndexToken, IntentQueue};
use xindex_chain_eth::rpc::WsEndpointList;
use xindex_ops::{init_tracing, serve_metrics, Metrics};
use xindex_relayer::{
    InMemoryIntentTracker, IntentTrackerStore, SqliteIntentTracker, TrackedIntent,
};

#[derive(Parser, Debug)]
#[command(version, about = "Xindex deadline relayer (M3)")]
struct Args {
    /// Comma-separated WebSocket Ethereum RPC endpoint(s). Position 0 is
    /// primary; subsequent entries are fallbacks tried only when primary
    /// returns a transient error at connect time. Anvil default is
    /// `ws://127.0.0.1:8545`. Production example:
    /// `wss://eth.alchemy.com/v2/KEY,wss://eth.infura.io/ws/v3/KEY,wss://eth.llamarpc.com`.
    ///
    /// **Closes Rust-audit L-R3.** Subscriptions still hold a single
    /// underlying connection — sub-death triggers daemon exit; operator
    /// restart promotes the next URL to primary via standard restart-on-
    /// failure orchestration (systemd `Restart=always`, k8s liveness, etc).
    #[arg(long, env = "ETH_RPC_URL", default_value = "ws://127.0.0.1:8545")]
    rpc_url: String,

    /// Deployed `IntentQueue` address. Watched for the three lifecycle
    /// events: `MintIntentCreated`, `MintIntentFinalized`, and
    /// `MintIntentCancelled`.
    #[arg(long, env = "INTENT_QUEUE_ADDR")]
    intent_queue: String,

    /// Gas-paying address used for permissionless cancelMint calls. The RPC
    /// delegates signing to a node-managed external signer; this process never
    /// accepts raw private key material.
    #[arg(long, env = "POSTER_ADDRESS")]
    poster_address: String,

    /// Scan interval in seconds. Each tick the relayer asks the tracker
    /// "which intents have crossed their deadline?" and dispatches cancel
    /// for each. Default 60 s — granular enough that no intent waits
    /// more than a minute past its deadline before recovery.
    #[arg(long, env = "SCAN_INTERVAL_SECS", default_value_t = 60)]
    scan_interval_secs: u64,

    /// Block number to start replay from when the daemon (re)starts.
    /// Use 0 (default) to subscribe only to new events. Pass a historical
    /// block to backfill missed events after downtime.
    #[arg(long, env = "FROM_BLOCK", default_value_t = 0)]
    from_block: u64,

    /// Optional `sqlx` database URL for persistent tracker state. If
    /// unset, the daemon falls back to an in-memory tracker (legacy
    /// behaviour — survives only until restart). Production should set
    /// `sqlite:./xindex-relayer.db?mode=rwc` so a crash + restart
    /// recovers without depending on `--from-block` backfill.
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,

    /// Bind address for the Prometheus `/metrics` + `/health` endpoint.
    /// Production: bind to a private interface (Prometheus scrape from
    /// inside the cluster); never expose publicly without an auth proxy.
    /// Default `0.0.0.0:9091` matches our k8s scrape annotation.
    #[arg(long, env = "METRICS_ADDR", default_value = "0.0.0.0:9091")]
    metrics_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let args = Args::parse();

    // Stand up the Prometheus + health server before anything else.
    // A scrape config in Prometheus that gets connection-refused on a
    // freshly-rolled pod is a paging false alarm; serving immediately
    // means the first scrape after rollout succeeds.
    let registry = Registry::new();
    let metrics = Arc::new(Metrics::new(&registry).context("init metrics")?);
    let metrics_addr: std::net::SocketAddr = args
        .metrics_addr
        .parse()
        .context("METRICS_ADDR must be a valid socket address")?;
    tokio::spawn(async move {
        if let Err(e) = serve_metrics(registry, metrics_addr).await {
            tracing::error!(error = %e, "metrics HTTP server exited");
        }
    });
    info!(%metrics_addr, "metrics endpoint listening");
    // Static dispatch: pick the store impl up-front. Avoids `Box<dyn>`
    // and the `async-trait` macro dependency. Both branches monomorphise
    // `run<T>` independently.
    if let Some(db_url) = args.database_url.clone() {
        info!(db_url = %db_url, "using SqliteIntentTracker (persistent)");
        let tracker = Arc::new(
            SqliteIntentTracker::connect(&db_url)
                .await
                .context("connect SqliteIntentTracker")?,
        );
        run(args, tracker, metrics).await
    } else {
        info!("using InMemoryIntentTracker (state lost on restart)");
        let tracker = Arc::new(InMemoryIntentTracker::new());
        run(args, tracker, metrics).await
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "single sequential pipeline; alloy 0.8 generic plumbing makes helper extraction painful"
)]
async fn run<T: IntentTrackerStore>(
    args: Args,
    tracker: Arc<T>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let intent_queue = Address::from_str(&args.intent_queue)
        .context("INTENT_QUEUE_ADDR must be a 20-byte hex address")?;

    let poster_address =
        Address::from_str(&args.poster_address).context("POSTER_ADDRESS invalid")?;
    if poster_address.is_zero() {
        anyhow::bail!("POSTER_ADDRESS must be non-zero");
    }

    // Parse the RPC URL list. Single URL is the common case; commas are
    // accepted to enable connect-time fallover (closes L-R3).
    let endpoints = WsEndpointList::from_csv(&args.rpc_url).context("parse ETH_RPC_URL list")?;
    let (used_url, provider) = endpoints
        .connect_first_working(|url| async move {
            let ws = WsConnect::new(&url);
            ProviderBuilder::new()
                .with_recommended_fillers()
                .on_ws(ws)
                .await
        })
        .await
        .map_err(|e| anyhow::anyhow!("connect WS provider: {e}"))?;
    let provider = Arc::new(provider);

    info!(
        rpc_endpoint = %xindex_chain_eth::rpc::redacted_endpoint(&used_url),
        endpoint_count = endpoints.len(),
        intent_queue = %intent_queue,
        scan_interval_secs = args.scan_interval_secs,
        "xindex-cancel starting"
    );

    // Backfill missed events before subscribing live. Inlined (rather
    // than extracted into a helper) to dodge alloy 0.8's deeply nested
    // FillProvider/PubSubFrontend generic type that fights `impl Provider`
    // bounds on standalone helpers.
    if args.from_block > 0 {
        let latest = provider
            .get_block_number()
            .await
            .context("get block number")?;
        info!(
            from_block = args.from_block,
            latest, "backfilling missed events"
        );
        let backfill_filter = Filter::new()
            .address(intent_queue)
            .event_signature(vec![
                IntentQueue::MintIntentCreated::SIGNATURE_HASH,
                IntentQueue::MintIntentFinalized::SIGNATURE_HASH,
                IntentQueue::MintIntentCancelled::SIGNATURE_HASH,
            ])
            .from_block(BlockNumberOrTag::Number(args.from_block))
            .to_block(BlockNumberOrTag::Number(latest));
        let logs = provider
            .get_logs(&backfill_filter)
            .await
            .context("backfill get_logs")?;
        info!(count = logs.len(), "backfill batch");

        for log in logs {
            let topic0 = log.topic0().copied().unwrap_or_default();
            if topic0 == IntentQueue::MintIntentCreated::SIGNATURE_HASH {
                if let Ok(decoded) = log.log_decode::<IntentQueue::MintIntentCreated>() {
                    let ev = decoded.inner.data;
                    if let Err(e) = tracker
                        .observe(
                            ev.intentId,
                            TrackedIntent {
                                deadline_unix_secs: ev.deadline,
                                index_token: ev.indexToken,
                            },
                        )
                        .await
                    {
                        warn!(intent_id = %ev.intentId, error = %e, "backfill observe failed");
                    }
                }
            } else if topic0 == IntentQueue::MintIntentFinalized::SIGNATURE_HASH {
                if let Ok(decoded) = log.log_decode::<IntentQueue::MintIntentFinalized>() {
                    if let Err(e) = tracker.mark_resolved(&decoded.inner.data.intentId).await {
                        warn!(error = %e, "backfill mark_resolved failed");
                    }
                }
            } else if topic0 == IntentQueue::MintIntentCancelled::SIGNATURE_HASH {
                if let Ok(decoded) = log.log_decode::<IntentQueue::MintIntentCancelled>() {
                    if let Err(e) = tracker.mark_resolved(&decoded.inner.data.intentId).await {
                        warn!(error = %e, "backfill mark_resolved failed");
                    }
                }
            }
        }
        let remaining = tracker.len().await.unwrap_or(0);
        info!(remaining, "backfill done");
    }

    // Subscribe to all three queue events at once. The filter combines
    // event signatures via the `event_signature` topic[0] match.
    let filter = Filter::new().address(intent_queue).event_signature(vec![
        IntentQueue::MintIntentCreated::SIGNATURE_HASH,
        IntentQueue::MintIntentFinalized::SIGNATURE_HASH,
        IntentQueue::MintIntentCancelled::SIGNATURE_HASH,
    ]);
    let sub = provider
        .subscribe_logs(&filter)
        .await
        .context("subscribe to queue events")?;
    let mut stream = sub.into_stream();

    let mut ticker = interval(Duration::from_secs(args.scan_interval_secs));
    // The first tick fires immediately — we don't want that on startup.
    ticker.tick().await;

    info!("subscribed; entering main loop");

    loop {
        tokio::select! {
            biased;

            log = stream.next() => {
                let Some(log) = log else {
                    warn!("event stream ended; exiting");
                    return Ok(());
                };
                let topic0 = log.topic0().copied().unwrap_or_default();
                if topic0 == IntentQueue::MintIntentCreated::SIGNATURE_HASH {
                    if let Ok(decoded) = log.log_decode::<IntentQueue::MintIntentCreated>() {
                        let ev = &decoded.inner.data;
                        let intent = TrackedIntent {
                            deadline_unix_secs: ev.deadline,
                            index_token: ev.indexToken,
                        };
                        if let Err(e) = tracker.observe(ev.intentId, intent).await {
                            warn!(intent_id = %ev.intentId, error = %e, "observe failed; will retry on re-emit");
                        } else {
                            metrics.relayer_intents_tracked.inc();
                            if let Ok(c) = tracker.len().await {
                                if let Ok(c64) = i64::try_from(c) {
                                    metrics.relayer_pending_intents.set(c64);
                                }
                            }
                            info!(
                                intent_id = %ev.intentId,
                                index_token = %ev.indexToken,
                                deadline = ev.deadline,
                                "tracking new intent"
                            );
                        }
                    }
                } else if topic0 == IntentQueue::MintIntentFinalized::SIGNATURE_HASH {
                    if let Ok(decoded) = log.log_decode::<IntentQueue::MintIntentFinalized>() {
                        let id = decoded.inner.data.intentId;
                        if let Err(e) = tracker.mark_resolved(&id).await {
                            warn!(intent_id = %id, error = %e, "mark_resolved failed");
                        } else {
                            metrics.relayer_intents_resolved
                                .with_label_values(&["finalized"]).inc();
                            if let Ok(c) = tracker.len().await {
                                if let Ok(c64) = i64::try_from(c) {
                                    metrics.relayer_pending_intents.set(c64);
                                }
                            }
                            info!(intent_id = %id, "finalized; dropped from tracker");
                        }
                    }
                } else if topic0 == IntentQueue::MintIntentCancelled::SIGNATURE_HASH {
                    if let Ok(decoded) = log.log_decode::<IntentQueue::MintIntentCancelled>() {
                        let id = decoded.inner.data.intentId;
                        if let Err(e) = tracker.mark_resolved(&id).await {
                            warn!(intent_id = %id, error = %e, "mark_resolved failed");
                        } else {
                            metrics.relayer_intents_resolved
                                .with_label_values(&["cancelled"]).inc();
                            if let Ok(c) = tracker.len().await {
                                if let Ok(c64) = i64::try_from(c) {
                                    metrics.relayer_pending_intents.set(c64);
                                }
                            }
                            info!(intent_id = %id, "cancelled; dropped from tracker");
                        }
                    }
                }
            }

            _ = ticker.tick() => {
                let Some(now_unix) = now_unix_secs() else {
                    warn!("system clock failure (pre-1970); skipping scan tick");
                    continue;
                };
                let decision = match tracker.scan(now_unix).await {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(error = %e, "scan failed; will retry next tick");
                        continue;
                    }
                };
                if decision.expired.is_empty() {
                    continue;
                }
                info!(now_unix, count = decision.expired.len(), "scan: expired intents");
                for (intent_id, intent) in decision.expired {
                    let token = IndexToken::new(intent.index_token, provider.clone());
                    match token.cancelMint(intent_id).from(poster_address).send().await {
                        Ok(pending) => match pending.get_receipt().await {
                            Ok(receipt) => {
                                metrics.relayer_cancel_attempts
                                    .with_label_values(&["confirmed"]).inc();
                                info!(
                                    intent_id = %intent_id,
                                    index_token = %intent.index_token,
                                    tx_hash = %receipt.transaction_hash,
                                    "cancelMint confirmed"
                                );
                            }
                            Err(e) => {
                                metrics.relayer_cancel_attempts
                                    .with_label_values(&["receipt_error"]).inc();
                                warn!(
                                    intent_id = %intent_id, error = %e,
                                    "cancelMint receipt failed; will retry next tick"
                                );
                            }
                        },
                        Err(e) => {
                            // Common revert reasons:
                            //   - AsyncIntentAlreadyResolved (raced by user / another keeper)
                            //   - FinalizableMustBeFinalized (H-A1 guard — finalize wins)
                            //   - IntentQueue_DeadlineNotPassed (clock skew between us + chain)
                            // Log + continue; don't kill the daemon.
                            let label = classify_cancel_error(&e.to_string());
                            metrics.relayer_cancel_attempts
                                .with_label_values(&[label]).inc();
                            warn!(
                                intent_id = %intent_id, error = %e,
                                "cancelMint send failed; logging and continuing"
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Categorize a `cancelMint` send-error string into a stable label set
/// for the Prometheus `xindex_relayer_cancel_attempts_total{result=...}`
/// counter. Label cardinality is bounded: any unrecognized error falls
/// into `revert_other`, so a noisy upstream change can't blow up
/// Prometheus storage.
fn classify_cancel_error(msg: &str) -> &'static str {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("alreadyresolved") || lower.contains("already_resolved") {
        "revert_already_resolved"
    } else if lower.contains("finalizablemustbefinalized") || lower.contains("must_be_finalized") {
        "revert_finalizable"
    } else if lower.contains("deadlinenotpassed") || lower.contains("deadline_not_passed") {
        "revert_deadline_not_passed"
    } else if lower.contains("revert") {
        "revert_other"
    } else {
        "send_error"
    }
}

/// Wall-clock unix seconds. Used for the deadline scan. We don't use
/// chain `block.timestamp` for scanning — local clock is fine since the
/// final on-chain `cancelMint` call is what enforces the deadline; we
/// only avoid wasting RPC calls on intents that obviously haven't
/// expired yet.
///
/// Returns `None` on clock failure (clock set before 1970). Caller MUST
/// skip the scan tick rather than substitute 0 — `scan(0)` would mark
/// every intent as expired and the keeper would spam reverting
/// `cancelMint` txs.
fn now_unix_secs() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn now_unix_secs_is_recent() {
        // Sanity: we got a positive value from the system clock.
        let n = now_unix_secs().expect("system clock should be set past 1970");
        assert!(n > 1_700_000_000, "unix clock should be past 2023-11-14");
    }
}
