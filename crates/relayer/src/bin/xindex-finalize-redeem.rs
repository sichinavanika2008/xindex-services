//! `xindex-finalize-redeem` — burn → USDT redemption relayer.
//!
//! Watches a deployed `IntentQueue` for the redemption lifecycle and
//! nudges the chain to its terminal state:
//!
//! - `RedemptionAttested` (delivery) → `IndexToken.finalizeBurn`
//! - `RedemptionRefundAttested`      → `IndexToken.cancelBurn`
//! - `RedemptionIntent{Finalized,Cancelled}` → drop from tracker
//!
//! Both contract calls are PERMISSIONLESS and authorized purely by the
//! on-chain attestation state (verify-the-refund: cancel needs a refund
//! attestation, NOT a deadline). We never decide anything; we only
//! relay. A re-attempt reverts cleanly (already-resolved /
//! mutually-excluded) — logged and skipped.
//!
//! ## SD-B stuck detection (alert only)
//!
//! A redemption past its deadline with NEITHER attestation (`THORChain`
//! vault halted / orphaned inbound) is genuinely stuck. We surface it
//! via the `xindex_redeem_relayer_stuck` gauge + a `warn!` for the
//! operator runbook. There is deliberately NO on-chain auto-action — no
//! admin/timelock backdoor (SD-B).
//!
//! ## swapHints (F1 — config-static)
//!
//! `finalizeBurn(redemptionId, swapHints)` needs one `bytes` per basket
//! slot. We read `IndexToken.isAsync()` and place the operator-supplied
//! `--erc20-swap-hint-hex` for each ERC20 slot (empty for the async
//! slot). Static, deterministic; the binding end-to-end `minUsdtOut`
//! re-checked on-chain is the slippage protection (matches the Solidity
//! audit-slippage stance). Empty default works with mock adapters /
//! Anvil. Multi-basket (per-indexToken hint map) is a v2 follow-up.

use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, Bytes};
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
    InMemoryRedemptionTracker, RedemptionTrackerStore, SqliteRedemptionTracker, TrackedRedemption,
};

#[derive(Parser, Debug)]
#[command(version, about = "Xindex burn→USDT redemption relayer")]
struct Args {
    #[arg(long, env = "ETH_RPC_URL", default_value = "ws://127.0.0.1:8545")]
    rpc_url: String,

    #[arg(long, env = "INTENT_QUEUE_ADDR")]
    intent_queue: String,

    /// Gas-paying address for permissionless finalize calls. The connected RPC
    /// delegates signing to a node-managed external signer; this process never
    /// accepts raw private key material.
    #[arg(long, env = "POSTER_ADDRESS")]
    poster_address: String,

    #[arg(long, env = "SCAN_INTERVAL_SECS", default_value_t = 60)]
    scan_interval_secs: u64,

    #[arg(long, env = "FROM_BLOCK", default_value_t = 0)]
    from_block: u64,

    /// Persistent tracker URL. Unset = in-memory (lost on restart;
    /// recover via `--from-block`). Production:
    /// `sqlite:./xindex-redeem-relayer.db?mode=rwc`.
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,

    /// F1 config-static V4 swap hint applied to every ERC20 slot, hex
    /// (`0x`-optional) of one ABI-encoded `V4SwapHints`. Empty (default)
    /// = mock-adapter / Anvil. The async (BTC) slot always gets empty.
    #[arg(long, env = "ERC20_SWAP_HINT_HEX", default_value = "")]
    erc20_swap_hint_hex: String,

    #[arg(long, env = "METRICS_ADDR", default_value = "0.0.0.0:9092")]
    metrics_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

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

    if let Some(db_url) = args.database_url.clone() {
        info!(db_url = %db_url, "using SqliteRedemptionTracker (persistent)");
        let t = Arc::new(
            SqliteRedemptionTracker::connect(&db_url)
                .await
                .context("connect SqliteRedemptionTracker")?,
        );
        run(args, t, metrics).await
    } else {
        info!("using InMemoryRedemptionTracker (state lost on restart)");
        run(args, Arc::new(InMemoryRedemptionTracker::new()), metrics).await
    }
}

/// Parse the F1 hex hint once. Empty string ⇒ empty `Bytes` (mock /
/// Anvil). Invalid hex is a hard startup failure — a malformed hint
/// would make every `finalizeBurn` revert.
fn parse_hint(hex: &str) -> Result<Bytes> {
    let s = hex.trim();
    if s.is_empty() {
        return Ok(Bytes::new());
    }
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    Ok(Bytes::from(
        alloy_primitives::hex::decode(stripped).context("ERC20_SWAP_HINT_HEX not valid hex")?,
    ))
}

#[expect(
    clippy::too_many_lines,
    reason = "single sequential pipeline; alloy 0.8 generic plumbing makes helper extraction painful"
)]
async fn run<T: RedemptionTrackerStore>(
    args: Args,
    tracker: Arc<T>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let intent_queue =
        Address::from_str(&args.intent_queue).context("INTENT_QUEUE_ADDR invalid")?;
    let erc20_hint = parse_hint(&args.erc20_swap_hint_hex)?;

    let poster_address =
        Address::from_str(&args.poster_address).context("POSTER_ADDRESS invalid")?;
    if poster_address.is_zero() {
        anyhow::bail!("POSTER_ADDRESS must be non-zero");
    }
    let endpoints = WsEndpointList::from_csv(&args.rpc_url).context("parse ETH_RPC_URL list")?;
    let (used_url, provider) = endpoints
        .connect_first_working(|url| async move {
            ProviderBuilder::new()
                .with_recommended_fillers()
                .on_ws(WsConnect::new(&url))
                .await
        })
        .await
        .map_err(|e| anyhow::anyhow!("connect WS provider: {e}"))?;
    let provider = Arc::new(provider);
    info!(
        rpc_endpoint = %xindex_chain_eth::rpc::redacted_endpoint(&used_url),
        intent_queue = %intent_queue,
        "xindex-finalize-redeem starting"
    );

    let created = IntentQueue::RedemptionIntentCreated::SIGNATURE_HASH;
    let attested = IntentQueue::LegAttested::SIGNATURE_HASH;
    let refunded = IntentQueue::LegRefunded::SIGNATURE_HASH;
    // Phase 3.0: unified terminal — `RedemptionIntentFinalized` is now
    // emitted whether the redemption resolved all-delivered, all-refunded,
    // or mixed. There is no separate `RedemptionIntentCancelled` event.
    let finalized = IntentQueue::RedemptionIntentFinalized::SIGNATURE_HASH;
    let sigs = vec![created, attested, refunded, finalized];

    // One reusable closure handles a decoded log. Errors LOGGED, never
    // propagated. Used by backfill + the live loop.
    let handle = async |log: alloy::rpc::types::Log| {
        let topic0 = log.topic0().copied().unwrap_or_default();
        if topic0 == created {
            if let Ok(d) = log.log_decode::<IntentQueue::RedemptionIntentCreated>() {
                let ev = &d.inner.data;
                let tr = TrackedRedemption {
                    deadline_unix_secs: ev.deadline,
                    index_token: ev.indexToken,
                };
                if let Err(e) = tracker.observe(ev.redemptionId, tr).await {
                    warn!(redemption_id = %ev.redemptionId, error = %e, "observe failed");
                } else {
                    metrics.redeem_relayer_tracked.inc();
                    if let Ok(c) = tracker.len().await {
                        if let Ok(c64) = i64::try_from(c) {
                            metrics.redeem_relayer_pending.set(c64);
                        }
                    }
                    info!(redemption_id = %ev.redemptionId, index_token = %ev.indexToken,
                          deadline = ev.deadline, "tracking redemption");
                }
            }
        } else if topic0 == attested {
            if let Ok(d) = log.log_decode::<IntentQueue::LegAttested>() {
                let rid = d.inner.data.redemptionId;
                let Ok(Some(tr)) = tracker.get(&rid).await else {
                    warn!(redemption_id = %rid,
                          "delivery-attested but redemption not tracked (missed Created?); \
                           skipping — backfill with --from-block to recover");
                    return;
                };
                // F1 swapHints inline (alloy 0.8 generic-helper pain —
                // mirrors why the other binaries inline everything):
                // ERC20 slots get the configured hint, async slot empty.
                let token = IndexToken::new(tr.index_token, provider.clone());
                let hints: Vec<Bytes> = match token.isAsync().call().await {
                    Ok(r) => {
                        r._0.into_iter()
                            .map(|a| if a { Bytes::new() } else { erc20_hint.clone() })
                            .collect()
                    }
                    Err(e) => {
                        warn!(redemption_id = %rid, error = %e,
                              "isAsync() failed; will retry on next event/backfill");
                        return;
                    }
                };
                match token
                    .finalizeBurn(rid, hints)
                    .from(poster_address)
                    .send()
                    .await
                {
                    Ok(p) => match p.get_receipt().await {
                        Ok(r) => {
                            metrics
                                .redeem_relayer_finalize_attempts
                                .with_label_values(&["confirmed"])
                                .inc();
                            info!(redemption_id = %rid, tx = %r.transaction_hash,
                                  "finalizeBurn confirmed");
                        }
                        Err(e) => {
                            metrics
                                .redeem_relayer_finalize_attempts
                                .with_label_values(&["send_error"])
                                .inc();
                            warn!(redemption_id = %rid, error = %e,
                                  "finalizeBurn receipt failed; retry next event");
                        }
                    },
                    Err(e) => {
                        let lbl = if e.to_string().to_ascii_lowercase().contains("revert") {
                            "revert"
                        } else {
                            "send_error"
                        };
                        metrics
                            .redeem_relayer_finalize_attempts
                            .with_label_values(&[lbl])
                            .inc();
                        warn!(redemption_id = %rid, error = %e,
                              "finalizeBurn send failed (already resolved / slippage / paused)");
                    }
                }
            }
        } else if topic0 == refunded {
            // Phase 3.0: refund-attestation no longer triggers a
            // separate `cancelBurn` — it's one of N legs (single-leg
            // for THORChain rail today). The unified `finalizeBurn`
            // resolves the whole redemption once every leg is attested
            // XOR refunded. For single-leg baskets the refunded event
            // means the redemption is now fully-resolved and we can
            // attempt finalize directly. (Multi-leg baskets — Phase
            // 3.1 — would gate this on
            // `queue.isRedemptionFullyResolved(rid)`.)
            if let Ok(d) = log.log_decode::<IntentQueue::LegRefunded>() {
                let rid = d.inner.data.redemptionId;
                let Ok(Some(tr)) = tracker.get(&rid).await else {
                    warn!(redemption_id = %rid,
                          "refund-attested but redemption not tracked; skipping (backfill)");
                    return;
                };
                let token = IndexToken::new(tr.index_token, provider.clone());
                let hints: Vec<Bytes> = match token.isAsync().call().await {
                    Ok(r) => {
                        r._0.into_iter()
                            .map(|a| if a { Bytes::new() } else { erc20_hint.clone() })
                            .collect()
                    }
                    Err(e) => {
                        warn!(redemption_id = %rid, error = %e,
                              "isAsync() failed; will retry on next event/backfill");
                        return;
                    }
                };
                match token
                    .finalizeBurn(rid, hints)
                    .from(poster_address)
                    .send()
                    .await
                {
                    Ok(p) => match p.get_receipt().await {
                        Ok(r) => {
                            metrics
                                .redeem_relayer_cancel_attempts
                                .with_label_values(&["confirmed"])
                                .inc();
                            info!(redemption_id = %rid, tx = %r.transaction_hash,
                                  "finalizeBurn (refund-only) confirmed");
                        }
                        Err(e) => {
                            metrics
                                .redeem_relayer_cancel_attempts
                                .with_label_values(&["send_error"])
                                .inc();
                            warn!(redemption_id = %rid, error = %e,
                                  "finalizeBurn (refund-only) receipt failed; retry next event");
                        }
                    },
                    Err(e) => {
                        let lbl = if e.to_string().to_ascii_lowercase().contains("revert") {
                            "revert"
                        } else {
                            "send_error"
                        };
                        metrics
                            .redeem_relayer_cancel_attempts
                            .with_label_values(&[lbl])
                            .inc();
                        warn!(redemption_id = %rid, error = %e,
                              "finalizeBurn (refund-only) send failed \
                               (already resolved / not fully resolved / paused)");
                    }
                }
            }
        } else if topic0 == finalized {
            if let Ok(d) = log.log_decode::<IntentQueue::RedemptionIntentFinalized>() {
                let rid = d.inner.data.redemptionId;
                if tracker.mark_resolved(&rid).await.is_ok() {
                    metrics
                        .redeem_relayer_resolved
                        .with_label_values(&["finalized"])
                        .inc();
                    if let Ok(c) = tracker.len().await {
                        if let Ok(c64) = i64::try_from(c) {
                            metrics.redeem_relayer_pending.set(c64);
                        }
                    }
                    info!(redemption_id = %rid, "finalized; dropped from tracker");
                }
            }
        }
    };

    if args.from_block > 0 {
        let latest = provider.get_block_number().await.context("block number")?;
        let f = Filter::new()
            .address(intent_queue)
            .event_signature(sigs.clone())
            .from_block(BlockNumberOrTag::Number(args.from_block))
            .to_block(BlockNumberOrTag::Number(latest));
        let logs = provider.get_logs(&f).await.context("backfill get_logs")?;
        info!(count = logs.len(), "backfilling redemption events");
        for log in logs {
            handle(log).await;
        }
    }

    let filter = Filter::new().address(intent_queue).event_signature(sigs);
    let sub = provider
        .subscribe_logs(&filter)
        .await
        .context("subscribe")?;
    let mut stream = sub.into_stream();
    let mut ticker = interval(Duration::from_secs(args.scan_interval_secs));
    ticker.tick().await; // skip the immediate first tick
    info!("subscribed; entering main loop");

    loop {
        tokio::select! {
            biased;
            log = stream.next() => {
                let Some(log) = log else { warn!("event stream ended; exiting"); return Ok(()); };
                handle(log).await;
            }
            _ = ticker.tick() => {
                let Some(now) = now_unix_secs() else {
                    warn!("system clock failure (pre-1970); skipping stuck scan");
                    continue;
                };
                match tracker.scan(now).await {
                    Ok(d) => {
                        let n = i64::try_from(d.stuck.len()).unwrap_or(i64::MAX);
                        metrics.redeem_relayer_stuck.set(n);
                        if !d.stuck.is_empty() {
                            // SD-B: alert only, NO on-chain auto-action.
                            for (rid, tr) in &d.stuck {
                                warn!(
                                    redemption_id = %rid,
                                    index_token = %tr.index_token,
                                    deadline = tr.deadline_unix_secs,
                                    "SD-B STUCK redemption (no delivery/refund attestation past \
                                     deadline) — operator runbook: investigate THORChain status \
                                     for this btc inbound; resolve via multi-party reconciliation. \
                                     NO automated action is taken."
                                );
                            }
                        }
                    }
                    Err(e) => warn!(error = %e, "stuck scan failed; retry next tick"),
                }
            }
        }
    }
}

/// Wall-clock unix seconds; `None` on a pre-1970 clock (caller skips the
/// scan rather than treating everything as stuck).
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
    fn parse_hint_empty_is_empty_bytes() {
        assert!(parse_hint("").expect("ok").is_empty());
        assert!(parse_hint("  ").expect("ok").is_empty());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn parse_hint_decodes_hex_with_or_without_0x() {
        assert_eq!(parse_hint("0xabcd").expect("ok").to_vec(), vec![0xab, 0xcd]);
        assert_eq!(parse_hint("abcd").expect("ok").to_vec(), vec![0xab, 0xcd]);
    }

    #[test]
    fn parse_hint_rejects_bad_hex() {
        assert!(parse_hint("0xzz").is_err());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn now_unix_secs_is_recent() {
        assert!(now_unix_secs().expect("clock") > 1_700_000_000);
    }
}
