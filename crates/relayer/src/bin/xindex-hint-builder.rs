//! `xindex-hint-builder` — reference off-chain `THORChain` streaming-swap
//! hint-builder (plan Part A2).
//!
//! Pulls live pool depth from a `THORNode` (`/thorchain/pools`), estimates
//! the slip for a given swap size against the target pool, and prints the
//! `(interval, quantity)` stream shape the on-chain `ThorchainAdapter`
//! consumes — bounded by `MAX_STREAM_BLOCKS` and the intent deadline
//! (mandatory deadline-margin gate). Output is one JSON object on stdout
//! so it composes into a frontend / keeper pipeline.
//!
//! ## Trust posture
//!
//! The on-chain memo only trusts the chosen `(interval, quantity)` within
//! the duration bound; a hostile/buggy split cannot lose funds (the LIM
//! and the prorated floor still bind on-chain — worst case is a
//! slower/under-saved swap). This binary is advisory.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::{info, warn};
use xindex_chain_thor::ThorClient;
use xindex_ops::init_tracing;
use xindex_relayer::{plan_stream, slip_bps, HintParams, StreamPlan};

#[derive(Parser, Debug)]
#[command(
    version,
    about = "THORChain streaming-swap hint-builder (interval, quantity)"
)]
struct Args {
    /// `THORNode` base URL.
    #[arg(
        long,
        env = "THOR_NODE_URL",
        default_value = "https://thornode.thorchain.network"
    )]
    thor_node_url: String,

    /// `THORChain` pool asset whose depth gates the swap (e.g. `BTC.BTC`).
    #[arg(long, default_value = "BTC.BTC")]
    asset: String,

    /// Swap size in the pool asset's 1e8 fixed-point units.
    #[arg(long)]
    swap_size: u128,

    /// Intent deadline (unix seconds). The stream must finish inside it.
    #[arg(long)]
    deadline_unix: u64,

    /// "Now" (unix seconds). Defaults to the system clock.
    #[arg(long)]
    now_unix: Option<u64>,

    /// Don't stream below this estimated slip (bps).
    #[arg(long, default_value_t = 10)]
    min_slip_bps: u64,

    /// Target slip per sub-swap (bps) — controls split aggressiveness.
    #[arg(long, default_value_t = 5)]
    target_subswap_slip_bps: u64,

    /// Blocks between sub-swaps (`0` = rapid).
    #[arg(long, default_value_t = 1)]
    interval_blocks: u64,

    /// Seconds reserved before the deadline for confirmation + attestation.
    #[arg(long, default_value_t = 20 * 60)]
    deadline_margin_secs: u64,
}

/// Find the target pool and parse its asset-side depth (1e8). `Available`
/// pools only — a `Staged`/`Suspended` pool has no usable liquidity.
async fn pool_depth(thor: &ThorClient, asset: &str) -> Result<u128> {
    let pools = thor.pools().await.context("fetch THORChain pools")?;
    let pool = pools
        .iter()
        .find(|p| p.asset.eq_ignore_ascii_case(asset))
        .ok_or_else(|| anyhow!("no pool for asset '{asset}'"))?;
    if pool.status != "Available" {
        warn!(asset, status = %pool.status, "pool not Available — streaming disabled");
        return Ok(0);
    }
    pool.balance_asset
        .parse::<u128>()
        .with_context(|| format!("non-integer balance_asset '{}'", pool.balance_asset))
}

#[tokio::main]
#[expect(
    clippy::print_stdout,
    reason = "CLI tool: the computed hint JSON on stdout is this binary's interface"
)]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    let now = match args.now_unix {
        Some(n) => n,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before unix epoch")?
            .as_secs(),
    };

    let thor = ThorClient::with_base_url(&args.thor_node_url).context("build THORChain client")?;
    let depth = pool_depth(&thor, &args.asset).await?;

    let params = HintParams {
        min_slip_bps: args.min_slip_bps,
        target_subswap_slip_bps: args.target_subswap_slip_bps,
        interval_blocks: args.interval_blocks,
        deadline_margin_secs: args.deadline_margin_secs,
    };
    let plan: StreamPlan = plan_stream(args.swap_size, depth, now, args.deadline_unix, &params);
    let slip = slip_bps(args.swap_size, depth);

    info!(
        asset = %args.asset,
        depth,
        slip_bps = slip,
        interval = plan.interval,
        quantity = plan.quantity,
        streaming = plan.is_streaming(),
        "hint computed"
    );

    let out = serde_json::json!({
        "asset": args.asset,
        "pool_depth_1e8": depth.to_string(),
        "swap_size_1e8": args.swap_size.to_string(),
        "slip_bps": slip,
        "interval": plan.interval,
        "quantity": plan.quantity,
        "streaming": plan.is_streaming(),
        "duration_secs": plan.duration_secs(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).context("serialize hint")?
    );
    Ok(())
}
