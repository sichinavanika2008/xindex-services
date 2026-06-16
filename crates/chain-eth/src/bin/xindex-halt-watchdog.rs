//! `xindex-halt-watchdog` — per-operator `THORChain` liveness → on-chain halt.
//!
//! Closes the mint-side halt asymmetry. The burn/redeem dispatch path is
//! already fail-closed on a `THORChain` halt (the per-operator `RIC`
//! agreement gate refuses a halted Asgard vault, so no custody BTC is spent),
//! but the mint deposit is triggered ON-CHAIN by `acquire` and only gates on
//! vault *freshness* — there is no off-chain "refuse to mint into a halted
//! chain" lever. This daemon adds one.
//!
//! It polls the operator's OWN ≥2 distinct `THORChain` sources for the
//! per-chain halt/pause flags and, once a halt is observed on
//! `--halt-confirmations` consecutive polls, engages the on-chain
//! `CustodyGuard.halt()` containment — which fail-closes BOTH new mint
//! creation (`IntentQueue.createMintIntent` → `requireNotHalted`) and new
//! burn dispatch (`checkDispatch`) for 24h (quorum-reversible, auto-expiring).
//!
//! Each of the operators runs its own instance; any one engaging the halt is
//! sufficient (`CustodyGuard.halt()` is a single-operator power). It never
//! UN-halts — that is a deliberate quorum action via `voteUnhalt`.
//!
//! Trigger posture is fail-closed but bounded:
//! - the multi-source poll requires ≥2 sources to agree the chain is present
//!   before any verdict, so one hostile/flaky source can force a (bounded,
//!   reversible) pause but can never SUPPRESS a real halt;
//! - `Indeterminate` reads (transport failure / sub-quorum) never trigger — a
//!   total outage already fails closed via the on-chain vault-freshness gate
//!   and the dispatch `RIC` gate;
//! - `--halt-confirmations` consecutive clean HALTED reads debounce a
//!   transient blip;
//! - engaging is idempotent (re-reads `isHalted()` first) so a restart against
//!   an already-halted guard does not spam.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::Address;
use alloy::providers::{ProviderBuilder, WsConnect};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use clap::Parser;
use tokio::time::interval;
use tracing::{error, info, warn};
use xindex_chain_eth::bindings::CustodyGuard;
use xindex_chain_thor::{AsgardAgreement, HaltOutcome, ThorClient};

#[derive(Parser, Debug, Clone)]
#[command(
    version,
    about = "Xindex per-operator THORChain halt watchdog → CustodyGuard.halt()"
)]
struct Args {
    /// WebSocket RPC used to submit the `halt()` tx. Anvil: <ws://127.0.0.1:8545>.
    #[arg(long, env = "ETH_RPC_URL", default_value = "ws://127.0.0.1:8545")]
    eth_rpc_url: String,

    /// Deployed `CustodyGuard` address (the `IntentQueue`'s wired guard).
    #[arg(long, env = "CUSTODY_GUARD_ADDR")]
    custody_guard: String,

    /// This operator's roster EOA key — MUST be one of `CustodyGuard`'s
    /// operators, else every `halt()` submission reverts `OnlyOperator`.
    #[arg(long, env = "OPERATOR_KEY")]
    operator_key: String,

    /// Comma-separated `THORNode` REST base URLs — the operator's OWN ≥2
    /// DISTINCT sources (diverse-source halt signal; a single source is
    /// refused at startup, mirroring the RIC observer floor).
    #[arg(long, env = "THORNODE_URLS")]
    thornode_urls: String,

    /// `THORChain` chain symbol to watch (Phase 2.A: BTC).
    #[arg(long, env = "HALT_WATCH_CHAIN", default_value = "BTC")]
    chain: String,

    /// Seconds between halt polls.
    #[arg(long, env = "POLL_INTERVAL_SECS", default_value_t = 30)]
    poll_interval_secs: u64,

    /// Consecutive clean HALTED polls required before engaging `halt()`
    /// (debounce; filters a single transient blip).
    #[arg(long, env = "HALT_CONFIRMATIONS", default_value_t = 2)]
    halt_confirmations: u32,

    /// Observe + log only; never submit `halt()`. For rehearsal / staging.
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    run(Args::parse()).await
}

/// Split a comma-separated list, trimming whitespace and dropping empties.
fn parse_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(String::from)
        .collect()
}

async fn run(args: Args) -> Result<()> {
    let urls = parse_csv(&args.thornode_urls);
    let mut clients = Vec::with_capacity(urls.len());
    for url in &urls {
        clients.push(
            ThorClient::with_base_url(url.clone())
                .with_context(|| format!("build THORNode client for {url}"))?,
        );
    }
    // Refuses < MIN_AGREEING_SOURCES — a single-source watchdog is as
    // poisonable as a single-source RIC.
    let agreement = AsgardAgreement::new(clients)
        .context("build AsgardAgreement (need ≥2 distinct THORNODE_URLS)")?;

    let operator: PrivateKeySigner = args.operator_key.parse().context("invalid OPERATOR_KEY")?;
    let operator_addr = operator.address();
    let guard_addr =
        Address::from_str(&args.custody_guard).context("CUSTODY_GUARD_ADDR invalid")?;

    let ws = WsConnect::new(&args.eth_rpc_url);
    let provider = Arc::new(
        ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(EthereumWallet::new(operator))
            .on_ws(ws)
            .await
            .context("connect WS provider")?,
    );
    let guard = CustodyGuard::new(guard_addr, provider.clone());

    info!(
        operator = %operator_addr,
        custody_guard = %guard_addr,
        chain = %args.chain,
        sources = urls.len(),
        poll_interval_secs = args.poll_interval_secs,
        halt_confirmations = args.halt_confirmations,
        dry_run = args.dry_run,
        "xindex-halt-watchdog starting"
    );

    let mut consecutive_halted: u32 = 0;
    let mut halt_engaged = false;
    let mut ticker = interval(Duration::from_secs(args.poll_interval_secs));
    loop {
        ticker.tick().await;
        match agreement.poll_chain_halt(&args.chain).await {
            HaltOutcome::Live => {
                if halt_engaged || consecutive_halted > 0 {
                    info!(chain = %args.chain, "THORChain reports live again; resetting halt counter");
                }
                consecutive_halted = 0;
                halt_engaged = false;
            }
            HaltOutcome::Indeterminate { reason } => {
                // Not a trigger: a total outage already fails closed elsewhere.
                warn!(chain = %args.chain, %reason,
                      "halt read indeterminate; NOT counting toward halt (other gates stay fail-closed)");
                consecutive_halted = 0;
            }
            HaltOutcome::Halted { source_idx } => {
                consecutive_halted = consecutive_halted.saturating_add(1);
                warn!(chain = %args.chain, source_idx, consecutive_halted,
                      threshold = args.halt_confirmations, "THORChain reports HALTED");
                if consecutive_halted < args.halt_confirmations || halt_engaged {
                    continue;
                }
                // Sustained halt — engage on-chain containment. Idempotent:
                // re-read isHalted() so a restart against an already-halted
                // guard latches without re-submitting.
                match guard.isHalted().call().await {
                    Ok(r) if r._0 => {
                        info!("CustodyGuard already halted on-chain; nothing to do");
                        halt_engaged = true;
                    }
                    Ok(_) if args.dry_run => {
                        warn!("DRY RUN: would call CustodyGuard.halt() now (sustained THORChain halt)");
                        halt_engaged = true;
                    }
                    Ok(_) => {
                        info!("engaging CustodyGuard.halt() (sustained THORChain halt)");
                        match guard.halt().send().await {
                            Ok(p) => match p.get_receipt().await {
                                Ok(r) => {
                                    info!(tx = %r.transaction_hash, "CustodyGuard.halt() mined");
                                    halt_engaged = true;
                                }
                                Err(e) => error!(error = %e,
                                    "halt() sent but receipt failed; verify on-chain, retry next poll"),
                            },
                            Err(e) => error!(error = %e,
                                "halt() submission failed (operator not in roster? re-halt cooldown? already halted?); retry next poll"),
                        }
                    }
                    Err(e) => error!(error = %e, "isHalted() read failed; retry next poll"),
                }
            }
        }
    }
}
