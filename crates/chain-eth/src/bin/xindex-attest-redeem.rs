//! `xindex-attest-redeem` — burn → USDT redemption attestation poster.
//!
//! Watches a deployed `IntentQueue` for `RedemptionIntentCreated`, looks
//! up the BTC→Asgard inbound the executor broadcast (F2 store), runs the
//! `THORChain` cross-check, and posts EXACTLY ONE terminal attestation:
//!
//! - delivery confirmed → `AttestationOracle.attestRedemption`
//!   (`RedemptionAttestation` typehash)
//! - `THORChain` slip-refunded → `AttestationOracle.attestRefund`
//!   (`RefundAttestation` typehash)
//!
//! Delivery and refund are mutually exclusive, mirroring the on-chain
//! queue — the cross-check disambiguates ONLY by `THORChain`'s
//! `REFUND:<txid>` memo, never by time. Separate binary from
//! `xindex-attest` (defense-in-depth: mint vs redemption signing paths
//! isolated, like the on-chain separate typehashes).
//!
//! Trust note: holds N keys in one process for local testing only.
//! Production (M5) splits each key into its own HSM-backed daemon.

use std::str::FromStr;
use std::sync::Arc;

use alloy::eips::BlockNumberOrTag;
use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use bitcoin::Network;
use clap::{Parser, ValueEnum};
use futures_util::StreamExt;
use tracing::{error, info, warn};
use xindex_chain_eth::bindings::{AttestationOracle, IntentQueue};
use xindex_chain_eth::RpcErc20LogClient;
use xindex_chain_thor::ThorClient;
use xindex_chain_utxo::EsploraClient;
use xindex_shared::eip712::{
    attestation_oracle_domain, redemption_attestation, refund_attestation, streamed_settlement,
};
use xindex_shared::redemption_dispatch::{AnyRedemptionDispatch, RedemptionDispatchStore};
use xindex_signer::crosscheck::{
    PassThroughRedemption, PassThroughRefund, RedemptionCrossCheck, RedemptionCrossCheckError,
    RefundCrossCheck, StreamedOutcome, StreamedSettlementCrossCheck, ThorUtxoRefundPolicy,
    ThorUtxoStreamedSettlementPolicy, ThorUtxoToUsdtPolicy,
};
use xindex_signer::remote::{AnyHsmBackend, RemoteHsmBackend};
use xindex_signer::{
    aggregate_redemption_signatures, aggregate_refund_signatures,
    aggregate_streamed_settlement_signatures, SoftwareSigner,
};

/// Signer-key backend selection — mirrors `xindex-attest`. `software`
/// is dev/Anvil; `remote` posts typed signing requests to N signer-
/// daemons (PART 5 / DL-M5-1) and pins each daemon's disclosed address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SignerMode {
    Software,
    Remote,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CrossCheckMode {
    /// Anvil only — always succeeds with configured amounts.
    PassThrough,
    /// Production — `THORChain` + on-chain USDT / BTC confirmation.
    ThorBtcUsdt,
}

#[derive(Parser, Debug, Clone)]
#[command(version, about = "Xindex redemption attestation poster")]
struct Args {
    /// WebSocket RPC (events + tx submission). Anvil: <ws://127.0.0.1:8545>.
    #[arg(long, env = "ETH_RPC_URL", default_value = "ws://127.0.0.1:8545")]
    rpc_url: String,

    /// HTTP RPC for the (blocking) ERC20-arrival log scan. Required for
    /// `thor-btc-usdt` mode.
    #[arg(long, env = "ETH_HTTP_RPC_URL")]
    eth_http_rpc_url: Option<String>,

    #[arg(long, env = "INTENT_QUEUE_ADDR")]
    intent_queue: String,

    #[arg(long, env = "ATTESTATION_ORACLE_ADDR")]
    attestation_oracle: String,

    /// Signer-key backend. Mainnet MUST be `remote`. See `xindex-attest`
    /// `--signer-mode` for the full doc.
    #[arg(long, env = "SIGNER_MODE", value_enum, default_value_t = SignerMode::Software)]
    signer_mode: SignerMode,

    /// (software mode) Comma-separated hex signer keys; first
    /// `threshold` are used. DEV / TEST ONLY.
    #[arg(long, env = "SIGNER_KEYS")]
    signer_keys: Option<String>,

    /// (remote mode) Comma-separated base URLs of the signer daemons.
    #[arg(long, env = "SIGNER_DAEMON_URLS")]
    signer_daemon_urls: Option<String>,

    /// (remote mode) Comma-separated daemon Ethereum addresses pinned
    /// per `(url, address)` pair (`key-ceremony.md` Set B disclosure).
    #[arg(long, env = "SIGNER_DAEMON_ADDRESSES")]
    signer_daemon_addresses: Option<String>,

    #[arg(long, env = "THRESHOLD")]
    threshold: usize,

    /// EOA that submits + pays gas for the attest tx.
    #[arg(long, env = "POSTER_KEY")]
    poster_key: String,

    #[arg(long, env = "FROM_BLOCK", default_value_t = 0)]
    from_block: u64,

    /// Persistent F2 store URL (`sqlite:./xindex-redemption-dispatch.db`).
    /// MUST be the SAME store the executor writes, else the signer can't
    /// correlate the redemption's BTC inbound. Unset = in-memory (dev).
    #[arg(long, env = "REDEMPTION_DATABASE_URL")]
    redemption_database_url: Option<String>,

    #[arg(long, env = "CROSS_CHECK_MODE", value_enum, default_value_t = CrossCheckMode::PassThrough)]
    cross_check_mode: CrossCheckMode,

    /// USDT ERC20 address (the redemption-exit token). Required for
    /// `thor-btc-usdt`.
    #[arg(long, env = "USDT_ADDRESS")]
    usdt_address: Option<String>,

    #[arg(long, env = "THOR_URL")]
    thor_url: Option<String>,

    #[arg(long, env = "ESPLORA_URL")]
    esplora_url: Option<String>,

    #[arg(long, env = "BTC_NETWORK")]
    btc_network: Option<String>,

    /// Our 3-of-5 P2WSH multisig (the refund destination).
    #[arg(long, env = "BTC_MULTISIG_ADDRESS")]
    btc_multisig_address: Option<String>,

    /// Min ETH confirmations for the USDT arrival. Default 12 (the ETH
    /// `conf_depth`); a lower override is rejected at startup (audit M9/I12).
    #[arg(long, env = "ETH_MIN_CONFIRMATIONS", default_value_t = 12)]
    eth_min_confirmations: u32,

    /// Min BTC confirmations for a refund UTXO. Default 6 (the BTC
    /// `conf_depth`); a lower override is rejected at startup, and each leg is
    /// additionally checked against its own chain's `conf_depth` (audit M9).
    #[arg(long, env = "BTC_MIN_CONFIRMATIONS", default_value_t = 6)]
    btc_min_confirmations: u32,

    /// USDT tolerance (1e6 units) between THORChain-scaled and on-chain.
    #[arg(long, env = "USDT_TOLERANCE_1E6", default_value_t = 0)]
    usdt_tolerance_1e6: u128,

    /// BTC refund tolerance (sats).
    #[arg(long, env = "BTC_TOLERANCE_SATS", default_value_t = 0)]
    btc_tolerance_sats: u64,

    /// `eth_getLogs` look-back window for the USDT arrival scan.
    #[arg(long, env = "ETH_LOOKBACK_BLOCKS", default_value_t = 7200)]
    eth_lookback_blocks: u64,

    /// Pass-through delivered USDT (1e6) — Anvil mode only.
    #[arg(long, env = "PASS_USDT_1E6", default_value_t = 0)]
    pass_usdt_1e6: u128,

    /// Pass-through refunded BTC (sats) — Anvil mode only.
    #[arg(long, env = "PASS_BTC_SATS", default_value_t = 0)]
    pass_btc_sats: u64,
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

fn parse_btc_network(s: &str) -> Result<Network> {
    match s {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "signet" => Ok(Network::Signet),
        "testnet" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        other => anyhow::bail!("unknown btc_network: {other}"),
    }
}

/// M9 hard floor: refuse to start the production (`thor-btc-usdt`) cross-check
/// with a confirmation threshold below the chain's `conf_depth`. An operator
/// can RAISE a threshold (more conservative) but never lower it below the
/// reorg-safety bar — `ChainId::Eth.conf_depth()` (12) for the USDT arrival,
/// `ChainId::Btc.conf_depth()` (6) for the refund UTXO. Below the floor, a
/// reorg could revert an "observed" delivery/refund AFTER the attestation
/// signs, double-paying the redemption.
fn enforce_confirmation_floors(eth_min: u32, btc_min: u32) -> Result<()> {
    use xindex_shared::chain_registry::ChainId;
    let eth_floor = ChainId::Eth.conf_depth();
    if eth_min < eth_floor {
        anyhow::bail!(
            "--eth-min-confirmations {eth_min} is below the ETH conf_depth floor \
             {eth_floor} (audit M9: refuse under-confirmation)"
        );
    }
    let btc_floor = ChainId::Btc.conf_depth();
    if btc_min < btc_floor {
        anyhow::bail!(
            "--btc-min-confirmations {btc_min} is below the BTC conf_depth floor \
             {btc_floor} (audit M9: refuse under-confirmation)"
        );
    }
    Ok(())
}

/// M9 per-leg depth: the configured UTXO confirmation threshold must meet the
/// LEG chain's `conf_depth` (BTC 6, LTC 12, DOGE 40, ZEC 10). For a BTC leg
/// with the default config this always holds; it fail-closes a leg whose chain
/// requires deeper confirmation than the binary is configured for (a
/// misconfiguration, or a premature non-BTC leg before the per-chain rollout).
fn leg_depth_satisfied(configured: u32, leg: xindex_shared::chain_registry::ChainId) -> bool {
    configured >= leg.conf_depth()
}

/// The streaming-swap finality gate's pair: the combined streamed-settlement
/// cross-check + a `THORChain` client used to poll `tx/status` for stream
/// finalisation (`STREAM-B2-COORD`). `None` in pass-through (Anvil) mode —
/// streaming swaps are a production `THORChain` feature.
type StreamedGate = (Arc<dyn StreamedSettlementCrossCheck>, ThorClient);

/// The coordinator's three cross-check policies: delivery + refund (the XOR
/// terminal paths) + the optional streaming finality gate.
type CrossChecks = (
    Arc<dyn RedemptionCrossCheck>,
    Arc<dyn RefundCrossCheck>,
    Option<StreamedGate>,
);

fn build_cross_checks(args: &Args) -> Result<CrossChecks> {
    match args.cross_check_mode {
        CrossCheckMode::PassThrough => Ok((
            Arc::new(PassThroughRedemption {
                usdt_1e6: args.pass_usdt_1e6,
            }),
            Arc::new(PassThroughRefund {
                btc_sats: args.pass_btc_sats,
            }),
            // No streamed gate in Anvil mode — streaming is production-only.
            None,
        )),
        CrossCheckMode::ThorBtcUsdt => {
            // M9: refuse a sub-conf_depth confirmation threshold before any
            // attestation can be posted.
            enforce_confirmation_floors(args.eth_min_confirmations, args.btc_min_confirmations)?;
            let thor_url = args.thor_url.as_deref().context("--thor-url required")?;
            let http = args
                .eth_http_rpc_url
                .as_deref()
                .context("--eth-http-rpc-url required for thor-btc-usdt")?;
            let usdt = Address::from_str(
                args.usdt_address
                    .as_deref()
                    .context("--usdt-address required")?,
            )
            .context("invalid USDT address")?;
            let esplora = args
                .esplora_url
                .as_deref()
                .context("--esplora-url required")?;
            let net = parse_btc_network(
                args.btc_network
                    .as_deref()
                    .context("--btc-network required")?,
            )?;
            let multisig = bitcoin::Address::from_str(
                args.btc_multisig_address
                    .as_deref()
                    .context("--btc-multisig-address required")?,
            )
            .context("invalid multisig address")?
            .require_network(net)
            .context("multisig network mismatch")?;

            let thor = ThorClient::with_base_url(thor_url.to_string()).context("ThorClient")?;
            let erc20 = RpcErc20LogClient::new(http, args.eth_lookback_blocks);
            let delivery = ThorUtxoToUsdtPolicy::new(
                thor.clone(),
                erc20,
                usdt,
                args.eth_min_confirmations,
                args.usdt_tolerance_1e6,
            );
            let refund = ThorUtxoRefundPolicy::new(
                thor.clone(),
                EsploraClient::with_url(net, esplora),
                multisig.clone(),
                args.btc_min_confirmations,
                args.btc_tolerance_sats,
            );
            // Combined streamed-settlement policy for partial-fill redeems.
            // Reuses the same THORChain + ETH + BTC observations; uses the
            // MORE conservative of the two confirmation floors for both legs
            // (so the USDT arrival is never checked below the ETH conf_depth).
            let streamed_confs = args.eth_min_confirmations.max(args.btc_min_confirmations);
            let streamed = ThorUtxoStreamedSettlementPolicy::new(
                thor.clone(),
                RpcErc20LogClient::new(http, args.eth_lookback_blocks),
                EsploraClient::with_url(net, esplora),
                usdt,
                multisig,
                streamed_confs,
                args.usdt_tolerance_1e6,
                args.btc_tolerance_sats,
            );
            Ok((
                Arc::new(delivery),
                Arc::new(refund),
                Some((Arc::new(streamed), thor)),
            ))
        }
    }
}

/// Build the configured signer backend set — same shape as
/// `xindex-attest::build_signers`. `software` → raw keys from
/// `--signer-keys` (DEV ONLY). `remote` → one [`RemoteHsmBackend`] per
/// `(url, address)` pair, with the address pinned per response.
fn build_signers(args: &Args) -> Result<Vec<AnyHsmBackend>> {
    match args.signer_mode {
        SignerMode::Software => {
            let keys = args
                .signer_keys
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--signer-keys required in software mode"))?;
            let mut out = Vec::new();
            for k in keys.split(',') {
                let s =
                    SoftwareSigner::from_hex(k.trim()).with_context(|| format!("bad key: {k}"))?;
                out.push(AnyHsmBackend::Software(s));
            }
            Ok(out)
        }
        SignerMode::Remote => {
            let urls = args
                .signer_daemon_urls
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--signer-daemon-urls required in remote mode"))?;
            let addrs = args.signer_daemon_addresses.as_deref().ok_or_else(|| {
                anyhow::anyhow!("--signer-daemon-addresses required in remote mode")
            })?;
            let urls: Vec<&str> = urls.split(',').map(str::trim).collect();
            let addrs: Vec<&str> = addrs.split(',').map(str::trim).collect();
            if urls.len() != addrs.len() {
                anyhow::bail!(
                    "--signer-daemon-urls ({}) and --signer-daemon-addresses ({}) length mismatch",
                    urls.len(),
                    addrs.len()
                );
            }
            let mut out = Vec::new();
            for (url, addr) in urls.iter().zip(addrs.iter()) {
                let a = Address::from_str(addr)
                    .with_context(|| format!("invalid daemon address: {addr}"))?;
                out.push(AnyHsmBackend::Remote(RemoteHsmBackend::new(
                    (*url).to_string(),
                    a,
                )));
            }
            Ok(out)
        }
    }
}

/// Outcome of the streaming-swap FINALITY gate (`STREAM-B2-COORD`).
enum StreamedGateResult {
    /// This inbound is NOT a streaming swap — fall through to the
    /// delivery-XOR-refund path.
    NotStreaming,
    /// A streaming swap that is NOT yet finalised (or whose cross-check is
    /// not ready) — defer (retry on backfill). NEVER settle a partial
    /// mid-stream fill.
    Defer,
    /// A FULLY-finalised streaming swap — attest this combined on-chain
    /// outcome via `attestStreamedSettlement`.
    Settle(StreamedOutcome),
}

/// Streaming-swap FINALITY gate + combined cross-check (`STREAM-B2-COORD`).
/// Polls `THORChain`'s `tx/status` stages: a non-streaming inbound returns
/// [`StreamedGateResult::NotStreaming`]; a streaming swap that has not fully
/// finalised returns [`StreamedGateResult::Defer`] (the gate — never settle a
/// partial); a finalised stream returns [`StreamedGateResult::Settle`] with
/// the cross-checked on-chain outcome.
async fn try_settle_streamed(
    thor: &ThorClient,
    cc: &dyn StreamedSettlementCrossCheck,
    btc_txid: &str,
    index_token: Address,
) -> StreamedGateResult {
    let stages = match thor.tx_status_stages(btc_txid).await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "tx_status_stages failed; falling back to delivery/refund");
            return StreamedGateResult::NotStreaming;
        }
    };
    let is_streaming = stages
        .stages
        .swap_status
        .as_ref()
        .and_then(|s| s.streaming.as_ref())
        .is_some();
    if !is_streaming {
        return StreamedGateResult::NotStreaming;
    }
    // The gate: never settle a stream that has not fully finalised.
    if !stages.is_swap_finalised() {
        info!("streaming swap not yet finalised — deferring settlement (finality gate)");
        return StreamedGateResult::Defer;
    }
    match cc.verify(btc_txid, index_token).await {
        Ok(outcome) => StreamedGateResult::Settle(outcome),
        Err(e) => {
            warn!(error = %e, "streamed cross-check not ready; retry on backfill");
            StreamedGateResult::Defer
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "single sequential pipeline; splitting fights alloy 0.8's nested fillers generic"
)]
async fn run(args: Args) -> Result<()> {
    let intent_queue =
        Address::from_str(&args.intent_queue).context("INTENT_QUEUE_ADDR invalid")?;
    let attestation_oracle =
        Address::from_str(&args.attestation_oracle).context("ATTESTATION_ORACLE_ADDR invalid")?;

    let args_signers = args.clone();
    let signers: Arc<Vec<AnyHsmBackend>> = Arc::new(
        tokio::task::spawn_blocking(move || build_signers(&args_signers))
            .await
            .context("build_signers task")??,
    );
    if signers.len() < args.threshold {
        anyhow::bail!(
            "fewer signer backends ({}) than threshold ({})",
            signers.len(),
            args.threshold
        );
    }

    let args_cc = args.clone();
    let (delivery_cc, refund_cc, streamed) =
        tokio::task::spawn_blocking(move || build_cross_checks(&args_cc))
            .await
            .context("build_cross_checks task")?
            .context("build cross-checks")?;
    if args.redemption_database_url.is_none() {
        warn!(
            "F2 store IN-MEMORY — a fresh process has NO record of redemptions the executor \
             dispatched earlier; their attestations will never post. Point \
             REDEMPTION_DATABASE_URL at the SAME sqlite file the executor writes."
        );
    }
    let dispatch = Arc::new(
        AnyRedemptionDispatch::connect(args.redemption_database_url.as_deref())
            .await
            .context("connect F2 dispatch store")?,
    );

    let ws = WsConnect::new(&args.rpc_url);
    let poster: PrivateKeySigner = args.poster_key.parse().context("invalid POSTER_KEY")?;
    let provider = Arc::new(
        ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(EthereumWallet::new(poster))
            .on_ws(ws)
            .await
            .context("connect WS provider")?,
    );
    let chain_id = provider.get_chain_id().await.context("chain id")?;
    let domain = attestation_oracle_domain(chain_id, attestation_oracle);
    let oracle = AttestationOracle::new(attestation_oracle, provider.clone());
    info!(chain_id, mode = ?args.cross_check_mode, "xindex-attest-redeem starting");

    let process = async |ev: &IntentQueue::RedemptionIntentCreated| {
        let rid = ev.redemptionId;
        let index_token = ev.indexToken;
        // Phase 3.0: per-leg attestation. The single-async-slot baskets
        // that the THORChain rail supports today produce a length-1
        // `legAssetIds` array; the leg's assetId is the binding that
        // both the oracle (typed-data) and queue (re-check) verify.
        // Multi-leg expansion (mixed BTC + LTC + ... baskets) is
        // Phase 3.1 wiring; for now attest leg 0.
        let leg_index = U256::ZERO;
        // u32 mirror for the F2 store (per-leg keyed since H1). Same
        // value as `leg_index` above — kept as two locals because the
        // oracle wants U256 (ABI uint256) and the store wants u32.
        let leg_index_u32: u32 = 0;
        let Some(&asset_id) = ev.legAssetIds.first() else {
            warn!(redemption_id = %rid,
                  "RedemptionIntentCreated event has zero legs; skipping");
            return;
        };

        // U10: route per-leg by ChainId derived from `asset_id`
        // (= keccak256(thor_asset)). An unknown asset is a hard
        // skip — never sign for a chain we don't know how to
        // cross-check. Once any chain is in production, an unknown
        // asset_id is a runbook alert (likely a new chain being
        // recognised on-chain ahead of the off-chain rollout).
        let Some(leg_chain) = xindex_shared::chain_registry::ChainId::from_asset_id(asset_id)
        else {
            warn!(redemption_id = %rid, %asset_id,
                  "leg asset_id does not match any known chain; skipping (runbook)");
            return;
        };
        // `from_asset_id` now resolves EVM (Phase 3.2) and Cosmos (Phase
        // 3.3) assets too, so a "known" chain no longer implies this
        // UTXO-only attest path can service it: the delivery/refund
        // cross-checks here are BTC/UTXO-specific (ThorUtxo* policies). Gate
        // on custody family — a non-UTXO leg is skipped (a runbook alert)
        // until its own attest path lands (Cosmos: C6/C7) rather than being
        // mis-routed into the UTXO cross-check.
        if leg_chain.custody_family() != xindex_shared::chain_registry::CustodyFamily::Utxo {
            warn!(redemption_id = %rid, chain = ?leg_chain,
                  family = ?leg_chain.custody_family(),
                  "leg chain is not UTXO-family; xindex-attest-redeem services \
                   only UTXO legs — skipping (runbook)");
            return;
        }
        info!(redemption_id = %rid, chain = ?leg_chain,
              "leg routed by asset_id");

        // M9 per-leg depth: never attest a leg below its chain's conf_depth.
        // The configured UTXO threshold (`btc_min_confirmations`) must meet the
        // leg chain's requirement (BTC 6, LTC 12, DOGE 40, ZEC 10). For a BTC
        // leg this is a no-op; it fail-closes a leg whose chain needs deeper
        // confirmation than the binary is configured for, rather than attesting
        // an under-confirmed (reorg-revertible) delivery/refund.
        if !leg_depth_satisfied(args.btc_min_confirmations, leg_chain) {
            warn!(redemption_id = %rid, chain = ?leg_chain,
                  configured = args.btc_min_confirmations,
                  required = leg_chain.conf_depth(),
                  "configured confirmation threshold is below this leg chain's conf_depth; \
                   refusing to attest under-confirmed (runbook)");
            return;
        }

        // F2 correlation: the executor records (redemptionId, legIndex)
        // → inbound_txid AFTER it broadcasts the Asgard deposit. If
        // absent, the executor hasn't dispatched this leg yet — skip;
        // a `--from-block` backfill on the next restart re-processes
        // (same eventual-consistency posture as xindex-attest).
        let btc_txid = match dispatch.get(&rid, leg_index_u32).await {
            Ok(Some(r)) => r.inbound_txid,
            Ok(None) => {
                info!(redemption_id = %rid,
                      "no F2 dispatch record yet (executor not broadcast); skipping");
                return;
            }
            Err(e) => {
                error!(redemption_id = %rid, error = %e, "F2 lookup failed; skipping");
                return;
            }
        };

        // Streaming-swap finality gate (STREAM-B2-COORD): a streaming redeem
        // can PARTIALLY fill — both a USDT delivery to the IndexToken AND a
        // native refund to our custody on ONE leg. When THORChain reports
        // this inbound as a streaming swap, settle the COMBINED outcome via
        // attestStreamedSettlement — but ONLY once the stream has FULLY
        // finalised. Attesting mid-stream would settle a partial fill and
        // under-credit the user; the gate defers until finalisation.
        if let Some((streamed_cc, thor)) = streamed.as_ref() {
            match try_settle_streamed(thor, streamed_cc.as_ref(), &btc_txid, index_token).await {
                // Not a streaming swap — fall through to the delivery/refund XOR.
                StreamedGateResult::NotStreaming => {}
                // Streaming, but not yet final / cross-check not ready — defer.
                StreamedGateResult::Defer => return,
                // Fully finalised — attest the combined on-chain outcome.
                StreamedGateResult::Settle(outcome) => {
                    let delivered = U256::from(outcome.delivered_usdt_1e6);
                    let refunded = U256::from(outcome.refunded_sats);
                    let payload =
                        streamed_settlement(rid, leg_index, asset_id, delivered, refunded);
                    let signers_c = Arc::clone(&signers);
                    let threshold = args.threshold;
                    let domain_c = domain.clone();
                    let agg = tokio::task::spawn_blocking(move || {
                        let backends: Vec<&AnyHsmBackend> =
                            signers_c.iter().take(threshold).collect();
                        aggregate_streamed_settlement_signatures(&backends, &domain_c, &payload)
                    })
                    .await;
                    let sigs = match agg {
                        Ok(Ok(s)) => s.into_iter().map(Bytes::from).collect::<Vec<_>>(),
                        Ok(Err(e)) => {
                            error!(redemption_id = %rid, error = %e,
                                       "streamed-settlement aggregate failed");
                            return;
                        }
                        Err(e) => {
                            error!(redemption_id = %rid, error = %e,
                                       "streamed-settlement aggregate task panicked");
                            return;
                        }
                    };
                    info!(redemption_id = %rid,
                          delivered_usdt_1e6 = outcome.delivered_usdt_1e6,
                          refunded_sats = outcome.refunded_sats,
                          "posting attestStreamedSettlement()");
                    match oracle
                        .attestStreamedSettlement(
                            rid, leg_index, asset_id, delivered, refunded, sigs,
                        )
                        .send()
                        .await
                    {
                        Ok(p) => match p.get_receipt().await {
                            Ok(r) => info!(redemption_id = %rid, tx = %r.transaction_hash,
                                           "attestStreamedSettlement confirmed"),
                            Err(e) => error!(redemption_id = %rid, error = %e,
                                             "attestStreamedSettlement receipt failed"),
                        },
                        Err(e) => error!(redemption_id = %rid, error = %e,
                                         "attestStreamedSettlement send failed (already \
                                          settled / paused)"),
                    }
                    return;
                }
            }
        }

        // Delivery first; the policy returns RefundedInstead if a
        // REFUND outbound is present (mutual exclusion, memo-based).
        match delivery_cc.verify(&btc_txid, index_token).await {
            Ok(usdt_1e6) => {
                let amount = U256::from(usdt_1e6);
                let payload = redemption_attestation(rid, leg_index, asset_id, amount);
                let signers_c = Arc::clone(&signers);
                let threshold = args.threshold;
                let domain_c = domain.clone();
                let agg = tokio::task::spawn_blocking(move || {
                    let backends: Vec<&AnyHsmBackend> = signers_c.iter().take(threshold).collect();
                    aggregate_redemption_signatures(&backends, &domain_c, &payload)
                })
                .await;
                let sigs = match agg {
                    Ok(Ok(s)) => s.into_iter().map(Bytes::from).collect::<Vec<_>>(),
                    Ok(Err(e)) => {
                        error!(redemption_id = %rid, error = %e, "redemption aggregate failed");
                        return;
                    }
                    Err(e) => {
                        error!(redemption_id = %rid, error = %e,
                                   "redemption aggregate task panicked");
                        return;
                    }
                };
                info!(redemption_id = %rid, usdt_1e6, "posting attestRedemption()");
                match oracle
                    .attestRedemption(rid, leg_index, asset_id, amount, sigs)
                    .send()
                    .await
                {
                    Ok(p) => match p.get_receipt().await {
                        Ok(r) => info!(redemption_id = %rid, tx = %r.transaction_hash,
                                       "attestRedemption confirmed"),
                        Err(e) => error!(redemption_id = %rid, error = %e,
                                         "attestRedemption receipt failed"),
                    },
                    Err(e) => error!(redemption_id = %rid, error = %e,
                                     "attestRedemption send failed (already attested / \
                                      refund-excluded / paused)"),
                }
            }
            Err(RedemptionCrossCheckError::RefundedInstead) => {
                match refund_cc.verify(&btc_txid).await {
                    Ok(btc_sats) => {
                        let amount = U256::from(btc_sats);
                        let payload = refund_attestation(rid, leg_index, asset_id, amount);
                        let signers_c = Arc::clone(&signers);
                        let threshold = args.threshold;
                        let domain_c = domain.clone();
                        let agg = tokio::task::spawn_blocking(move || {
                            let backends: Vec<&AnyHsmBackend> =
                                signers_c.iter().take(threshold).collect();
                            aggregate_refund_signatures(&backends, &domain_c, &payload)
                        })
                        .await;
                        let sigs = match agg {
                            Ok(Ok(s)) => s.into_iter().map(Bytes::from).collect::<Vec<_>>(),
                            Ok(Err(e)) => {
                                error!(redemption_id = %rid, error = %e,
                                           "refund aggregate failed");
                                return;
                            }
                            Err(e) => {
                                error!(redemption_id = %rid, error = %e,
                                           "refund aggregate task panicked");
                                return;
                            }
                        };
                        info!(redemption_id = %rid, btc_sats, "posting attestRefund()");
                        match oracle
                            .attestRefund(rid, leg_index, asset_id, amount, sigs)
                            .send()
                            .await
                        {
                            Ok(p) => match p.get_receipt().await {
                                Ok(r) => info!(redemption_id = %rid, tx = %r.transaction_hash,
                                               "attestRefund confirmed"),
                                Err(e) => error!(redemption_id = %rid, error = %e,
                                                 "attestRefund receipt failed"),
                            },
                            Err(e) => error!(redemption_id = %rid, error = %e,
                                             "attestRefund send failed (already attested / \
                                              delivery-excluded / paused)"),
                        }
                    }
                    Err(e) => warn!(redemption_id = %rid, error = %e,
                                    "refund cross-check not ready; will retry on backfill"),
                }
            }
            Err(e) => warn!(redemption_id = %rid, error = %e,
                            "delivery cross-check not ready; will retry on backfill"),
        }
    };

    if args.from_block > 0 {
        let latest = provider.get_block_number().await.context("block number")?;
        let f = Filter::new()
            .address(intent_queue)
            .event_signature(IntentQueue::RedemptionIntentCreated::SIGNATURE_HASH)
            .from_block(BlockNumberOrTag::Number(args.from_block))
            .to_block(BlockNumberOrTag::Number(latest));
        let logs = provider.get_logs(&f).await.context("backfill get_logs")?;
        info!(count = logs.len(), "backfilling RedemptionIntentCreated");
        for log in logs {
            if let Ok(d) = log.log_decode::<IntentQueue::RedemptionIntentCreated>() {
                process(&d.inner.data).await;
            }
        }
    }

    let filter = Filter::new()
        .address(intent_queue)
        .event_signature(IntentQueue::RedemptionIntentCreated::SIGNATURE_HASH);
    let sub = provider
        .subscribe_logs(&filter)
        .await
        .context("subscribe")?;
    let mut stream = sub.into_stream();
    info!("subscribed; waiting for RedemptionIntentCreated…");
    while let Some(log) = stream.next().await {
        let Ok(d) = log.log_decode::<IntentQueue::RedemptionIntentCreated>() else {
            warn!("failed to decode RedemptionIntentCreated");
            continue;
        };
        process(&d.inner.data).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use xindex_shared::chain_registry::ChainId;

    #[test]
    fn parse_btc_network_canonical() {
        assert!(matches!(parse_btc_network("signet"), Ok(Network::Signet)));
        assert!(parse_btc_network("doge").is_err());
    }

    /// M9: the startup floor accepts at/above `conf_depth` and rejects below.
    #[test]
    fn confirmation_floors_reject_under_depth() {
        // Defaults (ETH 12, BTC 6) are exactly the floors → ok.
        assert!(enforce_confirmation_floors(12, 6).is_ok());
        // Raising is fine.
        assert!(enforce_confirmation_floors(20, 10).is_ok());
        // ETH below its conf_depth (12) → reject.
        assert!(enforce_confirmation_floors(11, 6).is_err());
        // BTC below its conf_depth (6) → reject.
        assert!(enforce_confirmation_floors(12, 5).is_err());
        assert!(enforce_confirmation_floors(12, 0).is_err());
    }

    /// M9: a leg is only serviced when the configured threshold meets the
    /// LEG chain's `conf_depth` (BTC 6, LTC 12, DOGE 40, ZEC 10).
    #[test]
    fn per_leg_depth_gate() {
        // BTC default config services a BTC leg.
        assert!(leg_depth_satisfied(6, ChainId::Btc));
        // …but NOT a deeper-finality leg at BTC's depth.
        assert!(!leg_depth_satisfied(6, ChainId::Doge)); // needs 40
        assert!(!leg_depth_satisfied(6, ChainId::Zec)); // needs 10
        assert!(!leg_depth_satisfied(6, ChainId::Ltc)); // needs 12
                                                        // A binary configured for the deeper chain services it.
        assert!(leg_depth_satisfied(40, ChainId::Doge));
        assert!(leg_depth_satisfied(10, ChainId::Zec));
    }
}
