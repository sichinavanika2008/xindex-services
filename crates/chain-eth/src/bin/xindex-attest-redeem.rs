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
    attestation_oracle_domain, redemption_attestation, refund_attestation,
};
use xindex_shared::redemption_dispatch::{AnyRedemptionDispatch, RedemptionDispatchStore};
use xindex_signer::crosscheck::{
    PassThroughRedemption, PassThroughRefund, RedemptionCrossCheck, RedemptionCrossCheckError,
    RefundCrossCheck, ThorUtxoRefundPolicy, ThorUtxoToUsdtPolicy,
};
use xindex_signer::remote::{AnyHsmBackend, RemoteHsmBackend};
use xindex_signer::{aggregate_redemption_signatures, aggregate_refund_signatures, SoftwareSigner};

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

#[derive(Parser, Debug)]
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

    /// Min ETH confirmations for the USDT arrival. Default 6.
    #[arg(long, env = "ETH_MIN_CONFIRMATIONS", default_value_t = 6)]
    eth_min_confirmations: u32,

    /// Min BTC confirmations for a refund UTXO. Default 6.
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

fn build_cross_checks(
    args: &Args,
) -> Result<(Arc<dyn RedemptionCrossCheck>, Arc<dyn RefundCrossCheck>)> {
    match args.cross_check_mode {
        CrossCheckMode::PassThrough => Ok((
            Arc::new(PassThroughRedemption {
                usdt_1e6: args.pass_usdt_1e6,
            }),
            Arc::new(PassThroughRefund {
                btc_sats: args.pass_btc_sats,
            }),
        )),
        CrossCheckMode::ThorBtcUsdt => {
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
                thor,
                EsploraClient::with_url(net, esplora),
                multisig,
                args.btc_min_confirmations,
                args.btc_tolerance_sats,
            );
            Ok((Arc::new(delivery), Arc::new(refund)))
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

#[expect(
    clippy::too_many_lines,
    reason = "single sequential pipeline; splitting fights alloy 0.8's nested fillers generic"
)]
async fn run(args: Args) -> Result<()> {
    let intent_queue =
        Address::from_str(&args.intent_queue).context("INTENT_QUEUE_ADDR invalid")?;
    let attestation_oracle =
        Address::from_str(&args.attestation_oracle).context("ATTESTATION_ORACLE_ADDR invalid")?;

    let signers: Vec<AnyHsmBackend> = build_signers(&args)?;
    if signers.len() < args.threshold {
        anyhow::bail!(
            "fewer signer backends ({}) than threshold ({})",
            signers.len(),
            args.threshold
        );
    }

    let (delivery_cc, refund_cc) = build_cross_checks(&args).context("build cross-checks")?;
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
                  "leg asset_id does not match any known UTXO chain; skipping (runbook)");
            return;
        };
        info!(redemption_id = %rid, chain = ?leg_chain,
              "leg routed by asset_id");

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

        // Delivery first; the policy returns RefundedInstead if a
        // REFUND outbound is present (mutual exclusion, memo-based).
        match delivery_cc.verify(&btc_txid, index_token).await {
            Ok(usdt_1e6) => {
                let amount = U256::from(usdt_1e6);
                let payload = redemption_attestation(rid, leg_index, asset_id, amount);
                let backends: Vec<&AnyHsmBackend> = signers.iter().take(args.threshold).collect();
                let sigs = match aggregate_redemption_signatures(&backends, &domain, &payload) {
                    Ok(s) => s.into_iter().map(Bytes::from).collect::<Vec<_>>(),
                    Err(e) => {
                        error!(redemption_id = %rid, error = %e, "redemption aggregate failed");
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
                        let backends: Vec<&AnyHsmBackend> =
                            signers.iter().take(args.threshold).collect();
                        let sigs = match aggregate_refund_signatures(&backends, &domain, &payload) {
                            Ok(s) => s.into_iter().map(Bytes::from).collect::<Vec<_>>(),
                            Err(e) => {
                                error!(redemption_id = %rid, error = %e,
                                           "refund aggregate failed");
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

    #[test]
    fn parse_btc_network_canonical() {
        assert!(matches!(parse_btc_network("signet"), Ok(Network::Signet)));
        assert!(parse_btc_network("doge").is_err());
    }
}
