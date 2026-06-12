//! `xindex-observe-redeem` — CTD-1 (`DL-CTD-2` Slice B) per-operator
//! REDEMPTION OBSERVER service.
//!
//! Each of the 5 operators runs ONE instance, alongside its own Set-B
//! signer daemon. The service:
//!   1. Watches `RedeemDispatched` on the operator's OWN Ethereum RPC and
//!      records each leg's facts (amount / memo / final destination) in
//!      memory.
//!   2. Exposes `POST /api/v1/certify-ric`: on each request it resolves
//!      the Asgard inbound from the operator's OWN diverse `THORChain`
//!      sources (cross-confirmed across ≥2, refinement 1), rebuilds the
//!      canonical Redemption Intent Certificate from its own observations,
//!      and asks its OWN Set-B daemon to sign it.
//!
//! The relay ([`xindex_executor::RicCollector`]) fans a certify request
//! out to all operators and assembles the k-of-n proof. A compromised
//! relay cannot forge what an honest observer resolves; the RPC-free
//! custody daemon re-verifies the assembled proof statelessly. This is
//! the "teeth" Slice A's mechanism was built for.
//!
//! Trust note: in `software` signer mode the Set-B key is held in this
//! process (DEV / Anvil only). Production MUST use `remote` so the key
//! lives in the operator's HSM-backed daemon.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use bitcoin::Network;
use clap::{Parser, ValueEnum};
use futures_util::StreamExt;
use tracing::{error, info, warn};
use xindex_chain_eth::bindings::ThorchainAdapter;
use xindex_chain_eth::observer::{
    AnyHaltSource, HttpHaltSource, InMemoryLegSource, LegFacts, NeverHalted, Observer,
    ObserverConfig, ObserverError,
};
use xindex_chain_thor::{AsgardAgreement, ThorClient};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{ErrorBody, ObserverCertifyRequest, ObserverCertifyResponse};
use xindex_signer::remote::{AnyHsmBackend, RemoteHsmBackend};
use xindex_signer::SoftwareSigner;

/// Set-B signer-key backend. `software` holds the key in process (DEV /
/// Anvil only); `remote` forwards to the operator's HSM-backed daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SignerMode {
    Software,
    Remote,
}

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Xindex per-operator redemption observer (CTD-1 Slice B)"
)]
struct Args {
    /// This operator's OWN WebSocket Ethereum RPC — the source of
    /// `RedeemDispatched` leg facts. Each operator MUST use its own
    /// distinct endpoint (the per-operator-observer trust model).
    #[arg(long, env = "ETH_RPC_URL", default_value = "ws://127.0.0.1:8545")]
    rpc_url: String,

    /// Deployed `ThorchainAdapter` address — the contract emitting
    /// `RedeemDispatched`.
    #[arg(long, env = "THORCHAIN_ADAPTER_ADDR")]
    thorchain_adapter: String,

    /// Deployed `AttestationOracle` address — the RIC EIP-712 domain's
    /// verifying contract. MUST match the custody daemon's pin.
    #[arg(long, env = "ATTESTATION_ORACLE_ADDR")]
    attestation_oracle: String,

    /// This operator's OWN, DISTINCT `THORNode` REST base URLs —
    /// comma-separated, ≥2 (refinement 1: the k-of-n floor is illusory
    /// on a single shared source). Asgard is cross-confirmed across
    /// these before any certification.
    #[arg(long, env = "THORNODE_URLS")]
    thornode_urls: String,

    /// Custody chain this observer certifies (`btc` for Phase 2.A). The
    /// observer refuses any other chain; `sol` is always refused (RA-2).
    #[arg(long, env = "CHAIN", default_value = "btc")]
    chain: String,

    /// Bitcoin network for parsing the resolved Asgard address into the
    /// scriptPubKey whose keccak is `immediate_target_hash`.
    #[arg(long, env = "BTC_NETWORK", default_value = "bitcoin")]
    btc_network: String,

    /// Set-B signer backend. Mainnet MUST be `remote`.
    #[arg(long, env = "SIGNER_MODE", value_enum, default_value_t = SignerMode::Software)]
    signer_mode: SignerMode,

    /// (software mode) This operator's Set-B hex private key. DEV ONLY.
    #[arg(long, env = "SIGNER_KEY")]
    signer_key: Option<String>,

    /// (remote mode) Base URL of this operator's OWN Set-B signer daemon.
    #[arg(long, env = "SIGNER_DAEMON_URL")]
    signer_daemon_url: Option<String>,

    /// (remote mode) Pinned Set-B address of this operator's daemon
    /// (disclosed at the key ceremony). Every signature is checked
    /// against it.
    #[arg(long, env = "SIGNER_DAEMON_ADDRESS")]
    signer_daemon_address: Option<String>,

    /// Block to backfill `RedeemDispatched` from on startup (0 = live
    /// only). A restart re-backfills so the leg map is repopulated.
    #[arg(long, env = "FROM_BLOCK", default_value_t = 0)]
    from_block: u64,

    /// Max absolute skew (seconds) between local time and a proposed
    /// `vault_resolved_at` the observer will certify under.
    #[arg(long, env = "STAMP_WINDOW_SECS", default_value_t = 120)]
    stamp_window_secs: u64,

    /// Address the certify-ric HTTP service listens on.
    #[arg(long, env = "LISTEN_ADDR", default_value = "127.0.0.1:9101")]
    listen_addr: String,

    /// Deployed `CustodyGuard` address (DL-CTD-E). When set (together
    /// with --eth-http-url) the observer refuses to certify while the
    /// on-chain halt is active. Unset = no halt gate (DEV ONLY —
    /// production MUST set it).
    #[arg(long, env = "CUSTODY_GUARD_ADDR")]
    custody_guard: Option<String>,

    /// HTTP(S) Ethereum JSON-RPC used for the halt poll (a plain
    /// `eth_call`; typically the HTTP port of `ETH_RPC_URL`'s node).
    #[arg(long, env = "ETH_HTTP_URL")]
    eth_http_url: Option<String>,

    /// E2 fraud window (DL-CTD-E): legs STRICTLY ABOVE this native
    /// smallest-unit amount wait `LARGE_SPEND_DELAY_SECS` from first
    /// observation before this observer certifies (production: ≈2% of
    /// per-chain custody, decimal). Unset = no fraud window (DEV ONLY).
    #[arg(long, env = "LARGE_SPEND_THRESHOLD")]
    large_spend_threshold: Option<String>,

    /// E2 fraud-window delay seconds (production default 1800 = 30 min).
    #[arg(long, env = "LARGE_SPEND_DELAY_SECS", default_value_t = 1_800)]
    large_spend_delay_secs: u64,
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

/// Build the diverse-source Asgard agreement gate from the operator's
/// comma-separated `THORNode` URLs (≥2 required; the gate's constructor
/// rejects fewer).
fn build_agreement(spec: &str) -> Result<AsgardAgreement> {
    let mut clients = Vec::new();
    for url in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        clients.push(ThorClient::with_base_url(url.to_string()).context("thornode client")?);
    }
    AsgardAgreement::new(clients).map_err(|e| {
        anyhow::anyhow!("diverse-source Asgard gate: {e} (configure ≥2 THORNode URLs)")
    })
}

/// Build this operator's single Set-B signer backend.
fn build_signer(args: &Args) -> Result<AnyHsmBackend> {
    match args.signer_mode {
        SignerMode::Software => {
            let key = args
                .signer_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--signer-key required in software mode"))?;
            warn!("software Set-B signer — key in process heap; DEV / ANVIL ONLY");
            Ok(AnyHsmBackend::Software(
                SoftwareSigner::from_hex(key).context("parse Set-B key")?,
            ))
        }
        SignerMode::Remote => {
            let url = args
                .signer_daemon_url
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--signer-daemon-url required in remote mode"))?;
            let addr_s = args.signer_daemon_address.as_deref().ok_or_else(|| {
                anyhow::anyhow!("--signer-daemon-address required in remote mode")
            })?;
            let addr = Address::from_str(addr_s).context("invalid Set-B daemon address")?;
            Ok(AnyHsmBackend::Remote(RemoteHsmBackend::new(
                url.to_string(),
                addr,
            )))
        }
    }
}

/// Shared axum state: the observer (over the in-memory leg source) the
/// event loop writes into.
#[derive(Clone, Debug)]
struct ObserverState {
    observer: Arc<Observer<InMemoryLegSource, AnyHsmBackend, AnyHaltSource>>,
}

/// Build the DL-CTD-E halt source: both the guard address and the HTTP
/// RPC, or neither (DEV ONLY, loud).
fn build_halt_source(args: &Args) -> Result<AnyHaltSource> {
    match (&args.custody_guard, &args.eth_http_url) {
        (Some(guard), Some(url)) => {
            let guard = Address::from_str(guard).context("CUSTODY_GUARD_ADDR invalid")?;
            Ok(AnyHaltSource::Http(HttpHaltSource::new(url.clone(), guard)))
        }
        (None, None) => {
            warn!("no CustodyGuard halt gate configured — DEV ONLY");
            Ok(AnyHaltSource::Never(NeverHalted))
        }
        _ => anyhow::bail!("CUSTODY_GUARD_ADDR and ETH_HTTP_URL must be set together"),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "single sequential setup + inlined event loop (alloy provider-generic friction forces the inline)"
)]
async fn run(args: Args) -> Result<()> {
    let adapter =
        Address::from_str(&args.thorchain_adapter).context("THORCHAIN_ADAPTER_ADDR invalid")?;
    let oracle =
        Address::from_str(&args.attestation_oracle).context("ATTESTATION_ORACLE_ADDR invalid")?;
    let chain = ChainId::from_str(&args.chain)
        .map_err(|e| anyhow::anyhow!("--chain {:?}: {e}", args.chain))?;
    let network = parse_btc_network(&args.btc_network)?;
    let listen: SocketAddr = args.listen_addr.parse().context("LISTEN_ADDR invalid")?;

    let agreement = build_agreement(&args.thornode_urls)?;
    let signer = build_signer(&args)?;
    let halt = build_halt_source(&args)?;
    let large_spend_threshold = args
        .large_spend_threshold
        .as_deref()
        .map(|s| {
            U256::from_str_radix(s, 10).context("LARGE_SPEND_THRESHOLD must be a decimal amount")
        })
        .transpose()?;
    if large_spend_threshold.is_none() {
        warn!("no E2 fraud-window threshold configured — DEV ONLY");
    }
    let legs = InMemoryLegSource::new();

    let ws = WsConnect::new(&args.rpc_url);
    let provider = Arc::new(
        ProviderBuilder::new()
            .on_ws(ws)
            .await
            .context("connect WS provider")?,
    );
    let eth_chain_id = provider.get_chain_id().await.context("chain id")?;

    let observer = Arc::new(Observer::new(
        ObserverConfig {
            chain,
            eth_chain_id,
            oracle,
            btc_network: network,
            stamp_window_secs: args.stamp_window_secs,
            large_spend_threshold,
            large_spend_delay_secs: args.large_spend_delay_secs,
        },
        agreement,
        legs.clone(),
        signer,
        halt,
    ));
    info!(
        %adapter, %oracle, chain = ?chain, eth_chain_id,
        listen = %listen, "xindex-observe-redeem starting"
    );

    // Spawn the RedeemDispatched event loop on the operator's OWN RPC →
    // leg map. Inlined (not a helper) to dodge alloy 0.8's nested
    // FillProvider/PubSubFrontend generic that fights `impl Provider`
    // bounds on standalone helpers — same pattern as `xindex-cancel`.
    let loop_provider = Arc::clone(&provider);
    let loop_legs = legs.clone();
    let from_block = args.from_block;
    tokio::spawn(async move {
        let record = |ev: &ThorchainAdapter::RedeemDispatched| {
            loop_legs.insert(
                ev.redemptionId,
                0,
                LegFacts {
                    amount: ev.amount,
                    memo: ev.memo.as_bytes().to_vec(),
                    final_destination: ev.destination,
                },
                now_unix(),
            );
            info!(redemption_id = %ev.redemptionId, "recorded RedeemDispatched leg facts");
        };
        let sig = ThorchainAdapter::RedeemDispatched::SIGNATURE_HASH;
        if from_block > 0 {
            match loop_provider.get_block_number().await {
                Ok(latest) => {
                    let f = Filter::new()
                        .address(adapter)
                        .event_signature(sig)
                        .from_block(BlockNumberOrTag::Number(from_block))
                        .to_block(BlockNumberOrTag::Number(latest));
                    match loop_provider.get_logs(&f).await {
                        Ok(logs) => {
                            for log in logs {
                                if let Ok(d) =
                                    log.log_decode::<ThorchainAdapter::RedeemDispatched>()
                                {
                                    record(&d.inner.data);
                                }
                            }
                        }
                        Err(e) => error!(error = %e, "observer backfill get_logs failed"),
                    }
                }
                Err(e) => error!(error = %e, "observer backfill block number failed"),
            }
        }
        let filter = Filter::new().address(adapter).event_signature(sig);
        match loop_provider.subscribe_logs(&filter).await {
            Ok(sub) => {
                let mut stream = sub.into_stream();
                info!("observer subscribed to RedeemDispatched");
                while let Some(log) = stream.next().await {
                    match log.log_decode::<ThorchainAdapter::RedeemDispatched>() {
                        Ok(d) => record(&d.inner.data),
                        Err(e) => warn!(error = %e, "failed to decode RedeemDispatched"),
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "observer subscribe failed; certify-ric will 404 new legs");
            }
        }
    });

    let app = Router::new()
        .route("/api/v1/certify-ric", post(handle_certify))
        .route("/api/v1/health", axum::routing::get(|| async { "ok" }))
        .with_state(ObserverState { observer });
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind {listen}"))?;
    axum::serve(listener, app).await.context("serve")?;
    Ok(())
}

/// `POST /api/v1/certify-ric` — resolve + certify one leg from THIS
/// observer's own view, or return the typed refusal.
async fn handle_certify(
    State(state): State<ObserverState>,
    Json(req): Json<ObserverCertifyRequest>,
) -> Result<Json<ObserverCertifyResponse>, (StatusCode, Json<ErrorBody>)> {
    let now = now_unix();
    match state.observer.certify_ric(&req, now).await {
        Ok(resp) => Ok(Json(resp)),
        Err(e) => {
            warn!(error = %e, code = e.error_code(), "certify-ric refused");
            Err((
                status_for(&e),
                Json(ErrorBody {
                    code: e.error_code().to_string(),
                    message: e.to_string(),
                }),
            ))
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// HTTP status for each observer refusal class.
fn status_for(e: &ObserverError) -> StatusCode {
    match e {
        ObserverError::EventNotFound { .. } => StatusCode::NOT_FOUND,
        ObserverError::AsgardUnavailable(_)
        | ObserverError::LegSource(_)
        | ObserverError::SignerUnavailable(_)
        | ObserverError::HaltUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        ObserverError::ChainUnsupported(_)
        | ObserverError::BadRequest(_)
        | ObserverError::EventInvalid(_)
        | ObserverError::StampOutOfWindow(_) => StatusCode::UNPROCESSABLE_ENTITY,
        ObserverError::Halted => StatusCode::LOCKED,
        ObserverError::FraudWindowActive { .. } => StatusCode::TOO_EARLY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_btc_network_roundtrips() {
        assert!(matches!(parse_btc_network("bitcoin"), Ok(Network::Bitcoin)));
        assert!(matches!(parse_btc_network("signet"), Ok(Network::Signet)));
        assert!(parse_btc_network("dogecoin").is_err());
    }

    #[test]
    fn build_agreement_requires_two_sources() {
        assert!(build_agreement("http://only-one").is_err());
        assert!(build_agreement("http://a,http://b").is_ok());
    }

    #[test]
    fn status_codes_map_each_class() {
        assert_eq!(
            status_for(&ObserverError::EventNotFound {
                redemption_id: alloy::primitives::B256::ZERO,
                leg_index: 0
            }),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status_for(&ObserverError::AsgardUnavailable("x".into())),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status_for(&ObserverError::StampOutOfWindow("x".into())),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
}
