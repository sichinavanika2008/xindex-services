//! `xindex-observe-redeem` — CTD-1 (`DL-CTD-2` Slice B) per-operator
//! REDEMPTION OBSERVER service.
//!
//! Each of the 5 operators runs ONE instance, alongside its own Set-B
//! signer daemon. The service:
//!   1. Watches `RedeemDispatched` AND `AcquireCancelled` on the
//!      operator's OWN Ethereum RPC and records each leg's / cancel's
//!      facts in memory.
//!   2. Exposes `POST /api/v1/certify-ric`: on each request it resolves
//!      the Asgard inbound from the operator's OWN diverse `THORChain`
//!      sources (fullnode + two public providers), rebuilds the
//!      canonical Redemption Intent Certificate from its own observations,
//!      and asks its OWN Set-B daemon to sign it.
//!   3. Exposes `POST /api/v1/certify-acc` (Slice C tail): the
//!      mint-cancel swap-back sibling. The memo's destination is pinned
//!      to THIS operator's configured recovery address — a compromised
//!      coordinator cannot steer the swapped-back USDT.
//!
//! The relay ([`xindex_executor::RicCollector`]) fans a certify request
//! out to all operators and assembles the k-of-n proof. A compromised
//! relay cannot forge what an honest observer resolves; the RPC-free
//! custody daemon re-verifies the assembled proof statelessly. This is
//! the "teeth" Slice A's mechanism was built for.
//!
//! This implementation is explicitly development-only because its event facts
//! are still held in memory and its backfill/live handoff has no finalized
//! checkpoint/reorg rollback. It refuses to boot without `--dev`; a production
//! successor must replace the event source with the durable observer store.

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
    AnyHaltSource, CancelFacts, HttpHaltSource, InMemoryLegSource, LegFacts, NeverHalted, Observer,
    ObserverConfig, ObserverError,
};
use xindex_chain_thor::{AsgardAgreement, ThorClient};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{
    ErrorBody, ObserverCertifyAccRequest, ObserverCertifyAccResponse, ObserverCertifyRequest,
    ObserverCertifyResponse,
};
use xindex_signer::remote::{AnyHsmBackend, RemoteHsmBackend};
use xindex_signer::SoftwareSigner;

/// Set-B signer-key backend. `software` holds the key in process (DEV /
/// Anvil only); `remote` forwards to the operator's HSM-backed daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SignerMode {
    Software,
    Remote,
}

#[derive(Parser, Debug, Clone)]
#[command(
    version,
    about = "Xindex per-operator redemption observer (CTD-1 Slice B)"
)]
struct Args {
    /// Explicit development acknowledgement. Required because this binary's
    /// event source is in-memory and not reorg-safe.
    #[arg(long, env = "XINDEX_DEV", default_value_t = false)]
    dev: bool,

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
    /// comma-separated: operator-controlled fullnode plus at least two
    /// independently administered public providers. Asgard is cross-confirmed
    /// across all three roles before any certification.
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

    /// CTD-1 Slice C tail: the ONLY Ethereum destination a mint-cancel
    /// swap-back memo may pay (the protocol's documented recovery sink —
    /// ceremony/runbook material). Unset = `certify-acc` disabled; there
    /// is no safe default destination.
    #[arg(long, env = "CANCEL_RECOVERY_DEST")]
    cancel_recovery_dest: Option<String>,

    /// `THORChain` asset string a swap-back memo must target
    /// (stagenet/testnet rehearsals differ from mainnet).
    #[arg(long, env = "SWAP_BACK_ASSET", default_value = "ETH.USDT")]
    swap_back_asset: String,
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
/// comma-separated `THORNode` URLs (≥3 required; the gate's constructor
/// rejects fewer).
fn build_agreement(spec: &str) -> Result<AsgardAgreement> {
    let mut clients = Vec::new();
    for url in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        clients.push(ThorClient::with_base_url(url.to_string()).context("thornode client")?);
    }
    AsgardAgreement::new(clients).map_err(|e| {
        anyhow::anyhow!(
            "diverse-source Asgard gate: {e} (configure fullnode + two public THORNode URLs)"
        )
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
    if !args.dev {
        anyhow::bail!(
            "xindex-observe-redeem is development-only until finalized checkpoints, reorg rollback, and durable event facts replace its in-memory source; pass --dev only for local rehearsal"
        );
    }
    let adapter =
        Address::from_str(&args.thorchain_adapter).context("THORCHAIN_ADAPTER_ADDR invalid")?;
    let oracle =
        Address::from_str(&args.attestation_oracle).context("ATTESTATION_ORACLE_ADDR invalid")?;
    let chain = ChainId::from_str(&args.chain)
        .map_err(|e| anyhow::anyhow!("--chain {:?}: {e}", args.chain))?;
    let network = parse_btc_network(&args.btc_network)?;
    let listen: SocketAddr = args.listen_addr.parse().context("LISTEN_ADDR invalid")?;

    let agreement = build_agreement(&args.thornode_urls)?;
    // `build_signer` (remote mode) constructs a `reqwest::blocking` client,
    // which must NOT be built on a runtime worker thread: reqwest's blocking
    // builder spawns + drops a temporary runtime, and dropping a runtime
    // inside an async context panics ("Cannot drop a runtime in a context
    // where blocking is not allowed"). Build it on a blocking thread — the
    // same discipline the library's tests use. (Software mode has no blocking
    // client; building it here is harmless.)
    let signer = {
        let a = args.clone();
        tokio::task::spawn_blocking(move || build_signer(&a))
            .await
            .context("build_signer task")??
    };
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
    let cancel_recovery_dest = args
        .cancel_recovery_dest
        .as_deref()
        .map(|s| Address::from_str(s).context("CANCEL_RECOVERY_DEST invalid"))
        .transpose()?;
    if cancel_recovery_dest.is_none() {
        warn!("no CANCEL_RECOVERY_DEST configured — certify-acc disabled");
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
            cancel_recovery_dest,
            swap_back_asset: args.swap_back_asset.clone(),
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

    // Spawn the RedeemDispatched + AcquireCancelled event loop on the
    // operator's OWN RPC → leg/cancel maps. Inlined (not a helper) to
    // dodge alloy 0.8's nested FillProvider/PubSubFrontend generic that
    // fights `impl Provider` bounds on standalone helpers — same
    // pattern as `xindex-cancel`.
    let loop_provider = Arc::clone(&provider);
    let loop_legs = legs.clone();
    let loop_cancels = observer.cancel_source();
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
        // A1/A5: the event's `amount` (non-authoritative USDT units) is
        // deliberately NOT recorded — a swap-back is never sized from it.
        let record_cancel = |ev: &ThorchainAdapter::AcquireCancelled| {
            let Ok(slot_index) = u32::try_from(ev.slotIndex) else {
                warn!(cancel_id = %ev.cancelId, "AcquireCancelled slotIndex exceeds u32");
                return;
            };
            loop_cancels.insert(
                ev.cancelId,
                CancelFacts {
                    intent_id: ev.intentId,
                    slot_index,
                },
                now_unix(),
            );
            info!(cancel_id = %ev.cancelId, "recorded AcquireCancelled facts");
        };
        let redeem_sig = ThorchainAdapter::RedeemDispatched::SIGNATURE_HASH;
        let cancel_sig = ThorchainAdapter::AcquireCancelled::SIGNATURE_HASH;
        let handle_log = |log: &alloy::rpc::types::Log| {
            if log.topic0() == Some(&redeem_sig) {
                match log.log_decode::<ThorchainAdapter::RedeemDispatched>() {
                    Ok(d) => record(&d.inner.data),
                    Err(e) => warn!(error = %e, "failed to decode RedeemDispatched"),
                }
            } else if log.topic0() == Some(&cancel_sig) {
                match log.log_decode::<ThorchainAdapter::AcquireCancelled>() {
                    Ok(d) => record_cancel(&d.inner.data),
                    Err(e) => warn!(error = %e, "failed to decode AcquireCancelled"),
                }
            }
        };
        if from_block > 0 {
            match loop_provider.get_block_number().await {
                Ok(latest) => {
                    let f = Filter::new()
                        .address(adapter)
                        .event_signature(vec![redeem_sig, cancel_sig])
                        .from_block(BlockNumberOrTag::Number(from_block))
                        .to_block(BlockNumberOrTag::Number(latest));
                    match loop_provider.get_logs(&f).await {
                        Ok(logs) => {
                            for log in logs {
                                handle_log(&log);
                            }
                        }
                        Err(e) => error!(error = %e, "observer backfill get_logs failed"),
                    }
                }
                Err(e) => error!(error = %e, "observer backfill block number failed"),
            }
        }
        let filter = Filter::new()
            .address(adapter)
            .event_signature(vec![redeem_sig, cancel_sig]);
        match loop_provider.subscribe_logs(&filter).await {
            Ok(sub) => {
                let mut stream = sub.into_stream();
                info!("observer subscribed to RedeemDispatched + AcquireCancelled");
                while let Some(log) = stream.next().await {
                    handle_log(&log);
                }
            }
            Err(e) => {
                error!(error = %e, "observer subscribe failed; certify will 404 new events");
            }
        }
    });

    let app = Router::new()
        .route("/api/v1/certify-ric", post(handle_certify))
        .route("/api/v1/certify-acc", post(handle_certify_acc))
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

/// `POST /api/v1/certify-acc` — resolve + certify one mint-cancel
/// swap-back from THIS observer's own view (CTD-1 Slice C tail), or
/// return the typed refusal.
async fn handle_certify_acc(
    State(state): State<ObserverState>,
    Json(req): Json<ObserverCertifyAccRequest>,
) -> Result<Json<ObserverCertifyAccResponse>, (StatusCode, Json<ErrorBody>)> {
    let now = now_unix();
    match state.observer.certify_acc(&req, now).await {
        Ok(resp) => Ok(Json(resp)),
        Err(e) => {
            warn!(error = %e, code = e.error_code(), "certify-acc refused");
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
        ObserverError::EventNotFound { .. } | ObserverError::CancelNotFound { .. } => {
            StatusCode::NOT_FOUND
        }
        ObserverError::AsgardUnavailable(_)
        | ObserverError::LegSource(_)
        | ObserverError::SignerUnavailable(_)
        | ObserverError::HaltUnavailable(_)
        | ObserverError::CancelDisabled => StatusCode::SERVICE_UNAVAILABLE,
        ObserverError::ChainUnsupported(_)
        | ObserverError::BadRequest(_)
        | ObserverError::EventInvalid(_)
        | ObserverError::StampOutOfWindow(_)
        | ObserverError::MemoRejected(_) => StatusCode::UNPROCESSABLE_ENTITY,
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
