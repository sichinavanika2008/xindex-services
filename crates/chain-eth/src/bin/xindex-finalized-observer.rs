//! Production per-operator finalized redemption/cancellation observer.
//!
//! This service has no software signer and no transaction sender. It journals
//! exact finalized Ethereum blocks/logs with reorg rollback, independently
//! resolves Asgard from three complete THORNode/CometBFT sources, and asks one
//! operator-local signer daemon for RIC/ACC signatures over pinned mTLS.

use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::providers::ProviderBuilder;
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolEvent;
use anyhow::{Context, Result};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use bitcoin::Network;
use clap::Parser;
use futures_util::future::join_all;
use prometheus::Registry;
use serde::{Deserialize, Serialize};
use xindex_chain_eth::bindings::{AttestationOracle, IntentQueue, ThorchainAdapter};
use xindex_chain_eth::finalized_observer::{
    decode_protocol_logs, FinalizedCheckpoint, SqliteFinalizedObserverStore,
};
use xindex_chain_eth::finalized_rpc::{FinalizedBlock, FinalizedRpcClient, RawRpcResponse};
use xindex_chain_eth::observer::{
    AsgardSource, HttpHaltSource, InMemoryCancelSource, Observer, ObserverConfig, ObserverError,
};
use xindex_chain_eth::settlement_observer::{
    BtcSettlementConfig, BtcSettlementObserver, SettlementObserverError,
};
use xindex_chain_thor::{
    derive_inbound, CanonicalSourceBundle, InboundAddress, InboundPolicy, RawSourcePoll,
    SourceSnapshot, ThorClient, ThorConsensusClient, ThorSourceClient, TipCheckpoint,
};
use xindex_ops::tls::{
    load_cert_chain, load_private_key, pinned_root_store, serve_mtls, server_config,
};
use xindex_ops::{serve_metrics, Metrics};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::consumed_inflow::AnyConsumedInflow;
use xindex_shared::eip712::attestation_oracle_domain;
use xindex_shared::evidence::EvidenceStore;
use xindex_shared::native_inflow::AnyNativeInflow;
use xindex_shared::registry_state::{SqliteRegistryState, TipAdvance};
use xindex_shared::settlement_wire::{
    MintSettlementRequest, RedemptionSettlementRequest, SignedDeliverySettlement,
    SignedMintSettlement, SignedRefundSettlement, SignedStreamedSettlement,
};
use xindex_shared::signer_wire::{
    ErrorBody, ObserverCertifyAccRequest, ObserverCertifyAccResponse, ObserverCertifyRequest,
    ObserverCertifyResponse,
};
use xindex_signer::remote::RemoteHsmBackend;

const MAX_API_BODY_BYTES: usize = 64 * 1024;
const MAX_BLOCK_FUTURE_SKEW_SECS: u64 = 15;
const PRODUCTION_ATTESTATION_SIGNER_COUNT: usize = 5;
const PRODUCTION_ATTESTATION_THRESHOLD: usize = 3;

#[derive(Debug, Parser)]
struct Args {
    /// Absolute path to a strict, owner-only JSON configuration file.
    config: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    operator_id: String,
    expected_chain_id: u64,
    ethereum_rpc_url: String,
    thorchain_adapter: String,
    intent_queue: String,
    attestation_oracle: String,
    custody_guard: String,
    chain: ChainId,
    btc_network: String,
    redemption_leg_index: u32,
    mint_asset_id: String,
    target_token: String,
    btc_custody_address: String,
    btc_esplora_url: String,
    btc_min_confirmations: u32,
    btc_tolerance_sats: u64,
    usdt_token: String,
    ethereum_lookback_blocks: u64,
    usdt_tolerance_1e6: u128,
    settlement_database_url: String,
    expected_attestation_signer_count: usize,
    expected_attestation_threshold: usize,
    start_block: u64,
    poll_interval_millis: u64,
    observer_database_url: String,
    thor_state_database_url: String,
    evidence_dir: PathBuf,
    listen_address: SocketAddr,
    metrics_address: SocketAddr,
    stamp_window_secs: u64,
    large_spend_threshold: String,
    large_spend_delay_secs: u64,
    cancel_recovery_destination: String,
    swap_back_asset: String,
    inbound_policy: InboundPolicy,
    sources: Vec<SourceConfig>,
    signer: SignerConfig,
    server_cert_pem: PathBuf,
    server_key_pem: PathBuf,
    coordinator_client_cert_pems: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceConfig {
    id: String,
    thornode_url: String,
    consensus_url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerConfig {
    url: String,
    address: String,
    client_cert_pem: PathBuf,
    client_key_pem: PathBuf,
    server_ca_pem: PathBuf,
    timeout_secs: u64,
}

#[derive(Clone)]
struct PolicyAsgardSource {
    operator_id: String,
    sources: Arc<Vec<ThorSourceClient>>,
    policy: InboundPolicy,
    state: SqliteRegistryState,
    evidence: EvidenceStore,
    poll_lock: Arc<tokio::sync::Mutex<()>>,
    metrics: Metrics,
}

impl std::fmt::Debug for PolicyAsgardSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PolicyAsgardSource")
            .field("operator_id", &self.operator_id)
            .finish_non_exhaustive()
    }
}

impl PolicyAsgardSource {
    async fn poll_and_persist(
        &self,
        chain: &str,
        now_unix: u64,
    ) -> std::result::Result<Vec<RawSourcePoll>, String> {
        let polls = join_all(self.sources.iter().map(|source| source.poll(now_unix)))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                self.metrics
                    .registry_source_polls
                    .with_label_values(&["source_error"])
                    .inc();
                error.to_string()
            })?;
        let raw = AsgardRawEvidence {
            schema: "xindex.asgard-observer-raw.v1",
            operator_id: &self.operator_id,
            requested_chain: chain,
            sources: polls.iter().map(raw_source_evidence).collect(),
        };
        self.evidence
            .persist_hashed(&format!("asgard-raw-{now_unix}"), &raw)
            .map_err(|error| {
                self.metrics.registry_evidence_failures.inc();
                error.to_string()
            })?;
        Ok(polls)
    }

    async fn snapshots(
        &self,
        polls: &[RawSourcePoll],
    ) -> std::result::Result<Vec<SourceSnapshot>, String> {
        let mut snapshots = Vec::with_capacity(polls.len());
        for poll in polls {
            let advance = self
                .state
                .record_source_tip(
                    &poll.source_id,
                    poll.consensus.value.height,
                    &poll.consensus.value.block_hash,
                    poll.observed_at,
                )
                .await
                .map_err(|error| error.to_string())?;
            let previous = match advance {
                TipAdvance::First => None,
                TipAdvance::Advanced { previous } => Some(TipCheckpoint {
                    height: previous.height,
                    observed_at: previous.observed_at,
                    proven_advance: true,
                }),
                TipAdvance::Unchanged { previous } => Some(TipCheckpoint {
                    height: previous.height,
                    observed_at: previous.observed_at,
                    proven_advance: previous.advanced_once,
                }),
            };
            snapshots.push(poll.snapshot(previous));
        }
        Ok(snapshots)
    }
}

impl AsgardSource for PolicyAsgardSource {
    async fn resolve_asgard(&self, chain: &str, now_unix: u64) -> Result<InboundAddress, String> {
        let _guard = self.poll_lock.lock().await;
        let polls = self.poll_and_persist(chain, now_unix).await?;
        let snapshots = self.snapshots(&polls).await?;
        let derived = derive_inbound(&self.policy, &snapshots, now_unix).map_err(|error| {
            self.metrics
                .registry_source_polls
                .with_label_values(&["policy_error"])
                .inc();
            error.to_string()
        })?;
        self.metrics
            .registry_pause_flags
            .set(i64::from(derived.pause_flags));
        if derived.pause_flags != 0 {
            self.metrics
                .registry_source_polls
                .with_label_values(&["stale_tip"])
                .inc();
            return Err(format!(
                "THORChain route is fail-closed with pause flags 0x{:02x}",
                derived.pause_flags
            ));
        }
        let inbound = canonical_target_inbound(&derived.bundle, chain)?;
        self.metrics
            .registry_source_polls
            .with_label_values(&["success"])
            .inc();
        self.metrics
            .registry_last_success_timestamp_seconds
            .with_label_values(&["source_poll"])
            .set(u64_to_i64(now_unix));
        Ok(inbound)
    }
}

fn canonical_target_inbound(
    bundle: &CanonicalSourceBundle,
    chain: &str,
) -> std::result::Result<InboundAddress, String> {
    let mut rows = bundle.sources.iter().map(|source| {
        source
            .inbound
            .iter()
            .find(|row| row.chain == chain)
            .cloned()
            .ok_or_else(|| format!("source {} lacks {chain} inbound", source.source_id))
    });
    let first = rows
        .next()
        .ok_or_else(|| "no canonical THOR sources".to_string())??;
    for row in rows {
        let row = row?;
        if row.address != first.address
            || row.halted
            || row.global_trading_paused
            || row.chain_trading_paused
            || row.chain_lp_actions_paused
        {
            return Err(format!(
                "{chain} inbound differs or is paused across sources"
            ));
        }
    }
    Ok(first)
}

type ProductionObserver =
    Observer<SqliteFinalizedObserverStore, RemoteHsmBackend, HttpHaltSource, PolicyAsgardSource>;

#[derive(Clone)]
struct AppState {
    observer: Arc<ProductionObserver>,
    settlement: Arc<BtcSettlementObserver>,
    store: SqliteFinalizedObserverStore,
    rpc: FinalizedRpcClient,
    evidence: EvidenceStore,
    operator_id: String,
    ready: Arc<AtomicBool>,
    last_sync_at: Arc<AtomicU64>,
    max_sync_age_secs: u64,
    metrics: Metrics,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppState")
            .field("operator_id", &self.operator_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct EventLoopState {
    operator_id: String,
    adapter: Address,
    intent_queue: Address,
    mint_asset_id: B256,
    redemption_leg_index: u32,
    start_block: u64,
    poll_interval: Duration,
    store: SqliteFinalizedObserverStore,
    rpc: FinalizedRpcClient,
    evidence: EvidenceStore,
    cancels: InMemoryCancelSource,
    metrics: Metrics,
    ready: Arc<AtomicBool>,
    last_sync_at: Arc<AtomicU64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawSourceEvidence<'a> {
    source_id: &'a str,
    observed_at: u64,
    inbound_body: &'a str,
    mimir_body: &'a str,
    pools_body: &'a str,
    consensus_body: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AsgardRawEvidence<'a> {
    schema: &'static str,
    operator_id: &'a str,
    requested_chain: &'a str,
    sources: Vec<RawSourceEvidence<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvmBlockEvidence<'a> {
    schema: &'static str,
    operator_id: &'a str,
    finalized_head_number: u64,
    finalized_head_hash: String,
    finalized_head_body: &'a str,
    block_number: u64,
    block_hash: String,
    parent_hash: String,
    header_body: &'a str,
    logs_body: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalCheckEvidence<'a> {
    schema: &'static str,
    operator_id: &'a str,
    block_number: u64,
    expected_hash: String,
    observed_hash: String,
    raw_body: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreSignCheckEvidence<'a> {
    schema: &'static str,
    operator_id: &'a str,
    expected_number: u64,
    expected_hash: String,
    finalized_number: u64,
    finalized_hash: String,
    finalized_raw_body: &'a str,
    canonical_hash: String,
    canonical_raw_body: &'a str,
}

struct LaunchValues {
    adapter: Address,
    intent_queue: Address,
    mint_asset_id: B256,
    target_token: Address,
    btc_custody_address: bitcoin::Address,
    usdt_token: Address,
    oracle: Address,
    guard: Address,
    recovery: Address,
    signer_address: Address,
    network: Network,
    large_spend_threshold: U256,
}

struct Runtime {
    operator_id: String,
    adapter: Address,
    chain: ChainId,
    registry: Registry,
    metrics_address: SocketAddr,
    app: Router,
    tls: Arc<rustls::ServerConfig>,
    listener: tokio::net::TcpListener,
    event_state: EventLoopState,
}

#[tokio::main]
async fn main() -> Result<()> {
    xindex_ops::init_tracing();
    let args = Args::parse();
    validate_secret_file(&args.config)?;
    let config: Config =
        serde_json::from_slice(&fs::read(&args.config).context("read observer configuration")?)
            .context("decode strict observer configuration")?;
    validate_config(&config)?;
    run_runtime(build_runtime(&config).await?).await
}

#[expect(
    clippy::too_many_lines,
    reason = "startup deliberately binds finalized state, the exact roster, pinned transports, settlement ledgers, metrics, and event-loop readiness together"
)]
async fn build_runtime(config: &Config) -> Result<Runtime> {
    let launch = parse_launch_values(config)?;
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).context("register metrics")?;
    // Materialize readiness series before the first RPC succeeds. Otherwise an
    // observer stuck before its initial checkpoint would expose `up == 1` but
    // no stale/lag vector for Prometheus to evaluate.
    metrics
        .observer_checkpoint_height
        .with_label_values(&[&config.operator_id])
        .set(0);
    metrics
        .observer_finalized_head_height
        .with_label_values(&[&config.operator_id])
        .set(0);
    metrics
        .observer_last_sync_timestamp_seconds
        .with_label_values(&[&config.operator_id])
        .set(0);
    let evidence = EvidenceStore::open(&config.evidence_dir).context("open evidence store")?;
    let store = SqliteFinalizedObserverStore::connect(
        &config.observer_database_url,
        &format!("{}-{}", config.operator_id, config.chain),
    )
    .await
    .context("open finalized observer store")?;
    let thor_state = SqliteRegistryState::connect(&config.thor_state_database_url)
        .await
        .context("open THOR source-tip state")?;
    let rpc = FinalizedRpcClient::new(config.ethereum_rpc_url.clone())?;
    let chain = rpc.chain_id().await.context("read Ethereum chain id")?;
    if chain.value != config.expected_chain_id {
        anyhow::bail!(
            "Ethereum chain id {} differs from configured {}",
            chain.value,
            config.expected_chain_id
        );
    }
    verify_attestation_roster(config, &launch).await?;
    let signer = build_remote_signer(&config.signer, launch.signer_address).await?;
    let observer = build_observer(
        config,
        &launch,
        &metrics,
        &evidence,
        store.clone(),
        thor_state,
        signer.clone(),
    )?;
    let settlement_state = Arc::new(
        build_settlement_observer(config, &launch, store.clone(), signer, &evidence).await?,
    );
    let cancels = observer.cancel_source();
    cancels
        .replace_all(store.all_cancels().await.context("restore cancellations")?)
        .map_err(anyhow::Error::msg)?;

    let ready = Arc::new(AtomicBool::new(false));
    let last_sync_at = Arc::new(AtomicU64::new(0));
    if let Some(checkpoint) = store.last_checkpoint().await? {
        metrics
            .observer_checkpoint_height
            .with_label_values(&[&config.operator_id])
            .set(u64_to_i64(checkpoint.block_number));
    }

    let app_state = AppState {
        observer,
        settlement: settlement_state,
        store: store.clone(),
        rpc: rpc.clone(),
        evidence: evidence.clone(),
        operator_id: config.operator_id.clone(),
        ready: Arc::clone(&ready),
        last_sync_at: Arc::clone(&last_sync_at),
        max_sync_age_secs: (config.poll_interval_millis / 1_000)
            .saturating_mul(3)
            .max(15),
        metrics: metrics.clone(),
    };
    let app = Router::new()
        .route("/api/v1/certify-ric", post(handle_certify_ric))
        .route("/api/v1/certify-acc", post(handle_certify_acc))
        .route("/api/v1/settlement/mint", post(handle_settlement_mint))
        .route(
            "/api/v1/settlement/delivery",
            post(handle_settlement_delivery),
        )
        .route("/api/v1/settlement/refund", post(handle_settlement_refund))
        .route(
            "/api/v1/settlement/streamed",
            post(handle_settlement_streamed),
        )
        .route("/api/v1/health", get(|| async { "ok" }))
        .route("/api/v1/ready", get(handle_ready))
        .layer(DefaultBodyLimit::max(MAX_API_BODY_BYTES))
        .with_state(app_state);
    let tls = Arc::new(load_server_tls(config)?);
    let listener = tokio::net::TcpListener::bind(config.listen_address)
        .await
        .context("bind observer mTLS listener")?;
    let event_state = EventLoopState {
        operator_id: config.operator_id.clone(),
        adapter: launch.adapter,
        intent_queue: launch.intent_queue,
        mint_asset_id: launch.mint_asset_id,
        redemption_leg_index: config.redemption_leg_index,
        start_block: config.start_block,
        poll_interval: Duration::from_millis(config.poll_interval_millis),
        store,
        rpc,
        evidence,
        cancels,
        metrics,
        ready,
        last_sync_at,
    };
    Ok(Runtime {
        operator_id: config.operator_id.clone(),
        adapter: launch.adapter,
        chain: config.chain,
        registry,
        metrics_address: config.metrics_address,
        app,
        tls,
        listener,
        event_state,
    })
}

fn build_observer(
    config: &Config,
    launch: &LaunchValues,
    metrics: &Metrics,
    evidence: &EvidenceStore,
    store: SqliteFinalizedObserverStore,
    thor_state: SqliteRegistryState,
    signer: RemoteHsmBackend,
) -> Result<Arc<ProductionObserver>> {
    let asgard = PolicyAsgardSource {
        operator_id: config.operator_id.clone(),
        sources: Arc::new(build_sources(&config.sources)?),
        policy: config.inbound_policy.clone(),
        state: thor_state,
        evidence: evidence.clone(),
        poll_lock: Arc::new(tokio::sync::Mutex::new(())),
        metrics: metrics.clone(),
    };
    let halt = HttpHaltSource::finalized(config.ethereum_rpc_url.clone(), launch.guard);
    Ok(Arc::new(Observer::new(
        ObserverConfig {
            chain: config.chain,
            eth_chain_id: config.expected_chain_id,
            oracle: launch.oracle,
            btc_network: launch.network,
            stamp_window_secs: config.stamp_window_secs,
            large_spend_threshold: Some(launch.large_spend_threshold),
            large_spend_delay_secs: config.large_spend_delay_secs,
            cancel_recovery_dest: Some(launch.recovery),
            swap_back_asset: config.swap_back_asset.clone(),
        },
        asgard,
        store,
        signer,
        halt,
    )))
}

async fn build_settlement_observer(
    config: &Config,
    launch: &LaunchValues,
    store: SqliteFinalizedObserverStore,
    signer: RemoteHsmBackend,
    evidence: &EvidenceStore,
) -> Result<BtcSettlementObserver> {
    let consumed = Arc::new(
        AnyConsumedInflow::connect(Some(&config.settlement_database_url))
            .await
            .context("open durable ERC20 inflow ledger")?,
    );
    let native = Arc::new(
        AnyNativeInflow::connect(&config.settlement_database_url)
            .await
            .context("open durable native inflow ledger")?,
    );
    let thor_sources = config
        .sources
        .iter()
        .map(|source| {
            Ok((
                source.id.clone(),
                ThorClient::with_base_url(source.thornode_url.clone())?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    BtcSettlementObserver::new(
        BtcSettlementConfig {
            operator_id: config.operator_id.clone(),
            asset_id: launch.mint_asset_id,
            target_token: launch.target_token,
            btc_custody_address: launch.btc_custody_address.clone(),
            btc_network: launch.network,
            esplora_url: config.btc_esplora_url.clone(),
            btc_min_confirmations: config.btc_min_confirmations,
            btc_tolerance_sats: config.btc_tolerance_sats,
            usdt_token: launch.usdt_token,
            ethereum_rpc_url: config.ethereum_rpc_url.clone(),
            ethereum_lookback_blocks: config.ethereum_lookback_blocks,
            usdt_tolerance_1e6: config.usdt_tolerance_1e6,
        },
        store,
        thor_sources,
        signer,
        attestation_oracle_domain(config.expected_chain_id, launch.oracle),
        evidence.clone(),
        consumed,
        native,
    )
    .context("build finalized settlement observer")
}

async fn verify_attestation_roster(config: &Config, launch: &LaunchValues) -> Result<()> {
    let rpc_url = config
        .ethereum_rpc_url
        .parse()
        .context("parse Ethereum RPC URL")?;
    let provider = Arc::new(ProviderBuilder::new().on_http(rpc_url));
    let oracle = AttestationOracle::new(launch.oracle, provider);
    let onchain_threshold: usize = oracle
        .threshold()
        .call()
        .await
        .context("read attestation threshold")?
        ._0
        .try_into()
        .context("attestation threshold does not fit usize")?;
    let onchain_count: usize = oracle
        .signerCount()
        .call()
        .await
        .context("read attestation signer count")?
        ._0
        .try_into()
        .context("attestation signer count does not fit usize")?;
    if onchain_threshold != PRODUCTION_ATTESTATION_THRESHOLD
        || onchain_count != PRODUCTION_ATTESTATION_SIGNER_COUNT
    {
        anyhow::bail!("on-chain attestation topology must be exactly 3-of-5");
    }
    if !oracle
        .isSigner(launch.signer_address)
        .call()
        .await
        .context("read observer signer membership")?
        ._0
    {
        anyhow::bail!("operator signer is not active in AttestationOracle");
    }
    let queue = oracle
        .intentQueue()
        .call()
        .await
        .context("read oracle IntentQueue")?
        ._0;
    if queue != launch.intent_queue {
        anyhow::bail!("AttestationOracle IntentQueue differs from observer configuration");
    }
    Ok(())
}

async fn run_runtime(runtime: Runtime) -> Result<()> {
    tracing::info!(
        operator = %runtime.operator_id,
        adapter = %runtime.adapter,
        chain = %runtime.chain,
        "finalized observer starting"
    );
    let metrics_server = serve_metrics(runtime.registry, runtime.metrics_address);
    let api_server = serve_mtls(runtime.listener, runtime.tls, runtime.app);
    let event_loop = run_event_loop(runtime.event_state);
    tokio::select! {
        result = metrics_server => result.context("metrics server"),
        result = api_server => result.context("observer mTLS server"),
        result = event_loop => result.context("finalized event loop"),
    }
}

fn parse_launch_values(config: &Config) -> Result<LaunchValues> {
    let threshold = U256::from_str_radix(&config.large_spend_threshold, 10)
        .context("large_spend_threshold must be decimal")?;
    if threshold.is_zero() {
        anyhow::bail!("large_spend_threshold must be non-zero");
    }
    Ok(LaunchValues {
        adapter: parse_nonzero_address("thorchain_adapter", &config.thorchain_adapter)?,
        intent_queue: parse_nonzero_address("intent_queue", &config.intent_queue)?,
        mint_asset_id: parse_nonzero_b256("mint_asset_id", &config.mint_asset_id)?,
        target_token: parse_nonzero_address("target_token", &config.target_token)?,
        btc_custody_address: bitcoin::Address::from_str(&config.btc_custody_address)
            .context("parse btc_custody_address")?
            .require_network(parse_btc_network(&config.btc_network)?)
            .context("btc_custody_address network mismatch")?,
        usdt_token: parse_nonzero_address("usdt_token", &config.usdt_token)?,
        oracle: parse_nonzero_address("attestation_oracle", &config.attestation_oracle)?,
        guard: parse_nonzero_address("custody_guard", &config.custody_guard)?,
        recovery: parse_nonzero_address(
            "cancel_recovery_destination",
            &config.cancel_recovery_destination,
        )?,
        signer_address: parse_nonzero_address("signer address", &config.signer.address)?,
        network: parse_btc_network(&config.btc_network)?,
        large_spend_threshold: threshold,
    })
}

async fn run_event_loop(state: EventLoopState) -> Result<()> {
    loop {
        state.ready.store(false, Ordering::Release);
        reconcile_checkpoint(&state).await?;
        let head = state.rpc.finalized_head().await.context("finalized head")?;
        state
            .metrics
            .observer_finalized_head_height
            .with_label_values(&[&state.operator_id])
            .set(u64_to_i64(head.value.number));
        let next = state
            .store
            .last_checkpoint()
            .await?
            .map_or(state.start_block, |checkpoint| {
                checkpoint.block_number.saturating_add(1)
            });
        if next <= head.value.number {
            for number in next..=head.value.number {
                process_block(&state, &head, number).await?;
            }
        }
        let checkpoint = state.store.last_checkpoint().await?;
        if let Some(checkpoint) = checkpoint {
            if checkpoint.block_number > head.value.number {
                anyhow::bail!("durable checkpoint is ahead of finalized head");
            }
            if checkpoint.block_number == head.value.number
                && checkpoint.block_hash != head.value.hash
            {
                continue;
            }
            state
                .metrics
                .observer_checkpoint_height
                .with_label_values(&[&state.operator_id])
                .set(u64_to_i64(checkpoint.block_number));
            let now = now_unix()?;
            state.last_sync_at.store(now, Ordering::Release);
            state
                .metrics
                .observer_last_sync_timestamp_seconds
                .with_label_values(&[&state.operator_id])
                .set(u64_to_i64(now));
            state.ready.store(true, Ordering::Release);
        }
        tokio::time::sleep(state.poll_interval).await;
    }
}

async fn process_block(
    state: &EventLoopState,
    head: &RawRpcResponse<FinalizedBlock>,
    number: u64,
) -> Result<()> {
    let header = state.rpc.block_by_number(number).await?;
    if header.value.number != number
        || (number == head.value.number && header.value.hash != head.value.hash)
    {
        anyhow::bail!("block-by-number differs from selected finalized chain");
    }
    let now = now_unix()?;
    if header.value.timestamp > now.saturating_add(MAX_BLOCK_FUTURE_SKEW_SECS) {
        anyhow::bail!("finalized block timestamp is future-dated");
    }
    let topics = [
        ThorchainAdapter::Acquired::SIGNATURE_HASH,
        ThorchainAdapter::RedeemDispatched::SIGNATURE_HASH,
        ThorchainAdapter::AcquireCancelled::SIGNATURE_HASH,
        IntentQueue::MintIntentCreated::SIGNATURE_HASH,
    ];
    let logs = state
        .rpc
        .logs_by_block_hash(
            header.value.hash,
            &[state.adapter, state.intent_queue],
            &topics,
        )
        .await?;
    if logs.value.iter().any(|log| log.block_number != number) {
        anyhow::bail!("finalized log reports a different block number");
    }
    let evidence = EvmBlockEvidence {
        schema: "xindex.finalized-evm-block.v1",
        operator_id: &state.operator_id,
        finalized_head_number: head.value.number,
        finalized_head_hash: format!("{:#x}", head.value.hash),
        finalized_head_body: &head.raw_body,
        block_number: number,
        block_hash: format!("{:#x}", header.value.hash),
        parent_hash: format!("{:#x}", header.value.parent_hash),
        header_body: &header.raw_body,
        logs_body: &logs.raw_body,
    };
    state
        .evidence
        .persist_hashed(&format!("evm-finalized-{number}"), &evidence)
        .context("persist finalized block evidence")?;
    let (mints, legs, cancels) = decode_protocol_logs(
        state.adapter,
        state.intent_queue,
        state.redemption_leg_index,
        state.mint_asset_id,
        &logs.value,
    )?;
    state
        .store
        .commit_block(
            FinalizedCheckpoint {
                block_number: number,
                block_hash: header.value.hash,
                parent_hash: header.value.parent_hash,
                header_evidence_hash: header.response_hash,
                logs_evidence_hash: logs.response_hash,
            },
            now,
            &mints,
            &legs,
            &cancels,
        )
        .await?;
    for event in &cancels {
        state.cancels.insert(event.cancel_id, event.facts, now);
        state
            .metrics
            .observer_events
            .with_label_values(&["acquire_cancel", "observed"])
            .inc();
    }
    state
        .metrics
        .observer_events
        .with_label_values(&["mint_dispatch", "observed"])
        .inc_by(u64::try_from(mints.len()).unwrap_or(u64::MAX));
    state
        .metrics
        .observer_events
        .with_label_values(&["redemption_dispatch", "observed"])
        .inc_by(u64::try_from(legs.len()).unwrap_or(u64::MAX));
    Ok(())
}

async fn reconcile_checkpoint(state: &EventLoopState) -> Result<()> {
    let Some(checkpoint) = state.store.last_checkpoint().await? else {
        return Ok(());
    };
    let observed = state.rpc.block_by_number(checkpoint.block_number).await?;
    persist_canonical_check(state, checkpoint.block_hash, &observed)?;
    if observed.value.hash == checkpoint.block_hash {
        return Ok(());
    }
    state.metrics.observer_reorg_rollbacks.inc();
    let mut height = checkpoint.block_number;
    while height > state.start_block {
        height -= 1;
        let Some(stored_hash) = state.store.checkpoint_hash(height).await? else {
            continue;
        };
        let remote = state.rpc.block_by_number(height).await?;
        persist_canonical_check(state, stored_hash, &remote)?;
        if remote.value.hash == stored_hash {
            state.store.rollback_to(height, stored_hash).await?;
            state
                .cancels
                .replace_all(state.store.all_cancels().await?)
                .map_err(anyhow::Error::msg)?;
            tracing::error!(
                observer = %state.operator_id,
                ancestor = height,
                "finalized-chain hash changed; durable facts rolled back"
            );
            return Ok(());
        }
    }
    anyhow::bail!("no retained common ancestor for finalized checkpoint mismatch")
}

fn persist_canonical_check(
    state: &EventLoopState,
    expected_hash: B256,
    observed: &RawRpcResponse<FinalizedBlock>,
) -> Result<()> {
    state
        .evidence
        .persist_hashed(
            &format!("evm-canonical-check-{}", observed.value.number),
            &CanonicalCheckEvidence {
                schema: "xindex.finalized-canonical-check.v1",
                operator_id: &state.operator_id,
                block_number: observed.value.number,
                expected_hash: format!("{expected_hash:#x}"),
                observed_hash: format!("{:#x}", observed.value.hash),
                raw_body: &observed.raw_body,
            },
        )
        .context("persist canonical-check evidence")?;
    Ok(())
}

async fn handle_certify_ric(
    State(state): State<AppState>,
    Json(request): Json<ObserverCertifyRequest>,
) -> Result<Json<ObserverCertifyResponse>, (StatusCode, Json<ErrorBody>)> {
    ensure_canonical_ready(&state).await?;
    match state.observer.certify_ric(&request, now_unix_wire()?).await {
        Ok(response) => Ok(Json(response)),
        Err(error) => Err(render_observer_error(&error)),
    }
}

async fn handle_certify_acc(
    State(state): State<AppState>,
    Json(request): Json<ObserverCertifyAccRequest>,
) -> Result<Json<ObserverCertifyAccResponse>, (StatusCode, Json<ErrorBody>)> {
    ensure_canonical_ready(&state).await?;
    match state.observer.certify_acc(&request, now_unix_wire()?).await {
        Ok(response) => Ok(Json(response)),
        Err(error) => Err(render_observer_error(&error)),
    }
}

async fn handle_settlement_mint(
    State(state): State<AppState>,
    Json(request): Json<MintSettlementRequest>,
) -> Result<Json<SignedMintSettlement>, (StatusCode, Json<ErrorBody>)> {
    ensure_canonical_ready(&state).await?;
    match state
        .settlement
        .certify_mint(&request, now_unix_wire()?)
        .await
    {
        Ok(response) => {
            state
                .metrics
                .observer_events
                .with_label_values(&["mint_settlement", "signed"])
                .inc();
            Ok(Json(response))
        }
        Err(error) => {
            state
                .metrics
                .observer_events
                .with_label_values(&["mint_settlement", "refused"])
                .inc();
            Err(render_settlement_error(&error))
        }
    }
}

async fn handle_settlement_delivery(
    State(state): State<AppState>,
    Json(request): Json<RedemptionSettlementRequest>,
) -> Result<Json<SignedDeliverySettlement>, (StatusCode, Json<ErrorBody>)> {
    ensure_canonical_ready(&state).await?;
    match state
        .settlement
        .certify_delivery(&request, now_unix_wire()?)
        .await
    {
        Ok(response) => {
            state
                .metrics
                .observer_events
                .with_label_values(&["delivery_settlement", "signed"])
                .inc();
            Ok(Json(response))
        }
        Err(error) => {
            state
                .metrics
                .observer_events
                .with_label_values(&["delivery_settlement", "refused"])
                .inc();
            Err(render_settlement_error(&error))
        }
    }
}

async fn handle_settlement_refund(
    State(state): State<AppState>,
    Json(request): Json<RedemptionSettlementRequest>,
) -> Result<Json<SignedRefundSettlement>, (StatusCode, Json<ErrorBody>)> {
    ensure_canonical_ready(&state).await?;
    match state
        .settlement
        .certify_refund(&request, now_unix_wire()?)
        .await
    {
        Ok(response) => {
            state
                .metrics
                .observer_events
                .with_label_values(&["refund_settlement", "signed"])
                .inc();
            Ok(Json(response))
        }
        Err(error) => {
            state
                .metrics
                .observer_events
                .with_label_values(&["refund_settlement", "refused"])
                .inc();
            Err(render_settlement_error(&error))
        }
    }
}

async fn handle_settlement_streamed(
    State(state): State<AppState>,
    Json(request): Json<RedemptionSettlementRequest>,
) -> Result<Json<SignedStreamedSettlement>, (StatusCode, Json<ErrorBody>)> {
    ensure_canonical_ready(&state).await?;
    match state
        .settlement
        .certify_streamed(&request, now_unix_wire()?)
        .await
    {
        Ok(response) => {
            state
                .metrics
                .observer_events
                .with_label_values(&["streamed_settlement", "signed"])
                .inc();
            Ok(Json(response))
        }
        Err(error) => {
            state
                .metrics
                .observer_events
                .with_label_values(&["streamed_settlement", "refused"])
                .inc();
            Err(render_settlement_error(&error))
        }
    }
}

async fn handle_ready(State(state): State<AppState>) -> StatusCode {
    if readiness(&state) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn ensure_canonical_ready(state: &AppState) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if !readiness(state) {
        return Err(service_unavailable("observer checkpoint is not caught up"));
    }
    let checkpoint = state
        .store
        .last_checkpoint()
        .await
        .map_err(|_| service_unavailable("observer checkpoint read failed"))?
        .ok_or_else(|| service_unavailable("observer has no finalized checkpoint"))?;
    let head = state
        .rpc
        .finalized_head()
        .await
        .map_err(|_| service_unavailable("finalized head check failed"))?;
    let observed = state
        .rpc
        .block_by_number(checkpoint.block_number)
        .await
        .map_err(|_| service_unavailable("canonical block check failed"))?;
    state
        .evidence
        .persist_hashed(
            &format!("evm-presign-check-{}", checkpoint.block_number),
            &PreSignCheckEvidence {
                schema: "xindex.finalized-presign-check.v1",
                operator_id: &state.operator_id,
                expected_number: checkpoint.block_number,
                expected_hash: format!("{:#x}", checkpoint.block_hash),
                finalized_number: head.value.number,
                finalized_hash: format!("{:#x}", head.value.hash),
                finalized_raw_body: &head.raw_body,
                canonical_hash: format!("{:#x}", observed.value.hash),
                canonical_raw_body: &observed.raw_body,
            },
        )
        .map_err(|_| service_unavailable("pre-sign evidence persistence failed"))?;
    if observed.value.hash != checkpoint.block_hash
        || head.value.number != checkpoint.block_number
        || head.value.hash != checkpoint.block_hash
    {
        state.ready.store(false, Ordering::Release);
        return Err(service_unavailable(
            "observer checkpoint is no longer the finalized head",
        ));
    }
    Ok(())
}

fn readiness(state: &AppState) -> bool {
    if !state.ready.load(Ordering::Acquire) {
        return false;
    }
    let last = state.last_sync_at.load(Ordering::Acquire);
    now_unix().is_ok_and(|now| last != 0 && now.saturating_sub(last) <= state.max_sync_age_secs)
}

fn render_observer_error(error: &ObserverError) -> (StatusCode, Json<ErrorBody>) {
    let status = match error {
        ObserverError::EventNotFound { .. } | ObserverError::CancelNotFound { .. } => {
            StatusCode::NOT_FOUND
        }
        ObserverError::AsgardUnavailable(_)
        | ObserverError::LegSource(_)
        | ObserverError::SignerUnavailable(_)
        | ObserverError::HaltUnavailable(_)
        | ObserverError::CancelDisabled => StatusCode::SERVICE_UNAVAILABLE,
        ObserverError::Halted => StatusCode::LOCKED,
        ObserverError::FraudWindowActive { .. } => StatusCode::TOO_EARLY,
        ObserverError::ChainUnsupported(_)
        | ObserverError::BadRequest(_)
        | ObserverError::EventInvalid(_)
        | ObserverError::StampOutOfWindow(_)
        | ObserverError::MemoRejected(_) => StatusCode::UNPROCESSABLE_ENTITY,
    };
    (
        status,
        Json(ErrorBody {
            code: error.error_code().to_string(),
            message: error.to_string(),
        }),
    )
}

fn render_settlement_error(error: &SettlementObserverError) -> (StatusCode, Json<ErrorBody>) {
    let status = match error {
        SettlementObserverError::BadRequest(_) | SettlementObserverError::Configuration(_) => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        SettlementObserverError::NotFound => StatusCode::NOT_FOUND,
        SettlementObserverError::NotReady(_)
        | SettlementObserverError::Journal(_)
        | SettlementObserverError::Mint(_)
        | SettlementObserverError::Redemption(_)
        | SettlementObserverError::Evidence(_)
        | SettlementObserverError::Bitcoin(_)
        | SettlementObserverError::Ethereum(_)
        | SettlementObserverError::Signer(_)
        | SettlementObserverError::Worker => StatusCode::SERVICE_UNAVAILABLE,
    };
    (
        status,
        Json(ErrorBody {
            code: "settlement_refused".to_string(),
            message: error.to_string(),
        }),
    )
}

fn service_unavailable(message: &str) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorBody {
            code: "observer_not_ready".to_string(),
            message: message.to_string(),
        }),
    )
}

fn now_unix_wire() -> Result<u64, (StatusCode, Json<ErrorBody>)> {
    now_unix().map_err(|_| service_unavailable("system clock is before Unix epoch"))
}

async fn build_remote_signer(
    config: &SignerConfig,
    signer_address: Address,
) -> Result<RemoteHsmBackend> {
    let cert = fs::read(&config.client_cert_pem).context("read signer client certificate")?;
    let key = fs::read(&config.client_key_pem).context("read signer client TLS key")?;
    let roots = fs::read(&config.server_ca_pem).context("read signer server CA")?;
    let url = config.url.clone();
    let timeout = Duration::from_secs(config.timeout_secs);
    tokio::task::spawn_blocking(move || {
        RemoteHsmBackend::with_mtls_pem(url, signer_address, &cert, &key, &roots, timeout)
    })
    .await
    .context("build remote signer task")?
    .context("build remote signer")
}

fn build_sources(configs: &[SourceConfig]) -> Result<Vec<ThorSourceClient>> {
    configs
        .iter()
        .map(|source| {
            Ok(ThorSourceClient::new(
                source.id.clone(),
                ThorClient::with_base_url(source.thornode_url.clone())?,
                ThorConsensusClient::with_base_url(source.consensus_url.clone())?,
            ))
        })
        .collect()
}

fn raw_source_evidence(poll: &RawSourcePoll) -> RawSourceEvidence<'_> {
    RawSourceEvidence {
        source_id: &poll.source_id,
        observed_at: poll.observed_at,
        inbound_body: &poll.inbound.raw_body,
        mimir_body: &poll.mimir.raw_body,
        pools_body: &poll.pools.raw_body,
        consensus_body: &poll.consensus.raw_body,
    }
}

fn load_server_tls(config: &Config) -> Result<rustls::ServerConfig> {
    let server_cert = fs::read(&config.server_cert_pem).context("read server certificate")?;
    let server_key = fs::read(&config.server_key_pem).context("read server TLS key")?;
    let client_roots = config
        .coordinator_client_cert_pems
        .iter()
        .map(fs::read)
        .collect::<std::io::Result<Vec<_>>>()
        .context("read coordinator client roots")?;
    server_config(
        load_cert_chain(&server_cert)?,
        load_private_key(&server_key)?,
        pinned_root_store(&client_roots)?,
    )
    .context("build observer mTLS server")
}

#[expect(
    clippy::too_many_lines,
    reason = "the production startup gate validates every identity, durable path, source origin, and launch invariant in one fail-closed pass"
)]
fn validate_config(config: &Config) -> Result<()> {
    validate_public_id(&config.operator_id)?;
    if config.expected_chain_id == 0
        || config.start_block == 0
        || !(500..=30_000).contains(&config.poll_interval_millis)
        || config.stamp_window_secs == 0
        || config.stamp_window_secs > 120
        || config.large_spend_delay_secs < 1_800
        || config.signer.timeout_secs == 0
        || config.redemption_leg_index != 0
        || config.chain != ChainId::Btc
        || config.sources.len() != 3
        || config.coordinator_client_cert_pems.is_empty()
        || config.btc_min_confirmations < 6
        || config.ethereum_lookback_blocks == 0
        || config.ethereum_lookback_blocks > 250_000
        || config.btc_tolerance_sats > 10_000
        || config.usdt_tolerance_1e6 > 10_000
        || config.expected_attestation_signer_count != PRODUCTION_ATTESTATION_SIGNER_COUNT
        || config.expected_attestation_threshold != PRODUCTION_ATTESTATION_THRESHOLD
    {
        anyhow::bail!(
            "invalid production observer count/time/launch policy; attestation topology must be exactly 3-of-5"
        );
    }
    if config.inbound_policy.source_chain != "ETH"
        || !config
            .inbound_policy
            .enabled_chains
            .iter()
            .any(|chain| chain == "BTC")
        || !config
            .inbound_policy
            .enabled_chains
            .iter()
            .any(|chain| chain == "ETH")
    {
        anyhow::bail!("inbound policy must validate ETH source plus BTC target");
    }
    if config.observer_database_url == config.thor_state_database_url
        || config.observer_database_url == config.settlement_database_url
        || config.thor_state_database_url == config.settlement_database_url
    {
        anyhow::bail!("observer, THOR state, and settlement databases must be separate files");
    }
    validate_database_url(&config.observer_database_url)?;
    validate_database_url(&config.thor_state_database_url)?;
    validate_database_url(&config.settlement_database_url)?;
    validate_owner_only_directory(&config.evidence_dir)?;
    if !config.metrics_address.ip().is_loopback() {
        anyhow::bail!("metrics_address must bind loopback");
    }
    endpoint_origin("ethereum_rpc_url", &config.ethereum_rpc_url, false)?;
    endpoint_origin("btc_esplora_url", &config.btc_esplora_url, false)?;
    endpoint_origin("signer.url", &config.signer.url, true)?;
    let mut source_ids = HashSet::new();
    let mut thor_origins = HashSet::new();
    let mut consensus_origins = HashSet::new();
    for source in &config.sources {
        validate_public_id(&source.id)?;
        if !source_ids.insert(source.id.clone())
            || !thor_origins.insert(endpoint_origin(
                "source.thornode_url",
                &source.thornode_url,
                true,
            )?)
            || !consensus_origins.insert(endpoint_origin(
                "source.consensus_url",
                &source.consensus_url,
                true,
            )?)
        {
            anyhow::bail!("THOR source identities and origins must be distinct");
        }
    }
    validate_secret_file(&config.server_key_pem)?;
    validate_secret_file(&config.signer.client_key_pem)?;
    for path in [
        &config.server_cert_pem,
        &config.signer.client_cert_pem,
        &config.signer.server_ca_pem,
    ] {
        validate_regular_file(path)?;
    }
    for path in &config.coordinator_client_cert_pems {
        validate_regular_file(path)?;
    }
    let adapter = parse_nonzero_address("thorchain_adapter", &config.thorchain_adapter)?;
    let intent_queue = parse_nonzero_address("intent_queue", &config.intent_queue)?;
    parse_nonzero_address("attestation_oracle", &config.attestation_oracle)?;
    parse_nonzero_address("target_token", &config.target_token)?;
    parse_nonzero_address("usdt_token", &config.usdt_token)?;
    parse_nonzero_address("custody_guard", &config.custody_guard)?;
    parse_nonzero_address(
        "cancel_recovery_destination",
        &config.cancel_recovery_destination,
    )?;
    parse_nonzero_address("signer address", &config.signer.address)?;
    parse_nonzero_b256("mint_asset_id", &config.mint_asset_id)?;
    if adapter == intent_queue {
        anyhow::bail!("thorchain_adapter and intent_queue must differ");
    }
    parse_btc_network(&config.btc_network)?;
    bitcoin::Address::from_str(&config.btc_custody_address)
        .context("parse btc_custody_address")?
        .require_network(parse_btc_network(&config.btc_network)?)
        .context("btc_custody_address network mismatch")?;
    Ok(())
}

fn endpoint_origin(label: &str, raw: &str, require_https: bool) -> Result<String> {
    let url = reqwest::Url::parse(raw).with_context(|| format!("{label} must be a URL"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("{label} must not contain userinfo, query, or fragment");
    }
    let host = url.host_str().context("endpoint has no host")?;
    let host_ip = host.trim_start_matches('[').trim_end_matches(']');
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host_ip
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if require_https && url.scheme() != "https" {
        anyhow::bail!("{label} must use HTTPS");
    }
    if !require_https && url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        anyhow::bail!("{label} must use HTTPS or loopback HTTP");
    }
    let port = url
        .port_or_known_default()
        .context("endpoint has no usable port")?;
    Ok(format!(
        "{}://{}:{port}",
        url.scheme(),
        host.to_ascii_lowercase()
    ))
}

fn validate_database_url(url: &str) -> Result<()> {
    let raw = url
        .strip_prefix("sqlite://")
        .context("database URL must use sqlite:///absolute/path")?;
    let path = Path::new(raw.split('?').next().context("database path absent")?);
    if !path.is_absolute() {
        anyhow::bail!("database path must be absolute");
    }
    validate_owner_only_directory(path.parent().context("database parent absent")?)
}

fn validate_owner_only_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect durable directory {}", path.display()))?;
    if !metadata.file_type().is_dir() {
        anyhow::bail!("durable path must be a non-symlink directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("durable directory must be owner-only");
        }
    }
    Ok(())
}

fn validate_regular_file(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("configured path must be a non-symlink regular file");
    }
    Ok(())
}

fn validate_secret_file(path: &Path) -> Result<()> {
    validate_regular_file(path)?;
    if !path.is_absolute() {
        anyhow::bail!("secret/config file path must be absolute");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = fs::symlink_metadata(path)?;
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            anyhow::bail!("secret/config file must be owner-only and single-link");
        }
    }
    Ok(())
}

fn validate_public_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        anyhow::bail!("operator/source id must be safe ASCII");
    }
    Ok(())
}

fn parse_nonzero_address(label: &str, raw: &str) -> Result<Address> {
    let address = Address::from_str(raw).with_context(|| format!("parse {label}"))?;
    if address.is_zero() {
        anyhow::bail!("{label} must be non-zero");
    }
    Ok(address)
}

fn parse_nonzero_b256(label: &str, raw: &str) -> Result<B256> {
    let value = B256::from_str(raw).with_context(|| format!("parse {label}"))?;
    if value == B256::ZERO {
        anyhow::bail!("{label} must be non-zero");
    }
    Ok(value)
}

fn parse_btc_network(raw: &str) -> Result<Network> {
    match raw {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        _ => anyhow::bail!("production finalized observer supports Bitcoin mainnet only"),
    }
}

fn now_unix() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .context("system clock is before Unix epoch")
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_policy_rejects_credentials_and_plaintext_public_hosts() {
        assert!(endpoint_origin("rpc", "https://rpc.example", false).is_ok());
        assert!(endpoint_origin("rpc", "http://127.0.0.1:8545", false).is_ok());
        assert!(endpoint_origin("rpc", "http://rpc.example", false).is_err());
        assert!(endpoint_origin("rpc", "https://user:secret@rpc.example", false).is_err());
        assert!(endpoint_origin("signer", "http://127.0.0.1:9000", true).is_err());
    }
}
