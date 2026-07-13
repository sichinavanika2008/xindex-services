//! Untrusted `THORChain` candidate producer, exact quorum collector, inbound
//! poster, and canonical quote-hint service.
//!
//! This process has no protocol signing key. Its poster address is delegated to
//! a node-managed signer and has no authority beyond permissionless registry
//! submission. Every value-moving authorization still requires an exact
//! threshold of independently operated registry signers.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::eips::{BlockId, BlockNumberOrTag};
use alloy::providers::{Provider, ProviderBuilder, ReqwestProvider};
use alloy::rpc::types::BlockTransactionsKind;
use alloy::sol;
use alloy::transports::Transport;
use alloy_primitives::{Address, Bytes, B256, U256};
use anyhow::{Context, Result};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use clap::Parser;
use futures_util::future::join_all;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperBuilder;
use hyper_util::service::TowerToHyperService;
use prometheus::Registry;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{mpsc, Notify};
use tokio_rustls::TlsAcceptor;
use xindex_chain_eth::bindings::{IndexFactory, ThorchainAdapter, ThorchainVaultRegistry};
use xindex_chain_eth::rpc::is_transient_rpc_error;
use xindex_chain_thor::{
    derive_inbound, evaluate_quote, evm_raw_to_thor, validate_common_quote,
    ExternalPriceObservation, InboundCandidate, InboundPolicy, QuoteCandidate, QuoteDecision,
    QuoteEvidence, QuotePolicy, RawResponse, RawSourcePoll, SwapQuoteRequest, SwapQuoteResponse,
    ThorClient, ThorConsensusClient, ThorSourceClient, TipCheckpoint,
};
use xindex_ops::{serve_metrics, Metrics};
use xindex_relayer::registry_collector::{
    inbound_payload_from_message, quote_payload_from_message, CollectOutcome, InboundPayload,
    QuotePayload, ReadyInbound, ReadyQuote, RegistryCollector,
};
use xindex_relayer::registry_hints::{encode_acquire_hints, quote_payload_from_candidate};
use xindex_shared::eip712::thorchain_registry_domain;
use xindex_shared::evidence::EvidenceStore;
use xindex_shared::registry_state::{SqliteRegistryState, TipAdvance};
use xindex_shared::registry_wire::{SignedInboundStateMessage, SignedQuoteAuthorizationMessage};
use xindex_signer_daemon::price_venue::{
    BinanceVenue, CoinbaseVenue, KrakenVenue, PriceVenue, SourcedValue, VenueError,
};

const PRODUCTION_REGISTRY_SIGNER_COUNT: usize = 5;
const PRODUCTION_REGISTRY_THRESHOLD: usize = 3;

#[derive(Debug)]
struct PriceFleet {
    binance: BinanceVenue,
    coinbase: CoinbaseVenue,
    kraken: KrakenVenue,
}

#[derive(Debug)]
struct PricePair {
    source_id: &'static str,
    funding: SourcedValue,
    target: SourcedValue,
}

sol! {
    #[sol(rpc)]
    interface IERC20Metadata {
        function decimals() external view returns (uint8);
    }
}

#[derive(Debug, Parser)]
struct Args {
    /// Strict JSON production configuration.
    config: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    chain_id: u64,
    registry_contract: String,
    poster_address: String,
    ethereum_rpc_url: String,
    operator_id: String,
    database_url: String,
    evidence_dir: PathBuf,
    listen_address: SocketAddr,
    metrics_address: SocketAddr,
    inbound_interval_secs: u64,
    report_validity_secs: u64,
    quote_wait_secs: u64,
    post_attempts: u32,
    retry_base_ms: u64,
    retry_max_ms: u64,
    inbound_policy: InboundPolicy,
    quote_policy: QuotePolicy,
    sources: Vec<SourceConfig>,
    routes: Vec<RouteConfig>,
    asset_prices: Vec<AssetPriceConfig>,
    binance_base: String,
    coinbase_base: String,
    kraken_base: String,
    signers: Vec<SignerConfig>,
    threshold: usize,
    signer_timeout_secs: u64,
    signer_client_identity_pem: PathBuf,
    signer_server_ca_pems: Vec<PathBuf>,
    server_cert_pem: PathBuf,
    server_key_pem: PathBuf,
    pinned_client_cert_pems: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceConfig {
    id: String,
    thornode_url: String,
    consensus_url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RouteConfig {
    adapter: String,
    funding_token: String,
    funding_asset: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetPriceConfig {
    asset: String,
    binance: String,
    coinbase: String,
    kraken: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerConfig {
    address: String,
    url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QuoteBuildRequest {
    adapter: String,
    index_token: String,
    originator: String,
    funding_token: String,
    target_token: String,
    amount_in: String,
    liquidity_tolerance_bps: u16,
    streaming_interval: u64,
    streaming_quantity: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct QuoteHintsResponse {
    hints: String,
    min_out_native: String,
    dispatch_deadline: u64,
    quote_nonce: u64,
    quote_hash: String,
    memo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InboundSignatureSubmission {
    candidate: InboundCandidate,
    signed: SignedInboundStateMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QuoteSignatureSubmission {
    candidate: QuoteCandidate,
    signed: SignedQuoteAuthorizationMessage,
}

struct AppState {
    chain_id: u64,
    registry_address: Address,
    provider: Arc<ReqwestProvider>,
    durable_state: SqliteRegistryState,
    evidence: EvidenceStore,
    operator_id: String,
    inbound_policy: InboundPolicy,
    quote_policy: QuotePolicy,
    report_validity_secs: u64,
    quote_wait_secs: u64,
    sources: Vec<ThorSourceClient>,
    routes: HashMap<(Address, Address), RouteConfig>,
    asset_prices: HashMap<String, AssetPriceConfig>,
    prices: PriceFleet,
    signer_client: reqwest::Client,
    signer_urls: Vec<String>,
    collector: Arc<Mutex<RegistryCollector>>,
    inbound_ready_tx: mpsc::Sender<ReadyInbound>,
    quote_candidates: Mutex<HashMap<QuotePayload, QuoteCandidate>>,
    ready_quotes: Mutex<HashMap<QuotePayload, ReadyQuote>>,
    quote_notify: Notify,
    quote_build_lock: tokio::sync::Mutex<()>,
    metrics: Metrics,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppState")
            .field("chain_id", &self.chain_id)
            .field("registry_address", &self.registry_address)
            .field("operator_id", &self.operator_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct FinalizedBlock {
    id: BlockId,
    number: u64,
    hash: B256,
}

#[derive(Debug)]
struct QuoteChainState {
    block: FinalizedBlock,
    vault: Address,
    router: Address,
    valid_until: u64,
    inbound_hash: B256,
    quote_nonce: u64,
    custody_address: String,
    custody_hash: B256,
    memo_asset: String,
    target_token: Address,
    funding_decimals: u8,
}

#[derive(Debug)]
enum ApiError {
    Refused(&'static str),
    Dependency(&'static str),
    Timeout,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, component) = match self {
            Self::Refused(component) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "request_refused",
                component,
            ),
            Self::Dependency(component) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "dependency_unavailable",
                component,
            ),
            Self::Timeout => (StatusCode::GATEWAY_TIMEOUT, "quorum_timeout", "signers"),
        };
        tracing::warn!(
            error_code = code,
            component,
            "registry coordinator request failed"
        );
        (status, Json(json!({"error": code}))).into_response()
    }
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
struct InboundProducerEvidence<'a> {
    schema: &'static str,
    operator_id: &'a str,
    finalized_block_number: u64,
    finalized_block_hash: String,
    candidate: Option<&'a InboundCandidate>,
    sources: Vec<RawSourceEvidence<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawPriceEvidence<'a> {
    source_id: &'a str,
    funding_subject: &'a str,
    funding_value_wad: String,
    funding_raw_response: &'a str,
    target_subject: &'a str,
    target_value_wad: String,
    target_raw_response: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawQuoteEvidence<'a> {
    source_id: &'a str,
    response_hash: String,
    raw_response: &'a str,
    decision: &'a QuoteDecision,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QuoteProducerEvidence<'a> {
    schema: &'static str,
    operator_id: &'a str,
    finalized_block_number: u64,
    finalized_block_hash: String,
    candidate: &'a QuoteCandidate,
    prices: Vec<RawPriceEvidence<'a>>,
    quotes: Vec<RawQuoteEvidence<'a>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    xindex_ops::init_tracing();
    run(Args::parse()).await
}

#[expect(
    clippy::too_many_lines,
    reason = "fail-closed startup validates roster, source, TLS, poster, and storage boundaries together"
)]
async fn run(args: Args) -> Result<()> {
    validate_secret_file(&args.config)?;
    let raw = fs::read(&args.config).context("read registry coordinator config")?;
    let config: Config =
        serde_json::from_slice(&raw).context("parse registry coordinator config")?;
    validate_config(&config)?;
    let registry_address = parse_nonzero_address("registry_contract", &config.registry_contract)?;
    let poster_address = parse_nonzero_address("poster_address", &config.poster_address)?;
    let read_provider = Arc::new(
        ProviderBuilder::new().on_http(
            config
                .ethereum_rpc_url
                .parse()
                .context("Ethereum RPC URL")?,
        ),
    );
    let actual_chain_id = read_provider
        .get_chain_id()
        .await
        .context("read chain id")?;
    if actual_chain_id != config.chain_id {
        anyhow::bail!("configured chain id differs from RPC chain id");
    }
    let roster = config
        .signers
        .iter()
        .map(|signer| parse_nonzero_address("signer address", &signer.address))
        .collect::<Result<Vec<_>>>()?;
    verify_roster(&read_provider, registry_address, &roster, config.threshold).await?;
    let domain = thorchain_registry_domain(config.chain_id, registry_address);
    let collector = RegistryCollector::new(domain, roster, config.threshold)
        .context("construct registry collector")?;
    let durable_state = SqliteRegistryState::connect(&config.database_url)
        .await
        .context("open durable registry state")?;
    let evidence = EvidenceStore::open(&config.evidence_dir).context("open evidence store")?;
    let sources = config
        .sources
        .iter()
        .map(|source| {
            Ok(ThorSourceClient::new(
                source.id.clone(),
                ThorClient::with_base_url(&source.thornode_url)?,
                ThorConsensusClient::with_base_url(&source.consensus_url)?,
            ))
        })
        .collect::<Result<Vec<_>, xindex_chain_thor::ThorError>>()
        .context("construct THOR sources")?;
    let routes = config
        .routes
        .iter()
        .map(|route| {
            Ok((
                (
                    parse_nonzero_address("route adapter", &route.adapter)?,
                    parse_nonzero_address("route funding token", &route.funding_token)?,
                ),
                route.clone(),
            ))
        })
        .collect::<Result<HashMap<_, _>>>()?;
    let asset_prices = config
        .asset_prices
        .iter()
        .map(|asset| (asset.asset.clone(), asset.clone()))
        .collect();
    let public_http = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.signer_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build public-data client")?;
    let prices = PriceFleet {
        binance: BinanceVenue::new(public_http.clone(), config.binance_base.clone()),
        coinbase: CoinbaseVenue::new(public_http.clone(), config.coinbase_base.clone()),
        kraken: KrakenVenue::new(public_http, config.kraken_base.clone()),
    };
    let signer_client = signer_client(&config)?;
    let signer_urls = config
        .signers
        .iter()
        .map(|signer| signer.url.trim_end_matches('/').to_string())
        .collect();
    let tls = Arc::new(load_server_tls(&config)?);

    let prometheus = Registry::new();
    let metrics = Metrics::new(&prometheus).context("register metrics")?;
    for kind in ["source_poll", "inbound_post"] {
        // Ensure stale alerts see a zero baseline even before the first
        // successful production/post round; absent Prometheus series do not
        // satisfy arithmetic alert expressions.
        metrics
            .registry_last_success_timestamp_seconds
            .with_label_values(&[kind])
            .set(0);
    }
    let metrics_address = config.metrics_address;

    let (inbound_ready_tx, inbound_ready_rx) = mpsc::channel(64);
    let state = Arc::new(AppState {
        chain_id: config.chain_id,
        registry_address,
        provider: read_provider,
        durable_state,
        evidence,
        operator_id: config.operator_id,
        inbound_policy: config.inbound_policy,
        quote_policy: config.quote_policy,
        report_validity_secs: config.report_validity_secs,
        quote_wait_secs: config.quote_wait_secs,
        sources,
        routes,
        asset_prices,
        prices,
        signer_client,
        signer_urls,
        collector: Arc::new(Mutex::new(collector)),
        inbound_ready_tx,
        quote_candidates: Mutex::new(HashMap::new()),
        ready_quotes: Mutex::new(HashMap::new()),
        quote_notify: Notify::new(),
        quote_build_lock: tokio::sync::Mutex::new(()),
        metrics,
    });

    let poster_provider = Arc::new(
        ProviderBuilder::new()
            .with_recommended_fillers()
            .on_http(config.ethereum_rpc_url.parse().context("poster RPC URL")?),
    );
    let poster = inbound_poster(
        inbound_ready_rx,
        poster_provider,
        registry_address,
        poster_address,
        config.post_attempts,
        config.retry_base_ms,
        config.retry_max_ms,
        state.metrics.clone(),
    );
    let producer_state = state.clone();
    let producer = inbound_producer_loop(producer_state, config.inbound_interval_secs);

    let app = Router::new()
        .route(
            "/api/v1/registry/inbound-signatures",
            post(collect_inbound_submission),
        )
        .route(
            "/api/v1/registry/quote-signatures",
            post(collect_quote_submission),
        )
        .route("/api/v1/registry/quote", post(build_quote))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(config.listen_address)
        .await
        .context("bind coordinator mTLS listener")?;
    tracing::info!(address = %config.listen_address, "registry coordinator mTLS listener ready");
    let api_server = serve_mtls(listener, tls, app);
    let metrics_server = serve_metrics(prometheus, metrics_address);
    tokio::select! {
        result = api_server => match result {
            Ok(()) => Err(anyhow::anyhow!("registry coordinator API exited unexpectedly")),
            Err(error) => Err(anyhow::anyhow!("registry coordinator API failed: {error}")),
        },
        result = metrics_server => match result {
            Ok(()) => Err(anyhow::anyhow!("registry coordinator metrics server exited unexpectedly")),
            Err(error) => Err(anyhow::anyhow!("registry coordinator metrics server failed: {error}")),
        },
        () = poster => Err(anyhow::anyhow!("registry inbound poster exited unexpectedly")),
        () = producer => Err(anyhow::anyhow!("registry inbound producer exited unexpectedly")),
    }
}

async fn collect_inbound_submission(
    State(state): State<Arc<AppState>>,
    Json(submission): Json<InboundSignatureSubmission>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let now = now_unix().map_err(|_| ApiError::Dependency("clock"))?;
    ingest_inbound_submission(&state, submission, now).await
}

async fn ingest_inbound_submission(
    state: &Arc<AppState>,
    submission: InboundSignatureSubmission,
    now: u64,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let expected = inbound_payload_from_candidate(&submission.candidate)
        .map_err(|_| ApiError::Refused("inbound_candidate"))?;
    let signed = inbound_payload_from_message(&submission.signed)
        .map_err(|_| ApiError::Refused("inbound_message"))?;
    if expected != signed {
        return Err(ApiError::Refused("inbound_envelope_mismatch"));
    }
    state
        .evidence
        .persist_hashed(
            &format!("collector-inbound-{}", expected.sequence),
            &submission,
        )
        .map_err(|_| ApiError::Dependency("evidence_store"))?;
    let outcome = state
        .collector
        .lock()
        .map_err(|_| ApiError::Dependency("collector_lock"))?
        .ingest_inbound(&submission.signed, now)
        .map_err(|_| ApiError::Refused("inbound_signature"))?;
    match outcome {
        CollectOutcome::Accepted { count } => Ok((
            StatusCode::ACCEPTED,
            Json(json!({"status": "accepted", "signatures": count})),
        )),
        CollectOutcome::Duplicate { count } => Ok((
            StatusCode::OK,
            Json(json!({"status": "duplicate", "signatures": count})),
        )),
        CollectOutcome::Ready(ready) => {
            let count = ready.signatures.len();
            state
                .inbound_ready_tx
                .send(ready)
                .await
                .map_err(|_| ApiError::Dependency("poster_worker"))?;
            Ok((
                StatusCode::ACCEPTED,
                Json(json!({"status": "quorum", "signatures": count})),
            ))
        }
    }
}

async fn collect_quote_submission(
    State(state): State<Arc<AppState>>,
    Json(submission): Json<QuoteSignatureSubmission>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let now = now_unix().map_err(|_| ApiError::Dependency("clock"))?;
    ingest_quote_submission(&state, &submission, now)
}

fn ingest_quote_submission(
    state: &Arc<AppState>,
    submission: &QuoteSignatureSubmission,
    now: u64,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let expected = quote_payload_from_candidate(&submission.candidate)
        .map_err(|_| ApiError::Refused("quote_candidate"))?;
    let signed = quote_payload_from_message(&submission.signed)
        .map_err(|_| ApiError::Refused("quote_message"))?;
    if expected != signed {
        return Err(ApiError::Refused("quote_envelope_mismatch"));
    }
    state
        .evidence
        .persist_hashed(
            &format!("collector-quote-{}", expected.quote_nonce),
            &submission,
        )
        .map_err(|_| ApiError::Dependency("evidence_store"))?;
    {
        let mut candidates = state
            .quote_candidates
            .lock()
            .map_err(|_| ApiError::Dependency("candidate_lock"))?;
        if let Some(existing) = candidates.get(&expected) {
            if existing != &submission.candidate {
                return Err(ApiError::Refused("quote_candidate_conflict"));
            }
        } else {
            candidates.insert(expected, submission.candidate.clone());
        }
    }
    let outcome = state
        .collector
        .lock()
        .map_err(|_| ApiError::Dependency("collector_lock"))?
        .ingest_quote(&submission.signed, now)
        .map_err(|_| ApiError::Refused("quote_signature"))?;
    match outcome {
        CollectOutcome::Accepted { count } => Ok((
            StatusCode::ACCEPTED,
            Json(json!({"status": "accepted", "signatures": count})),
        )),
        CollectOutcome::Duplicate { count } => Ok((
            StatusCode::OK,
            Json(json!({"status": "duplicate", "signatures": count})),
        )),
        CollectOutcome::Ready(ready) => {
            let count = ready.signatures.len();
            state
                .ready_quotes
                .lock()
                .map_err(|_| ApiError::Dependency("ready_quote_lock"))?
                .insert(ready.payload, ready);
            state.quote_notify.notify_waiters();
            Ok((
                StatusCode::ACCEPTED,
                Json(json!({"status": "quorum", "signatures": count})),
            ))
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "quote production binds every request field to one finalized chain view and complete raw evidence"
)]
async fn build_quote(
    State(state): State<Arc<AppState>>,
    Json(request): Json<QuoteBuildRequest>,
) -> Result<Json<QuoteHintsResponse>, ApiError> {
    let _guard = state.quote_build_lock.lock().await;
    let now = now_unix().map_err(|_| ApiError::Dependency("clock"))?;
    cleanup_quotes(&state, now)?;
    let adapter = Address::from_str(&request.adapter).map_err(|_| ApiError::Refused("adapter"))?;
    let funding_token = Address::from_str(&request.funding_token)
        .map_err(|_| ApiError::Refused("funding_token"))?;
    let index_token =
        Address::from_str(&request.index_token).map_err(|_| ApiError::Refused("index_token"))?;
    let originator =
        Address::from_str(&request.originator).map_err(|_| ApiError::Refused("originator"))?;
    let target_token =
        Address::from_str(&request.target_token).map_err(|_| ApiError::Refused("target_token"))?;
    let amount_in =
        U256::from_str_radix(&request.amount_in, 10).map_err(|_| ApiError::Refused("amount_in"))?;
    let route = state
        .routes
        .get(&(adapter, funding_token))
        .ok_or(ApiError::Refused("route_allowlist"))?;
    let chain = quote_chain_state(
        &state.provider,
        state.registry_address,
        adapter,
        funding_token,
        index_token,
        originator,
    )
    .await
    .map_err(|_| ApiError::Dependency("finalized_quote_reads"))?;
    if target_token != chain.target_token || chain.router == Address::ZERO {
        return Err(ApiError::Refused("target_or_router"));
    }
    let amount_thor = evm_raw_to_thor(amount_in, chain.funding_decimals)
        .map_err(|_| ApiError::Refused("amount_scaling"))?;
    let quote_request = SwapQuoteRequest {
        from_asset: route.funding_asset.clone(),
        to_asset: chain.memo_asset.clone(),
        amount: amount_thor.to_string(),
        destination: chain.custody_address.clone(),
        refund_address: format!("{originator:#x}"),
        liquidity_tolerance_bps: request.liquidity_tolerance_bps,
        streaming_interval: request.streaming_interval,
        streaming_quantity: request.streaming_quantity,
    };
    let funding_symbols = state
        .asset_prices
        .get(&quote_request.from_asset)
        .ok_or(ApiError::Refused("funding_price_symbols"))?;
    let target_symbols = state
        .asset_prices
        .get(&quote_request.to_asset)
        .ok_or(ApiError::Refused("target_price_symbols"))?;
    let prices = fetch_price_pairs(&state.prices, funding_symbols, target_symbols)
        .await
        .map_err(|_| ApiError::Dependency("price_sources"))?;
    let external_prices = prices
        .iter()
        .map(|pair| external_price_observation(pair, now))
        .collect::<Vec<_>>();
    let source_results = join_all(state.sources.iter().map(|source| async {
        let raw = source.quote_swap(&quote_request).await?;
        let evidence = QuoteEvidence {
            schema: "xindex.thorchain-quote-evidence.v1".to_string(),
            quote_source_id: source.source_id().to_string(),
            request: quote_request.clone(),
            response: raw.value.clone(),
            raw_quote_hash: raw.response_hash,
            external_prices: external_prices.clone(),
        };
        let decision = evaluate_quote(
            &state.quote_policy,
            &evidence,
            &format!("{:#x}", chain.vault),
            chain.valid_until,
            now,
        )?;
        Ok::<_, QuoteBuildError>((source.source_id(), raw, evidence, decision))
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| ApiError::Refused("common_quote_sources"))?;
    let selected = select_strictest_quote(&source_results)
        .map_err(|_| ApiError::Refused("common_quote_selection"))?;
    let candidate = QuoteCandidate {
        evidence: selected.2.clone(),
        raw_quote_body: selected.1.raw_body.clone(),
        decision: selected.3.clone(),
        adapter: format!("{adapter:#x}"),
        index_token: format!("{index_token:#x}"),
        originator: format!("{originator:#x}"),
        funding_token: format!("{funding_token:#x}"),
        target_token: format!("{target_token:#x}"),
        amount_in: amount_in.to_string(),
        custody_hash: chain.custody_hash,
        inbound_state_hash: chain.inbound_hash,
        current_state_valid_until: chain.valid_until,
        finalized_onchain_nonce: chain.quote_nonce,
    };
    validate_common_quote(
        &state.quote_policy,
        &candidate,
        &format!("{:#x}", chain.vault),
        chain.valid_until,
        now,
    )
    .map_err(|_| ApiError::Refused("common_quote_policy"))?;
    let evidence = QuoteProducerEvidence {
        schema: "xindex.registry-quote-producer-evidence.v1",
        operator_id: &state.operator_id,
        finalized_block_number: chain.block.number,
        finalized_block_hash: format!("{:#x}", chain.block.hash),
        candidate: &candidate,
        prices: prices.iter().map(raw_price_evidence).collect(),
        quotes: source_results
            .iter()
            .map(|(source_id, raw, _, decision)| RawQuoteEvidence {
                source_id,
                response_hash: format!("{:#x}", raw.response_hash),
                raw_response: &raw.raw_body,
                decision,
            })
            .collect(),
    };
    state
        .evidence
        .persist_hashed(
            &format!("quote-producer-{}", chain.quote_nonce.saturating_add(1)),
            &evidence,
        )
        .map_err(|_| ApiError::Dependency("evidence_store"))?;
    let payload =
        quote_payload_from_candidate(&candidate).map_err(|_| ApiError::Refused("quote_payload"))?;
    state
        .quote_candidates
        .lock()
        .map_err(|_| ApiError::Dependency("candidate_lock"))?
        .insert(payload, candidate.clone());
    distribute_quote_candidate(&state, &candidate, now).await;
    let ready = wait_for_quote(&state, &payload).await?;
    let hints = encode_acquire_hints(&candidate, &ready)
        .map_err(|_| ApiError::Refused("canonical_hints"))?;
    Ok(Json(QuoteHintsResponse {
        hints: format!("0x{}", alloy_primitives::hex::encode(hints)),
        min_out_native: candidate.decision.min_out_1e8.clone(),
        dispatch_deadline: candidate.decision.dispatch_deadline,
        quote_nonce: payload.quote_nonce,
        quote_hash: format!("{:#x}", candidate.decision.quote_hash),
        memo: candidate.decision.memo,
    }))
}

#[derive(Debug, thiserror::Error)]
enum QuoteBuildError {
    #[error("THOR source unavailable")]
    Thor(#[from] xindex_chain_thor::ThorError),
    #[error("quote policy refused")]
    Policy(#[from] xindex_chain_thor::ThorPolicyError),
}

async fn inbound_producer_loop(state: Arc<AppState>, interval_secs: u64) {
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        if produce_inbound(&state).await.is_err() {
            state
                .metrics
                .registry_source_polls
                .with_label_values(&["source_error"])
                .inc();
            tracing::warn!(
                error_class = "inbound_round",
                "inbound producer round failed"
            );
        }
    }
}

async fn produce_inbound(state: &Arc<AppState>) -> Result<()> {
    let now = now_unix()?;
    let block = finalized_block(&state.provider).await?;
    let registry = ThorchainVaultRegistry::new(state.registry_address, state.provider.clone());
    let current = registry
        .inboundState()
        .block(block.id)
        .call()
        .await
        .context("read finalized inbound sequence")?
        ._0;
    let sequence = current
        .sequence
        .checked_add(1)
        .context("inbound sequence exhausted")?;
    let polls = poll_all_sources(&state.sources, now).await?;
    let before_tip = InboundProducerEvidence {
        schema: "xindex.registry-inbound-producer-raw.v1",
        operator_id: &state.operator_id,
        finalized_block_number: block.number,
        finalized_block_hash: format!("{:#x}", block.hash),
        candidate: None,
        sources: polls.iter().map(raw_source_evidence).collect(),
    };
    state
        .evidence
        .persist_hashed(&format!("inbound-producer-raw-{sequence}"), &before_tip)?;
    let mut snapshots = Vec::with_capacity(polls.len());
    for poll in &polls {
        let advance = state
            .durable_state
            .record_source_tip(
                &poll.source_id,
                poll.consensus.value.height,
                &poll.consensus.value.block_hash,
                poll.observed_at,
            )
            .await?;
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
    let derived = derive_inbound(&state.inbound_policy, &snapshots, now)?;
    let candidate = InboundCandidate {
        derived,
        observed_at: now,
        valid_until: now
            .checked_add(state.report_validity_secs)
            .context("inbound validity overflow")?,
        sequence,
    };
    let complete = InboundProducerEvidence {
        schema: "xindex.registry-inbound-producer-evidence.v1",
        operator_id: &state.operator_id,
        finalized_block_number: block.number,
        finalized_block_hash: format!("{:#x}", block.hash),
        candidate: Some(&candidate),
        sources: polls.iter().map(raw_source_evidence).collect(),
    };
    state
        .evidence
        .persist_hashed(&format!("inbound-producer-{sequence}"), &complete)?;
    state
        .metrics
        .registry_source_polls
        .with_label_values(&["success"])
        .inc();
    state
        .metrics
        .registry_pause_flags
        .set(i64::from(candidate.derived.pause_flags));
    state
        .metrics
        .registry_last_success_timestamp_seconds
        .with_label_values(&["source_poll"])
        .set(u64_to_i64(now));
    distribute_inbound_candidate(state, &candidate, now).await;
    Ok(())
}

async fn distribute_inbound_candidate(
    state: &Arc<AppState>,
    candidate: &InboundCandidate,
    now: u64,
) {
    let responses = join_all(state.signer_urls.iter().map(|base| async move {
        state
            .signer_client
            .post(format!("{base}/api/v1/registry/inbound-candidate"))
            .json(candidate)
            .send()
            .await
    }))
    .await;
    for response in responses.into_iter().flatten() {
        if !response.status().is_success() {
            continue;
        }
        if let Ok(signed) = response.json::<SignedInboundStateMessage>().await {
            let submission = InboundSignatureSubmission {
                candidate: candidate.clone(),
                signed,
            };
            let _ = ingest_inbound_submission(state, submission, now).await;
        }
    }
}

async fn distribute_quote_candidate(state: &Arc<AppState>, candidate: &QuoteCandidate, now: u64) {
    let responses = join_all(state.signer_urls.iter().map(|base| async move {
        state
            .signer_client
            .post(format!("{base}/api/v1/registry/quote-candidate"))
            .json(candidate)
            .send()
            .await
    }))
    .await;
    for response in responses.into_iter().flatten() {
        if !response.status().is_success() {
            continue;
        }
        if let Ok(signed) = response.json::<SignedQuoteAuthorizationMessage>().await {
            let submission = QuoteSignatureSubmission {
                candidate: candidate.clone(),
                signed,
            };
            let _ = ingest_quote_submission(state, &submission, now);
        }
    }
}

async fn wait_for_quote(
    state: &Arc<AppState>,
    payload: &QuotePayload,
) -> Result<ReadyQuote, ApiError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(state.quote_wait_secs);
    loop {
        let notified = state.quote_notify.notified();
        if let Some(ready) = state
            .ready_quotes
            .lock()
            .map_err(|_| ApiError::Dependency("ready_quote_lock"))?
            .remove(payload)
        {
            return Ok(ready);
        }
        tokio::time::timeout_at(deadline, notified)
            .await
            .map_err(|_| ApiError::Timeout)?;
    }
}

fn cleanup_quotes(state: &Arc<AppState>, now: u64) -> Result<(), ApiError> {
    state
        .quote_candidates
        .lock()
        .map_err(|_| ApiError::Dependency("candidate_lock"))?
        .retain(|payload, _| payload.dispatch_deadline > now);
    state
        .ready_quotes
        .lock()
        .map_err(|_| ApiError::Dependency("ready_quote_lock"))?
        .retain(|payload, _| payload.dispatch_deadline > now);
    Ok(())
}

fn select_strictest_quote<'a>(
    quotes: &'a [(
        &str,
        RawResponse<SwapQuoteResponse>,
        QuoteEvidence,
        QuoteDecision,
    )],
) -> Result<&'a (
    &'a str,
    RawResponse<SwapQuoteResponse>,
    QuoteEvidence,
    QuoteDecision,
)> {
    let mut strictest_min = U256::ZERO;
    let mut earliest_deadline = u64::MAX;
    for quote in quotes {
        let min = U256::from_str_radix(&quote.3.min_out_1e8, 10).context("parse quote minimum")?;
        strictest_min = strictest_min.max(min);
        earliest_deadline = earliest_deadline.min(quote.3.dispatch_deadline);
    }
    quotes
        .iter()
        .find(|quote| {
            U256::from_str_radix(&quote.3.min_out_1e8, 10).is_ok_and(|min| {
                min == strictest_min && quote.3.dispatch_deadline == earliest_deadline
            })
        })
        .context("no single quote is at least as strict as every source")
}

#[expect(
    clippy::too_many_arguments,
    reason = "one isolated worker owns the poster provider and its explicit retry policy"
)]
async fn inbound_poster<P, T>(
    mut ready_rx: mpsc::Receiver<ReadyInbound>,
    provider: Arc<P>,
    registry_address: Address,
    poster_address: Address,
    attempts: u32,
    retry_base_ms: u64,
    retry_max_ms: u64,
    metrics: Metrics,
) where
    P: Provider<T> + 'static,
    T: Transport + Clone + 'static,
{
    let registry = ThorchainVaultRegistry::new(registry_address, provider);
    while let Some(ready) = ready_rx.recv().await {
        let payload = ready.payload;
        for attempt in 1..=attempts {
            match registry.inboundState().call().await {
                Ok(current) if current._0.sequence >= payload.sequence => {
                    if inbound_matches_state(payload, &current._0) {
                        metrics
                            .registry_last_success_timestamp_seconds
                            .with_label_values(&["inbound_post"])
                            .set(u64_to_i64(now_unix().map_or(0, |value| value)));
                    }
                    break;
                }
                Ok(_) => {}
                Err(error) if is_transient_rpc_error(&error) && attempt < attempts => {
                    tokio::time::sleep(retry_delay(attempt, retry_base_ms, retry_max_ms)).await;
                    continue;
                }
                Err(_) => break,
            }
            let signatures = ready.signatures.iter().copied().map(Bytes::from).collect();
            let sent = registry
                .attestInbound(
                    payload.vault,
                    payload.router,
                    payload.pause_flags,
                    payload.observed_at,
                    payload.valid_until,
                    payload.sequence,
                    payload.source_hash,
                    signatures,
                )
                .from(poster_address)
                .send()
                .await;
            match sent {
                Ok(transaction) => match transaction.get_receipt().await {
                    Ok(receipt) if receipt.status() => {
                        metrics
                            .registry_last_success_timestamp_seconds
                            .with_label_values(&["inbound_post"])
                            .set(u64_to_i64(now_unix().map_or(0, |value| value)));
                        break;
                    }
                    Err(_) if attempt < attempts => {
                        tokio::time::sleep(retry_delay(attempt, retry_base_ms, retry_max_ms)).await;
                    }
                    Ok(_) | Err(_) => break,
                },
                Err(error) if is_transient_rpc_error(&error) && attempt < attempts => {
                    tokio::time::sleep(retry_delay(attempt, retry_base_ms, retry_max_ms)).await;
                }
                Err(_) => break,
            }
        }
    }
}

fn inbound_matches_state(
    payload: InboundPayload,
    state: &xindex_chain_eth::bindings::ThorchainVaultRegistry::InboundState,
) -> bool {
    state.vault == payload.vault
        && state.router == payload.router
        && state.observedAt == payload.observed_at
        && state.validUntil == payload.valid_until
        && state.sequence == payload.sequence
        && state.pauseFlags == payload.pause_flags
        && state.sourceHash == payload.source_hash
}

fn inbound_payload_from_candidate(candidate: &InboundCandidate) -> Result<InboundPayload> {
    Ok(InboundPayload {
        vault: Address::from_str(&candidate.derived.vault).context("candidate vault")?,
        router: Address::from_str(&candidate.derived.router).context("candidate Router")?,
        pause_flags: candidate.derived.pause_flags,
        observed_at: candidate.observed_at,
        valid_until: candidate.valid_until,
        sequence: candidate.sequence,
        source_hash: candidate.derived.source_hash,
    })
}

async fn verify_roster(
    provider: &Arc<ReqwestProvider>,
    registry_address: Address,
    signers: &[Address],
    threshold: usize,
) -> Result<()> {
    let block = finalized_block(provider).await?;
    let registry = ThorchainVaultRegistry::new(registry_address, provider.clone());
    let onchain_threshold: usize = registry
        .threshold()
        .block(block.id)
        .call()
        .await?
        ._0
        .try_into()
        .context("threshold does not fit usize")?;
    let onchain_count: usize = registry
        .signerCount()
        .block(block.id)
        .call()
        .await?
        ._0
        .try_into()
        .context("signer count does not fit usize")?;
    if threshold != onchain_threshold || signers.len() != onchain_count {
        anyhow::bail!("configured registry roster differs from finalized on-chain roster");
    }
    for signer in signers {
        if !registry.isSigner(*signer).block(block.id).call().await?._0 {
            anyhow::bail!("configured signer is not active on-chain");
        }
    }
    Ok(())
}

async fn finalized_block(provider: &ReqwestProvider) -> Result<FinalizedBlock> {
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Finalized, BlockTransactionsKind::Hashes)
        .await?
        .context("RPC returned no finalized block")?;
    Ok(FinalizedBlock {
        id: BlockId::hash_canonical(block.header.hash),
        number: block.header.number,
        hash: block.header.hash,
    })
}

async fn quote_chain_state(
    provider: &Arc<ReqwestProvider>,
    registry_address: Address,
    adapter_address: Address,
    funding_token: Address,
    index_token: Address,
    originator: Address,
) -> Result<QuoteChainState> {
    let block = finalized_block(provider).await?;
    let registry = ThorchainVaultRegistry::new(registry_address, provider.clone());
    let usable = registry.currentInbound().block(block.id).call().await?;
    let quote_nonce = registry
        .quoteNonce(originator)
        .block(block.id)
        .call()
        .await?
        ._0;
    let adapter = ThorchainAdapter::new(adapter_address, provider.clone());
    let adapter_registry = adapter.VAULT_REGISTRY().block(block.id).call().await?._0;
    if adapter_registry != registry_address {
        anyhow::bail!("adapter points at a different registry");
    }
    let router = adapter.ROUTER().block(block.id).call().await?._0;
    if router != usable.state.router {
        anyhow::bail!("adapter Router differs from attested Router");
    }
    let target_token = adapter
        .TARGET_TOKEN_SENTINEL()
        .block(block.id)
        .call()
        .await?
        ._0;
    let custody_address = adapter
        .nativeCustodyAddress()
        .block(block.id)
        .call()
        .await?
        ._0;
    let custody_hash = adapter.nativeCustodyHash().block(block.id).call().await?._0;
    if custody_hash != alloy_primitives::keccak256(custody_address.as_bytes()) {
        anyhow::bail!("adapter custody address/hash mismatch");
    }
    let memo_asset = adapter.memoAsset().block(block.id).call().await?._0;
    let factory_address = adapter.FACTORY().block(block.id).call().await?._0;
    if !IndexFactory::new(factory_address, provider.clone())
        .isIndexToken(index_token)
        .block(block.id)
        .call()
        .await?
        ._0
    {
        anyhow::bail!("index token is not registered");
    }
    let funding_decimals = IERC20Metadata::new(funding_token, provider.clone())
        .decimals()
        .block(block.id)
        .call()
        .await?
        ._0;
    Ok(QuoteChainState {
        block,
        vault: usable.state.vault,
        router,
        valid_until: usable.state.validUntil,
        inbound_hash: usable.stateHash,
        quote_nonce,
        custody_address,
        custody_hash,
        memo_asset,
        target_token,
        funding_decimals,
    })
}

async fn poll_all_sources(
    sources: &[ThorSourceClient],
    observed_at: u64,
) -> Result<Vec<RawSourcePoll>, xindex_chain_thor::ThorError> {
    join_all(sources.iter().map(|source| source.poll(observed_at)))
        .await
        .into_iter()
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

async fn fetch_price_pair(
    venue: &dyn PriceVenue,
    funding_symbol: &str,
    target_symbol: &str,
) -> Result<PricePair, VenueError> {
    let (funding, target) = tokio::try_join!(
        venue.fetch_price_observation(funding_symbol),
        venue.fetch_price_observation(target_symbol)
    )?;
    Ok(PricePair {
        source_id: venue.name(),
        funding,
        target,
    })
}

async fn fetch_price_pairs(
    fleet: &PriceFleet,
    funding: &AssetPriceConfig,
    target: &AssetPriceConfig,
) -> Result<Vec<PricePair>, VenueError> {
    let (binance, coinbase, kraken) = tokio::try_join!(
        fetch_price_pair(&fleet.binance, &funding.binance, &target.binance),
        fetch_price_pair(&fleet.coinbase, &funding.coinbase, &target.coinbase),
        fetch_price_pair(&fleet.kraken, &funding.kraken, &target.kraken)
    )?;
    Ok(vec![binance, coinbase, kraken])
}

fn external_price_observation(pair: &PricePair, observed_at: u64) -> ExternalPriceObservation {
    let mut commitment = Vec::with_capacity(64);
    commitment.extend_from_slice(pair.funding.response_hash.as_slice());
    commitment.extend_from_slice(pair.target.response_hash.as_slice());
    ExternalPriceObservation {
        source_id: pair.source_id.to_string(),
        funding_price_wad: pair.funding.value.to_string(),
        target_price_wad: pair.target.value.to_string(),
        observed_at,
        raw_response_hash: alloy_primitives::keccak256(commitment),
    }
}

fn raw_price_evidence(pair: &PricePair) -> RawPriceEvidence<'_> {
    RawPriceEvidence {
        source_id: pair.source_id,
        funding_subject: &pair.funding.subject,
        funding_value_wad: pair.funding.value.to_string(),
        funding_raw_response: &pair.funding.raw_response,
        target_subject: &pair.target.subject,
        target_value_wad: pair.target.value.to_string(),
        target_raw_response: &pair.target.raw_response,
    }
}

fn retry_delay(attempt: u32, base_ms: u64, max_ms: u64) -> Duration {
    let factor = 1u64 << attempt.saturating_sub(1).min(6);
    Duration::from_millis(base_ms.saturating_mul(factor).min(max_ms))
}

fn validate_config(config: &Config) -> Result<()> {
    if config.chain_id == 0
        || config.sources.len() != 3
        || config.signers.len() != PRODUCTION_REGISTRY_SIGNER_COUNT
        || config.threshold != PRODUCTION_REGISTRY_THRESHOLD
        || config.inbound_interval_secs == 0
        || config.report_validity_secs == 0
        || config.report_validity_secs > 600
        || config.quote_wait_secs == 0
        || config.post_attempts == 0
        || config.retry_base_ms == 0
        || config.retry_max_ms < config.retry_base_ms
        || config.quote_policy.min_price_sources != 3
        || config.routes.is_empty()
    {
        anyhow::bail!("invalid production setting; registry topology must be exactly 3-of-5");
    }
    validate_public_id(&config.operator_id)?;
    validate_database_url(&config.database_url)?;
    validate_owner_only_directory(&config.evidence_dir)?;
    validate_secret_file(&config.signer_client_identity_pem)?;
    validate_secret_file(&config.server_key_pem)?;
    if !config.metrics_address.ip().is_loopback() {
        anyhow::bail!("metrics address must bind loopback");
    }
    endpoint_origin("ethereum_rpc_url", &config.ethereum_rpc_url, true)?;
    let mut source_ids = HashSet::new();
    let mut thor_origins = HashSet::new();
    let mut consensus_origins = HashSet::new();
    for source in &config.sources {
        validate_public_id(&source.id)?;
        if !source_ids.insert(source.id.clone())
            || !thor_origins.insert(endpoint_origin("thornode_url", &source.thornode_url, true)?)
            || !consensus_origins.insert(endpoint_origin(
                "consensus_url",
                &source.consensus_url,
                true,
            )?)
        {
            anyhow::bail!("THOR source identities/origins must be distinct");
        }
    }
    let mut signer_addresses = HashSet::new();
    let mut signer_origins = HashSet::new();
    for signer in &config.signers {
        if !signer_addresses.insert(parse_nonzero_address("signer", &signer.address)?)
            || !signer_origins.insert(endpoint_origin("signer URL", &signer.url, true)?)
        {
            anyhow::bail!("signer addresses/origins must be distinct");
        }
    }
    let venues = [
        endpoint_origin("binance", &config.binance_base, true)?,
        endpoint_origin("coinbase", &config.coinbase_base, true)?,
        endpoint_origin("kraken", &config.kraken_base, true)?,
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    if venues.len() != 3 {
        anyhow::bail!("price venue origins must be distinct");
    }
    let mut assets = HashSet::new();
    for asset in &config.asset_prices {
        if asset.asset.is_empty()
            || asset.binance.is_empty()
            || asset.coinbase.is_empty()
            || asset.kraken.is_empty()
            || !assets.insert(asset.asset.clone())
            || !config
                .quote_policy
                .allowlisted_assets
                .contains(&asset.asset)
        {
            anyhow::bail!("invalid asset-price mapping");
        }
    }
    let mut routes = HashSet::new();
    for route in &config.routes {
        let key = (
            parse_nonzero_address("route adapter", &route.adapter)?,
            parse_nonzero_address("route funding token", &route.funding_token)?,
        );
        if !routes.insert(key)
            || !assets.contains(&route.funding_asset)
            || !config
                .quote_policy
                .allowlisted_assets
                .contains(&route.funding_asset)
        {
            anyhow::bail!("invalid route mapping");
        }
    }
    if config.signer_server_ca_pems.is_empty() || config.pinned_client_cert_pems.is_empty() {
        anyhow::bail!("mTLS trust roots must not be empty");
    }
    Ok(())
}

fn endpoint_origin(label: &str, raw: &str, require_https: bool) -> Result<String> {
    let url = reqwest::Url::parse(raw).with_context(|| format!("{label} must be a URL"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (require_https && url.scheme() != "https")
    {
        anyhow::bail!("{label} must be credential-free HTTPS without query/fragment");
    }
    let host = url
        .host_str()
        .with_context(|| format!("{label} has no host"))?;
    let port = url
        .port_or_known_default()
        .with_context(|| format!("{label} has no port"))?;
    Ok(format!(
        "{}://{}:{port}",
        url.scheme(),
        host.to_ascii_lowercase()
    ))
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

fn validate_database_url(database_url: &str) -> Result<()> {
    let path = database_url
        .strip_prefix("sqlite://")
        .context("database URL must be sqlite:///absolute/path")?
        .split('?')
        .next()
        .context("database URL path absent")?;
    let path = Path::new(path);
    if !path.is_absolute() {
        anyhow::bail!("database path must be absolute");
    }
    validate_owner_only_directory(path.parent().context("database parent absent")?)
}

fn validate_owner_only_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
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

fn validate_secret_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect secret file {}", path.display()))?;
    if !path.is_absolute() || !metadata.file_type().is_file() {
        anyhow::bail!("secret/config path must be an absolute non-symlink regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            anyhow::bail!("secret/config file must be owner-only and single-link");
        }
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

fn signer_client(config: &Config) -> Result<reqwest::Client> {
    let identity = reqwest::Identity::from_pem(&fs::read(&config.signer_client_identity_pem)?)?;
    let mut builder = reqwest::Client::builder()
        .identity(identity)
        .timeout(Duration::from_secs(config.signer_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false);
    for path in &config.signer_server_ca_pems {
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&fs::read(path)?)?);
    }
    Ok(builder.build()?)
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn load_server_tls(config: &Config) -> Result<ServerConfig> {
    let chain = CertificateDer::pem_slice_iter(&fs::read(&config.server_cert_pem)?)
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(&fs::read(&config.server_key_pem)?)?;
    let mut roots = RootCertStore::empty();
    for path in &config.pinned_client_cert_pems {
        for cert in CertificateDer::pem_slice_iter(&fs::read(path)?) {
            roots.add(cert?)?;
        }
    }
    if roots.is_empty() {
        anyhow::bail!("pinned mTLS client roots are empty");
    }
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider()).build()?;
    Ok(ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?)
}

async fn serve_mtls(
    listener: tokio::net::TcpListener,
    config: Arc<ServerConfig>,
    app: Router,
) -> std::io::Result<()> {
    let acceptor = TlsAcceptor::from(config);
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let Ok(stream) = acceptor.accept(tcp).await else {
                return;
            };
            let service = TowerToHyperService::new(app);
            let _ = HyperBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await;
        });
    }
}

fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock before Unix epoch")?
        .as_secs())
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).map_or(i64::MAX, |converted| converted)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use super::*;

    fn test_quote(
        source: &'static str,
        min_out: &str,
        deadline: u64,
    ) -> (
        &'static str,
        RawResponse<SwapQuoteResponse>,
        QuoteEvidence,
        QuoteDecision,
    ) {
        let response = SwapQuoteResponse {
            inbound_address: "0x1111111111111111111111111111111111111111".to_string(),
            inbound_confirmation_blocks: 1,
            inbound_confirmation_seconds: 6,
            outbound_delay_blocks: 1,
            outbound_delay_seconds: 6,
            fees: xindex_chain_thor::SwapQuoteFees {
                asset: "BTC.BTC".to_string(),
                affiliate: "0".to_string(),
                outbound: "1".to_string(),
                liquidity: "1".to_string(),
                total: "2".to_string(),
                slippage_bps: 1,
                total_bps: 1,
            },
            expiry: deadline + 10,
            warning: "test".to_string(),
            dust_threshold: "1".to_string(),
            recommended_min_amount_in: "1".to_string(),
            recommended_gas_rate: "1".to_string(),
            gas_rate_units: "satsperbyte".to_string(),
            memo: format!("=:BTC.BTC:bc1qdest/0xrefund:{min_out}/1/1"),
            expected_amount_out: min_out.to_string(),
            max_streaming_quantity: 1,
            streaming_swap_blocks: 0,
            streaming_swap_seconds: 0,
            total_swap_seconds: 12,
        };
        let request = SwapQuoteRequest {
            from_asset: "ETH.USDT-0XDAC17F".to_string(),
            to_asset: "BTC.BTC".to_string(),
            amount: "100".to_string(),
            destination: "bc1qdest".to_string(),
            refund_address: "0xrefund".to_string(),
            liquidity_tolerance_bps: 100,
            streaming_interval: 1,
            streaming_quantity: 1,
        };
        (
            source,
            RawResponse {
                value: response.clone(),
                raw_body: "{}".to_string(),
                response_hash: B256::repeat_byte(1),
            },
            QuoteEvidence {
                schema: "test".to_string(),
                quote_source_id: source.to_string(),
                request,
                response,
                raw_quote_hash: B256::repeat_byte(2),
                external_prices: Vec::new(),
            },
            QuoteDecision {
                min_out_1e8: min_out.to_string(),
                memo: "test".to_string(),
                dispatch_deadline: deadline,
                quote_hash: B256::repeat_byte(3),
            },
        )
    }

    #[test]
    fn endpoint_policy_rejects_credentials_and_plaintext() {
        assert!(endpoint_origin("signer", "https://signer.example", true).is_ok());
        assert!(endpoint_origin("signer", "http://signer.example", true).is_err());
        assert!(endpoint_origin("signer", "https://u:p@signer.example", true).is_err());
    }

    #[test]
    fn strictest_quote_requires_one_source_to_dominate_both_bounds() {
        let no_dominating_source = [
            test_quote("a", "100", 90),
            test_quote("b", "110", 100),
            test_quote("c", "105", 80),
        ];
        assert!(select_strictest_quote(&no_dominating_source).is_err());

        let dominating_source = [
            test_quote("a", "100", 90),
            test_quote("b", "110", 100),
            test_quote("c", "110", 80),
        ];
        let selected = select_strictest_quote(&dominating_source).expect("strict quote");
        assert_eq!(selected.0, "c");
        assert_eq!(selected.3.min_out_1e8, "110");
        assert_eq!(selected.3.dispatch_deadline, 80);
    }
}
