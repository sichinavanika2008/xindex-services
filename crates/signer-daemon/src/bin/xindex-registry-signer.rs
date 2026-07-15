//! Production `THORChain` inbound-state and exact-quote signer.
//!
//! The coordinator is untrusted. Before an HSM call this process pins one
//! finalized Ethereum block, replays the common candidate policy, polls three
//! operator-controlled `THORNode`/`CometBFT` sources, obtains three independent
//! price pairs for quotes, and durably stores the exact raw evidence. Signed
//! messages are pushed to at least two collectors over mTLS.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::eips::{BlockId, BlockNumberOrTag};
use alloy::providers::{Provider, ProviderBuilder, ReqwestProvider};
use alloy::rpc::types::BlockTransactionsKind;
use alloy::sol;
use alloy_primitives::{keccak256, Address, B256, U256};
use anyhow::{Context, Result};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use clap::Parser;
use futures_util::future::join_all;
use prometheus::Registry;
use serde::{Deserialize, Serialize};
use serde_json::json;
use xindex_chain_eth::bindings::{IndexFactory, ThorchainAdapter, ThorchainVaultRegistry};
use xindex_chain_thor::{
    derive_inbound, evaluate_quote, evm_raw_to_thor, validate_common_inbound,
    validate_common_quote, validate_independent_inbound, validate_independent_quote,
    ExternalPriceObservation, InboundCandidate, InboundPolicy, QuoteCandidate, QuoteDecision,
    QuoteEvidence, QuotePolicy, RawSourcePoll, ThorClient, ThorConsensusClient, ThorSourceClient,
    TipCheckpoint,
};
use xindex_ops::network::{async_client, HttpClientPolicy};
use xindex_ops::{serve_metrics, Metrics};
use xindex_shared::eip712::thorchain_registry_domain;
use xindex_shared::registry_state::{SqliteRegistryState, TipAdvance};
use xindex_shared::registry_wire::{SignedInboundStateMessage, SignedQuoteAuthorizationMessage};
use xindex_signer_daemon::evidence::EvidenceStore;
use xindex_signer_daemon::price_venue::{
    BinanceVenue, CoinbaseVenue, KrakenVenue, PriceVenue, SourcedValue, VenueError,
};
use xindex_signer_daemon::registry_sign::{
    InboundValidationContext, QuoteValidationContext, RegistrySigner,
};
use xindex_signer_daemon::tls::{
    exact_pinned_async_client_builder, load_cert_chain, load_private_key, pinned_cert_store,
    serve_mtls, server_config,
};
use xindex_signer_daemon::web3signer::HttpHsmClient;

const PRODUCTION_REGISTRY_SIGNER_COUNT: usize = 5;
const PRODUCTION_REGISTRY_THRESHOLD: usize = 3;

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
    signer_address: String,
    operator_id: String,
    ethereum_rpc_url: String,
    hsm_url: String,
    database_url: String,
    evidence_dir: PathBuf,
    listen_address: SocketAddr,
    metrics_address: SocketAddr,
    report_validity_secs: u64,
    inbound_policy: InboundPolicy,
    quote_policy: QuotePolicy,
    sources: Vec<SourceConfig>,
    routes: Vec<RouteConfig>,
    asset_prices: Vec<AssetPriceConfig>,
    binance_base: String,
    coinbase_base: String,
    kraken_base: String,
    collectors: Vec<String>,
    collector_publish_attempts: u32,
    collector_timeout_secs: u64,
    server_cert_pem: PathBuf,
    server_key_pem: PathBuf,
    coordinator_client_cert_pems: Vec<PathBuf>,
    collector_client_identity_pem: PathBuf,
    /// Legacy-named leaf-first exact collector peer bundles.
    collector_server_ca_pems: Vec<PathBuf>,
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

#[derive(Debug)]
struct PriceFleet {
    binance: BinanceVenue,
    coinbase: CoinbaseVenue,
    kraken: KrakenVenue,
}

#[derive(Debug)]
struct CollectorPublisher {
    client: reqwest::Client,
    bases: Vec<String>,
    attempts: u32,
}

struct AppState {
    chain_id: u64,
    registry_address: Address,
    signer_address: Address,
    operator_id: String,
    provider: Arc<ReqwestProvider>,
    hsm: HttpHsmClient,
    durable_state: SqliteRegistryState,
    evidence: EvidenceStore,
    inbound_policy: InboundPolicy,
    quote_policy: QuotePolicy,
    report_validity_secs: u64,
    sources: Vec<ThorSourceClient>,
    routes: HashMap<(Address, Address), RouteConfig>,
    asset_prices: HashMap<String, AssetPriceConfig>,
    prices: PriceFleet,
    publisher: CollectorPublisher,
    metrics: Metrics,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppState")
            .field("chain_id", &self.chain_id)
            .field("registry_address", &self.registry_address)
            .field("signer_address", &self.signer_address)
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
struct InboundChainState {
    block: FinalizedBlock,
    vault: Address,
    router: Address,
    valid_until: u64,
    sequence: u64,
    state_hash: B256,
}

#[derive(Debug)]
struct AdapterChainState {
    inbound: InboundChainState,
    quote_nonce: u64,
    adapter: Address,
    registry: Address,
    router: Address,
    target_token: Address,
    custody_address: String,
    custody_hash: B256,
    memo_asset: String,
    funding_decimals: u8,
}

#[derive(Debug)]
struct PricePair {
    source_id: &'static str,
    funding: SourcedValue,
    target: SourcedValue,
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
struct InboundSigningEvidence<'a> {
    schema: &'static str,
    operator_id: &'a str,
    signer_address: String,
    finalized_block_number: u64,
    finalized_block_hash: String,
    candidate: &'a InboundCandidate,
    independent_sources: Vec<RawSourceEvidence<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawPricePairEvidence<'a> {
    source_id: &'a str,
    funding_subject: &'a str,
    funding_value_wad: String,
    funding_response_hash: String,
    funding_raw_response: &'a str,
    target_subject: &'a str,
    target_value_wad: String,
    target_response_hash: String,
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
struct QuoteSigningEvidence<'a> {
    schema: &'static str,
    operator_id: &'a str,
    signer_address: String,
    finalized_block_number: u64,
    finalized_block_hash: String,
    candidate: &'a QuoteCandidate,
    independent_prices: Vec<RawPricePairEvidence<'a>>,
    independent_quotes: Vec<RawQuoteEvidence<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InboundSignatureSubmission<'a> {
    candidate: &'a InboundCandidate,
    signed: &'a SignedInboundStateMessage,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QuoteSignatureSubmission<'a> {
    candidate: &'a QuoteCandidate,
    signed: &'a SignedQuoteAuthorizationMessage,
}

#[derive(Debug)]
enum ApiError {
    Refused(&'static str),
    Dependency(&'static str),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, component) = match self {
            Self::Refused(component) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "candidate_refused",
                component,
            ),
            Self::Dependency(component) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "dependency_unavailable",
                component,
            ),
        };
        tracing::warn!(
            error_code = code,
            component,
            "registry signer request failed"
        );
        (status, Json(json!({"error": code}))).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    xindex_ops::init_tracing();
    run(Args::parse()).await
}

#[expect(
    clippy::too_many_lines,
    reason = "fail-closed production startup keeps every external trust boundary visible"
)]
async fn run(args: Args) -> Result<()> {
    validate_secret_file(&args.config)?;
    let raw = fs::read(&args.config).context("read registry signer config")?;
    let config: Config = serde_json::from_slice(&raw).context("parse registry signer config")?;
    validate_config(&config)?;

    let registry_address = parse_nonzero_address("registry_contract", &config.registry_contract)?;
    let signer_address = parse_nonzero_address("signer_address", &config.signer_address)?;
    let provider = Arc::new(
        ProviderBuilder::new().on_http(
            config
                .ethereum_rpc_url
                .parse()
                .context("Ethereum RPC URL")?,
        ),
    );
    let actual_chain_id = provider
        .get_chain_id()
        .await
        .context("read Ethereum chain id")?;
    if actual_chain_id != config.chain_id {
        anyhow::bail!(
            "configured chain id {} differs from RPC chain id {actual_chain_id}",
            config.chain_id
        );
    }

    let boot_block = finalized_block(&provider).await?;
    let registry_contract = ThorchainVaultRegistry::new(registry_address, provider.clone());
    let onchain_threshold: usize = registry_contract
        .threshold()
        .block(boot_block.id)
        .call()
        .await
        .context("read finalized registry threshold")?
        ._0
        .try_into()
        .context("registry threshold does not fit usize")?;
    let onchain_count: usize = registry_contract
        .signerCount()
        .block(boot_block.id)
        .call()
        .await
        .context("read finalized registry signer count")?
        ._0
        .try_into()
        .context("registry signer count does not fit usize")?;
    if onchain_count != PRODUCTION_REGISTRY_SIGNER_COUNT
        || onchain_threshold != PRODUCTION_REGISTRY_THRESHOLD
    {
        anyhow::bail!("production registry topology must be exactly 3-of-5");
    }
    if !registry_contract
        .isSigner(signer_address)
        .block(boot_block.id)
        .call()
        .await
        .context("read finalized registry signer roster")?
        ._0
    {
        anyhow::bail!("configured signer is not active in the finalized registry roster");
    }

    let durable_state = SqliteRegistryState::connect(&config.database_url)
        .await
        .context("open durable registry state")?;
    let evidence = EvidenceStore::open(&config.evidence_dir).context("open evidence directory")?;
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
        .context("construct THORChain sources")?;
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

    let http = async_client(HttpClientPolicy {
        connect_timeout: Duration::from_secs(config.collector_timeout_secs.min(3)),
        request_timeout: Duration::from_secs(config.collector_timeout_secs),
        max_response_bytes: 2 * 1024 * 1024,
    })
    .context("build public-data HTTP client")?;
    let prices = PriceFleet {
        binance: BinanceVenue::new(http.clone(), config.binance_base.clone()),
        coinbase: CoinbaseVenue::new(http.clone(), config.coinbase_base.clone()),
        kraken: KrakenVenue::new(http, config.kraken_base.clone()),
    };
    let publisher = CollectorPublisher {
        client: collector_client(&config)?,
        bases: config
            .collectors
            .iter()
            .map(|base| base.trim_end_matches('/').to_string())
            .collect(),
        attempts: config.collector_publish_attempts,
    };
    let tls_config = Arc::new(load_server_tls(&config)?);

    let prometheus = Registry::new();
    let metrics = Metrics::new(&prometheus).context("register metrics")?;
    for kind in ["source_poll", "inbound_sign", "quote_sign"] {
        // Materialize zero-valued series at boot. Prometheus treats an absent
        // vector as "no data", so the stale-publication rule could otherwise
        // miss a signer that has never completed its first request.
        metrics
            .registry_last_success_timestamp_seconds
            .with_label_values(&[kind])
            .set(0);
    }
    let metrics_address = config.metrics_address;

    let state = Arc::new(AppState {
        chain_id: config.chain_id,
        registry_address,
        signer_address,
        operator_id: config.operator_id,
        provider,
        hsm: HttpHsmClient::new(config.hsm_url),
        durable_state,
        evidence,
        inbound_policy: config.inbound_policy,
        quote_policy: config.quote_policy,
        report_validity_secs: config.report_validity_secs,
        sources,
        routes,
        asset_prices,
        prices,
        publisher,
        metrics,
    });
    let app = Router::new()
        .route("/api/v1/registry/inbound-candidate", post(sign_inbound))
        .route("/api/v1/registry/quote-candidate", post(sign_quote))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.listen_address)
        .await
        .context("bind registry signer mTLS listener")?;
    tracing::info!(address = %config.listen_address, "registry signer mTLS listener ready");
    let api_server = serve_mtls(listener, tls_config, app);
    let metrics_server = serve_metrics(prometheus, metrics_address);
    tokio::select! {
        result = api_server => match result {
            Ok(()) => Err(anyhow::anyhow!("registry signer API exited unexpectedly")),
            Err(error) => Err(anyhow::anyhow!("registry signer API failed: {error}")),
        },
        result = metrics_server => match result {
            Ok(()) => Err(anyhow::anyhow!("registry signer metrics server exited unexpectedly")),
            Err(error) => Err(anyhow::anyhow!("registry signer metrics server failed: {error}")),
        },
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the inbound handler deliberately preserves the evidence-before-tip-before-HSM sequence inline"
)]
async fn sign_inbound(
    State(state): State<Arc<AppState>>,
    Json(candidate): Json<InboundCandidate>,
) -> Result<Json<SignedInboundStateMessage>, ApiError> {
    let now = now_unix().map_err(|_| ApiError::Dependency("clock"))?;
    validate_common_inbound(&state.inbound_policy, &candidate.derived, now)
        .map_err(|_| ApiError::Refused("common_inbound_policy"))?;
    let common_observed_at = candidate
        .derived
        .bundle
        .sources
        .iter()
        .map(|source| source.observed_at)
        .min()
        .ok_or(ApiError::Refused("common_inbound_sources"))?;
    if candidate.observed_at != common_observed_at {
        return Err(ApiError::Refused("common_inbound_timestamp"));
    }

    let onchain = raw_inbound_state(&state.provider, state.registry_address)
        .await
        .map_err(|_| ApiError::Dependency("finalized_registry_read"))?;
    if candidate.sequence
        != onchain
            .sequence
            .checked_add(1)
            .ok_or(ApiError::Refused("sequence"))?
    {
        return Err(ApiError::Refused("sequence"));
    }
    if candidate.valid_until
        != candidate
            .observed_at
            .checked_add(state.report_validity_secs)
            .ok_or(ApiError::Refused("validity"))?
    {
        return Err(ApiError::Refused("validity"));
    }

    let polls = poll_all_sources(&state.sources, now)
        .await
        .map_err(|_| ApiError::Dependency("thor_sources"))?;
    let raw_evidence = InboundSigningEvidence {
        schema: "xindex.registry-inbound-signing-evidence.v1",
        operator_id: &state.operator_id,
        signer_address: format!("{:#x}", state.signer_address),
        finalized_block_number: onchain.block.number,
        finalized_block_hash: format!("{:#x}", onchain.block.hash),
        candidate: &candidate,
        independent_sources: polls.iter().map(raw_source_evidence).collect::<Vec<_>>(),
    };
    if state
        .evidence
        .persist_hashed(&format!("inbound-{}", candidate.sequence), &raw_evidence)
        .is_err()
    {
        state.metrics.registry_evidence_failures.inc();
        return Err(ApiError::Dependency("evidence_store"));
    }

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
            .await
            .map_err(|_| ApiError::Refused("source_tip_checkpoint"))?;
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
    let local = derive_inbound(&state.inbound_policy, &snapshots, now)
        .map_err(|_| ApiError::Refused("independent_inbound_policy"))?;
    state
        .metrics
        .registry_source_polls
        .with_label_values(&["success"])
        .inc();
    state
        .metrics
        .registry_pause_flags
        .set(i64::from(local.pause_flags));
    state
        .metrics
        .registry_last_success_timestamp_seconds
        .with_label_values(&["source_poll"])
        .set(u64_to_i64(now));
    validate_independent_inbound(&candidate.derived, &local)
        .map_err(|_| ApiError::Refused("independent_inbound_disagreement"))?;

    let context = InboundValidationContext {
        vault: Address::from_str(&candidate.derived.vault)
            .map_err(|_| ApiError::Refused("vault"))?,
        router: Address::from_str(&candidate.derived.router)
            .map_err(|_| ApiError::Refused("router"))?,
        pause_flags: candidate.derived.pause_flags,
        observed_at: candidate.observed_at,
        valid_until: candidate.valid_until,
        next_sequence: candidate.sequence,
        source_hash: candidate.derived.source_hash,
        now,
    };
    let domain = thorchain_registry_domain(state.chain_id, state.registry_address);
    let signer = RegistrySigner {
        hsm: &state.hsm,
        signer_address: state.signer_address,
        domain: &domain,
        state: &state.durable_state,
    };
    let message = signer.sign_inbound(&context).await.map_err(|_| {
        state
            .metrics
            .registry_signatures
            .with_label_values(&["inbound", "refused"])
            .inc();
        ApiError::Refused("registry_signing_state")
    })?;
    state
        .metrics
        .registry_signatures
        .with_label_values(&["inbound", "signed"])
        .inc();
    let submission = InboundSignatureSubmission {
        candidate: &candidate,
        signed: &message,
    };
    state
        .publisher
        .publish(
            "inbound",
            "/api/v1/registry/inbound-signatures",
            &submission,
            &state.metrics,
        )
        .await
        .map_err(|_| ApiError::Dependency("collectors"))?;
    state
        .metrics
        .registry_last_success_timestamp_seconds
        .with_label_values(&["inbound_sign"])
        .set(u64_to_i64(now));
    Ok(Json(message))
}

#[expect(
    clippy::too_many_lines,
    reason = "the quote handler deliberately checks every signed/on-chain/raw-evidence field inline"
)]
async fn sign_quote(
    State(state): State<Arc<AppState>>,
    Json(candidate): Json<QuoteCandidate>,
) -> Result<Json<SignedQuoteAuthorizationMessage>, ApiError> {
    let now = now_unix().map_err(|_| ApiError::Dependency("clock"))?;
    let adapter =
        Address::from_str(&candidate.adapter).map_err(|_| ApiError::Refused("adapter"))?;
    let funding_token = Address::from_str(&candidate.funding_token)
        .map_err(|_| ApiError::Refused("funding_token"))?;
    let route = state
        .routes
        .get(&(adapter, funding_token))
        .ok_or(ApiError::Refused("route_allowlist"))?;
    let originator =
        Address::from_str(&candidate.originator).map_err(|_| ApiError::Refused("originator"))?;
    let index_token =
        Address::from_str(&candidate.index_token).map_err(|_| ApiError::Refused("index_token"))?;
    let target_token = Address::from_str(&candidate.target_token)
        .map_err(|_| ApiError::Refused("target_token"))?;
    let amount_in = U256::from_str_radix(&candidate.amount_in, 10)
        .map_err(|_| ApiError::Refused("amount_in"))?;

    let chain = adapter_chain_state(
        &state.provider,
        state.registry_address,
        adapter,
        funding_token,
        originator,
        index_token,
    )
    .await
    .map_err(|_| ApiError::Dependency("finalized_quote_reads"))?;
    if chain.registry != state.registry_address
        || chain.adapter != adapter
        || chain.router != chain.inbound.router
        || target_token != chain.target_token
        || candidate.custody_hash != chain.custody_hash
        || candidate.inbound_state_hash != chain.inbound.state_hash
        || candidate.current_state_valid_until != chain.inbound.valid_until
        || candidate.finalized_onchain_nonce != chain.quote_nonce
        || candidate.evidence.request.from_asset != route.funding_asset
        || candidate.evidence.request.to_asset != chain.memo_asset
        || candidate.evidence.request.destination != chain.custody_address
        || candidate.evidence.request.refund_address != format!("{originator:#x}")
    {
        return Err(ApiError::Refused("finalized_quote_binding"));
    }
    let expected_thor_amount = evm_raw_to_thor(amount_in, chain.funding_decimals)
        .map_err(|_| ApiError::Refused("amount_scaling"))?;
    if candidate.evidence.request.amount != expected_thor_amount.to_string() {
        return Err(ApiError::Refused("amount_scaling"));
    }
    validate_common_quote(
        &state.quote_policy,
        &candidate,
        &format!("{:#x}", chain.inbound.vault),
        chain.inbound.valid_until,
        now,
    )
    .map_err(|_| ApiError::Refused("common_quote_policy"))?;

    let funding_symbols = state
        .asset_prices
        .get(&candidate.evidence.request.from_asset)
        .ok_or(ApiError::Refused("funding_price_symbols"))?;
    let target_symbols = state
        .asset_prices
        .get(&candidate.evidence.request.to_asset)
        .ok_or(ApiError::Refused("target_price_symbols"))?;
    let prices = fetch_price_pairs(&state.prices, funding_symbols, target_symbols)
        .await
        .map_err(|_| ApiError::Dependency("price_sources"))?;
    let external_prices = prices
        .iter()
        .map(|pair| external_price_observation(pair, now))
        .collect::<Vec<_>>();

    let quote_results = join_all(state.sources.iter().map(|source| async {
        let response = source.quote_swap(&candidate.evidence.request).await?;
        let evidence = QuoteEvidence {
            schema: "xindex.thorchain-quote-evidence.v1".to_string(),
            quote_source_id: source.source_id().to_string(),
            request: candidate.evidence.request.clone(),
            response: response.value.clone(),
            raw_quote_hash: response.response_hash,
            external_prices: external_prices.clone(),
        };
        let decision = evaluate_quote(
            &state.quote_policy,
            &evidence,
            &format!("{:#x}", chain.inbound.vault),
            chain.inbound.valid_until,
            now,
        )?;
        validate_independent_quote(
            &candidate.evidence,
            &candidate.decision,
            &evidence,
            &decision,
        )?;
        Ok::<_, QuoteSourceError>((source.source_id(), response, decision))
    }))
    .await;
    let quotes = quote_results
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApiError::Refused("independent_quote_policy"))?;

    let raw_evidence = QuoteSigningEvidence {
        schema: "xindex.registry-quote-signing-evidence.v1",
        operator_id: &state.operator_id,
        signer_address: format!("{:#x}", state.signer_address),
        finalized_block_number: chain.inbound.block.number,
        finalized_block_hash: format!("{:#x}", chain.inbound.block.hash),
        candidate: &candidate,
        independent_prices: prices.iter().map(raw_price_evidence).collect(),
        independent_quotes: quotes
            .iter()
            .map(|(source_id, response, decision)| RawQuoteEvidence {
                source_id,
                response_hash: format!("{:#x}", response.response_hash),
                raw_response: &response.raw_body,
                decision,
            })
            .collect(),
    };
    if state
        .evidence
        .persist_hashed(
            &format!(
                "quote-{}-{:#x}",
                chain.quote_nonce.saturating_add(1),
                originator
            )
            .replace("0x", ""),
            &raw_evidence,
        )
        .is_err()
    {
        state.metrics.registry_evidence_failures.inc();
        return Err(ApiError::Dependency("evidence_store"));
    }

    let context = QuoteValidationContext {
        adapter,
        index_token,
        originator,
        funding_token,
        target_token,
        amount_in,
        custody_hash: candidate.custody_hash,
        inbound_state_hash: candidate.inbound_state_hash,
        memo_hash: keccak256(candidate.decision.memo.as_bytes()),
        dispatch_deadline: candidate.decision.dispatch_deadline,
        finalized_onchain_nonce: chain.quote_nonce,
        quote_hash: candidate.decision.quote_hash,
        current_state_valid_until: chain.inbound.valid_until,
        now,
    };
    let domain = thorchain_registry_domain(state.chain_id, state.registry_address);
    let signer = RegistrySigner {
        hsm: &state.hsm,
        signer_address: state.signer_address,
        domain: &domain,
        state: &state.durable_state,
    };
    let message = signer.sign_quote(&context).await.map_err(|_| {
        state
            .metrics
            .registry_signatures
            .with_label_values(&["quote", "refused"])
            .inc();
        ApiError::Refused("registry_signing_state")
    })?;
    state
        .metrics
        .registry_signatures
        .with_label_values(&["quote", "signed"])
        .inc();
    let submission = QuoteSignatureSubmission {
        candidate: &candidate,
        signed: &message,
    };
    state
        .publisher
        .publish(
            "quote",
            "/api/v1/registry/quote-signatures",
            &submission,
            &state.metrics,
        )
        .await
        .map_err(|_| ApiError::Dependency("collectors"))?;
    state
        .metrics
        .registry_last_success_timestamp_seconds
        .with_label_values(&["quote_sign"])
        .set(u64_to_i64(now));
    Ok(Json(message))
}

#[derive(Debug, thiserror::Error)]
enum QuoteSourceError {
    #[error("THOR source unavailable")]
    Thor(#[from] xindex_chain_thor::ThorError),
    #[error("quote policy refused")]
    Policy(#[from] xindex_chain_thor::ThorPolicyError),
}

async fn finalized_block(provider: &ReqwestProvider) -> Result<FinalizedBlock> {
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Finalized, BlockTransactionsKind::Hashes)
        .await
        .context("read finalized block")?
        .context("RPC returned no finalized block")?;
    Ok(FinalizedBlock {
        id: BlockId::hash_canonical(block.header.hash),
        number: block.header.number,
        hash: block.header.hash,
    })
}

async fn raw_inbound_state(
    provider: &Arc<ReqwestProvider>,
    registry_address: Address,
) -> Result<InboundChainState> {
    let block = finalized_block(provider).await?;
    let registry = ThorchainVaultRegistry::new(registry_address, provider.clone());
    let raw = registry
        .inboundState()
        .block(block.id)
        .call()
        .await
        .context("read raw inbound state")?
        ._0;
    let state_hash = registry
        .inboundStateHash()
        .block(block.id)
        .call()
        .await
        .context("read inbound state hash")?
        ._0;
    Ok(InboundChainState {
        block,
        vault: raw.vault,
        router: raw.router,
        valid_until: raw.validUntil,
        sequence: raw.sequence,
        state_hash,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "one pinned finalized block supplies every adapter/registry binding used by a quote"
)]
async fn adapter_chain_state(
    provider: &Arc<ReqwestProvider>,
    registry_address: Address,
    adapter_address: Address,
    funding_token: Address,
    originator: Address,
    index_token: Address,
) -> Result<AdapterChainState> {
    let block = finalized_block(provider).await?;
    let registry = ThorchainVaultRegistry::new(registry_address, provider.clone());
    let usable = registry
        .currentInbound()
        .block(block.id)
        .call()
        .await
        .context("read usable inbound state")?;
    let quote_nonce = registry
        .quoteNonce(originator)
        .block(block.id)
        .call()
        .await
        .context("read quote nonce")?
        ._0;
    let adapter = ThorchainAdapter::new(adapter_address, provider.clone());
    let adapter_registry = adapter
        .VAULT_REGISTRY()
        .block(block.id)
        .call()
        .await
        .context("read adapter registry")?
        ._0;
    let router = adapter
        .ROUTER()
        .block(block.id)
        .call()
        .await
        .context("read adapter Router")?
        ._0;
    let target_token = adapter
        .TARGET_TOKEN_SENTINEL()
        .block(block.id)
        .call()
        .await
        .context("read target sentinel")?
        ._0;
    let custody_address = adapter
        .nativeCustodyAddress()
        .block(block.id)
        .call()
        .await
        .context("read custody address")?
        ._0;
    let custody_hash = adapter
        .nativeCustodyHash()
        .block(block.id)
        .call()
        .await
        .context("read custody hash")?
        ._0;
    if custody_hash != keccak256(custody_address.as_bytes()) {
        anyhow::bail!("adapter custody getter/hash mismatch");
    }
    let memo_asset = adapter
        .memoAsset()
        .block(block.id)
        .call()
        .await
        .context("read memo asset")?
        ._0;
    let factory_address = adapter
        .FACTORY()
        .block(block.id)
        .call()
        .await
        .context("read adapter factory")?
        ._0;
    let factory = IndexFactory::new(factory_address, provider.clone());
    if !factory
        .isIndexToken(index_token)
        .block(block.id)
        .call()
        .await
        .context("verify IndexToken registration")?
        ._0
    {
        anyhow::bail!("quote index token is not registered");
    }
    let funding_decimals = IERC20Metadata::new(funding_token, provider.clone())
        .decimals()
        .block(block.id)
        .call()
        .await
        .context("read funding token decimals")?
        ._0;
    let inbound = usable.state;
    Ok(AdapterChainState {
        inbound: InboundChainState {
            block,
            vault: inbound.vault,
            router: inbound.router,
            valid_until: inbound.validUntil,
            sequence: inbound.sequence,
            state_hash: usable.stateHash,
        },
        quote_nonce,
        adapter: adapter_address,
        registry: adapter_registry,
        router,
        target_token,
        custody_address,
        custody_hash,
        memo_asset,
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
        raw_response_hash: keccak256(commitment),
    }
}

fn raw_price_evidence(pair: &PricePair) -> RawPricePairEvidence<'_> {
    RawPricePairEvidence {
        source_id: pair.source_id,
        funding_subject: &pair.funding.subject,
        funding_value_wad: pair.funding.value.to_string(),
        funding_response_hash: format!("{:#x}", pair.funding.response_hash),
        funding_raw_response: &pair.funding.raw_response,
        target_subject: &pair.target.subject,
        target_value_wad: pair.target.value.to_string(),
        target_response_hash: format!("{:#x}", pair.target.response_hash),
        target_raw_response: &pair.target.raw_response,
    }
}

impl CollectorPublisher {
    async fn publish<T: Serialize + Sync>(
        &self,
        kind: &'static str,
        path: &'static str,
        message: &T,
        metrics: &Metrics,
    ) -> Result<()> {
        let deliveries = join_all(self.bases.iter().map(|base| async move {
            for attempt in 0..self.attempts {
                let result = self
                    .client
                    .post(format!("{base}{path}"))
                    .json(message)
                    .send()
                    .await;
                if result
                    .as_ref()
                    .is_ok_and(|response| response.status().is_success())
                {
                    return true;
                }
                if attempt + 1 < self.attempts {
                    tokio::time::sleep(Duration::from_millis(
                        200u64.saturating_mul(1u64 << attempt.min(5)),
                    ))
                    .await;
                }
            }
            false
        }))
        .await;
        let mut successes = 0usize;
        for delivered in deliveries {
            let result = if delivered { "success" } else { "error" };
            metrics
                .registry_collector_deliveries
                .with_label_values(&[kind, result])
                .inc();
            successes += usize::from(delivered);
        }
        if successes < 2 {
            anyhow::bail!("fewer than two collectors accepted the signed message");
        }
        Ok(())
    }
}

fn validate_config(config: &Config) -> Result<()> {
    if config.chain_id == 0
        || config.report_validity_secs == 0
        || config.report_validity_secs > 600
        || config.collector_publish_attempts == 0
        || config.collector_timeout_secs == 0
        || config.sources.len() != 3
        || config.collectors.len() < 2
        || config.routes.is_empty()
        || config.asset_prices.len() < 2
        || config.quote_policy.min_price_sources != 3
    {
        anyhow::bail!("invalid zero/count/lifetime policy setting");
    }
    validate_public_id(&config.operator_id)?;
    ensure_loopback(config.metrics_address.ip(), "metrics_address")?;
    let hsm = endpoint_origin("hsm_url", &config.hsm_url, true, false)?;
    let _rpc = endpoint_origin("ethereum_rpc_url", &config.ethereum_rpc_url, false, true)?;
    let _ = hsm;

    let mut source_ids = HashSet::new();
    let mut thor_origins = HashSet::new();
    let mut consensus_origins = HashSet::new();
    for source in &config.sources {
        validate_public_id(&source.id)?;
        if !source_ids.insert(source.id.clone())
            || !thor_origins.insert(endpoint_origin(
                "thornode_url",
                &source.thornode_url,
                false,
                true,
            )?)
            || !consensus_origins.insert(endpoint_origin(
                "consensus_url",
                &source.consensus_url,
                false,
                true,
            )?)
        {
            anyhow::bail!("THOR source identities and origins must be distinct");
        }
    }
    let mut collectors = HashSet::new();
    for collector in &config.collectors {
        if !collectors.insert(endpoint_origin("collector", collector, false, true)?) {
            anyhow::bail!("collector origins must be distinct");
        }
    }
    for (label, base) in [
        ("binance_base", config.binance_base.as_str()),
        ("coinbase_base", config.coinbase_base.as_str()),
        ("kraken_base", config.kraken_base.as_str()),
    ] {
        endpoint_origin(label, base, false, true)?;
    }
    let venue_origins = [
        endpoint_origin("binance_base", &config.binance_base, false, true)?,
        endpoint_origin("coinbase_base", &config.coinbase_base, false, true)?,
        endpoint_origin("kraken_base", &config.kraken_base, false, true)?,
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    if venue_origins.len() != 3 {
        anyhow::bail!("price venue origins must be distinct");
    }
    let mut price_assets = HashSet::new();
    for asset in &config.asset_prices {
        if asset.asset.is_empty()
            || asset.binance.is_empty()
            || asset.coinbase.is_empty()
            || asset.kraken.is_empty()
            || !price_assets.insert(asset.asset.clone())
            || !config
                .quote_policy
                .allowlisted_assets
                .contains(&asset.asset)
        {
            anyhow::bail!("invalid, duplicate, or unallowlisted asset price mapping");
        }
    }
    let mut routes = HashSet::new();
    for route in &config.routes {
        let adapter = parse_nonzero_address("route adapter", &route.adapter)?;
        let funding = parse_nonzero_address("route funding token", &route.funding_token)?;
        if route.funding_asset.is_empty()
            || !routes.insert((adapter, funding))
            || !config
                .quote_policy
                .allowlisted_assets
                .contains(&route.funding_asset)
            || !price_assets.contains(&route.funding_asset)
        {
            anyhow::bail!("invalid or duplicate route mapping");
        }
    }
    if config.coordinator_client_cert_pems.is_empty() || config.collector_server_ca_pems.is_empty()
    {
        anyhow::bail!("mTLS exact-peer allowlists must not be empty");
    }
    // Filesystem/secret inspection is deliberately last. Every pure policy
    // mutation above must fail before the process touches secret-bearing paths.
    validate_durable_and_secret_paths(config)?;
    Ok(())
}

fn validate_durable_and_secret_paths(config: &Config) -> Result<()> {
    validate_database_url(&config.database_url)?;
    validate_owner_only_directory(&config.evidence_dir)?;
    validate_secret_file(&config.server_key_pem)?;
    validate_secret_file(&config.collector_client_identity_pem)
}

fn endpoint_origin(
    label: &str,
    raw: &str,
    loopback_only: bool,
    require_https: bool,
) -> Result<String> {
    let url = reqwest::Url::parse(raw).with_context(|| format!("{label} must be a URL"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("{label} must not contain userinfo, query, or fragment");
    }
    let host = url
        .host_str()
        .with_context(|| format!("{label} has no host"))?;
    let host_ip = host.trim_start_matches('[').trim_end_matches(']');
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host_ip
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if loopback_only && !loopback {
        anyhow::bail!("{label} must terminate on loopback");
    }
    if require_https && url.scheme() != "https" {
        anyhow::bail!("{label} must use HTTPS");
    }
    if !require_https && url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        anyhow::bail!("{label} must use HTTPS or loopback HTTP");
    }
    let port = url
        .port_or_known_default()
        .with_context(|| format!("{label} has no usable port"))?;
    Ok(format!(
        "{}://{}:{port}",
        url.scheme(),
        host.to_ascii_lowercase()
    ))
}

fn validate_database_url(database_url: &str) -> Result<()> {
    let path = database_url
        .strip_prefix("sqlite://")
        .context("database_url must be sqlite:///absolute/path")?
        .split('?')
        .next()
        .context("database_url has no path")?;
    let path = Path::new(path);
    if !path.is_absolute() {
        anyhow::bail!("database_url must resolve to an absolute durable path");
    }
    let parent = path.parent().context("database path has no parent")?;
    validate_owner_only_directory(parent)
}

fn validate_owner_only_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect directory {}", path.display()))?;
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

fn validate_public_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        anyhow::bail!("public identifier must be 1..=64 safe ASCII characters");
    }
    Ok(())
}

fn ensure_loopback(address: IpAddr, label: &str) -> Result<()> {
    if !address.is_loopback() {
        anyhow::bail!("{label} must bind loopback");
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

fn load_server_tls(config: &Config) -> Result<rustls::ServerConfig> {
    let server_cert = fs::read(&config.server_cert_pem).context("read server certificate")?;
    let server_key = fs::read(&config.server_key_pem).context("read server TLS key")?;
    let pinned = config
        .coordinator_client_cert_pems
        .iter()
        .map(fs::read)
        .collect::<std::io::Result<Vec<_>>>()
        .context("read pinned coordinator certificates")?;
    server_config(
        load_cert_chain(&server_cert).context("parse server certificate")?,
        load_private_key(&server_key).context("parse server TLS key")?,
        pinned_cert_store(&pinned).context("parse exact coordinator peer pins")?,
    )
    .context("build server mTLS config")
}

fn collector_client(config: &Config) -> Result<reqwest::Client> {
    let identity_pem = fs::read(&config.collector_client_identity_pem)
        .context("read collector client identity")?;
    let peers = config
        .collector_server_ca_pems
        .iter()
        .map(fs::read)
        .collect::<std::io::Result<Vec<_>>>()
        .context("read exact collector peer bundles")?;
    let builder = exact_pinned_async_client_builder(
        HttpClientPolicy {
            connect_timeout: Duration::from_secs(config.collector_timeout_secs.min(3)),
            request_timeout: Duration::from_secs(config.collector_timeout_secs),
            max_response_bytes: 256 * 1024,
        },
        load_cert_chain(&identity_pem).context("parse collector client certificate")?,
        load_private_key(&identity_pem).context("parse collector client key")?,
        pinned_cert_store(&peers).context("parse exact collector peer pins")?,
    )?;
    builder.build().context("build collector mTLS client")
}

fn now_unix() -> Result<u64, SystemTimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| SystemTimeError)
}

#[derive(Debug, thiserror::Error)]
#[error("system clock is before Unix epoch")]
struct SystemTimeError;

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).map_or(i64::MAX, |converted| converted)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use super::*;

    fn production_config() -> Config {
        Config {
            chain_id: 1,
            registry_contract: "0x0000000000000000000000000000000000000001".into(),
            signer_address: "0x0000000000000000000000000000000000000002".into(),
            operator_id: "operator-01".into(),
            ethereum_rpc_url: "https://rpc.example".into(),
            hsm_url: "http://127.0.0.1:9000".into(),
            database_url: "sqlite:///definitely/not/read/registry.db".into(),
            evidence_dir: "/definitely/not/read/evidence".into(),
            listen_address: SocketAddr::from(([0, 0, 0, 0], 9443)),
            metrics_address: SocketAddr::from(([127, 0, 0, 1], 9096)),
            report_validity_secs: 60,
            inbound_policy: InboundPolicy {
                source_chain: "ETH".into(),
                enabled_chains: vec!["ETH".into(), "BTC".into()],
                allowlisted_pools: vec!["BTC.BTC".into()],
                max_tip_age_secs: 12,
                max_height_skew: 2,
            },
            quote_policy: QuotePolicy {
                allowlisted_assets: vec!["BTC.BTC".into(), "ETH.USDT".into()],
                min_price_sources: 3,
                max_price_age_secs: 30,
                max_price_deviation_bps: 100,
                external_floor_bps: 9_900,
                max_dispatch_ttl_secs: 300,
                max_stream_blocks: 100,
                max_total_swap_secs: 600,
            },
            sources: (1..=3)
                .map(|index| SourceConfig {
                    id: format!("source-{index}"),
                    thornode_url: format!("https://thornode-{index}.example"),
                    consensus_url: format!("https://consensus-{index}.example"),
                })
                .collect(),
            routes: vec![RouteConfig {
                adapter: "0x0000000000000000000000000000000000000003".into(),
                funding_token: "0x0000000000000000000000000000000000000004".into(),
                funding_asset: "ETH.USDT".into(),
            }],
            asset_prices: vec![
                AssetPriceConfig {
                    asset: "BTC.BTC".into(),
                    binance: "BTCUSDT".into(),
                    coinbase: "BTC-USD".into(),
                    kraken: "XBTUSD".into(),
                },
                AssetPriceConfig {
                    asset: "ETH.USDT".into(),
                    binance: "ETHUSDT".into(),
                    coinbase: "ETH-USD".into(),
                    kraken: "ETHUSD".into(),
                },
            ],
            binance_base: "https://binance.example".into(),
            coinbase_base: "https://coinbase.example".into(),
            kraken_base: "https://kraken.example".into(),
            collectors: vec![
                "https://collector-1.example".into(),
                "https://collector-2.example".into(),
            ],
            collector_publish_attempts: 3,
            collector_timeout_secs: 5,
            server_cert_pem: "/definitely/not/read/server.crt".into(),
            server_key_pem: "/definitely/not/read/server.key".into(),
            coordinator_client_cert_pems: vec!["/definitely/not/read/coordinator.crt".into()],
            collector_client_identity_pem: "/definitely/not/read/collector.pem".into(),
            collector_server_ca_pems: vec!["/definitely/not/read/collector-peer.pem".into()],
        }
    }

    fn assert_policy_rejection(config: &Config) {
        let error = validate_config(config).expect_err("unsafe production mutation must fail");
        assert!(
            !error.to_string().contains("definitely/not/read"),
            "policy mutation reached secret/path I/O: {error:#}"
        );
    }

    #[test]
    fn production_profile_behavior_rejects_unsafe_mutations() {
        let mut zero_chain = production_config();
        zero_chain.chain_id = 0;
        assert_policy_rejection(&zero_chain);

        let mut two_sources = production_config();
        two_sources.sources.truncate(2);
        assert_policy_rejection(&two_sources);

        let mut public_hsm = production_config();
        public_hsm.hsm_url = "https://hsm.example".into();
        assert_policy_rejection(&public_hsm);

        let mut plaintext_rpc = production_config();
        plaintext_rpc.ethereum_rpc_url = "http://rpc.example".into();
        assert_policy_rejection(&plaintext_rpc);

        let mut public_metrics = production_config();
        public_metrics.metrics_address = SocketAddr::from(([0, 0, 0, 0], 9096));
        assert_policy_rejection(&public_metrics);

        let mut duplicate_sources = production_config();
        duplicate_sources.sources[1].id = duplicate_sources.sources[0].id.clone();
        assert_policy_rejection(&duplicate_sources);

        let mut duplicate_venues = production_config();
        duplicate_venues.coinbase_base = duplicate_venues.binance_base.clone();
        assert_policy_rejection(&duplicate_venues);

        let mut no_peer_pins = production_config();
        no_peer_pins.coordinator_client_cert_pems.clear();
        assert_policy_rejection(&no_peer_pins);
    }

    #[test]
    fn endpoint_policy_rejects_credentials_and_public_hsm() {
        assert!(endpoint_origin("rpc", "https://rpc.example", false, true).is_ok());
        assert!(endpoint_origin("rpc", "https://user:secret@rpc.example", false, true).is_err());
        assert!(endpoint_origin("hsm", "http://127.0.0.1:9000", true, false).is_ok());
        assert!(endpoint_origin("hsm", "https://hsm.example", true, false).is_err());
    }
}
