//! Untrusted exact-quorum settlement coordinator and permissionless poster.
//!
//! This process has no protocol signing key. It fans one logical trigger out
//! to independently operated finalized observers over pinned mutual TLS,
//! binds each endpoint to its configured on-chain signer, recovery-verifies
//! every response, groups byte-identical EIP-712 payloads, and posts only an
//! exact threshold payload through a node-managed gas-paying account.

use std::collections::HashSet;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::providers::{Provider, ProviderBuilder, ReqwestProvider};
use alloy_primitives::{Address, Bytes, B256, U256};
use anyhow::{Context, Result};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use futures_util::future::join_all;
use futures_util::StreamExt;
use prometheus::Registry;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use xindex_chain_eth::bindings::{AttestationOracle, IntentQueue};
use xindex_chain_eth::rpc::is_transient_rpc_error;
use xindex_ops::tls::{
    load_cert_chain, load_private_key, pinned_root_store, serve_mtls, server_config,
};
use xindex_ops::{serve_metrics, Metrics};
use xindex_relayer::{
    ReadySettlement, SettlementCollector, SettlementIngestOutcome, SettlementPayload,
};
use xindex_shared::eip712::attestation_oracle_domain;
use xindex_shared::evidence::EvidenceStore;
use xindex_shared::settlement_wire::{
    MintSettlementRequest, RedemptionSettlementRequest, SignedDeliverySettlement,
    SignedMintSettlement, SignedRefundSettlement, SignedStreamedSettlement,
};

const MAX_API_BODY_BYTES: usize = 64 * 1024;
const MAX_OBSERVER_BODY_BYTES: usize = 256 * 1024;
const PRODUCTION_OBSERVER_COUNT: usize = 5;
const PRODUCTION_OBSERVER_THRESHOLD: usize = 3;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Xindex independent settlement quorum collector + permissionless poster"
)]
struct Args {
    /// Strict JSON production configuration. The file must be owner-only.
    config: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    chain_id: u64,
    ethereum_rpc_url: String,
    attestation_oracle: String,
    intent_queue: String,
    asset_id: String,
    redemption_leg_index: u32,
    poster_address: String,
    observers: Vec<ObserverConfig>,
    threshold: usize,
    max_response_age_secs: u64,
    observer_timeout_secs: u64,
    post_attempts: u32,
    retry_base_ms: u64,
    retry_max_ms: u64,
    evidence_dir: PathBuf,
    listen_address: SocketAddr,
    metrics_address: SocketAddr,
    observer_client_identity_pem: PathBuf,
    observer_server_ca_pems: Vec<PathBuf>,
    server_cert_pem: PathBuf,
    server_key_pem: PathBuf,
    pinned_client_cert_pems: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserverConfig {
    operator_id: String,
    signer_address: String,
    base_url: String,
}

#[derive(Debug, Clone)]
struct ObserverEndpoint {
    operator_id: String,
    signer_address: Address,
    base_url: String,
}

#[derive(Clone)]
struct AppState {
    oracle_address: Address,
    queue_address: Address,
    asset_id: B256,
    redemption_leg_index: u32,
    threshold: usize,
    provider: Arc<ReqwestProvider>,
    observer_client: reqwest::Client,
    observers: Arc<Vec<ObserverEndpoint>>,
    collector: Arc<Mutex<SettlementCollector>>,
    ready_tx: mpsc::Sender<ReadySettlement>,
    evidence: EvidenceStore,
    metrics: Metrics,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppState")
            .field("oracle_address", &self.oracle_address)
            .field("queue_address", &self.queue_address)
            .field("asset_id", &self.asset_id)
            .field("observer_count", &self.observers.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
enum ApiError {
    BadRequest(&'static str),
    Refused(&'static str),
    Dependency(&'static str),
    QuorumUnavailable { valid: usize, required: usize },
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::BadRequest(reason) => (
                StatusCode::BAD_REQUEST,
                json!({"error": "bad_request", "reason": reason}),
            ),
            Self::Refused(reason) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({"error": "refused", "reason": reason}),
            ),
            Self::Dependency(dependency) => (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "dependency_unavailable", "dependency": dependency}),
            ),
            Self::QuorumUnavailable { valid, required } => (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({
                    "error": "quorum_unavailable",
                    "validSignatures": valid,
                    "requiredSignatures": required,
                }),
            ),
        };
        (status, Json(body)).into_response()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CollectorResponse {
    status: &'static str,
    valid_signatures: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    xindex_ops::init_tracing();
    let args = Args::parse();
    validate_secret_file(&args.config)?;
    let config: Config = serde_json::from_slice(
        &fs::read(&args.config).context("read settlement collector configuration")?,
    )
    .context("decode strict settlement collector configuration")?;
    validate_config(&config)?;
    run(config).await
}

async fn run(config: Config) -> Result<()> {
    let oracle_address = parse_nonzero_address("attestation_oracle", &config.attestation_oracle)?;
    let queue_address = parse_nonzero_address("intent_queue", &config.intent_queue)?;
    let asset_id = parse_nonzero_b256("asset_id", &config.asset_id)?;
    let poster_address = parse_nonzero_address("poster_address", &config.poster_address)?;
    let observers = parse_observers(&config.observers)?;
    let rpc_url = config
        .ethereum_rpc_url
        .parse()
        .context("parse ethereum_rpc_url")?;
    let provider = Arc::new(ProviderBuilder::new().on_http(rpc_url));
    verify_roster(
        &provider,
        config.chain_id,
        oracle_address,
        queue_address,
        &observers,
        config.threshold,
    )
    .await?;

    let registry = Registry::new();
    let metrics = Metrics::new(&registry).context("register metrics")?;
    let evidence = EvidenceStore::open(&config.evidence_dir).context("open evidence store")?;
    let observer_client = build_observer_client(&config)?;
    let collector = SettlementCollector::new(
        attestation_oracle_domain(config.chain_id, oracle_address),
        observers.iter().map(|observer| observer.signer_address),
        config.threshold,
        config.max_response_age_secs,
    )
    .context("build exact settlement collector")?;
    let (ready_tx, ready_rx) = mpsc::channel::<ReadySettlement>(256);
    let worker = tokio::spawn(poster_worker(
        ready_rx,
        Arc::clone(&provider),
        oracle_address,
        queue_address,
        asset_id,
        poster_address,
        config.post_attempts,
        config.retry_base_ms,
        config.retry_max_ms,
        metrics.clone(),
    ));
    let state = AppState {
        oracle_address,
        queue_address,
        asset_id,
        redemption_leg_index: config.redemption_leg_index,
        threshold: config.threshold,
        provider,
        observer_client,
        observers: Arc::new(observers),
        collector: Arc::new(Mutex::new(collector)),
        ready_tx,
        evidence,
        metrics,
    };
    let app = Router::new()
        .route("/api/v1/settlement/mint", post(trigger_mint))
        .route("/api/v1/settlement/delivery", post(trigger_delivery))
        .route("/api/v1/settlement/refund", post(trigger_refund))
        .route("/api/v1/settlement/streamed", post(trigger_streamed))
        .route("/api/v1/health", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(MAX_API_BODY_BYTES))
        .with_state(state);
    let tls = Arc::new(build_server_tls(&config)?);
    let listener = tokio::net::TcpListener::bind(config.listen_address)
        .await
        .context("bind settlement collector mTLS listener")?;
    info!(
        address = %config.listen_address,
        chain_id = config.chain_id,
        %oracle_address,
        threshold = config.threshold,
        observers = config.observers.len(),
        "settlement collector ready"
    );
    let api_server = serve_mtls(listener, tls, app);
    let metrics_server = serve_metrics(registry, config.metrics_address);
    tokio::select! {
        result = api_server => result.context("settlement collector mTLS server"),
        result = metrics_server => result.context("settlement collector metrics server"),
        result = worker => match result {
            Ok(()) => Err(anyhow::anyhow!("settlement poster worker exited while API server was live")),
            Err(error) => Err(anyhow::anyhow!("settlement poster worker crashed: {error}")),
        },
    }
}

async fn trigger_mint(
    State(state): State<AppState>,
    Json(request): Json<MintSettlementRequest>,
) -> Result<(StatusCode, Json<CollectorResponse>), ApiError> {
    let intent_id = parse_wire_b256(&request.intent_id).ok_or(ApiError::BadRequest("intent_id"))?;
    let slot_index =
        parse_wire_u256(&request.slot_index).ok_or(ApiError::BadRequest("slot_index"))?;
    precheck_mint(&state, intent_id, slot_index).await?;
    let jobs = state.observers.iter().map(|observer| {
        fetch_observer::<_, SignedMintSettlement>(
            &state.observer_client,
            observer,
            "/api/v1/settlement/mint",
            &request,
        )
    });
    let results = join_all(jobs).await;
    let mut ready = None;
    let mut highest = 0;
    for (observer, result) in state.observers.iter().zip(results) {
        let message = match result {
            Ok(message) => message,
            Err(error) => {
                state
                    .metrics
                    .observer_events
                    .with_label_values(&["mint", "error"])
                    .inc();
                warn!(operator = %observer.operator_id, %error, "mint observer unavailable");
                continue;
            }
        };
        if !response_matches_endpoint(&message.signer_address, observer) {
            state
                .metrics
                .observer_events
                .with_label_values(&["mint", "refused"])
                .inc();
            warn!(operator = %observer.operator_id, "mint response signer does not match endpoint");
            continue;
        }
        persist_observer_response(&state, "mint", observer, &request, &message)?;
        let outcome = state
            .collector
            .lock()
            .map_err(|_| ApiError::Dependency("collector_lock"))?
            .ingest_mint(&message, intent_id, slot_index, now_unix_wire()?)
            .map_err(|error| {
                warn!(operator = %observer.operator_id, %error, "mint signature refused");
                ApiError::Refused("observer_signature")
            });
        match outcome {
            Ok(value) => record_outcome(&state, "mint", value, &mut ready, &mut highest),
            Err(error) => {
                state
                    .metrics
                    .observer_events
                    .with_label_values(&["mint", "refused"])
                    .inc();
                warn!(operator = %observer.operator_id, ?error, "mint response rejected");
            }
        }
    }
    finish_collection(&state, "mint", ready, highest).await
}

async fn trigger_delivery(
    State(state): State<AppState>,
    Json(request): Json<RedemptionSettlementRequest>,
) -> Result<(StatusCode, Json<CollectorResponse>), ApiError> {
    let (redemption_id, leg_index) = parse_redemption_request(&state, &request)?;
    precheck_redemption(&state, redemption_id, leg_index).await?;
    let jobs = state.observers.iter().map(|observer| {
        fetch_observer::<_, SignedDeliverySettlement>(
            &state.observer_client,
            observer,
            "/api/v1/settlement/delivery",
            &request,
        )
    });
    let results = join_all(jobs).await;
    let mut ready = None;
    let mut highest = 0;
    for (observer, result) in state.observers.iter().zip(results) {
        let message = match result {
            Ok(message) => message,
            Err(error) => {
                observer_transport_error(&state, "delivery", observer, &error);
                continue;
            }
        };
        if !response_matches_endpoint(&message.signer_address, observer) {
            observer_signer_mismatch(&state, "delivery", observer);
            continue;
        }
        persist_observer_response(&state, "delivery", observer, &request, &message)?;
        let outcome = state
            .collector
            .lock()
            .map_err(|_| ApiError::Dependency("collector_lock"))?
            .ingest_delivery(
                &message,
                redemption_id,
                leg_index,
                state.asset_id,
                now_unix_wire()?,
            );
        collect_or_log(
            &state,
            "delivery",
            observer,
            outcome,
            &mut ready,
            &mut highest,
        );
    }
    finish_collection(&state, "delivery", ready, highest).await
}

async fn trigger_refund(
    State(state): State<AppState>,
    Json(request): Json<RedemptionSettlementRequest>,
) -> Result<(StatusCode, Json<CollectorResponse>), ApiError> {
    let (redemption_id, leg_index) = parse_redemption_request(&state, &request)?;
    precheck_redemption(&state, redemption_id, leg_index).await?;
    let jobs = state.observers.iter().map(|observer| {
        fetch_observer::<_, SignedRefundSettlement>(
            &state.observer_client,
            observer,
            "/api/v1/settlement/refund",
            &request,
        )
    });
    let results = join_all(jobs).await;
    let mut ready = None;
    let mut highest = 0;
    for (observer, result) in state.observers.iter().zip(results) {
        let message = match result {
            Ok(message) => message,
            Err(error) => {
                observer_transport_error(&state, "refund", observer, &error);
                continue;
            }
        };
        if !response_matches_endpoint(&message.signer_address, observer) {
            observer_signer_mismatch(&state, "refund", observer);
            continue;
        }
        persist_observer_response(&state, "refund", observer, &request, &message)?;
        let outcome = state
            .collector
            .lock()
            .map_err(|_| ApiError::Dependency("collector_lock"))?
            .ingest_refund(
                &message,
                redemption_id,
                leg_index,
                state.asset_id,
                now_unix_wire()?,
            );
        collect_or_log(
            &state,
            "refund",
            observer,
            outcome,
            &mut ready,
            &mut highest,
        );
    }
    finish_collection(&state, "refund", ready, highest).await
}

async fn trigger_streamed(
    State(state): State<AppState>,
    Json(request): Json<RedemptionSettlementRequest>,
) -> Result<(StatusCode, Json<CollectorResponse>), ApiError> {
    let (redemption_id, leg_index) = parse_redemption_request(&state, &request)?;
    precheck_redemption(&state, redemption_id, leg_index).await?;
    let jobs = state.observers.iter().map(|observer| {
        fetch_observer::<_, SignedStreamedSettlement>(
            &state.observer_client,
            observer,
            "/api/v1/settlement/streamed",
            &request,
        )
    });
    let results = join_all(jobs).await;
    let mut ready = None;
    let mut highest = 0;
    for (observer, result) in state.observers.iter().zip(results) {
        let message = match result {
            Ok(message) => message,
            Err(error) => {
                observer_transport_error(&state, "streamed", observer, &error);
                continue;
            }
        };
        if !response_matches_endpoint(&message.signer_address, observer) {
            observer_signer_mismatch(&state, "streamed", observer);
            continue;
        }
        persist_observer_response(&state, "streamed", observer, &request, &message)?;
        let outcome = state
            .collector
            .lock()
            .map_err(|_| ApiError::Dependency("collector_lock"))?
            .ingest_streamed(
                &message,
                redemption_id,
                leg_index,
                state.asset_id,
                now_unix_wire()?,
            );
        collect_or_log(
            &state,
            "streamed",
            observer,
            outcome,
            &mut ready,
            &mut highest,
        );
    }
    finish_collection(&state, "streamed", ready, highest).await
}

fn parse_redemption_request(
    state: &AppState,
    request: &RedemptionSettlementRequest,
) -> Result<(B256, U256), ApiError> {
    let redemption_id =
        parse_wire_b256(&request.redemption_id).ok_or(ApiError::BadRequest("redemption_id"))?;
    let leg_index = parse_wire_u256(&request.leg_index).ok_or(ApiError::BadRequest("leg_index"))?;
    if leg_index != U256::from(state.redemption_leg_index) {
        return Err(ApiError::Refused("unsupported_leg_index"));
    }
    if request.inbound_tx_hash.len() != 64
        || !request
            .inbound_tx_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ApiError::BadRequest("inbound_tx_hash"));
    }
    Ok((redemption_id, leg_index))
}

async fn precheck_mint(
    state: &AppState,
    intent_id: B256,
    slot_index: U256,
) -> Result<(), ApiError> {
    let queue = IntentQueue::new(state.queue_address, Arc::clone(&state.provider));
    let intent = queue
        .getIntent(intent_id)
        .call()
        .await
        .map_err(|error| {
            warn!(%error, "mint queue precheck failed");
            ApiError::Dependency("ethereum_rpc")
        })?
        ._0;
    if intent.oracle != state.oracle_address {
        return Err(ApiError::Refused("wrong_or_unknown_oracle"));
    }
    let index: usize = slot_index
        .try_into()
        .map_err(|_| ApiError::BadRequest("slot_index"))?;
    let slot = intent
        .slots
        .get(index)
        .ok_or(ApiError::Refused("unknown_slot"))?;
    if slot.assetId != state.asset_id || !slot.expectedAmount.is_zero() {
        return Err(ApiError::Refused("unsupported_mint_slot"));
    }
    if slot.attested {
        return Err(ApiError::Refused("slot_already_attested"));
    }
    Ok(())
}

async fn precheck_redemption(
    state: &AppState,
    redemption_id: B256,
    leg_index: U256,
) -> Result<(), ApiError> {
    let queue = IntentQueue::new(state.queue_address, Arc::clone(&state.provider));
    let redemption = queue
        .getRedemption(redemption_id)
        .call()
        .await
        .map_err(|error| {
            warn!(%error, "redemption queue precheck failed");
            ApiError::Dependency("ethereum_rpc")
        })?
        ._0;
    if redemption.oracle != state.oracle_address {
        return Err(ApiError::Refused("wrong_or_unknown_oracle"));
    }
    let index: usize = leg_index
        .try_into()
        .map_err(|_| ApiError::BadRequest("leg_index"))?;
    let leg = redemption
        .legs
        .get(index)
        .ok_or(ApiError::Refused("unknown_leg"))?;
    if leg.assetId != state.asset_id {
        return Err(ApiError::Refused("wrong_asset"));
    }
    if leg.attested || leg.refunded {
        return Err(ApiError::Refused("leg_already_resolved"));
    }
    Ok(())
}

async fn fetch_observer<T, R>(
    client: &reqwest::Client,
    observer: &ObserverEndpoint,
    path: &str,
    request: &T,
) -> Result<R>
where
    T: Serialize + Sync + ?Sized,
    R: DeserializeOwned,
{
    let url = format!("{}{}", observer.base_url, path);
    let response = client
        .post(url)
        .json(request)
        .send()
        .await
        .context("observer request")?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("observer refused with HTTP {status}");
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_OBSERVER_BODY_BYTES as u64)
    {
        anyhow::bail!("observer response exceeds body limit");
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("observer response body")?;
        if body.len().saturating_add(chunk.len()) > MAX_OBSERVER_BODY_BYTES {
            anyhow::bail!("observer response exceeds body limit");
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).context("decode observer response")
}

fn response_matches_endpoint(raw: &str, observer: &ObserverEndpoint) -> bool {
    Address::from_str(raw).is_ok_and(|address| address == observer.signer_address)
}

fn persist_observer_response<T, R>(
    state: &AppState,
    kind: &str,
    observer: &ObserverEndpoint,
    request: &T,
    response: &R,
) -> Result<(), ApiError>
where
    T: Serialize,
    R: Serialize,
{
    state
        .evidence
        .persist_hashed(
            &format!("settlement-{kind}-{}", observer.operator_id),
            &json!({
                "schema": "xindex.settlement-collector-response.v1",
                "kind": kind,
                "operatorId": observer.operator_id,
                "expectedSigner": format!("{:#x}", observer.signer_address),
                "request": request,
                "response": response,
            }),
        )
        .map_err(|error| {
            error!(%error, "collector response evidence persistence failed");
            ApiError::Dependency("evidence_store")
        })?;
    Ok(())
}

fn collect_or_log(
    state: &AppState,
    kind: &'static str,
    observer: &ObserverEndpoint,
    outcome: Result<SettlementIngestOutcome, impl std::fmt::Display>,
    ready: &mut Option<ReadySettlement>,
    highest: &mut usize,
) {
    match outcome {
        Ok(value) => record_outcome(state, kind, value, ready, highest),
        Err(error) => {
            state
                .metrics
                .observer_events
                .with_label_values(&[kind, "refused"])
                .inc();
            warn!(operator = %observer.operator_id, %error, "settlement response rejected");
        }
    }
}

fn record_outcome(
    state: &AppState,
    kind: &'static str,
    outcome: SettlementIngestOutcome,
    ready: &mut Option<ReadySettlement>,
    highest: &mut usize,
) {
    match outcome {
        SettlementIngestOutcome::Accepted { count } => {
            *highest = (*highest).max(count);
            state
                .metrics
                .observer_events
                .with_label_values(&[kind, "observed"])
                .inc();
        }
        SettlementIngestOutcome::Duplicate { count } => {
            *highest = (*highest).max(count);
            state
                .metrics
                .observer_events
                .with_label_values(&[kind, "duplicate"])
                .inc();
        }
        SettlementIngestOutcome::Ready(candidate) => {
            *highest = (*highest).max(candidate.signatures.len());
            state
                .metrics
                .observer_events
                .with_label_values(&[kind, "observed"])
                .inc();
            if ready.is_none() {
                *ready = Some(candidate);
            }
        }
    }
}

async fn finish_collection(
    state: &AppState,
    kind: &'static str,
    ready: Option<ReadySettlement>,
    highest: usize,
) -> Result<(StatusCode, Json<CollectorResponse>), ApiError> {
    let Some(ready) = ready else {
        return Err(ApiError::QuorumUnavailable {
            valid: highest,
            required: state.threshold,
        });
    };
    let count = ready.signatures.len();
    state
        .evidence
        .persist_hashed(
            &format!("settlement-quorum-{kind}"),
            &ready_evidence(&ready),
        )
        .map_err(|error| {
            error!(%error, "settlement quorum evidence persistence failed");
            ApiError::Dependency("evidence_store")
        })?;
    state
        .ready_tx
        .send(ready)
        .await
        .map_err(|_| ApiError::Dependency("poster_worker"))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CollectorResponse {
            status: "quorum",
            valid_signatures: count,
        }),
    ))
}

fn ready_evidence(ready: &ReadySettlement) -> Value {
    let payload = match ready.payload {
        SettlementPayload::Mint {
            intent_id,
            slot_index,
            attested_amount,
        } => json!({
            "kind": "mint",
            "intentId": format!("{intent_id:#x}"),
            "slotIndex": slot_index.to_string(),
            "attestedAmount": attested_amount.to_string(),
        }),
        SettlementPayload::Delivery {
            redemption_id,
            leg_index,
            asset_id,
            delivered_amount,
        } => json!({
            "kind": "delivery",
            "redemptionId": format!("{redemption_id:#x}"),
            "legIndex": leg_index.to_string(),
            "assetId": format!("{asset_id:#x}"),
            "deliveredAmount": delivered_amount.to_string(),
        }),
        SettlementPayload::Refund {
            redemption_id,
            leg_index,
            asset_id,
            refunded_amount,
        } => json!({
            "kind": "refund",
            "redemptionId": format!("{redemption_id:#x}"),
            "legIndex": leg_index.to_string(),
            "assetId": format!("{asset_id:#x}"),
            "refundedAmount": refunded_amount.to_string(),
        }),
        SettlementPayload::Streamed {
            redemption_id,
            leg_index,
            asset_id,
            delivered_usdt,
            refunded_native,
        } => json!({
            "kind": "streamed",
            "redemptionId": format!("{redemption_id:#x}"),
            "legIndex": leg_index.to_string(),
            "assetId": format!("{asset_id:#x}"),
            "deliveredUsdt": delivered_usdt.to_string(),
            "refundedNative": refunded_native.to_string(),
        }),
    };
    json!({
        "schema": "xindex.settlement-collector-quorum.v1",
        "payload": payload,
        "signatures": ready
            .signatures
            .iter()
            .map(|signature| format!("0x{}", alloy_primitives::hex::encode(signature)))
            .collect::<Vec<_>>(),
    })
}

fn observer_transport_error(
    state: &AppState,
    kind: &'static str,
    observer: &ObserverEndpoint,
    error: &anyhow::Error,
) {
    state
        .metrics
        .observer_events
        .with_label_values(&[kind, "error"])
        .inc();
    warn!(operator = %observer.operator_id, %error, "settlement observer unavailable");
}

fn observer_signer_mismatch(state: &AppState, kind: &'static str, observer: &ObserverEndpoint) {
    state
        .metrics
        .observer_events
        .with_label_values(&[kind, "refused"])
        .inc();
    warn!(operator = %observer.operator_id, "response signer does not match observer endpoint");
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the isolated poster worker explicitly owns every on-chain identity, retry bound, idempotence check, and exact ABI call"
)]
async fn poster_worker(
    mut ready_rx: mpsc::Receiver<ReadySettlement>,
    provider: Arc<ReqwestProvider>,
    oracle_address: Address,
    queue_address: Address,
    asset_id: B256,
    poster_address: Address,
    attempts: u32,
    retry_base_ms: u64,
    retry_max_ms: u64,
    metrics: Metrics,
) {
    let oracle = AttestationOracle::new(oracle_address, Arc::clone(&provider));
    let queue = IntentQueue::new(queue_address, provider);
    while let Some(ready) = ready_rx.recv().await {
        let kind = payload_kind(ready.payload);
        for attempt in 1..=attempts {
            match settlement_state(&queue, oracle_address, asset_id, ready.payload).await {
                Ok(SettlementState::Exact) => {
                    metrics
                        .observer_events
                        .with_label_values(&[kind, "duplicate"])
                        .inc();
                    info!(kind, "settlement already matches on-chain state");
                    break;
                }
                Ok(SettlementState::Conflict(reason)) => {
                    metrics
                        .observer_events
                        .with_label_values(&[kind, "refused"])
                        .inc();
                    error!(kind, reason, "settlement conflicts with on-chain state");
                    break;
                }
                Ok(SettlementState::Unresolved) => {}
                Err(error) if is_transient_rpc_error(&error) && attempt < attempts => {
                    warn!(kind, attempt, %error, "settlement state read failed; retrying");
                    tokio::time::sleep(retry_delay(attempt, retry_base_ms, retry_max_ms)).await;
                    continue;
                }
                Err(error) => {
                    metrics
                        .observer_events
                        .with_label_values(&[kind, "error"])
                        .inc();
                    error!(kind, %error, "settlement state read failed permanently");
                    break;
                }
            }
            let signatures: Vec<Bytes> =
                ready.signatures.iter().copied().map(Bytes::from).collect();
            let sent = match ready.payload {
                SettlementPayload::Mint {
                    intent_id,
                    slot_index,
                    attested_amount,
                } => {
                    oracle
                        .attest(intent_id, slot_index, attested_amount, signatures)
                        .from(poster_address)
                        .send()
                        .await
                }
                SettlementPayload::Delivery {
                    redemption_id,
                    leg_index,
                    asset_id,
                    delivered_amount,
                } => {
                    oracle
                        .attestRedemption(
                            redemption_id,
                            leg_index,
                            asset_id,
                            delivered_amount,
                            signatures,
                        )
                        .from(poster_address)
                        .send()
                        .await
                }
                SettlementPayload::Refund {
                    redemption_id,
                    leg_index,
                    asset_id,
                    refunded_amount,
                } => {
                    oracle
                        .attestRefund(
                            redemption_id,
                            leg_index,
                            asset_id,
                            refunded_amount,
                            signatures,
                        )
                        .from(poster_address)
                        .send()
                        .await
                }
                SettlementPayload::Streamed {
                    redemption_id,
                    leg_index,
                    asset_id,
                    delivered_usdt,
                    refunded_native,
                } => {
                    oracle
                        .attestStreamedSettlement(
                            redemption_id,
                            leg_index,
                            asset_id,
                            delivered_usdt,
                            refunded_native,
                            signatures,
                        )
                        .from(poster_address)
                        .send()
                        .await
                }
            };
            match sent {
                Ok(transaction) => match transaction.get_receipt().await {
                    Ok(receipt) if receipt.status() => {
                        metrics
                            .observer_events
                            .with_label_values(&[kind, "posted"])
                            .inc();
                        info!(kind, tx_hash = %receipt.transaction_hash, "settlement attestation confirmed");
                        break;
                    }
                    Ok(receipt) => {
                        metrics
                            .observer_events
                            .with_label_values(&[kind, "refused"])
                            .inc();
                        error!(kind, tx_hash = %receipt.transaction_hash, "settlement transaction reverted");
                        break;
                    }
                    Err(error) if attempt < attempts => {
                        warn!(kind, attempt, %error, "settlement receipt unavailable; retrying idempotently");
                        tokio::time::sleep(retry_delay(attempt, retry_base_ms, retry_max_ms)).await;
                    }
                    Err(error) => {
                        metrics
                            .observer_events
                            .with_label_values(&[kind, "error"])
                            .inc();
                        error!(kind, %error, "settlement receipt attempts exhausted");
                        break;
                    }
                },
                Err(error) if is_transient_rpc_error(&error) && attempt < attempts => {
                    warn!(kind, attempt, %error, "settlement submission failed; retrying");
                    tokio::time::sleep(retry_delay(attempt, retry_base_ms, retry_max_ms)).await;
                }
                Err(error) => {
                    metrics
                        .observer_events
                        .with_label_values(&[kind, "refused"])
                        .inc();
                    error!(kind, %error, "settlement submission failed permanently");
                    break;
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettlementState {
    Unresolved,
    Exact,
    Conflict(&'static str),
}

#[expect(
    clippy::too_many_lines,
    reason = "one exhaustive payload match keeps all four exact on-chain idempotence checks adjacent"
)]
async fn settlement_state<P, T>(
    queue: &IntentQueue::IntentQueueInstance<T, P>,
    oracle_address: Address,
    expected_asset_id: B256,
    payload: SettlementPayload,
) -> Result<SettlementState>
where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    match payload {
        SettlementPayload::Mint {
            intent_id,
            slot_index,
            attested_amount,
        } => {
            let intent = queue.getIntent(intent_id).call().await?._0;
            if intent.oracle != oracle_address {
                return Ok(SettlementState::Conflict("wrong_or_unknown_oracle"));
            }
            let Ok(index) = usize::try_from(slot_index) else {
                return Ok(SettlementState::Conflict("slot_index_overflow"));
            };
            let Some(slot) = intent.slots.get(index) else {
                return Ok(SettlementState::Conflict("unknown_slot"));
            };
            if slot.assetId != expected_asset_id {
                return Ok(SettlementState::Conflict("wrong_asset"));
            }
            if !slot.attested {
                return Ok(SettlementState::Unresolved);
            }
            if slot.attestedAmount == attested_amount {
                Ok(SettlementState::Exact)
            } else {
                Ok(SettlementState::Conflict("different_mint_amount"))
            }
        }
        SettlementPayload::Delivery {
            redemption_id,
            leg_index,
            asset_id,
            delivered_amount,
        } => {
            let redemption = queue.getRedemption(redemption_id).call().await?._0;
            let Ok(index) = usize::try_from(leg_index) else {
                return Ok(SettlementState::Conflict("leg_index_overflow"));
            };
            Ok(redemption_state(
                redemption.oracle,
                redemption.legs.get(index).map(|leg| {
                    (
                        leg.assetId,
                        leg.attested,
                        leg.refunded,
                        leg.attestedAmount,
                        leg.refundedAmount,
                    )
                }),
                oracle_address,
                expected_asset_id,
                asset_id,
                Some(delivered_amount),
                None,
            ))
        }
        SettlementPayload::Refund {
            redemption_id,
            leg_index,
            asset_id,
            refunded_amount,
        } => {
            let redemption = queue.getRedemption(redemption_id).call().await?._0;
            let Ok(index) = usize::try_from(leg_index) else {
                return Ok(SettlementState::Conflict("leg_index_overflow"));
            };
            Ok(redemption_state(
                redemption.oracle,
                redemption.legs.get(index).map(|leg| {
                    (
                        leg.assetId,
                        leg.attested,
                        leg.refunded,
                        leg.attestedAmount,
                        leg.refundedAmount,
                    )
                }),
                oracle_address,
                expected_asset_id,
                asset_id,
                None,
                Some(refunded_amount),
            ))
        }
        SettlementPayload::Streamed {
            redemption_id,
            leg_index,
            asset_id,
            delivered_usdt,
            refunded_native,
        } => {
            let redemption = queue.getRedemption(redemption_id).call().await?._0;
            let Ok(index) = usize::try_from(leg_index) else {
                return Ok(SettlementState::Conflict("leg_index_overflow"));
            };
            Ok(redemption_state(
                redemption.oracle,
                redemption.legs.get(index).map(|leg| {
                    (
                        leg.assetId,
                        leg.attested,
                        leg.refunded,
                        leg.attestedAmount,
                        leg.refundedAmount,
                    )
                }),
                oracle_address,
                expected_asset_id,
                asset_id,
                Some(delivered_usdt),
                Some(refunded_native),
            ))
        }
    }
}

fn redemption_state(
    redemption_oracle: Address,
    leg: Option<(B256, bool, bool, U256, U256)>,
    oracle_address: Address,
    expected_asset_id: B256,
    payload_asset_id: B256,
    delivered: Option<U256>,
    refunded: Option<U256>,
) -> SettlementState {
    if redemption_oracle != oracle_address {
        return SettlementState::Conflict("wrong_or_unknown_oracle");
    }
    if payload_asset_id != expected_asset_id {
        return SettlementState::Conflict("wrong_asset");
    }
    let Some((leg_asset_id, leg_attested, leg_refunded, attested_amount, refunded_amount)) = leg
    else {
        return SettlementState::Conflict("unknown_leg");
    };
    if leg_asset_id != expected_asset_id {
        return SettlementState::Conflict("wrong_asset");
    }
    if !leg_attested && !leg_refunded {
        return SettlementState::Unresolved;
    }
    let delivered_exact = delivered
        .is_none_or(|amount| leg_attested != amount.is_zero() && attested_amount == amount);
    let refunded_exact =
        refunded.is_none_or(|amount| leg_refunded != amount.is_zero() && refunded_amount == amount);
    let unexpected_delivery = delivered.is_none() && leg_attested;
    let unexpected_refund = refunded.is_none() && leg_refunded;
    if delivered_exact && refunded_exact && !unexpected_delivery && !unexpected_refund {
        SettlementState::Exact
    } else {
        SettlementState::Conflict("different_redemption_outcome")
    }
}

fn payload_kind(payload: SettlementPayload) -> &'static str {
    match payload {
        SettlementPayload::Mint { .. } => "mint",
        SettlementPayload::Delivery { .. } => "delivery",
        SettlementPayload::Refund { .. } => "refund",
        SettlementPayload::Streamed { .. } => "streamed",
    }
}

async fn verify_roster(
    provider: &Arc<ReqwestProvider>,
    expected_chain_id: u64,
    oracle_address: Address,
    queue_address: Address,
    observers: &[ObserverEndpoint],
    threshold: usize,
) -> Result<()> {
    let chain_id = provider.get_chain_id().await.context("read chain id")?;
    if chain_id != expected_chain_id {
        anyhow::bail!("Ethereum chain id {chain_id} differs from configured {expected_chain_id}");
    }
    let oracle = AttestationOracle::new(oracle_address, Arc::clone(provider));
    let onchain_threshold: usize = oracle
        .threshold()
        .call()
        .await
        .context("read attestation threshold")?
        ._0
        .try_into()
        .context("threshold does not fit usize")?;
    let onchain_count: usize = oracle
        .signerCount()
        .call()
        .await
        .context("read attestation signer count")?
        ._0
        .try_into()
        .context("signer count does not fit usize")?;
    if threshold != PRODUCTION_OBSERVER_THRESHOLD
        || observers.len() != PRODUCTION_OBSERVER_COUNT
        || onchain_threshold != PRODUCTION_OBSERVER_THRESHOLD
        || onchain_count != PRODUCTION_OBSERVER_COUNT
    {
        anyhow::bail!("configured/on-chain attestation topology must both be exactly 3-of-5");
    }
    if oracle
        .intentQueue()
        .call()
        .await
        .context("read oracle IntentQueue")?
        ._0
        != queue_address
    {
        anyhow::bail!("oracle IntentQueue differs from configured queue");
    }
    for observer in observers {
        if !oracle
            .isSigner(observer.signer_address)
            .call()
            .await
            .with_context(|| format!("read signer membership for {}", observer.operator_id))?
            ._0
        {
            anyhow::bail!("observer {} is not an active signer", observer.operator_id);
        }
    }
    Ok(())
}

fn validate_config(config: &Config) -> Result<()> {
    if config.chain_id == 0
        || config.observers.len() != PRODUCTION_OBSERVER_COUNT
        || config.threshold != PRODUCTION_OBSERVER_THRESHOLD
        || config.max_response_age_secs == 0
        || config.max_response_age_secs > 300
        || config.observer_timeout_secs == 0
        || config.observer_timeout_secs > config.max_response_age_secs
        || config.post_attempts == 0
        || config.retry_base_ms == 0
        || config.retry_max_ms < config.retry_base_ms
    {
        anyhow::bail!(
            "invalid production configuration; settlement topology must be exactly 3-of-5"
        );
    }
    if !config.metrics_address.ip().is_loopback() {
        anyhow::bail!("metrics address must bind loopback");
    }
    endpoint_origin("ethereum_rpc_url", &config.ethereum_rpc_url, true)?;
    validate_owner_only_directory(&config.evidence_dir)?;
    validate_secret_file(&config.observer_client_identity_pem)?;
    validate_secret_file(&config.server_key_pem)?;
    if config.observer_server_ca_pems.is_empty() || config.pinned_client_cert_pems.is_empty() {
        anyhow::bail!("pinned mTLS trust roots must not be empty");
    }
    let mut operators = HashSet::new();
    let mut signers = HashSet::new();
    let mut origins = HashSet::new();
    for observer in &config.observers {
        validate_public_id(&observer.operator_id)?;
        if !operators.insert(observer.operator_id.clone())
            || !signers.insert(parse_nonzero_address(
                "observer signer_address",
                &observer.signer_address,
            )?)
            || !origins.insert(endpoint_origin(
                "observer base_url",
                &observer.base_url,
                true,
            )?)
        {
            anyhow::bail!("observer ids, signer addresses, and endpoint origins must be distinct");
        }
        let url = reqwest::Url::parse(&observer.base_url)?;
        if !matches!(url.path(), "" | "/") {
            anyhow::bail!("observer base_url must not contain a path");
        }
    }
    Ok(())
}

fn parse_observers(configured: &[ObserverConfig]) -> Result<Vec<ObserverEndpoint>> {
    configured
        .iter()
        .map(|observer| {
            Ok(ObserverEndpoint {
                operator_id: observer.operator_id.clone(),
                signer_address: parse_nonzero_address(
                    "observer signer_address",
                    &observer.signer_address,
                )?,
                base_url: observer.base_url.trim_end_matches('/').to_string(),
            })
        })
        .collect()
}

fn build_observer_client(config: &Config) -> Result<reqwest::Client> {
    let identity = reqwest::Identity::from_pem(&fs::read(&config.observer_client_identity_pem)?)
        .context("parse observer client identity")?;
    let mut builder = reqwest::Client::builder()
        .identity(identity)
        .timeout(Duration::from_secs(config.observer_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false);
    for path in &config.observer_server_ca_pems {
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(&fs::read(path)?)
                .with_context(|| format!("parse observer CA {}", path.display()))?,
        );
    }
    builder.build().context("build pinned observer mTLS client")
}

fn build_server_tls(config: &Config) -> Result<rustls::ServerConfig> {
    let server_chain = load_cert_chain(&fs::read(&config.server_cert_pem)?)?;
    let server_key = load_private_key(&fs::read(&config.server_key_pem)?)?;
    let roots = config
        .pinned_client_cert_pems
        .iter()
        .map(fs::read)
        .collect::<std::io::Result<Vec<_>>>()?;
    let roots = pinned_root_store(&roots)?;
    server_config(server_chain, server_key, roots).map_err(Into::into)
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

fn parse_wire_b256(raw: &str) -> Option<B256> {
    B256::from_str(raw)
        .ok()
        .filter(|value| *value != B256::ZERO)
}

fn parse_wire_u256(raw: &str) -> Option<U256> {
    U256::from_str_radix(raw, 10).ok()
}

fn validate_public_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        anyhow::bail!("operator id must be 1..=64 safe ASCII characters");
    }
    Ok(())
}

fn validate_owner_only_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute() || !metadata.file_type().is_dir() {
        anyhow::bail!("evidence directory must be an existing absolute non-symlink directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("evidence directory must be owner-only");
        }
    }
    Ok(())
}

fn validate_secret_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("read secret-file metadata for {}", path.display()))?;
    if !path.is_absolute() || !metadata.file_type().is_file() {
        anyhow::bail!("secret-bearing files must be existing absolute non-symlink regular files");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            anyhow::bail!("secret-bearing files must be owner-only and single-link");
        }
    }
    Ok(())
}

fn retry_delay(attempt: u32, base_ms: u64, max_ms: u64) -> Duration {
    let factor = 1u64 << attempt.saturating_sub(1).min(6);
    Duration::from_millis(base_ms.saturating_mul(factor).min(max_ms))
}

fn now_unix_wire() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ApiError::Dependency("system_clock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_policy_rejects_plaintext_credentials_and_query() {
        assert!(endpoint_origin("observer", "https://observer.example", true).is_ok());
        assert!(endpoint_origin("observer", "http://observer.example", true).is_err());
        assert!(endpoint_origin("observer", "https://user@observer.example", true).is_err());
        assert!(endpoint_origin("observer", "https://observer.example?token=x", true).is_err());
    }

    #[test]
    fn wire_identity_parsers_fail_closed() {
        assert!(parse_wire_b256(&format!("{:#x}", B256::repeat_byte(0x11))).is_some());
        assert!(parse_wire_b256(&format!("{:#x}", B256::ZERO)).is_none());
        assert!(parse_wire_u256("0").is_some());
        assert!(parse_wire_u256("0x0").is_none());
    }

    #[test]
    fn retry_delay_is_exponential_and_capped() {
        assert_eq!(retry_delay(1, 500, 10_000), Duration::from_millis(500));
        assert_eq!(retry_delay(2, 500, 10_000), Duration::from_secs(1));
        assert_eq!(retry_delay(9, 500, 10_000), Duration::from_secs(10));
    }
}
