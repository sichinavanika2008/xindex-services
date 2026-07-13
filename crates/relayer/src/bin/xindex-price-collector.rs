//! `xindex-price-collector` — untrusted exact-quorum collector and permissionless
//! `PriceAttestationOracle.attestPrice` poster.
//!
//! Each signer independently sources/canonicalizes its price and POSTs an
//! already-signed complete tuple. This process cannot invent or average a
//! quorum: it recover-verifies the configured on-chain signer set and only
//! posts signatures over one byte-identical tuple.

use std::collections::HashSet;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, Bytes};
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use clap::Parser;
use prometheus::Registry;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use xindex_chain_eth::bindings::PriceAttestationOracle;
use xindex_chain_eth::rpc::is_transient_rpc_error;
use xindex_ops::tls::{
    load_cert_chain, load_private_key, pinned_root_store, serve_mtls, server_config,
};
use xindex_ops::{serve_metrics, Metrics};
use xindex_relayer::{IngestOutcome, PriceCollector, ReadyPrice};
use xindex_shared::eip712::price_oracle_domain;
use xindex_shared::price_wire::SignedPriceMessage;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Xindex exact k-of-n NAV price collector + attestPrice poster"
)]
struct Args {
    /// Ethereum JSON-RPC endpoint.
    #[arg(long, env = "ETH_RPC_URL", default_value = "http://127.0.0.1:8545")]
    rpc_url: String,

    /// Deployed `PriceAttestationOracle` address.
    #[arg(long, env = "PRICE_ORACLE_ADDR")]
    oracle_address: String,

    /// Dedicated gas-paying poster address. The connected RPC delegates
    /// signing to an external node-managed signer (for example Clef/HSM); this
    /// process never accepts private key material. `attestPrice` is
    /// permissionless, so the poster has no oracle authority.
    #[arg(long, env = "PRICE_POSTER_ADDRESS")]
    poster_address: String,

    /// Complete comma-separated on-chain price signer set.
    #[arg(long, env = "PRICE_SIGNER_ADDRESSES")]
    signer_addresses: String,

    /// Exact on-chain threshold. Startup fails if it differs.
    #[arg(long, env = "PRICE_THRESHOLD")]
    threshold: usize,

    /// Pinned Ethereum chain id. Production launch policy is Ethereum mainnet.
    #[arg(long, env = "EXPECTED_ETH_CHAIN_ID")]
    expected_chain_id: u64,

    /// Maximum accepted signed-message age.
    #[arg(long, env = "PRICE_MAX_AGE_SECS", default_value_t = 300)]
    max_age_secs: u64,

    /// Private bind by default. Put authentication/mTLS at the service mesh if
    /// exposing beyond loopback; signatures remain cryptographically checked.
    #[arg(long, env = "PRICE_COLLECTOR_ADDR", default_value = "127.0.0.1:9191")]
    listen_address: String,

    /// Loopback Prometheus/health listener supervised with the collector.
    #[arg(long, env = "METRICS_ADDRESS", default_value = "127.0.0.1:9192")]
    metrics_address: SocketAddr,

    /// Collector mTLS server certificate chain.
    #[arg(long, env = "PRICE_SERVER_CERT_PEM")]
    server_cert_pem: PathBuf,

    /// Owner-only collector mTLS private key.
    #[arg(long, env = "PRICE_SERVER_KEY_PEM")]
    server_key_pem: PathBuf,

    /// Explicit price-signer client certificate/CA pins.
    #[arg(long, env = "PRICE_PINNED_CLIENT_CERT_PEMS", value_delimiter = ',')]
    pinned_client_cert_pems: Vec<PathBuf>,

    /// Attempts for transient RPC/receipt failures. Deterministic contract
    /// reverts are never retried.
    #[arg(long, env = "PRICE_POST_ATTEMPTS", default_value_t = 6)]
    post_attempts: u32,

    /// Initial exponential retry delay.
    #[arg(long, env = "PRICE_RETRY_BASE_MS", default_value_t = 500)]
    retry_base_ms: u64,

    /// Maximum exponential retry delay.
    #[arg(long, env = "PRICE_RETRY_MAX_MS", default_value_t = 10_000)]
    retry_max_ms: u64,
}

#[derive(Clone, Debug)]
struct AppState {
    collector: Arc<Mutex<PriceCollector>>,
    ready_tx: mpsc::Sender<ReadyPrice>,
    metrics: Metrics,
}

fn now_unix() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn parse_signers(csv: &str) -> Result<Vec<Address>> {
    let parsed: Vec<Address> = csv
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| Address::from_str(s).with_context(|| format!("invalid signer address {s}")))
        .collect::<Result<_>>()?;
    let unique: HashSet<Address> = parsed.iter().copied().collect();
    if parsed.is_empty() || unique.len() != parsed.len() {
        anyhow::bail!("PRICE_SIGNER_ADDRESSES must be non-empty and duplicate-free");
    }
    Ok(parsed)
}

async fn submit_signature(
    State(state): State<AppState>,
    Json(message): Json<SignedPriceMessage>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(now) = now_unix() else {
        state
            .metrics
            .price_collector_messages
            .with_label_values(&["error"])
            .inc();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "system clock before unix epoch"})),
        );
    };
    let outcome = {
        let Ok(mut collector) = state.collector.lock() else {
            state
                .metrics
                .price_collector_messages
                .with_label_values(&["error"])
                .inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "collector lock poisoned"})),
            );
        };
        collector.ingest(&message, now)
    };
    match outcome {
        Ok(IngestOutcome::Accepted { count }) => {
            state
                .metrics
                .price_collector_messages
                .with_label_values(&["accepted"])
                .inc();
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({"status": "accepted", "signatures": count})),
            )
        }
        Ok(IngestOutcome::Duplicate { count }) => {
            state
                .metrics
                .price_collector_messages
                .with_label_values(&["duplicate"])
                .inc();
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "duplicate", "signatures": count})),
            )
        }
        Ok(IngestOutcome::Ready(ready)) => {
            let signatures = ready.signatures.len();
            if state.ready_tx.send(ready).await.is_err() {
                state
                    .metrics
                    .price_collector_messages
                    .with_label_values(&["error"])
                    .inc();
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({"error": "poster worker unavailable"})),
                );
            }
            state
                .metrics
                .price_collector_messages
                .with_label_values(&["quorum"])
                .inc();
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({"status": "quorum", "signatures": signatures})),
            )
        }
        Err(e) => {
            state
                .metrics
                .price_collector_messages
                .with_label_values(&["refused"])
                .inc();
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        }
    }
}

fn retry_delay(attempt: u32, base_ms: u64, max_ms: u64) -> Duration {
    let factor = 1u64 << attempt.saturating_sub(1).min(6);
    Duration::from_millis(base_ms.saturating_mul(factor).min(max_ms))
}

fn validate_rpc_url(raw: &str) -> Result<()> {
    let url = reqwest::Url::parse(raw).context("ETH_RPC_URL must be a URL (value redacted)")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("ETH_RPC_URL must not contain credentials, query, or fragment");
    }
    let host = url.host_str().context("ETH_RPC_URL has no host")?;
    let host_ip = host.trim_start_matches('[').trim_end_matches(']');
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host_ip
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        anyhow::bail!("ETH_RPC_URL must use HTTPS or loopback HTTP");
    }
    Ok(())
}

fn validate_secret_file(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !path.is_absolute() || !metadata.file_type().is_file() {
        anyhow::bail!("TLS private key path must be an absolute non-symlink regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            anyhow::bail!("TLS private key must be owner-only and single-link");
        }
    }
    Ok(())
}

fn build_server_tls(args: &Args) -> Result<rustls::ServerConfig> {
    validate_secret_file(&args.server_key_pem)?;
    if args.pinned_client_cert_pems.is_empty() {
        anyhow::bail!("at least one pinned price-signer client certificate is required");
    }
    let server_chain = load_cert_chain(&fs::read(&args.server_cert_pem)?)?;
    let server_key = load_private_key(&fs::read(&args.server_key_pem)?)?;
    let roots = args
        .pinned_client_cert_pems
        .iter()
        .map(fs::read)
        .collect::<std::io::Result<Vec<_>>>()?;
    server_config(server_chain, server_key, pinned_root_store(&roots)?).map_err(Into::into)
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

#[expect(
    clippy::too_many_lines,
    reason = "startup validation and the single sequential nonce-safe poster worker are clearer together"
)]
async fn run(args: Args) -> Result<()> {
    if args.max_age_secs == 0
        || args.post_attempts == 0
        || args.retry_base_ms == 0
        || args.retry_max_ms < args.retry_base_ms
    {
        anyhow::bail!("age/retry settings must be non-zero and retry_max_ms >= retry_base_ms");
    }
    if args.expected_chain_id == 0 {
        anyhow::bail!("EXPECTED_ETH_CHAIN_ID must be non-zero");
    }
    if !args.metrics_address.ip().is_loopback() || args.metrics_address.port() == 0 {
        anyhow::bail!("METRICS_ADDRESS must be a non-zero loopback listener");
    }
    validate_rpc_url(&args.rpc_url)?;
    let oracle_address = Address::from_str(&args.oracle_address).context("PRICE_ORACLE_ADDR")?;
    if oracle_address.is_zero() {
        anyhow::bail!("PRICE_ORACLE_ADDR must be non-zero");
    }
    let signers = parse_signers(&args.signer_addresses)?;
    if signers.len() != 11 || args.threshold != 7 {
        anyhow::bail!("production price topology must be exactly 7-of-11");
    }
    let poster_address = Address::from_str(&args.poster_address).context("PRICE_POSTER_ADDRESS")?;
    if poster_address.is_zero() {
        anyhow::bail!("PRICE_POSTER_ADDRESS must be non-zero");
    }
    let listen: SocketAddr = args
        .listen_address
        .parse()
        .context("PRICE_COLLECTOR_ADDR")?;
    if listen == args.metrics_address {
        anyhow::bail!("collector and metrics listeners must be distinct");
    }
    let tls = Arc::new(build_server_tls(&args)?);
    let rpc_url = args.rpc_url.parse().context("ETH_RPC_URL")?;
    let provider = Arc::new(
        ProviderBuilder::new()
            .with_recommended_fillers()
            .on_http(rpc_url),
    );
    let oracle = PriceAttestationOracle::new(oracle_address, provider.clone());
    let chain_id = provider.get_chain_id().await.context("get chain id")?;
    if chain_id != args.expected_chain_id {
        anyhow::bail!("Ethereum chain id differs from EXPECTED_ETH_CHAIN_ID");
    }

    let prometheus = Registry::new();
    let metrics = Metrics::new(&prometheus).context("register price collector metrics")?;

    // Fail closed if the static collector roster is stale. A rotation requires
    // restarting with the new complete set; otherwise a removed signer could
    // consume memory/liveness even though Solidity would ultimately reject it.
    let onchain_threshold: usize = oracle
        .threshold()
        .call()
        .await
        .context("oracle threshold")?
        ._0
        .try_into()
        .context("threshold does not fit usize")?;
    let onchain_count: usize = oracle
        .signerCount()
        .call()
        .await
        .context("oracle signerCount")?
        ._0
        .try_into()
        .context("signerCount does not fit usize")?;
    if args.threshold != onchain_threshold || signers.len() != onchain_count {
        anyhow::bail!(
            "collector roster mismatch: configured threshold/count {}/{}, on-chain {}/{}",
            args.threshold,
            signers.len(),
            onchain_threshold,
            onchain_count
        );
    }
    for signer in &signers {
        if !oracle
            .isSigner(*signer)
            .call()
            .await
            .with_context(|| format!("isSigner({signer})"))?
            ._0
        {
            anyhow::bail!("configured signer {signer} is not active on-chain");
        }
    }

    let domain = price_oracle_domain(chain_id, oracle_address);
    let collector = PriceCollector::new(domain, signers, args.threshold, args.max_age_secs)
        .context("build collector")?;
    let (ready_tx, mut ready_rx) = mpsc::channel::<ReadyPrice>(128);
    let worker_oracle = PriceAttestationOracle::new(oracle_address, provider);
    let post_attempts = args.post_attempts;
    let retry_base_ms = args.retry_base_ms;
    let retry_max_ms = args.retry_max_ms;
    let worker_metrics = metrics.clone();

    // One worker serializes the poster EOA nonce. Each candidate is idempotence
    // checked against pendingQuote before send, so a receipt timeout followed by
    // a mined transaction becomes success rather than a replay transaction.
    let poster_worker = tokio::spawn(async move {
        while let Some(ready) = ready_rx.recv().await {
            let p = ready.payload;
            for attempt in 1..=post_attempts {
                let pending = match worker_oracle.pendingQuote(p.asset_id).call().await {
                    Ok(value) => value,
                    Err(e) => {
                        if is_transient_rpc_error(&e) && attempt < post_attempts {
                            warn!(asset_id = %p.asset_id, attempt, error = %e,
                                  "pendingQuote transient read failed; retrying");
                            tokio::time::sleep(retry_delay(attempt, retry_base_ms, retry_max_ms))
                                .await;
                            continue;
                        }
                        error!(asset_id = %p.asset_id, error = %e,
                               "pendingQuote permanent/exhausted failure; dropping candidate");
                        worker_metrics
                            .price_post_attempts
                            .with_label_values(&["error"])
                            .inc();
                        break;
                    }
                };
                if pending.updatedAt >= p.timestamp {
                    if pending.updatedAt == p.timestamp
                        && pending.priceWad == p.price_wad
                        && pending.supply == p.supply
                    {
                        worker_metrics
                            .price_post_attempts
                            .with_label_values(&["idempotent"])
                            .inc();
                        info!(asset_id = %p.asset_id, timestamp = p.timestamp,
                              "price tuple already present on-chain (idempotent success)");
                    } else {
                        worker_metrics
                            .price_post_attempts
                            .with_label_values(&["conflict"])
                            .inc();
                        warn!(asset_id = %p.asset_id, timestamp = p.timestamp,
                              onchain_timestamp = pending.updatedAt,
                              "candidate is obsolete/conflicts with accepted epoch; not retrying");
                    }
                    break;
                }

                let signatures: Vec<Bytes> =
                    ready.signatures.iter().copied().map(Bytes::from).collect();
                let sent = worker_oracle
                    .attestPrice(p.asset_id, p.price_wad, p.supply, p.timestamp, signatures)
                    .from(poster_address)
                    .send()
                    .await;
                match sent {
                    Ok(tx) => match tx.get_receipt().await {
                        Ok(receipt) if receipt.status() => {
                            worker_metrics
                                .price_post_attempts
                                .with_label_values(&["confirmed"])
                                .inc();
                            info!(asset_id = %p.asset_id, timestamp = p.timestamp,
                                  tx_hash = %receipt.transaction_hash,
                                  "attestPrice confirmed");
                            break;
                        }
                        Ok(receipt) => {
                            worker_metrics
                                .price_post_attempts
                                .with_label_values(&["revert"])
                                .inc();
                            error!(asset_id = %p.asset_id, timestamp = p.timestamp,
                                   tx_hash = %receipt.transaction_hash,
                                   "attestPrice reverted after mining; deterministic, not retrying");
                            break;
                        }
                        Err(e) if attempt < post_attempts => {
                            // The tx was accepted; a receipt timeout/disconnect or
                            // short reorg is retryable. Next attempt first re-reads
                            // pendingQuote, preventing a duplicate if it mined.
                            warn!(asset_id = %p.asset_id, attempt, error = %e,
                                  "attestPrice receipt unavailable; retrying idempotently");
                            tokio::time::sleep(retry_delay(attempt, retry_base_ms, retry_max_ms))
                                .await;
                        }
                        Err(e) => {
                            worker_metrics
                                .price_post_attempts
                                .with_label_values(&["error"])
                                .inc();
                            error!(asset_id = %p.asset_id, error = %e,
                                   "attestPrice receipt attempts exhausted");
                            break;
                        }
                    },
                    Err(e) if is_transient_rpc_error(&e) && attempt < post_attempts => {
                        warn!(asset_id = %p.asset_id, attempt, error = %e,
                              "attestPrice transient submit failure; retrying");
                        tokio::time::sleep(retry_delay(attempt, retry_base_ms, retry_max_ms)).await;
                    }
                    Err(e) => {
                        worker_metrics
                            .price_post_attempts
                            .with_label_values(&["error"])
                            .inc();
                        // Revert/estimate-gas failures (bounds, Chainlink,
                        // paused, stale timestamp, bad quorum) are deterministic
                        // for this tuple. Unknown errors default permanent via
                        // is_transient_rpc_error's fail-closed classification.
                        error!(asset_id = %p.asset_id, error = %e,
                               "attestPrice deterministic/permanent failure; not retrying");
                        break;
                    }
                }
            }
        }
    });

    let state = AppState {
        collector: Arc::new(Mutex::new(collector)),
        ready_tx,
        metrics,
    };
    let app = Router::new()
        .route("/api/v1/price-signature", post(submit_signature))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind {listen}"))?;
    info!(%listen, chain_id, %oracle_address, threshold = args.threshold,
          "price collector ready");
    let server = serve_mtls(listener, tls, app);
    let metrics_server = serve_metrics(prometheus, args.metrics_address);
    tokio::select! {
        result = server => match result {
            Ok(()) => Err(anyhow::anyhow!("price collector API exited unexpectedly")),
            Err(error) => Err(anyhow::anyhow!("price collector API failed: {error}")),
        },
        result = metrics_server => match result {
            Ok(()) => Err(anyhow::anyhow!("price collector metrics server exited unexpectedly")),
            Err(error) => Err(anyhow::anyhow!("price collector metrics server failed: {error}")),
        },
        result = poster_worker => {
            match result {
                Ok(()) => Err(anyhow::anyhow!(
                    "poster worker exited while collector HTTP server was live; terminating fail-closed"
                )),
                Err(e) => Err(anyhow::anyhow!(
                    "poster worker crashed while collector HTTP server was live: {e}; terminating fail-closed"
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_is_exponential_and_capped() {
        assert_eq!(retry_delay(1, 500, 10_000), Duration::from_millis(500));
        assert_eq!(retry_delay(2, 500, 10_000), Duration::from_secs(1));
        assert_eq!(retry_delay(9, 500, 10_000), Duration::from_secs(10));
    }

    #[test]
    fn deterministic_revert_is_not_transient() {
        assert!(!is_transient_rpc_error(
            &"execution reverted: PriceAttestationOracle_StaleTimestamp"
        ));
        assert!(is_transient_rpc_error(&"503 service unavailable"));
    }
}
