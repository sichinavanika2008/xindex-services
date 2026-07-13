//! `xindex-price-signer` — self-driven NAV price-attestation producer
//! (workstream A, `DL-INDEX-METHOD-ORACLE-1`).
//!
//! On an interval, for each configured asset: source the price from multiple
//! independent CEX venues + the circulating supply from supply feeds, median
//! each (outlier-rejected, fail-closed), sign the `PriceAttestation` with the
//! HSM (recover-verified), emit the complete signed tuple as a JSON line, and
//! push it to the configured untrusted collectors. Collectors recover-verify
//! and group exact tuples before posting `attestPrice` on-chain.
//!
//! It NEVER signs a price it was handed — it signs its own aggregated value
//! (the CTD-1 "don't trust the coordinator" property applied to the oracle).
//!
//! Usage: `xindex-price-signer <config.json>`.
#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "producer binary: signed attestations are emitted as JSON lines on \
              stdout for the k-of-n collector; operational status goes to stderr"
)]

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::{Address, B256, U256};
use prometheus::Registry;
use serde::{Deserialize, Serialize};
use xindex_ops::{serve_metrics, Metrics};
use xindex_shared::eip712::price_oracle_domain;
use xindex_shared::price_twap::{TwapConfig, TwapSample};
use xindex_shared::price_wire::SignedPriceMessage;
use xindex_signer_daemon::price_sign::{
    produce_signed_price_from_observations, ObservedProducerInputs, PricePolicy, PriceSignError,
};
use xindex_signer_daemon::price_supply::{
    source_supply_evidence, CoinCapSupply, CoinGeckoSupply, SupplyFeed,
};
use xindex_signer_daemon::price_venue::{
    source_quote_evidence, BinanceVenue, CoinbaseVenue, Feed, KrakenVenue, SourcedValue,
};
use xindex_signer_daemon::web3signer::HttpHsmClient;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// EIP-712 domain chainId of the `PriceAttestationOracle`.
    oracle_chain_id: u64,
    /// `PriceAttestationOracle` address (EIP-712 verifyingContract), hex.
    oracle_contract: String,
    /// This signer's EOA the HSM signs for, hex.
    signer_address: String,
    /// HSM frontend base URL (loopback inside the daemon's mTLS perimeter).
    hsm_url: String,
    /// Minimum independent price venues (fail closed below).
    min_venues: usize,
    /// Outlier band (bps) for both price and supply medians.
    max_deviation_bps: u32,
    /// Independent supply sources required. This build fixes it at 2
    /// (`CoinGecko` + `CoinCap` on distinct network origins).
    supply_min_venues: usize,
    /// TWAP window (secs): the trailing span the spatial medians are
    /// time-weight-averaged over (OM-4). A transient spike must persist across
    /// this window to move the signed price. Suggested a large multiple of
    /// `interval_secs` (e.g. 30 min for a 60s interval).
    twap_window_secs: u64,
    /// Minimum samples informing the TWAP window (>= 2). Higher forces denser
    /// coverage before a price can be signed.
    twap_min_samples: usize,
    /// Maximum stale gap allowed inside the TWAP window (secs). A longer feed
    /// stall fails closed; must be in `interval_secs..=twap_window_secs`.
    twap_max_gap_secs: u64,
    /// Seconds between observation rounds.
    interval_secs: u64,
    /// Deterministic timestamp epoch shared by every independent signer. The
    /// timestamp signed in a round is `floor(now / epoch_secs) * epoch_secs`,
    /// never the host's arbitrary wall-clock second.
    epoch_secs: u64,
    /// Decimal significant digits retained in the signed WAD price. Four is the
    /// minimum accepted (<10 bps deterministic downward canonicalization).
    price_significant_digits: u8,
    /// Decimal significant digits retained in the signed raw supply.
    supply_significant_digits: u8,
    /// Path to the durable anti-equivocation state file (per-asset last-signed
    /// timestamps); persists the monotonic guard across restarts.
    state_file: String,
    /// Locked-down directory for append-only, exact raw source-response
    /// evidence. One create-new JSON file is synced per asset/epoch before HSM
    /// signing can begin.
    evidence_dir: String,
    /// Public operator identifier written into evidence (never a credential).
    evidence_operator_id: String,
    /// Consecutive failed rounds for one asset before the process latches shut.
    /// Must exceed the configured TWAP cold-start sample count.
    anomaly_failure_threshold: u32,
    /// Base URLs of redundant untrusted collectors. The signer independently
    /// creates the price; collectors receive only an already-signed tuple.
    collector_urls: Vec<String>,
    /// Per-collector publish attempts for transient transport/5xx/429 errors.
    publish_attempts: u32,
    /// Timeout for one collector HTTP attempt.
    publish_timeout_secs: u64,
    /// Loopback Prometheus/health listener supervised with the producer loop.
    metrics_address: SocketAddr,
    /// Combined PEM client certificate/private key presented to collectors.
    collector_client_identity_pem: PathBuf,
    /// Explicit collector CA/certificate pins. System roots are disabled.
    collector_server_ca_pems: Vec<PathBuf>,
    binance_base: String,
    coinbase_base: String,
    kraken_base: String,
    coingecko_base: String,
    coincap_base: String,
    assets: Vec<AssetConfig>,
}

#[derive(Deserialize)]
struct AssetConfig {
    /// Registry asset id (keccak of the `THORChain` asset string), hex.
    asset_id: String,
    /// Token decimals (scales circulating supply to raw units).
    decimals: u8,
    /// Per-venue symbols / ids for this asset.
    binance: String,
    coinbase: String,
    kraken: String,
    coingecko: String,
    coincap: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceValue<'a> {
    source: &'static str,
    subject: &'a str,
    normalized_value: String,
    response_hash: String,
    raw_response: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawPriceEvidence<'a> {
    schema: &'static str,
    operator_id: &'a str,
    signer_address: String,
    asset_id: String,
    observation_epoch: u64,
    price_sources: Vec<EvidenceValue<'a>>,
    supply_sources: Vec<EvidenceValue<'a>>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Align an observation to the shared deterministic epoch. `epoch_secs == 0`
/// is rejected at boot, so this helper's zero branch is defensive only.
fn observation_epoch(now: u64, epoch_secs: u64) -> u64 {
    if epoch_secs == 0 {
        return 0;
    }
    now - now % epoch_secs
}

/// Load the persisted per-asset last-signed timestamps (the anti-equivocation
/// guard) so it SURVIVES a producer restart. A missing file is a first run
/// (empty map); a CORRUPT file fails closed — refuse to start rather than
/// silently reset the guard and risk signing two prices for one instant.
fn load_last_signed(path: &str) -> Result<HashMap<B256, u64>, Box<dyn std::error::Error>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(format!("cannot read anti-equivocation state: {e}").into()),
    };
    let map: HashMap<String, u64> = serde_json::from_str(&raw)
        .map_err(|e| format!("corrupt anti-equivocation state: {e} (refusing to start)"))?;
    let mut out = HashMap::with_capacity(map.len());
    for (k, v) in map {
        out.insert(
            k.parse::<B256>()
                .map_err(|e| format!("bad asset id '{k}' in anti-equivocation state: {e}"))?,
            v,
        );
    }
    Ok(out)
}

/// Atomically persist the guard (write a temp file, then rename) so a crash
/// mid-write cannot corrupt or truncate the state.
fn save_last_signed(path: &str, map: &HashMap<B256, u64>) -> std::io::Result<()> {
    let raw: HashMap<String, u64> = map.iter().map(|(k, v)| (format!("{k:#x}"), *v)).collect();
    let json = serde_json::to_string(&raw).map_err(std::io::Error::other)?;
    let path = Path::new(path);
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("state path has no file name"))?;
    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    if let Err(error) = (|| {
        file.write_all(json.as_bytes())?;
        file.sync_all()
    })() {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    std::fs::rename(&tmp, path)?;
    // Persist the directory entry too. A successful return means a power loss
    // cannot resurrect the prior epoch map after a signature was published.
    File::open(parent)?.sync_all()
}

fn ensure_evidence_directory(path: &str) -> std::io::Result<()> {
    let path = Path::new(path);
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(std::io::Error::other(
            "evidence path must be a non-symlink directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::other(
                "evidence directory must not be group/world accessible",
            ));
        }
    }
    Ok(())
}

fn validate_owner_only_file(path: &Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::other(
            "secret path must be a non-symlink regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(std::io::Error::other(
                "secret-bearing file must be owner-only and have exactly one hard link",
            ));
        }
    }
    Ok(())
}

fn validate_state_path(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| std::io::Error::other("state path has no parent"))?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if !parent_metadata.file_type().is_dir() {
        return Err(std::io::Error::other(
            "state parent must be a non-symlink directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if parent_metadata.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::other("state parent must be owner-only"));
        }
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(std::io::Error::other(
                    "existing state must be a non-symlink regular file",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
                    return Err(std::io::Error::other(
                        "existing state must be owner-only and have exactly one hard link",
                    ));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

fn validate_transport_files(cfg: &Config) -> std::io::Result<()> {
    validate_owner_only_file(&cfg.collector_client_identity_pem)?;
    for path in &cfg.collector_server_ca_pems {
        if !std::fs::symlink_metadata(path)?.file_type().is_file() {
            return Err(std::io::Error::other(
                "collector CA path must be a non-symlink regular file",
            ));
        }
    }
    Ok(())
}

fn evidence_values(observations: &[SourcedValue]) -> Vec<EvidenceValue<'_>> {
    observations
        .iter()
        .map(|observation| EvidenceValue {
            source: observation.source,
            subject: &observation.subject,
            normalized_value: observation.value.to_string(),
            response_hash: format!("{:#x}", observation.response_hash),
            raw_response: &observation.raw_response,
        })
        .collect()
}

fn persist_raw_evidence(
    directory: &str,
    operator_id: &str,
    signer_address: Address,
    asset_id: B256,
    epoch: u64,
    price: &[SourcedValue],
    supply: &[SourcedValue],
) -> std::io::Result<()> {
    let evidence = RawPriceEvidence {
        schema: "xindex.price-source-evidence.v1",
        operator_id,
        signer_address: format!("{signer_address:#x}"),
        asset_id: format!("{asset_id:#x}"),
        observation_epoch: epoch,
        price_sources: evidence_values(price),
        supply_sources: evidence_values(supply),
    };
    let encoded = serde_json::to_vec(&evidence).map_err(std::io::Error::other)?;
    let file_name = format!(
        "{epoch}-{}.json",
        alloy_primitives::hex::encode(asset_id.as_slice())
    );
    let path = Path::new(directory).join(&file_name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    let digest = alloy_primitives::hex::encode(alloy_primitives::keccak256(&encoded).as_slice());
    let sidecar = Path::new(directory).join(format!("{file_name}.keccak256"));
    let mut sidecar_options = OpenOptions::new();
    sidecar_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        sidecar_options.mode(0o600);
    }
    let mut sidecar_file = sidecar_options.open(sidecar)?;
    sidecar_file.write_all(digest.as_bytes())?;
    sidecar_file.write_all(b"\n")?;
    sidecar_file.sync_all()?;
    File::open(directory)?.sync_all()
}

fn endpoint_origin(
    label: &str,
    raw: &str,
    loopback_only: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = reqwest::Url::parse(raw).map_err(|_| format!("{label} must be a valid URL"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            format!("{label} must not contain userinfo, query credentials, or a fragment").into(),
        );
    }
    let host = url
        .host_str()
        .ok_or_else(|| format!("{label} must include a host"))?;
    let host_ip = host.trim_start_matches('[').trim_end_matches(']');
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host_ip
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if loopback_only && !is_loopback {
        return Err(format!("{label} must terminate on loopback inside the HSM perimeter").into());
    }
    if url.scheme() != "https" && !(url.scheme() == "http" && is_loopback) {
        return Err(
            format!("{label} must use HTTPS (plain HTTP is allowed only on loopback)").into(),
        );
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| format!("{label} has no usable port"))?;
    Ok(format!(
        "{}://{}:{port}",
        url.scheme(),
        host.to_ascii_lowercase()
    ))
}

/// Fail-closed boot-time validation of the venue-consensus + TWAP policy. A
/// mis-set parameter silently weakens a manipulation guard, so refuse to start.
#[expect(
    clippy::too_many_lines,
    reason = "linear fail-closed boot policy keeps every safety parameter visible"
)]
fn validate_config(cfg: &Config) -> Result<(), Box<dyn std::error::Error>> {
    // G/red-team RT-A-LOW: the aggregator's outlier rejection needs an ODD
    // honest anchor. At min_venues == 2 an even survivor set averages the two
    // middle quotes, so one compromised venue moves the median by (X-P)/2
    // (bounded only by max_deviation_bps). Require >= 3 price venues so a single
    // bad venue is always out-voted by an honest majority.
    if cfg.min_venues != 3 {
        return Err(format!(
            "min_venues must be exactly 3 because this build configures three independent price \
             providers (got {})",
            cfg.min_venues
        )
        .into());
    }
    if cfg.supply_min_venues != 2 {
        return Err(format!(
            "supply_min_venues must be exactly 2 because this build configures CoinGecko and \
             CoinCap as independent supply providers (got {})",
            cfg.supply_min_venues
        )
        .into());
    }
    if cfg.max_deviation_bps == 0 || cfg.max_deviation_bps > 5_000 {
        return Err(format!(
            "max_deviation_bps must be in 1..=5000 (got {})",
            cfg.max_deviation_bps
        )
        .into());
    }
    if cfg.epoch_secs == 0 || cfg.interval_secs == 0 || cfg.epoch_secs != cfg.interval_secs {
        return Err(format!(
            "epoch_secs and interval_secs must be the same non-zero cadence (epoch={}, interval={}); \
             every signer must produce at most one tuple for the same shared epoch",
            cfg.epoch_secs, cfg.interval_secs
        )
        .into());
    }
    if !(4..=78).contains(&cfg.price_significant_digits) {
        return Err(format!(
            "price_significant_digits must be in 4..=78 (got {}); fewer than 4 can \
             move the canonical price downward by >=10 bps",
            cfg.price_significant_digits
        )
        .into());
    }
    if !(4..=78).contains(&cfg.supply_significant_digits) {
        return Err(format!(
            "supply_significant_digits must be in 4..=78 (got {})",
            cfg.supply_significant_digits
        )
        .into());
    }
    if cfg.publish_attempts == 0 || cfg.publish_timeout_secs == 0 {
        return Err("publish_attempts and publish_timeout_secs must be non-zero".into());
    }
    if cfg.metrics_address.port() == 0 || !cfg.metrics_address.ip().is_loopback() {
        return Err("metrics_address must be a non-zero loopback listener".into());
    }
    if cfg.collector_server_ca_pems.is_empty() {
        return Err("collector_server_ca_pems must not be empty".into());
    }
    if cfg.collector_urls.len() < 2 {
        return Err("at least two redundant collector endpoints are required".into());
    }
    if cfg.assets.is_empty() {
        return Err("at least one asset must be configured".into());
    }
    if !Path::new(&cfg.state_file).is_absolute() {
        return Err("state_file must be an absolute path on durable storage".into());
    }
    if !Path::new(&cfg.evidence_dir).is_absolute() {
        return Err("evidence_dir must be an absolute path on durable storage".into());
    }
    if cfg.evidence_operator_id.trim().is_empty()
        || cfg.evidence_operator_id.len() > 128
        || !cfg
            .evidence_operator_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err("evidence_operator_id must be 1..=128 ASCII letters/digits/_/-".into());
    }
    let cold_start_floor = u32::try_from(cfg.twap_min_samples)
        .unwrap_or(u32::MAX)
        .saturating_add(2);
    if cfg.anomaly_failure_threshold < cold_start_floor {
        return Err(format!(
            "anomaly_failure_threshold must be at least twap_min_samples + 2 ({cold_start_floor})"
        )
        .into());
    }

    endpoint_origin("hsm_url", &cfg.hsm_url, true)?;
    let price_origins = [
        endpoint_origin("binance_base", &cfg.binance_base, false)?,
        endpoint_origin("coinbase_base", &cfg.coinbase_base, false)?,
        endpoint_origin("kraken_base", &cfg.kraken_base, false)?,
    ];
    if price_origins.iter().collect::<HashSet<_>>().len() != price_origins.len() {
        return Err("price providers must have distinct network origins".into());
    }
    let supply_origins = [
        endpoint_origin("coingecko_base", &cfg.coingecko_base, false)?,
        endpoint_origin("coincap_base", &cfg.coincap_base, false)?,
    ];
    if supply_origins[0] == supply_origins[1] {
        return Err("supply providers must have distinct network origins".into());
    }
    let collector_origins = cfg
        .collector_urls
        .iter()
        .enumerate()
        .map(|(index, endpoint)| {
            endpoint_origin(&format!("collector_urls[{index}]"), endpoint, false)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if collector_origins
        .iter()
        .any(|origin| !origin.starts_with("https://"))
    {
        return Err("collector endpoints must use HTTPS for pinned mTLS".into());
    }
    if collector_origins.iter().collect::<HashSet<_>>().len() != collector_origins.len() {
        return Err("collector endpoints must have distinct network origins".into());
    }
    let mut asset_ids = HashSet::with_capacity(cfg.assets.len());
    for asset in &cfg.assets {
        let asset_id = asset
            .asset_id
            .parse::<B256>()
            .map_err(|_| "every asset_id must be a canonical bytes32 hex value")?;
        if !asset_ids.insert(asset_id) {
            return Err("duplicate asset_id in signer configuration".into());
        }
        if [
            asset.binance.as_str(),
            asset.coinbase.as_str(),
            asset.kraken.as_str(),
            asset.coingecko.as_str(),
            asset.coincap.as_str(),
        ]
        .iter()
        .any(|value| value.trim().is_empty())
        {
            return Err("every asset requires identifiers for all five independent sources".into());
        }
    }
    // TWAP (OM-4) window sanity. Ordering: interval <= max_gap <= window, and
    // >= 2 informing samples (a single sample is not a time average).
    if cfg.twap_min_samples < 2 {
        return Err(format!(
            "twap_min_samples must be >= 2 (got {}); a single sample is not a time average",
            cfg.twap_min_samples
        )
        .into());
    }
    if cfg.twap_window_secs < cfg.interval_secs {
        return Err(format!(
            "twap_window_secs ({}) must be >= interval_secs ({})",
            cfg.twap_window_secs, cfg.interval_secs
        )
        .into());
    }
    if cfg.twap_max_gap_secs < cfg.interval_secs || cfg.twap_max_gap_secs > cfg.twap_window_secs {
        return Err(format!(
            "twap_max_gap_secs must be in {}..={} (got {}); below interval every normal \
             gap trips it, above window it never trips",
            cfg.interval_secs, cfg.twap_window_secs, cfg.twap_max_gap_secs
        )
        .into());
    }
    Ok(())
}

const COLLECT_PATH: &str = "/api/v1/price-signature";

/// Publish an already-signed tuple. Retry only errors that can plausibly change
/// without changing the signed plaintext (transport, 429, 5xx). A collector's
/// deterministic 4xx rejection is logged and not retried.
async fn publish_to_collector(
    http: &reqwest::Client,
    base_url: &str,
    message: &SignedPriceMessage,
    attempts: u32,
) -> Result<(), String> {
    let url = format!("{}{COLLECT_PATH}", base_url.trim_end_matches('/'));
    for attempt in 1..=attempts {
        match http.post(&url).json(message).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response)
                if response.status().is_server_error()
                    || response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
            {
                let status = response.status();
                if attempt == attempts {
                    return Err(format!("http {status} after {attempts} attempt(s)"));
                }
            }
            Ok(response) => {
                let status = response.status();
                return Err(format!("collector rejected signed tuple: http {status}"));
            }
            Err(e) => {
                if attempt == attempts {
                    let class = if e.is_timeout() {
                        "timeout"
                    } else if e.is_connect() {
                        "connect"
                    } else if e.is_body() {
                        "body"
                    } else {
                        "request"
                    };
                    return Err(format!("{class} after {attempts} attempt(s)"));
                }
            }
        }
        let shift = attempt.saturating_sub(1).min(6);
        tokio::time::sleep(Duration::from_millis(250u64.saturating_mul(1u64 << shift))).await;
    }
    Err("publish attempt loop exhausted".to_string())
}

fn collector_client(cfg: &Config) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    let identity =
        reqwest::Identity::from_pem(&std::fs::read(&cfg.collector_client_identity_pem)?)?;
    let mut builder = reqwest::Client::builder()
        .identity(identity)
        .timeout(Duration::from_secs(cfg.publish_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false);
    for path in &cfg.collector_server_ca_pems {
        builder =
            builder.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(path)?)?);
    }
    Ok(builder.build()?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: xindex-price-signer <config.json>")?;
    validate_owner_only_file(Path::new(&path))?;
    let cfg: Config = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    validate_config(&cfg)?;
    validate_state_path(Path::new(&cfg.state_file))?;
    validate_transport_files(&cfg)?;
    let registry = Registry::new();
    let metrics = Metrics::new(&registry)?;
    let metrics_address = cfg.metrics_address;
    let producer = run_producer(cfg, metrics);
    let metrics_server = serve_metrics(registry, metrics_address);
    tokio::select! {
        result = producer => result,
        result = metrics_server => match result {
            Ok(()) => Err("price signer metrics server exited unexpectedly".into()),
            Err(error) => Err(format!("price signer metrics server failed: {error}").into()),
        },
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one sequential observe-evidence-sign-persist-publish loop is easier to audit"
)]
async fn run_producer(cfg: Config, metrics: Metrics) -> Result<(), Box<dyn std::error::Error>> {
    ensure_evidence_directory(&cfg.evidence_dir)
        .map_err(|error| format!("unsafe/unavailable evidence directory: {error}"))?;

    let oracle_contract: Address = cfg.oracle_contract.parse()?;
    let signer_address: Address = cfg.signer_address.parse()?;
    let assets: Vec<(B256, &AssetConfig)> = cfg
        .assets
        .iter()
        .map(|a| Ok::<_, Box<dyn std::error::Error>>((a.asset_id.parse::<B256>()?, a)))
        .collect::<Result<_, _>>()?;

    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()?;
    let publish_http = collector_client(&cfg)?;
    let binance = BinanceVenue::new(http.clone(), &cfg.binance_base);
    let coinbase = CoinbaseVenue::new(http.clone(), &cfg.coinbase_base);
    let kraken = KrakenVenue::new(http.clone(), &cfg.kraken_base);
    let coingecko = CoinGeckoSupply::new(http.clone(), &cfg.coingecko_base);
    let coincap = CoinCapSupply::new(http.clone(), &cfg.coincap_base);
    let hsm = HttpHsmClient::new(cfg.hsm_url.clone());
    let domain = price_oracle_domain(cfg.oracle_chain_id, oracle_contract);
    let policy = PricePolicy {
        min_venues: cfg.min_venues,
        max_deviation_bps: cfg.max_deviation_bps,
        supply_min_venues: cfg.supply_min_venues,
        price_significant_digits: cfg.price_significant_digits,
        supply_significant_digits: cfg.supply_significant_digits,
        twap: TwapConfig {
            window_secs: cfg.twap_window_secs,
            min_samples: cfg.twap_min_samples,
            max_gap_secs: cfg.twap_max_gap_secs,
        },
    };

    // Anti-equivocation guard, loaded from durable state so it survives a
    // restart (a corrupt state file fails closed inside load_last_signed).
    let mut last_signed = load_last_signed(&cfg.state_file)?;
    // Per-asset TWAP sample buffer. In-memory only: on restart it starts empty
    // and the TWAP fails closed (no signing) until it refills across the window
    // — the safe cold-start behaviour, so it needs no durability.
    let mut twap_history: HashMap<B256, Vec<TwapSample>> = HashMap::new();
    let mut failure_streaks: HashMap<B256, u32> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(cfg.interval_secs));
    for (asset_id, _) in &assets {
        let asset = format!("{asset_id:#x}");
        metrics
            .price_signer_anomaly_streak
            .with_label_values(&[&asset])
            .set(0);
        metrics
            .price_signer_last_success_timestamp_seconds
            .with_label_values(&[&asset])
            .set(
                last_signed
                    .get(asset_id)
                    .copied()
                    .and_then(|value| i64::try_from(value).ok())
                    .unwrap_or(0),
            );
    }
    loop {
        tick.tick().await;
        let now = observation_epoch(now_unix(), cfg.epoch_secs);
        for (asset_id, a) in &assets {
            let asset = format!("{asset_id:#x}");
            let price_feeds = [
                Feed {
                    venue: &binance,
                    symbol: &a.binance,
                },
                Feed {
                    venue: &coinbase,
                    symbol: &a.coinbase,
                },
                Feed {
                    venue: &kraken,
                    symbol: &a.kraken,
                },
            ];
            let supply_feeds = [
                SupplyFeed {
                    source: &coingecko,
                    id: &a.coingecko,
                },
                SupplyFeed {
                    source: &coincap,
                    id: &a.coincap,
                },
            ];
            let price_observations = source_quote_evidence(&price_feeds).await;
            let supply_observations = source_supply_evidence(&supply_feeds, a.decimals).await;
            // Persist the exact raw provider bodies BEFORE any HSM call. A
            // create-new collision or storage failure refuses this round.
            if let Err(error) = persist_raw_evidence(
                &cfg.evidence_dir,
                &cfg.evidence_operator_id,
                signer_address,
                *asset_id,
                now,
                &price_observations,
                &supply_observations,
            ) {
                metrics
                    .price_signer_rounds
                    .with_label_values(&["evidence_error"])
                    .inc();
                return Err(format!(
                    "raw evidence persistence failed; signing halted before HSM use: {error}"
                )
                .into());
            }
            let price_quotes: Vec<U256> = price_observations
                .iter()
                .map(|observation| observation.value)
                .collect();
            let supply_quotes: Vec<U256> = supply_observations
                .iter()
                .map(|observation| observation.value)
                .collect();
            let input = ObservedProducerInputs {
                asset_id: *asset_id,
                price_quotes: &price_quotes,
                supply_quotes: &supply_quotes,
                timestamp: now,
                last_signed_at: last_signed.get(asset_id).copied(),
            };
            let history = twap_history.entry(*asset_id).or_default();
            match produce_signed_price_from_observations(
                &hsm,
                signer_address,
                &domain,
                policy,
                &input,
                history,
            )
            .await
            {
                Ok(signed) => {
                    failure_streaks.insert(*asset_id, 0);
                    metrics
                        .price_signer_anomaly_streak
                        .with_label_values(&[&asset])
                        .set(0);
                    let mut next_last_signed = last_signed.clone();
                    next_last_signed.insert(*asset_id, now);
                    // Persist the guard BEFORE emitting, so a restart cannot
                    // reset it and re-sign a different price at this timestamp.
                    // Publication MUST stop if the durable guard cannot be
                    // committed. Continuing would let a restart sign a
                    // different payload for the same epoch.
                    if let Err(error) = save_last_signed(&cfg.state_file, &next_last_signed) {
                        metrics
                            .price_signer_rounds
                            .with_label_values(&["state_error"])
                            .inc();
                        return Err(format!(
                            "anti-equivocation persistence failed; publication halted: {error}"
                        )
                        .into());
                    }
                    last_signed = next_last_signed;
                    metrics
                        .price_signer_rounds
                        .with_label_values(&["signed"])
                        .inc();
                    metrics
                        .price_signer_last_success_timestamp_seconds
                        .with_label_values(&[&asset])
                        .set(i64::try_from(now).unwrap_or(i64::MAX));
                    let message = SignedPriceMessage {
                        asset_id: format!("{:#x}", signed.asset_id),
                        price_wad: signed.price_wad.to_string(),
                        supply: signed.supply.to_string(),
                        timestamp: signed.timestamp,
                        signer_address: format!("{:#x}", signed.signer_address),
                        signature: format!("0x{}", alloy_primitives::hex::encode(signed.signature)),
                    };
                    println!("{}", serde_json::to_string(&message)?);
                    let mut delivered = 0usize;
                    for (collector_index, collector) in cfg.collector_urls.iter().enumerate() {
                        if let Err(e) = publish_to_collector(
                            &publish_http,
                            collector,
                            &message,
                            cfg.publish_attempts,
                        )
                        .await
                        {
                            metrics
                                .price_collector_deliveries
                                .with_label_values(&["error"])
                                .inc();
                            eprintln!(
                                "price-publish {asset_id:#x} epoch {now} collector_index={collector_index} failed: {e}"
                            );
                        } else {
                            delivered += 1;
                            metrics
                                .price_collector_deliveries
                                .with_label_values(&["success"])
                                .inc();
                        }
                    }
                    if delivered == 0 {
                        metrics
                            .price_signer_rounds
                            .with_label_values(&["publish_error"])
                            .inc();
                        return Err(format!(
                            "all collectors rejected/unreachable for {asset_id:#x} epoch {now}; anomaly latch halted the signer"
                        )
                        .into());
                    }
                }
                Err(e) => {
                    let result = if matches!(
                        &e,
                        PriceSignError::Hsm(_)
                            | PriceSignError::RecoverMismatch { .. }
                            | PriceSignError::SignatureParse(_)
                    ) {
                        "hsm_error"
                    } else {
                        "refused"
                    };
                    metrics
                        .price_signer_rounds
                        .with_label_values(&[result])
                        .inc();
                    let streak = failure_streaks
                        .entry(*asset_id)
                        .and_modify(|count| *count = count.saturating_add(1))
                        .or_insert(1);
                    metrics
                        .price_signer_anomaly_streak
                        .with_label_values(&[&asset])
                        .set(i64::from(*streak));
                    eprintln!(
                        "price-sign {asset_id:#x} failed (fail-closed), consecutive_failures={streak}: {e}"
                    );
                    if *streak >= cfg.anomaly_failure_threshold {
                        metrics
                            .price_signer_rounds
                            .with_label_values(&["latched"])
                            .inc();
                        return Err(format!(
                            "price anomaly latch tripped for {asset_id:#x} after {streak} consecutive failed rounds"
                        )
                        .into());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    #[expect(clippy::expect_used, reason = "test-only temporary path setup")]
    fn state_and_evidence_paths_reject_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = std::env::temp_dir().join(format!(
            "xindex-price-path-policy-{}-{}",
            std::process::id(),
            now_unix()
        ));
        std::fs::create_dir(&root).expect("create root");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("secure root");
        let missing_state = root.join("state.json");
        assert!(validate_state_path(&missing_state).is_ok());

        let target = root.join("target");
        std::fs::write(&target, b"{}").expect("write target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("secure target");
        let state_link = root.join("state-link.json");
        symlink(&target, &state_link).expect("link state");
        assert!(validate_state_path(&state_link).is_err());

        let evidence_link = root.join("evidence-link");
        symlink(&root, &evidence_link).expect("link evidence");
        assert!(ensure_evidence_directory(evidence_link.to_str().expect("utf8")).is_err());

        std::fs::remove_file(evidence_link).expect("remove evidence link");
        std::fs::remove_file(state_link).expect("remove state link");
        std::fs::remove_file(target).expect("remove target");
        std::fs::remove_dir(root).expect("remove root");
    }

    /// G/RT-A-MED: the anti-equivocation guard must persist across restarts and
    /// fail closed on a corrupt state file (never silently reset).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn last_signed_state_round_trips_and_corrupt_fails_closed() {
        let path = std::env::temp_dir().join(format!(
            "xindex-pricesigner-state-{}.json",
            std::process::id()
        ));
        let p = path.to_str().expect("utf8 path");
        let _ = std::fs::remove_file(p);
        // Missing file → empty (first run).
        assert!(load_last_signed(p).expect("missing-ok").is_empty());
        // Round-trip a guard entry.
        let mut m = HashMap::new();
        m.insert(B256::repeat_byte(0xab), 1_700_000_000_u64);
        save_last_signed(p, &m).expect("save");
        assert_eq!(load_last_signed(p).expect("load"), m);
        // Corrupt state → fail closed (refuse to start), never silently reset.
        std::fs::write(p, "{ not json").expect("write corrupt");
        assert!(
            load_last_signed(p).is_err(),
            "corrupt state must fail closed"
        );
        let _ = std::fs::remove_file(p);
    }

    /// A sane policy: 3 venues, a 30-min TWAP window sampled every 60s with a
    /// 5-min stale-gap cap and 10 informing samples.
    fn valid_cfg() -> Config {
        Config {
            oracle_chain_id: 1,
            oracle_contract: "0x0000000000000000000000000000000000000001".into(),
            signer_address: "0x0000000000000000000000000000000000000002".into(),
            hsm_url: "http://localhost".into(),
            min_venues: 3,
            max_deviation_bps: 5000,
            supply_min_venues: 2,
            twap_window_secs: 1800,
            twap_min_samples: 10,
            twap_max_gap_secs: 300,
            interval_secs: 60,
            epoch_secs: 60,
            price_significant_digits: 4,
            supply_significant_digits: 6,
            state_file: "/tmp/xindex-price-signer-state.json".into(),
            evidence_dir: "/tmp".into(),
            evidence_operator_id: "P01".into(),
            anomaly_failure_threshold: 12,
            collector_urls: vec![
                "https://collector-one.prod".into(),
                "https://collector-two.prod".into(),
            ],
            publish_attempts: 3,
            publish_timeout_secs: 5,
            metrics_address: SocketAddr::from(([127, 0, 0, 1], 9095)),
            collector_client_identity_pem: "/tmp/collector-identity.pem".into(),
            collector_server_ca_pems: vec!["/tmp/collector-ca.pem".into()],
            binance_base: "https://api.binance.com".into(),
            coinbase_base: "https://api.coinbase.com".into(),
            kraken_base: "https://api.kraken.com".into(),
            coingecko_base: "https://api.coingecko.com".into(),
            coincap_base: "https://api.coincap.io".into(),
            assets: vec![AssetConfig {
                asset_id: format!("{:#x}", B256::repeat_byte(0x11)),
                decimals: 8,
                binance: "BTCUSDT".into(),
                coinbase: "BTC-USD".into(),
                kraken: "XBTUSD".into(),
                coingecko: "bitcoin".into(),
                coincap: "bitcoin".into(),
            }],
        }
    }

    #[test]
    fn validate_config_accepts_sane_policy() {
        assert!(validate_config(&valid_cfg()).is_ok());
    }

    #[test]
    fn validate_config_rejects_two_venues() {
        let mut c = valid_cfg();
        c.min_venues = 2; // no odd honest anchor
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn observation_time_is_epoch_aligned_and_never_future() {
        assert_eq!(observation_epoch(1_700_000_059, 60), 1_700_000_040);
        assert!(observation_epoch(1_700_000_059, 60) <= 1_700_000_059);
    }

    #[test]
    fn validate_config_rejects_mismatched_epoch_cadence() {
        let mut c = valid_cfg();
        c.epoch_secs = 30;
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn validate_config_rejects_coarse_price_canonicalization() {
        let mut c = valid_cfg();
        c.price_significant_digits = 3;
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn validate_config_rejects_single_twap_sample() {
        let mut c = valid_cfg();
        c.twap_min_samples = 1; // a single sample is not a time average
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn validate_config_rejects_window_below_interval() {
        let mut c = valid_cfg();
        c.twap_window_secs = 30; // < interval 60
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn validate_config_rejects_gap_out_of_range() {
        let mut below = valid_cfg();
        below.twap_max_gap_secs = 59; // < interval → every normal gap trips it
        assert!(validate_config(&below).is_err());
        let mut above = valid_cfg();
        above.twap_max_gap_secs = above.twap_window_secs + 1; // > window → never trips
        assert!(validate_config(&above).is_err());
    }
}
