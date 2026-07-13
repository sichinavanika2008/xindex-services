//! `xindex-signer-daemon` — the production k-of-n signing daemon binary.
//!
//! Each of the 5 operators runs one instance (Set-A custody PSBT signing +
//! Set-B EIP-712 attestation/RIC/ACC certification). This `main` wires the
//! library (`server::DaemonState` + `router` + `tls::serve_mtls`) from a
//! single JSON config file — the same config-file shape the sibling
//! `xindex-price-signer` bin uses.
//!
//! Two modes:
//!   * PRODUCTION (default): an HTTP HSM frontend (`hsm.kind = "http"`),
//!     mTLS required, every served chain metered. The daemon runs
//!     [`DaemonState::assert_production_safe`] and refuses to boot
//!     otherwise.
//!   * `--dev` (one-box testnet rehearsal —
//!     `docs/runbooks/testnet-rehearsal-localhost.md`): permits
//!     `hsm.kind = "software"` (in-process keys, additionally gated by
//!     `XINDEX_ALLOW_SOFTWARE_KEYS=1`), permits plain-HTTP on loopback when
//!     no `tls` block is set, and skips `assert_production_safe`. Software
//!     keys can NEVER run a production daemon: the mode is explicit, the
//!     env gate is explicit, and the production path rejects both.
//!
//! Usage: `xindex-signer-daemon <config.json> [--dev]`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use alloy_primitives::Address;
use anyhow::{bail, Context, Result};
use bitcoin::{Network, PublicKey};
use serde::Deserialize;
use tokio::net::TcpListener;
use tracing::{info, warn};

use xindex_multisig::MultisigDescriptor;
use xindex_shared::chain_registry::ChainId;
use xindex_signer_daemon::intent::IntentPolicy;
use xindex_signer_daemon::psbt::UtxoSignerConfig;
use xindex_signer_daemon::replay::{InMemoryReplayStore, ReplayStore, SqliteReplayStore};
use xindex_signer_daemon::server::{router, CertVolumePolicy, DaemonConfig, DaemonState};
use xindex_signer_daemon::soft_hsm::SoftwareHsm;
use xindex_signer_daemon::tls;
use xindex_signer_daemon::web3signer::{HsmDigestSigner, HttpHsmClient};

// ───────────────────────────── config (serde) ─────────────────────────────

/// The on-disk JSON config. Parsed into the runtime `DaemonConfig` +
/// signing roles by the `build_*` helpers below (the runtime types are not
/// `Deserialize` — they hold parsed alloy/bitcoin primitives).
#[derive(Deserialize)]
struct FileConfig {
    /// EIP-712 domain chain id the daemon signs attestations for.
    chain_id: u64,
    /// Deployed `AttestationOracle` address (EIP-712 verifying contract).
    verifying_contract: String,
    /// This operator's Set-B Ethereum signer address.
    eth_address: String,
    /// CTD-1 RIC verification policy (Set-B whitelist + quorum + recency).
    intent_policy: IntentPolicyFile,
    /// CTD-1 Slice E per-chain certification volume caps.
    cert_volume: CertVolumeFile,
    /// HSM backend selection.
    hsm: HsmFile,
    /// `SQLite` replay/slashing DB URL (e.g. `sqlite://daemon.db`). Absent =
    /// in-memory store (dev only — loses replay state on restart).
    #[serde(default)]
    database_url: Option<String>,
    /// Optional Set-A BTC custody (PSBT) signing role.
    #[serde(default)]
    utxo: Option<UtxoFile>,
    /// mTLS material. Required outside `--dev`; omit only for a `--dev`
    /// plain-HTTP loopback bring-up.
    #[serde(default)]
    tls: Option<TlsFile>,
    /// Listen address, e.g. `127.0.0.1:8443`.
    bind: String,
}

#[derive(Debug, Deserialize)]
struct IntentPolicyFile {
    signer_whitelist: Vec<String>,
    intent_quorum: usize,
    ric_max_age_secs: u64,
}

#[derive(Debug, Deserialize)]
struct CertVolumeFile {
    window_secs: u64,
    /// chain name (`btc`) → cap in native smallest units.
    caps: HashMap<String, u128>,
}

#[derive(Deserialize)]
struct HsmFile {
    kind: HsmKind,
    /// `http` backend: HSM frontend base URL (e.g. `http://127.0.0.1:9000`).
    #[serde(default)]
    url: Option<String>,
    /// `software` backend (dev only): in-process secret keys.
    #[serde(default)]
    software: Option<SoftwareKeysFile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum HsmKind {
    Http,
    Software,
}

#[derive(Deserialize)]
struct SoftwareKeysFile {
    /// 32-byte hex Ethereum (Set-B) secret key.
    eth_secret_key: String,
    /// 32-byte hex Bitcoin (Set-A) secret key.
    btc_secret_key: String,
}

#[derive(Debug, Deserialize)]
struct UtxoFile {
    chain: String,
    network: String,
    threshold: usize,
    /// The 3-of-5 custody pubkeys (compressed hex).
    pubkeys: Vec<String>,
    /// This operator's own pubkey (must be one of `pubkeys`).
    my_pubkey: String,
    /// The address alias the HSM routes the BTC key under (distinct from
    /// `eth_address`).
    hsm_address: String,
}

#[derive(Debug, Deserialize)]
struct TlsFile {
    server_cert: String,
    server_key: String,
    pinned_client_certs: Vec<String>,
}

// ───────────────────────────── serve plumbing ─────────────────────────────

/// Bundles the non-store/non-hsm serve inputs so [`run`] stays within the
/// positional-parameter limit.
struct Serve {
    utxo: Option<UtxoSignerConfig>,
    dev: bool,
    tls: Option<rustls::ServerConfig>,
    bind: SocketAddr,
}

/// Assemble the daemon state and serve it (mTLS, or plain HTTP under
/// `--dev`). Generic over the concrete store + HSM so each runtime
/// combination is a static-dispatch monomorphization.
async fn run<S, H>(cfg: DaemonConfig, replay: Arc<S>, hsm: Arc<H>, serve: Serve) -> Result<()>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    let mut state = DaemonState::new(cfg, replay, hsm);
    if let Some(utxo) = serve.utxo {
        state = state.with_utxo(utxo);
    }
    if serve.dev {
        warn!("--dev: skipping assert_production_safe (software keys / unmetered / plain-HTTP permitted — NEVER use for mainnet custody)");
    } else {
        state
            .assert_production_safe()
            .map_err(|e| anyhow::anyhow!("production-safety check failed: {e}"))?;
    }
    let app = router(state);
    let listener = TcpListener::bind(serve.bind)
        .await
        .with_context(|| format!("bind {}", serve.bind))?;
    info!(bind = %serve.bind, mtls = serve.tls.is_some(), "xindex-signer-daemon listening");
    if let Some(server_config) = serve.tls {
        return tls::serve_mtls(listener, Arc::new(server_config), app)
            .await
            .map_err(Into::into);
    }
    if !serve.dev {
        bail!("mTLS config (`tls`) is required outside --dev; a production daemon must not serve plain HTTP");
    }
    warn!("--dev: serving PLAIN HTTP (no mTLS) — loopback rehearsal only");
    axum::serve(listener, app).await.map_err(Into::into)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let dev = args.iter().any(|a| a == "--dev");
    let config_path = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .context("usage: xindex-signer-daemon <config.json> [--dev]")?;

    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("read config {config_path}"))?;
    let file: FileConfig = serde_json::from_str(&raw).context("parse config json")?;
    validate_runtime_mode(&file, dev)?;

    let cfg = build_daemon_config(&file)?;
    let utxo = file.utxo.as_ref().map(build_utxo).transpose()?;
    let tls = file.tls.as_ref().map(build_server_config).transpose()?;
    let bind: SocketAddr = file
        .bind
        .parse()
        .with_context(|| format!("bind address {}", file.bind))?;
    let serve = Serve {
        utxo,
        dev,
        tls,
        bind,
    };

    match (file.database_url.as_deref(), file.hsm.kind) {
        (Some(db), HsmKind::Http) => {
            let replay = Arc::new(SqliteReplayStore::connect(db).await?);
            run(cfg, replay, Arc::new(build_http_hsm(&file)?), serve).await
        }
        (None, HsmKind::Http) => {
            warn_in_memory();
            let replay = Arc::new(InMemoryReplayStore::new());
            run(cfg, replay, Arc::new(build_http_hsm(&file)?), serve).await
        }
        (Some(db), HsmKind::Software) => {
            let replay = Arc::new(SqliteReplayStore::connect(db).await?);
            run(cfg, replay, Arc::new(build_software_hsm(&file)?), serve).await
        }
        (None, HsmKind::Software) => {
            warn_in_memory();
            let replay = Arc::new(InMemoryReplayStore::new());
            run(cfg, replay, Arc::new(build_software_hsm(&file)?), serve).await
        }
    }
}

fn warn_in_memory() {
    warn!("no database_url — using IN-MEMORY replay store; replay/equivocation state is LOST on restart (dev only)");
}

/// Enforce the properties that live outside [`DaemonState`]: the concrete
/// replay backend, the transport to the HSM frontend, and the outer mTLS
/// listener. These checks run before opening the database or binding a socket.
fn validate_runtime_mode(file: &FileConfig, dev: bool) -> Result<()> {
    if file.hsm.kind == HsmKind::Software && !dev {
        bail!("hsm.kind=\"software\" requires --dev; a production daemon must front an HSM (hsm.kind=\"http\")");
    }
    if file.hsm.kind == HsmKind::Http {
        validate_hsm_url(
            file.hsm
                .url
                .as_deref()
                .context("hsm.kind=\"http\" requires hsm.url")?,
        )?;
    }
    if !dev {
        if file.database_url.is_none() {
            bail!("database_url is required outside --dev; production replay/equivocation state must survive restart");
        }
        if file.tls.is_none() {
            bail!("mTLS config (`tls`) is required outside --dev; a production daemon must not serve plain HTTP");
        }
    }
    Ok(())
}

/// Production HSM traffic is process-local. Refuse credentials in the URL and
/// refuse DNS names other than `localhost`, so an operator cannot accidentally
/// send signing requests (including digests and key aliases) over a routed
/// network.
fn validate_hsm_url(raw: &str) -> Result<()> {
    let url = reqwest::Url::parse(raw).context("hsm.url must be a valid URL (value redacted)")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("hsm.url must not contain userinfo, a query, or a fragment");
    }
    if !matches!(url.scheme(), "http" | "https") {
        bail!("hsm.url must use http or https on loopback");
    }
    let host = url.host_str().context("hsm.url must include a host")?;
    let host_ip = host.trim_start_matches('[').trim_end_matches(']');
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host_ip
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if !loopback {
        bail!("hsm.url must terminate on loopback inside the HSM perimeter");
    }
    Ok(())
}

// ───────────────────────────── builders ─────────────────────────────

fn build_daemon_config(file: &FileConfig) -> Result<DaemonConfig> {
    let intent_policy = IntentPolicy {
        signer_whitelist: file
            .intent_policy
            .signer_whitelist
            .iter()
            .map(|a| parse_addr(a))
            .collect::<Result<_>>()?,
        intent_quorum: file.intent_policy.intent_quorum,
        ric_max_age_secs: file.intent_policy.ric_max_age_secs,
    };
    intent_policy
        .validate()
        .map_err(|e| anyhow::anyhow!("intent_policy invalid: {e}"))?;

    let mut caps = HashMap::with_capacity(file.cert_volume.caps.len());
    for (name, cap) in &file.cert_volume.caps {
        caps.insert(parse_chain_id(name)?, *cap);
    }
    let cert_volume = CertVolumePolicy {
        window_secs: file.cert_volume.window_secs,
        caps,
    };
    cert_volume
        .validate()
        .map_err(|e| anyhow::anyhow!("cert_volume invalid: {e}"))?;

    Ok(DaemonConfig {
        chain_id: file.chain_id,
        verifying_contract: parse_addr(&file.verifying_contract)?,
        eth_address: parse_addr(&file.eth_address)?,
        intent_policy,
        cert_volume,
    })
}

fn build_utxo(u: &UtxoFile) -> Result<UtxoSignerConfig> {
    let pubkeys = u
        .pubkeys
        .iter()
        .map(|p| PublicKey::from_str(p).with_context(|| format!("utxo pubkey {p}")))
        .collect::<Result<Vec<_>>>()?;
    let descriptor = MultisigDescriptor::new_p2wsh(u.threshold, &pubkeys)
        .map_err(|e| anyhow::anyhow!("build p2wsh descriptor: {e}"))?;
    let my_pubkey = PublicKey::from_str(&u.my_pubkey)
        .with_context(|| format!("utxo my_pubkey {}", u.my_pubkey))?;
    Ok(UtxoSignerConfig {
        chain_id: parse_chain_id(&u.chain)?,
        network: parse_network(&u.network)?,
        descriptor,
        my_pubkey,
        hsm_address: parse_addr(&u.hsm_address)?,
    })
}

fn build_http_hsm(file: &FileConfig) -> Result<HttpHsmClient> {
    let url = file
        .hsm
        .url
        .as_deref()
        .context("hsm.kind=\"http\" requires hsm.url")?;
    Ok(HttpHsmClient::new(url))
}

fn build_software_hsm(file: &FileConfig) -> Result<SoftwareHsm> {
    let keys = file
        .hsm
        .software
        .as_ref()
        .context("hsm.kind=\"software\" requires hsm.software keys")?;
    let eth = hex32(&keys.eth_secret_key).context("hsm.software.eth_secret_key")?;
    let btc = hex32(&keys.btc_secret_key).context("hsm.software.btc_secret_key")?;
    SoftwareHsm::new(eth, btc).map_err(Into::into)
}

fn build_server_config(t: &TlsFile) -> Result<rustls::ServerConfig> {
    let server_chain = tls::load_cert_chain(
        &std::fs::read(&t.server_cert).with_context(|| format!("read {}", t.server_cert))?,
    )?;
    let server_key = tls::load_private_key(
        &std::fs::read(&t.server_key).with_context(|| format!("read {}", t.server_key))?,
    )?;
    let pins = t
        .pinned_client_certs
        .iter()
        .map(|p| std::fs::read(p).with_context(|| format!("read {p}")))
        .collect::<Result<Vec<_>>>()?;
    let roots = tls::pinned_root_store(&pins)?;
    Ok(tls::server_config(server_chain, server_key, roots)?)
}

// ───────────────────────────── parse helpers ─────────────────────────────

fn parse_addr(s: &str) -> Result<Address> {
    Address::from_str(s).with_context(|| format!("invalid address {s}"))
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes =
        alloy_primitives::hex::decode(stripped).context("bad secret hex (value redacted)")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes, got {}", bytes.len()))
}

/// Map a config chain name to a [`ChainId`]. The one-box rehearsal targets
/// BTC; other families are gated behind their own rehearsals (DL-P3-7), so
/// they are deliberately not accepted here yet.
fn parse_chain_id(name: &str) -> Result<ChainId> {
    match name.to_ascii_lowercase().as_str() {
        "btc" => Ok(ChainId::Btc),
        other => bail!("unsupported chain '{other}' (the rehearsal daemon serves btc)"),
    }
}

fn parse_network(s: &str) -> Result<Network> {
    match s.to_ascii_lowercase().as_str() {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => bail!("unknown bitcoin network '{other}'"),
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]

    use super::*;

    #[test]
    fn hsm_url_is_strictly_loopback_and_redacted() {
        assert!(validate_hsm_url("http://127.0.0.1:9000").is_ok());
        assert!(validate_hsm_url("https://[::1]:9000").is_ok());
        assert!(validate_hsm_url("https://localhost:9000").is_ok());
        assert!(validate_hsm_url("https://hsm.example:9000").is_err());
        assert!(validate_hsm_url("http://user:secret@127.0.0.1:9000").is_err());

        let secret_url = "not-a-url-containing-secret-123";
        let error = validate_hsm_url(secret_url).expect_err("invalid URL must fail");
        assert!(!error.to_string().contains(secret_url));
    }

    #[test]
    fn malformed_software_secret_is_redacted() {
        let secret = "not-hex-secret-456";
        let error = hex32(secret).expect_err("malformed secret must fail");
        assert!(!error.to_string().contains(secret));
        assert!(error.to_string().contains("redacted"));
    }
}
