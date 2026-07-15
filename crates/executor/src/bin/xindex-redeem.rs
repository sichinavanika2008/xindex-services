//! `xindex-redeem` — current-protocol Bitcoin custody executor.
//!
//! Production consumes only the canonical finalized observer journal,
//! collects an exact 3-of-5 RIC from independent observers, builds one exact
//! Bitcoin transaction, obtains threshold partial signatures from remote
//! HSM-backed daemons over pinned mTLS, persists the correlation and finalized
//! bytes before broadcast, and supervises exact-byte rebroadcast/reorg state.
//! The software-key and latest-log paths exist only behind explicit `--dev`.
//!
//! Replay-after-restart: the daemon optionally backfills missed events
//! between `--from-block` and the latest tip before subscribing live.
//! Replay is gated by [`BroadcastRegistry::has_record`]: if an intent is
//! already in the registry (pending or confirmed) we skip it. Without
//! this gate, the Bitcoin chain would NOT save us — the original tx's
//! UTXO is mempool-spent (filtered out by Esplora), so a second
//! execute would pick a different UTXO and broadcast a fresh, valid
//! payout. The user would receive 2× their pro-rata for one share burn.
//! Operationally, set `BROADCAST_DATABASE_URL` to a persistent `SQLite`
//! file so the gate survives daemon restarts; an in-memory registry
//! reverts to the unsafe behaviour and the daemon logs a warning at
//! startup.

use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address as EvmAddress;
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Network, PublicKey};
use clap::{Parser, ValueEnum};
use futures_util::StreamExt;
use prometheus::Registry;
use tracing::{error, info, warn};
use xindex_chain_eth::bindings::ThorchainAdapter;
use xindex_chain_eth::finalized_observer::{FinalizedDispatchRecord, SqliteFinalizedObserverStore};
use xindex_chain_eth::finalized_rpc::FinalizedRpcClient;
use xindex_chain_eth::rpc::redacted_endpoint;
use xindex_chain_thor::ThorClient;
use xindex_chain_utxo::{EsploraClient, UtxoChainClient, UtxoParams};
use xindex_executor::remote_cosigner::RemoteMultisigCosigner;
use xindex_executor::ric_collector::{CollectedRic, RicCollector};
use xindex_executor::{
    decode_redeem_event, now_unix_secs, run_watcher, BroadcastRegistry, InMemoryBroadcastRegistry,
    InProcessExecutor, MultisigCosigner, PendingBroadcast, SqliteBroadcastRegistry, WatcherConfig,
};

/// Signer-key backend selection. `software` loads K secret keys from
/// `--multisig-secret-keys` (DEV ONLY — keys live in this process's
/// heap, spending real BTC). `remote` posts PSBT inputs over HTTP to
/// N signer-daemons each holding one HSM-backed key. Production
/// mainnet MUST be `remote`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SignerMode {
    Software,
    Remote,
}
use xindex_multisig::MultisigDescriptor;
use xindex_ops::{serve_metrics, Metrics};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::redemption_dispatch::{AnyRedemptionDispatch, RedemptionDispatchStore};

#[derive(Parser, Debug, Clone)]
#[command(version, about = "Xindex redemption executor (M3)")]
struct Args {
    /// Enable local/test scaffolding, including software keys and in-memory
    /// replay state. Omit for the fail-closed production profile.
    #[arg(long, env = "XINDEX_DEV", default_value_t = false)]
    dev: bool,

    /// WebSocket Ethereum RPC endpoint. Anvil default is `ws://127.0.0.1:8545`;
    /// Sepolia uses an Alchemy/Infura WSS URL.
    #[arg(long, env = "ETH_RPC_URL", default_value = "ws://127.0.0.1:8545")]
    rpc_url: String,

    /// Deployed `ThorchainAdapter` address. We watch this contract for
    /// `RedeemDispatched` events.
    #[arg(long, env = "THORCHAIN_ADAPTER_ADDR")]
    thorchain_adapter: String,

    /// Expected BTC target-token sentinel emitted by the adapter.
    #[arg(long, env = "BTC_TARGET_TOKEN")]
    btc_target_token: Option<String>,

    /// HTTP RPC exposing Ethereum's consensus-finalized tag. Production uses
    /// this only to prove the shared finalized journal is caught up/canonical.
    #[arg(long, env = "ETH_FINALIZED_RPC_URL")]
    eth_finalized_rpc_url: Option<String>,

    /// Expected Ethereum chain id for the finalized execution RPC.
    #[arg(long, env = "EXPECTED_ETH_CHAIN_ID")]
    expected_eth_chain_id: Option<u64>,

    /// Finalized observer `SQLite` database populated by this operator's
    /// `xindex-finalized-observer` instance.
    #[arg(long, env = "FINALIZED_OBSERVER_DATABASE_URL")]
    finalized_observer_database_url: Option<String>,

    /// Exact observer identity used to namespace the finalized journal.
    #[arg(long, env = "FINALIZED_OBSERVER_ID")]
    finalized_observer_id: Option<String>,

    /// Production finalized-journal scan interval.
    #[arg(long, env = "FINALIZED_POLL_MILLIS", default_value_t = 2_000)]
    finalized_poll_millis: u64,

    /// `THORNode` REST base URL. Used to resolve the live BTC Asgard
    /// inbound vault (rotates per churn) the reverse deposit is sent to.
    /// Mainnet: `https://thornode.thorchain.network`. Stagenet:
    /// `https://stagenet-thornode.ninerealms.com`.
    #[arg(
        long,
        env = "THORNODE_URL",
        default_value = "https://thornode.thorchain.network"
    )]
    thornode_url: String,

    /// Optional `sqlx` URL for the persistent F2 redemption-dispatch
    /// store (`(redemptionId, legIndex) → inbound_txid`). The signer's
    /// redemption cross-check reads this to exact-txid query
    /// `THORChain`. Unset = in-memory (lost on restart; the signer then
    /// cannot correlate a redemption it didn't see dispatched in this
    /// process). Production:
    /// `sqlite:./xindex-redemption-dispatch.db?mode=rwc`.
    #[arg(long, env = "REDEMPTION_DATABASE_URL")]
    redemption_database_url: Option<String>,

    /// Esplora HTTP base URL. Mainnet:
    /// `https://blockstream.info/api`. Signet:
    /// `https://blockstream.info/signet/api`. Self-hosted Esplora is
    /// also supported (point at your own instance for production).
    #[arg(long, env = "ESPLORA_URL")]
    esplora_url: String,

    /// Bitcoin network the multisig lives on. Must match the `esplora_url`.
    /// Valid values: `bitcoin`, `signet`, `testnet`, `regtest`.
    #[arg(long, env = "BTC_NETWORK", default_value = "signet")]
    btc_network: String,

    /// UTXO chain this executor instance serves. One of `btc`, `ltc`,
    /// `bch`, `doge`, `zec`. Determines (a) which `ChainId` is recorded
    /// in the dispatch store so the signer's per-leg cross-check finds
    /// the right inbound, and (b) which per-chain config the
    /// signer-daemon dispatches against. Default `btc`.
    #[arg(long, env = "CHAIN", default_value = "btc")]
    chain: String,

    /// Comma-separated 33-byte (compressed) secp256k1 public keys of the
    /// N multisig signers, hex-encoded. The order MUST match the order
    /// the multisig descriptor was built with at deploy time.
    #[arg(long, env = "MULTISIG_PUBKEYS")]
    multisig_pubkeys: String,

    /// k-of-n threshold of the multisig (e.g., 3 for a 3-of-5).
    #[arg(long, env = "MULTISIG_THRESHOLD")]
    multisig_threshold: usize,

    /// Signer-key backend. `software` (default) loads the K secret keys
    /// from `--multisig-secret-keys` (DEV ONLY — keys in process heap).
    /// `remote` posts PSBT inputs to N signer-daemons (PART 5 /
    /// DL-M5-1) — coordinator holds zero key material. Mainnet MUST
    /// use `remote`.
    #[arg(long, env = "SIGNER_MODE", value_enum, default_value_t = SignerMode::Software)]
    signer_mode: SignerMode,

    /// (software mode) Comma-separated 32-byte secp256k1 secret keys,
    /// hex-encoded. ≥ `multisig_threshold` keys must be supplied. Each
    /// key must correspond to one of the public keys in
    /// `--multisig-pubkeys`. DEV / STAGING ONLY.
    #[arg(long, env = "MULTISIG_SECRET_KEYS")]
    multisig_secret_keys: Option<String>,

    /// (remote mode) Comma-separated base URLs of the signer-daemons
    /// (one per signer party). Same length / ordering as
    /// `--cosigner-pubkeys`.
    #[arg(long, env = "COSIGNER_DAEMON_URLS")]
    cosigner_daemon_urls: Option<String>,

    /// (remote mode) Comma-separated compressed-secp256k1 pubkeys (Set
    /// A per `docs/runbooks/key-ceremony.md`). Each daemon's
    /// `PsbtSignResponse.pubkey` is pinned per index — a misdirected
    /// daemon returning a different pubkey is a hard fail.
    #[arg(long, env = "COSIGNER_PUBKEYS")]
    cosigner_pubkeys: Option<String>,

    /// Production mTLS client certificate presented to every custody signer.
    #[arg(long, env = "COSIGNER_CLIENT_CERT_PEM")]
    cosigner_client_cert_pem: Option<PathBuf>,

    /// Owner-only production mTLS client private key.
    #[arg(long, env = "COSIGNER_CLIENT_KEY_PEM")]
    cosigner_client_key_pem: Option<PathBuf>,

    /// Leaf-first exact signer-daemon peer bundle. The legacy CLI/environment
    /// name says CA, but a CA-only file does not authorize its issued leaves.
    #[arg(long, env = "COSIGNER_SERVER_CA_PEM")]
    cosigner_server_ca_pem: Option<PathBuf>,

    /// CTD-1 (`DL-CTD-2` Slice B): comma-separated base URLs of the
    /// per-operator REDEMPTION OBSERVER services (one per operator,
    /// e.g. `http://op1.internal:9101,http://op2.internal:9101`). When
    /// set, the executor collects a k-of-n Redemption Intent
    /// Certificate from these observers and attaches it to every custody
    /// spend; the spend pays to the Asgard inbound the observers'
    /// quorum independently agreed on. REQUIRED for any mainnet path —
    /// the RPC-free signer daemons REJECT a proof-less spend.
    #[arg(long, env = "OBSERVER_URLS")]
    observer_urls: Option<String>,

    /// CTD-1 Slice B: number of agreeing observer certificates required
    /// to assemble the RIC (the k of the k-of-n Set-B ceremony, e.g. 3
    /// of 5). Required when `--observer-urls` is set.
    #[arg(long, env = "INTENT_QUORUM")]
    intent_quorum: Option<usize>,

    /// Production mTLS client certificate presented to observer services.
    #[arg(long, env = "OBSERVER_CLIENT_CERT_PEM")]
    observer_client_cert_pem: Option<PathBuf>,

    /// Owner-only observer-transport client private key.
    #[arg(long, env = "OBSERVER_CLIENT_KEY_PEM")]
    observer_client_key_pem: Option<PathBuf>,

    /// Leaf-first exact observer peer bundle. The legacy CLI/environment name
    /// says CA, but a CA-only file does not authorize its issued leaves.
    #[arg(long, env = "OBSERVER_SERVER_CA_PEM")]
    observer_server_ca_pem: Option<PathBuf>,

    /// Fee FLOOR + fallback (sats). The daemon derives the absolute fee
    /// from a live Esplora `/fee-estimates` rate at startup
    /// (`estimate_fee_rate_sat_vb`); this value is the lower bound and
    /// the value used verbatim if the estimator errors. The old
    /// conservative ~5 000-sat constant is preserved as that floor so
    /// behaviour never regresses below the previous static fee.
    #[arg(long, env = "BTC_FEE_SATS", default_value_t = 5_000)]
    fee_sats: u64,

    /// Confirmation-target (blocks) for the live fee estimate. Default 3
    /// — a redemption deposit should confirm promptly without paying the
    /// 1-block premium. See `pick_fee_estimate`.
    #[arg(long, env = "BTC_FEE_TARGET_BLOCKS", default_value_t = 3)]
    fee_target_blocks: u16,

    /// Hard cap (sats) on the derived fee. Guards against an Esplora
    /// fee-spike or garbage estimate draining the change output. Default
    /// 100 000 sats — generous for a 3-of-5 P2WSH redeem even in a
    /// congested mempool, but bounded.
    #[arg(long, env = "BTC_FEE_CAP_SATS", default_value_t = 100_000)]
    fee_cap_sats: u64,

    /// Block number to start replay from when the daemon (re)starts. Use
    /// 0 (default) to subscribe to new events only. Pass a historical
    /// block to backfill missed events after downtime.
    #[arg(long, env = "FROM_BLOCK", default_value_t = 0)]
    from_block: u64,

    /// Optional `sqlx` database URL for persistent broadcast registry.
    /// If unset, the daemon falls back to an in-memory registry — pending
    /// broadcasts are lost on restart and Bitcoin txs may sit stuck in
    /// mempool indefinitely without re-broadcast. Production should set
    /// `sqlite:./xindex-redeem.db?mode=rwc` so the watcher's reorg-aware
    /// re-broadcast loop has stable state.
    #[arg(long, env = "BROADCAST_DATABASE_URL")]
    broadcast_database_url: Option<String>,

    /// Stuck-timeout for the re-broadcast watcher (seconds). A pending
    /// tx that isn't visible on chain for longer than this gets
    /// re-broadcast. Default 1 hour — far longer than normal mempool
    /// propagation; short enough that a dropped tx is detected within
    /// the same operational shift.
    #[arg(long, env = "REBROADCAST_STUCK_TIMEOUT_SECS", default_value_t = 3600)]
    rebroadcast_stuck_timeout_secs: u64,

    /// Confirmation depth at which a broadcast is marked `confirmed` (the
    /// watcher keeps re-validating it against re-org until `final_depth`).
    /// Default 6, matching BTC `conf_depth` + the `xindex-attest` policy.
    #[arg(long, env = "REBROADCAST_MIN_CONFIRMATIONS", default_value_t = 6)]
    rebroadcast_min_confirmations: u32,

    /// Depth at which a confirmed broadcast is considered FINAL — beyond any
    /// plausible re-org — and the watcher stops re-validating it (audit M8).
    /// Default 100 blocks (~16 h on BTC).
    #[arg(long, env = "REBROADCAST_FINAL_DEPTH", default_value_t = 100)]
    rebroadcast_final_depth: u32,

    /// Loopback Prometheus/health listener. The custody process treats an
    /// unexpected metrics-server exit as fatal so monitoring cannot silently
    /// disappear while broadcasts continue.
    #[arg(long, env = "METRICS_ADDRESS", default_value = "127.0.0.1:9094")]
    metrics_address: SocketAddr,
}

impl Args {
    fn assert_production_safe(&self) -> Result<()> {
        if self.dev {
            return Ok(());
        }
        if self.signer_mode != SignerMode::Remote || self.multisig_secret_keys.is_some() {
            anyhow::bail!("production requires remote HSM cosigners and prohibits raw secret keys");
        }
        if self.chain != "btc" || !matches!(self.btc_network.as_str(), "bitcoin" | "mainnet") {
            anyhow::bail!("the reviewed production profile enables Bitcoin mainnet only");
        }
        let custody_signers = csv_member_count(Some(&self.multisig_pubkeys));
        if custody_signers != 5 || self.multisig_threshold != 3 {
            anyhow::bail!("production custody topology must be exactly 3-of-5");
        }
        if !self.metrics_address.ip().is_loopback() || self.metrics_address.port() == 0 {
            anyhow::bail!("production metrics listener must use a non-zero loopback port");
        }
        if self.broadcast_database_url.is_none() || self.redemption_database_url.is_none() {
            anyhow::bail!("production requires durable broadcast and redemption SQLite stores");
        }
        if self.finalized_observer_database_url.is_none()
            || self.finalized_observer_id.is_none()
            || self.eth_finalized_rpc_url.is_none()
            || self
                .expected_eth_chain_id
                .is_none_or(|chain_id| chain_id == 0)
            || self.btc_target_token.is_none()
            || !(500..=30_000).contains(&self.finalized_poll_millis)
        {
            anyhow::bail!(
                "production requires a bounded, canonical finalized-observer journal source"
            );
        }
        validate_finalized_rpc_url(
            self.eth_finalized_rpc_url
                .as_deref()
                .context("finalized RPC absent")?,
        )?;
        let target = EvmAddress::from_str(
            self.btc_target_token
                .as_deref()
                .context("BTC target token absent")?,
        )
        .context("BTC target token invalid")?;
        if target.is_zero() {
            anyhow::bail!("BTC target token must be non-zero");
        }
        let observers = csv_member_count(self.observer_urls.as_deref());
        let quorum = self.intent_quorum.unwrap_or(0);
        if observers != 5 || quorum != 3 {
            anyhow::bail!("production observer topology must be exactly 3-of-5");
        }
        if self.cosigner_daemon_urls.is_none() || self.cosigner_pubkeys.is_none() {
            anyhow::bail!("production requires pinned remote cosigner endpoints and public keys");
        }
        let cosigner_endpoints = csv_member_count(self.cosigner_daemon_urls.as_deref());
        let cosigner_keys = csv_member_count(self.cosigner_pubkeys.as_deref());
        if cosigner_endpoints != 5 || cosigner_keys != 5 {
            anyhow::bail!("production remote-cosigner topology must be exactly 3-of-5");
        }
        for path in [
            &self.cosigner_client_cert_pem,
            &self.cosigner_client_key_pem,
            &self.cosigner_server_ca_pem,
            &self.observer_client_cert_pem,
            &self.observer_client_key_pem,
            &self.observer_server_ca_pem,
        ] {
            if path.is_none() {
                anyhow::bail!(
                    "production requires pinned mTLS material for cosigners and observers"
                );
            }
        }
        validate_distinct_https_origins(
            self.cosigner_daemon_urls.as_deref().unwrap_or_default(),
            "cosigner",
        )?;
        validate_distinct_https_origins(
            self.observer_urls.as_deref().unwrap_or_default(),
            "observer",
        )?;
        validate_secret_file(
            self.cosigner_client_key_pem
                .as_deref()
                .context("cosigner client key absent")?,
        )?;
        validate_secret_file(
            self.observer_client_key_pem
                .as_deref()
                .context("observer client key absent")?,
        )?;
        Ok(())
    }
}

fn csv_member_count(spec: Option<&str>) -> usize {
    spec.unwrap_or_default()
        .split(',')
        .filter(|value| !value.trim().is_empty())
        .count()
}

fn validate_distinct_https_origins(spec: &str, label: &str) -> Result<()> {
    let mut origins = HashSet::new();
    for raw in spec
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let url = reqwest::Url::parse(raw).with_context(|| format!("invalid {label} URL"))?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            anyhow::bail!("production {label} URLs must be credential-free HTTPS origins");
        }
        let host = url
            .host_str()
            .with_context(|| format!("{label} URL has no host"))?;
        let port = url
            .port_or_known_default()
            .with_context(|| format!("{label} URL has no port"))?;
        if !origins.insert(format!("{}:{port}", host.to_ascii_lowercase())) {
            anyhow::bail!("production {label} endpoint origins must be distinct");
        }
    }
    Ok(())
}

fn validate_finalized_rpc_url(raw: &str) -> Result<()> {
    let url = reqwest::Url::parse(raw).context("invalid finalized RPC URL")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("finalized RPC URL must not contain credentials/query/fragment");
    }
    let host = url.host_str().context("finalized RPC URL has no host")?;
    let host_ip = host.trim_start_matches('[').trim_end_matches(']');
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host_ip
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        anyhow::bail!("finalized RPC must use HTTPS or loopback HTTP");
    }
    Ok(())
}

fn validate_secret_file(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !path.is_absolute() || !metadata.file_type().is_file() {
        anyhow::bail!("secret path must be an absolute non-symlink regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            anyhow::bail!("transport private key must be owner-only and single-link");
        }
    }
    Ok(())
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

    let args = Args::parse();
    args.assert_production_safe()?;
    // Static dispatch on the broadcast registry impl. Persistent
    // (SQLite) for prod; in-memory for dev.
    if let Some(db_url) = args.broadcast_database_url.clone() {
        info!("using SqliteBroadcastRegistry (persistent)");
        let registry = Arc::new(
            SqliteBroadcastRegistry::connect(&db_url)
                .await
                .context("connect SqliteBroadcastRegistry")?,
        );
        Box::pin(run(args, registry)).await
    } else {
        // The double-pay defense (registry.has_record gate before
        // executing) only works if the registry persists across
        // restarts. In-memory mode loses its records on restart, so a
        // --from-block backfill would re-execute everything and risk
        // user double-pay. Loud warn at startup so the operator can
        // never accidentally run this against real funds.
        warn!(
            "InMemoryBroadcastRegistry — state lost on restart. DOUBLE-PAY DEFENSE DISABLED \
             across daemon restarts. DO NOT use against mainnet / any chain holding real BTC. \
             Set BROADCAST_DATABASE_URL=sqlite:./xindex-redeem.db?mode=rwc for production."
        );
        let registry = Arc::new(InMemoryBroadcastRegistry::new());
        Box::pin(run(args, registry)).await
    }
}

/// Parse `--btc-network` text into a [`bitcoin::Network`]. We accept the
/// canonical four (`bitcoin`/`signet`/`testnet`/`regtest`) and fail on
/// anything else — a typo here would route a real-money redemption to
/// the wrong chain.
fn parse_network(s: &str) -> Result<Network> {
    match s {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "signet" => Ok(Network::Signet),
        "testnet" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        other => anyhow::bail!("unknown btc_network: {other}"),
    }
}

/// Parse a comma-separated list of hex-encoded compressed secp256k1
/// public keys.
fn parse_pubkeys(spec: &str) -> Result<Vec<PublicKey>> {
    let pubkeys = spec
        .split(',')
        .map(|s| PublicKey::from_str(s.trim()).with_context(|| format!("invalid pubkey: {s}")))
        .collect::<Result<Vec<_>>>()?;
    let unique = pubkeys
        .iter()
        .map(ToString::to_string)
        .collect::<HashSet<_>>();
    if unique.len() != pubkeys.len() {
        anyhow::bail!("multisig/cosigner pubkeys must be distinct");
    }
    Ok(pubkeys)
}

/// Parse a comma-separated list of hex-encoded 32-byte secret keys.
fn parse_secret_keys(spec: &str) -> Result<Vec<SecretKey>> {
    spec.split(',')
        .enumerate()
        .map(|(i, s)| {
            let trimmed = s.trim();
            let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
            let bytes = alloy_primitives::hex::decode(stripped)
                .with_context(|| format!("secret key #{i}: invalid hex"))?;
            if bytes.len() != 32 {
                anyhow::bail!("secret key #{i}: must be 32 bytes, got {}", bytes.len());
            }
            SecretKey::from_slice(&bytes)
                .with_context(|| format!("secret key #{i}: not a valid secp256k1 scalar"))
        })
        .collect()
}

/// Cross-check that every secret key derives a public key in the
/// configured multisig set. Mismatch means the operator handed us keys
/// for a different multisig — a redemption attempt would still produce
/// signatures, but the finalized witness would fail Bitcoin script
/// validation, the broadcast would revert, and the user would wait
/// forever. Better to fail at startup.
fn verify_keys_match_descriptor(secret_keys: &[SecretKey], pubkeys: &[PublicKey]) -> Result<()> {
    let secp = Secp256k1::new();
    for (i, sk) in secret_keys.iter().enumerate() {
        let derived = PublicKey::new(sk.public_key(&secp));
        if !pubkeys.iter().any(|p| p == &derived) {
            anyhow::bail!("secret key #{i} derives a pubkey that is not in --multisig-pubkeys");
        }
    }
    Ok(())
}

/// Estimated virtual size (vB) of a redeem spend: a 3-of-5 P2WSH input
/// (~ 3 ECDSA sigs + the witness script in the witness) plus the Asgard
/// output, the `OP_RETURN` memo, and a change output. Conservative —
/// overestimating fee slightly is safe (it only shrinks change, never
/// underpays relay); a second input adds ~104 vB but the cap + floor
/// bound both ends. Used only to turn a sat/vB rate into an absolute
/// budget; the binding protection is still the on-chain `minOut`.
const EST_REDEEM_VSIZE: u64 = 400;

/// Turn a live sat/vB `rate` into an absolute fee, clamped to
/// `[floor_sats, cap_sats]`. Pure + total — the mutation-test target.
/// A non-finite or non-positive rate (garbage estimate) yields the
/// floor, never 0 or NaN.
#[must_use]
fn derive_fee_sats(rate_sat_vb: f64, est_vsize: u64, floor_sats: u64, cap_sats: u64) -> u64 {
    let cap = cap_sats.max(floor_sats);
    if !rate_sat_vb.is_finite() || rate_sat_vb <= 0.0 {
        return floor_sats.min(cap);
    }
    // Clamp the f64 product into the integer window FIRST so the final
    // f64→u64 cast is provably finite and non-negative (no truncation
    // beyond intent, no sign loss). vsize ≤ 400, rate finite +
    // positive ⇒ product well under 2^53.
    #[expect(
        clippy::cast_precision_loss,
        reason = "vsize ≤ 400 ≪ 2^53; exact in f64"
    )]
    let vsize_f = est_vsize as f64;
    #[expect(
        clippy::cast_precision_loss,
        reason = "cap clamps below 2^53 sats; exact in f64"
    )]
    let cap_f = cap as f64;
    #[expect(
        clippy::cast_precision_loss,
        reason = "floor clamps below 2^53 sats; exact in f64"
    )]
    let floor_f = floor_sats.min(cap) as f64;
    let clamped = (rate_sat_vb * vsize_f).ceil().clamp(floor_f, cap_f);
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "clamped to [floor, cap] ⊂ [0, u64::MAX) above; cast is total"
    )]
    let fee = clamped as u64;
    fee
}

fn resolve_fee_sats(chain: &EsploraClient, args: &Args) -> u64 {
    match chain.estimate_fee_rate_sat_vb(args.fee_target_blocks) {
        Ok(rate) => {
            let derived = derive_fee_sats(rate, EST_REDEEM_VSIZE, args.fee_sats, args.fee_cap_sats);
            info!(
                rate_sat_vb = rate,
                target_blocks = args.fee_target_blocks,
                floor_sats = args.fee_sats,
                cap_sats = args.fee_cap_sats,
                derived_fee_sats = derived,
                "derived dynamic Bitcoin fee from live Esplora estimate"
            );
            derived
        }
        Err(e) => {
            warn!(
                error = %e,
                fallback_fee_sats = args.fee_sats,
                "Esplora fee estimate unavailable; using configured flat floor"
            );
            args.fee_sats
        }
    }
}

/// Build the configured executor backend.
/// - `software`: parse the K secret keys + verify they belong to the
///   descriptor's pubkey set + hand to `InProcessExecutor::new`. DEV
///   ONLY (keys in process heap).
/// - `remote`: build one [`RemoteMultisigCosigner`] per `(url, pubkey)`
///   pair from the CLI; each entry pins its expected pubkey and a
///   misdirected daemon is a hard fail at first sign. Coordinator
///   holds zero key material.
fn build_executor(
    args: &Args,
    chain_id: ChainId,
    descriptor: MultisigDescriptor,
    pubkeys: &[PublicKey],
    chain: EsploraClient,
    network: Network,
    fee_sats: u64,
) -> Result<InProcessExecutor<EsploraClient>> {
    match args.signer_mode {
        SignerMode::Software => {
            let spec = args.multisig_secret_keys.as_deref().ok_or_else(|| {
                anyhow::anyhow!("--multisig-secret-keys required in software mode")
            })?;
            let secret_keys = parse_secret_keys(spec)?;
            if secret_keys.len() < args.multisig_threshold {
                anyhow::bail!(
                    "fewer secret keys ({}) than threshold ({})",
                    secret_keys.len(),
                    args.multisig_threshold
                );
            }
            verify_keys_match_descriptor(&secret_keys, pubkeys)?;
            warn!("running with SOFTWARE signer backend — keys held in heap; DEV / STAGING ONLY");
            InProcessExecutor::new(descriptor, secret_keys, chain, network, fee_sats)
                .map_err(|e| anyhow::anyhow!("build executor: {e}"))
        }
        SignerMode::Remote => {
            let urls = args
                .cosigner_daemon_urls
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--cosigner-daemon-urls required in remote mode"))?;
            let pks_spec = args
                .cosigner_pubkeys
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--cosigner-pubkeys required in remote mode"))?;
            let urls: Vec<&str> = urls.split(',').map(str::trim).collect();
            let pks = parse_pubkeys(pks_spec)?;
            if urls.len() != pks.len() {
                anyhow::bail!(
                    "--cosigner-daemon-urls ({}) and --cosigner-pubkeys ({}) length mismatch",
                    urls.len(),
                    pks.len()
                );
            }
            if pks.len() < args.multisig_threshold {
                anyhow::bail!(
                    "fewer cosigners ({}) than threshold ({})",
                    pks.len(),
                    args.multisig_threshold
                );
            }
            // Sanity: each cosigner pubkey must appear in the descriptor.
            for (i, pk) in pks.iter().enumerate() {
                if !pubkeys.contains(pk) {
                    anyhow::bail!(
                        "cosigner #{i} pubkey {pk} not in --multisig-pubkeys descriptor set"
                    );
                }
            }
            let mut cosigners: Vec<Box<dyn MultisigCosigner>> = Vec::with_capacity(pks.len());
            let tls = if args.dev {
                None
            } else {
                Some((
                    fs::read(
                        args.cosigner_client_cert_pem
                            .as_deref()
                            .context("cosigner client certificate required")?,
                    )?,
                    fs::read(
                        args.cosigner_client_key_pem
                            .as_deref()
                            .context("cosigner client key required")?,
                    )?,
                    fs::read(
                        args.cosigner_server_ca_pem
                            .as_deref()
                            .context("cosigner exact server peer bundle required")?,
                    )?,
                ))
            };
            for (url, pk) in urls.iter().zip(pks.iter()) {
                let cosigner = if let Some((cert, key, roots)) = &tls {
                    RemoteMultisigCosigner::with_mtls_pem(
                        chain_id,
                        (*url).to_string(),
                        *pk,
                        cert,
                        key,
                        roots,
                        Duration::from_secs(10),
                    )?
                } else {
                    RemoteMultisigCosigner::new(chain_id, (*url).to_string(), *pk)
                };
                cosigners.push(Box::new(cosigner));
            }
            InProcessExecutor::with_cosigners(descriptor, cosigners, chain, network, fee_sats)
                .map_err(|e| anyhow::anyhow!("build executor: {e}"))
        }
    }
}

/// Build the CTD-1 per-operator-observer RIC collector from the CLI.
/// `None` when `--observer-urls` is unset (dev / software mode). When
/// set, `--intent-quorum` is REQUIRED and the collector fails closed if
/// fewer observers than the quorum are configured.
fn build_ric_collector(args: &Args) -> Result<Option<RicCollector>> {
    let Some(spec) = args.observer_urls.as_deref() else {
        return Ok(None);
    };
    let quorum = args
        .intent_quorum
        .ok_or_else(|| anyhow::anyhow!("--intent-quorum required when --observer-urls is set"))?;
    let urls: Vec<String> = spec
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let collector = if args.dev {
        RicCollector::new(urls, quorum)
    } else {
        RicCollector::with_mtls_pem(
            urls,
            quorum,
            &fs::read(
                args.observer_client_cert_pem
                    .as_deref()
                    .context("observer client certificate required")?,
            )?,
            &fs::read(
                args.observer_client_key_pem
                    .as_deref()
                    .context("observer client key required")?,
            )?,
            &fs::read(
                args.observer_server_ca_pem
                    .as_deref()
                    .context("observer exact server peer bundle required")?,
            )?,
            Duration::from_secs(20),
        )
    }
    .map_err(|e| anyhow::anyhow!("build RIC collector: {e}"))?;
    info!(
        quorum,
        "CTD-1 RIC collector enabled (per-operator observers)"
    );
    Ok(Some(collector))
}

/// Self-resolve the live BTC Asgard inbound vault (dev / software-mode
/// fallback when no observers are configured). Logs + returns `None` on
/// halt / absence / query failure / invalid network so the caller skips
/// the leg. The observer path supersedes this in production.
async fn resolve_self_btc_asgard(
    thor: &ThorClient,
    redemption_id: alloy::primitives::B256,
) -> Option<String> {
    match thor.vault_for_chain("BTC").await {
        Ok(Some(v)) if !v.halted => Some(v.address),
        Ok(Some(_)) => {
            error!(redemption_id = %redemption_id,
                   "THORChain BTC inbound HALTED; skipping (retries on next event)");
            None
        }
        Ok(None) => {
            error!(redemption_id = %redemption_id,
                   "THORChain returned no BTC inbound vault; skipping");
            None
        }
        Err(e) => {
            error!(redemption_id = %redemption_id, error = %e,
                   "THORChain vault query failed; skipping");
            None
        }
    }
}

fn finalized_dispatch_event(
    record: FinalizedDispatchRecord,
    expected_target: EvmAddress,
) -> Result<ThorchainAdapter::RedeemDispatched> {
    if record.leg_index != 0 {
        anyhow::bail!("reviewed BTC launch profile permits redemption leg 0 only");
    }
    if record.target_token != expected_target {
        anyhow::bail!("finalized dispatch target token differs from launch configuration");
    }
    let memo =
        String::from_utf8(record.facts.memo).context("finalized dispatch memo is not UTF-8")?;
    Ok(ThorchainAdapter::RedeemDispatched {
        dispatchId: record.dispatch_id,
        redemptionId: record.redemption_id,
        targetToken: record.target_token,
        amount: record.facts.amount,
        destination: record.facts.final_destination,
        memo,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "single sequential pipeline; splitting fights alloy 0.8's deeply nested fillers generic"
)]
async fn run<R>(args: Args, registry: Arc<R>) -> Result<()>
where
    R: BroadcastRegistry + 'static,
{
    let prometheus = Registry::new();
    let metrics = Metrics::new(&prometheus).context("register custody metrics")?;
    let metrics_address = args.metrics_address;
    let adapter_addr = EvmAddress::from_str(&args.thorchain_adapter)
        .context("THORCHAIN_ADAPTER_ADDR must be a 20-byte hex address")?;
    let network = parse_network(&args.btc_network)?;
    let chain: ChainId = args
        .chain
        .parse()
        .with_context(|| format!("--chain {:?} is not a known UTXO chain", args.chain))?;

    let pubkeys = parse_pubkeys(&args.multisig_pubkeys)?;
    let descriptor = MultisigDescriptor::new_p2wsh(args.multisig_threshold, &pubkeys)
        .context("build multisig descriptor")?;
    let multisig_addr = descriptor
        .address(network)
        .context("derive multisig address")?;
    info!(
        rpc_endpoint = %redacted_endpoint(&args.rpc_url),
        thorchain_adapter = %adapter_addr,
        esplora_endpoint = %redacted_endpoint(&args.esplora_url),
        btc_network = ?network,
        multisig_address = %multisig_addr,
        threshold = args.multisig_threshold,
        signer_count = pubkeys.len(),
        signer_mode = ?args.signer_mode,
        "xindex-redeem starting"
    );

    // Two Esplora clients: one owned by the executor (for UTXO selection
    // + broadcast), one shared with the watcher (for confirmation polling
    // + stuck-tx re-broadcast). Both point at the same URL; the cost is
    // a second HTTP connection pool, far cheaper than refactoring
    // InProcessExecutor to share an `Arc<C>` with the watcher.
    // EsploraClient + the remote cosigners are `reqwest::blocking` clients;
    // constructing them (and the fee probe, which calls Esplora) on a runtime
    // worker thread panics — reqwest's blocking builder spawns + drops a
    // temporary runtime, and dropping a runtime inside an async context is
    // forbidden. Build them on a blocking thread.
    let (executor, watcher_chain) = {
        let a = args.clone();
        let descriptor = descriptor.clone();
        let pubkeys = pubkeys.clone();
        tokio::task::spawn_blocking(move || {
            let executor_chain =
                EsploraClient::for_chain(UtxoParams::for_chain(chain), network, &a.esplora_url);
            // Live Esplora fee estimate (L-R5); floor + cap + fallback are
            // handled inside `resolve_fee_sats`.
            let fee_sats = resolve_fee_sats(&executor_chain, &a);
            let executor = build_executor(
                &a,
                chain,
                descriptor,
                &pubkeys,
                executor_chain,
                network,
                fee_sats,
            )
            .context("build executor")?;
            let watcher_chain = Arc::new(EsploraClient::for_chain(
                UtxoParams::for_chain(chain),
                network,
                &a.esplora_url,
            ));
            anyhow::Ok((executor, watcher_chain))
        })
        .await
        .context("build executor task")??
    };
    // Shared so each event's blocking spend can run on its own blocking thread.
    let executor = std::sync::Arc::new(executor);

    // THORChain client — resolves the live BTC Asgard inbound vault
    // (rotates per churn) the reverse deposit is sent to.
    let thor = ThorClient::with_base_url(&args.thornode_url).context("thornode client")?;

    // CTD-1 (`DL-CTD-2` Slice B): the per-operator-observer RIC
    // collector. `Some` only when `--observer-urls` is configured;
    // mandatory for any mainnet path (the RPC-free daemons reject a
    // proof-less custody spend). Built once; cloned-by-ref into the
    // event loop.
    // The RIC collector also holds a `reqwest::blocking` client — build it
    // off the runtime worker thread for the same reason as the executor.
    let collector = {
        let a = args.clone();
        tokio::task::spawn_blocking(move || build_ric_collector(&a))
            .await
            .context("build RIC collector task")??
    };
    if collector.is_none() && matches!(args.signer_mode, SignerMode::Remote) {
        warn!(
            "REMOTE signer mode with NO --observer-urls: every custody spend will be REJECTED \
             by the daemons (CTD-1 requires a k-of-n RIC). Configure the per-operator observers."
        );
    }

    // F2 correlation store (executor writer / signer reader).
    if args.redemption_database_url.is_none() {
        warn!(
            "F2 redemption-dispatch store IN-MEMORY — lost on restart. The signer's \
             redemption cross-check cannot correlate a redemption it didn't see dispatched \
             in THIS process; finalize/cancel would stall. Set REDEMPTION_DATABASE_URL \
             (sqlite:./xindex-redemption-dispatch.db?mode=rwc) for production."
        );
    }
    let dispatch_store = Arc::new(
        AnyRedemptionDispatch::connect(args.redemption_database_url.as_deref())
            .await
            .context("connect F2 redemption-dispatch store")?,
    );

    // Spawn the reorg-aware re-broadcast watcher BEFORE entering the
    // subscribe loop. Closes Rust-audit finding L-R2: previously a
    // broadcast tx that was evicted from mempool (fee competition,
    // reorg) silently lost the redemption — shares burnt on Ethereum,
    // no BTC delivered. Now we register every broadcast and the watcher
    // re-broadcasts any stuck tx.
    let pending_at_startup = registry
        .pending_count()
        .await
        .context("registry pending_count")?;
    let reserved_at_startup = registry
        .reserved_count()
        .await
        .context("registry reserved_count")?;
    if reserved_at_startup != 0 && !args.dev {
        anyhow::bail!(
            "{reserved_at_startup} custody dispatch reservation(s) lack an exact persisted transaction; operator incident review required"
        );
    }
    info!(
        pending_broadcasts_recovered = pending_at_startup,
        incomplete_reservations = reserved_at_startup,
        stuck_timeout_secs = args.rebroadcast_stuck_timeout_secs,
        min_confirmations = args.rebroadcast_min_confirmations,
        final_depth = args.rebroadcast_final_depth,
        "spawning rebroadcast watcher"
    );
    metrics
        .executor_pending_broadcasts
        .set(i64::try_from(pending_at_startup).unwrap_or(i64::MAX));
    let watcher_registry = Arc::clone(&registry);
    let watcher_chain_clone = Arc::clone(&watcher_chain);
    let watcher_cfg = WatcherConfig {
        interval: Duration::from_mins(1),
        stuck_timeout: Duration::from_secs(args.rebroadcast_stuck_timeout_secs),
        min_confirmations: args.rebroadcast_min_confirmations,
        final_depth: args.rebroadcast_final_depth,
    };
    let watcher = run_watcher(
        watcher_registry,
        watcher_chain_clone,
        watcher_cfg,
        Some(metrics.clone()),
    );

    // Helper: process one decoded event end-to-end. Inlined as a closure
    // returning a Future so we can `.await` the registry calls.
    // Errors LOGGED, not propagated — a single bad event never crashes
    // the daemon.
    let process_event = async |ev: ThorchainAdapter::RedeemDispatched| {
        metrics.executor_redemptions_received.inc();
        let mut task = match decode_redeem_event(&ev) {
            Ok(t) => t,
            Err(e) => {
                metrics
                    .executor_redemptions_failed
                    .with_label_values(&["decode_error"])
                    .inc();
                error!(redemption_id = %ev.redemptionId, error = %e,
                       "decode failed; skipping event");
                return;
            }
        };

        // Idempotency gate keyed by the per-adapter dispatch id (unique
        // per dispatch). Without it a `--from-block` backfill or restart
        // re-replays an unconfirmed event: Esplora reports the original
        // UTXO spent, the executor picks a different UTXO and broadcasts
        // a second valid Asgard deposit → the redemption's BTC is sent
        // to THORChain twice for one burn. Defer on lookup error.
        match registry.has_record(&task.dispatch_id).await {
            Ok(true) => {
                metrics
                    .custody_dispatches
                    .with_label_values(&["btc", "refused"])
                    .inc();
                info!(dispatch_id = %task.dispatch_id,
                      "dispatch already in registry; skipping replay");
                return;
            }
            Ok(false) => {}
            Err(e) => {
                metrics
                    .custody_dispatches
                    .with_label_values(&["btc", "error"])
                    .inc();
                error!(dispatch_id = %task.dispatch_id, error = %e,
                       "registry has_record check failed; skipping for safety");
                return;
            }
        }

        // CTD-1 (`DL-CTD-2` Slice B): when per-operator observers are
        // configured, collect the k-of-n RIC and pay to the Asgard
        // inbound the observers' quorum independently agreed on — not a
        // single coordinator resolution — so the PSBT matches the
        // certified `immediate_target_hash` the RPC-free daemon binds. A
        // sub-quorum / split result skips the leg (never a proof-less
        // custody spend). With NO observers (dev / software mode) we
        // self-resolve; the daemons reject proof-less spends in remote
        // mode, so that path is dev-only by construction.
        let collected: Option<CollectedRic> = match collector.as_ref() {
            Some(c) => {
                let Some(stamp) = now_unix_secs() else {
                    error!(redemption_id = %task.redemption_id,
                           "system clock is before Unix epoch; refusing RIC collection");
                    return;
                };
                // RicCollector is a reqwest::blocking client — collect on a
                // blocking thread, not this async worker.
                let c = c.clone();
                let rid = task.redemption_id;
                match tokio::task::spawn_blocking(move || c.collect(chain, rid, 0, stamp)).await {
                    Ok(Ok(cr)) => Some(cr),
                    Ok(Err(e)) => {
                        metrics
                            .custody_dispatches
                            .with_label_values(&["btc", "refused"])
                            .inc();
                        error!(redemption_id = %task.redemption_id, error = %e,
                               "RIC collection failed; skipping (no proof-less custody spend)");
                        return;
                    }
                    Err(e) => {
                        metrics
                            .custody_dispatches
                            .with_label_values(&["btc", "error"])
                            .inc();
                        error!(redemption_id = %task.redemption_id, error = %e,
                               "RIC collection task panicked; skipping");
                        return;
                    }
                }
            }
            None => None,
        };
        let asgard_str = match &collected {
            // The observers' agreement gate already refused halted /
            // split vaults, so a collected target is live by construction.
            Some(cr) => cr.asgard_address.clone(),
            None => match resolve_self_btc_asgard(&thor, task.redemption_id).await {
                Some(addr) => addr,
                None => return,
            },
        };
        let Ok(Ok(asgard)) =
            bitcoin::Address::from_str(&asgard_str).map(|a| a.require_network(network))
        else {
            error!(redemption_id = %task.redemption_id, addr = %asgard_str,
                   "Asgard vault address invalid for our network; skipping");
            return;
        };
        // Attach the collected proof; the cosigners forward it to the
        // daemons, which REQUIRE + re-verify it before signing.
        if let Some(cr) = collected {
            task.intent_proof = Some(cr.proof);
        }

        info!(
            redemption_id = %task.redemption_id,
            asgard = %asgard,
            amount_sats = %task.amount,
            "executing reverse BTC→Asgard deposit"
        );

        // Write-ahead reserve BEFORE the irreversible broadcast (audit
        // H1): the idempotency row must exist before we broadcast, so a
        // crash or a transient register error afterwards can no longer
        // leave NO row and let a `--from-block` replay select a fresh
        // UTXO and broadcast a SECOND valid Asgard deposit for one burn.
        // Skip on a pre-existing reservation (replay); fail-safe-skip on
        // error (never broadcast without a persisted reservation).
        match registry.reserve(&task.dispatch_id).await {
            Ok(true) => metrics
                .custody_dispatches
                .with_label_values(&["btc", "reserved"])
                .inc(),
            Ok(false) => {
                metrics
                    .custody_dispatches
                    .with_label_values(&["btc", "refused"])
                    .inc();
                info!(dispatch_id = %task.dispatch_id,
                      "dispatch already reserved; skipping (reserve-before-broadcast)");
                return;
            }
            Err(e) => {
                metrics
                    .custody_dispatches
                    .with_label_values(&["btc", "error"])
                    .inc();
                error!(dispatch_id = %task.dispatch_id, error = %e,
                       "reserve failed; skipping for safety (no broadcast)");
                return;
            }
        }
        // Build + HSM-sign the exact transaction after reservation but do not
        // broadcast yet. The finalized bytes and F2 correlation must both be
        // durable first, so an ambiguous transport result can only retry this
        // same txid, never select a second UTXO.
        let prepare_executor = std::sync::Arc::clone(&executor);
        let (prepare_result, task, asgard) = match tokio::task::spawn_blocking(move || {
            let result = prepare_executor.prepare_redemption_tx(&task, &asgard);
            (result, task, asgard)
        })
        .await
        {
            Ok(triple) => triple,
            Err(e) => {
                metrics
                    .executor_redemptions_failed
                    .with_label_values(&["psbt_sign"])
                    .inc();
                metrics
                    .custody_dispatches
                    .with_label_values(&["btc", "error"])
                    .inc();
                error!(error = %e, "prepare task panicked; dispatch remains reserved");
                return;
            }
        };
        let tx = match prepare_result {
            Ok(tx) => tx,
            Err(e) => {
                metrics
                    .executor_redemptions_failed
                    .with_label_values(&["psbt_sign"])
                    .inc();
                metrics
                    .custody_dispatches
                    .with_label_values(&["btc", "error"])
                    .inc();
                error!(redemption_id = %task.redemption_id, error = %e,
                       "prepare/sign failed; dispatch remains durably reserved");
                return;
            }
        };
        metrics
            .custody_dispatches
            .with_label_values(&["btc", "signed"])
            .inc();
        let txid = tx.compute_txid();
        let Some(now) = now_unix_secs() else {
            metrics
                .custody_dispatches
                .with_label_values(&["btc", "error"])
                .inc();
            error!(redemption_id = %task.redemption_id, %txid,
                   "clock failure after signing; dispatch remains reserved and is not broadcast");
            return;
        };
        let Ok(amount_sats) = u64::try_from(task.amount) else {
            metrics
                .custody_dispatches
                .with_label_values(&["btc", "error"])
                .inc();
            error!(redemption_id = %task.redemption_id,
                   "prepared amount no longer fits u64; dispatch remains reserved");
            return;
        };

        // F2 correlation and exact tx bytes are both write-ahead records.
        // Either failure leaves a visible reservation and no broadcast.
        if let Err(e) = dispatch_store
            .record(task.redemption_id, 0u32, chain, txid.to_string(), now)
            .await
        {
            metrics
                .custody_dispatches
                .with_label_values(&["btc", "error"])
                .inc();
            error!(redemption_id = %task.redemption_id, %txid, error = %e,
                   "F2 dispatch record failed before broadcast; dispatch remains reserved");
            return;
        }
        let entry = PendingBroadcast {
            intent_id: task.dispatch_id,
            txid,
            tx_bytes: bitcoin::consensus::serialize(&tx),
            recipient_addr: asgard.to_string(),
            amount_sats,
            broadcast_at_unix_secs: now,
            // Zero makes an ambiguous/failed initial attempt eligible for
            // exact-byte rebroadcast on the next watcher tick.
            last_attempt_unix_secs: 0,
        };
        if let Err(e) = registry.register(entry).await {
            metrics
                .custody_dispatches
                .with_label_values(&["btc", "error"])
                .inc();
            error!(redemption_id = %task.redemption_id, %txid, error = %e,
                   "exact transaction persistence failed; not broadcasting");
            return;
        }
        metrics.executor_pending_broadcasts.inc();

        let broadcast_executor = std::sync::Arc::clone(&executor);
        let broadcast =
            tokio::task::spawn_blocking(move || broadcast_executor.broadcast_prepared(&tx)).await;
        match broadcast {
            Ok(Ok(observed)) => {
                metrics.executor_redemptions_broadcast.inc();
                metrics
                    .custody_dispatches
                    .with_label_values(&["btc", "broadcast"])
                    .inc();
                if let Err(e) = registry.touch_attempt(&task.dispatch_id, now).await {
                    warn!(dispatch_id = %task.dispatch_id, error = %e,
                          "broadcast succeeded but attempt timestamp update failed");
                }
                info!(redemption_id = %task.redemption_id, txid = %observed,
                      "BTC→Asgard broadcast from persisted transaction");
            }
            Ok(Err(e)) => {
                metrics
                    .executor_redemptions_failed
                    .with_label_values(&["broadcast_error"])
                    .inc();
                warn!(redemption_id = %task.redemption_id, %txid, error = %e,
                      "initial broadcast ambiguous/failed; exact tx queued for retry");
            }
            Err(e) => {
                metrics
                    .executor_redemptions_failed
                    .with_label_values(&["broadcast_error"])
                    .inc();
                warn!(redemption_id = %task.redemption_id, %txid, error = %e,
                      "broadcast task panicked; exact tx queued for retry");
            }
        }
    };

    let event_source = async {
        if !args.dev {
            let observer_store = SqliteFinalizedObserverStore::connect(
                args.finalized_observer_database_url
                    .as_deref()
                    .context("finalized observer database required")?,
                args.finalized_observer_id
                    .as_deref()
                    .context("finalized observer id required")?,
            )
            .await
            .context("connect finalized observer journal")?;
            let finalized_rpc = FinalizedRpcClient::new(
                args.eth_finalized_rpc_url
                    .as_deref()
                    .context("finalized RPC required")?
                    .to_string(),
            )?;
            let chain_id = finalized_rpc.chain_id().await?;
            if Some(chain_id.value) != args.expected_eth_chain_id {
                anyhow::bail!("finalized RPC chain id differs from production configuration");
            }
            let expected_target = EvmAddress::from_str(
                args.btc_target_token
                    .as_deref()
                    .context("BTC target token required")?,
            )?;
            let poll = Duration::from_millis(args.finalized_poll_millis);
            loop {
                let head = finalized_rpc.finalized_head().await?;
                let checkpoint = observer_store.last_checkpoint().await?;
                let caught_up = checkpoint.is_some_and(|checkpoint| {
                    checkpoint.block_number == head.value.number
                        && checkpoint.block_hash == head.value.hash
                });
                if !caught_up {
                    warn!(
                        finalized_head = head.value.number,
                        "custody paused until the finalized observer journal catches up"
                    );
                    tokio::time::sleep(poll).await;
                    continue;
                }
                for record in observer_store.all_dispatches().await? {
                    let event = finalized_dispatch_event(record, expected_target)?;
                    process_event(event).await;
                }
                tokio::time::sleep(poll).await;
            }
        }

        // Development-only event source. Production never subscribes to latest
        // logs and reaches this point only when `--dev` was explicitly supplied.
        let ws = WsConnect::new(&args.rpc_url);
        let provider = Arc::new(
            ProviderBuilder::new()
                .with_recommended_fillers()
                .on_ws(ws)
                .await
                .context("connect development WS provider")?,
        );

        // Backfill missed events if the operator passed `--from-block`.
        if args.from_block > 0 {
            let latest = provider
                .get_block_number()
                .await
                .context("get block number")?;
            info!(
                from_block = args.from_block,
                latest, "backfilling missed events"
            );
            let backfill_filter = Filter::new()
                .address(adapter_addr)
                .event_signature(ThorchainAdapter::RedeemDispatched::SIGNATURE_HASH)
                .from_block(BlockNumberOrTag::Number(args.from_block))
                .to_block(BlockNumberOrTag::Number(latest));
            let logs = provider
                .get_logs(&backfill_filter)
                .await
                .context("backfill get_logs")?;
            info!(count = logs.len(), "backfill batch");
            for log in logs {
                match log.log_decode::<ThorchainAdapter::RedeemDispatched>() {
                    Ok(decoded) => process_event(decoded.inner.data).await,
                    Err(e) => warn!(error = %e, "failed to decode RedeemDispatched log"),
                }
            }
        }

        let filter = Filter::new()
            .address(adapter_addr)
            .event_signature(ThorchainAdapter::RedeemDispatched::SIGNATURE_HASH);
        let sub = provider
            .subscribe_logs(&filter)
            .await
            .context("subscribe to RedeemDispatched")?;
        let mut stream = sub.into_stream();

        info!("subscribed; waiting for RedeemDispatched events…");

        while let Some(log) = stream.next().await {
            match log.log_decode::<ThorchainAdapter::RedeemDispatched>() {
                Ok(decoded) => process_event(decoded.inner.data).await,
                Err(e) => warn!(error = %e, "failed to decode RedeemDispatched log"),
            }
        }
        anyhow::Ok(())
    };

    let metrics_server = serve_metrics(prometheus, metrics_address);
    tokio::select! {
        result = event_source => match result {
            Ok(()) => Err(anyhow::anyhow!("custody event source exited unexpectedly")),
            Err(error) => Err(error),
        },
        result = watcher => match result {
            Ok(()) => Err(anyhow::anyhow!("rebroadcast watcher exited unexpectedly")),
            Err(error) => Err(anyhow::anyhow!("rebroadcast watcher failed: {error}")),
        },
        result = metrics_server => match result {
            Ok(()) => Err(anyhow::anyhow!("custody metrics server exited unexpectedly")),
            Err(error) => Err(anyhow::anyhow!("custody metrics server failed: {error}")),
        },
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use super::*;

    fn production_args() -> Args {
        Args {
            dev: false,
            rpc_url: "wss://execution.example".into(),
            thorchain_adapter: "0x0000000000000000000000000000000000000001".into(),
            btc_target_token: Some("0x0000000000000000000000000000000000000002".into()),
            eth_finalized_rpc_url: Some("https://finalized.example".into()),
            expected_eth_chain_id: Some(1),
            finalized_observer_database_url: Some("sqlite:///var/lib/xindex/finalized.db".into()),
            finalized_observer_id: Some("observer-01".into()),
            finalized_poll_millis: 2_000,
            thornode_url: "https://thornode.example".into(),
            redemption_database_url: Some("sqlite:///var/lib/xindex/redemptions.db".into()),
            esplora_url: "https://esplora.example".into(),
            btc_network: "bitcoin".into(),
            chain: "btc".into(),
            multisig_pubkeys: "p1,p2,p3,p4,p5".into(),
            multisig_threshold: 3,
            signer_mode: SignerMode::Remote,
            multisig_secret_keys: None,
            cosigner_daemon_urls: Some(
                "https://c1.example,https://c2.example,https://c3.example,https://c4.example,https://c5.example"
                    .into(),
            ),
            cosigner_pubkeys: Some("p1,p2,p3,p4,p5".into()),
            cosigner_client_cert_pem: Some("/definitely/not/read/cosigner.crt".into()),
            cosigner_client_key_pem: Some("/definitely/not/read/cosigner.key".into()),
            cosigner_server_ca_pem: Some("/definitely/not/read/cosigner-peer.pem".into()),
            observer_urls: Some(
                "https://o1.example,https://o2.example,https://o3.example,https://o4.example,https://o5.example"
                    .into(),
            ),
            intent_quorum: Some(3),
            observer_client_cert_pem: Some("/definitely/not/read/observer.crt".into()),
            observer_client_key_pem: Some("/definitely/not/read/observer.key".into()),
            observer_server_ca_pem: Some("/definitely/not/read/observer-peer.pem".into()),
            fee_sats: 5_000,
            fee_target_blocks: 3,
            fee_cap_sats: 100_000,
            from_block: 0,
            broadcast_database_url: Some("sqlite:///var/lib/xindex/broadcast.db".into()),
            rebroadcast_stuck_timeout_secs: 3_600,
            rebroadcast_min_confirmations: 6,
            rebroadcast_final_depth: 100,
            metrics_address: SocketAddr::from(([127, 0, 0, 1], 9094)),
        }
    }

    fn assert_policy_rejection(args: &Args, expected: &str) {
        let error = args
            .assert_production_safe()
            .expect_err("unsafe production mutation must fail");
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?}, got {error:#}"
        );
        assert!(
            !error.to_string().contains("definitely/not/read"),
            "policy mutation reached secret-file I/O: {error:#}"
        );
    }

    /// L-04: compiled mutation matrix over the production-only custody
    /// preflight. Dummy secret paths and key text must remain untouched.
    #[test]
    fn production_profile_behavior_rejects_unsafe_mutations() {
        let mut software = production_args();
        software.signer_mode = SignerMode::Software;
        assert_policy_rejection(&software, "requires remote HSM cosigners");

        let mut raw_key = production_args();
        raw_key.multisig_secret_keys = Some("never-read-secret".into());
        assert_policy_rejection(&raw_key, "prohibits raw secret keys");

        let mut non_mainnet = production_args();
        non_mainnet.btc_network = "signet".into();
        assert_policy_rejection(&non_mainnet, "Bitcoin mainnet only");

        let mut collapsed_custody = production_args();
        collapsed_custody.multisig_pubkeys = "p1,p2,p3".into();
        assert_policy_rejection(
            &collapsed_custody,
            "custody topology must be exactly 3-of-5",
        );

        let mut public_metrics = production_args();
        public_metrics.metrics_address = SocketAddr::from(([0, 0, 0, 0], 9094));
        assert_policy_rejection(&public_metrics, "metrics listener");

        let mut ephemeral = production_args();
        ephemeral.broadcast_database_url = None;
        assert_policy_rejection(&ephemeral, "durable broadcast and redemption SQLite stores");

        let mut no_finalized_journal = production_args();
        no_finalized_journal.finalized_observer_database_url = None;
        assert_policy_rejection(&no_finalized_journal, "finalized-observer journal source");

        let mut plaintext_finalized_rpc = production_args();
        plaintext_finalized_rpc.eth_finalized_rpc_url = Some("http://rpc.example".into());
        assert_policy_rejection(&plaintext_finalized_rpc, "must use HTTPS");

        let mut collapsed_observers = production_args();
        collapsed_observers.observer_urls = Some("https://o1.example,https://o2.example".into());
        assert_policy_rejection(
            &collapsed_observers,
            "observer topology must be exactly 3-of-5",
        );

        let mut collapsed_cosigners = production_args();
        collapsed_cosigners.cosigner_daemon_urls = Some("https://c1.example".into());
        assert_policy_rejection(
            &collapsed_cosigners,
            "remote-cosigner topology must be exactly 3-of-5",
        );

        let mut missing_tls = production_args();
        missing_tls.observer_client_key_pem = None;
        assert_policy_rejection(&missing_tls, "pinned mTLS material");

        let mut duplicate_origin = production_args();
        duplicate_origin.cosigner_daemon_urls = Some(
            "https://c1.example,https://c1.example,https://c3.example,https://c4.example,https://c5.example"
                .into(),
        );
        assert_policy_rejection(&duplicate_origin, "origins must be distinct");
    }

    #[test]
    fn parse_network_accepts_canonical_aliases() {
        assert!(matches!(parse_network("bitcoin"), Ok(Network::Bitcoin)));
        assert!(matches!(parse_network("mainnet"), Ok(Network::Bitcoin)));
        assert!(matches!(parse_network("signet"), Ok(Network::Signet)));
        assert!(matches!(parse_network("testnet"), Ok(Network::Testnet)));
        assert!(matches!(parse_network("regtest"), Ok(Network::Regtest)));
    }

    #[test]
    fn parse_network_rejects_unknown() {
        assert!(parse_network("doge").is_err());
        assert!(parse_network("").is_err());
    }

    #[test]
    fn parse_pubkeys_rejects_duplicate_members() {
        const GENERATOR: &str =
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        assert!(parse_pubkeys(&format!("{GENERATOR},{GENERATOR}")).is_err());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test parses a known-valid hex spec")]
    fn parse_secret_keys_handles_0x_prefix() {
        // Two valid 32-byte keys, one with prefix one without.
        let spec = "0x0000000000000000000000000000000000000000000000000000000000000001,\
             0000000000000000000000000000000000000000000000000000000000000002";
        let keys = parse_secret_keys(spec).expect("parse");
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn parse_secret_keys_rejects_wrong_length() {
        let spec = "0x1234";
        assert!(parse_secret_keys(spec).is_err());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code constructs known-valid keys")]
    fn verify_keys_match_descriptor_accepts_subset() {
        let secp = Secp256k1::new();
        let sks: Vec<SecretKey> = (1u8..=5)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[31] = i;
                SecretKey::from_slice(&bytes).expect("valid")
            })
            .collect();
        let pks: Vec<PublicKey> = sks
            .iter()
            .map(|sk| PublicKey::new(sk.public_key(&secp)))
            .collect();
        // Only 3 of the 5 keys are in our wallet — that's the K-of-N case.
        verify_keys_match_descriptor(&sks[..3], &pks).expect("subset accepted");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code constructs known-valid keys")]
    fn verify_keys_match_descriptor_rejects_outsider() {
        let secp = Secp256k1::new();
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        let insider = SecretKey::from_slice(&bytes).expect("valid");
        bytes[31] = 99;
        let outsider = SecretKey::from_slice(&bytes).expect("valid");

        let pks = vec![PublicKey::new(insider.public_key(&secp))];
        assert!(verify_keys_match_descriptor(&[outsider], &pks).is_err());
    }

    #[test]
    fn derive_fee_sats_ceils_and_clamps() {
        // 45 sat/vB * 400 vB = 18 000, within [5 000, 100 000].
        assert_eq!(derive_fee_sats(45.0, 400, 5_000, 100_000), 18_000);
        // ceil: 1.001 * 400 = 400.4 → 401, but floor 5 000 dominates.
        assert_eq!(derive_fee_sats(1.001, 400, 5_000, 100_000), 5_000);
        // High rate clamped to cap.
        assert_eq!(derive_fee_sats(900.0, 400, 5_000, 100_000), 100_000);
        // Exact ceil with no clamp: 12.5 * 400 = 5 000 exactly.
        assert_eq!(derive_fee_sats(12.5, 400, 1_000, 100_000), 5_000);
        // ceil rounds up a fractional sat: 12.5001 * 400 = 5000.04 → 5001.
        assert_eq!(derive_fee_sats(12.5001, 400, 1_000, 100_000), 5_001);
    }

    #[test]
    fn derive_fee_sats_garbage_rate_yields_floor_never_zero_or_nan() {
        assert_eq!(derive_fee_sats(f64::NAN, 400, 5_000, 100_000), 5_000);
        assert_eq!(derive_fee_sats(f64::INFINITY, 400, 5_000, 100_000), 5_000);
        assert_eq!(derive_fee_sats(0.0, 400, 5_000, 100_000), 5_000);
        assert_eq!(derive_fee_sats(-3.0, 400, 5_000, 100_000), 5_000);
    }

    #[test]
    fn derive_fee_sats_cap_below_floor_is_coerced() {
        // Misconfig: cap < floor. cap is raised to floor; result is floor,
        // never an inverted clamp panic.
        assert_eq!(derive_fee_sats(45.0, 400, 10_000, 1_000), 10_000);
        assert_eq!(derive_fee_sats(f64::NAN, 400, 10_000, 1_000), 10_000);
    }
}
