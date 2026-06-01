//! `xindex-redeem` — production redemption executor (M3 deliverable).
//!
//! Watches a deployed `ThorchainAdapter` for `RedeemDispatched` events,
//! constructs a Bitcoin spending transaction from the multisig UTXO set,
//! signs it with K-of-N software keys, and broadcasts to the configured
//! Esplora endpoint. Together with `xindex-attest` (the attestation
//! poster) this closes the off-chain settlement loop.
//!
//! Trust note (M3, not M5): the K secret keys are loaded as a single
//! comma-separated CLI argument and held in this one process. Production
//! (M5) splits each key into its own daemon backed by `YubiHSM2` and
//! exchanges partial signatures over a wire protocol. The library code
//! in `xindex-executor` is structured so that swap is a drop-in: replace
//! `InProcessExecutor` with a `MultisigCosigner`-backed equivalent.
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
use tracing::{error, info, warn};
use xindex_chain_eth::bindings::ThorchainAdapter;
use xindex_chain_thor::ThorClient;
use xindex_chain_utxo::{EsploraClient, UtxoChainClient, UtxoParams};
use xindex_executor::remote_cosigner::RemoteMultisigCosigner;
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
use xindex_shared::chain_registry::ChainId;
use xindex_shared::redemption_dispatch::{AnyRedemptionDispatch, RedemptionDispatchStore};

#[derive(Parser, Debug)]
#[command(version, about = "Xindex redemption executor (M3)")]
struct Args {
    /// WebSocket Ethereum RPC endpoint. Anvil default is `ws://127.0.0.1:8545`;
    /// Sepolia uses an Alchemy/Infura WSS URL.
    #[arg(long, env = "ETH_RPC_URL", default_value = "ws://127.0.0.1:8545")]
    rpc_url: String,

    /// Deployed `ThorchainAdapter` address. We watch this contract for
    /// `RedeemDispatched` events.
    #[arg(long, env = "THORCHAIN_ADAPTER_ADDR")]
    thorchain_adapter: String,

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

    /// Confirmation depth at which a broadcast is considered settled
    /// (the watcher stops polling and marks it confirmed). Default 3,
    /// matching the cross-check policy in `xindex-attest`.
    #[arg(long, env = "REBROADCAST_MIN_CONFIRMATIONS", default_value_t = 3)]
    rebroadcast_min_confirmations: u32,
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
    // Static dispatch on the broadcast registry impl. Persistent
    // (SQLite) for prod; in-memory for dev.
    if let Some(db_url) = args.broadcast_database_url.clone() {
        info!(db_url = %db_url, "using SqliteBroadcastRegistry (persistent)");
        let registry = Arc::new(
            SqliteBroadcastRegistry::connect(&db_url)
                .await
                .context("connect SqliteBroadcastRegistry")?,
        );
        run(args, registry).await
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
        run(args, registry).await
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
    spec.split(',')
        .map(|s| PublicKey::from_str(s.trim()).with_context(|| format!("invalid pubkey: {s}")))
        .collect()
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
            for (url, pk) in urls.iter().zip(pks.iter()) {
                cosigners.push(Box::new(RemoteMultisigCosigner::new(
                    chain_id,
                    (*url).to_string(),
                    *pk,
                )));
            }
            InProcessExecutor::with_cosigners(descriptor, cosigners, chain, network, fee_sats)
                .map_err(|e| anyhow::anyhow!("build executor: {e}"))
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "single sequential pipeline; splitting fights alloy 0.8's deeply nested fillers generic"
)]
async fn run<R>(args: Args, registry: Arc<R>) -> Result<()>
where
    R: BroadcastRegistry + 'static,
{
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
        rpc_url = %args.rpc_url,
        thorchain_adapter = %adapter_addr,
        esplora_url = %args.esplora_url,
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
    let executor_chain =
        EsploraClient::for_chain(UtxoParams::for_chain(chain), network, &args.esplora_url);

    // Live Esplora fee estimate (L-R5); floor + cap + fallback handled
    // inside `resolve_fee_sats`. Extracted so `run` stays inside the
    // line budget.
    let fee_sats = resolve_fee_sats(&executor_chain, &args);
    let executor = build_executor(
        &args,
        chain,
        descriptor.clone(),
        &pubkeys,
        executor_chain,
        network,
        fee_sats,
    )
    .context("build executor")?;
    let watcher_chain = Arc::new(EsploraClient::for_chain(
        UtxoParams::for_chain(chain),
        network,
        &args.esplora_url,
    ));

    // THORChain client — resolves the live BTC Asgard inbound vault
    // (rotates per churn) the reverse deposit is sent to.
    let thor = ThorClient::with_base_url(&args.thornode_url).context("thornode client")?;

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

    let ws = WsConnect::new(&args.rpc_url);
    let provider = Arc::new(
        ProviderBuilder::new()
            .with_recommended_fillers()
            .on_ws(ws)
            .await
            .context("connect WS provider")?,
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
    info!(
        pending_broadcasts_recovered = pending_at_startup,
        stuck_timeout_secs = args.rebroadcast_stuck_timeout_secs,
        min_confirmations = args.rebroadcast_min_confirmations,
        "spawning rebroadcast watcher"
    );
    let watcher_registry = Arc::clone(&registry);
    let watcher_chain_clone = Arc::clone(&watcher_chain);
    let watcher_cfg = WatcherConfig {
        interval: Duration::from_secs(60),
        stuck_timeout: Duration::from_secs(args.rebroadcast_stuck_timeout_secs),
        min_confirmations: args.rebroadcast_min_confirmations,
    };
    tokio::spawn(async move {
        if let Err(e) = run_watcher(watcher_registry, watcher_chain_clone, watcher_cfg).await {
            error!(error = %e, "watcher exited; redemptions may sit stuck without re-broadcast");
        }
    });

    // Helper: process one decoded event end-to-end. Inlined as a closure
    // returning a Future so we can `.await` the registry calls.
    // Errors LOGGED, not propagated — a single bad event never crashes
    // the daemon.
    let process_event = async |ev: ThorchainAdapter::RedeemDispatched| {
        let task = match decode_redeem_event(&ev) {
            Ok(t) => t,
            Err(e) => {
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
                info!(dispatch_id = %task.dispatch_id,
                      "dispatch already in registry; skipping replay");
                return;
            }
            Ok(false) => {}
            Err(e) => {
                error!(dispatch_id = %task.dispatch_id, error = %e,
                       "registry has_record check failed; skipping for safety");
                return;
            }
        }

        // Resolve the LIVE BTC Asgard inbound vault. Reject if THORChain
        // reports it halted or absent — never deposit into a paused
        // vault (funds would sit unswapped). It'll retry on the next
        // event / restart backfill.
        let inbound = match thor.vault_for_chain("BTC").await {
            Ok(Some(v)) if !v.halted => v,
            Ok(Some(_)) => {
                error!(redemption_id = %task.redemption_id,
                       "THORChain BTC inbound HALTED; skipping (retries on next event)");
                return;
            }
            Ok(None) => {
                error!(redemption_id = %task.redemption_id,
                       "THORChain returned no BTC inbound vault; skipping");
                return;
            }
            Err(e) => {
                error!(redemption_id = %task.redemption_id, error = %e,
                       "THORChain vault query failed; skipping");
                return;
            }
        };
        let Ok(Ok(asgard)) =
            bitcoin::Address::from_str(&inbound.address).map(|a| a.require_network(network))
        else {
            error!(redemption_id = %task.redemption_id, addr = %inbound.address,
                   "THORChain BTC vault address invalid for our network; skipping");
            return;
        };

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
            Ok(true) => {}
            Ok(false) => {
                info!(dispatch_id = %task.dispatch_id,
                      "dispatch already reserved; skipping (reserve-before-broadcast)");
                return;
            }
            Err(e) => {
                error!(dispatch_id = %task.dispatch_id, error = %e,
                       "reserve failed; skipping for safety (no broadcast)");
                return;
            }
        }
        match executor.execute_capturing_tx(&task, &asgard) {
            Ok((txid, tx)) => {
                info!(redemption_id = %task.redemption_id, %txid, "BTC→Asgard broadcast");
                let tx_bytes = bitcoin::consensus::serialize(&tx);
                let Some(now) = now_unix_secs() else {
                    warn!(redemption_id = %task.redemption_id, %txid,
                          "clock failure (pre-1970) post-broadcast; SKIPPING registry + F2 \
                           record. Operator must monitor this txid AND manually backfill the \
                           F2 redemptionId→txid mapping before the redemption deadline.");
                    return;
                };
                let amount_sats = u64::try_from(task.amount).unwrap_or(0);
                let entry = PendingBroadcast {
                    intent_id: task.dispatch_id, // dedup key = dispatch id
                    txid,
                    tx_bytes,
                    recipient_addr: asgard.to_string(),
                    amount_sats,
                    broadcast_at_unix_secs: now,
                    last_attempt_unix_secs: now,
                };
                if let Err(e) = registry.register(entry).await {
                    warn!(redemption_id = %task.redemption_id, error = %e,
                          "register broadcast failed; watcher won't re-broadcast on eviction");
                }
                // F2: correlate (redemptionId, legIndex) → inbound_txid
                // so the signer's redemption cross-check can exact-txid
                // query THORChain. First-write-wins per leg, so a
                // re-broadcast keeps the original.
                //
                // leg_index = 0: today's THORChain rail is single-async-
                // slot, so every RedeemDispatched event is leg 0. Phase
                // 3.1 (U10) routes per ChainId::from_asset_id and will
                // populate this from the dispatched event's leg.
                if let Err(e) = dispatch_store
                    .record(task.redemption_id, 0u32, chain, txid.to_string(), now)
                    .await
                {
                    error!(redemption_id = %task.redemption_id, %txid, error = %e,
                           "F2 dispatch record FAILED — signer cannot correlate this \
                            redemption; finalize/cancel will stall. Operator must backfill \
                            the F2 mapping manually before the redemption deadline.");
                }
            }
            Err(e) => error!(redemption_id = %task.redemption_id, error = %e,
                              "execute failed; will not retry this event in current process"),
        }
    };

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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
