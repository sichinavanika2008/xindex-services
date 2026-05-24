//! `xindex-attest` — M2 deliverable.
//!
//! Watches a deployed `IntentQueue` for `MintIntentCreated` events, signs
//! each slot's `Attestation` typed-data with N software keys (simulating
//! the k-of-n signer quorum), and posts the aggregated signatures to
//! `AttestationOracle.attest`. With `THORChain` not yet integrated (M3),
//! the `attestedAmount` is taken verbatim from the intent's
//! `slotExpectedAmounts` array — the off-chain validity check (which
//! confirms the BTC actually arrived at our multisig) lands in M3.
//!
//! Trust note: this binary holds N private keys in a single process,
//! collapsing what production splits across N independent signer daemons.
//! Suitable for local Anvil end-to-end testing only. Production deploy
//! is M5: each key in its own `YubiHSM2`-backed daemon, a separate keeper
//! aggregates k-of-n from the network and posts.

use std::str::FromStr;
use std::sync::Arc;

use alloy::eips::BlockNumberOrTag;
use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use bitcoin::Network;
use clap::{Parser, ValueEnum};
use futures_util::StreamExt;
use tracing::{error, info, warn};
use xindex_chain_btc::EsploraClient;
use xindex_chain_eth::bindings::{AttestationOracle, IntentQueue};
use xindex_chain_thor::ThorClient;
use xindex_shared::eip712::{attestation, attestation_oracle_domain};
use xindex_signer::crosscheck::{CrossCheck, PassThroughPolicy, ThorBtcPolicy};
use xindex_signer::remote::{AnyHsmBackend, RemoteHsmBackend};
use xindex_signer::{aggregate_signatures, SoftwareSigner};

/// Signer-key backend selection. `software` loads raw private keys from
/// `--signer-keys` (Anvil / dev only — keys live in heap). `remote`
/// posts typed signing requests to N signer-daemons (PART 5 / DL-M5-1)
/// over HTTP; coordinator holds **zero** key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SignerMode {
    Software,
    Remote,
}

/// Cross-check policy selection. **`PassThrough` is for Anvil tests
/// only** — it always returns Ok and emits a `WARN` log on every call.
/// Production deploys MUST use `ThorBtc`, which requires `--thor-url`,
/// `--esplora-url`, `--btc-network`, and `--btc-multisig-address`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CrossCheckMode {
    PassThrough,
    ThorBtc,
}

#[derive(Parser, Debug)]
#[command(version, about = "Xindex k-of-n attestation signer + poster (M2)")]
struct Args {
    /// WebSocket RPC endpoint (Anvil default `ws://127.0.0.1:8545`).
    #[arg(long, env = "ETH_RPC_URL", default_value = "ws://127.0.0.1:8545")]
    rpc_url: String,

    /// Deployed `IntentQueue` address. Watched for events.
    #[arg(long, env = "INTENT_QUEUE_ADDR")]
    intent_queue: String,

    /// Deployed `AttestationOracle` address. Receives `attest` calls.
    #[arg(long, env = "ATTESTATION_ORACLE_ADDR")]
    attestation_oracle: String,

    /// Signer-key backend. `software` (default) loads raw private keys
    /// from `--signer-keys` — DEV / TEST ONLY. `remote` posts to N
    /// signer-daemons over HTTP and pins each daemon's disclosed signer
    /// address (`--signer-daemon-addresses`). Mainnet MUST be `remote`.
    #[arg(long, env = "SIGNER_MODE", value_enum, default_value_t = SignerMode::Software)]
    signer_mode: SignerMode,

    /// (software mode) Comma-separated hex private keys of the signers
    /// (in any order; must match `_isSigner[...]` registrations on the
    /// oracle). DEV / TEST ONLY — keys live in this process's heap.
    #[arg(long, env = "SIGNER_KEYS")]
    signer_keys: Option<String>,

    /// (remote mode) Comma-separated base URLs of the signer-daemons —
    /// one per signer party (e.g.
    /// `https://signer-1.ops.internal,https://signer-2.ops.internal,…`).
    /// Same length / ordering as `--signer-daemon-addresses`.
    #[arg(long, env = "SIGNER_DAEMON_URLS")]
    signer_daemon_urls: Option<String>,

    /// (remote mode) Comma-separated Ethereum addresses of the signer
    /// daemons (Set B per `docs/runbooks/key-ceremony.md`, the publicly
    /// disclosed signer set). Each daemon's response is pinned and
    /// verified against the matching entry — a misdirected daemon is a
    /// hard fail.
    #[arg(long, env = "SIGNER_DAEMON_ADDRESSES")]
    signer_daemon_addresses: Option<String>,

    /// k-of-n threshold to post per attestation. MUST match the on-chain
    /// `_threshold` of the deployed oracle.
    #[arg(long, env = "THRESHOLD")]
    threshold: usize,

    /// Hex private key of the EOA that submits the `attest` transaction.
    /// Pays gas. Anvil deterministic account 0 is the conventional choice.
    #[arg(long, env = "POSTER_KEY")]
    poster_key: String,

    /// Block number to start replay from when the daemon (re)starts.
    /// Use 0 (the default) to subscribe only to new events. Use a specific
    /// historical block to backfill missed events after downtime — the
    /// daemon will fetch logs `[from_block, latest)` then transition to
    /// the live subscription.
    ///
    /// On-chain replay is safe: posting an attest for an already-attested
    /// slot reverts cleanly via `IntentQueue_SlotAlreadyAttested`. The
    /// daemon catches that revert (M-1 fix) and continues.
    #[arg(long, env = "FROM_BLOCK", default_value_t = 0)]
    from_block: u64,

    /// Cross-check policy. `pass-through` always succeeds (Anvil only).
    /// `thor-btc` requires `THORChain` RPC + Esplora + multisig configured;
    /// the signer verifies that `THORChain` reports the deposit observed
    /// AND a confirmed Bitcoin UTXO has arrived at our multisig before
    /// signing.
    #[arg(long, env = "CROSS_CHECK_MODE", value_enum, default_value_t = CrossCheckMode::PassThrough)]
    cross_check_mode: CrossCheckMode,

    /// `THORChain` REST URL (required for `thor-btc` mode). Stagenet:
    /// `https://stagenet-thornode.ninerealms.com`. Mainnet:
    /// `https://thornode.ninerealms.com`.
    #[arg(long, env = "THOR_URL")]
    thor_url: Option<String>,

    /// Esplora HTTP base URL (required for `thor-btc` mode). Signet:
    /// `https://blockstream.info/signet/api`.
    #[arg(long, env = "ESPLORA_URL")]
    esplora_url: Option<String>,

    /// Bitcoin network (required for `thor-btc` mode). Must match
    /// `--esplora-url`.
    #[arg(long, env = "BTC_NETWORK")]
    btc_network: Option<String>,

    /// 3-of-5 P2WSH Bitcoin multisig address that custodies the BTC
    /// arrivals (required for `thor-btc` mode). Cross-check verifies a
    /// matching UTXO is sitting at this address.
    #[arg(long, env = "BTC_MULTISIG_ADDRESS")]
    btc_multisig_address: Option<String>,

    /// Minimum Bitcoin confirmations required before attesting. Default
    /// 6 (≈ 1 hour); signet tests can lower to 1.
    #[arg(long, env = "BTC_MIN_CONFIRMATIONS", default_value_t = 6)]
    btc_min_confirmations: u32,

    /// Allowed sat-difference between `THORChain`'s claimed outbound and
    /// the actual UTXO arrival. Default 0 (exact equality).
    #[arg(long, env = "BTC_TOLERANCE_SATS", default_value_t = 0)]
    btc_tolerance_sats: u64,
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
    run(args).await
}

/// Build the configured signer backend set. `software` → raw keys from
/// `--signer-keys` (DEV ONLY). `remote` → one [`RemoteHsmBackend`] per
/// `(url, address)` pair, with the address pinned per response (a
/// misdirected daemon is a hard fail at the first signature).
fn build_signers(args: &Args) -> Result<Vec<AnyHsmBackend>> {
    match args.signer_mode {
        SignerMode::Software => {
            let keys = args
                .signer_keys
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--signer-keys required in software mode"))?;
            let mut out = Vec::new();
            for k in keys.split(',') {
                let s = SoftwareSigner::from_hex(k.trim())
                    .with_context(|| format!("invalid SIGNER_KEYS entry: {k}"))?;
                out.push(AnyHsmBackend::Software(s));
            }
            Ok(out)
        }
        SignerMode::Remote => {
            let urls = args
                .signer_daemon_urls
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--signer-daemon-urls required in remote mode"))?;
            let addrs = args.signer_daemon_addresses.as_deref().ok_or_else(|| {
                anyhow::anyhow!("--signer-daemon-addresses required in remote mode")
            })?;
            let urls: Vec<&str> = urls.split(',').map(str::trim).collect();
            let addrs: Vec<&str> = addrs.split(',').map(str::trim).collect();
            if urls.len() != addrs.len() {
                anyhow::bail!(
                    "--signer-daemon-urls ({}) and --signer-daemon-addresses ({}) length mismatch",
                    urls.len(),
                    addrs.len()
                );
            }
            let mut out = Vec::new();
            for (url, addr) in urls.iter().zip(addrs.iter()) {
                let a = Address::from_str(addr)
                    .with_context(|| format!("invalid signer daemon address: {addr}"))?;
                out.push(AnyHsmBackend::Remote(RemoteHsmBackend::new(
                    (*url).to_string(),
                    a,
                )));
            }
            Ok(out)
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "single sequential pipeline; splitting fights alloy 0.8's deeply nested fillers generic"
)]
async fn run(args: Args) -> Result<()> {
    let intent_queue = Address::from_str(&args.intent_queue)
        .context("INTENT_QUEUE_ADDR must be a 20-byte hex address")?;
    let attestation_oracle = Address::from_str(&args.attestation_oracle)
        .context("ATTESTATION_ORACLE_ADDR must be a 20-byte hex address")?;

    let signers: Vec<AnyHsmBackend> = build_signers(&args)?;
    if signers.len() < args.threshold {
        anyhow::bail!(
            "fewer signer backends ({}) than threshold ({})",
            signers.len(),
            args.threshold
        );
    }

    info!(
        rpc_url = %args.rpc_url,
        intent_queue = %intent_queue,
        attestation_oracle = %attestation_oracle,
        signer_count = signers.len(),
        threshold = args.threshold,
        "xindex-attest starting"
    );

    let ws = WsConnect::new(&args.rpc_url);
    let poster: PrivateKeySigner = args.poster_key.parse().context("invalid POSTER_KEY")?;
    let wallet = EthereumWallet::new(poster);
    let provider = Arc::new(
        ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_ws(ws)
            .await
            .context("connect WS provider")?,
    );

    let chain_id = provider.get_chain_id().await.context("get chain id")?;
    let domain = attestation_oracle_domain(chain_id, attestation_oracle);
    info!(chain_id, "domain initialized");

    // Build the cross-check policy once at startup. `Arc<dyn CrossCheck>`
    // lets the closure share it without per-event allocation. PassThrough
    // is the safe default for local Anvil tests; production MUST switch
    // to ThorBtc which requires partner-network connectivity.
    let cross_check: Arc<dyn CrossCheck> = build_cross_check(&args).context("build cross-check")?;
    info!(mode = ?args.cross_check_mode, "cross-check policy ready");

    let oracle = AttestationOracle::new(attestation_oracle, provider.clone());

    // Inline closure handles each event. Errors are LOGGED, not propagated
    // (M-1 fix) so a single bad event never crashes the daemon. Used by both
    // the backfill loop (M-2 fix) and the live subscription loop below.
    //
    // Takes the originating Ethereum tx hash (from the log metadata) so the
    // cross-check can ask THORChain "have you observed this tx?". For
    // `pass-through` mode the hash is unused but still passed.
    //
    // ## Phase 2.A invariant — exactly ONE async slot per intent
    //
    // `slotExpectedAmounts` is built by `IndexToken._buildAsyncMintLocals`
    // from `_countAsync(isAsyncMem)`, so it contains only the async slots
    // (not all basket slots). In Phase 2.A only BTC.BTC is async, so the
    // array always has length 1 and the single amount is in BTC sats.
    //
    // **Phase 3 hazard**: when ETH.ETH or any second native chain ships,
    // the array will have multiple entries in different units (sats vs
    // wei vs uatom...). The current `ThorBtcPolicy` cross-check is
    // BTC-specific. A naive multi-slot loop would happily attest the
    // wrong slot under the wrong policy. We REJECT multi-slot intents
    // here as a hard guard — Phase 3 must refactor this to per-slot
    // chain-aware cross-check before unfreezing.
    //
    // (M-R1 + M-R2 fix per the 2026-05-09 audit.)
    let process = async |ev: &IntentQueue::MintIntentCreated, eth_tx_hash: B256| {
        let intent_id = ev.intentId;
        info!(
            intent_id = %intent_id,
            slot_count = ev.slotExpectedAmounts.len(),
            "MintIntentCreated observed; signing all slots"
        );
        // Phase 2.A invariant.
        if ev.slotExpectedAmounts.len() != 1 {
            error!(
                intent_id = %intent_id,
                slot_count = ev.slotExpectedAmounts.len(),
                "multi-slot intents require Phase-3 per-slot cross-check; SKIPPING. \
                 This is a hard fail until xindex-attest gets per-slot chain-aware policies."
            );
            return;
        }
        let expected_amount = ev.slotExpectedAmounts[0];
        // Reject overflow rather than silently capping to u64::MAX —
        // u64-overflow is a strong hint we're cross-checking a non-BTC
        // amount with the BTC policy, which would produce false-positive
        // BtcNotReady (since 100 ETH = 1e20 wei > all of Bitcoin's supply
        // in sats).
        let expected_sats: u64 = match expected_amount.try_into() {
            Ok(s) => s,
            Err(e) => {
                error!(
                    intent_id = %intent_id,
                    expected = %expected_amount, error = %e,
                    "expected amount > u64::MAX (Phase-3 non-BTC slot?); SKIPPING"
                );
                return;
            }
        };

        // Cross-check: ask the policy whether the partner-chain settlement
        // actually happened. THORChain identifies the inbound by the
        // originating Ethereum tx hash (no `0x` prefix, lowercase hex).
        let thor_tx_hash = format!("{eth_tx_hash:x}");
        match cross_check.verify(&thor_tx_hash, expected_sats).await {
            Ok(()) => info!(intent_id = %intent_id, "cross-check OK"),
            Err(e) => {
                warn!(intent_id = %intent_id, error = %e,
                      "cross-check FAILED; SKIPPING attestation. The signer will not sign \
                       until partner-chain settlement is observed.");
                return;
            }
        }

        // Single-slot Phase 2.A path: sign and post the one slot.
        let slot_idx: usize = 0;
        let slot_index_u256 = alloy_primitives::U256::from(slot_idx);
        let attestation_payload = attestation(intent_id, slot_index_u256, expected_amount);
        let backends: Vec<&AnyHsmBackend> = signers.iter().take(args.threshold).collect();
        let sigs = match aggregate_signatures(&backends, &domain, &attestation_payload) {
            Ok(s) => s,
            Err(e) => {
                error!(intent_id = %intent_id, slot_index = slot_idx, error = %e,
                       "aggregate failed; skipping slot");
                return;
            }
        };
        let sig_bytes: Vec<Bytes> = sigs.into_iter().map(Bytes::from).collect();
        info!(
            intent_id = %intent_id,
            slot_index = slot_idx,
            attested_amount = %expected_amount,
            signers = backends.len(),
            "posting attest()"
        );
        let pending = match oracle
            .attest(intent_id, slot_index_u256, expected_amount, sig_bytes)
            .send()
            .await
        {
            Ok(p) => p,
            Err(e) => {
                error!(intent_id = %intent_id, slot_index = slot_idx, error = %e,
                       "attest send failed (already attested, oracle paused, or amount=0)");
                return;
            }
        };
        match pending.get_receipt().await {
            Ok(receipt) => info!(
                intent_id = %intent_id,
                slot_index = slot_idx,
                tx_hash = %receipt.transaction_hash,
                gas_used = receipt.gas_used,
                "attest() confirmed"
            ),
            Err(e) => error!(intent_id = %intent_id, slot_index = slot_idx, error = %e,
                              "attest receipt failed"),
        }
    };

    // Replay from a checkpoint if the operator passed one (M-2 fix).
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
            .address(intent_queue)
            .event_signature(IntentQueue::MintIntentCreated::SIGNATURE_HASH)
            .from_block(BlockNumberOrTag::Number(args.from_block))
            .to_block(BlockNumberOrTag::Number(latest));
        let logs = provider
            .get_logs(&backfill_filter)
            .await
            .context("backfill get_logs")?;
        info!(count = logs.len(), "backfill batch");
        for log in logs {
            if let Ok(decoded) = log.log_decode::<IntentQueue::MintIntentCreated>() {
                let tx_hash = decoded.transaction_hash.unwrap_or_default();
                process(&decoded.inner.data, tx_hash).await;
            }
        }
    }

    let filter = Filter::new()
        .address(intent_queue)
        .event_signature(IntentQueue::MintIntentCreated::SIGNATURE_HASH);
    let sub = provider
        .subscribe_logs(&filter)
        .await
        .context("subscribe to MintIntentCreated")?;
    let mut stream = sub.into_stream();

    info!("subscribed; waiting for MintIntentCreated events…");

    while let Some(log) = stream.next().await {
        let Ok(decoded) = log.log_decode::<IntentQueue::MintIntentCreated>() else {
            warn!("failed to decode MintIntentCreated log");
            continue;
        };
        let tx_hash = decoded.transaction_hash.unwrap_or_default();
        process(&decoded.inner.data, tx_hash).await;
    }

    Ok(())
}

/// Builds the configured cross-check policy. `pass-through` is the
/// always-Ok mode for Anvil tests; `thor-btc` is the production mode
/// requiring all four partner-network params.
fn build_cross_check(args: &Args) -> Result<Arc<dyn CrossCheck>> {
    match args.cross_check_mode {
        CrossCheckMode::PassThrough => Ok(Arc::new(PassThroughPolicy)),
        CrossCheckMode::ThorBtc => {
            let thor_url = args
                .thor_url
                .as_deref()
                .context("--thor-url required for thor-btc mode")?;
            let esplora_url = args
                .esplora_url
                .as_deref()
                .context("--esplora-url required for thor-btc mode")?;
            let btc_network_str = args
                .btc_network
                .as_deref()
                .context("--btc-network required for thor-btc mode")?;
            let multisig_str = args
                .btc_multisig_address
                .as_deref()
                .context("--btc-multisig-address required for thor-btc mode")?;

            let network = parse_btc_network(btc_network_str)?;
            let multisig = bitcoin::Address::from_str(multisig_str)
                .context("invalid btc multisig address")?
                .require_network(network)
                .context("multisig address network mismatch")?;
            let thor =
                ThorClient::with_base_url(thor_url.to_string()).context("build ThorClient")?;
            let btc = EsploraClient::with_url(network, esplora_url);
            let policy = ThorBtcPolicy::new(
                thor,
                btc,
                multisig,
                args.btc_min_confirmations,
                args.btc_tolerance_sats,
                network,
            );
            Ok(Arc::new(policy))
        }
    }
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
