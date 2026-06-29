//! `xindex-redeem-turnkey-btc` — single-leg BTC redeem driver under Turnkey
//! enclave custody (`DL-CUSTODY-TURNKEY-1`).
//!
//! The BTC counterpart to `xindex-redeem-evm`'s `turnkey` subcommand. Drives
//! one [`TurnkeyBtcRedeemExecutor`] leg: build the P2WPKH spend, have Turnkey
//! sign the sighash (gated by the `xindex-turnkey-approver` fleet), assemble
//! the witness, and broadcast. Unlike the 3-of-5 multisig daemon
//! (`xindex-redeem`), custody here is one Turnkey enclave key (P2WPKH).
//!
//! ## v1 scope
//!
//! A **skeleton** that drives a single leg via the CLI — the long-running
//! event-driven loop (`RedeemDispatched` → build → sign → broadcast → confirm
//! → record) is the daemon's job. Operators drive single legs here for
//! rehearsal / the dev-env reconcile in the meantime.
//!
//! ## async / blocking boundary
//!
//! `execute_leg` is async (Turnkey HTTP). The Esplora client is
//! `reqwest::blocking`, so its construction + UTXO fetch + broadcast run on
//! `spawn_blocking` threads, AROUND the async sign — never inside it.

#![expect(
    clippy::print_stdout,
    reason = "CLI binary — println is the operator interface"
)]

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{Address as EvmAddress, B256, U256};
use anyhow::{anyhow, Context, Result};
use bitcoin::{Address, CompressedPublicKey, Network};
use clap::Parser;
use tracing::info;

use xindex_chain_utxo::{EsploraClient, UtxoChainClient, UtxoParams};
use xindex_custody_core::prepare::SqlitePrepareStore;
use xindex_executor::turnkey_btc_redeem::{TurnkeyBtcRedeemConfig, TurnkeyBtcRedeemExecutor};
use xindex_executor::RedeemTask;
use xindex_shared::chain_registry::ChainId;
use xindex_turnkey_client::{TurnkeyClient, TurnkeyStamper, TURNKEY_API_BASE};

/// Drive one Turnkey-backed BTC redeem leg. The Turnkey API P-256 private key
/// is read from `XINDEX_TURNKEY_API_KEY` (hex) — never an argv flag.
#[derive(Debug, Parser)]
#[command(name = "xindex-redeem-turnkey-btc", version)]
struct Args {
    /// UTXO chain (`btc` first; same shape for `ltc`).
    #[arg(long, default_value = "btc")]
    chain: String,

    /// Bitcoin network (`bitcoin` / `signet` / `testnet` / `regtest`). Must
    /// match `--esplora-url`.
    #[arg(long, default_value = "signet")]
    btc_network: String,

    /// The compressed (33-byte) secp256k1 custody public key, hex. The P2WPKH
    /// custody address is derived from it.
    #[arg(long)]
    custody_pubkey: String,

    /// The Turnkey `signWith` selector (private-key id / wallet-account
    /// address) for the custody key.
    #[arg(long)]
    sign_with: String,

    /// The Turnkey custody sub-organization id.
    #[arg(long)]
    organization_id: String,

    /// Current `THORChain` BTC Asgard inbound vault address. Operator refreshes
    /// from `inbound_addresses` before each run.
    #[arg(long)]
    vault: String,

    /// Esplora HTTP base URL (UTXO fetch + broadcast). Must match
    /// `--btc-network`.
    #[arg(long)]
    esplora_url: String,

    /// Shared sqlite URL for the bind-prepare store (the
    /// `xindex-turnkey-approver` process reads the same DB to gate signing).
    #[arg(long)]
    db: String,

    /// Turnkey API host. Defaults to production; the dev-env is a sub-org on
    /// the same host.
    #[arg(long, default_value_t = TURNKEY_API_BASE.to_string())]
    turnkey_host: String,

    /// Flat fee budget (sats) for the single-input spend.
    #[arg(long, default_value_t = 5_000)]
    fee_sats: u64,

    /// Seconds between Turnkey activity-status polls.
    #[arg(long, default_value_t = 5)]
    poll_interval_secs: u64,

    /// Max status polls before timing out.
    #[arg(long, default_value_t = 60)]
    poll_max_attempts: u32,

    /// Originating dispatch id (32-byte hex). Defaults to zero for a manual
    /// drive; pass a distinct id per re-drive.
    #[arg(
        long,
        default_value = "0x0000000000000000000000000000000000000000000000000000000000000000"
    )]
    dispatch_id: String,

    /// Originating redemption id (32-byte hex) for attestation correlation.
    #[arg(
        long,
        default_value = "0x0000000000000000000000000000000000000000000000000000000000000000"
    )]
    redemption_id: String,

    /// `THORChain` swap memo carried in the `OP_RETURN`
    /// (`=:ETH.USDT:<recipient>:<minOut>`).
    #[arg(long)]
    memo: String,

    /// BTC amount to send to Asgard, in 8-decimal native sats.
    #[arg(long)]
    amount_sats: String,
}

fn parse_network(s: &str) -> Result<Network> {
    match s {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "signet" => Ok(Network::Signet),
        "testnet" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        other => Err(anyhow!("unknown btc_network: {other}")),
    }
}

fn parse_compressed_pubkey(hex: &str) -> Result<CompressedPublicKey> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = alloy_primitives::hex::decode(stripped).context("--custody-pubkey: bad hex")?;
    CompressedPublicKey::from_slice(&bytes)
        .map_err(|e| anyhow!("--custody-pubkey: not a valid 33-byte compressed key: {e}"))
}

fn parse_b256(field: &str, hex: &str) -> Result<B256> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes =
        alloy_primitives::hex::decode(stripped).with_context(|| format!("{field}: bad hex"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{field}: expected 32-byte hash"))?;
    Ok(B256::from(arr))
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
    let chain: ChainId = args
        .chain
        .parse()
        .with_context(|| format!("--chain {:?} is not a known UTXO chain", args.chain))?;
    let network = parse_network(&args.btc_network)?;
    let custody_pubkey = parse_compressed_pubkey(&args.custody_pubkey)?;
    let custody_address = Address::p2wpkh(&custody_pubkey, network);
    let vault = Address::from_str(&args.vault)
        .context("--vault: invalid BTC address")?
        .require_network(network)
        .context("--vault: address is for a different network")?;
    let dispatch_id = parse_b256("--dispatch-id", &args.dispatch_id)?;
    let redemption_id = parse_b256("--redemption-id", &args.redemption_id)?;
    let amount =
        U256::from_str_radix(&args.amount_sats, 10).context("--amount-sats: bad decimal")?;

    // The Turnkey API P-256 key stays out of argv — read it from the env.
    let api_key = std::env::var("XINDEX_TURNKEY_API_KEY")
        .context("XINDEX_TURNKEY_API_KEY (hex P-256 private key) must be set")?;
    let stamper = TurnkeyStamper::from_hex(&api_key).map_err(|e| anyhow!("turnkey key: {e}"))?;
    let turnkey = Arc::new(
        TurnkeyClient::new(&args.turnkey_host, &args.organization_id, stamper)
            .map_err(|e| anyhow!("turnkey client: {e}"))?,
    );

    // Shared bind-prepare store: keyed by the signing sighash; the approver
    // process `get`s the same DB file to gate the signature.
    let prepare = Arc::new(
        SqlitePrepareStore::connect(&args.db)
            .await
            .map_err(|e| anyhow!("prepare store {}: {e}", args.db))?,
    );

    let config = TurnkeyBtcRedeemConfig {
        chain,
        custody_address: custody_address.clone(),
        custody_pubkey,
        sign_with: args.sign_with,
        fee_sats: args.fee_sats,
        poll_interval: Duration::from_secs(args.poll_interval_secs),
        poll_max_attempts: args.poll_max_attempts,
    };
    let executor = TurnkeyBtcRedeemExecutor::new(config, turnkey, prepare);

    // EsploraClient is reqwest::blocking — construct it on a blocking thread
    // (its builder spawns + drops a temporary runtime, which panics on a
    // runtime worker thread).
    let esplora_url = args.esplora_url.clone();
    let chain_client = Arc::new(
        tokio::task::spawn_blocking(move || {
            EsploraClient::for_chain(UtxoParams::for_chain(chain), network, &esplora_url)
        })
        .await
        .context("construct Esplora client")?,
    );

    // Fetch the custody UTXO set on a blocking thread, then run the async sign
    // off it, then broadcast on a blocking thread.
    let fetch_chain = Arc::clone(&chain_client);
    let fetch_addr = custody_address.clone();
    let utxos = tokio::task::spawn_blocking(move || fetch_chain.get_address_utxos(&fetch_addr))
        .await
        .context("fetch utxos task")?
        .context("get_address_utxos")?;

    let task = RedeemTask {
        dispatch_id,
        redemption_id,
        target_token: EvmAddress::ZERO,
        amount,
        memo: args.memo.into_bytes(),
        // CTD-1: the RIC is supplied by the observer/relay (Slice B); None
        // fail-closes at the approver (decide_redeem_spend is cert-gated).
        intent_proof: None,
    };
    info!(?chain, custody_address = %custody_address, vault = %vault, %amount,
        "turnkey BTC redeem execute_leg start");
    let outcome = executor
        .execute_leg(&task, &vault, &utxos)
        .await
        .map_err(|e| anyhow!("execute_leg: {e}"))?;

    // Broadcast the assembled signed tx on a blocking thread.
    let bcast_chain = Arc::clone(&chain_client);
    let signed_tx = outcome.signed_tx.clone();
    let txid = tokio::task::spawn_blocking(move || bcast_chain.broadcast(&signed_tx))
        .await
        .context("broadcast task")?
        .context("broadcast")?;

    info!(%txid, activity = %outcome.activity_id, "turnkey BTC redeem leg broadcast");
    println!("txid: {txid}");
    println!("activity_id: {}", outcome.activity_id);
    Ok(())
}
