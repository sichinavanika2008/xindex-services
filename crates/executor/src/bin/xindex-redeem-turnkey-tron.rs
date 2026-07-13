//! `xindex-redeem-turnkey-tron` — single-leg TRON redeem driver under Turnkey
//! enclave custody (`DL-CUSTODY-TURNKEY-1`).
//!
//! The TRON counterpart to `xindex-redeem-turnkey-btc`. Drives one
//! [`TurnkeyTronRedeemExecutor`] leg: build the `raw_data`, have Turnkey sign
//! the `txID` (gated by the `xindex-turnkey-approver` fleet), assemble the
//! 65-byte recoverable signature + signed `Transaction`, and broadcast. Custody
//! is one Turnkey enclave key on the `Owner` permission, not the
//! account-permission k-of-n multisig (`xindex-redeem-tron`).

#![expect(
    clippy::print_stdout,
    reason = "CLI binary — println is the operator interface"
)]

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::B256;
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::info;

use xindex_chain_tron::{ReqwestTronChainClient, TronChainClient};
use xindex_custody_core::prepare::SqlitePrepareStore;
use xindex_executor::tron_redeem::TronRedeemTask;
use xindex_executor::turnkey_tron_redeem::{TurnkeyTronRedeemConfig, TurnkeyTronRedeemExecutor};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::TronAssetKind;
use xindex_turnkey_client::{TurnkeyClient, TurnkeyStamper, TURNKEY_API_BASE};

/// Drive one Turnkey-backed TRON redeem leg. The Turnkey API P-256 key is read
/// from `XINDEX_TURNKEY_API_KEY` (hex) — never an argv flag.
#[derive(Debug, Parser)]
#[command(name = "xindex-redeem-turnkey-tron", version)]
struct Args {
    /// Required rehearsal mode. This binary reads a software P-256 Turnkey
    /// API stamping key, so it is not part of the production profile.
    #[arg(long, env = "XINDEX_DEV", default_value_t = false)]
    dev: bool,

    /// TRON custody chain.
    #[arg(long, default_value = "tron")]
    chain: String,
    /// The Turnkey `signWith` selector for the custody key.
    #[arg(long)]
    sign_with: String,
    /// The base58check `T…` custody account address (`owner_address`).
    #[arg(long)]
    owner_address: String,
    /// The Turnkey custody sub-organization id.
    #[arg(long)]
    organization_id: String,
    /// Current `THORChain` TRON Asgard inbound (`T…`).
    #[arg(long)]
    vault: String,
    /// Asset to move: `trx` or `usdt`.
    #[arg(long, default_value = "trx")]
    asset: String,
    /// `usdt` only: the TRC20 contract address (`T…`).
    #[arg(long)]
    contract_address: Option<String>,
    /// `usdt` only: the `fee_limit` (energy cap) in `sun`.
    #[arg(long, default_value_t = 0)]
    fee_limit: u64,
    /// Milliseconds added to the block timestamp for `expiration`.
    #[arg(long, default_value_t = 1_200_000)]
    expiration_window_ms: u64,
    /// `Contract.Permission_id` (0 = Owner permission for a single key).
    #[arg(long, default_value_t = 0)]
    permission_id: u32,
    /// TRON full-node HTTP base URL (now-block / broadcast).
    #[arg(long)]
    node_url: String,
    /// Shared sqlite URL for the bind-prepare store (the approver reads it).
    #[arg(long)]
    db: String,
    /// Turnkey API host.
    #[arg(long, default_value_t = TURNKEY_API_BASE.to_string())]
    turnkey_host: String,
    /// Seconds between Turnkey activity-status polls.
    #[arg(long, default_value_t = 5)]
    poll_interval_secs: u64,
    /// Max status polls before timing out.
    #[arg(long, default_value_t = 60)]
    poll_max_attempts: u32,
    /// Originating dispatch id (32-byte hex).
    #[arg(
        long,
        default_value = "0x0000000000000000000000000000000000000000000000000000000000000000"
    )]
    dispatch_id: String,
    /// Originating redemption id (32-byte hex).
    #[arg(
        long,
        default_value = "0x0000000000000000000000000000000000000000000000000000000000000000"
    )]
    redemption_id: String,
    /// `THORChain` swap memo carried in `raw_data.data`.
    #[arg(long)]
    memo: String,
    /// Native send amount in the asset's smallest unit (decimal).
    #[arg(long)]
    amount: u128,
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

fn parse_asset(s: &str) -> Result<TronAssetKind> {
    match s {
        "trx" | "TRX" => Ok(TronAssetKind::Trx),
        "usdt" | "USDT" => Ok(TronAssetKind::Usdt),
        other => Err(anyhow!("--asset {other:?} must be trx or usdt")),
    }
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
    if !args.dev {
        anyhow::bail!(
            "refusing production startup: the standalone Turnkey driver reads a software API stamping key; pass --dev only for an authorized rehearsal"
        );
    }
    let chain: ChainId = args
        .chain
        .parse()
        .with_context(|| format!("--chain {:?} is not a known chain", args.chain))?;
    let asset = parse_asset(&args.asset)?;
    let dispatch_id = parse_b256("--dispatch-id", &args.dispatch_id)?;
    let redemption_id = parse_b256("--redemption-id", &args.redemption_id)?;

    let api_key = std::env::var("XINDEX_TURNKEY_API_KEY")
        .context("XINDEX_TURNKEY_API_KEY (hex P-256 private key) must be set")?;
    let stamper = TurnkeyStamper::from_hex(&api_key).map_err(|e| anyhow!("turnkey key: {e}"))?;
    let turnkey = Arc::new(
        TurnkeyClient::new(&args.turnkey_host, &args.organization_id, stamper)
            .map_err(|e| anyhow!("turnkey client: {e}"))?,
    );
    let prepare = Arc::new(
        SqlitePrepareStore::connect(&args.db)
            .await
            .map_err(|e| anyhow!("prepare store {}: {e}", args.db))?,
    );
    let chain_client = ReqwestTronChainClient::new(chain, &args.node_url)
        .map_err(|e| anyhow!("tron client: {e}"))?;

    let config = TurnkeyTronRedeemConfig {
        chain,
        sign_with: args.sign_with,
        owner_address: args.owner_address,
        asset,
        contract_address: args.contract_address,
        fee_limit: args.fee_limit,
        expiration_window_ms: args.expiration_window_ms,
        permission_id: args.permission_id,
        poll_interval: Duration::from_secs(args.poll_interval_secs),
        poll_max_attempts: args.poll_max_attempts,
    };
    let executor = TurnkeyTronRedeemExecutor::new(config, turnkey, prepare)
        .map_err(|e| anyhow!("executor: {e}"))?;

    let block = chain_client
        .now_block()
        .await
        .map_err(|e| anyhow!("now_block: {e}"))?;
    let task = TronRedeemTask {
        dispatch_id,
        redemption_id,
        chain,
        memo: args.memo,
        send_amount: args.amount,
        intent_proof: None,
    };
    info!(?chain, vault = %args.vault, "turnkey tron execute_leg start");
    let outcome = executor
        .execute_leg(&task, &args.vault, &block)
        .await
        .map_err(|e| anyhow!("execute_leg: {e}"))?;

    let bcast = chain_client
        .broadcast_hex(&outcome.tx_hex)
        .await
        .map_err(|e| anyhow!("broadcast: {e}"))?;
    info!(result = bcast.result, code = %bcast.code, txid = %outcome.txid, activity = %outcome.activity_id, "turnkey tron leg broadcast");
    println!(
        "txid: {} (result {} {})",
        outcome.txid, bcast.result, bcast.code
    );
    println!("activity_id: {}", outcome.activity_id);
    Ok(())
}
