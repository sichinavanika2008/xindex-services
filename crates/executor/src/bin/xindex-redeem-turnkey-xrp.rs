//! `xindex-redeem-turnkey-xrp` — single-leg XRP redeem driver under Turnkey
//! enclave custody (`DL-CUSTODY-TURNKEY-1`).
//!
//! The XRP counterpart to `xindex-redeem-turnkey-btc`. Drives one
//! [`TurnkeyXrpRedeemExecutor`] leg: build the single-sign `Payment`, have
//! Turnkey sign the `SHA512Half` hash (gated by the `xindex-turnkey-approver`
//! fleet), assemble the `TxnSignature` tx-blob, and submit. Custody is one
//! Turnkey enclave key (regular single-sign), not the `SignerList` multisign
//! (`xindex-redeem-xrp`).

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

use xindex_chain_xrp::{ReqwestXrpChainClient, XrpChainClient};
use xindex_custody_core::prepare::SqlitePrepareStore;
use xindex_executor::turnkey_xrp_redeem::{TurnkeyXrpRedeemConfig, TurnkeyXrpRedeemExecutor};
use xindex_executor::xrp_redeem::XrpRedeemTask;
use xindex_shared::chain_registry::ChainId;
use xindex_turnkey_client::{TurnkeyClient, TurnkeyStamper, TURNKEY_API_BASE};

/// Drive one Turnkey-backed XRP redeem leg. The Turnkey API P-256 key is read
/// from `XINDEX_TURNKEY_API_KEY` (hex) — never an argv flag.
#[derive(Debug, Parser)]
#[command(name = "xindex-redeem-turnkey-xrp", version)]
struct Args {
    /// Required rehearsal mode. This binary reads a software P-256 Turnkey
    /// API stamping key, so it is not part of the production profile.
    #[arg(long, env = "XINDEX_DEV", default_value_t = false)]
    dev: bool,

    /// XRP custody chain.
    #[arg(long, default_value = "xrp")]
    chain: String,
    /// The compressed (33-byte) secp256k1 custody public key, hex.
    #[arg(long)]
    custody_pubkey: String,
    /// The classic r-address of the single-key custody account.
    #[arg(long)]
    account_address: String,
    /// The Turnkey `signWith` selector for the custody key.
    #[arg(long)]
    sign_with: String,
    /// The Turnkey custody sub-organization id.
    #[arg(long)]
    organization_id: String,
    /// Current `THORChain` XRP Asgard inbound (classic r-address).
    #[arg(long)]
    vault: String,
    /// Fee in drops.
    #[arg(long, default_value_t = 15)]
    fee_drops: u128,
    /// Ledgers added to the current index for `LastLedgerSequence`.
    #[arg(long, default_value_t = 75)]
    last_ledger_window: u32,
    /// XRPL JSON-RPC URL (account / ledger / submit).
    #[arg(long)]
    rpc_url: String,
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
    /// `THORChain` swap memo carried in `Memos[0].MemoData`.
    #[arg(long)]
    memo: String,
    /// Native send amount in drops (decimal).
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

fn parse_pubkey33(hex: &str) -> Result<[u8; 33]> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = alloy_primitives::hex::decode(stripped).context("--custody-pubkey: bad hex")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("--custody-pubkey: expected 33-byte compressed key"))
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
    let custody_pubkey = parse_pubkey33(&args.custody_pubkey)?;
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
    let chain_client =
        ReqwestXrpChainClient::new(chain, &args.rpc_url).map_err(|e| anyhow!("xrp client: {e}"))?;

    let config = TurnkeyXrpRedeemConfig {
        chain,
        account_address: args.account_address.clone(),
        custody_pubkey,
        sign_with: args.sign_with,
        fee_drops: args.fee_drops,
        poll_interval: Duration::from_secs(args.poll_interval_secs),
        poll_max_attempts: args.poll_max_attempts,
    };
    let executor = TurnkeyXrpRedeemExecutor::new(config, turnkey, prepare);

    let account = chain_client
        .account_info(&args.account_address)
        .await
        .map_err(|e| anyhow!("account_info: {e}"))?;
    let current = chain_client
        .ledger_current()
        .await
        .map_err(|e| anyhow!("ledger_current: {e}"))?;
    let last_ledger_sequence =
        u32::try_from(current.saturating_add(u64::from(args.last_ledger_window)))
            .map_err(|_| anyhow!("LastLedgerSequence > u32"))?;

    let task = XrpRedeemTask {
        dispatch_id,
        redemption_id,
        chain,
        memo: args.memo,
        send_amount: args.amount,
        intent_proof: None,
    };
    info!(?chain, vault = %args.vault, sequence = account.sequence, last_ledger_sequence, "turnkey xrp execute_leg start");
    let outcome = executor
        .execute_leg(&task, &args.vault, account.sequence, last_ledger_sequence)
        .await
        .map_err(|e| anyhow!("execute_leg: {e}"))?;

    let submit = chain_client
        .submit_tx_blob(&outcome.tx_blob)
        .await
        .map_err(|e| anyhow!("submit: {e}"))?;
    info!(engine_result = %submit.engine_result, txhash = %submit.txhash, activity = %outcome.activity_id, "turnkey xrp leg submitted");
    println!("txhash: {} ({})", submit.txhash, submit.engine_result);
    println!("activity_id: {}", outcome.activity_id);
    Ok(())
}
