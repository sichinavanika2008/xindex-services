//! `xindex-redeem-turnkey-cosmos` — single-leg Cosmos redeem driver under
//! Turnkey enclave custody (`DL-CUSTODY-TURNKEY-1`).
//!
//! The Cosmos counterpart to `xindex-redeem-turnkey-btc`. Drives one
//! [`TurnkeyCosmosRedeemExecutor`] leg: build the `MsgSend` amino sign-bytes,
//! have Turnkey sign them (gated by the `xindex-turnkey-approver` fleet),
//! assemble the single-sig `TxRaw`, and broadcast. Custody is one Turnkey
//! enclave key (single-sig account), not the 3-of-5 `LegacyAminoPubKey`
//! multisig (`xindex-redeem-cosmos`).
//!
//! v1 scope: a skeleton single-leg drive (the long-running event loop is the
//! daemon's job). All chain I/O is async reqwest (no blocking client).

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

use xindex_chain_cosmos::{CosmosChainClient, ReqwestCosmosChainClient};
use xindex_custody_core::prepare::SqlitePrepareStore;
use xindex_executor::cosmos_redeem::CosmosRedeemTask;
use xindex_executor::turnkey_cosmos_redeem::{
    TurnkeyCosmosRedeemConfig, TurnkeyCosmosRedeemExecutor,
};
use xindex_shared::chain_registry::ChainId;
use xindex_turnkey_client::{TurnkeyClient, TurnkeyStamper, TURNKEY_API_BASE};

/// Drive one Turnkey-backed Cosmos redeem leg. The Turnkey API P-256 key is
/// read from `XINDEX_TURNKEY_API_KEY` (hex) — never an argv flag.
#[derive(Debug, Parser)]
#[command(name = "xindex-redeem-turnkey-cosmos", version)]
struct Args {
    /// Cosmos custody chain (`gaia` first).
    #[arg(long, default_value = "gaia")]
    chain: String,
    /// The compressed (33-byte) secp256k1 custody public key, hex.
    #[arg(long)]
    custody_pubkey: String,
    /// The bech32 single-key custody account address (`MsgSend.from_address`).
    #[arg(long)]
    account_address: String,
    /// The Turnkey `signWith` selector for the custody key.
    #[arg(long)]
    sign_with: String,
    /// The Turnkey custody sub-organization id.
    #[arg(long)]
    organization_id: String,
    /// Current `THORChain` Cosmos Asgard inbound (bech32). Refreshed from
    /// `inbound_addresses` before each run.
    #[arg(long)]
    vault: String,
    /// Consensus chain-id bound into the sign-bytes (`"cosmoshub-4"`).
    #[arg(long)]
    cosmos_chain_id: String,
    /// Native micro-denom (`"uatom"`).
    #[arg(long, default_value = "uatom")]
    denom: String,
    /// Fee amount in the micro-unit.
    #[arg(long)]
    fee_amount: u128,
    /// Gas limit.
    #[arg(long, default_value_t = 200_000)]
    gas_limit: u64,
    /// Tendermint RPC base URL (broadcast).
    #[arg(long)]
    rpc_url: String,
    /// Cosmos REST base URL (account / sequence).
    #[arg(long)]
    rest_url: String,
    /// Shared sqlite URL for the bind-prepare store (the approver reads it).
    #[arg(long)]
    db: String,
    /// Turnkey API host (defaults to production; the dev-env is a sub-org).
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
    /// `THORChain` swap memo carried in the tx `memo`.
    #[arg(long)]
    memo: String,
    /// Native send amount in the micro-unit (decimal).
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
    let chain_client = ReqwestCosmosChainClient::new(
        chain,
        args.cosmos_chain_id.clone(),
        &args.rpc_url,
        &args.rest_url,
    )
    .map_err(|e| anyhow!("cosmos client: {e}"))?;

    let config = TurnkeyCosmosRedeemConfig {
        chain,
        account_address: args.account_address.clone(),
        custody_pubkey,
        sign_with: args.sign_with,
        cosmos_chain_id: args.cosmos_chain_id,
        denom: args.denom,
        fee_amount: args.fee_amount,
        gas_limit: args.gas_limit,
        poll_interval: Duration::from_secs(args.poll_interval_secs),
        poll_max_attempts: args.poll_max_attempts,
    };
    let executor = TurnkeyCosmosRedeemExecutor::new(config, turnkey, prepare);

    let account = chain_client
        .account(&args.account_address)
        .await
        .map_err(|e| anyhow!("fetch account: {e}"))?;
    let task = CosmosRedeemTask {
        dispatch_id,
        redemption_id,
        chain,
        memo: args.memo,
        send_amount: args.amount,
        intent_proof: None,
    };
    info!(?chain, vault = %args.vault, sequence = account.sequence, "turnkey cosmos execute_leg start");
    let outcome = executor
        .execute_leg(&task, &args.vault, account.account_number, account.sequence)
        .await
        .map_err(|e| anyhow!("execute_leg: {e}"))?;

    let bcast = chain_client
        .broadcast_tx_sync(&outcome.tx_raw)
        .await
        .map_err(|e| anyhow!("broadcast: {e}"))?;
    info!(txhash = %bcast.txhash, code = bcast.code, activity = %outcome.activity_id, "turnkey cosmos leg broadcast");
    println!("txhash: {} (code {})", bcast.txhash, bcast.code);
    println!("activity_id: {}", outcome.activity_id);
    Ok(())
}
