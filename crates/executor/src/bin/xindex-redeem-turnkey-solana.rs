//! `xindex-redeem-turnkey-solana` — single-leg Solana redeem driver under
//! Turnkey enclave custody (`DL-CUSTODY-TURNKEY-1`).
//!
//! The Solana counterpart to `xindex-redeem-turnkey-btc`. Drives one
//! [`TurnkeySolanaRedeemExecutor`] leg: build the `transfer + memo` legacy
//! message, have Turnkey sign the message bytes with the ed25519 custody key
//! (gated by the `xindex-turnkey-approver` fleet), assemble the signed
//! transaction, and submit. Custody is one Turnkey ed25519 key, not the Squads
//! V4 program multisig (`xindex-redeem-solana`).
//!
//! Solana is NOT in mainnet v1 scope (`KNOWN_FINDINGS` P-SOL-7) — this drives
//! devnet rehearsal of the single-key path.

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

use xindex_chain_solana::{ReqwestSolanaChainClient, SolanaChainClient};
use xindex_custody_core::prepare::SqlitePrepareStore;
use xindex_executor::turnkey_solana_redeem::{
    TurnkeySolanaRedeemConfig, TurnkeySolanaRedeemExecutor, TurnkeySolanaRedeemTask,
};
use xindex_shared::chain_registry::ChainId;
use xindex_solana_tx::Pubkey;
use xindex_turnkey_client::{TurnkeyClient, TurnkeyStamper, TURNKEY_API_BASE};

/// Drive one Turnkey-backed Solana redeem leg. The Turnkey API P-256 key is
/// read from `XINDEX_TURNKEY_API_KEY` (hex) — never an argv flag.
#[derive(Debug, Parser)]
#[command(name = "xindex-redeem-turnkey-solana", version)]
struct Args {
    /// Solana custody chain.
    #[arg(long, default_value = "sol")]
    chain: String,
    /// The ed25519 custody public key (base58 — the Solana address).
    #[arg(long)]
    custody_pubkey: String,
    /// The Turnkey `signWith` selector for the custody key.
    #[arg(long)]
    sign_with: String,
    /// The Turnkey custody sub-organization id.
    #[arg(long)]
    organization_id: String,
    /// Current `THORChain` Solana Asgard inbound (base58 pubkey).
    #[arg(long)]
    vault: String,
    /// Solana JSON-RPC URL (blockhash / submit).
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
    /// `THORChain` swap memo carried in the SPL-Memo instruction.
    #[arg(long)]
    memo: String,
    /// Native send amount in lamports (decimal).
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
    let custody_pubkey = Pubkey::from_base58(&args.custody_pubkey)
        .map_err(|e| anyhow!("--custody-pubkey: {e}"))?
        .to_bytes();
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
    let chain_client = ReqwestSolanaChainClient::new(chain, &args.rpc_url)
        .map_err(|e| anyhow!("solana client: {e}"))?;

    let config = TurnkeySolanaRedeemConfig {
        chain,
        custody_pubkey,
        sign_with: args.sign_with,
        poll_interval: Duration::from_secs(args.poll_interval_secs),
        poll_max_attempts: args.poll_max_attempts,
    };
    let executor = TurnkeySolanaRedeemExecutor::new(config, turnkey, prepare);

    let recent_blockhash = chain_client
        .recent_blockhash()
        .await
        .map_err(|e| anyhow!("recent_blockhash: {e}"))?;
    let task = TurnkeySolanaRedeemTask {
        dispatch_id,
        redemption_id,
        chain,
        memo: args.memo,
        send_amount: args.amount,
        intent_proof: None,
    };
    info!(?chain, vault = %args.vault, "turnkey solana execute_leg start");
    let outcome = executor
        .execute_leg(&task, &args.vault, recent_blockhash)
        .await
        .map_err(|e| anyhow!("execute_leg: {e}"))?;

    let signature = chain_client
        .send_transaction(&outcome.signed_tx)
        .await
        .map_err(|e| anyhow!("send_transaction: {e}"))?;
    info!(%signature, activity = %outcome.activity_id, "turnkey solana leg submitted");
    println!("signature: {signature}");
    println!("activity_id: {}", outcome.activity_id);
    Ok(())
}
