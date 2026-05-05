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

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use clap::Parser;
use futures_util::StreamExt;
use tracing::{info, warn};
use xindex_chain_eth::bindings::{AttestationOracle, IntentQueue};
use xindex_shared::eip712::{attestation, attestation_oracle_domain};
use xindex_signer::{aggregate_signatures, SoftwareSigner};

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

    /// Comma-separated hex private keys of the signers (in any order;
    /// must match `_isSigner[...]` registrations on the oracle). For
    /// Anvil testing, use the deterministic accounts 1..n. The first
    /// `threshold` keys are used per attestation.
    #[arg(long, env = "SIGNER_KEYS")]
    signer_keys: String,

    /// k-of-n threshold to post per attestation. MUST match the on-chain
    /// `_threshold` of the deployed oracle.
    #[arg(long, env = "THRESHOLD")]
    threshold: usize,

    /// Hex private key of the EOA that submits the `attest` transaction.
    /// Pays gas. Anvil deterministic account 0 is the conventional choice.
    #[arg(long, env = "POSTER_KEY")]
    poster_key: String,
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

async fn run(args: Args) -> Result<()> {
    let intent_queue = Address::from_str(&args.intent_queue)
        .context("INTENT_QUEUE_ADDR must be a 20-byte hex address")?;
    let attestation_oracle = Address::from_str(&args.attestation_oracle)
        .context("ATTESTATION_ORACLE_ADDR must be a 20-byte hex address")?;

    let signers: Vec<SoftwareSigner> = args
        .signer_keys
        .split(',')
        .map(|k| {
            SoftwareSigner::from_hex(k.trim())
                .with_context(|| format!("invalid SIGNER_KEYS entry: {k}"))
        })
        .collect::<Result<_>>()?;
    if signers.len() < args.threshold {
        anyhow::bail!(
            "fewer signer keys ({}) than threshold ({})",
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

    let oracle = AttestationOracle::new(attestation_oracle, provider.clone());
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
        let ev = &decoded.inner.data;
        let intent_id = ev.intentId;
        info!(
            intent_id = %intent_id,
            slot_count = ev.slotExpectedAmounts.len(),
            "MintIntentCreated observed; signing all slots"
        );

        // Sign and post one attestation per slot. The off-chain validity
        // check that confirms the corresponding native deposit landed at
        // our multisig is M3 — for M2 we use `slotExpectedAmounts[i]`
        // verbatim as `attestedAmount`, simulating a perfect off-chain
        // observation.
        for (slot_idx, expected) in ev.slotExpectedAmounts.iter().enumerate() {
            let slot_index_u256 = alloy_primitives::U256::from(slot_idx);
            let attestation_payload = attestation(intent_id, slot_index_u256, *expected);

            let backends: Vec<&SoftwareSigner> = signers.iter().take(args.threshold).collect();
            let sigs = aggregate_signatures(&backends, &domain, &attestation_payload)
                .context("aggregate signatures")?;
            let sig_bytes: Vec<Bytes> = sigs.into_iter().map(Bytes::from).collect();

            info!(
                intent_id = %intent_id,
                slot_index = slot_idx,
                attested_amount = %expected,
                signers = backends.len(),
                "posting attest()"
            );

            let pending = oracle
                .attest(intent_id, slot_index_u256, *expected, sig_bytes)
                .send()
                .await
                .context("send attest")?;
            let receipt = pending.get_receipt().await.context("attest receipt")?;
            info!(
                intent_id = %intent_id,
                slot_index = slot_idx,
                tx_hash = %receipt.transaction_hash,
                gas_used = receipt.gas_used,
                "attest() confirmed"
            );
        }
    }

    Ok(())
}
