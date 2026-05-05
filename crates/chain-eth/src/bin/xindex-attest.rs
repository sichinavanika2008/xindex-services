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
use alloy::primitives::{Address, Bytes};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use clap::Parser;
use futures_util::StreamExt;
use tracing::{error, info, warn};
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

#[expect(
    clippy::too_many_lines,
    reason = "single sequential pipeline; the inline closure handles per-event work and splitting it into helpers fights alloy 0.8's deeply nested fillers generic type"
)]
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

    // Inline closure handles each event. Errors are LOGGED, not propagated
    // (M-1 fix) so a single bad event never crashes the daemon. Used by both
    // the backfill loop (M-2 fix) and the live subscription loop below.
    let process = async |ev: &IntentQueue::MintIntentCreated| {
        let intent_id = ev.intentId;
        info!(
            intent_id = %intent_id,
            slot_count = ev.slotExpectedAmounts.len(),
            "MintIntentCreated observed; signing all slots"
        );
        for (slot_idx, expected) in ev.slotExpectedAmounts.iter().enumerate() {
            let slot_index_u256 = alloy_primitives::U256::from(slot_idx);
            let attestation_payload = attestation(intent_id, slot_index_u256, *expected);
            let backends: Vec<&SoftwareSigner> = signers.iter().take(args.threshold).collect();
            let sigs = match aggregate_signatures(&backends, &domain, &attestation_payload) {
                Ok(s) => s,
                Err(e) => {
                    error!(intent_id = %intent_id, slot_index = slot_idx, error = %e,
                           "aggregate failed; skipping slot");
                    continue;
                }
            };
            let sig_bytes: Vec<Bytes> = sigs.into_iter().map(Bytes::from).collect();
            info!(
                intent_id = %intent_id,
                slot_index = slot_idx,
                attested_amount = %expected,
                signers = backends.len(),
                "posting attest()"
            );
            let pending = match oracle
                .attest(intent_id, slot_index_u256, *expected, sig_bytes)
                .send()
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    error!(intent_id = %intent_id, slot_index = slot_idx, error = %e,
                           "attest send failed; skipping slot (already attested, oracle paused, or amount=0)");
                    continue;
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
                process(&decoded.inner.data).await;
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
        process(&decoded.inner.data).await;
    }

    Ok(())
}
