//! `xindex-watch` — M1 deliverable.
//!
//! Subscribes to logs emitted by a deployed `IntentQueue` contract and emits
//! one structured `tracing::info!` line per recognized event. Used as the
//! M1 verification gate (see plan §16): with Anvil running and the Phase 2
//! contracts deployed, triggering a `mintAsync` on an `IndexToken` should
//! produce a `MintIntentCreated` JSON line within ~2 seconds.
//!
//! Connection is WebSocket (alloy's `subscribe_logs` requires WS or IPC).
//! Anvil exposes `ws://127.0.0.1:8545` by default.

use std::str::FromStr;

use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use clap::Parser;
use futures_util::StreamExt;
use tracing::info;
use xindex_chain_eth::bindings::IntentQueue;

#[derive(Parser, Debug)]
#[command(version, about = "Xindex IntentQueue event watcher (M1)")]
struct Args {
    /// WebSocket RPC endpoint (Anvil default `ws://127.0.0.1:8545`).
    #[arg(long, env = "ETH_RPC_URL", default_value = "ws://127.0.0.1:8545")]
    rpc_url: String,

    /// Address of the deployed `IntentQueue` contract.
    #[arg(long, env = "INTENT_QUEUE_ADDR")]
    intent_queue: String,
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
    let intent_queue = Address::from_str(&args.intent_queue)
        .context("INTENT_QUEUE_ADDR must be a 20-byte hex address")?;

    info!(
        rpc_url = %args.rpc_url,
        intent_queue = %intent_queue,
        "xindex-watch starting"
    );

    let ws = WsConnect::new(&args.rpc_url);
    let provider = ProviderBuilder::new()
        .on_ws(ws)
        .await
        .context("failed to connect to Ethereum WS endpoint")?;

    let filter = Filter::new().address(intent_queue);
    let sub = provider
        .subscribe_logs(&filter)
        .await
        .context("failed to subscribe to logs")?;
    let mut stream = sub.into_stream();

    info!("subscribed to IntentQueue logs; waiting for events…");

    while let Some(log) = stream.next().await {
        // Match on event signature (topic[0]) so unknown events are skipped
        // cleanly without spamming decode-failure noise.
        let Some(topic0) = log.topic0() else {
            continue;
        };

        if *topic0 == IntentQueue::MintIntentCreated::SIGNATURE_HASH {
            if let Ok(decoded) = log.log_decode::<IntentQueue::MintIntentCreated>() {
                let ev = &decoded.inner.data;
                info!(
                    event = "MintIntentCreated",
                    intent_id = %ev.intentId,
                    index_token = %ev.indexToken,
                    originator = %ev.originator,
                    funding_token = %ev.fundingToken,
                    amount_in = %ev.amountIn,
                    deadline = ev.deadline,
                    "intent created"
                );
            }
        } else if *topic0 == IntentQueue::SlotAttested::SIGNATURE_HASH {
            if let Ok(decoded) = log.log_decode::<IntentQueue::SlotAttested>() {
                let ev = &decoded.inner.data;
                info!(
                    event = "SlotAttested",
                    intent_id = %ev.intentId,
                    slot_index = %ev.slotIndex,
                    attested_amount = %ev.attestedAmount,
                    "slot attested"
                );
            }
        } else if *topic0 == IntentQueue::MintIntentFinalized::SIGNATURE_HASH {
            if let Ok(decoded) = log.log_decode::<IntentQueue::MintIntentFinalized>() {
                let ev = &decoded.inner.data;
                info!(event = "MintIntentFinalized", intent_id = %ev.intentId, "intent finalized");
            }
        } else if *topic0 == IntentQueue::MintIntentCancelled::SIGNATURE_HASH {
            if let Ok(decoded) = log.log_decode::<IntentQueue::MintIntentCancelled>() {
                let ev = &decoded.inner.data;
                info!(event = "MintIntentCancelled", intent_id = %ev.intentId, "intent cancelled");
            }
        }
    }

    Ok(())
}
