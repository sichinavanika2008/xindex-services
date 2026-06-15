//! Response types pinned to the `THORNode` `OpenAPI` spec.
//!
//! Only the fields the off-chain stack actually reads are deserialized.
//! `serde(default)` lets us tolerate missing or new optional fields
//! without breaking on every upstream schema change.

use serde::{Deserialize, Serialize};

/// One entry in the response of `GET /thorchain/inbound_addresses`.
///
/// One row per supported chain. The vault `address` rotates per
/// `THORChain` churn cycle; the off-chain bot polls this and pushes any
/// change to the on-chain `ThorchainVaultRegistry`. Halt flags exist
/// per chain so the protocol can detect upstream incidents.
#[expect(
    clippy::struct_excessive_bools,
    reason = "shape mirrors the THORNode OpenAPI response — 4 halt flags upstream"
)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboundAddress {
    pub chain: String,
    pub pub_key: String,
    pub address: String,
    /// Numeric router address (only present for chains with a smart-contract
    /// router; absent for UTXO chains like BTC).
    #[serde(default)]
    pub router: Option<String>,
    /// Per-chain halt flags. When any of these is true, deposits via
    /// `THORChain` to / from this chain are paused.
    #[serde(default)]
    pub halted: bool,
    #[serde(default)]
    pub global_trading_paused: bool,
    #[serde(default)]
    pub chain_trading_paused: bool,
    #[serde(default)]
    pub chain_lp_actions_paused: bool,
    /// Recommended outbound gas rate, asset-specific units.
    #[serde(default)]
    pub gas_rate: Option<String>,
    #[serde(default)]
    pub gas_rate_units: Option<String>,
}

/// Subset of `GET /thorchain/tx/{hash}` we read for inbound observation.
///
/// Returned when `THORChain`'s Bifrost validators have voted on a deposit
/// observed on a partner chain. `observed_tx.status` transitions
/// `incomplete` → `done` once enough validators have signed off.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxResponse {
    pub observed_tx: ObservedTx,
    /// Outbound action(s) `THORChain` queued in response (the swap-output
    /// transaction sent to our multisig). Empty if the inbound was a
    /// direct-asset deposit with no outbound.
    #[serde(default)]
    pub actions: Vec<TxOutAction>,
    #[serde(default)]
    pub finalised_height: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservedTx {
    pub tx: TxDetails,
    pub status: String, // "incomplete" | "done"
    #[serde(default)]
    pub block_height: Option<i64>,
    #[serde(default)]
    pub finalise_height: Option<i64>,
    #[serde(default)]
    pub signers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxDetails {
    pub id: String,
    pub chain: String,
    pub from_address: String,
    pub to_address: String,
    pub coins: Vec<Coin>,
    pub memo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Coin {
    pub asset: String,
    pub amount: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxOutAction {
    pub chain: String,
    pub to_address: String,
    pub coin: Coin,
    pub memo: String,
    pub max_gas: Vec<Coin>,
}

/// One entry in `GET /thorchain/queue/outbound`. Not yet broadcast on
/// the destination chain — useful for relayers detecting partner-side
/// stalls.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundEntry {
    pub chain: String,
    pub to_address: String,
    pub coin: Coin,
    pub memo: String,
    pub in_hash: String,
    pub height: i64,
}

/// `GET /thorchain/pools` — one row per pool. We only need depth for
/// slip estimates; many other fields exist upstream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pool {
    pub asset: String,
    pub status: String, // "Available" | "Staged" | "Suspended"
    pub balance_asset: String,
    pub balance_rune: String,
    #[serde(default)]
    pub asset_tor_price: Option<String>,
}

/// Subset of `GET /thorchain/tx/status/{hash}` — the swap-lifecycle
/// "stages" view, used for the streaming-swap FINALITY gate.
///
/// The observation view (`GET /thorchain/tx/{hash}` → [`TxResponse`]) only
/// tells us the inbound was observed (`status == "done"`); it carries NO
/// signal that a STREAMING swap has emitted all of its sub-swaps. A
/// streaming redeem fills over several blocks, so attesting on the
/// observation view alone could settle a partial mid-stream fill
/// (`STREAM-B2-COORD`, the central streaming risk). This view exposes
/// `swap_finalised.completed` plus the streaming `count` / `quantity`,
/// which together gate settlement. Only the fields the gate reads are
/// deserialized; `serde(default)` tolerates the rest of the upstream
/// schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TxStatusResponse {
    #[serde(default)]
    pub stages: TxStages,
}

/// The `stages` object of a `tx/status` response (subset).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TxStages {
    /// Swap-execution status — carries the `streaming` sub-object while a
    /// streaming swap is mid-flight.
    #[serde(default)]
    pub swap_status: Option<SwapStatus>,
    /// Whether the (possibly streaming) swap has fully finalised — the
    /// primary finality signal.
    #[serde(default)]
    pub swap_finalised: Option<StageCompleted>,
}

/// `stages.swap_status` — execution state of the swap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SwapStatus {
    /// True while the swap (or a remaining sub-swap) is still pending.
    #[serde(default)]
    pub pending: bool,
    /// Present only for streaming swaps — the sub-swap progress counters.
    #[serde(default)]
    pub streaming: Option<StreamingStatus>,
}

/// `stages.swap_status.streaming` — streaming-swap sub-swap progress.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StreamingStatus {
    /// Total sub-swaps requested (the `quantity` of the streaming memo).
    #[serde(default)]
    pub quantity: u64,
    /// Sub-swaps executed so far. The stream is complete when
    /// `count >= quantity`.
    #[serde(default)]
    pub count: u64,
    /// Blocks between sub-swaps (the streaming `interval`).
    #[serde(default)]
    pub interval: u64,
}

/// A generic `{ "completed": bool }` stage entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StageCompleted {
    #[serde(default)]
    pub completed: bool,
}

impl TxStatusResponse {
    /// The streaming-swap FINALITY gate (`STREAM-B2-COORD`).
    ///
    /// The coordinator must settle a streamed redeem ONLY once the swap has
    /// fully finalised — otherwise it would attest a partial mid-stream
    /// fill and under-credit the user. Returns `true` iff `THORChain`
    /// reports `swap_finalised.completed` AND, for a streaming swap, every
    /// requested sub-swap has executed (`count >= quantity`) with nothing
    /// still `pending`. Fail closed: a missing/false signal, or streaming
    /// counters that disagree with the finalised flag (`count < quantity`),
    /// are treated as NOT final so the coordinator retries rather than
    /// settling short.
    #[must_use]
    pub fn is_swap_finalised(&self) -> bool {
        // Primary signal: THORChain's own finalisation flag.
        if !self
            .stages
            .swap_finalised
            .as_ref()
            .is_some_and(|s| s.completed)
        {
            return false;
        }
        // Defense-in-depth for streaming swaps: confirm nothing is pending
        // and every sub-swap executed. A partial that momentarily carries a
        // finalised flag must NOT settle short.
        if let Some(swap) = &self.stages.swap_status {
            if swap.pending {
                return false;
            }
            if let Some(stream) = &swap.streaming {
                // `quantity > 0` (G/red-team RT-C-INFO): a present-but-degenerate
                // streaming object (`count == quantity == 0`, e.g. a malformed
                // upstream) must NOT read as final via `0 >= 0`; defer instead.
                return stream.quantity > 0 && stream.count >= stream.quantity;
            }
        }
        true
    }
}
