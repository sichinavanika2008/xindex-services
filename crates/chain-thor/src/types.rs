//! Response types pinned to the `THORNode` `OpenAPI` spec.
//!
//! Only the fields the off-chain stack actually reads are deserialized.
//! `serde(default)` lets us tolerate missing or new optional fields
//! without breaking on every upstream schema change.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Missing upstream safety fields are ambiguous, never affirmative evidence
/// that trading is available. Default every halt flag to `true` so a schema
/// regression or partial provider response stops signing instead of silently
/// clearing a registry pause bit.
const fn default_paused() -> bool {
    true
}

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
    #[serde(default = "default_paused")]
    pub halted: bool,
    #[serde(default = "default_paused")]
    pub global_trading_paused: bool,
    #[serde(default = "default_paused")]
    pub chain_trading_paused: bool,
    #[serde(default = "default_paused")]
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

/// One OBSERVED outbound in `GET /thorchain/tx/details/{hash}` →
/// `out_txs`. Unlike [`TxOutAction`] (the PLANNED outbound in the
/// observation view, which carries no hash), this is the outbound
/// `THORChain`'s validators have observed confirmed on the destination
/// chain, so `id` is its real on-chain hash — for an ETH.USDT delivery,
/// the Ethereum tx hash that emitted the USDT `Transfer`. RUST-004 binds
/// the on-chain `Transfer.transaction_hash` to this 1:1. Every field is
/// `serde(default)` so a partially-populated entry (e.g. observed but not
/// yet hashed) deserializes and is simply skipped by the matcher.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OutboundTx {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub chain: String,
    #[serde(default)]
    pub to_address: String,
    #[serde(default)]
    pub coins: Vec<Coin>,
}

/// Subset of `GET /thorchain/tx/details/{hash}` — the richer details view
/// whose `out_txs` expose the OBSERVED outbound on-chain hash(es). The
/// observation view ([`TxResponse`], `GET /thorchain/tx/{hash}`) only
/// lists PLANNED outbound `actions` with no hash, so RUST-004's 1:1
/// inflow bind reads this view instead.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TxDetailsResponse {
    #[serde(default)]
    pub out_txs: Vec<OutboundTx>,
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

/// `GET /thorchain/mimir` response. Keys are case-insensitive in `THORNode`;
/// policy code normalizes them to uppercase before reading or hashing them.
pub type Mimir = BTreeMap<String, i64>;

/// Complete query parameters Xindex permits for `/thorchain/quote/swap`.
///
/// Every safety-sensitive option is explicit: no affiliate, no automatic
/// streaming quantity, no implicit refund recipient, and the fee-aware
/// `liquidity_tolerance_bps` parameter (never the legacy `tolerance_bps`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SwapQuoteRequest {
    pub from_asset: String,
    pub to_asset: String,
    /// `THORChain` Base amount (1e8), encoded losslessly as decimal text.
    pub amount: String,
    pub destination: String,
    pub refund_address: String,
    pub liquidity_tolerance_bps: u16,
    pub streaming_interval: u64,
    pub streaming_quantity: u64,
}

/// Fee breakdown returned by `/thorchain/quote/swap`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwapQuoteFees {
    pub asset: String,
    pub affiliate: String,
    pub outbound: String,
    pub liquidity: String,
    pub total: String,
    pub slippage_bps: u64,
    pub total_bps: u64,
}

/// Safety-relevant subset of `/thorchain/quote/swap`.
///
/// Load-bearing fields intentionally have no serde defaults. If `THORNode` or a
/// provider drops one, decoding fails and the signer cannot authorize a swap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwapQuoteResponse {
    pub inbound_address: String,
    pub inbound_confirmation_blocks: u64,
    pub inbound_confirmation_seconds: u64,
    pub outbound_delay_blocks: u64,
    pub outbound_delay_seconds: u64,
    pub fees: SwapQuoteFees,
    pub expiry: u64,
    pub warning: String,
    pub dust_threshold: String,
    pub recommended_min_amount_in: String,
    pub recommended_gas_rate: String,
    pub gas_rate_units: String,
    pub memo: String,
    pub expected_amount_out: String,
    pub max_streaming_quantity: u64,
    pub streaming_swap_blocks: u64,
    #[serde(default)]
    pub streaming_swap_seconds: u64,
    pub total_swap_seconds: u64,
}

/// Standard `CometBFT` `/status` envelope (only the sync fields Xindex reads).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusStatusResponse {
    pub result: ConsensusStatusResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusStatusResult {
    pub node_info: ConsensusNodeInfo,
    pub sync_info: ConsensusSyncInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusNodeInfo {
    pub id: String,
    pub network: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusSyncInfo {
    pub latest_block_hash: String,
    pub latest_block_height: String,
    pub latest_block_time: String,
    pub catching_up: bool,
}

/// Parsed, policy-ready `CometBFT` tip. Numeric/time parsing happens at the
/// client boundary so no signer can accidentally compare height strings or
/// treat a malformed timestamp as fresh.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusTip {
    pub node_id: String,
    pub network: String,
    pub version: String,
    pub block_hash: String,
    pub height: u64,
    pub block_time_unix: u64,
    pub catching_up: bool,
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

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]

    use super::*;

    #[test]
    fn missing_inbound_halt_fields_fail_closed() {
        let entry: InboundAddress = serde_json::from_value(serde_json::json!({
            "chain": "ETH",
            "pub_key": "thorpub1example",
            "address": "0x1111111111111111111111111111111111111111",
            "router": "0x2222222222222222222222222222222222222222"
        }))
        .expect("minimal inbound-address fixture");

        assert!(entry.halted);
        assert!(entry.global_trading_paused);
        assert!(entry.chain_trading_paused);
        assert!(entry.chain_lp_actions_paused);
    }

    #[test]
    fn explicit_false_inbound_halt_fields_remain_false() {
        let entry: InboundAddress = serde_json::from_value(serde_json::json!({
            "chain": "ETH",
            "pub_key": "thorpub1example",
            "address": "0x1111111111111111111111111111111111111111",
            "router": "0x2222222222222222222222222222222222222222",
            "halted": false,
            "global_trading_paused": false,
            "chain_trading_paused": false,
            "chain_lp_actions_paused": false
        }))
        .expect("complete inbound-address fixture");

        assert!(!entry.halted);
        assert!(!entry.global_trading_paused);
        assert!(!entry.chain_trading_paused);
        assert!(!entry.chain_lp_actions_paused);
    }
}
