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
