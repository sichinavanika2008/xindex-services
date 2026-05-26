//! `xindex-chain-evm` — RPC client for the EVM custody family (Phase 3.2).
//!
//! Sister crate to `chain-utxo`. While `chain-eth` holds the Ethereum-
//! mint-side event watcher (`xindex-watch` / `xindex-attest`), this crate
//! provides the **per-(destination-chain) RPC primitives** the executor
//! (V7) and cross-check policies (V6) need to drive Safe v1.4.1
//! `execTransaction` redeems across ETH / BSC / AVAX / BASE / POL.
//!
//! ## Surface
//!
//! [`EvmChainClient`] is the trait every EVM-side consumer programs
//! against. [`AlloyEvmChainClient`] is the production impl, backed by
//! an `alloy::providers::Provider`. The binary callsite constructs the
//! provider (typically over WS with multi-RPC fallover via
//! `chain-eth::WsEndpointList`) and wraps it once.
//!
//! ## Per-chain tx-type selection
//!
//! Reads `chain_registry::tx_type()` (V1) at submit time. ETH / AVAX /
//! BASE / POL get EIP-1559 (`max_fee_per_gas` + `max_priority_fee_per_gas`)
//! envelopes; BSC stays on type-0 legacy (`gas_price`) because its
//! mempool still routes 1559 inconsistently (DL-P3.2-4 locked).
//!
//! ## What this crate is NOT
//!
//! - Not a key-managing client. Submission takes raw signed-tx bytes;
//!   key material lives in the executor (V7) or the signer-daemon HSM.
//! - Not a chain-specific contract bindings host. Safe `execTransaction`
//!   calldata is built by `xindex-safe-evm` (V3); this crate only
//!   submits the resulting bytes and watches the receipt.
//! - Not an oracle / gas-price source. Caller supplies fee fields per
//!   request (DL-P3.2-7).

pub mod client;
pub mod submit;

pub use client::{
    AlloyEvmChainClient, EvmChainClient, EvmChainError, EvmConfirmedReceipt, EvmLogEntry,
    EvmLogFilter, EvmTransactionSummary,
};
pub use submit::{build_safe_exec_tx_request, EvmTxFee};
