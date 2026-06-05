//! `xindex-chain-tron` — RPC client for the TRON custody family (Phase
//! 4.6, TRON / TRON.TRX + TRC20 USDT).
//!
//! Sister crate to `chain-cosmos` / `chain-xrp` / `chain-solana`. Provides
//! the per-TRON-chain full-node JSON-RPC primitives the executor (the
//! redeem leg) needs to build, broadcast, and confirm a native
//! account-permission multisig transfer.
//!
//! ## Surface
//!
//! [`TronChainClient`] is the trait every TRON-side consumer programs
//! against (mirrors `XrpChainClient`). [`ReqwestTronChainClient`] is the
//! production impl: TRON full-node HTTP API (`wallet/getnowblock`,
//! `wallet/broadcasthex`, `wallet/gettransactioninfobyid`).
//!
//! ## What this crate is NOT
//!
//! - Not a key-managing client. [`TronChainClient::broadcast_hex`] takes
//!   an already-assembled, multi-signed `Transaction` protobuf hex (built
//!   by the executor from `tron-tx` partials).
//! - Not a tx builder. `raw_data` protobuf + `txID` + signature
//!   aggregation live in the pure `tron-tx` crate.
//! - Not an oracle. The caller supplies the `fee_limit` (TRC20 energy cap)
//!   and the TAPOS window.

pub mod client;

pub use client::{
    parse_broadcast, parse_now_block, parse_transaction_info, ReqwestTronChainClient, TronBlockRef,
    TronBroadcastOutcome, TronChainClient, TronChainError, TronTxReceipt,
};
