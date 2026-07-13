//! `xindex-chain-eth` — Ethereum chain client for the Xindex off-chain stack.
//!
//! Provides:
//! - Type-safe Solidity bindings via [`bindings`] (alloy `sol!` from vendored ABIs).
//! - The `xindex-watch` binary that subscribes to `IntentQueue` events for
//!   M1 verification.
//!
//! See workspace plan §15–§16 for the full milestone path.

pub mod bindings;
pub mod erc20;
pub mod finalized_observer;
pub mod finalized_rpc;
pub mod observer;
pub mod rpc;
pub mod settlement_observer;

pub use erc20::{FinalizedRpcErc20LogClient, RpcErc20LogClient};
pub use observer::{
    InMemoryLegSource, LegFacts, Observer, ObserverConfig, ObserverError, RedeemLegSource,
};
pub use rpc::{backoff, is_transient_rpc_error, ConnectAttempt, EndpointError, WsEndpointList};
