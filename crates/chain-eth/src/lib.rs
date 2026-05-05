//! `xindex-chain-eth` — Ethereum chain client for the Xindex off-chain stack.
//!
//! Provides:
//! - Type-safe Solidity bindings via [`bindings`] (alloy `sol!` from vendored ABIs).
//! - The `xindex-watch` binary that subscribes to `IntentQueue` events for
//!   M1 verification.
//!
//! See workspace plan §15–§16 for the full milestone path.

pub mod bindings;
