//! `xindex-chain-btc` — Bitcoin chain client + UTXO watcher.
//!
//! Two responsibilities for the Phase 2 off-chain stack:
//!
//! 1. **Inbound observation (signer cross-check)** — watch our 3-of-5
//!    P2WSH multisig address for confirmed BTC arrivals. The attestation
//!    signer cross-checks this against `THORChain`'s outbound observation
//!    before signing an `Attestation` for the on-chain oracle.
//!
//! 2. **Outbound dispatch (executor)** — broadcast Bitcoin transactions
//!    that the multisig has signed via PSBT round-trips with the per-key
//!    `xindex-multisig` daemon.
//!
//! The crate exposes a [`UtxoChainClient`] trait so production code
//! (Esplora HTTP) and tests (in-memory fake) share the same surface.

pub mod client;
pub mod types;
pub mod watcher;

pub use client::{EsploraClient, UtxoChainClient, UtxoError};
pub use types::{UtxoEntry, UtxoTxStatus};
pub use watcher::find_arrival;
