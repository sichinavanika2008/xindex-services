//! `xindex-chain-cosmos` — RPC client for the Cosmos custody family
//! (Phase 3.3, GAIA / ATOM).
//!
//! Sister crate to `chain-evm` / `chain-utxo`. Provides the
//! per-(Cosmos-chain) RPC primitives the cross-check policies (C6) and
//! executor (C7) need to verify `THORChain` deliveries/refunds and to
//! drive a `LegacyAminoPubKey` multisig `MsgSend` redeem.
//!
//! ## Surface
//!
//! [`CosmosChainClient`] is the trait every Cosmos-side consumer programs
//! against (mirrors `EvmChainClient`). [`ReqwestCosmosChainClient`] is the
//! production impl: Tendermint/CometBFT JSON-RPC (`/status`, `/tx_search`,
//! `/broadcast_tx_sync`) for chain reads/writes + the Cosmos SDK REST
//! `auth` endpoint for the account number/sequence.
//!
//! ## What this crate is NOT
//!
//! - Not a key-managing client. [`CosmosChainClient::broadcast_tx_sync`]
//!   takes already-signed `TxRaw` bytes (assembled by the executor from
//!   `cosmos-tx` C3 partials).
//! - Not a tx builder. Sign-bytes + multisig aggregation live in the pure
//!   `cosmos-tx` crate.
//! - Not an oracle. The caller supplies the fee (gas × gas-price in
//!   `uatom`).
//!
//! ## Tendermint event-attribute encoding
//!
//! Parsing assumes plain-string event attributes (`CometBFT` ≥ 0.35, which
//! Cosmos Hub `cosmoshub-4` runs). Pre-0.35 base64 attributes are out of
//! scope (GAIA is well past that). The pure parsers are unit-tested; live
//! RPC is exercised at signet/testnet rehearsal (DL-P3.3-8).

pub mod client;

pub use client::{
    CosmosAccount, CosmosBroadcastOutcome, CosmosChainClient, CosmosChainError, CosmosTransfer,
    ReqwestCosmosChainClient,
};
