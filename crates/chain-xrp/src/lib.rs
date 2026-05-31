//! `xindex-chain-xrp` — RPC client for the XRP custody family (Phase
//! 4.4, XRP / XRP.XRP).
//!
//! Sister crate to `chain-cosmos` / `chain-evm` / `chain-utxo`. Provides
//! the per-XRP-chain `rippled` JSON-RPC primitives the cross-check
//! policies (C6) and executor (C7) need to verify `THORChain`
//! deliveries/refunds and to drive a `SignerList` multisig `Payment`
//! redeem.
//!
//! ## Surface
//!
//! [`XrpChainClient`] is the trait every XRP-side consumer programs
//! against (mirrors `CosmosChainClient`). [`ReqwestXrpChainClient`] is the
//! production impl: `rippled` JSON-RPC over HTTP POST (`account_info`,
//! `ledger_current`, `ledger`, `account_tx`, `submit`).
//!
//! ## What this crate is NOT
//!
//! - Not a key-managing client. [`XrpChainClient::submit_tx_blob`] takes
//!   an already-assembled, multisigned tx-blob (built by the executor
//!   from `xrp-tx` C3 partials).
//! - Not a tx builder. `STObject` serialization + multisig aggregation
//!   live in the pure `xrp-tx` crate.
//! - Not an oracle. The caller supplies the fee (flat drops, scaled by
//!   signer count).
//!
//! ## The `delivered_amount` rule (DL-P4.4 security item)
//!
//! XRPL `Payment` supports `tfPartialPayment`, where the actually-
//! delivered amount can be far less than the `Amount` field. Observation
//! MUST read `meta.delivered_amount`, NEVER the top-level `Amount` — a
//! refund attestation that trusted `Amount` could be made to count a
//! 1-drop delivery as full value. [`client::parse_delivered_drops`]
//! enforces this; there is no `Amount` fallback (a missing/`unavailable`
//! `delivered_amount` yields an unverifiable transfer that is dropped,
//! not up-counted).

pub mod client;

pub use client::{
    parse_account_info, parse_account_tx, parse_delivered_drops, parse_ledger_current,
    parse_submit, parse_validated_ledger, ReqwestXrpChainClient, XrpAccount, XrpChainClient,
    XrpChainError, XrpSubmitOutcome, XrpTransfer,
};
