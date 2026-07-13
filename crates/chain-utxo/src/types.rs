//! Domain types for Bitcoin chain observations.
//!
//! Sized for the off-chain stack's two consumers:
//! - The attestation signer's "did the BTC arrive?" cross-check.
//! - The executor's PSBT-construction step (needs `txid` + `vout` +
//!   `value` per UTXO to spend).

use bitcoin::{Amount, BlockHash, Txid};
use serde::Serialize;

/// A confirmed UTXO at a watched address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoEntry {
    pub txid: Txid,
    pub vout: u32,
    pub value: Amount,
    /// Confirmation count at the time this was reported. The watcher
    /// caller decides what threshold to require (typically ≥6 for
    /// finality on mainnet, ≥3 on signet/testnet).
    pub confirmations: u32,
    /// Block hash the UTXO was first confirmed in. Tracked so the
    /// watcher can detect a reorg (block hash at that height changed)
    /// and reset its certainty.
    pub block_hash: Option<BlockHash>,
}

/// Confirmation status of an arbitrary Bitcoin transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoTxStatus {
    pub txid: Txid,
    /// `true` once the transaction has been mined into any block.
    /// Re-org awareness is the caller's responsibility — compare
    /// `block_hash` at the recorded height to detect a re-org and
    /// invalidate the confirmation.
    pub confirmed: bool,
    pub block_height: Option<u32>,
    pub block_hash: Option<BlockHash>,
    /// Confirmation count at the time of query. `0` for unconfirmed.
    pub confirmations: u32,
}

/// Fully decoded public transaction facts retained by settlement observers
/// before requesting any HSM signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UtxoTransactionFacts {
    pub txid: String,
    pub confirmed: bool,
    pub confirmations: u32,
    pub block_height: Option<u32>,
    pub block_hash: Option<String>,
    pub input_addresses: Vec<String>,
    pub outputs: Vec<UtxoOutputFacts>,
}

/// One output from [`UtxoTransactionFacts`]. The raw script is retained as
/// canonical lowercase hex so callers can bind both payments and `OP_RETURN`
/// memo bytes without trusting an address renderer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UtxoOutputFacts {
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub address: Option<String>,
}
