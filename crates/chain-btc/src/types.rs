//! Domain types for Bitcoin chain observations.
//!
//! Sized for the off-chain stack's two consumers:
//! - The attestation signer's "did the BTC arrive?" cross-check.
//! - The executor's PSBT-construction step (needs `txid` + `vout` +
//!   `value` per UTXO to spend).

use bitcoin::{Amount, BlockHash, Txid};

/// A confirmed UTXO at a watched address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinUtxo {
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
pub struct BitcoinTxStatus {
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
