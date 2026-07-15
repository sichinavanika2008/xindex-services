//! Per-operator settlement-observer and untrusted-collector wire shapes.
//!
//! Requests carry only logical identity plus, for redemption settlement, the
//! untrusted native-chain inbound transaction candidate. Each operator derives
//! every signed amount from its own finalized Ethereum, `THORChain`, Bitcoin,
//! and token-transfer observations before asking its local HSM daemon.

use serde::{Deserialize, Serialize};

/// Trigger a current single-slot mint settlement observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MintSettlementRequest {
    /// Finalized `MintIntentCreated.intentId`.
    pub intent_id: String,
    /// Launch scope requires slot zero.
    pub slot_index: String,
}

/// One operator's independently observed mint attestation signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedMintSettlement {
    pub intent_id: String,
    pub slot_index: String,
    pub attested_amount: String,
    pub signer_address: String,
    pub signature: String,
    /// Hash of the append-only pre-sign evidence envelope.
    pub evidence_hash: String,
    /// Operator observation time, signed into the EIP-712 payload.
    pub observed_at: u64,
    pub valid_until: u64,
    pub source_chain_id: u64,
    pub source_block_number: u64,
    pub source_block_hash: String,
    pub observation_epoch: u64,
}

/// Trigger a redemption outcome check. The proposed inbound transaction hash
/// is untrusted; every observer validates it against its finalized dispatch,
/// native custody transaction facts, and independent `THORChain` sources.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedemptionSettlementRequest {
    pub redemption_id: String,
    pub leg_index: String,
    pub inbound_tx_hash: String,
}

/// One operator's delivery-only settlement signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedDeliverySettlement {
    pub redemption_id: String,
    pub leg_index: String,
    pub asset_id: String,
    pub delivered_amount: String,
    pub signer_address: String,
    pub signature: String,
    pub evidence_hash: String,
    pub observed_at: u64,
    pub valid_until: u64,
    pub source_chain_id: u64,
    pub source_block_number: u64,
    pub source_block_hash: String,
    pub observation_epoch: u64,
}

/// One operator's refund-only settlement signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedRefundSettlement {
    pub redemption_id: String,
    pub leg_index: String,
    pub asset_id: String,
    pub refunded_amount: String,
    pub signer_address: String,
    pub signature: String,
    pub evidence_hash: String,
    pub observed_at: u64,
    pub valid_until: u64,
    pub source_chain_id: u64,
    pub source_block_number: u64,
    pub source_block_hash: String,
    pub observation_epoch: u64,
}

/// One operator's fully-finalized combined streamed settlement signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedStreamedSettlement {
    pub redemption_id: String,
    pub leg_index: String,
    pub asset_id: String,
    pub delivered_usdt: String,
    pub refunded_native: String,
    pub signer_address: String,
    pub signature: String,
    pub evidence_hash: String,
    pub observed_at: u64,
    pub valid_until: u64,
    pub source_chain_id: u64,
    pub source_block_number: u64,
    pub source_block_hash: String,
    pub observation_epoch: u64,
}
