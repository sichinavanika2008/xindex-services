//! Exact-quorum collection for independently observed mint/redemption facts.
//!
//! The collector is deliberately untrusted: every response is decoded,
//! low-S/recovery checked, matched to the requested logical round, checked
//! against the active signer allowlist, and grouped by complete EIP-712
//! plaintext. One signer cannot vote for two outcomes of the same leg.

use std::collections::{HashMap, HashSet};

use alloy_primitives::{Address, PrimitiveSignature, B256, U256};
use alloy_sol_types::Eip712Domain;
use thiserror::Error;
use xindex_shared::eip712::{
    attestation, attestation_signing_hash, redemption_attestation,
    redemption_attestation_signing_hash, refund_attestation, refund_attestation_signing_hash,
    streamed_settlement, streamed_settlement_signing_hash,
};
use xindex_shared::settlement_wire::{
    SignedDeliverySettlement, SignedMintSettlement, SignedRefundSettlement,
    SignedStreamedSettlement,
};

/// One exact on-chain attestation payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettlementPayload {
    /// Mint slot delivery.
    Mint {
        intent_id: B256,
        slot_index: U256,
        attested_amount: U256,
    },
    /// Redemption delivery-only outcome.
    Delivery {
        redemption_id: B256,
        leg_index: U256,
        asset_id: B256,
        delivered_amount: U256,
    },
    /// Redemption refund-only outcome.
    Refund {
        redemption_id: B256,
        leg_index: U256,
        asset_id: B256,
        refunded_amount: U256,
    },
    /// Fully-finalized combined streamed outcome.
    Streamed {
        redemption_id: B256,
        leg_index: U256,
        asset_id: B256,
        delivered_usdt: U256,
        refunded_native: U256,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SettlementRound {
    Mint(B256, U256),
    Redemption(B256, U256),
}

/// Exact payload with deterministic, recovered-signer-ordered signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadySettlement {
    /// Complete signed plaintext.
    pub payload: SettlementPayload,
    /// Threshold signatures ordered by recovered address.
    pub signatures: Vec<[u8; 65]>,
}

/// Result of accepting one observer response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementIngestOutcome {
    /// Valid vote below quorum.
    Accepted { count: usize },
    /// Exact signer/payload retry.
    Duplicate { count: usize },
    /// This vote completed an exact quorum.
    Ready(ReadySettlement),
}

/// Fail-closed observer-response validation errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SettlementCollectError {
    /// Impossible signer threshold.
    #[error("threshold {threshold} must be in 1..={signer_count}")]
    InvalidThreshold {
        threshold: usize,
        signer_count: usize,
    },
    /// Zero freshness budget.
    #[error("maximum response age must be non-zero")]
    InvalidResponseAge,
    /// Malformed typed field.
    #[error("invalid {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// Response identifies a different intent/leg/asset.
    #[error("response does not match the requested logical settlement")]
    WrongRound,
    /// Plain outcome must be non-zero.
    #[error("zero settlement amount")]
    ZeroAmount,
    /// Combined outcome cannot have two zero values.
    #[error("streamed settlement has both amounts zero")]
    EmptyStreamed,
    /// Observer result exceeded the short collection window.
    #[error("stale observer response: observed {observed_at}, now {now}")]
    Stale { observed_at: u64, now: u64 },
    /// Future observation stamp.
    #[error("future observer response: observed {observed_at}, now {now}")]
    Future { observed_at: u64, now: u64 },
    /// Malformed, high-S, or unrecoverable signature.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    /// Claimed response identity differs from ECDSA recovery.
    #[error("claimed signer {claimed} does not match recovered {recovered}")]
    SignerMismatch {
        claimed: Address,
        recovered: Address,
    },
    /// Recovered signer is not active/configured.
    #[error("signer {0} is not allowlisted")]
    SignerNotAllowed(Address),
    /// One signer voted for two payloads/outcomes of one logical round.
    #[error("signer {signer} equivocated for one logical settlement")]
    Equivocation { signer: Address },
}

/// Stateful exact-match fan-in. The on-chain queue remains the authoritative
/// replay boundary; retaining rounds here adds early equivocation detection.
#[derive(Debug)]
pub struct SettlementCollector {
    domain: Eip712Domain,
    allowed_signers: HashSet<Address>,
    threshold: usize,
    max_response_age_secs: u64,
    votes: HashMap<SettlementPayload, HashMap<Address, [u8; 65]>>,
    signer_rounds: HashMap<(SettlementRound, Address), SettlementPayload>,
}

impl SettlementCollector {
    /// Construct from the startup-verified complete on-chain signer roster.
    ///
    /// # Errors
    /// Impossible threshold or zero response-age budget.
    pub fn new(
        domain: Eip712Domain,
        allowed_signers: impl IntoIterator<Item = Address>,
        threshold: usize,
        max_response_age_secs: u64,
    ) -> Result<Self, SettlementCollectError> {
        let allowed_signers: HashSet<_> = allowed_signers.into_iter().collect();
        if threshold == 0 || threshold > allowed_signers.len() {
            return Err(SettlementCollectError::InvalidThreshold {
                threshold,
                signer_count: allowed_signers.len(),
            });
        }
        if max_response_age_secs == 0 {
            return Err(SettlementCollectError::InvalidResponseAge);
        }
        Ok(Self {
            domain,
            allowed_signers,
            threshold,
            max_response_age_secs,
            votes: HashMap::new(),
            signer_rounds: HashMap::new(),
        })
    }

    /// Validate and collect one mint response for the requested slot.
    ///
    /// # Errors
    /// Malformed/stale response, wrong round, invalid/inactive signer, or
    /// signer equivocation.
    pub fn ingest_mint(
        &mut self,
        message: &SignedMintSettlement,
        expected_intent_id: B256,
        expected_slot_index: U256,
        now: u64,
    ) -> Result<SettlementIngestOutcome, SettlementCollectError> {
        self.validate_metadata(&message.evidence_hash, message.observed_at, now)?;
        let intent_id = parse_b256("intentId", &message.intent_id)?;
        let slot_index = parse_u256("slotIndex", &message.slot_index)?;
        let attested_amount = parse_u256("attestedAmount", &message.attested_amount)?;
        if intent_id != expected_intent_id || slot_index != expected_slot_index {
            return Err(SettlementCollectError::WrongRound);
        }
        if attested_amount.is_zero() {
            return Err(SettlementCollectError::ZeroAmount);
        }
        let payload = SettlementPayload::Mint {
            intent_id,
            slot_index,
            attested_amount,
        };
        let digest = attestation_signing_hash(
            &attestation(intent_id, slot_index, attested_amount),
            &self.domain,
        );
        self.ingest_verified(
            payload,
            SettlementRound::Mint(intent_id, slot_index),
            &message.signer_address,
            &message.signature,
            digest,
        )
    }

    /// Validate and collect one delivery-only response.
    ///
    /// # Errors
    /// As [`Self::ingest_mint`], including exact asset metadata matching.
    pub fn ingest_delivery(
        &mut self,
        message: &SignedDeliverySettlement,
        expected_redemption_id: B256,
        expected_leg_index: U256,
        expected_asset_id: B256,
        now: u64,
    ) -> Result<SettlementIngestOutcome, SettlementCollectError> {
        self.validate_metadata(&message.evidence_hash, message.observed_at, now)?;
        let redemption_id = parse_b256("redemptionId", &message.redemption_id)?;
        let leg_index = parse_u256("legIndex", &message.leg_index)?;
        let asset_id = parse_b256("assetId", &message.asset_id)?;
        let delivered_amount = parse_u256("deliveredAmount", &message.delivered_amount)?;
        validate_redemption_round(
            (redemption_id, leg_index, asset_id),
            (
                expected_redemption_id,
                expected_leg_index,
                expected_asset_id,
            ),
        )?;
        if delivered_amount.is_zero() {
            return Err(SettlementCollectError::ZeroAmount);
        }
        let payload = SettlementPayload::Delivery {
            redemption_id,
            leg_index,
            asset_id,
            delivered_amount,
        };
        let digest = redemption_attestation_signing_hash(
            &redemption_attestation(redemption_id, leg_index, asset_id, delivered_amount),
            &self.domain,
        );
        self.ingest_verified(
            payload,
            SettlementRound::Redemption(redemption_id, leg_index),
            &message.signer_address,
            &message.signature,
            digest,
        )
    }

    /// Validate and collect one refund-only response.
    ///
    /// # Errors
    /// As [`Self::ingest_delivery`].
    pub fn ingest_refund(
        &mut self,
        message: &SignedRefundSettlement,
        expected_redemption_id: B256,
        expected_leg_index: U256,
        expected_asset_id: B256,
        now: u64,
    ) -> Result<SettlementIngestOutcome, SettlementCollectError> {
        self.validate_metadata(&message.evidence_hash, message.observed_at, now)?;
        let redemption_id = parse_b256("redemptionId", &message.redemption_id)?;
        let leg_index = parse_u256("legIndex", &message.leg_index)?;
        let asset_id = parse_b256("assetId", &message.asset_id)?;
        let refunded_amount = parse_u256("refundedAmount", &message.refunded_amount)?;
        validate_redemption_round(
            (redemption_id, leg_index, asset_id),
            (
                expected_redemption_id,
                expected_leg_index,
                expected_asset_id,
            ),
        )?;
        if refunded_amount.is_zero() {
            return Err(SettlementCollectError::ZeroAmount);
        }
        let payload = SettlementPayload::Refund {
            redemption_id,
            leg_index,
            asset_id,
            refunded_amount,
        };
        let digest = refund_attestation_signing_hash(
            &refund_attestation(redemption_id, leg_index, asset_id, refunded_amount),
            &self.domain,
        );
        self.ingest_verified(
            payload,
            SettlementRound::Redemption(redemption_id, leg_index),
            &message.signer_address,
            &message.signature,
            digest,
        )
    }

    /// Validate and collect one fully-finalized streamed response.
    ///
    /// # Errors
    /// As [`Self::ingest_delivery`], or both outcome amounts are zero.
    pub fn ingest_streamed(
        &mut self,
        message: &SignedStreamedSettlement,
        expected_redemption_id: B256,
        expected_leg_index: U256,
        expected_asset_id: B256,
        now: u64,
    ) -> Result<SettlementIngestOutcome, SettlementCollectError> {
        self.validate_metadata(&message.evidence_hash, message.observed_at, now)?;
        let redemption_id = parse_b256("redemptionId", &message.redemption_id)?;
        let leg_index = parse_u256("legIndex", &message.leg_index)?;
        let asset_id = parse_b256("assetId", &message.asset_id)?;
        let delivered_usdt = parse_u256("deliveredUsdt", &message.delivered_usdt)?;
        let refunded_native = parse_u256("refundedNative", &message.refunded_native)?;
        validate_redemption_round(
            (redemption_id, leg_index, asset_id),
            (
                expected_redemption_id,
                expected_leg_index,
                expected_asset_id,
            ),
        )?;
        if delivered_usdt.is_zero() && refunded_native.is_zero() {
            return Err(SettlementCollectError::EmptyStreamed);
        }
        let payload = SettlementPayload::Streamed {
            redemption_id,
            leg_index,
            asset_id,
            delivered_usdt,
            refunded_native,
        };
        let digest = streamed_settlement_signing_hash(
            &streamed_settlement(
                redemption_id,
                leg_index,
                asset_id,
                delivered_usdt,
                refunded_native,
            ),
            &self.domain,
        );
        self.ingest_verified(
            payload,
            SettlementRound::Redemption(redemption_id, leg_index),
            &message.signer_address,
            &message.signature,
            digest,
        )
    }

    fn validate_metadata(
        &self,
        evidence_hash: &str,
        observed_at: u64,
        now: u64,
    ) -> Result<(), SettlementCollectError> {
        if parse_b256("evidenceHash", evidence_hash)? == B256::ZERO {
            return Err(SettlementCollectError::InvalidField {
                field: "evidenceHash",
                reason: "zero".to_string(),
            });
        }
        if observed_at > now {
            return Err(SettlementCollectError::Future { observed_at, now });
        }
        if now.saturating_sub(observed_at) > self.max_response_age_secs {
            return Err(SettlementCollectError::Stale { observed_at, now });
        }
        Ok(())
    }

    fn ingest_verified(
        &mut self,
        payload: SettlementPayload,
        round: SettlementRound,
        claimed_raw: &str,
        signature_raw: &str,
        digest: B256,
    ) -> Result<SettlementIngestOutcome, SettlementCollectError> {
        let claimed = parse_address("signerAddress", claimed_raw)?;
        let signature = parse_signature(signature_raw)?;
        let parsed = PrimitiveSignature::try_from(signature.as_slice())
            .map_err(|error| SettlementCollectError::InvalidSignature(error.to_string()))?;
        if parsed.normalize_s().is_some() {
            return Err(SettlementCollectError::InvalidSignature(
                "high-S signature rejected by OpenZeppelin ECDSA".to_string(),
            ));
        }
        let recovered = parsed
            .recover_address_from_prehash(&digest)
            .map_err(|error| SettlementCollectError::InvalidSignature(error.to_string()))?;
        if claimed != recovered {
            return Err(SettlementCollectError::SignerMismatch { claimed, recovered });
        }
        if !self.allowed_signers.contains(&recovered) {
            return Err(SettlementCollectError::SignerNotAllowed(recovered));
        }
        if let Some(previous) = self.signer_rounds.get(&(round, recovered)) {
            if previous != &payload {
                return Err(SettlementCollectError::Equivocation { signer: recovered });
            }
        } else {
            self.signer_rounds.insert((round, recovered), payload);
        }
        let votes = self.votes.entry(payload).or_default();
        if votes.contains_key(&recovered) {
            if votes.len() >= self.threshold {
                return Ok(SettlementIngestOutcome::Ready(ready(payload, votes)));
            }
            return Ok(SettlementIngestOutcome::Duplicate { count: votes.len() });
        }
        votes.insert(recovered, signature);
        if votes.len() >= self.threshold {
            return Ok(SettlementIngestOutcome::Ready(ready(payload, votes)));
        }
        Ok(SettlementIngestOutcome::Accepted { count: votes.len() })
    }
}

fn ready(payload: SettlementPayload, votes: &HashMap<Address, [u8; 65]>) -> ReadySettlement {
    let mut ordered: Vec<_> = votes
        .iter()
        .map(|(address, signature)| (*address, *signature))
        .collect();
    ordered.sort_by(|(left, _), (right, _)| left.as_slice().cmp(right.as_slice()));
    ReadySettlement {
        payload,
        signatures: ordered
            .into_iter()
            .map(|(_, signature)| signature)
            .collect(),
    }
}

fn validate_redemption_round(
    actual: (B256, U256, B256),
    expected: (B256, U256, B256),
) -> Result<(), SettlementCollectError> {
    if actual != expected {
        return Err(SettlementCollectError::WrongRound);
    }
    Ok(())
}

fn parse_b256(field: &'static str, raw: &str) -> Result<B256, SettlementCollectError> {
    raw.parse::<B256>()
        .map_err(|error| SettlementCollectError::InvalidField {
            field,
            reason: error.to_string(),
        })
}

fn parse_u256(field: &'static str, raw: &str) -> Result<U256, SettlementCollectError> {
    U256::from_str_radix(raw, 10).map_err(|error| SettlementCollectError::InvalidField {
        field,
        reason: error.to_string(),
    })
}

fn parse_address(field: &'static str, raw: &str) -> Result<Address, SettlementCollectError> {
    raw.parse::<Address>()
        .map_err(|error| SettlementCollectError::InvalidField {
            field,
            reason: error.to_string(),
        })
}

fn parse_signature(raw: &str) -> Result<[u8; 65], SettlementCollectError> {
    let bytes = alloy_primitives::hex::decode(raw.strip_prefix("0x").unwrap_or(raw))
        .map_err(|error| SettlementCollectError::InvalidSignature(error.to_string()))?;
    let signature: [u8; 65] = bytes.try_into().map_err(|value: Vec<u8>| {
        SettlementCollectError::InvalidSignature(format!("expected 65 bytes, got {}", value.len()))
    })?;
    if !matches!(signature[64], 27 | 28) {
        return Err(SettlementCollectError::InvalidSignature(format!(
            "v must be 27 or 28, got {}",
            signature[64]
        )));
    }
    Ok(signature)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::{Signer, SignerSync};
    use xindex_shared::eip712::attestation_oracle_domain;

    use super::*;

    fn signer(seed: u8) -> PrivateKeySigner {
        format!("0x{}", format!("{seed:02x}").repeat(32))
            .parse()
            .expect("test signer")
    }

    fn domain() -> Eip712Domain {
        attestation_oracle_domain(31_337, Address::repeat_byte(0xcc))
    }

    fn mint_message(signer: &PrivateKeySigner, amount: u64) -> SignedMintSettlement {
        let intent = B256::repeat_byte(0x11);
        let digest = attestation_signing_hash(
            &attestation(intent, U256::ZERO, U256::from(amount)),
            &domain(),
        );
        let signature = signer.sign_hash_sync(&digest).expect("sign").as_bytes();
        SignedMintSettlement {
            intent_id: format!("{intent:#x}"),
            slot_index: "0".to_string(),
            attested_amount: amount.to_string(),
            signer_address: format!("{:#x}", signer.address()),
            signature: format!("0x{}", alloy_primitives::hex::encode(signature)),
            evidence_hash: format!("{:#x}", B256::repeat_byte(0xee)),
            observed_at: 1_000,
        }
    }

    #[test]
    fn exact_mint_quorum_and_equivocation_guard() {
        let signers = [signer(3), signer(1), signer(2)];
        let mut collector =
            SettlementCollector::new(domain(), signers.iter().map(Signer::address), 2, 60)
                .expect("collector");
        let intent = B256::repeat_byte(0x11);
        assert!(matches!(
            collector
                .ingest_mint(
                    &mint_message(&signers[0], 50_000),
                    intent,
                    U256::ZERO,
                    1_010
                )
                .expect("first"),
            SettlementIngestOutcome::Accepted { count: 1 }
        ));
        let ready = collector
            .ingest_mint(
                &mint_message(&signers[1], 50_000),
                intent,
                U256::ZERO,
                1_010,
            )
            .expect("second");
        assert!(matches!(ready, SettlementIngestOutcome::Ready(_)));
        let error = collector
            .ingest_mint(
                &mint_message(&signers[0], 60_000),
                intent,
                U256::ZERO,
                1_010,
            )
            .expect_err("equivocation");
        assert!(matches!(error, SettlementCollectError::Equivocation { .. }));
    }
}
