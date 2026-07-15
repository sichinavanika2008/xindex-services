//! Exact-quorum collection for independently observed mint/redemption facts.
//!
//! The collector is deliberately untrusted: every response is decoded,
//! low-S/recovery checked, matched to the requested logical round, checked
//! against the active signer allowlist, and grouped by complete EIP-712
//! plaintext. One signer cannot vote for two outcomes of the same leg.

use std::collections::{HashMap, HashSet};

use alloy_primitives::{Address, PrimitiveSignature, B256, U256};
use alloy_sol_types::Eip712Domain;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use xindex_shared::eip712::{
    attestation, attestation_signing_hash, redemption_attestation,
    redemption_attestation_signing_hash, refund_attestation, refund_attestation_signing_hash,
    settlement_context, streamed_settlement, streamed_settlement_signing_hash, SettlementContext,
};
use xindex_shared::settlement_wire::{
    SignedDeliverySettlement, SignedMintSettlement, SignedRefundSettlement,
    SignedStreamedSettlement,
};

/// One exact on-chain attestation payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SettlementPayload {
    /// Mint slot delivery.
    Mint {
        intent_id: B256,
        slot_index: U256,
        attested_amount: U256,
        context: SettlementContext,
    },
    /// Redemption delivery-only outcome.
    Delivery {
        redemption_id: B256,
        leg_index: U256,
        asset_id: B256,
        delivered_amount: U256,
        context: SettlementContext,
    },
    /// Redemption refund-only outcome.
    Refund {
        redemption_id: B256,
        leg_index: U256,
        asset_id: B256,
        refunded_amount: U256,
        context: SettlementContext,
    },
    /// Fully-finalized combined streamed outcome.
    Streamed {
        redemption_id: B256,
        leg_index: U256,
        asset_id: B256,
        delivered_usdt: U256,
        refunded_native: U256,
        context: SettlementContext,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SettlementRound {
    Mint(B256, U256, u64),
    Redemption(B256, U256, u64),
}

/// Exact payload with deterministic, recovered-signer-ordered signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadySettlement {
    /// Complete signed plaintext.
    pub payload: SettlementPayload,
    /// Threshold signatures ordered by recovered address.
    #[serde(with = "signature_vec_serde")]
    pub signatures: Vec<[u8; 65]>,
}

mod signature_vec_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(signatures: &[[u8; 65]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        signatures
            .iter()
            .map(|signature| format!("0x{}", alloy_primitives::hex::encode(signature)))
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 65]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|raw| super::parse_signature(&raw).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// Result of accepting one observer response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementIngestOutcome {
    /// Valid vote below quorum.
    Accepted { count: usize },
    /// Exact signer/payload retry.
    Duplicate { count: usize },
    /// This vote completed an exact quorum.
    Ready(Box<ReadySettlement>),
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
    /// Signed report lifetime has reached its strict deadline.
    #[error("expired observer response: valid until {valid_until}, now {now}")]
    Expired { valid_until: u64, now: u64 },
    /// Signed source chain is not the configured finalized journal chain.
    #[error("wrong settlement source chain: expected {expected}, got {actual}")]
    WrongSourceChain { expected: u64, actual: u64 },
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
    expected_source_chain_id: u64,
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
        expected_source_chain_id: u64,
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
        if expected_source_chain_id == 0 {
            return Err(SettlementCollectError::WrongSourceChain {
                expected: 1,
                actual: 0,
            });
        }
        Ok(Self {
            domain,
            allowed_signers,
            threshold,
            max_response_age_secs,
            expected_source_chain_id,
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
        self.retire_expired_rounds(now);
        let context = self.validate_context(
            &message.evidence_hash,
            message.observed_at,
            message.valid_until,
            message.source_chain_id,
            message.source_block_number,
            &message.source_block_hash,
            message.observation_epoch,
            now,
        )?;
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
            context,
        };
        let digest = attestation_signing_hash(
            &attestation(intent_id, slot_index, attested_amount, context),
            &self.domain,
        );
        self.ingest_verified(
            &payload,
            SettlementRound::Mint(intent_id, slot_index, context.observation_epoch),
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
        self.retire_expired_rounds(now);
        let context = self.validate_context(
            &message.evidence_hash,
            message.observed_at,
            message.valid_until,
            message.source_chain_id,
            message.source_block_number,
            &message.source_block_hash,
            message.observation_epoch,
            now,
        )?;
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
            context,
        };
        let digest = redemption_attestation_signing_hash(
            &redemption_attestation(
                redemption_id,
                leg_index,
                asset_id,
                delivered_amount,
                context,
            ),
            &self.domain,
        );
        self.ingest_verified(
            &payload,
            SettlementRound::Redemption(redemption_id, leg_index, context.observation_epoch),
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
        self.retire_expired_rounds(now);
        let context = self.validate_context(
            &message.evidence_hash,
            message.observed_at,
            message.valid_until,
            message.source_chain_id,
            message.source_block_number,
            &message.source_block_hash,
            message.observation_epoch,
            now,
        )?;
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
            context,
        };
        let digest = refund_attestation_signing_hash(
            &refund_attestation(redemption_id, leg_index, asset_id, refunded_amount, context),
            &self.domain,
        );
        self.ingest_verified(
            &payload,
            SettlementRound::Redemption(redemption_id, leg_index, context.observation_epoch),
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
        self.retire_expired_rounds(now);
        let context = self.validate_context(
            &message.evidence_hash,
            message.observed_at,
            message.valid_until,
            message.source_chain_id,
            message.source_block_number,
            &message.source_block_hash,
            message.observation_epoch,
            now,
        )?;
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
            context,
        };
        let digest = streamed_settlement_signing_hash(
            &streamed_settlement(
                redemption_id,
                leg_index,
                asset_id,
                delivered_usdt,
                refunded_native,
                context,
            ),
            &self.domain,
        );
        self.ingest_verified(
            &payload,
            SettlementRound::Redemption(redemption_id, leg_index, context.observation_epoch),
            &message.signer_address,
            &message.signature,
            digest,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "all flattened signed context fields are validated together"
    )]
    fn validate_context(
        &self,
        evidence_hash: &str,
        observed_at: u64,
        valid_until: u64,
        source_chain_id: u64,
        source_block_number: u64,
        source_block_hash: &str,
        observation_epoch: u64,
        now: u64,
    ) -> Result<SettlementContext, SettlementCollectError> {
        let evidence_hash = parse_b256("evidenceHash", evidence_hash)?;
        let source_block_hash = parse_b256("sourceBlockHash", source_block_hash)?;
        if evidence_hash == B256::ZERO
            || source_block_hash == B256::ZERO
            || source_block_number == 0
        {
            return Err(SettlementCollectError::InvalidField {
                field: "settlementContext",
                reason: "zero".to_string(),
            });
        }
        if source_chain_id != self.expected_source_chain_id {
            return Err(SettlementCollectError::WrongSourceChain {
                expected: self.expected_source_chain_id,
                actual: source_chain_id,
            });
        }
        if observed_at > now {
            return Err(SettlementCollectError::Future { observed_at, now });
        }
        if now >= valid_until {
            return Err(SettlementCollectError::Expired { valid_until, now });
        }
        if valid_until <= observed_at
            || valid_until.saturating_sub(observed_at) > self.max_response_age_secs
        {
            return Err(SettlementCollectError::InvalidField {
                field: "validUntil",
                reason: "outside configured signed lifetime".to_string(),
            });
        }
        if now.saturating_sub(observed_at) > self.max_response_age_secs {
            return Err(SettlementCollectError::Stale { observed_at, now });
        }
        Ok(settlement_context(
            evidence_hash,
            observed_at,
            valid_until,
            U256::from(source_chain_id),
            source_block_number,
            source_block_hash,
            observation_epoch,
        ))
    }

    fn ingest_verified(
        &mut self,
        payload: &SettlementPayload,
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
            if previous != payload {
                return Err(SettlementCollectError::Equivocation { signer: recovered });
            }
        } else {
            self.signer_rounds.insert((round, recovered), *payload);
        }
        let votes = self.votes.entry(*payload).or_default();
        if votes.contains_key(&recovered) {
            if votes.len() >= self.threshold {
                return Ok(SettlementIngestOutcome::Ready(Box::new(ready(
                    payload, votes,
                ))));
            }
            return Ok(SettlementIngestOutcome::Duplicate { count: votes.len() });
        }
        votes.insert(recovered, signature);
        if votes.len() >= self.threshold {
            return Ok(SettlementIngestOutcome::Ready(Box::new(ready(
                payload, votes,
            ))));
        }
        Ok(SettlementIngestOutcome::Accepted { count: votes.len() })
    }

    fn retire_expired_rounds(&mut self, now: u64) {
        self.votes
            .retain(|payload, _| settlement_valid_until(payload) > now);
        self.signer_rounds
            .retain(|_, payload| settlement_valid_until(payload) > now);
    }
}

fn settlement_valid_until(payload: &SettlementPayload) -> u64 {
    match payload {
        SettlementPayload::Mint { context, .. }
        | SettlementPayload::Delivery { context, .. }
        | SettlementPayload::Refund { context, .. }
        | SettlementPayload::Streamed { context, .. } => context.valid_until,
    }
}

fn ready(payload: &SettlementPayload, votes: &HashMap<Address, [u8; 65]>) -> ReadySettlement {
    let mut ordered: Vec<_> = votes
        .iter()
        .map(|(address, signature)| (*address, *signature))
        .collect();
    ordered.sort_by(|(left, _), (right, _)| left.as_slice().cmp(right.as_slice()));
    ReadySettlement {
        payload: *payload,
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

    fn test_context() -> SettlementContext {
        settlement_context(
            B256::repeat_byte(0xee),
            1_000,
            1_060,
            U256::from(31_337u64),
            20_000_000,
            B256::repeat_byte(0xdd),
            0,
        )
    }

    #[test]
    fn settlement_context_is_rejected_before_signature_recovery() {
        let collector =
            SettlementCollector::new(domain(), [Address::repeat_byte(1)], 1, 60, 31_337)
                .expect("collector");
        let evidence = format!("{:#x}", B256::repeat_byte(0xee));
        let source_hash = format!("{:#x}", B256::repeat_byte(0xdd));

        assert_eq!(
            collector.validate_context(
                &evidence,
                1_000,
                1_060,
                31_337,
                20_000_000,
                &source_hash,
                0,
                1_060,
            ),
            Err(SettlementCollectError::Expired {
                valid_until: 1_060,
                now: 1_060,
            })
        );
        assert!(matches!(
            collector.validate_context(
                &evidence,
                1_061,
                1_100,
                31_337,
                20_000_000,
                &source_hash,
                0,
                1_060,
            ),
            Err(SettlementCollectError::Future { .. })
        ));
        assert!(matches!(
            collector.validate_context(
                &evidence,
                1_000,
                1_060,
                1,
                20_000_000,
                &source_hash,
                0,
                1_010,
            ),
            Err(SettlementCollectError::WrongSourceChain { .. })
        ));
    }

    fn mint_message(signer: &PrivateKeySigner, amount: u64) -> SignedMintSettlement {
        let intent = B256::repeat_byte(0x11);
        let digest = attestation_signing_hash(
            &attestation(intent, U256::ZERO, U256::from(amount), test_context()),
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
            valid_until: 1_060,
            source_chain_id: 31_337,
            source_block_number: 20_000_000,
            source_block_hash: format!("{:#x}", B256::repeat_byte(0xdd)),
            observation_epoch: 0,
        }
    }

    #[test]
    fn exact_mint_quorum_and_equivocation_guard() {
        let signers = [signer(3), signer(1), signer(2)];
        let mut collector =
            SettlementCollector::new(domain(), signers.iter().map(Signer::address), 2, 60, 31_337)
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

    #[test]
    fn expired_generation_releases_in_memory_round_identity_at_equality() {
        let allowed = Address::repeat_byte(0x41);
        let mut collector =
            SettlementCollector::new(domain(), [allowed], 1, 120, 31_337).expect("collector");
        let expired = SettlementPayload::Mint {
            intent_id: B256::repeat_byte(0x21),
            slot_index: U256::ZERO,
            attested_amount: U256::from(1u64),
            context: test_context(),
        };
        let mut live_context = test_context();
        live_context.valid_until = 1_120;
        let live = SettlementPayload::Mint {
            intent_id: B256::repeat_byte(0x22),
            slot_index: U256::ZERO,
            attested_amount: U256::from(2u64),
            context: live_context,
        };
        collector
            .votes
            .insert(expired, HashMap::from([(allowed, [0x1b; 65])]));
        collector
            .votes
            .insert(live, HashMap::from([(allowed, [0x1c; 65])]));
        collector.signer_rounds.insert(
            (
                SettlementRound::Mint(B256::repeat_byte(0x21), U256::ZERO, 0),
                allowed,
            ),
            expired,
        );
        collector.signer_rounds.insert(
            (
                SettlementRound::Mint(B256::repeat_byte(0x22), U256::ZERO, 0),
                allowed,
            ),
            live,
        );

        collector.retire_expired_rounds(1_060);

        assert_eq!(collector.votes.len(), 1);
        assert!(collector.votes.contains_key(&live));
        assert_eq!(collector.signer_rounds.len(), 1);
        assert!(collector
            .signer_rounds
            .values()
            .all(|payload| *payload == live));
    }
}
