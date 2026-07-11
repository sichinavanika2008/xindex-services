//! Untrusted k-of-n NAV price signature collection.
//!
//! Price signers independently source and canonicalize their own observations.
//! This collector is only a fan-in: it recover-verifies each EIP-712 signature,
//! requires active configured signers, rejects per-signer equivocation for an
//! `(asset, epoch)`, and groups on the exact complete plaintext. It never
//! averages or chooses a price on behalf of a signer.

use std::collections::{HashMap, HashSet};

use alloy_primitives::{Address, PrimitiveSignature, B256, U256};
use alloy_sol_types::Eip712Domain;
use thiserror::Error;
use xindex_shared::eip712::{price_attestation, price_attestation_signing_hash};
use xindex_shared::price_wire::SignedPriceMessage;

/// Exact four-field plaintext accepted by
/// `PriceAttestationOracle.attestPrice`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PricePayload {
    /// Registry asset id.
    pub asset_id: B256,
    /// Canonicalized WAD price.
    pub price_wad: U256,
    /// Canonicalized raw circulating supply.
    pub supply: U256,
    /// Deterministic unix epoch.
    pub timestamp: u64,
}

/// One exact payload with enough unique, recover-verified signatures to post.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyPrice {
    /// Complete signed plaintext.
    pub payload: PricePayload,
    /// Signatures ordered by recovered signer address for deterministic
    /// calldata and logs. The Solidity contract accepts any order.
    pub signatures: Vec<[u8; 65]>,
}

/// Result of accepting a valid signed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    /// New signature accepted; this exact payload is still below quorum.
    Accepted {
        /// Unique signatures now held for this exact tuple.
        count: usize,
    },
    /// The exact same signer/payload/signature was already held.
    Duplicate {
        /// Unique signatures held for this exact tuple.
        count: usize,
    },
    /// This insertion completed the exact-match quorum.
    Ready(ReadyPrice),
}

/// Fail-closed signed-message validation errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PriceCollectError {
    /// Collector construction received an impossible threshold.
    #[error("threshold {threshold} must be in 1..={signer_count}")]
    InvalidThreshold {
        /// Configured threshold.
        threshold: usize,
        /// Number of unique allowlisted signers.
        signer_count: usize,
    },
    /// A string field could not be decoded to its exact EVM type.
    #[error("invalid {field}: {reason}")]
    InvalidField {
        /// Rejected field.
        field: &'static str,
        /// Decoder error.
        reason: String,
    },
    /// Contract rejects zero prices.
    #[error("zero price")]
    ZeroPrice,
    /// Contract rejects zero supplies.
    #[error("zero supply")]
    ZeroSupply,
    /// Observation is too old to publish safely.
    #[error("stale timestamp {timestamp}; now {now}, max age {max_age_secs}s")]
    Stale {
        /// Signed epoch.
        timestamp: u64,
        /// Collector clock.
        now: u64,
        /// Configured freshness budget.
        max_age_secs: u64,
    },
    /// The contract rejects future timestamps; do the same before storage.
    #[error("future timestamp {timestamp} > now {now}")]
    Future {
        /// Signed epoch.
        timestamp: u64,
        /// Collector clock.
        now: u64,
    },
    /// Signature was not exactly recoverable `r || s || v`.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    /// Claimed signer does not equal EIP-712 recovery.
    #[error("claimed signer {claimed} does not match recovered {recovered}")]
    SignerMismatch {
        /// Wire signer address.
        claimed: Address,
        /// Recovered signer address.
        recovered: Address,
    },
    /// Recovered signer is not in the startup-validated on-chain signer set.
    #[error("signer {0} is not allowlisted")]
    SignerNotAllowed(Address),
    /// A signer produced two different valid plaintexts for one asset/epoch.
    #[error("signer {signer} equivocated for asset {asset_id} epoch {timestamp}")]
    Equivocation {
        /// Recovered signer.
        signer: Address,
        /// Round asset.
        asset_id: B256,
        /// Round epoch.
        timestamp: u64,
    },
}

/// In-memory exact-match collector. Only valid signatures enter its maps, and
/// freshness pruning bounds retained rounds.
#[derive(Debug)]
pub struct PriceCollector {
    domain: Eip712Domain,
    allowed_signers: HashSet<Address>,
    threshold: usize,
    max_age_secs: u64,
    votes: HashMap<PricePayload, HashMap<Address, [u8; 65]>>,
    signer_rounds: HashMap<(B256, u64, Address), PricePayload>,
    queued: HashSet<PricePayload>,
}

impl PriceCollector {
    /// Construct from the signer set that the binary has already checked
    /// against `signerCount`, `threshold`, and `isSigner` on-chain.
    ///
    /// # Errors
    /// [`PriceCollectError::InvalidThreshold`] for zero or an impossible
    /// threshold. Duplicate configured addresses are collapsed before this
    /// check, so duplicates cannot inflate `signer_count`.
    pub fn new(
        domain: Eip712Domain,
        allowed_signers: impl IntoIterator<Item = Address>,
        threshold: usize,
        max_age_secs: u64,
    ) -> Result<Self, PriceCollectError> {
        let allowed_signers: HashSet<Address> = allowed_signers.into_iter().collect();
        if threshold == 0 || threshold > allowed_signers.len() {
            return Err(PriceCollectError::InvalidThreshold {
                threshold,
                signer_count: allowed_signers.len(),
            });
        }
        Ok(Self {
            domain,
            allowed_signers,
            threshold,
            max_age_secs,
            votes: HashMap::new(),
            signer_rounds: HashMap::new(),
            queued: HashSet::new(),
        })
    }

    /// Validate and collect one independently-signed message.
    ///
    /// # Errors
    /// Any malformed/stale/future signature, signer mismatch, inactive signer,
    /// or same-signer equivocation is refused before it can count toward quorum.
    pub fn ingest(
        &mut self,
        message: &SignedPriceMessage,
        now: u64,
    ) -> Result<IngestOutcome, PriceCollectError> {
        self.prune(now);
        let payload = parse_payload(message)?;
        if payload.price_wad.is_zero() {
            return Err(PriceCollectError::ZeroPrice);
        }
        if payload.supply.is_zero() {
            return Err(PriceCollectError::ZeroSupply);
        }
        if payload.timestamp > now {
            return Err(PriceCollectError::Future {
                timestamp: payload.timestamp,
                now,
            });
        }
        if now.saturating_sub(payload.timestamp) > self.max_age_secs {
            return Err(PriceCollectError::Stale {
                timestamp: payload.timestamp,
                now,
                max_age_secs: self.max_age_secs,
            });
        }

        let claimed = parse_address("signerAddress", &message.signer_address)?;
        let signature = parse_signature(&message.signature)?;
        let att = price_attestation(
            payload.asset_id,
            payload.price_wad,
            payload.supply,
            payload.timestamp,
        );
        let digest = price_attestation_signing_hash(&att, &self.domain);
        let parsed = PrimitiveSignature::try_from(signature.as_slice())
            .map_err(|e| PriceCollectError::InvalidSignature(e.to_string()))?;
        if parsed.normalize_s().is_some() {
            return Err(PriceCollectError::InvalidSignature(
                "high-S signature rejected by the on-chain OpenZeppelin ECDSA verifier".to_string(),
            ));
        }
        let recovered = parsed
            .recover_address_from_prehash(&digest)
            .map_err(|e| PriceCollectError::InvalidSignature(e.to_string()))?;
        if recovered != claimed {
            return Err(PriceCollectError::SignerMismatch { claimed, recovered });
        }
        if !self.allowed_signers.contains(&recovered) {
            return Err(PriceCollectError::SignerNotAllowed(recovered));
        }

        let round_key = (payload.asset_id, payload.timestamp, recovered);
        if let Some(previous) = self.signer_rounds.get(&round_key) {
            if previous != &payload {
                return Err(PriceCollectError::Equivocation {
                    signer: recovered,
                    asset_id: payload.asset_id,
                    timestamp: payload.timestamp,
                });
            }
        } else {
            self.signer_rounds.insert(round_key, payload);
        }

        let payload_votes = self.votes.entry(payload).or_default();
        if let Some(previous_signature) = payload_votes.get(&recovered) {
            if previous_signature != &signature {
                // A second valid ECDSA encoding over the same digest is not an
                // extra vote. Treat it as a duplicate and retain the first
                // deterministic calldata representation.
                return Ok(IngestOutcome::Duplicate {
                    count: payload_votes.len(),
                });
            }
            return Ok(IngestOutcome::Duplicate {
                count: payload_votes.len(),
            });
        }
        payload_votes.insert(recovered, signature);

        if payload_votes.len() >= self.threshold && self.queued.insert(payload) {
            let mut ordered: Vec<(Address, [u8; 65])> = payload_votes
                .iter()
                .map(|(address, sig)| (*address, *sig))
                .collect();
            ordered.sort_by(|(a, _), (b, _)| a.as_slice().cmp(b.as_slice()));
            return Ok(IngestOutcome::Ready(ReadyPrice {
                payload,
                signatures: ordered.into_iter().map(|(_, sig)| sig).collect(),
            }));
        }

        Ok(IngestOutcome::Accepted {
            count: payload_votes.len(),
        })
    }

    fn prune(&mut self, now: u64) {
        let cutoff = now.saturating_sub(self.max_age_secs);
        self.votes.retain(|payload, _| payload.timestamp >= cutoff);
        self.signer_rounds
            .retain(|(_, timestamp, _), _| *timestamp >= cutoff);
        self.queued.retain(|payload| payload.timestamp >= cutoff);
    }
}

fn parse_payload(message: &SignedPriceMessage) -> Result<PricePayload, PriceCollectError> {
    let asset_id =
        message
            .asset_id
            .parse::<B256>()
            .map_err(|e| PriceCollectError::InvalidField {
                field: "assetId",
                reason: e.to_string(),
            })?;
    let price_wad = U256::from_str_radix(&message.price_wad, 10).map_err(|e| {
        PriceCollectError::InvalidField {
            field: "priceWad",
            reason: e.to_string(),
        }
    })?;
    let supply =
        U256::from_str_radix(&message.supply, 10).map_err(|e| PriceCollectError::InvalidField {
            field: "supply",
            reason: e.to_string(),
        })?;
    Ok(PricePayload {
        asset_id,
        price_wad,
        supply,
        timestamp: message.timestamp,
    })
}

fn parse_address(field: &'static str, raw: &str) -> Result<Address, PriceCollectError> {
    raw.parse::<Address>()
        .map_err(|e| PriceCollectError::InvalidField {
            field,
            reason: e.to_string(),
        })
}

fn parse_signature(raw: &str) -> Result<[u8; 65], PriceCollectError> {
    let bytes = alloy_primitives::hex::decode(raw.strip_prefix("0x").unwrap_or(raw))
        .map_err(|e| PriceCollectError::InvalidSignature(e.to_string()))?;
    let signature: [u8; 65] = bytes.try_into().map_err(|v: Vec<u8>| {
        PriceCollectError::InvalidSignature(format!("expected 65 bytes, got {}", v.len()))
    })?;
    if !matches!(signature[64], 27 | 28) {
        return Err(PriceCollectError::InvalidSignature(format!(
            "v must be 27 or 28, got {}",
            signature[64]
        )));
    }
    Ok(signature)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]

    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::{Signer, SignerSync};
    use xindex_shared::eip712::price_oracle_domain;

    use super::*;

    fn signer(seed: u8) -> PrivateKeySigner {
        format!("0x{}", format!("{seed:02x}").repeat(32))
            .parse()
            .expect("test key")
    }

    fn domain() -> Eip712Domain {
        price_oracle_domain(31_337, Address::repeat_byte(0xcc))
    }

    fn signed_message(
        signer: &PrivateKeySigner,
        price: u64,
        supply: u64,
        timestamp: u64,
    ) -> SignedPriceMessage {
        let asset_id = B256::repeat_byte(0xab);
        let att = price_attestation(asset_id, U256::from(price), U256::from(supply), timestamp);
        let digest = price_attestation_signing_hash(&att, &domain());
        let sig = signer.sign_hash_sync(&digest).expect("sign").as_bytes();
        SignedPriceMessage {
            asset_id: format!("{asset_id:#x}"),
            price_wad: price.to_string(),
            supply: supply.to_string(),
            timestamp,
            signer_address: format!("{:#x}", signer.address()),
            signature: format!("0x{}", alloy_primitives::hex::encode(sig)),
        }
    }

    fn collector(signers: &[PrivateKeySigner], threshold: usize) -> PriceCollector {
        PriceCollector::new(
            domain(),
            signers.iter().map(Signer::address),
            threshold,
            300,
        )
        .expect("collector")
    }

    #[test]
    fn exact_tuple_quorum_includes_supply_and_sorts_signers() {
        let signers = [signer(3), signer(1), signer(2)];
        let mut collector = collector(&signers, 2);
        let first = signed_message(&signers[0], 43_210, 21_000_000, 1_000);
        let second = signed_message(&signers[1], 43_210, 21_000_000, 1_000);
        assert_eq!(
            collector.ingest(&first, 1_010).expect("first"),
            IngestOutcome::Accepted { count: 1 }
        );
        let outcome = collector.ingest(&second, 1_010).expect("second");
        assert!(matches!(&outcome, IngestOutcome::Ready(_)));
        let IngestOutcome::Ready(ready) = outcome else {
            return;
        };
        assert_eq!(ready.payload.supply, U256::from(21_000_000u64));
        assert_eq!(ready.signatures.len(), 2);

        let digest = price_attestation_signing_hash(
            &price_attestation(
                ready.payload.asset_id,
                ready.payload.price_wad,
                ready.payload.supply,
                ready.payload.timestamp,
            ),
            &domain(),
        );
        let recovered: Vec<Address> = ready
            .signatures
            .iter()
            .map(|sig| {
                PrimitiveSignature::try_from(sig.as_slice())
                    .expect("sig")
                    .recover_address_from_prehash(&digest)
                    .expect("recover")
            })
            .collect();
        assert!(recovered
            .windows(2)
            .all(|w| w[0].as_slice() < w[1].as_slice()));
    }

    #[test]
    fn close_but_not_exact_prices_do_not_mix() {
        let signers = [signer(1), signer(2), signer(3)];
        let mut collector = collector(&signers, 2);
        let a = signed_message(&signers[0], 43_210, 21_000_000, 1_000);
        let b = signed_message(&signers[1], 43_211, 21_000_000, 1_000);
        assert_eq!(
            collector.ingest(&a, 1_010).expect("a"),
            IngestOutcome::Accepted { count: 1 }
        );
        assert_eq!(
            collector.ingest(&b, 1_010).expect("b"),
            IngestOutcome::Accepted { count: 1 }
        );
    }

    #[test]
    fn same_signer_different_supply_same_round_is_equivocation() {
        let signers = [signer(1), signer(2), signer(3)];
        let mut collector = collector(&signers, 2);
        let a = signed_message(&signers[0], 43_210, 21_000_000, 1_000);
        let b = signed_message(&signers[0], 43_210, 20_999_999, 1_000);
        collector.ingest(&a, 1_010).expect("first");
        assert!(matches!(
            collector.ingest(&b, 1_010),
            Err(PriceCollectError::Equivocation { .. })
        ));
    }

    #[test]
    fn tamper_and_unallowlisted_signer_fail() {
        let signers = [signer(1), signer(2)];
        let outsider = signer(3);
        let mut collector = collector(&signers, 2);
        let mut tampered = signed_message(&signers[0], 43_210, 21_000_000, 1_000);
        tampered.supply = "1".to_string();
        assert!(matches!(
            collector.ingest(&tampered, 1_010),
            Err(PriceCollectError::SignerMismatch { .. })
        ));
        let outside = signed_message(&outsider, 43_210, 21_000_000, 1_000);
        assert!(matches!(
            collector.ingest(&outside, 1_010),
            Err(PriceCollectError::SignerNotAllowed(_))
        ));
    }

    #[test]
    fn stale_future_and_duplicate_fail_or_do_not_double_count() {
        let signers = [signer(1), signer(2)];
        let mut collector = collector(&signers, 2);
        let msg = signed_message(&signers[0], 43_210, 21_000_000, 1_000);
        assert!(matches!(
            collector.ingest(&msg, 1_301),
            Err(PriceCollectError::Stale { .. })
        ));
        assert!(matches!(
            collector.ingest(&msg, 999),
            Err(PriceCollectError::Future { .. })
        ));
        assert_eq!(
            collector.ingest(&msg, 1_010).expect("first"),
            IngestOutcome::Accepted { count: 1 }
        );
        assert_eq!(
            collector.ingest(&msg, 1_010).expect("duplicate"),
            IngestOutcome::Duplicate { count: 1 }
        );
    }
}
