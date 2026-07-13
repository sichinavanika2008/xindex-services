//! Untrusted exact-match collectors for `ThorchainVaultRegistry` signatures.
//!
//! The collector never creates or modifies a report. It parses every field,
//! recomputes the exact EIP-712 digest, enforces low-S recovery against the
//! startup-validated on-chain roster, rejects same-signer equivocation, and
//! emits a deterministic signature vector only when one byte-identical payload
//! reaches quorum.

use std::collections::{HashMap, HashSet};

use alloy_primitives::{Address, PrimitiveSignature, B256, U256};
use alloy_sol_types::Eip712Domain;
use thiserror::Error;
use xindex_shared::eip712::{
    inbound_state, inbound_state_signing_hash, quote_authorization,
    quote_authorization_signing_hash,
};
use xindex_shared::registry_wire::{SignedInboundStateMessage, SignedQuoteAuthorizationMessage};

/// Exact inbound plaintext accepted by `attestInbound`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InboundPayload {
    pub vault: Address,
    pub router: Address,
    pub pause_flags: u8,
    pub observed_at: u64,
    pub valid_until: u64,
    pub sequence: u64,
    pub source_hash: B256,
}

/// Exact quote plaintext consumed by `consumeQuoteAuthorization`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuotePayload {
    pub adapter: Address,
    pub index_token: Address,
    pub originator: Address,
    pub funding_token: Address,
    pub target_token: Address,
    pub amount_in: U256,
    pub custody_hash: B256,
    pub inbound_state_hash: B256,
    pub memo_hash: B256,
    pub dispatch_deadline: u64,
    pub quote_nonce: u64,
    pub quote_hash: B256,
}

/// Quorum-ready inbound report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyInbound {
    pub payload: InboundPayload,
    pub signatures: Vec<[u8; 65]>,
}

/// Quorum-ready quote authorization. This is returned to the acquiring caller;
/// it is consumed atomically inside the adapter call rather than posted alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyQuote {
    pub payload: QuotePayload,
    pub signatures: Vec<[u8; 65]>,
}

/// Result of collecting a valid signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectOutcome<T> {
    Accepted { count: usize },
    Duplicate { count: usize },
    Ready(T),
}

/// Fail-closed registry collection errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryCollectError {
    #[error("threshold {threshold} must be in 1..={signer_count}")]
    InvalidThreshold {
        threshold: usize,
        signer_count: usize,
    },
    #[error("threshold {threshold} is below strict majority {majority}")]
    BelowMajority { threshold: usize, majority: usize },
    #[error("invalid {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("inbound report is stale or not currently valid")]
    StaleInbound,
    #[error("quote is expired")]
    ExpiredQuote,
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("claimed signer {claimed} does not match recovered {recovered}")]
    SignerMismatch {
        claimed: Address,
        recovered: Address,
    },
    #[error("signer {0} is not allowlisted")]
    SignerNotAllowed(Address),
    #[error("signer {signer} equivocated for {identity}")]
    Equivocation { signer: Address, identity: String },
}

/// Both registry report-family collectors sharing the exact same on-chain
/// signer roster and threshold.
#[derive(Debug)]
pub struct RegistryCollector {
    domain: Eip712Domain,
    allowed_signers: HashSet<Address>,
    threshold: usize,
    inbound_votes: HashMap<InboundPayload, HashMap<Address, [u8; 65]>>,
    inbound_rounds: HashMap<(u64, Address), InboundPayload>,
    inbound_queued: HashSet<InboundPayload>,
    quote_votes: HashMap<QuotePayload, HashMap<Address, [u8; 65]>>,
    quote_rounds: HashMap<(Address, u64, Address), QuotePayload>,
    quote_queued: HashSet<QuotePayload>,
}

impl RegistryCollector {
    /// Construct from a roster already compared to `signerCount`, `threshold`
    /// and `isSigner` on-chain. Strict majority is rechecked locally.
    ///
    /// # Errors
    /// Returns [`RegistryCollectError`] if the roster/threshold cannot form a
    /// strict-majority quorum.
    pub fn new(
        domain: Eip712Domain,
        allowed_signers: impl IntoIterator<Item = Address>,
        threshold: usize,
    ) -> Result<Self, RegistryCollectError> {
        let allowed_signers: HashSet<Address> = allowed_signers.into_iter().collect();
        if threshold == 0 || threshold > allowed_signers.len() {
            return Err(RegistryCollectError::InvalidThreshold {
                threshold,
                signer_count: allowed_signers.len(),
            });
        }
        let majority = allowed_signers.len() / 2 + 1;
        if threshold < majority {
            return Err(RegistryCollectError::BelowMajority {
                threshold,
                majority,
            });
        }
        Ok(Self {
            domain,
            allowed_signers,
            threshold,
            inbound_votes: HashMap::new(),
            inbound_rounds: HashMap::new(),
            inbound_queued: HashSet::new(),
            quote_votes: HashMap::new(),
            quote_rounds: HashMap::new(),
            quote_queued: HashSet::new(),
        })
    }

    /// Recover-verify and collect one inbound signature.
    ///
    /// # Errors
    /// Returns [`RegistryCollectError`] for malformed/stale fields, a bad or
    /// unapproved signature, or same-signer equivocation.
    pub fn ingest_inbound(
        &mut self,
        message: &SignedInboundStateMessage,
        now: u64,
    ) -> Result<CollectOutcome<ReadyInbound>, RegistryCollectError> {
        let payload = parse_inbound(message)?;
        if payload.observed_at == 0
            || payload.observed_at > now
            || now.saturating_sub(payload.observed_at) > 120
            || payload.valid_until <= now
            || payload.valid_until <= payload.observed_at
            || payload.valid_until - payload.observed_at > 600
        {
            return Err(RegistryCollectError::StaleInbound);
        }
        let typed = inbound_state(
            payload.vault,
            payload.router,
            payload.pause_flags,
            payload.observed_at,
            payload.valid_until,
            payload.sequence,
            payload.source_hash,
        );
        let digest = inbound_state_signing_hash(&typed, &self.domain);
        let signer = self.recover(&message.signer_address, &message.signature, digest)?;
        let round = (payload.sequence, signer);
        if let Some(previous) = self.inbound_rounds.get(&round) {
            if previous != &payload {
                return Err(RegistryCollectError::Equivocation {
                    signer,
                    identity: format!("inbound sequence {}", payload.sequence),
                });
            }
        } else {
            self.inbound_rounds.insert(round, payload);
        }
        let signature = parse_signature(&message.signature)?;
        let votes = self.inbound_votes.entry(payload).or_default();
        if votes.insert(signer, signature).is_some() {
            return Ok(CollectOutcome::Duplicate { count: votes.len() });
        }
        if votes.len() >= self.threshold && self.inbound_queued.insert(payload) {
            return Ok(CollectOutcome::Ready(ReadyInbound {
                payload,
                signatures: ordered_signatures(votes),
            }));
        }
        Ok(CollectOutcome::Accepted { count: votes.len() })
    }

    /// Recover-verify and collect one exact quote signature.
    ///
    /// # Errors
    /// Returns [`RegistryCollectError`] for malformed/expired fields, a bad or
    /// unapproved signature, or same-signer equivocation.
    pub fn ingest_quote(
        &mut self,
        message: &SignedQuoteAuthorizationMessage,
        now: u64,
    ) -> Result<CollectOutcome<ReadyQuote>, RegistryCollectError> {
        let payload = parse_quote(message)?;
        if payload.dispatch_deadline <= now {
            return Err(RegistryCollectError::ExpiredQuote);
        }
        let typed = quote_authorization(
            payload.adapter,
            payload.index_token,
            payload.originator,
            payload.funding_token,
            payload.target_token,
            payload.amount_in,
            payload.custody_hash,
            payload.inbound_state_hash,
            payload.memo_hash,
            payload.dispatch_deadline,
            payload.quote_nonce,
            payload.quote_hash,
        );
        let digest = quote_authorization_signing_hash(&typed, &self.domain);
        let signer = self.recover(&message.signer_address, &message.signature, digest)?;
        let round = (payload.originator, payload.quote_nonce, signer);
        if let Some(previous) = self.quote_rounds.get(&round) {
            if previous != &payload {
                return Err(RegistryCollectError::Equivocation {
                    signer,
                    identity: format!(
                        "quote originator {:#x} nonce {}",
                        payload.originator, payload.quote_nonce
                    ),
                });
            }
        } else {
            self.quote_rounds.insert(round, payload);
        }
        let signature = parse_signature(&message.signature)?;
        let votes = self.quote_votes.entry(payload).or_default();
        if votes.insert(signer, signature).is_some() {
            return Ok(CollectOutcome::Duplicate { count: votes.len() });
        }
        if votes.len() >= self.threshold && self.quote_queued.insert(payload) {
            return Ok(CollectOutcome::Ready(ReadyQuote {
                payload,
                signatures: ordered_signatures(votes),
            }));
        }
        Ok(CollectOutcome::Accepted { count: votes.len() })
    }

    fn recover(
        &self,
        claimed_raw: &str,
        signature_raw: &str,
        digest: B256,
    ) -> Result<Address, RegistryCollectError> {
        let claimed = parse_address("signerAddress", claimed_raw)?;
        let signature = parse_signature(signature_raw)?;
        let parsed = PrimitiveSignature::try_from(signature.as_slice())
            .map_err(|error| RegistryCollectError::InvalidSignature(error.to_string()))?;
        if parsed.normalize_s().is_some() {
            return Err(RegistryCollectError::InvalidSignature(
                "high-S signature rejected by OpenZeppelin ECDSA".to_string(),
            ));
        }
        let recovered = parsed
            .recover_address_from_prehash(&digest)
            .map_err(|error| RegistryCollectError::InvalidSignature(error.to_string()))?;
        if recovered != claimed {
            return Err(RegistryCollectError::SignerMismatch { claimed, recovered });
        }
        if !self.allowed_signers.contains(&recovered) {
            return Err(RegistryCollectError::SignerNotAllowed(recovered));
        }
        Ok(recovered)
    }
}

fn parse_inbound(
    message: &SignedInboundStateMessage,
) -> Result<InboundPayload, RegistryCollectError> {
    let payload = InboundPayload {
        vault: parse_address("vault", &message.vault)?,
        router: parse_address("router", &message.router)?,
        pause_flags: message.pause_flags,
        observed_at: message.observed_at,
        valid_until: message.valid_until,
        sequence: message.sequence,
        source_hash: parse_b256("sourceHash", &message.source_hash)?,
    };
    if payload.vault == Address::ZERO
        || payload.router == Address::ZERO
        || payload.source_hash == B256::ZERO
        || payload.pause_flags & !0x7f != 0
        || payload.sequence == 0
    {
        return Err(RegistryCollectError::InvalidField {
            field: "inboundState",
            reason: "zero required field, unknown pause bit, or zero sequence".to_string(),
        });
    }
    Ok(payload)
}

fn parse_quote(
    message: &SignedQuoteAuthorizationMessage,
) -> Result<QuotePayload, RegistryCollectError> {
    let payload = QuotePayload {
        adapter: parse_address("adapter", &message.adapter)?,
        index_token: parse_address("indexToken", &message.index_token)?,
        originator: parse_address("originator", &message.originator)?,
        funding_token: parse_address("fundingToken", &message.funding_token)?,
        target_token: parse_address("targetToken", &message.target_token)?,
        amount_in: U256::from_str_radix(&message.amount_in, 10).map_err(|error| {
            RegistryCollectError::InvalidField {
                field: "amountIn",
                reason: error.to_string(),
            }
        })?,
        custody_hash: parse_b256("custodyHash", &message.custody_hash)?,
        inbound_state_hash: parse_b256("inboundStateHash", &message.inbound_state_hash)?,
        memo_hash: parse_b256("memoHash", &message.memo_hash)?,
        dispatch_deadline: message.dispatch_deadline,
        quote_nonce: message.quote_nonce,
        quote_hash: parse_b256("quoteHash", &message.quote_hash)?,
    };
    if [
        payload.adapter,
        payload.index_token,
        payload.originator,
        payload.funding_token,
        payload.target_token,
    ]
    .contains(&Address::ZERO)
        || payload.amount_in.is_zero()
        || payload.custody_hash == B256::ZERO
        || payload.inbound_state_hash == B256::ZERO
        || payload.memo_hash == B256::ZERO
        || payload.quote_hash == B256::ZERO
        || payload.quote_nonce == 0
    {
        return Err(RegistryCollectError::InvalidField {
            field: "quoteAuthorization",
            reason: "zero required field".to_string(),
        });
    }
    Ok(payload)
}

fn parse_address(field: &'static str, raw: &str) -> Result<Address, RegistryCollectError> {
    raw.parse()
        .map_err(
            |error: alloy_primitives::hex::FromHexError| RegistryCollectError::InvalidField {
                field,
                reason: error.to_string(),
            },
        )
}

fn parse_b256(field: &'static str, raw: &str) -> Result<B256, RegistryCollectError> {
    raw.parse()
        .map_err(
            |error: alloy_primitives::hex::FromHexError| RegistryCollectError::InvalidField {
                field,
                reason: error.to_string(),
            },
        )
}

fn parse_signature(raw: &str) -> Result<[u8; 65], RegistryCollectError> {
    let bytes = alloy_primitives::hex::decode(raw.strip_prefix("0x").unwrap_or(raw))
        .map_err(|error| RegistryCollectError::InvalidSignature(error.to_string()))?;
    let signature: [u8; 65] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        RegistryCollectError::InvalidSignature(format!("expected 65 bytes, got {}", bytes.len()))
    })?;
    if !matches!(signature[64], 27 | 28) {
        return Err(RegistryCollectError::InvalidSignature(format!(
            "v must be 27 or 28, got {}",
            signature[64]
        )));
    }
    Ok(signature)
}

fn ordered_signatures(votes: &HashMap<Address, [u8; 65]>) -> Vec<[u8; 65]> {
    let mut ordered: Vec<_> = votes
        .iter()
        .map(|(address, sig)| (*address, *sig))
        .collect();
    ordered.sort_by(|(left, _), (right, _)| left.as_slice().cmp(right.as_slice()));
    ordered
        .into_iter()
        .map(|(_, signature)| signature)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xindex_shared::eip712::thorchain_registry_domain;

    #[test]
    fn collector_requires_strict_majority() {
        let signers = [
            Address::repeat_byte(1),
            Address::repeat_byte(2),
            Address::repeat_byte(3),
            Address::repeat_byte(4),
            Address::repeat_byte(5),
        ];
        let domain = thorchain_registry_domain(1, Address::repeat_byte(0xcc));
        assert!(matches!(
            RegistryCollector::new(domain.clone(), signers, 2),
            Err(RegistryCollectError::BelowMajority {
                threshold: 2,
                majority: 3
            })
        ));
        assert!(RegistryCollector::new(domain, signers, 3).is_ok());
    }

    #[test]
    fn parser_rejects_zero_and_unknown_inbound_fields_without_recovery() {
        let message = SignedInboundStateMessage {
            vault: format!("{:#x}", Address::ZERO),
            router: format!("{:#x}", Address::repeat_byte(2)),
            pause_flags: 0x80,
            observed_at: 1,
            valid_until: 2,
            sequence: 0,
            source_hash: format!("{:#x}", B256::ZERO),
            signer_address: format!("{:#x}", Address::repeat_byte(3)),
            signature: format!("0x{}", "00".repeat(65)),
        };
        assert!(parse_inbound(&message).is_err());
    }
}
