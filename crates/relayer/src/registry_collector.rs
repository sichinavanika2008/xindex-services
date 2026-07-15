//! Untrusted exact-match collectors for `ThorchainVaultRegistry` signatures.
//!
//! The collector never creates or modifies a report. It parses every field,
//! recomputes the exact EIP-712 digest, enforces low-S recovery against the
//! startup-validated on-chain roster, rejects same-signer equivocation, and
//! emits a deterministic signature vector only when one byte-identical payload
//! reaches quorum.

use std::collections::{BTreeMap, HashMap, HashSet};

use alloy_primitives::{Address, PrimitiveSignature, B256, U256};
use alloy_sol_types::Eip712Domain;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use xindex_shared::eip712::{
    inbound_state, inbound_state_signing_hash, quote_authorization,
    quote_authorization_signing_hash,
};
use xindex_shared::registry_wire::{SignedInboundStateMessage, SignedQuoteAuthorizationMessage};

/// Exact inbound plaintext accepted by `attestInbound`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyInbound {
    pub payload: InboundPayload,
    #[serde(with = "signature_vec_serde")]
    pub signatures: Vec<[u8; 65]>,
}

/// Quorum-ready quote authorization. This is returned to the acquiring caller;
/// it is consumed atomically inside the adapter call rather than posted alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyQuote {
    pub payload: QuotePayload,
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
    #[error("invalid collector limits: {0}")]
    InvalidLimits(&'static str),
    #[error("{family} collector capacity exceeded for {scope}")]
    CapacityExceeded {
        family: &'static str,
        scope: &'static str,
    },
}

/// Hard steady-state limits for incomplete registry rounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryCollectorLimits {
    pub max_active_inbound_payloads: usize,
    pub max_active_quote_payloads: usize,
    pub max_rounds_per_signer: usize,
}

impl Default for RegistryCollectorLimits {
    fn default() -> Self {
        Self {
            max_active_inbound_payloads: 64,
            max_active_quote_payloads: 256,
            max_rounds_per_signer: 32,
        }
    }
}

/// Observable active-state counts used by tests and process metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryCollectorStats {
    pub inbound_payloads: usize,
    pub inbound_rounds: usize,
    pub inbound_queued: usize,
    pub quote_payloads: usize,
    pub quote_rounds: usize,
    pub quote_queued: usize,
}

/// Both registry report-family collectors sharing the exact same on-chain
/// signer roster and threshold.
#[derive(Debug)]
pub struct RegistryCollector {
    domain: Eip712Domain,
    allowed_signers: HashSet<Address>,
    threshold: usize,
    limits: RegistryCollectorLimits,
    inbound_votes: HashMap<InboundPayload, HashMap<Address, [u8; 65]>>,
    inbound_rounds: HashMap<(u64, Address), InboundPayload>,
    inbound_queued: HashSet<InboundPayload>,
    inbound_expiry: BTreeMap<u64, HashSet<InboundPayload>>,
    inbound_round_count: HashMap<Address, usize>,
    quote_votes: HashMap<QuotePayload, HashMap<Address, [u8; 65]>>,
    quote_rounds: HashMap<(Address, u64, Address), QuotePayload>,
    quote_queued: HashSet<QuotePayload>,
    quote_expiry: BTreeMap<u64, HashSet<QuotePayload>>,
    quote_round_count: HashMap<Address, usize>,
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
        Self::with_limits(
            domain,
            allowed_signers,
            threshold,
            RegistryCollectorLimits::default(),
        )
    }

    /// Construct with explicit active-round limits. Intended for focused
    /// tests and reviewed production profiles.
    ///
    /// # Errors
    /// The same roster errors as [`Self::new`], plus zero limits.
    pub fn with_limits(
        domain: Eip712Domain,
        allowed_signers: impl IntoIterator<Item = Address>,
        threshold: usize,
        limits: RegistryCollectorLimits,
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
        if limits.max_active_inbound_payloads == 0
            || limits.max_active_quote_payloads == 0
            || limits.max_rounds_per_signer == 0
        {
            return Err(RegistryCollectError::InvalidLimits(
                "all active-round limits must be non-zero",
            ));
        }
        Ok(Self {
            domain,
            allowed_signers,
            threshold,
            limits,
            inbound_votes: HashMap::new(),
            inbound_rounds: HashMap::new(),
            inbound_queued: HashSet::new(),
            inbound_expiry: BTreeMap::new(),
            inbound_round_count: HashMap::new(),
            quote_votes: HashMap::new(),
            quote_rounds: HashMap::new(),
            quote_queued: HashSet::new(),
            quote_expiry: BTreeMap::new(),
            quote_round_count: HashMap::new(),
        })
    }

    /// Current bounded state counts.
    #[must_use]
    pub fn stats(&self) -> RegistryCollectorStats {
        RegistryCollectorStats {
            inbound_payloads: self.inbound_votes.len(),
            inbound_rounds: self.inbound_rounds.len(),
            inbound_queued: self.inbound_queued.len(),
            quote_payloads: self.quote_votes.len(),
            quote_rounds: self.quote_rounds.len(),
            quote_queued: self.quote_queued.len(),
        }
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
        self.retire_expired_rounds(now);
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
        let (signer, signature) =
            self.recover(&message.signer_address, &message.signature, digest)?;
        let round = (payload.sequence, signer);
        if let Some(previous) = self.inbound_rounds.get(&round) {
            if previous != &payload {
                return Err(RegistryCollectError::Equivocation {
                    signer,
                    identity: format!("inbound sequence {}", payload.sequence),
                });
            }
        } else {
            if self
                .inbound_round_count
                .get(&signer)
                .copied()
                .unwrap_or_default()
                >= self.limits.max_rounds_per_signer
            {
                return Err(RegistryCollectError::CapacityExceeded {
                    family: "inbound",
                    scope: "signer",
                });
            }
            if !self.inbound_votes.contains_key(&payload)
                && self.inbound_votes.len() >= self.limits.max_active_inbound_payloads
            {
                return Err(RegistryCollectError::CapacityExceeded {
                    family: "inbound",
                    scope: "global",
                });
            }
            self.inbound_rounds.insert(round, payload);
            *self.inbound_round_count.entry(signer).or_default() += 1;
        }
        if !self.inbound_votes.contains_key(&payload) {
            self.inbound_expiry
                .entry(payload.valid_until)
                .or_default()
                .insert(payload);
        }
        let votes = self.inbound_votes.entry(payload).or_default();
        let duplicate = votes.insert(signer, signature).is_some();
        if votes.len() >= self.threshold {
            self.inbound_queued.insert(payload);
            return Ok(CollectOutcome::Ready(ReadyInbound {
                payload,
                signatures: ordered_signatures(votes),
            }));
        }
        if duplicate {
            return Ok(CollectOutcome::Duplicate { count: votes.len() });
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
        self.retire_expired_rounds(now);
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
        let (signer, signature) =
            self.recover(&message.signer_address, &message.signature, digest)?;
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
            if self
                .quote_round_count
                .get(&signer)
                .copied()
                .unwrap_or_default()
                >= self.limits.max_rounds_per_signer
            {
                return Err(RegistryCollectError::CapacityExceeded {
                    family: "quote",
                    scope: "signer",
                });
            }
            if !self.quote_votes.contains_key(&payload)
                && self.quote_votes.len() >= self.limits.max_active_quote_payloads
            {
                return Err(RegistryCollectError::CapacityExceeded {
                    family: "quote",
                    scope: "global",
                });
            }
            self.quote_rounds.insert(round, payload);
            *self.quote_round_count.entry(signer).or_default() += 1;
        }
        if !self.quote_votes.contains_key(&payload) {
            self.quote_expiry
                .entry(payload.dispatch_deadline)
                .or_default()
                .insert(payload);
        }
        let votes = self.quote_votes.entry(payload).or_default();
        let duplicate = votes.insert(signer, signature).is_some();
        if votes.len() >= self.threshold {
            self.quote_queued.insert(payload);
            return Ok(CollectOutcome::Ready(ReadyQuote {
                payload,
                signatures: ordered_signatures(votes),
            }));
        }
        if duplicate {
            return Ok(CollectOutcome::Duplicate { count: votes.len() });
        }
        Ok(CollectOutcome::Accepted { count: votes.len() })
    }

    fn recover(
        &self,
        claimed_raw: &str,
        signature_raw: &str,
        digest: B256,
    ) -> Result<(Address, [u8; 65]), RegistryCollectError> {
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
        Ok((recovered, signature))
    }

    fn retire_expired_rounds(&mut self, now: u64) {
        let inbound_expiries: Vec<_> = self
            .inbound_expiry
            .range(..=now)
            .map(|(expiry, _)| *expiry)
            .collect();
        for expiry in inbound_expiries {
            let Some(payloads) = self.inbound_expiry.remove(&expiry) else {
                continue;
            };
            for payload in payloads {
                let signers: Vec<_> = self
                    .inbound_rounds
                    .iter()
                    .filter_map(|((_, signer), candidate)| {
                        (candidate == &payload).then_some(*signer)
                    })
                    .collect();
                for signer in signers {
                    self.inbound_rounds.remove(&(payload.sequence, signer));
                    decrement_count(&mut self.inbound_round_count, signer);
                }
                self.inbound_votes.remove(&payload);
                self.inbound_queued.remove(&payload);
            }
        }

        let quote_expiries: Vec<_> = self
            .quote_expiry
            .range(..=now)
            .map(|(expiry, _)| *expiry)
            .collect();
        for expiry in quote_expiries {
            let Some(payloads) = self.quote_expiry.remove(&expiry) else {
                continue;
            };
            for payload in payloads {
                let signers: Vec<_> = self
                    .quote_rounds
                    .iter()
                    .filter_map(|((_, _, signer), candidate)| {
                        (candidate == &payload).then_some(*signer)
                    })
                    .collect();
                for signer in signers {
                    self.quote_rounds
                        .remove(&(payload.originator, payload.quote_nonce, signer));
                    decrement_count(&mut self.quote_round_count, signer);
                }
                self.quote_votes.remove(&payload);
                self.quote_queued.remove(&payload);
            }
        }
    }
}

fn decrement_count(counts: &mut HashMap<Address, usize>, signer: Address) {
    if let Some(count) = counts.get_mut(&signer) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&signer);
        }
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

/// Decode the complete inbound plaintext without counting its signature.
/// Collector HTTP envelopes use this to bind attached candidate evidence
/// before mutating quorum state.
///
/// # Errors
/// The same field errors as [`RegistryCollector::ingest_inbound`].
pub fn inbound_payload_from_message(
    message: &SignedInboundStateMessage,
) -> Result<InboundPayload, RegistryCollectError> {
    parse_inbound(message)
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

/// Decode the complete quote plaintext without counting its signature.
///
/// # Errors
/// The same field errors as [`RegistryCollector::ingest_quote`].
pub fn quote_payload_from_message(
    message: &SignedQuoteAuthorizationMessage,
) -> Result<QuotePayload, RegistryCollectError> {
    parse_quote(message)
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
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::{Signer, SignerSync};
    use xindex_shared::eip712::thorchain_registry_domain;

    fn signer(seed: u8) -> PrivateKeySigner {
        format!("0x{}", format!("{seed:02x}").repeat(32))
            .parse()
            .expect("test signer")
    }

    fn domain() -> Eip712Domain {
        thorchain_registry_domain(1, Address::repeat_byte(0xcc))
    }

    fn signed_inbound(
        signer: &PrivateKeySigner,
        sequence: u64,
        observed_at: u64,
        valid_until: u64,
    ) -> SignedInboundStateMessage {
        let source_hash = B256::from(U256::from(sequence));
        let typed = inbound_state(
            Address::repeat_byte(2),
            Address::repeat_byte(3),
            0,
            observed_at,
            valid_until,
            sequence,
            source_hash,
        );
        let digest = inbound_state_signing_hash(&typed, &domain());
        let signature = signer.sign_hash_sync(&digest).expect("sign").as_bytes();
        SignedInboundStateMessage {
            vault: format!("{:#x}", Address::repeat_byte(2)),
            router: format!("{:#x}", Address::repeat_byte(3)),
            pause_flags: 0,
            observed_at,
            valid_until,
            sequence,
            source_hash: format!("{source_hash:#x}"),
            signer_address: format!("{:#x}", signer.address()),
            signature: format!("0x{}", alloy_primitives::hex::encode(signature)),
        }
    }

    fn signed_quote(
        signer: &PrivateKeySigner,
        quote_nonce: u64,
        dispatch_deadline: u64,
    ) -> SignedQuoteAuthorizationMessage {
        let quote_hash = B256::from(U256::from(quote_nonce));
        let typed = quote_authorization(
            Address::repeat_byte(2),
            Address::repeat_byte(3),
            Address::repeat_byte(4),
            Address::repeat_byte(5),
            Address::repeat_byte(6),
            U256::from(7u8),
            B256::repeat_byte(8),
            B256::repeat_byte(9),
            B256::repeat_byte(10),
            dispatch_deadline,
            quote_nonce,
            quote_hash,
        );
        let digest = quote_authorization_signing_hash(&typed, &domain());
        let signature = signer.sign_hash_sync(&digest).expect("sign").as_bytes();
        SignedQuoteAuthorizationMessage {
            adapter: format!("{:#x}", Address::repeat_byte(2)),
            index_token: format!("{:#x}", Address::repeat_byte(3)),
            originator: format!("{:#x}", Address::repeat_byte(4)),
            funding_token: format!("{:#x}", Address::repeat_byte(5)),
            target_token: format!("{:#x}", Address::repeat_byte(6)),
            amount_in: "7".to_string(),
            custody_hash: format!("{:#x}", B256::repeat_byte(8)),
            inbound_state_hash: format!("{:#x}", B256::repeat_byte(9)),
            memo_hash: format!("{:#x}", B256::repeat_byte(10)),
            dispatch_deadline,
            quote_nonce,
            quote_hash: format!("{quote_hash:#x}"),
            signer_address: format!("{:#x}", signer.address()),
            signature: format!("0x{}", alloy_primitives::hex::encode(signature)),
        }
    }

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

    #[test]
    fn expired_generations_release_in_memory_round_identities() {
        let signer = Address::repeat_byte(1);
        let domain = thorchain_registry_domain(1, Address::repeat_byte(0xcc));
        let mut collector = RegistryCollector::new(domain, [signer], 1).expect("collector");
        let inbound = InboundPayload {
            vault: Address::repeat_byte(2),
            router: Address::repeat_byte(3),
            pause_flags: 0,
            observed_at: 10,
            valid_until: 20,
            sequence: 7,
            source_hash: B256::repeat_byte(4),
        };
        let quote = QuotePayload {
            adapter: Address::repeat_byte(5),
            index_token: Address::repeat_byte(6),
            originator: Address::repeat_byte(7),
            funding_token: Address::repeat_byte(8),
            target_token: Address::repeat_byte(9),
            amount_in: U256::from(10u8),
            custody_hash: B256::repeat_byte(11),
            inbound_state_hash: B256::repeat_byte(12),
            memo_hash: B256::repeat_byte(13),
            dispatch_deadline: 20,
            quote_nonce: 1,
            quote_hash: B256::repeat_byte(14),
        };
        collector.inbound_rounds.insert((7, signer), inbound);
        collector.inbound_votes.insert(inbound, HashMap::new());
        collector.inbound_queued.insert(inbound);
        collector
            .inbound_expiry
            .entry(20)
            .or_default()
            .insert(inbound);
        collector.inbound_round_count.insert(signer, 1);
        collector
            .quote_rounds
            .insert((quote.originator, 1, signer), quote);
        collector.quote_votes.insert(quote, HashMap::new());
        collector.quote_queued.insert(quote);
        collector.quote_expiry.entry(20).or_default().insert(quote);
        collector.quote_round_count.insert(signer, 1);

        collector.retire_expired_rounds(20);

        assert!(collector.inbound_rounds.is_empty());
        assert!(collector.inbound_votes.is_empty());
        assert!(collector.inbound_queued.is_empty());
        assert!(collector.inbound_expiry.is_empty());
        assert!(collector.inbound_round_count.is_empty());
        assert!(collector.quote_rounds.is_empty());
        assert!(collector.quote_votes.is_empty());
        assert!(collector.quote_queued.is_empty());
        assert!(collector.quote_expiry.is_empty());
        assert!(collector.quote_round_count.is_empty());
    }

    #[test]
    fn ten_thousand_one_vote_rounds_stay_bounded_and_honest_quorum_progresses() {
        let signers = [signer(1), signer(2), signer(3), signer(4), signer(5)];
        let limits = RegistryCollectorLimits {
            max_active_inbound_payloads: 4,
            max_active_quote_payloads: 4,
            max_rounds_per_signer: 2,
        };
        let mut collector = RegistryCollector::with_limits(
            domain(),
            signers.iter().map(Signer::address),
            3,
            limits,
        )
        .expect("collector");

        for sequence in 1..=10_000 {
            let result =
                collector.ingest_inbound(&signed_inbound(&signers[0], sequence, 100, 700), 100);
            if sequence <= 2 {
                assert!(matches!(result, Ok(CollectOutcome::Accepted { count: 1 })));
            } else {
                assert!(matches!(
                    result,
                    Err(RegistryCollectError::CapacityExceeded {
                        family: "inbound",
                        scope: "signer"
                    })
                ));
            }
        }
        let bounded = collector.stats();
        assert_eq!(bounded.inbound_payloads, 2);
        assert_eq!(bounded.inbound_rounds, 2);

        let honest = signed_inbound(&signers[1], 20_000, 100, 700);
        assert!(matches!(
            collector.ingest_inbound(&honest, 100),
            Ok(CollectOutcome::Accepted { count: 1 })
        ));
        let honest = signed_inbound(&signers[2], 20_000, 100, 700);
        assert!(matches!(
            collector.ingest_inbound(&honest, 100),
            Ok(CollectOutcome::Accepted { count: 2 })
        ));
        let honest = signed_inbound(&signers[3], 20_000, 100, 700);
        assert!(matches!(
            collector.ingest_inbound(&honest, 100),
            Ok(CollectOutcome::Ready(_))
        ));
    }

    #[test]
    fn quote_rounds_are_bounded_and_expiry_immediately_releases_capacity() {
        let signer = signer(1);
        let limits = RegistryCollectorLimits {
            max_active_inbound_payloads: 1,
            max_active_quote_payloads: 2,
            max_rounds_per_signer: 2,
        };
        let mut collector = RegistryCollector::with_limits(domain(), [signer.address()], 1, limits)
            .expect("collector");
        assert!(matches!(
            collector.ingest_quote(&signed_quote(&signer, 1, 110), 100),
            Ok(CollectOutcome::Ready(_))
        ));
        assert!(matches!(
            collector.ingest_quote(&signed_quote(&signer, 2, 120), 100),
            Ok(CollectOutcome::Ready(_))
        ));
        assert!(matches!(
            collector.ingest_quote(&signed_quote(&signer, 3, 130), 100),
            Err(RegistryCollectError::CapacityExceeded {
                family: "quote",
                scope: "signer"
            })
        ));

        // Exact expiry retires nonce 1 through the expiry index before quota
        // evaluation, so a fresh round can progress without a full-map leak.
        assert!(matches!(
            collector.ingest_quote(&signed_quote(&signer, 3, 130), 110),
            Ok(CollectOutcome::Ready(_))
        ));
        let stats = collector.stats();
        assert_eq!(stats.quote_payloads, 2);
        assert_eq!(stats.quote_rounds, 2);
    }

    #[test]
    fn ready_quorum_is_repeatable_until_durable_enqueue_succeeds() {
        let signers = [signer(1), signer(2), signer(3)];
        let mut collector =
            RegistryCollector::new(domain(), signers.iter().map(Signer::address), 3)
                .expect("collector");
        for signer in &signers[..2] {
            assert!(matches!(
                collector.ingest_inbound(&signed_inbound(signer, 1, 100, 200), 100),
                Ok(CollectOutcome::Accepted { .. })
            ));
        }
        let third = signed_inbound(&signers[2], 1, 100, 200);
        assert!(matches!(
            collector.ingest_inbound(&third, 100),
            Ok(CollectOutcome::Ready(_))
        ));
        assert!(matches!(
            collector.ingest_inbound(&third, 100),
            Ok(CollectOutcome::Ready(_))
        ));
    }
}
