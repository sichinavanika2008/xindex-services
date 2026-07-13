//! Exact, durable signing core for `ThorchainVaultRegistry` reports.
//!
//! Callers must independently reconstruct the expected inbound state or quote
//! from their own sources and pass it as the validation context. This module
//! compares every signed field, computes the EIP-712 digest locally, reserves
//! the identity in `SQLite` **before** HSM use, recover-verifies the HSM result,
//! commits the signature durably, and only then returns publishable bytes.

use alloy_primitives::{Address, PrimitiveSignature, B256, U256};
use alloy_sol_types::Eip712Domain;
use thiserror::Error;
use xindex_shared::eip712::{
    inbound_state, inbound_state_signing_hash, quote_authorization,
    quote_authorization_signing_hash, InboundState, QuoteAuthorization,
};
use xindex_shared::registry_state::{
    QuoteNonceReservation, RegistryStateError, SignatureReservation, SqliteRegistryState,
};
use xindex_shared::registry_wire::{SignedInboundStateMessage, SignedQuoteAuthorizationMessage};

use crate::web3signer::{HsmDigestSigner, HsmError};

/// On-chain maximum observation age in seconds.
pub const MAX_OBSERVATION_AGE_SECS: u64 = 120;
/// On-chain maximum report lifetime in seconds.
pub const MAX_REPORT_LIFETIME_SECS: u64 = 600;
/// All currently defined pause bits (`0..=6`).
pub const KNOWN_PAUSE_FLAGS: u8 = 0x7f;

/// Why a registry report was refused. Every variant is fail-closed.
#[derive(Debug, Error)]
pub enum RegistrySignError {
    /// The independently reconstructed policy context disagreed with the
    /// candidate or the candidate violates the on-chain time/field policy.
    #[error("policy: {0}")]
    Policy(String),
    /// Durable state failed.
    #[error("state: {0}")]
    State(#[from] RegistryStateError),
    /// The identity is already pending and requires operator resolution.
    #[error("signature identity is pending since {reserved_at}")]
    Pending { reserved_at: u64 },
    /// The signer previously reserved or signed a different payload at this
    /// identity.
    #[error("equivocation conflict with payload {previous_payload_hash:#x}")]
    Conflict { previous_payload_hash: B256 },
    /// HSM request failed. The pending reservation is deliberately retained.
    #[error("hsm: {0}")]
    Hsm(#[from] HsmError),
    /// HSM bytes were malformed or did not recover to the configured signer.
    #[error("signature: {0}")]
    Signature(String),
}

/// Independently reconstructed inbound fields. A coordinator-supplied
/// candidate is accepted only if it is byte-identical to this context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundValidationContext {
    pub vault: Address,
    pub router: Address,
    pub pause_flags: u8,
    pub observed_at: u64,
    pub valid_until: u64,
    pub next_sequence: u64,
    pub source_hash: B256,
    /// Local wall-clock time used for the same freshness checks as Solidity.
    pub now: u64,
}

impl InboundValidationContext {
    /// Build the exact typed report after applying contract-parity policy.
    ///
    /// # Errors
    /// [`RegistrySignError::Policy`] for a zero field, unknown pause bit,
    /// stale/future observation, invalid lifetime, or sequence exhaustion.
    pub fn validated_state(&self) -> Result<InboundState, RegistrySignError> {
        if self.vault == Address::ZERO || self.router == Address::ZERO {
            return Err(RegistrySignError::Policy(
                "vault and router must be non-zero".to_string(),
            ));
        }
        if self.source_hash == B256::ZERO {
            return Err(RegistrySignError::Policy(
                "source hash must be non-zero".to_string(),
            ));
        }
        if self.pause_flags & !KNOWN_PAUSE_FLAGS != 0 {
            return Err(RegistrySignError::Policy(format!(
                "unknown pause flags 0x{:02x}",
                self.pause_flags
            )));
        }
        if self.observed_at == 0 || self.observed_at > self.now {
            return Err(RegistrySignError::Policy(
                "observation timestamp is zero or in the future".to_string(),
            ));
        }
        if self.now - self.observed_at > MAX_OBSERVATION_AGE_SECS {
            return Err(RegistrySignError::Policy(
                "observation exceeds the two-minute age limit".to_string(),
            ));
        }
        if self.valid_until <= self.now
            || self.valid_until <= self.observed_at
            || self.valid_until - self.observed_at > MAX_REPORT_LIFETIME_SECS
        {
            return Err(RegistrySignError::Policy(
                "report validity is expired, reversed, or over ten minutes".to_string(),
            ));
        }
        if self.next_sequence == 0 {
            return Err(RegistrySignError::Policy(
                "inbound sequence zero is not a valid successor".to_string(),
            ));
        }
        Ok(inbound_state(
            self.vault,
            self.router,
            self.pause_flags,
            self.observed_at,
            self.valid_until,
            self.next_sequence,
            self.source_hash,
        ))
    }
}

/// Exact quote fields independently reconstructed by one observer. This is
/// intentionally the complete on-chain type: no digest or memo supplied by a
/// coordinator is trusted in place of these fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteValidationContext {
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
    pub finalized_onchain_nonce: u64,
    pub quote_hash: B256,
    pub current_state_valid_until: u64,
    pub now: u64,
}

impl QuoteValidationContext {
    /// Validate contract parity and derive the exact next-nonce report.
    ///
    /// # Errors
    /// [`RegistrySignError::Policy`] when any signed field is empty, the quote
    /// is expired/outlives state, or the nonce is exhausted.
    pub fn validated_quote(&self) -> Result<QuoteAuthorization, RegistrySignError> {
        if [
            self.adapter,
            self.index_token,
            self.originator,
            self.funding_token,
            self.target_token,
        ]
        .contains(&Address::ZERO)
            || self.amount_in.is_zero()
            || self.custody_hash == B256::ZERO
            || self.inbound_state_hash == B256::ZERO
            || self.memo_hash == B256::ZERO
            || self.quote_hash == B256::ZERO
        {
            return Err(RegistrySignError::Policy(
                "quote contains a zero required field".to_string(),
            ));
        }
        if self.dispatch_deadline <= self.now {
            return Err(RegistrySignError::Policy("quote is expired".to_string()));
        }
        if self.dispatch_deadline > self.current_state_valid_until {
            return Err(RegistrySignError::Policy(
                "quote outlives the attested inbound state".to_string(),
            ));
        }
        let quote_nonce = self
            .finalized_onchain_nonce
            .checked_add(1)
            .ok_or_else(|| RegistrySignError::Policy("quote nonce is exhausted".to_string()))?;
        Ok(quote_authorization(
            self.adapter,
            self.index_token,
            self.originator,
            self.funding_token,
            self.target_token,
            self.amount_in,
            self.custody_hash,
            self.inbound_state_hash,
            self.memo_hash,
            self.dispatch_deadline,
            quote_nonce,
            self.quote_hash,
        ))
    }
}

/// Signer core sharing one HSM address, exact registry domain and durable
/// anti-equivocation/nonce database.
#[derive(Debug)]
pub struct RegistrySigner<'a, H> {
    pub hsm: &'a H,
    pub signer_address: Address,
    pub domain: &'a Eip712Domain,
    pub state: &'a SqliteRegistryState,
}

impl<H: HsmDigestSigner> RegistrySigner<'_, H> {
    /// Validate, reserve, sign, recover-verify, persist, then return one exact
    /// inbound-state wire message.
    ///
    /// # Errors
    /// Returns [`RegistrySignError`] on policy mismatch, durable-state failure,
    /// pending/conflicting identity, or HSM/signature failure.
    pub async fn sign_inbound(
        &self,
        context: &InboundValidationContext,
    ) -> Result<SignedInboundStateMessage, RegistrySignError> {
        let report = context.validated_state()?;
        let digest = inbound_state_signing_hash(&report, self.domain);
        let signature = match self
            .state
            .reserve_inbound_signature(report.sequence, digest, context.now)
            .await?
        {
            SignatureReservation::Reserved => {
                let signature = self.sign_and_verify(digest).await?;
                self.state
                    .complete_inbound_signature(report.sequence, digest, signature, context.now)
                    .await?;
                signature
            }
            SignatureReservation::Signed(signature) => signature,
            SignatureReservation::Pending { reserved_at } => {
                return Err(RegistrySignError::Pending { reserved_at });
            }
            SignatureReservation::Conflict {
                previous_payload_hash,
                ..
            } => {
                return Err(RegistrySignError::Conflict {
                    previous_payload_hash,
                });
            }
        };
        Ok(inbound_wire(&report, self.signer_address, signature))
    }

    /// Reserve the finalized on-chain next nonce, then validate/sign/persist
    /// one exact quote authorization. A different active quote is returned as
    /// a policy error and is never sent to the HSM.
    ///
    /// # Errors
    /// Returns [`RegistrySignError`] on policy/nonce mismatch, durable-state
    /// failure, pending/conflicting identity, or HSM/signature failure.
    pub async fn sign_quote(
        &self,
        context: &QuoteValidationContext,
    ) -> Result<SignedQuoteAuthorizationMessage, RegistrySignError> {
        let quote = context.validated_quote()?;
        let digest = quote_authorization_signing_hash(&quote, self.domain);
        match self
            .state
            .reserve_quote_nonce(
                context.originator,
                context.finalized_onchain_nonce,
                digest,
                context.dispatch_deadline,
                context.now,
            )
            .await?
        {
            QuoteNonceReservation::Reserved { nonce }
            | QuoteNonceReservation::Idempotent { nonce }
                if nonce == quote.quoteNonce => {}
            QuoteNonceReservation::Busy { nonce, .. } => {
                return Err(RegistrySignError::Policy(format!(
                    "originator already has active quote nonce {nonce}"
                )));
            }
            QuoteNonceReservation::OnchainBehind {
                finalized_onchain_nonce,
                durable_consumed_nonce,
            } => {
                return Err(RegistrySignError::Policy(format!(
                    "finalized on-chain nonce {finalized_onchain_nonce} is behind durable consumed nonce {durable_consumed_nonce}"
                )));
            }
            QuoteNonceReservation::Exhausted => {
                return Err(RegistrySignError::Policy(
                    "quote nonce is exhausted".to_string(),
                ));
            }
            QuoteNonceReservation::Reserved { nonce }
            | QuoteNonceReservation::Idempotent { nonce } => {
                return Err(RegistrySignError::Policy(format!(
                    "reserved nonce {nonce} differs from typed quote nonce {}",
                    quote.quoteNonce
                )));
            }
        }
        let signature = match self
            .state
            .reserve_quote_signature(quote.originator, quote.quoteNonce, digest, context.now)
            .await?
        {
            SignatureReservation::Reserved => {
                let signature = self.sign_and_verify(digest).await?;
                self.state
                    .complete_quote_signature(
                        quote.originator,
                        quote.quoteNonce,
                        digest,
                        signature,
                        context.now,
                    )
                    .await?;
                signature
            }
            SignatureReservation::Signed(signature) => signature,
            SignatureReservation::Pending { reserved_at } => {
                return Err(RegistrySignError::Pending { reserved_at });
            }
            SignatureReservation::Conflict {
                previous_payload_hash,
                ..
            } => {
                return Err(RegistrySignError::Conflict {
                    previous_payload_hash,
                });
            }
        };
        Ok(quote_wire(&quote, self.signer_address, signature))
    }

    async fn sign_and_verify(&self, digest: B256) -> Result<[u8; 65], RegistrySignError> {
        let signature = self.hsm.sign_digest(self.signer_address, digest).await?;
        let parsed = PrimitiveSignature::try_from(signature.as_slice())
            .map_err(|error| RegistrySignError::Signature(error.to_string()))?;
        let canonical = parsed.normalize_s().unwrap_or(parsed);
        let recovered = canonical
            .recover_address_from_prehash(&digest)
            .map_err(|error| RegistrySignError::Signature(error.to_string()))?;
        if recovered != self.signer_address {
            return Err(RegistrySignError::Signature(format!(
                "recovered {recovered:#x}, expected {:#x}",
                self.signer_address
            )));
        }
        Ok(canonical.as_bytes())
    }
}

fn inbound_wire(
    report: &InboundState,
    signer: Address,
    signature: [u8; 65],
) -> SignedInboundStateMessage {
    SignedInboundStateMessage {
        vault: format!("{:#x}", report.vault),
        router: format!("{:#x}", report.router),
        pause_flags: report.pauseFlags,
        observed_at: report.observedAt,
        valid_until: report.validUntil,
        sequence: report.sequence,
        source_hash: format!("{:#x}", report.sourceHash),
        signer_address: format!("{signer:#x}"),
        signature: format!("0x{}", alloy_primitives::hex::encode(signature)),
    }
}

fn quote_wire(
    quote: &QuoteAuthorization,
    signer: Address,
    signature: [u8; 65],
) -> SignedQuoteAuthorizationMessage {
    SignedQuoteAuthorizationMessage {
        adapter: format!("{:#x}", quote.adapter),
        index_token: format!("{:#x}", quote.indexToken),
        originator: format!("{:#x}", quote.originator),
        funding_token: format!("{:#x}", quote.fundingToken),
        target_token: format!("{:#x}", quote.targetToken),
        amount_in: quote.amountIn.to_string(),
        custody_hash: format!("{:#x}", quote.custodyHash),
        inbound_state_hash: format!("{:#x}", quote.inboundStateHash),
        memo_hash: format!("{:#x}", quote.memoHash),
        dispatch_deadline: quote.dispatchDeadline,
        quote_nonce: quote.quoteNonce,
        quote_hash: format!("{:#x}", quote.quoteHash),
        signer_address: format!("{signer:#x}"),
        signature: format!("0x{}", alloy_primitives::hex::encode(signature)),
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]

    use super::*;

    fn inbound_context() -> InboundValidationContext {
        InboundValidationContext {
            vault: Address::repeat_byte(0x11),
            router: Address::repeat_byte(0x22),
            pause_flags: 0,
            observed_at: 1_000,
            valid_until: 1_500,
            next_sequence: 8,
            source_hash: B256::repeat_byte(0x33),
            now: 1_060,
        }
    }

    fn quote_context() -> QuoteValidationContext {
        QuoteValidationContext {
            adapter: Address::repeat_byte(0x11),
            index_token: Address::repeat_byte(0x22),
            originator: Address::repeat_byte(0x33),
            funding_token: Address::repeat_byte(0x44),
            target_token: Address::repeat_byte(0x55),
            amount_in: U256::from(1_000_000u64),
            custody_hash: B256::repeat_byte(0x66),
            inbound_state_hash: B256::repeat_byte(0x77),
            memo_hash: B256::repeat_byte(0x88),
            dispatch_deadline: 1_200,
            finalized_onchain_nonce: 4,
            quote_hash: B256::repeat_byte(0x99),
            current_state_valid_until: 1_300,
            now: 1_100,
        }
    }

    #[test]
    fn inbound_policy_matches_contract_boundaries() {
        assert!(inbound_context().validated_state().is_ok());
        let mut stale = inbound_context();
        stale.now = stale.observed_at + MAX_OBSERVATION_AGE_SECS + 1;
        assert!(stale.validated_state().is_err());
        let mut unknown = inbound_context();
        unknown.pause_flags = 0x80;
        assert!(unknown.validated_state().is_err());
        let mut too_long = inbound_context();
        too_long.valid_until = too_long.observed_at + MAX_REPORT_LIFETIME_SECS + 1;
        assert!(too_long.validated_state().is_err());
    }

    #[test]
    fn quote_policy_binds_next_nonce_and_state_expiry() {
        let quote = quote_context().validated_quote().expect("valid quote");
        assert_eq!(quote.quoteNonce, 5);
        let mut expired = quote_context();
        expired.dispatch_deadline = expired.now;
        assert!(expired.validated_quote().is_err());
        let mut outlives = quote_context();
        outlives.dispatch_deadline = outlives.current_state_valid_until + 1;
        assert!(outlives.validated_quote().is_err());
    }
}
