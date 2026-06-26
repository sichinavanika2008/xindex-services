//! CTD-1 (`DL-CTD-2`): stateless Redemption Intent Certificate (RIC)
//! verification — the custody daemon's defence against a compromised
//! coordinator.
//!
//! Every custody-spend handler (PSBT / EVM-Safe / Cosmos / XRP / TRON;
//! Solana hard-gated out per RA-2) will, before its HSM call, hand the
//! request's [`IntentProof`] to [`validate_intent_proof`]. The daemon
//! recomputes the RIC EIP-712 digest from the proof's PLAINTEXT fields
//! on its locally-pinned `attestation_oracle_domain` — it never trusts
//! a coordinator-supplied digest — recovers every signature, and
//! requires ≥ `intent_quorum` DISTINCT signers from a STATIC Set-B
//! whitelist (disclosed at the key ceremony; rotation is an operational
//! daemon-config update, NOT an RPC lookup — the daemon stays RPC-free
//! per DL-M5-5/RA-6).
//!
//! Verification is STRICT: any unparseable field, malformed signature,
//! non-whitelisted signer, or duplicate signer rejects the WHOLE proof.
//! An honest relay has no reason to attach garbage; its presence
//! signals tampering or a compromised component, so the daemon fails
//! closed and loud rather than skipping the bad element.
//!
//! Recency (RA-5): no `THORChain` endpoint exposes a vault epoch, so
//! the RIC carries `vault_resolved_at` (the observers' Asgard-resolution
//! time) and the daemon enforces a local `ric_max_age` window — a
//! certificate cannot be replayed onto a rotated Asgard vault. Future-
//! dated certificates are rejected beyond a small clock-skew tolerance
//! so a malicious relay cannot extend a certificate's lifetime.
//!
//! This module is PURE (no I/O, no state): the one-shot replay arm
//! lives in [`crate::replay`] (`check_ric_intent` / `record_ric_intent`)
//! and the `==`-binding of request fields to certified values lives in
//! each handler, where the family-specific spend shape is known.

use alloy_primitives::{Address, PrimitiveSignature, B256, U256};
use crate::eip712::{
    acquire_cancel_certificate, acquire_cancel_signing_hash, attestation_oracle_domain,
    redemption_intent_certificate, ric_signing_hash,
};
use crate::signer_wire::{error_codes, AcquireCancelProof, IntentProof};

/// Clock-skew tolerance for a `vault_resolved_at` in the future. The
/// observers' clocks are NTP-disciplined; anything beyond this is a
/// deliberately future-dated certificate trying to outlive `ric_max_age`.
pub const RIC_FUTURE_SKEW_TOLERANCE_SECS: u64 = 60;

/// Daemon-side RIC verification policy. Static configuration (loaded
/// once at startup, validated via [`IntentPolicy::validate`]); becomes
/// part of `DaemonConfig` when the handler gates are wired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentPolicy {
    /// The STATIC Set-B signer whitelist (Ethereum addresses disclosed
    /// at the key ceremony). The daemon is RPC-free, so membership is
    /// config, not an on-chain lookup.
    pub signer_whitelist: Vec<Address>,
    /// Minimum DISTINCT whitelisted signers required over the one RIC
    /// digest (k of the k-of-n ceremony, e.g. 3 of 5).
    pub intent_quorum: usize,
    /// Maximum age of `vault_resolved_at` in seconds. Must sit well
    /// inside the ~hours-scale `THORChain` vault-retirement window so a
    /// RIC cannot authorize a payment to a retired Asgard inbound.
    pub ric_max_age_secs: u64,
}

impl IntentPolicy {
    /// Startup sanity check — a daemon must refuse to boot on a policy
    /// that can never verify (or, worse, verifies trivially).
    ///
    /// # Errors
    /// Returns a human-readable description of the misconfiguration:
    /// empty whitelist, duplicate whitelist entry, zero quorum, quorum
    /// larger than the whitelist, or zero `ric_max_age_secs`.
    pub fn validate(&self) -> Result<(), String> {
        if self.signer_whitelist.is_empty() {
            return Err("signer whitelist is empty".to_string());
        }
        let mut sorted = self.signer_whitelist.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != self.signer_whitelist.len() {
            return Err("signer whitelist contains a duplicate address".to_string());
        }
        if self.intent_quorum == 0 {
            return Err("intent quorum is zero — RIC verification would be vacuous".to_string());
        }
        if self.intent_quorum > self.signer_whitelist.len() {
            return Err(format!(
                "intent quorum {} exceeds whitelist size {} — no proof could ever verify",
                self.intent_quorum,
                self.signer_whitelist.len()
            ));
        }
        if self.ric_max_age_secs == 0 {
            return Err("ric_max_age_secs is zero — every certificate would be stale".to_string());
        }
        Ok(())
    }
}

/// Why an [`IntentProof`] was rejected. Maps 1:1 onto the CTD-1 wire
/// error codes; the handler layer converts to an HTTP response.
#[derive(Debug, thiserror::Error)]
pub enum IntentError {
    /// Unparseable field, malformed/duplicate/non-whitelisted
    /// signature, sub-quorum signer count, or a fail-closed policy
    /// misconfiguration. Wire code
    /// [`error_codes::INTENT_PROOF_INVALID`], HTTP 422.
    #[error("intent proof invalid: {0}")]
    ProofInvalid(String),
    /// `vault_resolved_at` outside the `ric_max_age` window or
    /// future-dated beyond [`RIC_FUTURE_SKEW_TOLERANCE_SECS`]. Wire
    /// code [`error_codes::INTENT_VAULT_STALE`], HTTP 422.
    #[error("intent vault resolution stale: {0}")]
    VaultStale(String),
}

impl IntentError {
    /// The stable wire error-code string for this rejection.
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::ProofInvalid(_) => error_codes::INTENT_PROOF_INVALID,
            Self::VaultStale(_) => error_codes::INTENT_VAULT_STALE,
        }
    }
}

/// The certified, parsed RIC fields a handler binds the spend against
/// (`==` on destination hash / amount / memo hash etc.), plus the
/// distinct whitelisted signers that authorized it (sorted, for
/// deterministic audit logs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIntent {
    /// Certified `bytes32` redemption id.
    pub redemption_id: B256,
    /// Certified leg index (fits the replay-key width).
    pub leg_index: u32,
    /// Certified canonical asset id of the leg.
    pub asset_id: B256,
    /// Certified spend amount in the leg's native smallest units.
    pub amount: U256,
    /// Certified decimals pinning `amount`'s unit (RA-4).
    pub amount_decimals: u8,
    /// Certified keccak of the immediate spend target (Asgard inbound).
    pub immediate_target_hash: B256,
    /// Certified keccak of the exact `THORChain` memo bytes.
    pub memo_hash: B256,
    /// Certified keccak of the user's final payout destination.
    pub final_destination_hash: B256,
    /// Observers' Asgard-resolution time (unix seconds).
    pub vault_resolved_at: u64,
    /// Sorted distinct whitelisted signers that signed the RIC digest.
    pub signers: Vec<Address>,
}

/// Verify a wire [`IntentProof`] statelessly and return the certified
/// fields plus the recomputed RIC digest (the one-shot replay
/// `payload_hash`).
///
/// Checks, in order: fail-closed policy sanity, field parsing, digest
/// recomputation on the daemon's pinned domain, strict k-of-n signature
/// verification, then recency — so an `INTENT_VAULT_STALE` rejection
/// always refers to a certificate whose quorum was real.
///
/// # Errors
/// [`IntentError::ProofInvalid`] on any parse/signature/quorum/policy
/// failure; [`IntentError::VaultStale`] when `vault_resolved_at` falls
/// outside `[now - ric_max_age, now + skew]`.
pub fn validate_intent_proof(
    proof: &IntentProof,
    eth_chain_id: u64,
    verifying_contract: Address,
    policy: &IntentPolicy,
    now_unix: u64,
) -> Result<(VerifiedIntent, B256), IntentError> {
    // Fail closed on a policy that could never (or trivially) verify.
    // The wiring layer also validates at startup; this guard keeps the
    // pure function safe under direct misuse.
    policy
        .validate()
        .map_err(|e| IntentError::ProofInvalid(format!("daemon intent policy invalid: {e}")))?;
    let intent = parse_proof_fields(proof)?;
    let ric = redemption_intent_certificate(
        intent.redemption_id,
        U256::from(intent.leg_index),
        intent.asset_id,
        intent.amount,
        intent.amount_decimals,
        intent.immediate_target_hash,
        intent.memo_hash,
        intent.final_destination_hash,
        intent.vault_resolved_at,
    );
    let domain = attestation_oracle_domain(eth_chain_id, verifying_contract);
    let digest = ric_signing_hash(&ric, &domain);
    let signers = verify_signature_set(digest, &proof.signatures, policy)?;
    check_recency(intent.vault_resolved_at, now_unix, policy.ric_max_age_secs)?;
    Ok((VerifiedIntent { signers, ..intent }, digest))
}

/// The certified, parsed ACC fields a handler binds the mint-cancel
/// swap-back spend against, plus the distinct whitelisted signers. The
/// sibling of [`VerifiedIntent`] for the cancel path (`DL-CTD-2` Slice C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCancel {
    /// Certified `bytes32` cancel id (the one-shot replay key).
    pub cancel_id: B256,
    /// Certified `bytes32` intent id of the cancelled mint.
    pub intent_id: B256,
    /// Certified async slot index (fits the replay-key width).
    pub slot_index: u32,
    /// Certified canonical asset id of the swap-back leg.
    pub asset_id: B256,
    /// Certified swap-back amount in native smallest units.
    pub amount: U256,
    /// Certified decimals pinning `amount`'s unit (RA-4).
    pub amount_decimals: u8,
    /// Certified keccak of the immediate spend target (Asgard inbound).
    pub immediate_target_hash: B256,
    /// Certified keccak of the exact swap-back memo bytes.
    pub memo_hash: B256,
    /// Certified keccak of the final payout destination.
    pub final_destination_hash: B256,
    /// Observers' Asgard-resolution time (unix seconds).
    pub vault_resolved_at: u64,
    /// Sorted distinct whitelisted signers that signed the ACC digest.
    pub signers: Vec<Address>,
}

/// Verify a wire [`AcquireCancelProof`] statelessly and return the
/// certified fields plus the recomputed ACC digest (the one-shot replay
/// `payload_hash`). The cancel-path sibling of [`validate_intent_proof`]
/// — identical strict semantics (digest recomputed on the daemon's
/// pinned domain, k-of-n distinct whitelisted signers over the ACC
/// digest, recency), differing only in the certified field set.
///
/// # Errors
/// [`IntentError::ProofInvalid`] on any parse/signature/quorum/policy
/// failure; [`IntentError::VaultStale`] on a stale/future
/// `vault_resolved_at`. The handler maps these to the ACC-specific wire
/// codes (`acquire_cancel_proof_invalid` / `acquire_cancel_vault_stale`).
pub fn validate_acquire_cancel_proof(
    proof: &AcquireCancelProof,
    eth_chain_id: u64,
    verifying_contract: Address,
    policy: &IntentPolicy,
    now_unix: u64,
) -> Result<(VerifiedCancel, B256), IntentError> {
    policy
        .validate()
        .map_err(|e| IntentError::ProofInvalid(format!("daemon intent policy invalid: {e}")))?;
    let cancel = parse_cancel_fields(proof)?;
    let acc = acquire_cancel_certificate(
        cancel.cancel_id,
        cancel.intent_id,
        U256::from(cancel.slot_index),
        cancel.asset_id,
        cancel.amount,
        cancel.amount_decimals,
        cancel.immediate_target_hash,
        cancel.memo_hash,
        cancel.final_destination_hash,
        cancel.vault_resolved_at,
    );
    let domain = attestation_oracle_domain(eth_chain_id, verifying_contract);
    let digest = acquire_cancel_signing_hash(&acc, &domain);
    let signers = verify_signature_set(digest, &proof.signatures, policy)?;
    check_recency(cancel.vault_resolved_at, now_unix, policy.ric_max_age_secs)?;
    Ok((VerifiedCancel { signers, ..cancel }, digest))
}

/// Parse the wire ACC proof's string fields into typed values.
/// `signers` is left empty — filled by the caller after verification.
fn parse_cancel_fields(proof: &AcquireCancelProof) -> Result<VerifiedCancel, IntentError> {
    Ok(VerifiedCancel {
        cancel_id: parse_b256(&proof.cancel_id, "cancel_id")?,
        intent_id: parse_b256(&proof.intent_id, "intent_id")?,
        slot_index: parse_u32(&proof.slot_index, "slot_index")?,
        asset_id: parse_b256(&proof.asset_id, "asset_id")?,
        amount: parse_u256(&proof.amount, "amount")?,
        amount_decimals: proof.amount_decimals,
        immediate_target_hash: parse_b256(&proof.immediate_target_hash, "immediate_target_hash")?,
        memo_hash: parse_b256(&proof.memo_hash, "memo_hash")?,
        final_destination_hash: parse_b256(
            &proof.final_destination_hash,
            "final_destination_hash",
        )?,
        vault_resolved_at: proof.vault_resolved_at,
        signers: Vec::new(),
    })
}

/// Parse the wire proof's string fields into typed values. `signers`
/// is left empty — filled by the caller after signature verification.
fn parse_proof_fields(proof: &IntentProof) -> Result<VerifiedIntent, IntentError> {
    Ok(VerifiedIntent {
        redemption_id: parse_b256(&proof.redemption_id, "redemption_id")?,
        leg_index: parse_u32(&proof.leg_index, "leg_index")?,
        asset_id: parse_b256(&proof.asset_id, "asset_id")?,
        amount: parse_u256(&proof.amount, "amount")?,
        amount_decimals: proof.amount_decimals,
        immediate_target_hash: parse_b256(&proof.immediate_target_hash, "immediate_target_hash")?,
        memo_hash: parse_b256(&proof.memo_hash, "memo_hash")?,
        final_destination_hash: parse_b256(
            &proof.final_destination_hash,
            "final_destination_hash",
        )?,
        vault_resolved_at: proof.vault_resolved_at,
        signers: Vec::new(),
    })
}

/// Strict signature-set verification: every entry must be a valid
/// recoverable signature over `digest` from a DISTINCT whitelisted
/// signer, and the distinct count must reach quorum. Any bad element
/// rejects the whole proof.
fn verify_signature_set(
    digest: B256,
    signatures: &[String],
    policy: &IntentPolicy,
) -> Result<Vec<Address>, IntentError> {
    if signatures.len() > policy.signer_whitelist.len() {
        return Err(IntentError::ProofInvalid(format!(
            "{} signatures for a {}-member whitelist — must contain a duplicate or non-member",
            signatures.len(),
            policy.signer_whitelist.len()
        )));
    }
    let mut signers: Vec<Address> = Vec::with_capacity(signatures.len());
    for (i, sig_hex) in signatures.iter().enumerate() {
        let recovered = recover_ric_signer(sig_hex, digest)
            .map_err(|e| IntentError::ProofInvalid(format!("signature[{i}]: {e}")))?;
        if !policy.signer_whitelist.contains(&recovered) {
            return Err(IntentError::ProofInvalid(format!(
                "signature[{i}] recovered to non-whitelisted signer {recovered:#x}"
            )));
        }
        if signers.contains(&recovered) {
            return Err(IntentError::ProofInvalid(format!(
                "signature[{i}] is a duplicate from signer {recovered:#x}"
            )));
        }
        signers.push(recovered);
    }
    if signers.len() < policy.intent_quorum {
        return Err(IntentError::ProofInvalid(format!(
            "sub-quorum: {} distinct whitelisted signers, need {}",
            signers.len(),
            policy.intent_quorum
        )));
    }
    signers.sort_unstable();
    Ok(signers)
}

/// Recover the signer address of one `0x`-hex 65-byte recoverable
/// signature (`r ‖ s ‖ v`, v ∈ {0, 1, 27, 28}) over `digest`.
fn recover_ric_signer(sig_hex: &str, digest: B256) -> Result<Address, String> {
    let stripped = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
    let bytes = alloy_primitives::hex::decode(stripped).map_err(|e| format!("bad hex: {e}"))?;
    if bytes.len() != 65 {
        return Err(format!("expected 65 bytes, got {}", bytes.len()));
    }
    PrimitiveSignature::try_from(bytes.as_slice())
        .map_err(|e| format!("not a recoverable ECDSA signature: {e}"))?
        .recover_address_from_prehash(&digest)
        .map_err(|e| format!("did not recover to an address: {e}"))
}

/// RA-5 recency window: reject certificates older than `max_age_secs`
/// and certificates future-dated beyond the clock-skew tolerance.
fn check_recency(
    vault_resolved_at: u64,
    now_unix: u64,
    max_age_secs: u64,
) -> Result<(), IntentError> {
    if vault_resolved_at > now_unix.saturating_add(RIC_FUTURE_SKEW_TOLERANCE_SECS) {
        return Err(IntentError::VaultStale(format!(
            "vault_resolved_at {vault_resolved_at} is future-dated \
             (now {now_unix}, tolerance {RIC_FUTURE_SKEW_TOLERANCE_SECS}s)"
        )));
    }
    if now_unix.saturating_sub(vault_resolved_at) > max_age_secs {
        return Err(IntentError::VaultStale(format!(
            "vault_resolved_at {vault_resolved_at} is older than ric_max_age \
             {max_age_secs}s (now {now_unix})"
        )));
    }
    Ok(())
}

fn parse_b256(hex_str: &str, field: &str) -> Result<B256, IntentError> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = alloy_primitives::hex::decode(stripped)
        .map_err(|e| IntentError::ProofInvalid(format!("{field}: bad hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| IntentError::ProofInvalid(format!("{field}: not 32 bytes")))?;
    Ok(B256::from(arr))
}

fn parse_u256(dec_str: &str, field: &str) -> Result<U256, IntentError> {
    U256::from_str_radix(dec_str, 10)
        .map_err(|e| IntentError::ProofInvalid(format!("{field}: bad uint256 decimal: {e}")))
}

fn parse_u32(dec_str: &str, field: &str) -> Result<u32, IntentError> {
    dec_str.parse::<u32>().map_err(|e| {
        IntentError::ProofInvalid(format!(
            "{field}: not a u32 decimal (replay-key width): {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;
    use k256::ecdsa::SigningKey;

    const NOW: u64 = 1_750_000_000;
    const MAX_AGE: u64 = 3_600;
    const CHAIN_ID: u64 = 1;

    fn oracle() -> Address {
        Address::repeat_byte(0x42)
    }

    /// k256 test key → EOA address (uncompressed pubkey keccak).
    #[expect(clippy::expect_used, reason = "test code")]
    fn key_identity(seed: u8) -> (SigningKey, Address) {
        let sk = SigningKey::from_slice(&[seed; 32]).expect("key");
        let vk = sk.verifying_key();
        let uncompressed = vk.to_encoded_point(false);
        let hash = keccak256(&uncompressed.as_bytes()[1..]);
        (sk, Address::from_slice(&hash[12..]))
    }

    /// 65-byte `r ‖ s ‖ v` with v = 27 + recid (the HSM-stub convention).
    #[expect(clippy::expect_used, reason = "test code")]
    fn sign_digest(sk: &SigningKey, digest: B256) -> String {
        let (sig, recid) = sk
            .sign_prehash_recoverable(digest.as_slice())
            .expect("sign");
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(sig.to_bytes().as_ref());
        out[64] = 27 + recid.to_byte();
        format!("0x{}", alloy_primitives::hex::encode(out))
    }

    /// Whitelist = the addresses of test seeds 1..=5; quorum 3 of 5.
    fn policy() -> IntentPolicy {
        IntentPolicy {
            signer_whitelist: (1..=5).map(|s| key_identity(s).1).collect(),
            intent_quorum: 3,
            ric_max_age_secs: MAX_AGE,
        }
    }

    #[test]
    fn validate_accepts_quorum_equal_to_whitelist_size() {
        // A k-of-k policy (quorum == whitelist size, e.g. 3-of-3) is valid —
        // the `quorum > whitelist.len()` guard must be a strict `>`, not `>=`.
        let p = IntentPolicy {
            signer_whitelist: (1..=3).map(|s| key_identity(s).1).collect(),
            intent_quorum: 3,
            ric_max_age_secs: MAX_AGE,
        };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn validate_rejects_quorum_above_whitelist_size() {
        let p = IntentPolicy {
            signer_whitelist: (1..=3).map(|s| key_identity(s).1).collect(),
            intent_quorum: 4,
            ric_max_age_secs: MAX_AGE,
        };
        assert!(p.validate().is_err());
    }

    fn sample_proof() -> IntentProof {
        IntentProof {
            redemption_id: format!("0x{}", "ab".repeat(32)),
            leg_index: "1".to_string(),
            asset_id: format!("0x{}", "a1".repeat(32)),
            amount: "100000000".to_string(),
            amount_decimals: 8,
            immediate_target_hash: format!("0x{}", "cd".repeat(32)),
            memo_hash: format!("0x{}", "ef".repeat(32)),
            final_destination_hash: format!("0x{}", "12".repeat(32)),
            vault_resolved_at: NOW - 100,
            signatures: vec![],
        }
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn b256_of(hex_str: &str) -> B256 {
        let stripped = hex_str.strip_prefix("0x").expect("0x prefix");
        B256::from_slice(&alloy_primitives::hex::decode(stripped).expect("hex"))
    }

    /// Independent digest recompute from the proof's literal fields —
    /// catches a field-order swap in `parse_proof_fields` (the sigs
    /// would no longer verify against the production digest).
    #[expect(clippy::expect_used, reason = "test code")]
    fn digest_for(proof: &IntentProof, chain_id: u64, contract: Address) -> B256 {
        let ric = redemption_intent_certificate(
            b256_of(&proof.redemption_id),
            U256::from_str_radix(&proof.leg_index, 10).expect("leg"),
            b256_of(&proof.asset_id),
            U256::from_str_radix(&proof.amount, 10).expect("amount"),
            proof.amount_decimals,
            b256_of(&proof.immediate_target_hash),
            b256_of(&proof.memo_hash),
            b256_of(&proof.final_destination_hash),
            proof.vault_resolved_at,
        );
        ric_signing_hash(&ric, &attestation_oracle_domain(chain_id, contract))
    }

    /// Sign `sample_proof` (or a mutated copy) with the given seeds.
    fn signed_proof(mutate: impl FnOnce(&mut IntentProof), seeds: &[u8]) -> IntentProof {
        let mut proof = sample_proof();
        mutate(&mut proof);
        let digest = digest_for(&proof, CHAIN_ID, oracle());
        proof.signatures = seeds
            .iter()
            .map(|s| sign_digest(&key_identity(*s).0, digest))
            .collect();
        proof
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn assert_rejected(proof: &IntentProof, expected_code: &str, msg_fragment: &str) {
        let err = validate_intent_proof(proof, CHAIN_ID, oracle(), &policy(), NOW)
            .expect_err("must reject");
        assert_eq!(err.error_code(), expected_code, "wrong code: {err}");
        assert!(
            err.to_string().contains(msg_fragment),
            "expected '{msg_fragment}' in: {err}"
        );
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn three_of_five_quorum_passes() {
        let proof = signed_proof(|_| {}, &[1, 2, 3]);
        let (intent, digest) = validate_intent_proof(&proof, CHAIN_ID, oracle(), &policy(), NOW)
            .expect("3-of-5 must verify");
        assert_eq!(digest, digest_for(&proof, CHAIN_ID, oracle()));
        assert_eq!(intent.redemption_id, b256_of(&proof.redemption_id));
        assert_eq!(intent.leg_index, 1);
        assert_eq!(intent.asset_id, b256_of(&proof.asset_id));
        assert_eq!(intent.amount, U256::from(100_000_000_u64));
        assert_eq!(intent.amount_decimals, 8);
        assert_eq!(
            intent.immediate_target_hash,
            b256_of(&proof.immediate_target_hash)
        );
        assert_eq!(intent.memo_hash, b256_of(&proof.memo_hash));
        assert_eq!(
            intent.final_destination_hash,
            b256_of(&proof.final_destination_hash)
        );
        assert_eq!(intent.vault_resolved_at, NOW - 100);
        let mut expected: Vec<Address> = [1, 2, 3].iter().map(|s| key_identity(*s).1).collect();
        expected.sort_unstable();
        assert_eq!(intent.signers, expected);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn all_five_signers_pass() {
        let proof = signed_proof(|_| {}, &[1, 2, 3, 4, 5]);
        let (intent, _) = validate_intent_proof(&proof, CHAIN_ID, oracle(), &policy(), NOW)
            .expect("5-of-5 must verify");
        assert_eq!(intent.signers.len(), 5);
    }

    #[test]
    fn sub_quorum_rejected() {
        let proof = signed_proof(|_| {}, &[1, 2]);
        assert_rejected(&proof, error_codes::INTENT_PROOF_INVALID, "sub-quorum");
    }

    #[test]
    fn empty_signature_set_rejected() {
        let proof = signed_proof(|_| {}, &[]);
        assert_rejected(&proof, error_codes::INTENT_PROOF_INVALID, "sub-quorum");
    }

    #[test]
    fn duplicate_signer_rejected() {
        // Quorum-count entries, but only 2 distinct signers.
        let proof = signed_proof(|_| {}, &[1, 1, 2]);
        assert_rejected(&proof, error_codes::INTENT_PROOF_INVALID, "duplicate");
    }

    /// STRICT: quorum is met by seeds 1-3, but the outsider's signature
    /// still rejects the whole proof — an honest relay never attaches a
    /// non-member signature.
    #[test]
    fn non_whitelisted_signer_rejected_even_with_quorum_met() {
        let proof = signed_proof(|_| {}, &[1, 2, 3, 9]);
        assert_rejected(&proof, error_codes::INTENT_PROOF_INVALID, "non-whitelisted");
    }

    #[test]
    fn malformed_signatures_rejected() {
        let mut proof = signed_proof(|_| {}, &[1, 2, 3]);
        proof.signatures[0] = "0xzz".to_string();
        assert_rejected(&proof, error_codes::INTENT_PROOF_INVALID, "bad hex");

        let mut proof = signed_proof(|_| {}, &[1, 2, 3]);
        proof.signatures[1] = format!("0x{}", "ab".repeat(64));
        assert_rejected(&proof, error_codes::INTENT_PROOF_INVALID, "expected 65");
    }

    /// The CTD-1 core property: certify, then tamper one certified
    /// field — every signature stops recovering to a whitelisted
    /// signer, so the poisoned spend is rejected.
    #[test]
    fn tampered_amount_breaks_signatures() {
        let mut proof = signed_proof(|_| {}, &[1, 2, 3]);
        proof.amount = "200000000".to_string();
        assert_rejected(&proof, error_codes::INTENT_PROOF_INVALID, "non-whitelisted");
    }

    #[test]
    fn tampered_destination_breaks_signatures() {
        let mut proof = signed_proof(|_| {}, &[1, 2, 3]);
        proof.immediate_target_hash = format!("0x{}", "66".repeat(32));
        assert_rejected(&proof, error_codes::INTENT_PROOF_INVALID, "non-whitelisted");
    }

    /// Cross-chain replay defence: a RIC signed for mainnet does not
    /// verify on a daemon pinned to another chain id.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn wrong_domain_chain_id_breaks_signatures() {
        let proof = signed_proof(|_| {}, &[1, 2, 3]);
        let err = validate_intent_proof(&proof, 11_155_111, oracle(), &policy(), NOW)
            .expect_err("must reject");
        assert_eq!(err.error_code(), error_codes::INTENT_PROOF_INVALID);
    }

    /// Cross-oracle replay defence: same chain id, different pinned
    /// `AttestationOracle` address → different domain → no verify.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn wrong_verifying_contract_breaks_signatures() {
        let proof = signed_proof(|_| {}, &[1, 2, 3]);
        let err =
            validate_intent_proof(&proof, CHAIN_ID, Address::repeat_byte(0x43), &policy(), NOW)
                .expect_err("must reject");
        assert_eq!(err.error_code(), error_codes::INTENT_PROOF_INVALID);
    }

    /// Staleness is checked on a REAL quorum (signed over the stale
    /// timestamp), so `INTENT_VAULT_STALE` telemetry is truthful.
    #[test]
    fn stale_ric_rejected() {
        let proof = signed_proof(|p| p.vault_resolved_at = NOW - MAX_AGE - 1, &[1, 2, 3]);
        assert_rejected(&proof, error_codes::INTENT_VAULT_STALE, "older than");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn exact_max_age_boundary_passes() {
        let proof = signed_proof(|p| p.vault_resolved_at = NOW - MAX_AGE, &[1, 2, 3]);
        validate_intent_proof(&proof, CHAIN_ID, oracle(), &policy(), NOW)
            .expect("exact boundary is inside the window");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn future_dated_rejected_beyond_skew_tolerance() {
        let proof = signed_proof(
            |p| p.vault_resolved_at = NOW + RIC_FUTURE_SKEW_TOLERANCE_SECS + 1,
            &[1, 2, 3],
        );
        assert_rejected(&proof, error_codes::INTENT_VAULT_STALE, "future-dated");

        let proof = signed_proof(
            |p| p.vault_resolved_at = NOW + RIC_FUTURE_SKEW_TOLERANCE_SECS,
            &[1, 2, 3],
        );
        validate_intent_proof(&proof, CHAIN_ID, oracle(), &policy(), NOW)
            .expect("within skew tolerance");
    }

    /// Pigeonhole early-reject: more signatures than whitelist members
    /// must contain a duplicate or an outsider.
    #[test]
    fn more_signatures_than_whitelist_rejected() {
        let proof = signed_proof(|_| {}, &[1, 2, 3, 4, 5, 1]);
        assert_rejected(
            &proof,
            error_codes::INTENT_PROOF_INVALID,
            "duplicate or non-member",
        );
    }

    #[test]
    fn unparseable_fields_rejected() {
        let mut proof = signed_proof(|_| {}, &[1, 2, 3]);
        proof.redemption_id = "0x1234".to_string();
        assert_rejected(&proof, error_codes::INTENT_PROOF_INVALID, "not 32 bytes");

        let mut proof = signed_proof(|_| {}, &[1, 2, 3]);
        proof.leg_index = "4294967296".to_string(); // u32::MAX + 1
        assert_rejected(&proof, error_codes::INTENT_PROOF_INVALID, "leg_index");

        let mut proof = signed_proof(|_| {}, &[1, 2, 3]);
        proof.amount = "12x".to_string();
        assert_rejected(&proof, error_codes::INTENT_PROOF_INVALID, "amount");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn policy_validate_rejects_misconfiguration() {
        policy().validate().expect("reference policy is valid");

        let empty = IntentPolicy {
            signer_whitelist: vec![],
            ..policy()
        };
        assert!(empty.validate().is_err());

        let dup_entry = IntentPolicy {
            signer_whitelist: vec![key_identity(1).1, key_identity(1).1, key_identity(2).1],
            ..policy()
        };
        assert!(dup_entry.validate().is_err());

        let zero_quorum = IntentPolicy {
            intent_quorum: 0,
            ..policy()
        };
        assert!(zero_quorum.validate().is_err());

        let over_quorum = IntentPolicy {
            intent_quorum: 6,
            ..policy()
        };
        assert!(over_quorum.validate().is_err());

        let zero_age = IntentPolicy {
            ric_max_age_secs: 0,
            ..policy()
        };
        assert!(zero_age.validate().is_err());
    }

    /// Fail-closed: a misconfigured policy rejects even a proof whose
    /// signatures are genuinely valid.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn misconfigured_policy_fails_closed_in_validate_intent_proof() {
        let proof = signed_proof(|_| {}, &[1, 2, 3]);
        let zero_quorum = IntentPolicy {
            intent_quorum: 0,
            ..policy()
        };
        let err = validate_intent_proof(&proof, CHAIN_ID, oracle(), &zero_quorum, NOW)
            .expect_err("zero-quorum policy must fail closed");
        assert_eq!(err.error_code(), error_codes::INTENT_PROOF_INVALID);
        assert!(err.to_string().contains("policy invalid"), "got: {err}");
    }

    /* ---- CTD-1 Slice C: Acquire-Cancel Certificate validator ---- */

    fn sample_acc_proof() -> AcquireCancelProof {
        AcquireCancelProof {
            cancel_id: format!("0x{}", "11".repeat(32)),
            intent_id: format!("0x{}", "22".repeat(32)),
            slot_index: "0".to_string(),
            asset_id: format!("0x{}", "a1".repeat(32)),
            amount: "50000000".to_string(),
            amount_decimals: 8,
            immediate_target_hash: format!("0x{}", "cd".repeat(32)),
            memo_hash: format!("0x{}", "ef".repeat(32)),
            final_destination_hash: format!("0x{}", "12".repeat(32)),
            vault_resolved_at: NOW - 100,
            signatures: vec![],
        }
    }

    /// Independent ACC digest recompute from the proof's literal fields.
    #[expect(clippy::expect_used, reason = "test code")]
    fn acc_digest_for(proof: &AcquireCancelProof, chain_id: u64, contract: Address) -> B256 {
        let acc = acquire_cancel_certificate(
            b256_of(&proof.cancel_id),
            b256_of(&proof.intent_id),
            U256::from_str_radix(&proof.slot_index, 10).expect("slot"),
            b256_of(&proof.asset_id),
            U256::from_str_radix(&proof.amount, 10).expect("amount"),
            proof.amount_decimals,
            b256_of(&proof.immediate_target_hash),
            b256_of(&proof.memo_hash),
            b256_of(&proof.final_destination_hash),
            proof.vault_resolved_at,
        );
        acquire_cancel_signing_hash(&acc, &attestation_oracle_domain(chain_id, contract))
    }

    fn signed_acc_proof(
        mutate: impl FnOnce(&mut AcquireCancelProof),
        seeds: &[u8],
    ) -> AcquireCancelProof {
        let mut proof = sample_acc_proof();
        mutate(&mut proof);
        let digest = acc_digest_for(&proof, CHAIN_ID, oracle());
        proof.signatures = seeds
            .iter()
            .map(|s| sign_digest(&key_identity(*s).0, digest))
            .collect();
        proof
    }

    /// The ACC validator mirrors the RIC validator: 3-of-5 over the ACC
    /// digest verifies and returns the certified swap-back fields.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn acc_three_of_five_quorum_passes() {
        let proof = signed_acc_proof(|_| {}, &[1, 2, 3]);
        let (cancel, digest) =
            validate_acquire_cancel_proof(&proof, CHAIN_ID, oracle(), &policy(), NOW)
                .expect("3-of-5 must verify");
        assert_eq!(digest, acc_digest_for(&proof, CHAIN_ID, oracle()));
        assert_eq!(cancel.cancel_id, b256_of(&proof.cancel_id));
        assert_eq!(cancel.intent_id, b256_of(&proof.intent_id));
        assert_eq!(cancel.slot_index, 0);
        assert_eq!(cancel.amount, U256::from(50_000_000_u64));
        assert_eq!(cancel.signers.len(), 3);
    }

    /// The CTD-1 core property carries to the cancel path: tampering a
    /// certified field breaks every signature → rejected.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn acc_tampered_destination_breaks_signatures() {
        let mut proof = signed_acc_proof(|_| {}, &[1, 2, 3]);
        proof.immediate_target_hash = format!("0x{}", "66".repeat(32));
        let err = validate_acquire_cancel_proof(&proof, CHAIN_ID, oracle(), &policy(), NOW)
            .expect_err("tamper must reject");
        assert_eq!(err.error_code(), error_codes::INTENT_PROOF_INVALID);
    }

    /// A different daemon chain id → different domain → no verify
    /// (cross-chain replay defence on the cancel path).
    #[test]
    fn acc_wrong_domain_chain_id_breaks_signatures() {
        let proof = signed_acc_proof(|_| {}, &[1, 2, 3]);
        assert!(
            validate_acquire_cancel_proof(&proof, 11_155_111, oracle(), &policy(), NOW).is_err()
        );
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn acc_stale_rejected() {
        let proof = signed_acc_proof(|p| p.vault_resolved_at = NOW - MAX_AGE - 1, &[1, 2, 3]);
        let err = validate_acquire_cancel_proof(&proof, CHAIN_ID, oracle(), &policy(), NOW)
            .expect_err("stale must reject");
        assert_eq!(err.error_code(), error_codes::INTENT_VAULT_STALE);
    }
}
