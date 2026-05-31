//! secp256k1 signature helpers for XRPL: DER encoding with enforced
//! low-S, per-signer verification against the multisign digest, and the
//! `Signers`-array aggregation.
//!
//! XRPL `TxnSignature` is ASN.1 DER (`SEQUENCE { INTEGER r, INTEGER s }`)
//! with **low-S mandatory** — rippled's `RequireFullyCanonicalSig`
//! rejects high-S. We normalize on encode and reject high-S on verify.
//! Unlike Cosmos (one shared digest), each XRP signer is verified against
//! its OWN multisign digest (body + that signer's `AccountID`).

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};

use crate::signing::multisign_digest;
use crate::{VerifiedSigner, XrpMultisig};

/// Errors in the signature path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SigError {
    /// `(r, s)` did not form a valid signature (zero scalar, etc.).
    #[error("invalid signature scalars")]
    BadScalars,
    /// The signature bytes were not valid DER.
    #[error("invalid DER signature")]
    BadDer,
    /// The pubkey was not a valid compressed secp256k1 point.
    #[error("invalid compressed secp256k1 pubkey")]
    BadPubkey,
    /// The signature was high-S (rippled rejects it; we refuse it too).
    #[error("non-canonical (high-S) signature")]
    HighS,
    /// The signature did not verify against the pubkey + digest.
    #[error("signature verification failed")]
    BadSignature,
    /// A partial signature's pubkey is not in the descriptor.
    #[error("signer is not a descriptor member")]
    NotAMember,
    /// Two partials came from the same member.
    #[error("duplicate signer")]
    DuplicateSigner,
    /// The collected weight did not reach the quorum.
    #[error("quorum not met: {got} < {quorum}")]
    QuorumNotMet {
        /// Sum of weights of the verified signers.
        got: u32,
        /// The descriptor quorum.
        quorum: u32,
    },
}

/// DER-encode a signature, normalizing S to low-S first.
#[must_use]
pub fn der_low_s(sig: &Signature) -> Vec<u8> {
    let low = sig.normalize_s().unwrap_or(*sig);
    low.to_der().as_bytes().to_vec()
}

/// DER-encode a low-S signature from raw 32-byte `(r, s)` scalars (the
/// HSM returns `r ‖ s`). Normalizes high-S to low-S.
///
/// # Errors
///
/// Returns [`SigError::BadScalars`] if `(r, s)` do not form a valid
/// signature (e.g. a zero scalar).
pub fn der_low_s_from_rs(r: &[u8; 32], s: &[u8; 32]) -> Result<Vec<u8>, SigError> {
    let sig = Signature::from_scalars(*r, *s).map_err(|_| SigError::BadScalars)?;
    Ok(der_low_s(&sig))
}

/// Verify a DER signature against a compressed pubkey + 32-byte prehash,
/// **rejecting high-S** (rippled would too).
///
/// # Errors
///
/// Returns [`SigError`] if the pubkey is not a valid compressed point,
/// the signature is not valid DER, the signature is high-S, or it does
/// not verify against the pubkey and prehash.
pub fn verify_der(pubkey: &[u8; 33], prehash: &[u8; 32], der: &[u8]) -> Result<(), SigError> {
    let vk = VerifyingKey::from_sec1_bytes(pubkey).map_err(|_| SigError::BadPubkey)?;
    let sig = Signature::from_der(der).map_err(|_| SigError::BadDer)?;
    if sig.normalize_s().is_some() {
        return Err(SigError::HighS);
    }
    vk.verify_prehash(prehash, &sig)
        .map_err(|_| SigError::BadSignature)
}

/// One member's partial signature (pubkey + DER sig). The `AccountID` and
/// weight are looked up from the descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialSig {
    /// 33-byte compressed pubkey of the signer.
    pub pubkey: [u8; 33],
    /// DER-encoded low-S signature over this signer's multisign digest.
    pub der: Vec<u8>,
}

/// Verify every partial against its OWN multisign digest
/// (`SHA512Half(SMT\0 ‖ body ‖ signer_account_id)`), reject non-members
/// and duplicates, require the summed weight to reach the quorum, and
/// return the signers **sorted by `AccountID` ascending** — ready for the
/// `Signers` array. `body` is the shared serialized Payment body with an
/// empty `SigningPubKey` (from [`crate::tx::serialize_for_multisign`]).
///
/// # Errors
///
/// Returns [`SigError`] if a partial's pubkey is not a descriptor member,
/// two partials come from the same member, any signature fails to verify
/// against its per-signer digest, or the summed weight does not reach the
/// quorum.
pub fn aggregate_verified(
    descriptor: &XrpMultisig,
    body: &[u8],
    parts: &[PartialSig],
) -> Result<Vec<VerifiedSigner>, SigError> {
    let mut out: Vec<VerifiedSigner> = Vec::with_capacity(parts.len());
    let mut weight: u32 = 0;
    for part in parts {
        let member = descriptor
            .member_by_pubkey(&part.pubkey)
            .ok_or(SigError::NotAMember)?;
        if out.iter().any(|v| v.account_id == member.account_id) {
            return Err(SigError::DuplicateSigner);
        }
        let digest = multisign_digest(body, &member.account_id);
        verify_der(&part.pubkey, &digest, &part.der)?;
        weight += u32::from(member.weight);
        out.push(VerifiedSigner {
            account_id: member.account_id,
            pubkey: part.pubkey,
            der: part.der.clone(),
        });
    }
    if weight < descriptor.quorum() {
        return Err(SigError::QuorumNotMet {
            got: weight,
            quorum: descriptor.quorum(),
        });
    }
    out.sort_by_key(|v| v.account_id);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;

    #[expect(clippy::expect_used, reason = "test code")]
    fn key(seed: u8) -> (SigningKey, [u8; 33]) {
        let sk = SigningKey::from_slice(&[seed; 32]).expect("key");
        let ep = sk.verifying_key().to_encoded_point(true);
        let mut pk = [0u8; 33];
        pk.copy_from_slice(ep.as_bytes());
        (sk, pk)
    }

    /// Sign a digest with k256 (RFC6979, low-S by default), DER-encode.
    #[expect(clippy::expect_used, reason = "test code")]
    fn sign(sk: &SigningKey, digest: &[u8; 32]) -> Vec<u8> {
        let sig: Signature = sk.sign_prehash(digest).expect("sign");
        der_low_s(&sig)
    }

    #[test]
    fn der_round_trips_and_low_s_verifies() {
        let (sk, pk) = key(7);
        let digest = [0x42u8; 32];
        let der = sign(&sk, &digest);
        assert!(verify_der(&pk, &digest, &der).is_ok());
        // Wrong digest fails.
        assert!(verify_der(&pk, &[0x43u8; 32], &der).is_err());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn high_s_signature_is_rejected() {
        let (sk, pk) = key(9);
        let digest = [0x11u8; 32];
        // Build a high-S DER by negating S on a valid low-S signature.
        let sig: Signature = sk.sign_prehash(&digest).expect("sign");
        let low = sig.normalize_s().unwrap_or(sig);
        // The "high" form is the s-negation; ecdsa exposes it as the
        // non-normalized counterpart. Construct via scalars.
        let r = low.r();
        let s = low.s();
        let neg_s = -*s;
        let high = Signature::from_scalars(r.to_bytes(), neg_s.to_bytes()).expect("sig");
        // Sanity: `high` really is high-S.
        assert!(high.normalize_s().is_some(), "expected high-S");
        let der = high.to_der().as_bytes().to_vec();
        assert_eq!(verify_der(&pk, &digest, &der), Err(SigError::HighS));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn aggregate_verifies_per_signer_and_sorts() {
        let (sk1, pk1) = key(1);
        let (sk2, pk2) = key(2);
        let (sk3, pk3) = key(3);
        let ms = XrpMultisig::new(2, vec![(pk1, 1), (pk2, 1), (pk3, 1)]).expect("descriptor");
        let body = b"shared-payment-body".to_vec();

        // Two of three sign their OWN digest.
        let id1 = crate::addr::account_id(&pk1);
        let id2 = crate::addr::account_id(&pk2);
        let part1 = PartialSig {
            pubkey: pk1,
            der: sign(&sk1, &multisign_digest(&body, &id1)),
        };
        let part2 = PartialSig {
            pubkey: pk2,
            der: sign(&sk2, &multisign_digest(&body, &id2)),
        };
        let _ = sk3;

        let signers =
            aggregate_verified(&ms, &body, &[part2.clone(), part1.clone()]).expect("aggregate");
        assert_eq!(signers.len(), 2);
        // Sorted by AccountID ascending regardless of input order.
        assert!(signers[0].account_id < signers[1].account_id);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn aggregate_rejects_wrong_digest_signature() {
        let (sk1, pk1) = key(1);
        let (_sk2, pk2) = key(2);
        let ms = XrpMultisig::new(1, vec![(pk1, 1), (pk2, 1)]).expect("descriptor");
        let body = b"body".to_vec();
        // Sign the WRONG digest (signer1's sig over signer2's account id).
        let id2 = crate::addr::account_id(&pk2);
        let bad = PartialSig {
            pubkey: pk1,
            der: sign(&sk1, &multisign_digest(&body, &id2)),
        };
        assert_eq!(
            aggregate_verified(&ms, &body, &[bad]),
            Err(SigError::BadSignature)
        );
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn aggregate_rejects_non_member_duplicate_and_subquorum() {
        let (sk1, pk1) = key(1);
        let (sk2, pk2) = key(2);
        let (skx, pkx) = key(8);
        let ms = XrpMultisig::new(2, vec![(pk1, 1), (pk2, 1)]).expect("descriptor");
        let body = b"body".to_vec();
        let id1 = crate::addr::account_id(&pk1);
        let p1 = PartialSig {
            pubkey: pk1,
            der: sign(&sk1, &multisign_digest(&body, &id1)),
        };
        // Non-member.
        let idx = crate::addr::account_id(&pkx);
        let px = PartialSig {
            pubkey: pkx,
            der: sign(&skx, &multisign_digest(&body, &idx)),
        };
        assert_eq!(
            aggregate_verified(&ms, &body, &[px]),
            Err(SigError::NotAMember)
        );
        // Duplicate.
        assert_eq!(
            aggregate_verified(&ms, &body, &[p1.clone(), p1.clone()]),
            Err(SigError::DuplicateSigner)
        );
        // Sub-quorum (1 of required 2).
        let _ = sk2;
        assert_eq!(
            aggregate_verified(&ms, &body, &[p1]),
            Err(SigError::QuorumNotMet { got: 1, quorum: 2 })
        );
    }
}
