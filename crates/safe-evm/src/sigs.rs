//! Safe v1.4.1 signature aggregation — sort by recovered signer
//! address ascending, then concatenate 65-byte ECDSA sigs.
//!
//! Safe's `checkSignatures` iterates the concatenated `bytes signatures`
//! 65 bytes at a time, recovers each signer, and compares against the
//! NEXT-EXPECTED-OWNER in ascending address order. Two consequences:
//!
//! 1. Order matters — sorting by `(v, r, s)` instead of by recovered
//!    address would put the right signatures in the wrong slots and
//!    `checkSignatures` would revert.
//! 2. ECDSA `v` MUST be 27 or 28 (canonical EOA recovery, not
//!    `v == 0/1` which Safe reads as "approved hash" or "contract
//!    signature" — both of which require different setup).

use alloy_primitives::{Address, B256};

/// One ECDSA signature over the Safe `safeTxHash` digest. The signer
/// address is recovered from the signature itself; the daemon's
/// response includes the address as a defence-in-depth so the
/// coordinator can cross-check before aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdsaSig {
    /// 32-byte `r` component.
    pub r: B256,
    /// 32-byte `s` component.
    pub s: B256,
    /// Recovery byte. MUST be 27 or 28.
    pub v: u8,
}

impl EcdsaSig {
    /// Wire-format 65 bytes: `r || s || v` (Safe's expected layout).
    #[must_use]
    pub fn to_65_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(self.r.as_slice());
        out[32..64].copy_from_slice(self.s.as_slice());
        out[64] = self.v;
        out
    }

    /// Parse the 65-byte wire format. Rejects `v` values outside
    /// `{27, 28}` (EIP-2 canonical EOA recovery).
    ///
    /// # Errors
    /// [`AggregateError::NonCanonicalV`] if `v != 27 && v != 28`.
    pub fn from_65_bytes(bytes: [u8; 65]) -> Result<Self, AggregateError> {
        let v = bytes[64];
        if v != 27 && v != 28 {
            return Err(AggregateError::NonCanonicalV(v));
        }
        let mut r = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[32..64]);
        Ok(Self {
            r: B256::from(r),
            s: B256::from(s),
            v,
        })
    }
}

/// A `(signer, signature)` pair — the input to [`aggregate_signatures`].
/// The signer address is the SDK-recovered or coordinator-cross-checked
/// EOA; we use it as the sort key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedBy {
    /// 20-byte signer address.
    pub signer: Address,
    /// The 65-byte ECDSA signature.
    pub sig: EcdsaSig,
}

/// Aggregate k partial signatures into Safe's expected `bytes signatures`
/// blob. Sorts by signer address ASCENDING (Safe's `checkSignatures`
/// invariant), then concatenates the 65-byte sigs.
///
/// Defence-in-depth: also re-recovers each signer from
/// `(safe_tx_hash, sig)` and refuses if any signer disagrees with the
/// claimed `signer` field. The caller passes the digest the sig was
/// produced over (the Safe `safeTxHash` from
/// [`crate::digest::safe_tx_hash`]).
///
/// # Errors
/// - [`AggregateError::DuplicateSigner`] if the same signer appears twice.
/// - [`AggregateError::EmptyInput`] if `parts` is empty.
/// - [`AggregateError::NonCanonicalV`] if any sig has `v != 27 && v != 28`.
/// - [`AggregateError::Recovery`] if any sig fails to recover under the
///   given digest, or recovers to a different address than declared.
pub fn aggregate_signatures(digest: B256, parts: &[SignedBy]) -> Result<Vec<u8>, AggregateError> {
    if parts.is_empty() {
        return Err(AggregateError::EmptyInput);
    }
    let mut sorted: Vec<SignedBy> = parts.to_vec();
    sorted.sort_by_key(|p| p.signer);
    for window in sorted.windows(2) {
        if window[0].signer == window[1].signer {
            return Err(AggregateError::DuplicateSigner(window[0].signer));
        }
    }
    for p in &sorted {
        if p.sig.v != 27 && p.sig.v != 28 {
            return Err(AggregateError::NonCanonicalV(p.sig.v));
        }
        let recovered = recover_signer(digest, &p.sig)?;
        if recovered != p.signer {
            return Err(AggregateError::SignerMismatch {
                declared: p.signer,
                recovered,
            });
        }
    }
    let mut out = Vec::with_capacity(sorted.len() * 65);
    for p in &sorted {
        out.extend_from_slice(&p.sig.to_65_bytes());
    }
    Ok(out)
}

/// Errors from [`aggregate_signatures`] and [`EcdsaSig::from_65_bytes`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AggregateError {
    /// Empty input — Safe requires at least one signature.
    #[error("aggregate input is empty")]
    EmptyInput,
    /// The same signer appeared twice — Safe's `checkSignatures` would
    /// fail at the "owner is in ascending order" check on the duplicate.
    #[error("duplicate signer in aggregate input: {0}")]
    DuplicateSigner(Address),
    /// `v` byte was not 27 or 28. Safe treats `v < 27` as either
    /// "approved hash" (`v == 1`) or "contract signature" (`v == 0`),
    /// neither of which our HSM-signed EOA path produces.
    #[error("non-canonical ECDSA v byte: {0}")]
    NonCanonicalV(u8),
    /// The declared signer address didn't match the address recovered
    /// from `(digest, sig)`. Defends against a malicious daemon
    /// returning a signature whose recovered key isn't in the Safe's
    /// owner set.
    #[error("signer mismatch: declared {declared}, recovered {recovered}")]
    SignerMismatch {
        /// The address the coordinator believed the signature came from.
        declared: Address,
        /// The address actually recovered from the signature.
        recovered: Address,
    },
    /// `ecrecover` produced no point (malformed `(r, s)` — likely the
    /// daemon mangled the sig bytes).
    #[error("ECDSA recovery failed: {0}")]
    Recovery(String),
}

/// Recover the 20-byte signer address from `(digest, sig)`. Uses
/// `alloy_primitives::PrimitiveSignature::recover_address_from_prehash`
/// for the secp256k1 + keccak256 surface.
fn recover_signer(digest: B256, sig: &EcdsaSig) -> Result<Address, AggregateError> {
    use alloy_primitives::PrimitiveSignature;
    // EOA convention: v ∈ {27, 28} ⇒ y_parity ∈ {false, true}.
    let parity = match sig.v {
        27 => false,
        28 => true,
        _ => return Err(AggregateError::NonCanonicalV(sig.v)),
    };
    let s = PrimitiveSignature::from_scalars_and_parity(sig.r, sig.s, parity);
    s.recover_address_from_prehash(&digest)
        .map_err(|e| AggregateError::Recovery(format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, hex, keccak256, B256};

    /// `EcdsaSig::to_65_bytes` followed by `from_65_bytes` is the
    /// identity for canonical signatures.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn ecdsa_sig_wire_round_trip() {
        let sig = EcdsaSig {
            r: B256::from(hex!(
                "1111111111111111111111111111111111111111111111111111111111111111"
            )),
            s: B256::from(hex!(
                "2222222222222222222222222222222222222222222222222222222222222222"
            )),
            v: 27,
        };
        let bytes = sig.to_65_bytes();
        let back = EcdsaSig::from_65_bytes(bytes).expect("parse");
        assert_eq!(back, sig);
    }

    /// `EcdsaSig::from_65_bytes` rejects non-canonical v.
    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn ecdsa_sig_rejects_non_canonical_v() {
        let mut raw = [0u8; 65];
        raw[64] = 0; // v=0 — contract-signature marker in Safe
        let err = EcdsaSig::from_65_bytes(raw).unwrap_err();
        assert_eq!(err, AggregateError::NonCanonicalV(0));

        raw[64] = 1; // v=1 — approved-hash marker in Safe
        let err = EcdsaSig::from_65_bytes(raw).unwrap_err();
        assert_eq!(err, AggregateError::NonCanonicalV(1));
    }

    /// Aggregation refuses empty input.
    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn aggregate_rejects_empty_input() {
        let digest = B256::ZERO;
        let err = aggregate_signatures(digest, &[]).unwrap_err();
        assert_eq!(err, AggregateError::EmptyInput);
    }

    /// Aggregation detects duplicate signers BEFORE recovery (the
    /// signer-mismatch check would also catch a forged duplicate, but
    /// the explicit pre-check produces a more actionable error).
    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn aggregate_rejects_duplicate_signer() {
        let signer = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let bogus_sig = EcdsaSig {
            r: B256::ZERO,
            s: B256::ZERO,
            v: 27,
        };
        let err = aggregate_signatures(
            B256::ZERO,
            &[
                SignedBy {
                    signer,
                    sig: bogus_sig,
                },
                SignedBy {
                    signer,
                    sig: bogus_sig,
                },
            ],
        )
        .unwrap_err();
        assert_eq!(err, AggregateError::DuplicateSigner(signer));
    }

    /// End-to-end: build a digest, sign it with two distinct k1 keys,
    /// aggregate, verify the byte blob has the signatures in ASCENDING
    /// signer-address order regardless of input order.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn aggregate_sorts_ascending_by_signer_address() {
        use alloy_primitives::B256;

        // Generate two deterministic test keys + recover their addresses.
        // We use `alloy_primitives::PrivateKeySigner` for simplicity in
        // a unit-test; the daemon path uses an HSM in production.
        let (a_signer, a_sig) = test_sign(
            B256::from(hex!(
                "1111111111111111111111111111111111111111111111111111111111111111"
            )),
            test_digest(),
        );
        let (b_signer, b_sig) = test_sign(
            B256::from(hex!(
                "2222222222222222222222222222222222222222222222222222222222222222"
            )),
            test_digest(),
        );

        let parts_b_first = vec![
            SignedBy {
                signer: b_signer,
                sig: b_sig,
            },
            SignedBy {
                signer: a_signer,
                sig: a_sig,
            },
        ];
        let parts_a_first = vec![
            SignedBy {
                signer: a_signer,
                sig: a_sig,
            },
            SignedBy {
                signer: b_signer,
                sig: b_sig,
            },
        ];
        // Aggregation result depends ONLY on the set of (signer, sig)
        // pairs, not on input order. The sorted output places the
        // lower address first.
        let agg_b_first = aggregate_signatures(test_digest(), &parts_b_first).expect("agg");
        let agg_a_first = aggregate_signatures(test_digest(), &parts_a_first).expect("agg");
        assert_eq!(agg_b_first, agg_a_first);
        assert_eq!(agg_b_first.len(), 130);

        // First 65 bytes are the lower-address signer's sig.
        let (lower_signer, lower_sig) = if a_signer < b_signer {
            (a_signer, a_sig)
        } else {
            (b_signer, b_sig)
        };
        assert_eq!(&agg_b_first[..65], &lower_sig.to_65_bytes());
        let _ = lower_signer; // suppress unused — pin via assertion above
    }

    /// Aggregation fails the recovery cross-check if the declared
    /// signer is wrong (defence against a malicious daemon).
    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn aggregate_rejects_signer_mismatch() {
        let (real_signer, sig) = test_sign(
            B256::from(hex!(
                "3333333333333333333333333333333333333333333333333333333333333333"
            )),
            test_digest(),
        );
        let bogus = address!("ffffffffffffffffffffffffffffffffffffffff");
        let err =
            aggregate_signatures(test_digest(), &[SignedBy { signer: bogus, sig }]).unwrap_err();
        assert!(
            matches!(err, AggregateError::SignerMismatch { .. }),
            "expected SignerMismatch, got {err:?}"
        );
        // Sanity: the real signer would have aggregated cleanly.
        assert!(aggregate_signatures(
            test_digest(),
            &[SignedBy {
                signer: real_signer,
                sig,
            }]
        )
        .is_ok());
    }

    /// Helper: produce a deterministic test digest.
    fn test_digest() -> B256 {
        B256::from(hex!(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        ))
    }

    /// Helper: sign `digest` with `key_bytes` and return
    /// `(recovered_address, EcdsaSig)`. Uses k256 directly so we don't
    /// have to pull `alloy-signer`.
    #[expect(
        clippy::expect_used,
        reason = "test code — deterministic inputs cannot fail"
    )]
    fn test_sign(key_bytes: B256, digest: B256) -> (Address, EcdsaSig) {
        use alloy_primitives::PrimitiveSignature;
        use k256::ecdsa::{RecoveryId, Signature as K256Sig, SigningKey};

        let sk = SigningKey::from_bytes(key_bytes.as_slice().into()).expect("k256 key");
        let (sig, rec_id): (K256Sig, RecoveryId) = sk
            .sign_prehash_recoverable(digest.as_slice())
            .expect("sign");
        let r_bytes: [u8; 32] = sig.r().to_bytes().into();
        let s_bytes: [u8; 32] = sig.s().to_bytes().into();
        let v: u8 = 27 + rec_id.to_byte();

        // Derive the address by hashing the uncompressed pubkey suffix.
        let vk = sk.verifying_key();
        let pk_bytes = vk.to_encoded_point(false);
        // Skip the 0x04 prefix; keccak256 the 64-byte (X || Y).
        let hash = keccak256(&pk_bytes.as_bytes()[1..]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash.as_slice()[12..]);
        let address = Address::from(addr);

        let ecdsa = EcdsaSig {
            r: B256::from(r_bytes),
            s: B256::from(s_bytes),
            v,
        };

        // Cross-check: recovered address must match.
        let recovered = PrimitiveSignature::from_scalars_and_parity(ecdsa.r, ecdsa.s, v == 28)
            .recover_address_from_prehash(&digest)
            .expect("recover");
        assert_eq!(recovered, address);

        (address, ecdsa)
    }
}
