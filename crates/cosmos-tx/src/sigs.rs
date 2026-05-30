//! secp256k1 helpers for the Cosmos multisig.
//!
//! Three things distinguish the Cosmos signature path from the EVM/BTC
//! one already in the workspace:
//!
//! 1. **Non-recoverable, 64-byte.** Cosmos signatures are compact
//!    `r ‖ s` with NO recovery byte. The daemon cannot `ecrecover` the
//!    signer — it must [`verify`] against the configured member pubkey.
//! 2. **Low-S is mandatory.** Cosmos REJECTS high-S signatures (it does
//!    not auto-normalize like the EVM path tolerates via the recovery
//!    bit). [`to_cosmos_compact_low_s`] normalizes the HSM's `(r, s)` to
//!    low-S, and [`verify`] refuses a high-S signature outright.
//! 3. **Aggregation is positional.** k members' 64-byte sigs are placed
//!    into a `MultiSignature` in ascending member-index order, paired
//!    with a `CompactBitArray` marking which members signed
//!    ([`aggregate`]).

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};

use crate::proto;

/// Normalize an HSM-produced `(r, s)` ECDSA signature to low-S form and
/// return the 64-byte compact `r ‖ s` Cosmos expects. Drops any recovery
/// byte (the caller passes only `r` and `s`).
///
/// # Errors
/// [`SigError::Malformed`] if `(r, s)` does not parse as a valid
/// secp256k1 signature.
pub fn to_cosmos_compact_low_s(r: &[u8; 32], s: &[u8; 32]) -> Result<[u8; 64], SigError> {
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(r);
    raw[32..].copy_from_slice(s);
    let sig = Signature::from_slice(&raw).map_err(|e| SigError::Malformed(e.to_string()))?;
    // `normalize_s` returns `Some(low)` iff the input WAS high-S.
    let low = sig.normalize_s().unwrap_or(sig);
    let mut out = [0u8; 64];
    out.copy_from_slice(low.to_bytes().as_ref());
    Ok(out)
}

/// Verify a 64-byte compact signature against a 33-byte compressed member
/// pubkey over a 32-byte prehash (= `SHA-256(amino StdSignDoc)`). Refuses
/// high-S signatures, matching Cosmos consensus.
///
/// # Errors
/// - [`SigError::BadPubkey`] if `pubkey_compressed` is not a valid point.
/// - [`SigError::Malformed`] if `sig64` does not parse.
/// - [`SigError::HighS`] if the signature is not low-S.
/// - [`SigError::Verify`] if the signature does not verify.
pub fn verify(
    pubkey_compressed: &[u8; 33],
    prehash: &[u8; 32],
    sig64: &[u8; 64],
) -> Result<(), SigError> {
    let vk = VerifyingKey::from_sec1_bytes(pubkey_compressed)
        .map_err(|e| SigError::BadPubkey(e.to_string()))?;
    let sig = Signature::from_slice(sig64).map_err(|e| SigError::Malformed(e.to_string()))?;
    if sig.normalize_s().is_some() {
        return Err(SigError::HighS);
    }
    vk.verify_prehash(prehash, &sig)
        .map_err(|e| SigError::Verify(e.to_string()))
}

/// One member's contribution to a multisig signature: its frozen member
/// index + the 64-byte low-S signature over the shared sign-bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberSig {
    /// Position of the signing member in the frozen multisig order.
    pub member_index: usize,
    /// The member's 64-byte compact low-S signature.
    pub sig64: [u8; 64],
}

/// The proto-encoded aggregate that goes into the multisig tx.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedMultisig {
    /// proto bytes of `cosmos.crypto.multisig.v1beta1.CompactBitArray`
    /// (placed in `ModeInfo.Multi.bitarray`).
    pub compact_bitarray: Vec<u8>,
    /// proto bytes of `cosmos.crypto.multisig.v1beta1.MultiSignature`
    /// (placed in `Tx.signatures[signer_index]`).
    pub multi_signature: Vec<u8>,
    /// Number of members that signed.
    pub signed_count: usize,
}

/// Aggregate ≥ `threshold` member signatures into the `CompactBitArray` +
/// `MultiSignature` proto messages. Signatures are emitted in ascending
/// member-index order (the Cosmos multisig invariant); the bitarray marks
/// each signing member's position.
///
/// # Errors
/// - [`SigError::NoMembers`] if `total_members == 0`.
/// - [`SigError::EmptyInput`] if `parts` is empty.
/// - [`SigError::DuplicateMemberIndex`] if a member index appears twice.
/// - [`SigError::IndexOutOfRange`] if any index `>= total_members`.
/// - [`SigError::BelowThreshold`] if fewer than `threshold` sigs.
pub fn aggregate(
    total_members: usize,
    threshold: u32,
    parts: &[MemberSig],
) -> Result<AggregatedMultisig, SigError> {
    if total_members == 0 {
        return Err(SigError::NoMembers);
    }
    if parts.is_empty() {
        return Err(SigError::EmptyInput);
    }
    let mut sorted: Vec<MemberSig> = parts.to_vec();
    sorted.sort_by_key(|p| p.member_index);
    for w in sorted.windows(2) {
        if w[0].member_index == w[1].member_index {
            return Err(SigError::DuplicateMemberIndex(w[0].member_index));
        }
    }
    for p in &sorted {
        if p.member_index >= total_members {
            return Err(SigError::IndexOutOfRange {
                index: p.member_index,
                total: total_members,
            });
        }
    }
    if u32::try_from(sorted.len()).unwrap_or(u32::MAX) < threshold {
        return Err(SigError::BelowThreshold {
            got: sorted.len(),
            threshold,
        });
    }

    // CompactBitArray over `total_members` bits, MSB-first per byte
    // (cosmos-sdk `CompactBitArray.SetIndex`).
    let mut elems = vec![0u8; total_members.div_ceil(8)];
    for p in &sorted {
        let i = p.member_index;
        elems[i >> 3] |= 1u8 << (7 - (i % 8));
    }
    let extra_bits = u32::try_from(total_members % 8).unwrap_or(0);
    let mut compact_bitarray = Vec::new();
    if extra_bits != 0 {
        // proto3 omits a zero `extra_bits_stored` (field 1).
        proto::put_varint_field(1, u64::from(extra_bits), &mut compact_bitarray);
    }
    proto::put_len_delim(2, &elems, &mut compact_bitarray);

    // MultiSignature.signatures (repeated bytes, field 1) in member order.
    let mut multi_signature = Vec::new();
    for p in &sorted {
        proto::put_len_delim(1, &p.sig64, &mut multi_signature);
    }

    Ok(AggregatedMultisig {
        compact_bitarray,
        multi_signature,
        signed_count: sorted.len(),
    })
}

/// Errors from the secp256k1 + aggregation helpers.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SigError {
    /// Signature bytes did not parse as a valid secp256k1 signature.
    #[error("signature bytes malformed: {0}")]
    Malformed(String),
    /// Public-key bytes did not parse as a valid compressed point.
    #[error("public key malformed: {0}")]
    BadPubkey(String),
    /// Signature is high-S — Cosmos consensus rejects it.
    #[error("signature is not in low-S form (Cosmos rejects high-S)")]
    HighS,
    /// Signature did not verify under the given pubkey + prehash.
    #[error("signature verification failed: {0}")]
    Verify(String),
    /// `total_members == 0`.
    #[error("multisig has zero members")]
    NoMembers,
    /// No member signatures were supplied.
    #[error("no member signatures supplied")]
    EmptyInput,
    /// The same member index appeared twice.
    #[error("duplicate member index {0}")]
    DuplicateMemberIndex(usize),
    /// A member index was out of range for the member count.
    #[error("member index {index} out of range for {total} members")]
    IndexOutOfRange {
        /// The offending index.
        index: usize,
        /// The member count.
        total: usize,
    },
    /// Fewer signatures than the threshold.
    #[error("only {got} signatures, need threshold {threshold}")]
    BelowThreshold {
        /// Signatures supplied.
        got: usize,
        /// Required threshold.
        threshold: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::PrimeField;

    /// Sign a digest, normalize to the Cosmos compact form, and verify it
    /// round-trips: the output is low-S and verifies against the pubkey.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn sign_normalize_verify_round_trip() {
        let sk = SigningKey::from_slice(&[7u8; 32]).expect("key");
        let digest = [9u8; 32];
        let sig: Signature = sk.sign_prehash(&digest).expect("sign");
        let mut sb = [0u8; 64];
        sb.copy_from_slice(sig.to_bytes().as_ref());
        let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
        r.copy_from_slice(&sb[..32]);
        s.copy_from_slice(&sb[32..]);

        let cosmos = to_cosmos_compact_low_s(&r, &s).expect("low-s");
        // Output is low-S.
        assert!(Signature::from_slice(&cosmos)
            .expect("parse")
            .normalize_s()
            .is_none());

        let ep = sk.verifying_key().to_encoded_point(true);
        let mut pk = [0u8; 33];
        pk.copy_from_slice(ep.as_bytes());
        verify(&pk, &digest, &cosmos).expect("verify");
    }

    /// A high-S signature (`s' = n - s`) is normalized back to the low-S
    /// form by [`to_cosmos_compact_low_s`], and [`verify`] rejects the raw
    /// high-S form with [`SigError::HighS`].
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn high_s_is_normalized_and_rejected() {
        let sk = SigningKey::from_slice(&[7u8; 32]).expect("key");
        let digest = [9u8; 32];
        let sig: Signature = sk.sign_prehash(&digest).expect("sign");
        let mut sb = [0u8; 64];
        sb.copy_from_slice(sig.to_bytes().as_ref());
        let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
        r.copy_from_slice(&sb[..32]);
        s.copy_from_slice(&sb[32..]);

        // s_high = n - s (the other valid-but-rejected representation).
        let s_scalar =
            Option::<k256::Scalar>::from(k256::Scalar::from_repr(s.into())).expect("scalar");
        let s_high = -s_scalar;
        let mut s_high_bytes = [0u8; 32];
        s_high_bytes.copy_from_slice(s_high.to_bytes().as_ref());

        // Normalizing the high-S input yields the canonical low-S output.
        let canon = to_cosmos_compact_low_s(&r, &s).expect("low");
        let recanon = to_cosmos_compact_low_s(&r, &s_high_bytes).expect("renorm");
        assert_eq!(recanon, canon);

        // verify() refuses the raw high-S signature.
        let ep = sk.verifying_key().to_encoded_point(true);
        let mut pk = [0u8; 33];
        pk.copy_from_slice(ep.as_bytes());
        let mut raw_high = [0u8; 64];
        raw_high[..32].copy_from_slice(&r);
        raw_high[32..].copy_from_slice(&s_high_bytes);
        assert_eq!(
            verify(&pk, &digest, &raw_high).expect_err("must be high-s"),
            SigError::HighS
        );
    }

    /// `verify()` rejects a wrong pubkey.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn verify_rejects_wrong_pubkey() {
        let sk = SigningKey::from_slice(&[7u8; 32]).expect("key");
        let other = SigningKey::from_slice(&[8u8; 32]).expect("key2");
        let digest = [9u8; 32];
        let sig: Signature = sk.sign_prehash(&digest).expect("sign");
        let mut sb = [0u8; 64];
        sb.copy_from_slice(sig.to_bytes().as_ref());
        let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
        r.copy_from_slice(&sb[..32]);
        s.copy_from_slice(&sb[32..]);
        let cosmos = to_cosmos_compact_low_s(&r, &s).expect("low");

        let ep = other.verifying_key().to_encoded_point(true);
        let mut pk = [0u8; 33];
        pk.copy_from_slice(ep.as_bytes());
        assert!(matches!(
            verify(&pk, &digest, &cosmos).expect_err("must fail"),
            SigError::Verify(_)
        ));
    }

    /// Aggregation: 3-of-5, members {0,2,4} sign (supplied out of order).
    /// Sorted ascending; bitarray bits 0/2/4 set MSB-first; `MultiSignature`
    /// holds 3 length-delimited 64-byte sigs.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn aggregate_builds_bitarray_and_multisig() {
        let parts = [
            MemberSig {
                member_index: 4,
                sig64: [4u8; 64],
            },
            MemberSig {
                member_index: 0,
                sig64: [0u8; 64],
            },
            MemberSig {
                member_index: 2,
                sig64: [2u8; 64],
            },
        ];
        let agg = aggregate(5, 3, &parts).expect("aggregate");
        assert_eq!(agg.signed_count, 3);
        // bits 0,2,4 over 5 members → byte 0b1010_1000 = 0xA8; extra_bits 5.
        // proto: field1 varint(5)=0x08 0x05, field2 len-delim(0xA8)=0x12 0x01 0xA8.
        assert_eq!(agg.compact_bitarray, vec![0x08, 0x05, 0x12, 0x01, 0xA8]);
        // 3 sigs × (tag 0x0a + len 0x40 + 64 bytes) = 3 × 66 = 198 bytes.
        assert_eq!(agg.multi_signature.len(), 198);
        // First emitted sig is member 0's (ascending order).
        assert_eq!(&agg.multi_signature[..2], &[0x0a, 0x40]);
        assert_eq!(&agg.multi_signature[2..66], &[0u8; 64]);
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn aggregate_below_threshold_errors() {
        let parts = [
            MemberSig {
                member_index: 0,
                sig64: [0u8; 64],
            },
            MemberSig {
                member_index: 1,
                sig64: [1u8; 64],
            },
        ];
        assert_eq!(
            aggregate(5, 3, &parts).unwrap_err(),
            SigError::BelowThreshold {
                got: 2,
                threshold: 3
            }
        );
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn aggregate_rejects_duplicate_and_out_of_range() {
        let dup = [
            MemberSig {
                member_index: 1,
                sig64: [0u8; 64],
            },
            MemberSig {
                member_index: 1,
                sig64: [1u8; 64],
            },
        ];
        assert_eq!(
            aggregate(5, 1, &dup).unwrap_err(),
            SigError::DuplicateMemberIndex(1)
        );
        let oor = [MemberSig {
            member_index: 5,
            sig64: [0u8; 64],
        }];
        assert_eq!(
            aggregate(5, 1, &oor).unwrap_err(),
            SigError::IndexOutOfRange { index: 5, total: 5 }
        );
    }
}
