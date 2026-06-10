//! Shared EIP-2 low-S normalization for the secp256k1 daemon families.
//!
//! Factored out of `evm_safe` so the EVM-Safe and TRON sign paths share one
//! implementation (AUD-TRON-LOWS — TRON was the only secp256k1 family without
//! canonical-S enforcement). Solana is ed25519 (no low-S concept); the BTC
//! PSBT path uses `bitcoin::ecdsa` DER which the daemon verifies separately.

use axum::{http::StatusCode, response::Json};
use xindex_shared::signer_wire::{error_codes, ErrorBody};

/// EIP-2 low-S normalization of an HSM's 65-byte `r ‖ s ‖ v`.
///
/// Several verifiers (a Safe `checkSignatures`, java-tron's `checkSign`)
/// reject a high-S ECDSA signature (the malleability rule). If `s` is in the
/// upper half-order we replace it with `n - s` and flip the recovery byte; the
/// `(r, n-s)` pair recovers to the SAME signer with the opposite parity. The
/// HSM (`Web3Signer`) already emits low-S, so this is normally a no-op —
/// defense-in-depth against a non-canonical signing response.
///
/// The `v` convention is preserved (only 27↔28 / 0↔1 are flipped), so callers
/// can normalize while `v` is still in whatever form the HSM returned and
/// convert afterwards. Every caller re-verifies the recovered signer against
/// the configured address AFTER calling this, so a mis-normalization fails
/// closed (never recorded).
///
/// # Errors
/// [`error_codes::SIGNER_RECOVER_MISMATCH`] (500) if `r ‖ s` does not parse as
/// a secp256k1 signature.
pub(crate) fn normalize_low_s(sig: [u8; 65]) -> Result<[u8; 65], (StatusCode, Json<ErrorBody>)> {
    let parsed = k256::ecdsa::Signature::from_slice(&sig[..64]).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                code: error_codes::SIGNER_RECOVER_MISMATCH.to_string(),
                message: format!("HSM signature r||s did not parse: {e}"),
            }),
        )
    })?;
    let mut out = sig;
    if let Some(low) = parsed.normalize_s() {
        out[..64].copy_from_slice(&low.to_bytes());
        out[64] = match sig[64] {
            27 => 28,
            28 => 27,
            0 => 1,
            1 => 0,
            v => v,
        };
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, PrimitiveSignature};
    use k256::ecdsa::{Signature, SigningKey};

    /// Recover the EVM address of a k256 key (keccak of the uncompressed
    /// pubkey, last 20 bytes).
    fn evm_addr(sk: &SigningKey) -> Address {
        let unc = sk.verifying_key().to_encoded_point(false);
        let h = alloy_primitives::keccak256(&unc.as_bytes()[1..]);
        Address::from_slice(&h.as_slice()[12..])
    }

    /// A low-S signature passes through unchanged.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn low_s_signature_unchanged() {
        let sk = SigningKey::from_slice(&[5u8; 32]).expect("key");
        let digest = [0x42u8; 32];
        let (sig, recid) = sk.sign_prehash_recoverable(&digest).expect("sign"); // low-S
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&sig.to_bytes());
        bytes[64] = 27 + recid.to_byte();
        assert_eq!(normalize_low_s(bytes).expect("normalize"), bytes);
    }

    /// A high-S signature is normalized to low-S, the recovery byte is
    /// flipped, and the result still recovers to the signer.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn high_s_signature_is_normalized_and_recovers() {
        let sk = SigningKey::from_slice(&[9u8; 32]).expect("key");
        let digest = [0x11u8; 32];
        let (low, recid) = sk.sign_prehash_recoverable(&digest).expect("sign");
        let low_v = 27 + recid.to_byte();
        // High-S counterpart: (r, n - s); recovers with the opposite parity.
        let neg_s = -*low.s();
        let high = Signature::from_scalars(low.r().to_bytes(), neg_s.to_bytes()).expect("high sig");
        assert!(high.normalize_s().is_some(), "expected a high-S signature");
        let high_v = if low_v == 27 { 28 } else { 27 };
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&high.to_bytes());
        bytes[64] = high_v;

        let out = normalize_low_s(bytes).expect("normalize");
        // Output is the canonical low-S form with the flipped recovery byte.
        assert_eq!(&out[..64], &low.to_bytes()[..]);
        assert_eq!(out[64], low_v);
        assert!(
            Signature::from_slice(&out[..64])
                .expect("parse")
                .normalize_s()
                .is_none(),
            "output must be low-S"
        );
        // And it recovers to the signer.
        let recovered = PrimitiveSignature::try_from(out.as_slice())
            .expect("parse")
            .recover_address_from_prehash(&alloy_primitives::B256::from(digest))
            .expect("recover");
        assert_eq!(recovered, evm_addr(&sk));
    }
}
