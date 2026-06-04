//! ed25519 signing + strict verification for Solana messages.
//!
//! Solana signs the serialized legacy **message** (not a hash of it) with
//! ed25519; the 64-byte signatures are prepended to the message to form
//! the transaction. This is the first Xindex custody family on ed25519 —
//! every other family is secp256k1.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::{Pubkey, SolanaTxError};

/// Derive the 32-byte ed25519 public key from a 32-byte secret seed.
#[must_use]
pub fn pubkey_from_seed(seed: &[u8; 32]) -> Pubkey {
    let sk = SigningKey::from_bytes(seed);
    Pubkey::new(sk.verifying_key().to_bytes())
}

/// Sign `message` with the 32-byte ed25519 secret seed; returns the
/// 64-byte detached signature.
#[must_use]
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let sk = SigningKey::from_bytes(seed);
    sk.sign(message).to_bytes()
}

/// Strictly verify a 64-byte ed25519 signature over `message` under
/// `pubkey`. Strict verification rejects malleable / small-order points.
///
/// # Errors
/// Returns [`SolanaTxError::Ed25519`] if the public key is malformed or
/// the signature does not verify.
pub fn verify(pubkey: &Pubkey, message: &[u8], signature: &[u8; 64]) -> Result<(), SolanaTxError> {
    let vk = VerifyingKey::from_bytes(pubkey.as_bytes())
        .map_err(|e| SolanaTxError::Ed25519(e.to_string()))?;
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(message, &sig)
        .map_err(|e| SolanaTxError::Ed25519(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn sign_then_verify_round_trip() {
        let seed = [9u8; 32];
        let pk = pubkey_from_seed(&seed);
        let msg = b"solana legacy message bytes";
        let sig = sign(&seed, msg);
        verify(&pk, msg, &sig).expect("valid signature verifies");
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let seed = [9u8; 32];
        let pk = pubkey_from_seed(&seed);
        let sig = sign(&seed, b"original");
        assert!(verify(&pk, b"tampered", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_pubkey() {
        let sig = sign(&[9u8; 32], b"msg");
        let other = pubkey_from_seed(&[10u8; 32]);
        assert!(verify(&other, b"msg", &sig).is_err());
    }
}
