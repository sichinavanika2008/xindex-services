//! Cobo v2 request authentication (Ed25519).
//!
//! Per Cobo's scheme, each request carries three headers — `Biz-Api-Key` (the
//! API key = our Ed25519 public key, hex), `Biz-Api-Nonce` (unix ms), and
//! `Biz-Api-Signature` (hex) — where the signature is
//! `Ed25519(sha256(sha256("{METHOD}|{PATH}|{NONCE}|{PARAMS}|{BODY}")))`.
//!
//! RECONCILE AT DEV-ENV: the exact `PATH` form (we sign the full request path
//! incl. `/v2`) and whether `PARAMS` is the raw query string — confirm against
//! `api.dev.cobo.com` / the Cobo SDKs before production.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use crate::CoboError;

/// Holds the Ed25519 API secret and produces the `Biz-Api-*` request headers.
pub struct CoboSigner {
    signing_key: SigningKey,
}

impl std::fmt::Debug for CoboSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("CoboSigner").finish_non_exhaustive()
    }
}

impl CoboSigner {
    /// Build from the hex-encoded 32-byte Ed25519 API secret.
    ///
    /// # Errors
    /// [`CoboError::Auth`] if the hex is malformed or not 32 bytes.
    pub fn from_hex(api_secret_hex: &str) -> Result<Self, CoboError> {
        let bytes = alloy_primitives::hex::decode(api_secret_hex.trim())
            .map_err(|e| CoboError::Auth(format!("bad api secret hex: {e}")))?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            CoboError::Auth(format!("api secret must be 32 bytes, got {}", bytes.len()))
        })?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&arr),
        })
    }

    /// The API key (Ed25519 public key, hex) for the `Biz-Api-Key` header.
    #[must_use]
    pub fn api_key_hex(&self) -> String {
        alloy_primitives::hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// The `Biz-Api-Signature` hex over `{method}|{path}|{nonce}|{params}|{body}`
    /// (double-SHA-256 then Ed25519).
    #[must_use]
    pub fn sign(&self, method: &str, path: &str, nonce: &str, params: &str, body: &str) -> String {
        let str_to_sign = format!("{method}|{path}|{nonce}|{params}|{body}");
        let inner = Sha256::digest(str_to_sign.as_bytes());
        let outer = Sha256::digest(inner);
        let sig = self.signing_key.sign(&outer);
        alloy_primitives::hex::encode(sig.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    // Throwaway 32-byte Ed25519 secret (test-only).
    const TEST_SECRET: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn from_hex_rejects_wrong_length() {
        assert!(CoboSigner::from_hex("00").is_err());
        // Valid length parses.
        CoboSigner::from_hex(TEST_SECRET).expect("valid 32-byte secret");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn signature_is_deterministic_and_verifies() {
        let signer = CoboSigner::from_hex(TEST_SECRET).expect("signer");
        let a = signer.sign(
            "POST",
            "/v2/transactions/contract_call",
            "1700000000000",
            "",
            "{}",
        );
        let b = signer.sign(
            "POST",
            "/v2/transactions/contract_call",
            "1700000000000",
            "",
            "{}",
        );
        assert_eq!(a, b, "Ed25519 is deterministic");
        assert_eq!(a.len(), 128, "64-byte sig as hex");

        // The signature must verify against the api key over the double-sha256.
        let pk_bytes: [u8; 32] = alloy_primitives::hex::decode(signer.api_key_hex())
            .expect("pk hex")
            .as_slice()
            .try_into()
            .expect("32-byte pk");
        let vk = VerifyingKey::from_bytes(&pk_bytes).expect("vk");
        let inner =
            Sha256::digest("POST|/v2/transactions/contract_call|1700000000000||{}".as_bytes());
        let outer = Sha256::digest(inner);
        let sig_bytes: [u8; 64] = alloy_primitives::hex::decode(&a)
            .expect("sig hex")
            .as_slice()
            .try_into()
            .expect("64");
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(vk.verify(&outer, &sig).is_ok());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn different_body_changes_signature() {
        let signer = CoboSigner::from_hex(TEST_SECRET).expect("signer");
        let a = signer.sign("POST", "/v2/x", "1", "", "{\"a\":1}");
        let b = signer.sign("POST", "/v2/x", "1", "", "{\"a\":2}");
        assert_ne!(a, b);
    }
}
