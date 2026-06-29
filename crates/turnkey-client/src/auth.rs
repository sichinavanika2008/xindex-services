//! Turnkey request authentication (P-256 API-key stamp).
//!
//! Every Turnkey request carries an `X-Stamp` header: a base64url(no-pad) JSON
//! object `{publicKey, scheme, signature}` where `signature` is the
//! DER-encoded ECDSA-P256 signature over the **exact request body string**
//! (the `ecdsa` crate hashes the body with SHA-256), `scheme` is
//! `SIGNATURE_SCHEME_TK_API_P256`, and `publicKey` is the compressed SEC1
//! public key (hex). The server re-stamps the same body and checks the
//! signature, so the stamp binds the signer to the precise bytes sent.
//!
//! RECONCILE AT DEV-ENV: confirm the stamp is computed over the raw body (not a
//! canonicalized form) and that the DER (not fixed r‖s) encoding is expected —
//! both pinned from Turnkey's `@turnkey/api-key-stamper`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

use crate::TurnkeyError;

/// The Turnkey API-key signature scheme tag carried in the stamp.
const STAMP_SCHEME: &str = "SIGNATURE_SCHEME_TK_API_P256";

/// Holds the P-256 API private key and produces the `X-Stamp` header value.
pub struct TurnkeyStamper {
    signing_key: SigningKey,
    public_key_hex: String,
}

impl std::fmt::Debug for TurnkeyStamper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("TurnkeyStamper")
            .field("public_key_hex", &self.public_key_hex)
            .finish_non_exhaustive()
    }
}

impl TurnkeyStamper {
    /// Build from the hex-encoded 32-byte P-256 API private key.
    ///
    /// # Errors
    /// [`TurnkeyError::Auth`] if the hex is malformed or not a valid scalar.
    pub fn from_hex(api_private_key_hex: &str) -> Result<Self, TurnkeyError> {
        let bytes = alloy_primitives::hex::decode(api_private_key_hex.trim())
            .map_err(|e| TurnkeyError::Auth(format!("bad api private key hex: {e}")))?;
        let signing_key = SigningKey::from_slice(&bytes)
            .map_err(|e| TurnkeyError::Auth(format!("invalid P-256 private key: {e}")))?;
        let point = signing_key.verifying_key().to_encoded_point(true);
        let public_key_hex = alloy_primitives::hex::encode(point.as_bytes());
        Ok(Self {
            signing_key,
            public_key_hex,
        })
    }

    /// The compressed SEC1 public key (hex) — the Turnkey API public key, used
    /// to register the key and carried in every stamp.
    #[must_use]
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// The `X-Stamp` header value over `body`: base64url(no-pad) of
    /// `{publicKey, scheme, signature}` with a DER-encoded SHA-256 ECDSA-P256
    /// signature.
    ///
    /// # Errors
    /// [`TurnkeyError::Auth`] if the stamp JSON cannot be serialized.
    pub fn stamp(&self, body: &str) -> Result<String, TurnkeyError> {
        let sig: Signature = self.signing_key.sign(body.as_bytes());
        let signature_hex = alloy_primitives::hex::encode(sig.to_der().as_bytes());
        let stamp = serde_json::json!({
            "publicKey": self.public_key_hex,
            "scheme": STAMP_SCHEME,
            "signature": signature_hex,
        });
        let json = serde_json::to_string(&stamp).map_err(|e| TurnkeyError::Auth(e.to_string()))?;
        Ok(URL_SAFE_NO_PAD.encode(json.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    // Throwaway 32-byte P-256 private key (test-only). A valid non-zero scalar.
    const TEST_KEY: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn from_hex_rejects_bad_key() {
        assert!(TurnkeyStamper::from_hex("00").is_err());
        // All-zero scalar is not a valid P-256 signing key.
        assert!(TurnkeyStamper::from_hex(&"00".repeat(32)).is_err());
        TurnkeyStamper::from_hex(TEST_KEY).expect("valid key");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn public_key_is_compressed_sec1() {
        let s = TurnkeyStamper::from_hex(TEST_KEY).expect("stamper");
        let pk = s.public_key_hex();
        // 33-byte compressed point → 66 hex chars, leading 02/03.
        assert_eq!(pk.len(), 66);
        assert!(pk.starts_with("02") || pk.starts_with("03"));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn stamp_is_base64url_and_signature_verifies() {
        let stamper = TurnkeyStamper::from_hex(TEST_KEY).expect("stamper");
        let body = r#"{"type":"ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2"}"#;
        let header = stamper.stamp(body).expect("stamp");

        // Decode the stamp envelope.
        let raw = URL_SAFE_NO_PAD.decode(&header).expect("b64url");
        let env: serde_json::Value = serde_json::from_slice(&raw).expect("json");
        assert_eq!(env["scheme"], STAMP_SCHEME);
        assert_eq!(env["publicKey"], stamper.public_key_hex());

        // The DER signature must verify against the public key over the body
        // (SHA-256 ECDSA-P256, as the `ecdsa` Verifier does).
        let sig_der = alloy_primitives::hex::decode(env["signature"].as_str().expect("sig"))
            .expect("sig hex");
        let sig = Signature::from_der(&sig_der).expect("der");
        let pk_bytes = alloy_primitives::hex::decode(stamper.public_key_hex()).expect("pk hex");
        let vk = VerifyingKey::from_sec1_bytes(&pk_bytes).expect("vk");
        assert!(vk.verify(body.as_bytes(), &sig).is_ok());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn different_body_changes_stamp() {
        let stamper = TurnkeyStamper::from_hex(TEST_KEY).expect("stamper");
        let a = stamper.stamp(r#"{"a":1}"#).expect("a");
        let b = stamper.stamp(r#"{"a":2}"#).expect("b");
        assert_ne!(a, b);
    }
}
