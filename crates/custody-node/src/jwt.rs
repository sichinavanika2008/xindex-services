//! Mutual RS256 JWT for the Cobo TSS-Node callback (`DL-CUSTODY-COBO-1`).
//!
//! The TSS Node signs every request with its RSA private key; we verify it
//! with the node's public key. We sign our APPROVE/REJECT response with our
//! private key; the node verifies it with our public key. `ring`-backed
//! (jsonwebtoken 9.x) — see the dependency note in `Cargo.toml`.

use std::collections::HashSet;

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

use crate::cobo_types::{CallbackRequest, CallbackResponse};

/// A JWT key/verification failure (opaque — never leaks key material).
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// A PEM did not parse as an RSA key.
    #[error("invalid RSA key PEM: {0}")]
    Key(String),
    /// The incoming request JWT failed signature/parse verification.
    #[error("request JWT verification failed: {0}")]
    Verify(String),
    /// Signing the response JWT failed.
    #[error("response JWT signing failed: {0}")]
    Sign(String),
}

/// The callback's RS256 keys: verify incoming requests with the TSS Node's
/// public key, sign outgoing responses with our private key.
pub struct JwtKeys {
    decode_key: DecodingKey,
    encode_key: EncodingKey,
    validation: Validation,
}

impl std::fmt::Debug for JwtKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtKeys").finish_non_exhaustive()
    }
}

impl JwtKeys {
    /// Build from PEM bytes: `node_pubkey_pem` verifies the TSS Node's request
    /// JWT; `our_privkey_pem` signs our response JWT. Both RS256.
    ///
    /// # Errors
    /// [`JwtError::Key`] if either PEM is not a valid RSA key.
    pub fn from_pems(node_pubkey_pem: &[u8], our_privkey_pem: &[u8]) -> Result<Self, JwtError> {
        let decode_key =
            DecodingKey::from_rsa_pem(node_pubkey_pem).map_err(|e| JwtError::Key(e.to_string()))?;
        let encode_key =
            EncodingKey::from_rsa_pem(our_privkey_pem).map_err(|e| JwtError::Key(e.to_string()))?;
        let mut validation = Validation::new(Algorithm::RS256);
        // The request JWT's claims ARE the CallbackRequest — no standard
        // exp/aud/sub that we control. Verify the SIGNATURE (the security
        // property); leave claim-level exp/aud to dev-env reconciliation. The
        // spend itself is replay-protected by the RIC one-shot, so a replayed
        // JWT re-drives the same request_id → the decision core's one-shot
        // rejects it. RECONCILE AT DEV-ENV: enable `validate_exp` once the
        // request JWT's expiry claim is known.
        validation.required_spec_claims = HashSet::new();
        validation.validate_exp = false;
        validation.validate_aud = false;
        Ok(Self {
            decode_key,
            encode_key,
            validation,
        })
    }

    /// Verify + parse an incoming request JWT into a [`CallbackRequest`].
    ///
    /// # Errors
    /// [`JwtError::Verify`] on a bad signature, a malformed token, or a
    /// missing required field (`request_id`).
    pub fn verify_request(&self, token: &str) -> Result<CallbackRequest, JwtError> {
        decode::<CallbackRequest>(token.trim(), &self.decode_key, &self.validation)
            .map(|data| data.claims)
            .map_err(|e| JwtError::Verify(e.to_string()))
    }

    /// Sign a [`CallbackResponse`] into an outgoing RS256 JWT.
    ///
    /// # Errors
    /// [`JwtError::Sign`] if signing fails (e.g. a malformed private key).
    pub fn sign_response(&self, resp: &CallbackResponse) -> Result<String, JwtError> {
        encode(&Header::new(Algorithm::RS256), resp, &self.encode_key)
            .map_err(|e| JwtError::Sign(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_PRIV: &str = include_str!("../testdata/test_node_priv.pem");
    const NODE_PUB: &str = include_str!("../testdata/test_node_pub.pem");
    const OTHER_PUB: &str = include_str!("../testdata/test_other_pub.pem");

    /// Sign arbitrary claims with `priv_pem` the way a TSS Node would.
    #[expect(clippy::expect_used, reason = "test code")]
    fn node_sign(claims: &serde_json::Value, priv_pem: &str) -> String {
        let key = EncodingKey::from_rsa_pem(priv_pem.as_bytes()).expect("priv key");
        encode(&Header::new(Algorithm::RS256), claims, &key).expect("sign")
    }

    fn req_claims(request_id: &str) -> serde_json::Value {
        serde_json::json!({ "request_id": request_id, "request_type": 2, "request_detail": "{}", "extra_info": "{}" })
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn verifies_node_signed_request() {
        let keys = JwtKeys::from_pems(NODE_PUB.as_bytes(), NODE_PRIV.as_bytes()).expect("keys");
        let token = node_sign(&req_claims("abc-123"), NODE_PRIV);
        let req = keys.verify_request(&token).expect("verify");
        assert_eq!(req.request_id, "abc-123");
        assert!(req.is_key_sign());
    }

    #[test]
    fn rejects_request_signed_by_wrong_key() {
        // Verify against OTHER_PUB a token signed by NODE_PRIV → signature fails.
        #[expect(clippy::expect_used, reason = "test code")]
        let keys = JwtKeys::from_pems(OTHER_PUB.as_bytes(), NODE_PRIV.as_bytes()).expect("keys");
        let token = node_sign(&req_claims("abc-123"), NODE_PRIV);
        assert!(keys.verify_request(&token).is_err());
    }

    #[test]
    fn rejects_tampered_token() {
        #[expect(clippy::expect_used, reason = "test code")]
        let keys = JwtKeys::from_pems(NODE_PUB.as_bytes(), NODE_PRIV.as_bytes()).expect("keys");
        let mut token = node_sign(&req_claims("abc-123"), NODE_PRIV);
        // Flip the last char of the signature segment.
        token.pop();
        token.push(if token.ends_with('A') { 'B' } else { 'A' });
        assert!(keys.verify_request(&token).is_err());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn signs_response_verifiable_by_our_pubkey() {
        // our priv = NODE_PRIV ⇒ our pub = NODE_PUB.
        let keys = JwtKeys::from_pems(NODE_PUB.as_bytes(), NODE_PRIV.as_bytes()).expect("keys");
        let token = keys
            .sign_response(&CallbackResponse::approve())
            .expect("sign");
        let mut v = Validation::new(Algorithm::RS256);
        v.required_spec_claims = HashSet::new();
        v.validate_exp = false;
        let decoded = decode::<serde_json::Value>(
            &token,
            &DecodingKey::from_rsa_pem(NODE_PUB.as_bytes()).expect("pub"),
            &v,
        )
        .expect("decode");
        assert_eq!(
            decoded.claims.get("action").and_then(|a| a.as_str()),
            Some("APPROVE")
        );
    }

    #[test]
    fn bad_pem_is_key_error() {
        let err = JwtKeys::from_pems(b"not a pem", NODE_PRIV.as_bytes());
        assert!(matches!(err, Err(JwtError::Key(_))));
    }
}
