//! HSM-frontend HTTP client (PART 5 / DL-M5-2).
//!
//! The daemon owns the final 32-byte EIP-712 digest (or PSBT sighash)
//! and asks a local HSM frontend to **sign it raw**, never asking the
//! frontend to hash the message — this defuses the keccak-double-hash
//! hazard inherent in `Web3Signer`'s stock `eth1/sign` endpoint (which
//! applies Keccak-256 to its input).
//!
//! The locked production deployment is a `Web3Signer`-class HTTP
//! service fronting a `YubiHSM2` over PKCS#11; the daemon's *code*
//! depends only on this trait, so the choice of HSM-frontend
//! implementation (a `Web3Signer` fork with a raw-digest endpoint, a
//! custom thin Rust wrapper over PKCS#11, etc.) is an operator-side
//! integration decision audited separately, not a code-completion gate.
//!
//! Wire contract:
//! ```json
//! POST {base_url}/sign
//!   { "address": "0x…20-byte hex", "digest": "0x…32-byte hex" }
//!   → 200 { "signature": "0x…65-byte hex" }
//!   → 5xx / 4xx → error → daemon returns 503 hsm_unavailable
//! ```
//!
//! Defaults are deliberately minimal — production deployments will
//! point at a co-located signing service on loopback or a UDS, behind
//! the daemon's own mTLS perimeter.

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors surfaced by the HSM frontend client.
#[derive(Debug, Error)]
pub enum HsmError {
    /// Transport failure talking to the local HSM frontend (network,
    /// timeout, TLS).
    #[error("transport: {0}")]
    Transport(String),

    /// Non-2xx response from the HSM frontend.
    #[error("http {status}")]
    Status { status: u16 },

    /// Response did not decode into the expected shape, or the returned
    /// signature was not 65 bytes hex.
    #[error("decode: {0}")]
    Decode(String),
}

/// Daemon-facing signing trait. Decouples the daemon's request flow
/// from the choice of HSM frontend so the handler tests can run
/// against a software-backed mock and production swaps in the real
/// HTTP client.
#[async_trait::async_trait]
pub trait HsmDigestSigner: Send + Sync {
    /// Sign `digest` (the final 32-byte EIP-712 typed-data hash) with
    /// the key identified by `address`. Returns 65 bytes (`r ‖ s ‖ v`,
    /// v ∈ {27, 28}) ready for the on-chain `attest*` `bytes[]`
    /// argument.
    ///
    /// # Errors
    /// Any of the variants in [`HsmError`].
    async fn sign_digest(&self, address: Address, digest: B256) -> Result<[u8; 65], HsmError>;
}

/// JSON request body (the daemon → HSM-frontend contract).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignRequestBody {
    /// `0x`-prefixed 20-byte Ethereum address of the signing key.
    pub address: String,
    /// `0x`-prefixed 32-byte digest to sign **raw** (no further hashing).
    pub digest: String,
}

/// JSON response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignResponseBody {
    /// `0x`-prefixed 65-byte `r ‖ s ‖ v` signature (v ∈ {27, 28}).
    pub signature: String,
}

/// Production HTTP client.
///
/// `base_url` is the HSM frontend root (e.g. `http://127.0.0.1:9000`);
/// the client appends `/sign` for the signing endpoint. The
/// production deployment runs the HSM frontend on loopback inside the
/// daemon's own mTLS perimeter — no operator credential, no public
/// network exposure.
#[derive(Clone)]
pub struct HttpHsmClient {
    base_url: String,
    inner: Option<reqwest::Client>,
}

impl std::fmt::Debug for HttpHsmClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpHsmClient")
            .field("base_url", &"<redacted>")
            .field("configured", &self.inner.is_some())
            .finish()
    }
}

impl HttpHsmClient {
    /// Construct against `base_url`. Builds a fresh `reqwest::Client`
    /// with a 5-second timeout — production HSM signs in single-digit
    /// milliseconds; anything slower is treated as a fault.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_timeout(base_url, std::time::Duration::from_secs(5))
    }

    #[must_use]
    pub fn with_timeout(base_url: impl Into<String>, timeout: std::time::Duration) -> Self {
        let inner = reqwest::Client::builder().timeout(timeout).build().ok();
        Self {
            base_url: base_url.into(),
            inner,
        }
    }
}

#[async_trait::async_trait]
impl HsmDigestSigner for HttpHsmClient {
    async fn sign_digest(&self, address: Address, digest: B256) -> Result<[u8; 65], HsmError> {
        let req = SignRequestBody {
            address: format!("{address:#x}"),
            digest: format!("{digest:#x}"),
        };
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| HsmError::Transport("client configuration".to_string()))?;
        let resp = inner
            .post(format!("{}/sign", self.base_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| HsmError::Transport(transport_class(&e).to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(HsmError::Status {
                status: status.as_u16(),
            });
        }
        let body: SignResponseBody = resp
            .json()
            .await
            .map_err(|_| HsmError::Decode("malformed response json".to_string()))?;
        parse_signature_hex(&body.signature)
    }
}

fn transport_class(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_request() {
        "request"
    } else if error.is_body() {
        "body"
    } else {
        "unknown"
    }
}

/// Parse a `0x`-prefixed 65-byte signature hex into the on-chain
/// `r ‖ s ‖ v` byte array. `v` is left as the HSM frontend produced
/// it; the caller is responsible for ensuring the frontend returns
/// `v ∈ {27, 28}` (i.e. produces signatures in the format the on-chain
/// `ECDSA.recover` expects).
fn parse_signature_hex(s: &str) -> Result<[u8; 65], HsmError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = alloy_primitives::hex::decode(stripped)
        .map_err(|e| HsmError::Decode(format!("signature hex: {e}")))?;
    let arr: [u8; 65] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| HsmError::Decode(format!("signature length {} ≠ 65", bytes.len())))?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_signature_hex_round_trip() {
        let bytes: Vec<u8> = (0u8..65).collect();
        let s = format!("0x{}", alloy_primitives::hex::encode(&bytes));
        #[expect(clippy::expect_used, reason = "test code")]
        let arr = parse_signature_hex(&s).expect("parse");
        assert_eq!(arr.as_slice(), bytes.as_slice());
    }

    #[test]
    fn parse_signature_hex_accepts_no_prefix() {
        let bytes: Vec<u8> = (10u8..75).collect();
        let s = alloy_primitives::hex::encode(&bytes);
        #[expect(clippy::expect_used, reason = "test code")]
        let arr = parse_signature_hex(&s).expect("parse");
        assert_eq!(arr.as_slice(), bytes.as_slice());
    }

    #[test]
    fn parse_signature_hex_rejects_wrong_length() {
        assert!(parse_signature_hex("0x00").is_err());
        assert!(parse_signature_hex("0xZZ").is_err());
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn http_client_round_trip_via_mock() {
        let server = wiremock::MockServer::start().await;
        let address = Address::repeat_byte(0xab);
        let digest = B256::repeat_byte(0xcd);
        // The signature the mock will return.
        let sig_bytes: Vec<u8> = (1u8..66).collect();
        let sig_hex = format!("0x{}", alloy_primitives::hex::encode(&sig_bytes));

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/sign"))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({
                "address": format!("{address:#x}"),
                "digest": format!("{digest:#x}"),
            })))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "signature": sig_hex })),
            )
            .mount(&server)
            .await;

        let client = HttpHsmClient::new(server.uri());
        let got = client.sign_digest(address, digest).await.expect("sign");
        assert_eq!(got.as_slice(), sig_bytes.as_slice());
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn http_client_surfaces_non_2xx_as_status_error() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/sign"))
            .respond_with(wiremock::ResponseTemplate::new(503).set_body_string("hsm offline"))
            .mount(&server)
            .await;
        let client = HttpHsmClient::new(server.uri());
        let err = client
            .sign_digest(Address::ZERO, B256::ZERO)
            .await
            .expect_err("should fail");
        assert!(matches!(err, HsmError::Status { status: 503, .. }));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn http_client_surfaces_malformed_signature_as_decode_error() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/sign"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "signature": "0xdead" })),
            )
            .mount(&server)
            .await;
        let client = HttpHsmClient::new(server.uri());
        let err = client
            .sign_digest(Address::ZERO, B256::ZERO)
            .await
            .expect_err("should fail");
        assert!(matches!(err, HsmError::Decode(_)));
    }
}
