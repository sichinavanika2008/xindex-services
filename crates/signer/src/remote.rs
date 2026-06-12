//! Remote (daemon-backed) `HsmBackend` impl (PART 5 / DL-M5-1).
//!
//! Posts typed attestation messages to a signer-daemon's HTTP API; the
//! daemon owns the EIP-712 digest + replay/slashing DB + HSM frontend.
//! Coordinators hold zero key material — they pin only the daemon's
//! expected `eth_address` and verify it matches every response.
//!
//! `HsmBackend::sign_digest` is NOT supported here (the daemon refuses
//! to sign a coordinator-supplied digest by design — DL-M5-3). Callers
//! MUST go through the typed `sign_*_msg` trait methods, which the
//! free `sign_attestation` / `sign_redemption_attestation` /
//! `sign_refund_attestation` helpers in this crate already do.

use std::time::Duration;

use alloy_primitives::{Address, B256};
use alloy_sol_types::Eip712Domain;
use xindex_shared::chain_registry::ChainId;
use xindex_shared::eip712::{
    AcquireCancelCertificate, AsyncLegDeliveryAttestation, AsyncLegRefundAttestation, Attestation,
    RedemptionIntentCertificate,
};
use xindex_shared::signer_wire::{
    AcquireCancelSignRequest, AttestationSignRequest, Eip712SignResponse,
    RedemptionDeliverySignRequest, RefundSignRequest, RicSignRequest,
};

use crate::{HsmBackend, RicSigner, SignerError, SoftwareSigner};

const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// HTTP client implementing [`HsmBackend`] against one signer daemon.
/// Cheap to clone (the `reqwest::blocking::Client` is internally
/// `Arc`-shared); each coordinator host holds one per signer party in
/// the configured 3-of-5 set.
#[derive(Debug, Clone)]
pub struct RemoteHsmBackend {
    base_url: String,
    eth_address: Address,
    inner: reqwest::blocking::Client,
}

impl RemoteHsmBackend {
    /// Construct against `base_url` (e.g. `http://127.0.0.1:9001`; in
    /// production the URL points at a daemon behind the configured
    /// mTLS perimeter). `eth_address` is the publicly-disclosed signer
    /// address (Set B per `docs/runbooks/key-ceremony.md`); every
    /// daemon response is verified to match this exactly.
    #[must_use]
    pub fn new(base_url: impl Into<String>, eth_address: Address) -> Self {
        Self::with_timeout(
            base_url,
            eth_address,
            Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        )
    }

    #[must_use]
    pub fn with_timeout(
        base_url: impl Into<String>,
        eth_address: Address,
        timeout: Duration,
    ) -> Self {
        let inner = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        Self {
            base_url: base_url.into(),
            eth_address,
            inner,
        }
    }

    fn post_sign<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<[u8; 65], SignerError> {
        let url = format!("{}{path}", self.base_url);
        let resp = self
            .inner
            .post(&url)
            .json(body)
            .send()
            .map_err(|e| SignerError::Backend(format!("daemon transport: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(SignerError::Backend(format!(
                "daemon http {}: {body}",
                status.as_u16()
            )));
        }
        let parsed: Eip712SignResponse = resp
            .json()
            .map_err(|e| SignerError::Backend(format!("daemon response json: {e}")))?;
        // Pin: coordinator MUST verify the daemon signed with the
        // configured public key. A mis-pointed daemon returning the
        // wrong signer is a hard fail, never silently aggregated.
        let returned = parsed
            .signer_address
            .parse::<Address>()
            .map_err(|e| SignerError::Backend(format!("daemon signer_address: {e}")))?;
        if returned != self.eth_address {
            return Err(SignerError::Backend(format!(
                "daemon returned {returned:#x}, expected {:#x}",
                self.eth_address
            )));
        }
        let sig_hex = parsed
            .signature
            .strip_prefix("0x")
            .unwrap_or(&parsed.signature);
        let bytes = alloy_primitives::hex::decode(sig_hex)
            .map_err(|e| SignerError::Backend(format!("daemon signature hex: {e}")))?;
        bytes.as_slice().try_into().map_err(|_| {
            SignerError::Backend(format!("daemon signature length {} ≠ 65", bytes.len()))
        })
    }

    /// CTD-1 Slice A.7: ask the daemon to certify one redemption leg's
    /// custody-spend intent (`POST /api/v1/sign/eip712-ric`). Typed
    /// like the attestation methods — the daemon recomputes the RIC
    /// digest from these plaintext fields on its own pinned domain and
    /// refuses to equivocate per `(chain, redemption, leg)`. Called by
    /// the per-operator observer (Slice B); inherent rather than a
    /// [`HsmBackend`] trait method until the observer's software-mode
    /// story needs one there.
    ///
    /// # Errors
    /// [`SignerError::Backend`] on transport / HTTP / signer-pin /
    /// signature-shape failures — including the daemon's 409
    /// equivocation refusal and 422 stale-resolution rejections,
    /// surfaced with their HTTP status code in the message.
    pub fn sign_ric(
        &self,
        chain_id: ChainId,
        ric: &RedemptionIntentCertificate,
    ) -> Result<[u8; 65], SignerError> {
        let req = RicSignRequest {
            chain_id,
            redemption_id: format!("{:#x}", ric.redemptionId),
            leg_index: ric.legIndex.to_string(),
            asset_id: format!("{:#x}", ric.assetId),
            amount: ric.amount.to_string(),
            amount_decimals: ric.amountDecimals,
            immediate_target_hash: format!("{:#x}", ric.immediateTargetHash),
            memo_hash: format!("{:#x}", ric.memoHash),
            final_destination_hash: format!("{:#x}", ric.finalDestinationHash),
            vault_resolved_at: ric.vaultResolvedAt,
        };
        self.post_sign("/api/v1/sign/eip712-ric", &req)
    }

    /// CTD-1 Slice C: ask the daemon to certify one mint-cancel
    /// swap-back (`POST /api/v1/sign/eip712-acc`) — the Acquire-Cancel
    /// sibling of [`RemoteHsmBackend::sign_ric`]. Same discipline: the
    /// daemon recomputes the ACC digest from these plaintext fields on
    /// its own pinned domain and refuses to equivocate per
    /// `(chain, cancel_id)`.
    ///
    /// # Errors
    /// [`SignerError::Backend`] on transport / HTTP / signer-pin /
    /// signature-shape failures, incl. the daemon's 409 equivocation
    /// refusal and 422 stale-resolution rejections.
    pub fn sign_acc(
        &self,
        chain_id: ChainId,
        acc: &AcquireCancelCertificate,
    ) -> Result<[u8; 65], SignerError> {
        let req = AcquireCancelSignRequest {
            chain_id,
            cancel_id: format!("{:#x}", acc.cancelId),
            intent_id: format!("{:#x}", acc.intentId),
            slot_index: acc.slotIndex.to_string(),
            asset_id: format!("{:#x}", acc.assetId),
            amount: acc.amount.to_string(),
            amount_decimals: acc.amountDecimals,
            immediate_target_hash: format!("{:#x}", acc.immediateTargetHash),
            memo_hash: format!("{:#x}", acc.memoHash),
            final_destination_hash: format!("{:#x}", acc.finalDestinationHash),
            vault_resolved_at: acc.vaultResolvedAt,
        };
        self.post_sign("/api/v1/sign/eip712-acc", &req)
    }
}

impl RicSigner for RemoteHsmBackend {
    fn ric_signer_address(&self) -> Address {
        self.eth_address
    }

    fn sign_ric(
        &self,
        chain: ChainId,
        ric: &RedemptionIntentCertificate,
        _domain: &Eip712Domain,
    ) -> Result<[u8; 65], SignerError> {
        // The daemon recomputes the digest on its OWN pinned domain and
        // refuses to equivocate; we never hand it a domain or digest.
        RemoteHsmBackend::sign_ric(self, chain, ric)
    }

    fn sign_acc(
        &self,
        chain: ChainId,
        acc: &AcquireCancelCertificate,
        _domain: &Eip712Domain,
    ) -> Result<[u8; 65], SignerError> {
        // Same discipline as sign_ric: plaintext to the daemon, never a
        // domain or digest.
        RemoteHsmBackend::sign_acc(self, chain, acc)
    }
}

impl RicSigner for AnyHsmBackend {
    fn ric_signer_address(&self) -> Address {
        match self {
            Self::Software(s) => RicSigner::ric_signer_address(s),
            Self::Remote(r) => RicSigner::ric_signer_address(r),
        }
    }

    fn sign_ric(
        &self,
        chain: ChainId,
        ric: &RedemptionIntentCertificate,
        domain: &Eip712Domain,
    ) -> Result<[u8; 65], SignerError> {
        match self {
            Self::Software(s) => RicSigner::sign_ric(s, chain, ric, domain),
            Self::Remote(r) => RicSigner::sign_ric(r, chain, ric, domain),
        }
    }

    fn sign_acc(
        &self,
        chain: ChainId,
        acc: &AcquireCancelCertificate,
        domain: &Eip712Domain,
    ) -> Result<[u8; 65], SignerError> {
        match self {
            Self::Software(s) => RicSigner::sign_acc(s, chain, acc, domain),
            Self::Remote(r) => RicSigner::sign_acc(r, chain, acc, domain),
        }
    }
}

impl HsmBackend for RemoteHsmBackend {
    fn signer_address(&self) -> Address {
        self.eth_address
    }

    fn sign_digest(&self, _digest: B256) -> Result<[u8; 65], SignerError> {
        // The daemon refuses to sign a coordinator-supplied digest by
        // design (PART 5 / DL-M5-3): it computes its own. Callers MUST
        // use the typed methods on the trait.
        Err(SignerError::Backend(
            "RemoteHsmBackend does not support raw sign_digest; use the typed sign_*_msg methods"
                .to_string(),
        ))
    }

    fn sign_attestation_msg(
        &self,
        _domain: &Eip712Domain,
        attestation: &Attestation,
    ) -> Result<[u8; 65], SignerError> {
        let req = AttestationSignRequest {
            intent_id: format!("{:#x}", attestation.intentId),
            slot_index: attestation.slotIndex.to_string(),
            attested_amount: attestation.attestedAmount.to_string(),
        };
        self.post_sign("/api/v1/sign/eip712-attestation", &req)
    }

    fn sign_redemption_attestation_msg(
        &self,
        _domain: &Eip712Domain,
        attestation: &AsyncLegDeliveryAttestation,
    ) -> Result<[u8; 65], SignerError> {
        let req = RedemptionDeliverySignRequest {
            redemption_id: format!("{:#x}", attestation.redemptionId),
            leg_index: attestation.legIndex.to_string(),
            asset_id: format!("{:#x}", attestation.assetId),
            delivered_amount: attestation.deliveredAmount.to_string(),
        };
        self.post_sign("/api/v1/sign/eip712-redemption-delivery", &req)
    }

    fn sign_refund_attestation_msg(
        &self,
        _domain: &Eip712Domain,
        attestation: &AsyncLegRefundAttestation,
    ) -> Result<[u8; 65], SignerError> {
        let req = RefundSignRequest {
            redemption_id: format!("{:#x}", attestation.redemptionId),
            leg_index: attestation.legIndex.to_string(),
            asset_id: format!("{:#x}", attestation.assetId),
            refunded_amount: attestation.refundedAmount.to_string(),
        };
        self.post_sign("/api/v1/sign/eip712-refund", &req)
    }
}

/// Enum [`HsmBackend`] adapter — covers both [`SoftwareSigner`] (dev /
/// Anvil) and [`RemoteHsmBackend`] (M5 production daemon). Lets the
/// coordinator binaries (`xindex-attest`, `xindex-attest-redeem`) build
/// a `Vec<AnyHsmBackend>` from a `--signer-mode` flag and pass
/// `&[&AnyHsmBackend]` to the existing `aggregate_*` helpers unchanged.
///
/// Static dispatch through the enum's `match` (no `dyn HsmBackend`,
/// no allocator overhead per sign).
#[derive(Debug)]
pub enum AnyHsmBackend {
    Software(SoftwareSigner),
    Remote(RemoteHsmBackend),
}

impl HsmBackend for AnyHsmBackend {
    fn signer_address(&self) -> Address {
        match self {
            Self::Software(s) => s.signer_address(),
            Self::Remote(r) => r.signer_address(),
        }
    }

    fn sign_digest(&self, digest: B256) -> Result<[u8; 65], SignerError> {
        match self {
            Self::Software(s) => s.sign_digest(digest),
            Self::Remote(r) => r.sign_digest(digest),
        }
    }

    fn sign_attestation_msg(
        &self,
        domain: &Eip712Domain,
        attestation: &Attestation,
    ) -> Result<[u8; 65], SignerError> {
        match self {
            Self::Software(s) => s.sign_attestation_msg(domain, attestation),
            Self::Remote(r) => r.sign_attestation_msg(domain, attestation),
        }
    }

    fn sign_redemption_attestation_msg(
        &self,
        domain: &Eip712Domain,
        attestation: &AsyncLegDeliveryAttestation,
    ) -> Result<[u8; 65], SignerError> {
        match self {
            Self::Software(s) => s.sign_redemption_attestation_msg(domain, attestation),
            Self::Remote(r) => r.sign_redemption_attestation_msg(domain, attestation),
        }
    }

    fn sign_refund_attestation_msg(
        &self,
        domain: &Eip712Domain,
        attestation: &AsyncLegRefundAttestation,
    ) -> Result<[u8; 65], SignerError> {
        match self {
            Self::Software(s) => s.sign_refund_attestation_msg(domain, attestation),
            Self::Remote(r) => r.sign_refund_attestation_msg(domain, attestation),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use xindex_shared::eip712::{
        attestation, attestation_oracle_domain, redemption_attestation, refund_attestation,
    };

    fn signer_addr() -> Address {
        Address::repeat_byte(0xcd)
    }

    fn domain() -> Eip712Domain {
        attestation_oracle_domain(31337, Address::repeat_byte(0xab))
    }

    /// 65-byte deterministic test signature (NOT a real ECDSA sig —
    /// only the byte-shape is exercised through the wire).
    fn fake_sig_bytes() -> Vec<u8> {
        (1u8..66).collect()
    }
    fn fake_sig_hex() -> String {
        format!("0x{}", alloy_primitives::hex::encode(fake_sig_bytes()))
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sign_attestation_msg_round_trip_via_mock_daemon() {
        let server = wiremock::MockServer::start().await;
        let a = attestation(
            B256::repeat_byte(0x11),
            U256::from(0u8),
            U256::from(1_000_000u32),
        );

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v1/sign/eip712-attestation"))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({
                "intent_id": format!("{:#x}", a.intentId),
                "slot_index": a.slotIndex.to_string(),
                "attested_amount": a.attestedAmount.to_string(),
            })))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "signature": fake_sig_hex(),
                    "signer_address": format!("{:#x}", signer_addr()),
                })),
            )
            .mount(&server)
            .await;

        // Run the blocking client in a dedicated task — reqwest::blocking
        // cannot be awaited directly inside a Tokio runtime thread.
        let url = server.uri();
        let sig = tokio::task::spawn_blocking(move || {
            let backend = RemoteHsmBackend::new(url, signer_addr());
            backend.sign_attestation_msg(&domain(), &a)
        })
        .await
        .expect("join")
        .expect("sign");
        assert_eq!(sig.as_slice(), fake_sig_bytes().as_slice());
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn wrong_signer_address_in_response_is_hard_fail() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v1/sign/eip712-attestation"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "signature": fake_sig_hex(),
                    "signer_address": format!("{:#x}", Address::repeat_byte(0x99)),
                })),
            )
            .mount(&server)
            .await;
        let url = server.uri();
        let a = attestation(B256::ZERO, U256::ZERO, U256::ZERO);
        let err = tokio::task::spawn_blocking(move || {
            RemoteHsmBackend::new(url, signer_addr()).sign_attestation_msg(&domain(), &a)
        })
        .await
        .expect("join")
        .expect_err("must reject wrong signer");
        let msg = err.to_string();
        assert!(msg.contains("expected"), "msg: {msg}");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn daemon_5xx_is_surfaced_as_backend_error() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/api/v1/sign/eip712-redemption-delivery",
            ))
            .respond_with(wiremock::ResponseTemplate::new(503).set_body_string("hsm offline"))
            .mount(&server)
            .await;
        let url = server.uri();
        let r = redemption_attestation(
            B256::ZERO,
            U256::ZERO,
            B256::repeat_byte(0xa1),
            U256::from(1u8),
        );
        let err = tokio::task::spawn_blocking(move || {
            RemoteHsmBackend::new(url, signer_addr()).sign_redemption_attestation_msg(&domain(), &r)
        })
        .await
        .expect("join")
        .expect_err("must surface 503");
        assert!(err.to_string().contains("503"));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn refund_endpoint_hit_with_typed_payload() {
        let server = wiremock::MockServer::start().await;
        let red = B256::repeat_byte(0x77);
        let asset = B256::repeat_byte(0xa1);
        let amt = U256::from(99_990_000u64);

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v1/sign/eip712-refund"))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({
                "redemption_id": format!("{red:#x}"),
                "leg_index": "0",
                "asset_id": format!("{asset:#x}"),
                "refunded_amount": amt.to_string(),
            })))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "signature": fake_sig_hex(),
                    "signer_address": format!("{:#x}", signer_addr()),
                })),
            )
            .mount(&server)
            .await;
        let url = server.uri();
        let r = refund_attestation(red, U256::ZERO, asset, amt);
        let sig = tokio::task::spawn_blocking(move || {
            RemoteHsmBackend::new(url, signer_addr()).sign_refund_attestation_msg(&domain(), &r)
        })
        .await
        .expect("join")
        .expect("sign");
        assert_eq!(sig.as_slice(), fake_sig_bytes().as_slice());
    }

    #[test]
    fn sign_digest_returns_unsupported_error() {
        let backend = RemoteHsmBackend::new("http://127.0.0.1:0", signer_addr());
        let err = backend
            .sign_digest(B256::ZERO)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("typed"));
    }

    /// CTD-1 Slice A.7: the RIC certification request reaches the
    /// daemon's `eip712-ric` endpoint with the typed plaintext payload
    /// (the daemon recomputes the digest itself — no digest on the
    /// wire), and the signer-pin check applies to the response.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sign_ric_round_trip_via_mock_daemon() {
        let server = wiremock::MockServer::start().await;
        let ric = xindex_shared::eip712::redemption_intent_certificate(
            B256::repeat_byte(0xab),
            U256::from(1u8),
            B256::repeat_byte(0xa1),
            U256::from(100_000_000u64),
            8,
            B256::repeat_byte(0xcd),
            B256::repeat_byte(0xef),
            B256::repeat_byte(0x12),
            1_750_000_000,
        );

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v1/sign/eip712-ric"))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({
                "chain_id": "btc",
                "redemption_id": format!("{:#x}", ric.redemptionId),
                "leg_index": "1",
                "asset_id": format!("{:#x}", ric.assetId),
                "amount": "100000000",
                "amount_decimals": 8,
                "vault_resolved_at": 1_750_000_000_u64,
            })))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "signature": fake_sig_hex(),
                    "signer_address": format!("{:#x}", signer_addr()),
                })),
            )
            .mount(&server)
            .await;

        let url = server.uri();
        let sig = tokio::task::spawn_blocking(move || {
            RemoteHsmBackend::new(url, signer_addr())
                .sign_ric(xindex_shared::chain_registry::ChainId::Btc, &ric)
        })
        .await
        .expect("join")
        .expect("sign");
        assert_eq!(sig.as_slice(), fake_sig_bytes().as_slice());
    }
}
