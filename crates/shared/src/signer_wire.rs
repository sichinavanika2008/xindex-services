//! Coordinator ↔ signer-daemon JSON wire schema (PART 5 / DL-M5-3).
//!
//! The signing surface has FOUR endpoints, each with its own typed
//! request struct. Type-level separation — there is no runtime `kind`
//! discriminator the daemon could forget. The on-chain typehashes are
//! three structurally-distinct EIP-712 messages plus PSBT-input signing
//! for the Bitcoin multisig; this module mirrors that 4-way shape.
//!
//! Fields are hex strings (`0x…`-prefixed) so the schema is robust
//! across languages and tooling, and we never depend on a JSON
//! representation choice for alloy primitives. The daemon parses
//! strings into [`alloy_primitives`] types at the boundary.
//!
//! `xindex-shared` is the one place this schema lives — daemon and
//! coordinator both depend on it, so a wire-shape mismatch is a
//! compile error, never a runtime one.

use serde::{Deserialize, Serialize};

use crate::chain_registry::ChainId;

/// `POST /api/v1/sign/eip712-attestation`
///
/// Mint slot attestation. Mirrors the on-chain
/// `ATTESTATION_TYPEHASH = keccak256("Attestation(bytes32 intentId,uint256 slotIndex,uint256 attestedAmount)")`.
/// The daemon computes the EIP-712 digest itself from its locally-known
/// domain — it never trusts a coordinator-supplied digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationSignRequest {
    /// `bytes32` intent id, `0x`-prefixed 32-byte hex.
    pub intent_id: String,
    /// `uint256` slot index, decimal string (JSON numbers can't represent
    /// 256-bit cleanly).
    pub slot_index: String,
    /// `uint256` attested amount, decimal string.
    pub attested_amount: String,
}

/// `POST /api/v1/sign/eip712-redemption-delivery`
///
/// Burn-leg delivery attestation. Mirrors
/// Per-leg delivery attestation. Mirrors
/// `AttestationOracle.ASYNC_LEG_DELIVERY_TYPEHASH`. The daemon's replay
/// DB is keyed by `(redemption_id, leg_index, "delivery")` — re-signing
/// a different `delivered_amount` under the same (redemption, leg) is a
/// `Conflict` error, never reaches the HSM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedemptionDeliverySignRequest {
    /// `bytes32` redemption id, hex.
    pub redemption_id: String,
    /// `uint256` leg index, decimal string.
    pub leg_index: String,
    /// `bytes32` canonical asset id of THIS leg (e.g.
    /// `keccak256("BTC.BTC")`), 0x-prefixed hex. Bound in the typed-data
    /// digest AND re-checked at the on-chain queue; defends against
    /// leg-index confusion across heterogeneous baskets.
    pub asset_id: String,
    /// `uint256` delivered amount in the leg's exit-token units (on-chain
    /// USDT 1e6 for `THORChain` rail), decimal string.
    pub delivered_amount: String,
}

/// `POST /api/v1/sign/eip712-refund`
///
/// Per-leg refund attestation. Mirrors
/// `AttestationOracle.ASYNC_LEG_REFUND_TYPEHASH`. On-chain delivery-XOR-
/// refund at the LEG granularity is enforced at the queue; the daemon's
/// replay DB enforces the same per-leg exclusion locally — pre-flight
/// refuse to sign a refund for a `(redemption_id, leg_index)` that
/// already has a delivery recorded by this daemon, and vice versa.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefundSignRequest {
    /// `bytes32` redemption id, hex.
    pub redemption_id: String,
    /// `uint256` leg index, decimal string.
    pub leg_index: String,
    /// `bytes32` canonical asset id of THIS leg, 0x-prefixed hex.
    pub asset_id: String,
    /// `uint256` refunded amount in the leg's native asset's smallest
    /// units (e.g. sats for BTC), decimal string.
    pub refunded_amount: String,
}

/// `POST /api/v1/sign/psbt-input`
///
/// UTXO-family multisig partial-signature endpoint. The daemon:
///   1. Routes to the per-chain config keyed by `chain_id` (404 if
///      this daemon is not configured for that chain — U8 multi-role).
///   2. Decodes the PSBT.
///   3. Verifies the witness/redeem script at `input_index` matches
///      that chain's configured multisig descriptor (refuses unknown
///      scripts).
///   4. Verifies `vin[0]` of the unsigned tx belongs to that descriptor
///      (the Part-3 refund-address invariant — `THORChain` resolves
///      refund-sender to `vin[0]`'s prev-out).
///   5. Signs the input sighash with its single secp256k1 key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PsbtInputSignRequest {
    /// Which UTXO chain this PSBT is for (selects the daemon's
    /// per-chain descriptor + key + script-kind). Required since U8;
    /// daemon returns `endpoint_disabled` if it has no config for the
    /// requested chain.
    pub chain_id: ChainId,
    /// Base64-encoded PSBT (BIP-174 v0).
    pub psbt_base64: String,
    /// Which input index of the PSBT to partial-sign.
    pub input_index: u32,
}

/// Response for the three EIP-712 endpoints.
///
/// `signature` is 65-byte ECDSA `r ‖ s ‖ v` (v ∈ {27,28}) hex-encoded
/// for direct use as one element of the on-chain `attest*` `bytes[]`
/// argument; `signer_address` is the recovery address so the
/// coordinator can verify the signature without trusting the daemon
/// (recover from sig over the locally-recomputed digest, compare).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Eip712SignResponse {
    /// `0x`-prefixed 130-hex-char (65-byte) ECDSA signature.
    pub signature: String,
    /// `0x`-prefixed 20-byte Ethereum address of the signing key.
    pub signer_address: String,
}

/// Response for `psbt-input` signing.
///
/// `pubkey` is the 33-byte compressed signing pubkey (so the
/// coordinator can place the partial sig at the correct descriptor
/// position); `signature` is the Bitcoin-encoded ECDSA signature
/// (DER + 1-byte sighash flag) in hex.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PsbtSignResponse {
    /// `0x`-prefixed 33-byte compressed secp256k1 pubkey.
    pub pubkey: String,
    /// Hex DER+sighash signature (no `0x` prefix to mirror Bitcoin tooling).
    pub signature: String,
}

/// `GET /api/v1/keys`
///
/// Daemon identity — coordinator pins this and checks every response
/// signer matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeysResponse {
    /// `0x`-prefixed Ethereum address (EIP-712 role). `None` if this
    /// daemon is configured for PSBT-only signing.
    pub eth_address: Option<String>,
    /// `0x`-prefixed compressed pubkey (PSBT role). `None` if this
    /// daemon is configured for EIP-712-only signing.
    pub btc_pubkey: Option<String>,
}

/// `GET /api/v1/health` — daemon liveness + HSM connectivity probe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    /// `true` only if every configured key role's HSM responded to a
    /// no-op probe within the timeout. The daemon refuses to sign if
    /// this is `false`.
    pub ok: bool,
    /// Daemon-reported reason when `ok == false` (e.g.
    /// `"hsm_unreachable"`). Empty when `ok`.
    pub reason: String,
}

/// Stable error-code strings the daemon returns in non-2xx bodies, so
/// the coordinator can branch on the code rather than parse messages.
/// Codes are versioned by being string constants here — adding one is
/// backwards-compatible, renaming one is not.
pub mod error_codes {
    /// The replay DB recorded a different payload for the same identity
    /// tuple. Coordinator MUST NOT retry under the same id — investigate.
    /// HTTP 409.
    pub const CONFLICT_ALREADY_SIGNED_DIFFERENT: &str = "conflict_already_signed_different";
    /// The replay DB recorded a delivery for this redemption; a refund
    /// can no longer be signed (and vice versa). HTTP 409.
    pub const CONFLICT_DELIVERY_REFUND_MUTEX: &str = "conflict_delivery_refund_mutex";
    /// HSM (`Web3Signer` / `YubiHSM2`) refused the request or is unreachable.
    /// HTTP 503.
    pub const HSM_UNAVAILABLE: &str = "hsm_unavailable";
    /// The submitted PSBT did not decode or the input index is out of
    /// range. HTTP 400.
    pub const INVALID_PSBT: &str = "invalid_psbt";
    /// The PSBT input's witness script does not match this daemon's
    /// configured multisig descriptor. HTTP 422.
    pub const WRONG_DESCRIPTOR: &str = "wrong_descriptor";
    /// The PSBT's `vin[0]` is not a multisig UTXO — refusing to sign
    /// because `THORChain` would not resolve a refund back to our
    /// multisig (Part-3 invariant). HTTP 422.
    pub const VIN0_NOT_MULTISIG: &str = "vin0_not_multisig";
    /// A request field is malformed (bad hex, wrong length, etc.). HTTP 400.
    pub const BAD_REQUEST: &str = "bad_request";
    /// The endpoint is not configured for this daemon's role (e.g.
    /// PSBT request to an EIP-712-only daemon). HTTP 404.
    pub const ENDPOINT_DISABLED: &str = "endpoint_disabled";
}

/// HTTP error body. The daemon returns this on any non-2xx response;
/// coordinator branches on `code`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorBody {
    /// One of the constants in [`error_codes`].
    pub code: String,
    /// Human-readable detail. May be logged; not parsed by the
    /// coordinator.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    /// Round-tripping every request/response struct through JSON is the
    /// schema contract — a change that breaks this test is a wire
    /// break.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn attestation_request_json_round_trip() {
        let req = AttestationSignRequest {
            intent_id: "0xaa".to_string(),
            slot_index: "0".to_string(),
            attested_amount: "1000000".to_string(),
        };
        let s = serde_json::to_string(&req).expect("serialize");
        let back: AttestationSignRequest = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn redemption_delivery_request_json_round_trip() {
        let req = RedemptionDeliverySignRequest {
            redemption_id: "0xbb".to_string(),
            leg_index: "0".to_string(),
            asset_id: "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                .to_string(),
            delivered_amount: "70000000".to_string(),
        };
        let s = serde_json::to_string(&req).expect("serialize");
        let back: RedemptionDeliverySignRequest = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn refund_request_json_round_trip() {
        let req = RefundSignRequest {
            redemption_id: "0xcc".to_string(),
            leg_index: "0".to_string(),
            asset_id: "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                .to_string(),
            refunded_amount: "99990000".to_string(),
        };
        let s = serde_json::to_string(&req).expect("serialize");
        let back: RefundSignRequest = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn psbt_input_request_json_round_trip() {
        let req = PsbtInputSignRequest {
            chain_id: ChainId::Btc,
            psbt_base64: "cHNidP8BAA==".to_string(),
            input_index: 0,
        };
        let s = serde_json::to_string(&req).expect("serialize");
        let back: PsbtInputSignRequest = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, req);
        // chain_id serialised as lowercase string per the ChainId
        // serde-rename convention.
        assert!(s.contains("\"chain_id\":\"btc\""));
    }

    /// U8: `PsbtInputSignRequest` accepts non-BTC chain ids (LTC, BCH,
    /// DOGE, ZEC) on the wire. Per-chain routing happens at the
    /// daemon's request handler.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn psbt_input_request_accepts_every_utxo_chain() {
        for chain in [
            ChainId::Btc,
            ChainId::Ltc,
            ChainId::Bch,
            ChainId::Doge,
            ChainId::Zec,
        ] {
            let req = PsbtInputSignRequest {
                chain_id: chain,
                psbt_base64: "cHNidP8BAA==".to_string(),
                input_index: 0,
            };
            let s = serde_json::to_string(&req).expect("serialize");
            let back: PsbtInputSignRequest = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back, req);
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn eip712_response_json_round_trip() {
        let r = Eip712SignResponse {
            signature: format!("0x{}", "ab".repeat(65)),
            signer_address: "0x0000000000000000000000000000000000000001".to_string(),
        };
        let s = serde_json::to_string(&r).expect("serialize");
        let back: Eip712SignResponse = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, r);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn error_body_json_round_trip() {
        let e = ErrorBody {
            code: error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT.to_string(),
            message: "intent already signed with a different amount".to_string(),
        };
        let s = serde_json::to_string(&e).expect("serialize");
        let back: ErrorBody = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, e);
    }
}
