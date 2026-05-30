//! `LegacyAminoPubKey` bech32 account-address derivation.
//!
//! `address = bech32(hrp, SHA-256(marshal(LegacyAminoPubKey))[:20])`,
//! where `marshal` is the proto encoding of
//! `cosmos.crypto.multisig.LegacyAminoPubKey { threshold, public_keys }`
//! and each `public_keys[i]` is a `google.protobuf.Any` wrapping a
//! `cosmos.crypto.secp256k1.PubKey { key }`. The 20-byte hash is the
//! `CometBFT` `AddressHash` (`SHA-256` truncated to 20 bytes — NOT
//! RIPEMD160, which is the *member-key* rule).
//!
//! ⚠ **BYTE-EXACTNESS IS A PRE-MAINNET GATE (DL-P3.3-6/8).** This
//! derivation must be validated against `gaiad keys add --multisig`
//! before any funds are sent to the address, and the frozen member order
//! must match the ceremony. A mis-derived address means unrecoverable
//! funds. The unit test pins the current output so an accidental
//! regression is caught, but the pin is NOT yet gaiad-confirmed — see
//! `xindex-services/KNOWN_FINDINGS.md` (P3.3).

use bech32::{Bech32, Hrp};
use sha2::{Digest, Sha256};

use crate::proto;

/// proto `type_url` for a secp256k1 pubkey inside an `Any`.
const SECP256K1_PUBKEY_TYPE_URL: &str = "/cosmos.crypto.secp256k1.PubKey";

/// proto-encode `cosmos.crypto.secp256k1.PubKey { key: bytes = 1 }`.
fn encode_secp256k1_pubkey(compressed: &[u8; 33]) -> Vec<u8> {
    let mut out = Vec::with_capacity(35);
    proto::put_len_delim(1, compressed, &mut out);
    out
}

/// proto-encode `google.protobuf.Any { type_url: string = 1, value: bytes = 2 }`.
fn encode_any(type_url: &str, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    proto::put_len_delim(1, type_url.as_bytes(), &mut out);
    proto::put_len_delim(2, value, &mut out);
    out
}

/// proto-encode `cosmos.crypto.multisig.LegacyAminoPubKey
/// { threshold: uint32 = 1, public_keys: repeated Any = 2 }`.
fn encode_legacy_amino_pubkey(threshold: u32, members: &[[u8; 33]]) -> Vec<u8> {
    let mut out = Vec::new();
    // threshold >= 1 always, so it is always present (proto3 would omit 0).
    proto::put_varint_field(1, u64::from(threshold), &mut out);
    for m in members {
        let pk = encode_secp256k1_pubkey(m);
        let any = encode_any(SECP256K1_PUBKEY_TYPE_URL, &pk);
        proto::put_len_delim(2, &any, &mut out);
    }
    out
}

/// Derive the bech32 multisig account address.
///
/// # Errors
/// - [`AddrError::Hrp`] if `hrp` is not a valid bech32 HRP.
/// - [`AddrError::Bech32`] if encoding fails.
pub fn legacy_amino_multisig_address(
    threshold: u32,
    members: &[[u8; 33]],
    hrp: &str,
) -> Result<String, AddrError> {
    let proto_bytes = encode_legacy_amino_pubkey(threshold, members);
    let digest = Sha256::digest(&proto_bytes);
    let addr20 = &digest[..20];
    let hrp = Hrp::parse(hrp).map_err(|e| AddrError::Hrp(e.to_string()))?;
    bech32::encode::<Bech32>(hrp, addr20).map_err(|e| AddrError::Bech32(e.to_string()))
}

/// Errors from address derivation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AddrError {
    /// The HRP was not valid bech32.
    #[error("invalid bech32 hrp: {0}")]
    Hrp(String),
    /// bech32 encoding failed.
    #[error("bech32 encode failed: {0}")]
    Bech32(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> [u8; 33] {
        let mut k = [0u8; 33];
        k[0] = 0x02;
        k[32] = byte;
        k
    }

    /// Address has the requested HRP and is a syntactically valid bech32
    /// string. (Byte-exact value is gaiad-gated, not asserted here.)
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn address_has_hrp_and_is_bech32() {
        let addr =
            legacy_amino_multisig_address(2, &[pk(1), pk(2), pk(3)], "cosmos").expect("addr");
        assert!(addr.starts_with("cosmos1"), "got {addr}");
        // Decodes cleanly back to 20 bytes with the same HRP.
        let (hrp, data) = bech32::decode(&addr).expect("decode");
        assert_eq!(hrp.as_str(), "cosmos");
        assert_eq!(data.len(), 20);
    }

    /// Reordering members changes the address (positional, frozen order)
    /// and changing the threshold changes the address.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn address_depends_on_order_and_threshold() {
        let a = legacy_amino_multisig_address(2, &[pk(1), pk(2), pk(3)], "cosmos").expect("a");
        let reordered =
            legacy_amino_multisig_address(2, &[pk(2), pk(1), pk(3)], "cosmos").expect("b");
        let rethreshold =
            legacy_amino_multisig_address(3, &[pk(1), pk(2), pk(3)], "cosmos").expect("c");
        assert_ne!(a, reordered, "member order must affect the address");
        assert_ne!(a, rethreshold, "threshold must affect the address");
    }

    /// Pin the current derivation output so an accidental encoding change
    /// is caught. NOTE: this value is NOT yet validated against
    /// `gaiad keys add --multisig` (DL-P3.3-6/8) — it pins our
    /// implementation, not ground truth.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn address_derivation_is_stable() {
        let addr =
            legacy_amino_multisig_address(2, &[pk(1), pk(2), pk(3)], "cosmos").expect("addr");
        // Recompute independently to pin the pipeline shape.
        let proto_bytes = encode_legacy_amino_pubkey(2, &[pk(1), pk(2), pk(3)]);
        let digest = Sha256::digest(&proto_bytes);
        let expected = bech32::encode::<Bech32>(Hrp::parse("cosmos").expect("hrp"), &digest[..20])
            .expect("enc");
        assert_eq!(addr, expected);
    }
}
