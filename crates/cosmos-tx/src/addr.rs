//! `LegacyAminoPubKey` bech32 account-address derivation.
//!
//! `address = bech32(hrp, SHA-256(amino_marshal(LegacyAminoPubKey))[:20])`.
//! The cosmos-sdk derives the multisig account address from the **AMINO**
//! binary marshaling of the pubkey (`Address() = sha256(amino)[:20]`), NOT
//! the proto encoding: `amino_prefix(0x22c1f7e2) ‖ field1 threshold ‖
//! [field2 (amino_prefix(0xeb5ae987) ‖ len ‖ key))]*`. The 20-byte hash is
//! the `CometBFT` `AddressHash` (`SHA-256` truncated to 20 bytes — NOT
//! RIPEMD160, which is the *member-key* rule). The separate PROTO encoding
//! (with `Any`/`type_url`) is the right form for the `TxRaw`
//! `SignerInfo.public_key` ([`encode_legacy_amino_pubkey`]), NOT the
//! address — confusing the two is the bug the P3.3-3 byte-match caught.
//!
//! **BYTE-MATCH CLOSED (2026-06-12):** [`address_matches_cosmjs_reference`]
//! pins the derived address to `@cosmjs/amino`
//! `pubkeyToAddress(createMultisigThresholdPubkey(.., nosort=true))` and
//! [`amino_preimage_matches_cosmjs`] pins the amino preimage to its
//! `encodeAminoPubkey` — both the reference cosmos-sdk derivation that
//! `gaiad keys add --multisig --nosort-pubkeys` produces. The ceremony
//! MUST use `--nosort-pubkeys` so the on-chain account's `public_keys`
//! order (hence its address AND `CompactBitArray` bit positions) matches
//! our frozen member order (P3.3-17).

use bech32::{Bech32, Hrp};
use sha2::{Digest, Sha256};

use crate::proto;

/// proto `type_url` for a secp256k1 pubkey inside an `Any`. Shared with
/// [`crate::tx`]'s single-sig `TxRaw` builder so the type-URL string is
/// defined once (a divergent byte breaks the gaiad byte-match).
pub(crate) const SECP256K1_PUBKEY_TYPE_URL: &str = "/cosmos.crypto.secp256k1.PubKey";

/// Amino disambiguation prefix for `cosmos.crypto.multisig.LegacyAminoPubKey`
/// (`tendermint/PubKeyMultisigThreshold`). The cosmos-sdk derives the
/// multisig account address from the AMINO binary marshaling of the pubkey,
/// NOT the proto encoding — `Address() = sha256(amino_marshal)[:20]`.
const AMINO_PREFIX_MULTISIG: [u8; 4] = [0x22, 0xc1, 0xf7, 0xe2];
/// Amino disambiguation prefix for `tendermint/PubKeySecp256k1`.
const AMINO_PREFIX_SECP256K1: [u8; 4] = [0xeb, 0x5a, 0xe9, 0x87];

/// proto-encode `cosmos.crypto.secp256k1.PubKey { key: bytes = 1 }`. Shared
/// with [`crate::tx`]'s single-sig `TxRaw` builder.
pub(crate) fn encode_secp256k1_pubkey(compressed: &[u8; 33]) -> Vec<u8> {
    let mut out = Vec::with_capacity(35);
    proto::put_len_delim(1, compressed, &mut out);
    out
}

/// Amino-marshal one secp256k1 pubkey: `prefix(4) ‖ len(0x21=33) ‖ key`.
fn amino_secp256k1_pubkey(compressed: &[u8; 33]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 33);
    out.extend_from_slice(&AMINO_PREFIX_SECP256K1);
    out.push(0x21);
    out.extend_from_slice(compressed);
    out
}

/// Amino-marshal `LegacyAminoPubKey` — the cosmos-sdk address preimage.
/// `prefix(4) ‖ field1 varint threshold ‖ [field2 len-delim amino-pubkey]*`,
/// members in the frozen ceremony order (the ceremony MUST use
/// `gaiad keys add --multisig --nosort-pubkeys` so the on-chain account's
/// `public_keys` order — and thus its address AND the `CompactBitArray` bit
/// positions — match this order; see P3.3-17).
fn amino_marshal_legacy_amino_pubkey(threshold: u32, members: &[[u8; 33]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&AMINO_PREFIX_MULTISIG);
    proto::put_varint_field(1, u64::from(threshold), &mut out);
    for m in members {
        proto::put_len_delim(2, &amino_secp256k1_pubkey(m), &mut out);
    }
    out
}

/// proto-encode `google.protobuf.Any { type_url: string = 1, value: bytes = 2 }`.
pub(crate) fn encode_any(type_url: &str, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    proto::put_len_delim(1, type_url.as_bytes(), &mut out);
    proto::put_len_delim(2, value, &mut out);
    out
}

/// proto-encode `cosmos.crypto.multisig.LegacyAminoPubKey
/// { threshold: uint32 = 1, public_keys: repeated Any = 2 }`. Reused by
/// [`crate::tx`] for the `SignerInfo.public_key` `Any`.
pub(crate) fn encode_legacy_amino_pubkey(threshold: u32, members: &[[u8; 33]]) -> Vec<u8> {
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
    // cosmos-sdk: Address() = sha256(amino_marshal(LegacyAminoPubKey))[:20].
    // The AMINO marshaling (not the proto encoding) is the address preimage.
    let amino_bytes = amino_marshal_legacy_amino_pubkey(threshold, members);
    let digest = Sha256::digest(&amino_bytes);
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

    /// P3.3-3 byte-match CLOSED (multisig address): the derived address
    /// is byte-identical to `@cosmjs/amino`'s
    /// `pubkeyToAddress(createMultisigThresholdPubkey([pk1,pk2,pk3], 2),
    /// "cosmos")` — the reference cosmos-sdk `LegacyAminoPubKey` address
    /// derivation that `gaiad keys add --multisig` also produces.
    /// Regenerate via `tools/byte-match/cosmos.mjs`. The ceremony's
    /// address disclosure (P3.3-17) re-confirms against the operators'
    /// own `gaiad` at key-generation time.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn address_matches_cosmjs_reference() {
        // cosmjs `createMultisigThresholdPubkey([pk1,pk2,pk3], 2, /*nosort*/ true)`
        // → `pubkeyToAddress(_, "cosmos")`. The `nosort` form matches our
        // frozen member order (the ceremony pins `--nosort-pubkeys`).
        // Regenerate via `tools/byte-match/cosmos.mjs`.
        let addr =
            legacy_amino_multisig_address(2, &[pk(1), pk(2), pk(3)], "cosmos").expect("addr");
        assert_eq!(addr, "cosmos1lvrtl05q9qk8cjgvm03s0dwr3sethmyf5envnz");
    }

    /// The amino preimage is byte-identical to cosmjs `encodeAminoPubkey`
    /// (frozen / nosort order) — the proof the address derivation now
    /// hashes the cosmos-sdk amino marshaling, not the proto encoding.
    #[test]
    fn amino_preimage_matches_cosmjs() {
        let amino = amino_marshal_legacy_amino_pubkey(2, &[pk(1), pk(2), pk(3)]);
        let hex: String = amino.iter().fold(String::new(), |mut a, b| {
            use std::fmt::Write as _;
            let _ = write!(a, "{b:02x}");
            a
        });
        assert_eq!(
            hex,
            "22c1f7e208021226eb5ae987210200000000000000000000000000000000000000000000000000000000000000011226eb5ae987210200000000000000000000000000000000000000000000000000000000000000021226eb5ae98721020000000000000000000000000000000000000000000000000000000000000003"
        );
    }
}
