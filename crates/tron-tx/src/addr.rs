//! TRON address codec.
//!
//! A TRON address is derived from a secp256k1 public key exactly like an
//! Ethereum address, then re-encoded with a 1-byte version prefix and a
//! base58check checksum:
//!
//! 1. `evm20 = keccak256(uncompressed_pubkey[1..])[12..]` — the last 20
//!    bytes of the keccak of the 64-byte uncompressed pubkey (no `0x04`
//!    SEC1 prefix). This is the same 20 bytes an Ethereum address uses.
//! 2. `raw21 = 0x41 ‖ evm20` — TRON's mainnet version prefix is `0x41`.
//! 3. checksum = first 4 bytes of `sha256(sha256(raw21))`.
//! 4. `T…` address = base58(`raw21 ‖ checksum`) (Bitcoin base58 alphabet).
//!
//! **Inside the transaction protobuf, addresses are the 21-byte `raw21`
//! form, NOT base58.** The `T…` string is display / API / config only.
//! TRC20 call data uses the 20-byte `evm20` form (left-padded to 32).

use sha2::{Digest, Sha256};

use crate::TronTxError;

/// TRON mainnet address version byte (`0x41`).
pub const TRON_PREFIX: u8 = 0x41;

/// Derive the 20-byte EVM-style address from a 33-byte compressed
/// secp256k1 pubkey: `keccak256(uncompressed[1..])[12..]`.
///
/// # Errors
/// [`TronTxError::BadPubkey`] if `pubkey` is not a valid compressed
/// secp256k1 point.
pub fn evm_address(pubkey_compressed: &[u8; 33]) -> Result<[u8; 20], TronTxError> {
    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey_compressed)
        .map_err(|_| TronTxError::BadPubkey)?;
    let uncompressed = vk.to_encoded_point(false);
    // `to_encoded_point(false)` returns 65 bytes: 0x04 ‖ X(32) ‖ Y(32).
    let hash = alloy_primitives::keccak256(&uncompressed.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash.as_slice()[12..]);
    Ok(out)
}

/// The 21-byte protobuf address form (`0x41 ‖ evm20`).
#[must_use]
pub fn raw21(evm20: &[u8; 20]) -> [u8; 21] {
    let mut out = [0u8; 21];
    out[0] = TRON_PREFIX;
    out[1..].copy_from_slice(evm20);
    out
}

/// First 4 bytes of `sha256(sha256(input))`.
fn checksum(input: &[u8]) -> [u8; 4] {
    let h1 = Sha256::digest(input);
    let h2 = Sha256::digest(h1);
    let mut out = [0u8; 4];
    out.copy_from_slice(&h2[..4]);
    out
}

/// Encode a 21-byte `raw21` address as a base58check `T…` string.
#[must_use]
pub fn encode_base58check(raw21: &[u8; 21]) -> String {
    let mut payload = Vec::with_capacity(25);
    payload.extend_from_slice(raw21);
    payload.extend_from_slice(&checksum(raw21));
    bs58::encode(payload).into_string()
}

/// Encode a 33-byte compressed pubkey directly to its `T…` address.
///
/// # Errors
/// [`TronTxError::BadPubkey`] if `pubkey` is not a valid compressed point.
pub fn pubkey_to_address(pubkey_compressed: &[u8; 33]) -> Result<String, TronTxError> {
    let evm = evm_address(pubkey_compressed)?;
    Ok(encode_base58check(&raw21(&evm)))
}

/// Decode a base58check `T…` address to its 21-byte `raw21` form,
/// verifying the version byte (`0x41`) and the double-sha256 checksum.
///
/// # Errors
/// [`TronTxError::BadAddress`] if the string is not valid base58, the
/// decoded payload is not 25 bytes, the version byte is not `0x41`, or the
/// checksum does not match.
pub fn decode_base58check(addr: &str) -> Result<[u8; 21], TronTxError> {
    let raw = bs58::decode(addr)
        .into_vec()
        .map_err(|e| TronTxError::BadAddress(format!("base58: {e}")))?;
    if raw.len() != 25 {
        return Err(TronTxError::BadAddress(format!(
            "expected 25 bytes, got {}",
            raw.len()
        )));
    }
    let (body, csum) = raw.split_at(21);
    if body[0] != TRON_PREFIX {
        return Err(TronTxError::BadAddress(format!(
            "not a mainnet address (version byte {:#x})",
            body[0]
        )));
    }
    if checksum(body) != csum {
        return Err(TronTxError::BadAddress("checksum mismatch".to_string()));
    }
    let mut out = [0u8; 21];
    out.copy_from_slice(body);
    Ok(out)
}

/// Decode a `T…` address to its 20-byte EVM form (the `raw21` minus the
/// `0x41` prefix) — the form used in TRC20 call data.
///
/// # Errors
/// [`TronTxError::BadAddress`] (see [`decode_base58check`]).
pub fn decode_to_evm20(addr: &str) -> Result<[u8; 20], TronTxError> {
    let raw = decode_base58check(addr)?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&raw[1..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn pubkey(seed: u8) -> [u8; 33] {
        #[expect(clippy::expect_used, reason = "test code")]
        let sk = SigningKey::from_slice(&[seed; 32]).expect("key");
        let ep = sk.verifying_key().to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(ep.as_bytes());
        out
    }

    /// `T…` addresses always start with the byte 0x41 → base58 'T'.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn derived_address_starts_with_t() {
        let addr = pubkey_to_address(&pubkey(7)).expect("addr");
        assert!(addr.starts_with('T'), "got {addr}");
        assert_eq!(addr.len(), 34);
    }

    /// Round-trip: pubkey → T-address → raw21 → evm20 are all consistent.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn address_round_trip() {
        let pk = pubkey(9);
        let evm = evm_address(&pk).expect("evm");
        let addr = pubkey_to_address(&pk).expect("addr");
        let decoded = decode_base58check(&addr).expect("decode");
        assert_eq!(decoded, raw21(&evm));
        assert_eq!(decode_to_evm20(&addr).expect("evm20"), evm);
    }

    /// A flipped checksum byte is rejected.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn corrupted_address_rejected() {
        let addr = pubkey_to_address(&pubkey(3)).expect("addr");
        let mut bytes = addr.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'a' { b'b' } else { b'a' };
        let corrupted = String::from_utf8(bytes).expect("utf8");
        assert!(decode_base58check(&corrupted).is_err());
    }

    /// SOURCED vector: the protobuf 21-byte address
    /// `41718de6b323652d1257437ace160c4f4198aae4e1` (the `owner_address`
    /// in `THORChain`'s `createtransaction.json`) base58check-encodes to a
    /// `T…` address that round-trips back to the same 21 bytes.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn sourced_raw21_round_trips() {
        let raw: [u8; 21] = {
            let v: Vec<u8> = (0.."41718de6b323652d1257437ace160c4f4198aae4e1".len())
                .step_by(2)
                .map(|i| {
                    u8::from_str_radix(&"41718de6b323652d1257437ace160c4f4198aae4e1"[i..i + 2], 16)
                        .expect("hex")
                })
                .collect();
            let mut a = [0u8; 21];
            a.copy_from_slice(&v);
            a
        };
        let addr = encode_base58check(&raw);
        assert!(addr.starts_with('T'));
        assert_eq!(decode_base58check(&addr).expect("decode"), raw);
    }
}
