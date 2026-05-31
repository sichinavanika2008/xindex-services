//! XRPL classic-address codec + `AccountID` derivation.
//!
//! `AccountID` = `RIPEMD160(SHA256(compressed_secp256k1_pubkey))` (20
//! bytes). Classic r-address = base58check over `0x00 ‖ AccountID`, where
//! the checksum is the first 4 bytes of `SHA256(SHA256(payload))` and the
//! alphabet is the XRPL reordering (NOT Bitcoin's).
//!
//! Two distinct hashes live here vs `signing`: the address checksum is
//! double-SHA256; the signing digest (in `signing`) is `SHA512Half`. Do
//! not conflate them.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// The XRPL base58 dictionary (index 0 = `'r'`). Distinct from Bitcoin's
/// base58 alphabet — hard-pinned.
const ALPHABET: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/// Classic-address version byte (`TypeAccountID`).
const ACCOUNT_PREFIX: u8 = 0x00;

/// Errors decoding a classic r-address.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddrError {
    /// A character was not in the XRPL base58 alphabet.
    #[error("invalid base58 character: {0:?}")]
    BadChar(char),
    /// The decoded payload was not 25 bytes (`1 version + 20 id + 4 csum`).
    #[error("bad decoded length: expected 25 bytes, got {0}")]
    BadLength(usize),
    /// The version byte was not `0x00` (`TypeAccountID`).
    #[error("not a classic account address (version byte {0:#x})")]
    BadVersion(u8),
    /// The 4-byte double-SHA256 checksum did not match.
    #[error("checksum mismatch")]
    BadChecksum,
}

/// Derive the 20-byte `AccountID` from a 33-byte compressed secp256k1
/// pubkey: `RIPEMD160(SHA256(pubkey))`.
#[must_use]
pub fn account_id(pubkey_compressed: &[u8; 33]) -> [u8; 20] {
    let sha = Sha256::digest(pubkey_compressed);
    let rip = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

/// First 4 bytes of `SHA256(SHA256(input))`.
fn checksum(input: &[u8]) -> [u8; 4] {
    let h1 = Sha256::digest(input);
    let h2 = Sha256::digest(h1);
    let mut out = [0u8; 4];
    out.copy_from_slice(&h2[..4]);
    out
}

/// Base58-encode bytes with the XRPL alphabet (big-endian, leading-zero
/// bytes map to a leading `'r'` each).
fn base58_encode(data: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::with_capacity(data.len() * 138 / 100 + 1);
    for &byte in data {
        let mut carry = u32::from(byte);
        for d in &mut digits {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(digits.len() + data.len());
    for &byte in data {
        if byte == 0 {
            out.push(ALPHABET[0] as char);
        } else {
            break;
        }
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

/// Base58-decode an XRPL-alphabet string to bytes.
#[expect(
    clippy::cast_possible_truncation,
    reason = "alphabet position is a digit < 58, so `position(...) as u32` cannot truncate"
)]
fn base58_decode(s: &str) -> Result<Vec<u8>, AddrError> {
    let mut bytes: Vec<u8> = Vec::with_capacity(s.len());
    for ch in s.chars() {
        let val = ALPHABET
            .iter()
            .position(|&c| c as char == ch)
            .ok_or(AddrError::BadChar(ch))? as u32;
        let mut carry = val;
        for b in &mut bytes {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }
    for ch in s.chars() {
        if ch == ALPHABET[0] as char {
            bytes.push(0);
        } else {
            break;
        }
    }
    bytes.reverse();
    Ok(bytes)
}

/// Encode a 20-byte `AccountID` as a classic r-address.
#[must_use]
pub fn encode_classic_address(account_id: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(25);
    payload.push(ACCOUNT_PREFIX);
    payload.extend_from_slice(account_id);
    payload.extend_from_slice(&checksum(&payload));
    base58_encode(&payload)
}

/// Decode a classic r-address to its 20-byte `AccountID`, verifying the
/// version byte and the double-SHA256 checksum.
///
/// # Errors
///
/// Returns [`AddrError`] if a character is outside the XRPL base58
/// alphabet, the decoded payload is not 25 bytes, the version byte is not
/// `0x00`, or the double-SHA256 checksum does not match.
pub fn decode_classic_address(addr: &str) -> Result<[u8; 20], AddrError> {
    let raw = base58_decode(addr)?;
    if raw.len() != 25 {
        return Err(AddrError::BadLength(raw.len()));
    }
    if raw[0] != ACCOUNT_PREFIX {
        return Err(AddrError::BadVersion(raw[0]));
    }
    if checksum(&raw[..21]) != raw[21..25] {
        return Err(AddrError::BadChecksum);
    }
    let mut id = [0u8; 20];
    id.copy_from_slice(&raw[1..21]);
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a hex string into a fixed array (test-only, no `hex` dep).
    #[expect(clippy::expect_used, reason = "test code")]
    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect();
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    /// §9.1 SOURCED vectors (`THORChain` passing tests + XRPL genesis).
    /// Pubkey → classic r-address must match exactly.
    #[test]
    fn pubkey_to_classic_address_sourced_vectors() {
        let cases = [
            (
                "0237FEF6D393A2D209C879A344EFD39C20C01A8E2413298EBC6E6CCDECEEBAA7AD",
                "r4qmPsHfdoqtNMPx9popoXG3nDtsCSzUZQ",
            ),
            (
                "0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020",
                "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
            ),
            (
                "027190BF2204E1F99A9346C0717508788A73A8A3B7E5A925C349969ED1BA7FF2A0",
                "rs3xN42EFLE23gUDG2Rw4rwxhR9MnjwZKQ",
            ),
        ];
        for (pk_hex, addr) in cases {
            let pk: [u8; 33] = unhex(pk_hex);
            let id = account_id(&pk);
            assert_eq!(encode_classic_address(&id), addr, "pubkey {pk_hex}");
        }
    }

    /// Round-trip encode → decode recovers the `AccountID` and validates
    /// the checksum.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn classic_address_round_trip() {
        let id: [u8; 20] = unhex("d4b66bcf790babd0032c5dbfdc14ff1c643a4f48");
        let addr = encode_classic_address(&id);
        assert_eq!(decode_classic_address(&addr).expect("decode"), id);
    }

    /// A flipped character fails the checksum (or the alphabet check).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn corrupted_address_rejected() {
        let id: [u8; 20] = unhex("d4b66bcf790babd0032c5dbfdc14ff1c643a4f48");
        let mut addr = encode_classic_address(&id).into_bytes();
        // Flip a middle char to another valid alphabet char.
        let mid = addr.len() / 2;
        addr[mid] = if addr[mid] == b'p' { b'r' } else { b'p' };
        let corrupted = String::from_utf8(addr).expect("utf8");
        assert!(decode_classic_address(&corrupted).is_err());
    }

    /// The genesis address `rHb9CJ…` is externally verifiable on any
    /// XRPL explorer — a zero-trust anchor for the codec.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn genesis_address_decodes() {
        let id = decode_classic_address("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").expect("decode");
        assert_eq!(
            encode_classic_address(&id),
            "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
        );
    }
}
