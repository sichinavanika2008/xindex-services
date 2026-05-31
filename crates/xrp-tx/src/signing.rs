//! XRPL signing-blob construction + the `SHA512Half` digest.
//!
//! The load-bearing divergence from Cosmos: in XRPL multisign **each
//! signer signs a different message** — the shared transaction body with
//! that signer's own 20-byte `AccountID` appended as a raw suffix. Cosmos
//! members all sign identical sign-bytes; here they do not. This module
//! owns that construction. It has **no thornode reference** (`THORChain`'s
//! XRP client is single-sign / TSS only) and is gated on a rippled
//! byte-match before mainnet (`KNOWN_FINDINGS` P4.4-1).

use sha2::{Digest, Sha512};

/// Single-signing hash prefix `HashPrefix::txSign` = `"STX\0"`.
pub const PREFIX_SINGLE: [u8; 4] = [0x53, 0x54, 0x58, 0x00];
/// Multi-signing hash prefix `HashPrefix::txMultiSign` = `"SMT\0"`.
pub const PREFIX_MULTI: [u8; 4] = [0x53, 0x4D, 0x54, 0x00];

/// `SHA512Half`: plain SHA-512, then the **first 32 bytes** (high 256
/// bits). NOT SHA-512/256 (different IV) and NOT SHA-256.
#[must_use]
pub fn sha512half(data: &[u8]) -> [u8; 32] {
    let full = Sha512::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// Single-sign digest = `SHA512Half(STX\0 ‖ serialized_tx)`, where
/// `serialized_tx` carries a populated `SigningPubKey` and no
/// `TxnSignature`/`Signers`. Provided for symmetry + the §9.3 sourced
/// test vector; the custody path uses [`multisign_blob`].
#[must_use]
pub fn single_sign_digest(serialized_tx: &[u8]) -> [u8; 32] {
    let mut blob = Vec::with_capacity(4 + serialized_tx.len());
    blob.extend_from_slice(&PREFIX_SINGLE);
    blob.extend_from_slice(serialized_tx);
    sha512half(&blob)
}

/// The raw multi-signing blob (pre-hash) for one signer:
/// `SMT\0 ‖ body ‖ signer_account_id`. `body` is the shared serialized
/// transaction with an empty `SigningPubKey` and no `TxnSignature` /
/// `Signers`. The 20-byte `AccountID` is appended **raw** — no VL prefix,
/// no field header. Exposed (not just the digest) so tests + the rippled
/// byte-match can inspect the exact bytes.
#[must_use]
pub fn multisign_blob(body: &[u8], signer_account_id: &[u8; 20]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(4 + body.len() + 20);
    blob.extend_from_slice(&PREFIX_MULTI);
    blob.extend_from_slice(body);
    blob.extend_from_slice(signer_account_id);
    blob
}

/// Multi-sign digest for one signer = `SHA512Half(multisign_blob(...))`.
/// Each signer's digest differs by the trailing `AccountID` — this binds a
/// signature to a specific signer and prevents `Signer.Account` swapping.
#[must_use]
pub fn multisign_digest(body: &[u8], signer_account_id: &[u8; 20]) -> [u8; 32] {
    sha512half(&multisign_blob(body, signer_account_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_are_ascii_tagged() {
        assert_eq!(&PREFIX_SINGLE, b"STX\0");
        assert_eq!(&PREFIX_MULTI, b"SMT\0");
    }

    /// `SHA512Half` is the first 32 bytes of SHA-512, not SHA-256 and not
    /// the low half. Pin against a known SHA-512("abc") prefix.
    #[test]
    fn sha512half_takes_high_256_bits() {
        // SHA-512("abc") = ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a ...
        let h = sha512half(b"abc");
        let expected: [u8; 32] = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a,
        ];
        assert_eq!(h, expected);
    }

    /// The multisign blob is prefix ‖ body ‖ account-id, in that exact
    /// order, with the `AccountID` raw (no VL prefix).
    #[test]
    fn multisign_blob_layout() {
        let body = [0xAA, 0xBB, 0xCC];
        let acct = [0x11u8; 20];
        let blob = multisign_blob(&body, &acct);
        assert_eq!(&blob[..4], b"SMT\0");
        assert_eq!(&blob[4..7], &body);
        assert_eq!(&blob[7..27], &acct);
        assert_eq!(blob.len(), 4 + 3 + 20);
    }

    /// Different signers (different `AccountID` suffix) over the same body
    /// produce different digests — the property that makes XRPL multisign
    /// per-signer.
    #[test]
    fn different_signers_get_different_digests() {
        let body = [0x01, 0x02, 0x03, 0x04];
        let a = multisign_digest(&body, &[0x11; 20]);
        let b = multisign_digest(&body, &[0x22; 20]);
        assert_ne!(a, b);
    }
}
