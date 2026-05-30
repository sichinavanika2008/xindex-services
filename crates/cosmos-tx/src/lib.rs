//! Cosmos-SDK `LegacyAminoPubKey` k-of-n multisig helper crate (Phase 3.3).
//!
//! Pure-logic primitives for the Cosmos custody family (GAIA / ATOM —
//! Phase 3.3). This crate is the Cosmos analogue of `safe-evm`: it holds
//! every byte-exact, deterministic, **network-free** primitive needed to
//! sign and assemble a `THORChain`-memo'd `MsgSend` from a 3-of-5
//! on-chain multisig account:
//!
//! 1. [`amino`] — `SIGN_MODE_LEGACY_AMINO_JSON` `StdSignDoc` canonical
//!    sign-bytes. Produces the 32-byte SHA-256 digest the signer-daemon's
//!    `cosmos-tx` endpoint signs with its secp256k1 key (C5).
//! 2. [`sigs`] — secp256k1 helpers: low-S normalization (Cosmos REJECTS
//!    high-S — it does not auto-normalize), verify-against-pubkey (Cosmos
//!    signatures are non-recoverable, 64-byte `r ‖ s`), and the
//!    `MultiSignature` + `CompactBitArray` aggregation.
//! 3. [`addr`] — `LegacyAminoPubKey` bech32 account-address derivation.
//!
//! Crate has **no RPC dependency** and **no `cosmrs`/`prost`** — the
//! protobuf surface we need (the multisig pubkey + the aggregate
//! signature messages) is tiny and hand-encoded in [`proto`], mirroring
//! the `safe-evm` rationale: a narrow, auditable, byte-exact
//! implementation beats dragging a large dependency tree for a handful of
//! deterministic encodings.
//!
//! ## Amino canonicalization is the named footgun (DL-P3.3-3)
//!
//! The amino `StdSignDoc` JSON must be byte-identical to what a Cosmos
//! validator reconstructs: recursively sorted keys, no whitespace,
//! numbers-as-strings, the `MsgSend` wrapped as
//! `{"type":"cosmos-sdk/MsgSend","value":{…}}`. A single divergent byte
//! makes the signature silently invalid. The implementation here is
//! deterministic and unit-tested, but byte-level equivalence against
//! `gaiad tx … --generate-only` (pinned to the target Gaia SDK version)
//! plus the multisig address against `gaiad keys add --multisig` is a
//! **mandatory pre-mainnet gate** (DL-P3.3-6/8) — see
//! `xindex-services/KNOWN_FINDINGS.md`.

pub mod addr;
pub mod amino;
mod proto;
pub mod sigs;

/// A Cosmos-SDK `LegacyAminoPubKey` k-of-n multisig configuration.
///
/// Unlike [`xindex_safe_evm::SafeDescriptor`], the member pubkeys are
/// **NOT sorted** — legacy-amino multisig is positional, and the account
/// address is `SHA-256(amino(LegacyAminoPubKey))[:20]` over the members
/// in their given order. The caller MUST freeze a canonical member
/// ordering at the key ceremony and never reorder it (DL-P3.3-4/6); a
/// permutation yields a different, unrecoverable account address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosmosMultisig {
    /// k of `member_pubkeys.len()` — the threshold of member signatures
    /// the account requires.
    threshold: u32,
    /// Ordered list of 33-byte compressed secp256k1 member pubkeys. Order
    /// is significant and frozen.
    member_pubkeys: Vec<[u8; 33]>,
    /// bech32 human-readable prefix for the account address (`"cosmos"`
    /// for GAIA).
    hrp: String,
}

impl CosmosMultisig {
    /// Build a multisig descriptor, preserving member order.
    ///
    /// # Errors
    /// - [`CosmosMultisigError::NoMembers`] if `member_pubkeys` is empty.
    /// - [`CosmosMultisigError::ZeroThreshold`] if `threshold == 0`.
    /// - [`CosmosMultisigError::ThresholdExceedsMembers`] if
    ///   `threshold > member_pubkeys.len()`.
    /// - [`CosmosMultisigError::DuplicateMember`] if a pubkey appears
    ///   twice (a duplicate would corrupt the `CompactBitArray` mapping).
    pub fn new(
        threshold: u32,
        member_pubkeys: Vec<[u8; 33]>,
        hrp: impl Into<String>,
    ) -> Result<Self, CosmosMultisigError> {
        if member_pubkeys.is_empty() {
            return Err(CosmosMultisigError::NoMembers);
        }
        if threshold == 0 {
            return Err(CosmosMultisigError::ZeroThreshold);
        }
        if threshold as usize > member_pubkeys.len() {
            return Err(CosmosMultisigError::ThresholdExceedsMembers {
                threshold,
                members: member_pubkeys.len(),
            });
        }
        for i in 0..member_pubkeys.len() {
            for j in (i + 1)..member_pubkeys.len() {
                if member_pubkeys[i] == member_pubkeys[j] {
                    return Err(CosmosMultisigError::DuplicateMember(i, j));
                }
            }
        }
        Ok(Self {
            threshold,
            member_pubkeys,
            hrp: hrp.into(),
        })
    }

    /// The signature threshold k.
    #[must_use]
    pub const fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Total member count n.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.member_pubkeys.len()
    }

    /// The ordered member compressed pubkeys (frozen order).
    #[must_use]
    pub fn member_pubkeys(&self) -> &[[u8; 33]] {
        &self.member_pubkeys
    }

    /// The bech32 HRP for this account's chain.
    #[must_use]
    pub fn hrp(&self) -> &str {
        &self.hrp
    }

    /// Position of `pubkey` in the frozen member order, or `None` if it is
    /// not a member. Used to place a member's partial signature at the
    /// correct `CompactBitArray` index.
    #[must_use]
    pub fn member_index(&self, pubkey: &[u8; 33]) -> Option<usize> {
        self.member_pubkeys.iter().position(|m| m == pubkey)
    }

    /// Derive the bech32 account address
    /// (`bech32(hrp, SHA-256(amino(LegacyAminoPubKey))[:20])`).
    ///
    /// # Errors
    /// [`CosmosMultisigError::Address`] if bech32 encoding fails.
    pub fn account_address(&self) -> Result<String, CosmosMultisigError> {
        addr::legacy_amino_multisig_address(self.threshold, &self.member_pubkeys, &self.hrp)
            .map_err(|e| CosmosMultisigError::Address(e.to_string()))
    }
}

/// Construction / derivation errors for [`CosmosMultisig`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CosmosMultisigError {
    /// `member_pubkeys` was empty.
    #[error("multisig has no members")]
    NoMembers,
    /// `threshold` was 0.
    #[error("multisig threshold cannot be zero")]
    ZeroThreshold,
    /// `threshold > members`.
    #[error("threshold {threshold} exceeds member count {members}")]
    ThresholdExceedsMembers {
        /// The configured threshold.
        threshold: u32,
        /// The number of members.
        members: usize,
    },
    /// Two members share the same pubkey (positions `.0` and `.1`).
    #[error("duplicate member pubkey at positions {0} and {1}")]
    DuplicateMember(usize, usize),
    /// bech32 address derivation failed.
    #[error("address derivation failed: {0}")]
    Address(String),
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;

    fn pk(byte: u8) -> [u8; 33] {
        let mut k = [0u8; 33];
        k[0] = 0x02; // valid compressed-point prefix
        k[32] = byte;
        k
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn descriptor_preserves_member_order() {
        let members = vec![pk(3), pk(1), pk(2)];
        let m = CosmosMultisig::new(2, members.clone(), "cosmos").expect("ok");
        // Order is PRESERVED, not sorted (positional legacy-amino multisig).
        assert_eq!(m.member_pubkeys(), members.as_slice());
        assert_eq!(m.threshold(), 2);
        assert_eq!(m.member_count(), 3);
        assert_eq!(m.member_index(&pk(1)), Some(1));
        assert_eq!(m.member_index(&pk(9)), None);
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn descriptor_rejects_zero_threshold() {
        let err = CosmosMultisig::new(0, vec![pk(1)], "cosmos").unwrap_err();
        assert_eq!(err, CosmosMultisigError::ZeroThreshold);
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn descriptor_rejects_empty_members() {
        let err = CosmosMultisig::new(1, vec![], "cosmos").unwrap_err();
        assert_eq!(err, CosmosMultisigError::NoMembers);
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn descriptor_rejects_threshold_above_members() {
        let err = CosmosMultisig::new(3, vec![pk(1), pk(2)], "cosmos").unwrap_err();
        assert_eq!(
            err,
            CosmosMultisigError::ThresholdExceedsMembers {
                threshold: 3,
                members: 2,
            }
        );
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn descriptor_rejects_duplicate_members() {
        let err = CosmosMultisig::new(1, vec![pk(1), pk(1)], "cosmos").unwrap_err();
        assert_eq!(err, CosmosMultisigError::DuplicateMember(0, 1));
    }
}
