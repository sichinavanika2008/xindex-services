//! XRP Ledger native `SignerList` k-of-n multisign helper crate (Phase
//! 4.4).
//!
//! Pure-logic primitives for the XRP custody family (XRP / XRP.XRP). This
//! crate is the XRP analogue of `cosmos-tx` / `safe-evm`: every
//! byte-exact, deterministic, **network-free** primitive needed to sign
//! and assemble a `THORChain`-memo'd `Payment` from an on-chain
//! `SignerList` k-of-n account:
//!
//! 1. [`st`] — canonical `STObject` binary serialization (the amino
//!    analogue, the byte-exact footgun).
//! 2. [`addr`] — `AccountID` derivation + classic r-address base58check.
//! 3. [`signing`] — single/multi signing-blob construction + `SHA512Half`.
//! 4. [`sigs`] — secp256k1 DER + low-S, per-signer verify, and the
//!    `Signers`-array aggregation.
//! 5. [`tx`] — high-level `Payment` + `SignerListSet` builders.
//!
//! No RPC dependency and **no `xrpl-rust`/`bs58`** — the byte surface we
//! need is narrow (`Payment` + `SignerListSet`) and hand-encoded, the
//! same rationale as `cosmos-tx`.
//!
//! ## Two divergences from Cosmos that drive the design
//!
//! - **Per-signer signing blob.** XRPL multisign has each member sign a
//!   *different* message — the shared body with that signer's own
//!   `AccountID` appended (see [`signing::multisign_blob`]). So the
//!   descriptor sorts members by `AccountID` (for the `Signers` array) and
//!   the account address is NOT derived from the member set (unlike
//!   Cosmos `LegacyAminoPubKey`); it is a separately-funded XRPL account
//!   whose `SignerList` is configured by a one-time `SignerListSet`.
//! - **DER + low-S signatures** (not Cosmos's 64-byte compact), enforced
//!   on verification (rippled rejects high-S).
//!
//! The native-multisign byte layout has **no thornode reference**
//! (`THORChain`'s XRP client is single-sign / TSS only) and is gated on a
//! rippled byte-match before mainnet (`KNOWN_FINDINGS` P4.4-1).

pub mod addr;
pub mod signing;
pub mod sigs;
mod st;
pub mod tx;

use k256::ecdsa::VerifyingKey;

/// Maximum entries in an XRPL `SignerList`.
const MAX_SIGNERS: usize = 32;

/// One member of an XRP `SignerList`: its derived `AccountID`, compressed
/// pubkey, and signer weight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrpMember {
    /// 20-byte `AccountID` = `RIPEMD160(SHA256(pubkey))`.
    pub account_id: [u8; 20],
    /// 33-byte compressed secp256k1 pubkey.
    pub pubkey: [u8; 33],
    /// Signer weight (≥ 1). The quorum compares against the sum of the
    /// weights of the members that actually signed.
    pub weight: u16,
}

/// A verified partial signature, ready to place in the `Signers` array.
/// Produced by [`sigs::aggregate_verified`] (sorted by `AccountID`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSigner {
    /// Signer's 20-byte `AccountID` (the `Signers` sort key).
    pub account_id: [u8; 20],
    /// Signer's 33-byte compressed pubkey (the `Signer.SigningPubKey`).
    pub pubkey: [u8; 33],
    /// Signer's DER-encoded low-S signature (the `Signer.TxnSignature`).
    pub der: Vec<u8>,
}

/// Errors constructing an [`XrpMultisig`] descriptor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XrpMultisigError {
    /// `quorum` was zero.
    #[error("quorum must be > 0")]
    ZeroQuorum,
    /// The member list was empty.
    #[error("member list is empty")]
    NoMembers,
    /// The member list exceeded the XRPL `SignerList` maximum (32).
    #[error("too many members: {0} > {MAX_SIGNERS}")]
    TooManyMembers(usize),
    /// A member weight was zero.
    #[error("member weight must be > 0")]
    ZeroWeight,
    /// A member pubkey was not a valid compressed secp256k1 point.
    #[error("invalid compressed secp256k1 pubkey at index {0}")]
    BadPubkey(usize),
    /// Two members had the same pubkey or `AccountID`.
    #[error("duplicate member (pubkey or account id)")]
    DuplicateMember,
    /// `quorum` exceeded the sum of all member weights (unsatisfiable).
    #[error("quorum {quorum} exceeds total weight {total}")]
    QuorumUnsatisfiable {
        /// The configured quorum.
        quorum: u32,
        /// The sum of all member weights.
        total: u32,
    },
}

/// An XRP `SignerList` k-of-n multisig descriptor.
///
/// Members are **sorted by `AccountID` ascending** (the `Signers`-array
/// wire order), unlike Cosmos's positional `LegacyAminoPubKey`. The
/// account's classic address is NOT stored here — it is a separately
/// funded XRPL account (config), not a function of the member set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrpMultisig {
    quorum: u32,
    members: Vec<XrpMember>,
}

impl XrpMultisig {
    /// Build + validate a descriptor from `(pubkey, weight)` pairs.
    ///
    /// Validates: `quorum > 0`; 1..=32 members; each weight ≥ 1; each
    /// pubkey a valid compressed secp256k1 point; no duplicate pubkeys or
    /// `AccountID`s; `quorum ≤ Σ weights`. Members are frozen sorted by
    /// `AccountID` ascending.
    ///
    /// # Errors
    ///
    /// Returns [`XrpMultisigError`] if `quorum` is zero, the member list is
    /// empty or exceeds 32, any weight is zero, any pubkey is not a valid
    /// compressed secp256k1 point, two members collide on pubkey or
    /// `AccountID`, or `quorum` exceeds the total member weight.
    pub fn new(quorum: u32, members: Vec<([u8; 33], u16)>) -> Result<Self, XrpMultisigError> {
        if quorum == 0 {
            return Err(XrpMultisigError::ZeroQuorum);
        }
        if members.is_empty() {
            return Err(XrpMultisigError::NoMembers);
        }
        if members.len() > MAX_SIGNERS {
            return Err(XrpMultisigError::TooManyMembers(members.len()));
        }
        let mut built: Vec<XrpMember> = Vec::with_capacity(members.len());
        let mut total: u32 = 0;
        for (i, (pubkey, weight)) in members.into_iter().enumerate() {
            if weight == 0 {
                return Err(XrpMultisigError::ZeroWeight);
            }
            VerifyingKey::from_sec1_bytes(&pubkey).map_err(|_| XrpMultisigError::BadPubkey(i))?;
            let account_id = addr::account_id(&pubkey);
            if built
                .iter()
                .any(|m| m.pubkey == pubkey || m.account_id == account_id)
            {
                return Err(XrpMultisigError::DuplicateMember);
            }
            total += u32::from(weight);
            built.push(XrpMember {
                account_id,
                pubkey,
                weight,
            });
        }
        if quorum > total {
            return Err(XrpMultisigError::QuorumUnsatisfiable { quorum, total });
        }
        built.sort_by_key(|m| m.account_id);
        Ok(Self {
            quorum,
            members: built,
        })
    }

    /// The signing quorum (sum-of-weights threshold).
    #[must_use]
    pub fn quorum(&self) -> u32 {
        self.quorum
    }

    /// The frozen, AccountID-sorted member list.
    #[must_use]
    pub fn members(&self) -> &[XrpMember] {
        &self.members
    }

    /// Look up a member by its compressed pubkey.
    #[must_use]
    pub fn member_by_pubkey(&self, pubkey: &[u8; 33]) -> Option<&XrpMember> {
        self.members.iter().find(|m| &m.pubkey == pubkey)
    }

    /// Look up a member by its 20-byte `AccountID`.
    #[must_use]
    pub fn member_by_account_id(&self, account_id: &[u8; 20]) -> Option<&XrpMember> {
        self.members.iter().find(|m| &m.account_id == account_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    /// Deterministic test pubkeys from small scalars.
    #[expect(clippy::expect_used, reason = "test code")]
    fn pubkey(seed: u8) -> [u8; 33] {
        let sk = SigningKey::from_slice(&[seed; 32]).expect("key");
        let ep = sk.verifying_key().to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(ep.as_bytes());
        out
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn descriptor_sorts_members_by_account_id() {
        let ms = XrpMultisig::new(2, vec![(pubkey(3), 1), (pubkey(1), 1), (pubkey(2), 1)])
            .expect("descriptor");
        let ids: Vec<[u8; 20]> = ms.members().iter().map(|m| m.account_id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "members must be AccountID-ascending");
        assert_eq!(ms.quorum(), 2);
    }

    #[test]
    fn rejects_zero_quorum_and_empty() {
        assert_eq!(
            XrpMultisig::new(0, vec![(pubkey(1), 1)]),
            Err(XrpMultisigError::ZeroQuorum)
        );
        assert_eq!(
            XrpMultisig::new(1, vec![]),
            Err(XrpMultisigError::NoMembers)
        );
    }

    #[test]
    fn rejects_unsatisfiable_quorum() {
        let r = XrpMultisig::new(5, vec![(pubkey(1), 1), (pubkey(2), 1)]);
        assert_eq!(
            r,
            Err(XrpMultisigError::QuorumUnsatisfiable {
                quorum: 5,
                total: 2
            })
        );
    }

    #[test]
    fn rejects_duplicate_member() {
        let r = XrpMultisig::new(1, vec![(pubkey(1), 1), (pubkey(1), 1)]);
        assert_eq!(r, Err(XrpMultisigError::DuplicateMember));
    }

    #[test]
    fn rejects_zero_weight_and_bad_pubkey() {
        assert_eq!(
            XrpMultisig::new(1, vec![(pubkey(1), 0)]),
            Err(XrpMultisigError::ZeroWeight)
        );
        assert_eq!(
            XrpMultisig::new(1, vec![([0u8; 33], 1)]),
            Err(XrpMultisigError::BadPubkey(0))
        );
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn lookup_by_pubkey_and_account_id() {
        let ms = XrpMultisig::new(2, vec![(pubkey(1), 1), (pubkey(2), 1)]).expect("descriptor");
        let pk = pubkey(1);
        let m = ms.member_by_pubkey(&pk).expect("by pubkey");
        assert_eq!(
            ms.member_by_account_id(&m.account_id).map(|x| x.pubkey),
            Some(pk)
        );
    }
}
