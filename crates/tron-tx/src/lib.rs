//! TRON native account-permission k-of-n multisig helper crate (Phase 4.6).
//!
//! Pure-logic primitives for the TRON custody family (TRON / TRON.TRX +
//! TRC20 USDT). The TRON analogue of `cosmos-tx` / `xrp-tx` / `solana-tx`:
//! every byte-exact, deterministic, **network-free** primitive needed to
//! build, sign, and assemble a `THORChain`-memo'd transfer from a native
//! account-permission multisig account:
//!
//! 1. [`proto`] — the minimal hand-rolled protobuf-3 wire encoder (the
//!    amino / `STObject` analogue, the byte-exact footgun).
//! 2. [`addr`] — secp256k1 pubkey → 21-byte protobuf address → base58check
//!    `T…` string.
//! 3. [`tx`] — `raw_data` builders (`TransferContract` for TRX,
//!    `TriggerSmartContract` for TRC20 USDT) + `txID = sha256(raw_data)`.
//! 4. [`sigs`] — secp256k1 RECOVERABLE sign / recover + the
//!    weight-threshold signature aggregation.
//!
//! No RPC dependency and **no TRON SDK / `prost`** — the byte surface we
//! need is narrow and hand-encoded, the same rationale as `cosmos-tx`.
//!
//! ## The divergence from XRP that drives the design
//!
//! XRPL multisign has each member sign a *different* per-signer blob. TRON
//! is simpler: every member signs the **identical** `txID = sha256(raw_data)`
//! and the 65-byte recoverable signatures append to `Transaction.signature[]`
//! in any order — the node recovers each signer, looks up its weight in the
//! account's `Active` `Permission`, and accepts iff `Σ weight ≥ threshold`.
//! The `Permission_id` lives INSIDE `raw_data`, so it is bound into the
//! `txID`; all signers therefore agree on it up front (the coordinator
//! builds `raw_data` once and distributes the one `txID`).
//!
//! The hand-rolled wire layout is gated on a `tronweb` / `java-tron`
//! byte-match before mainnet (`KNOWN_FINDINGS` P-TRON-1); the TRX
//! `TransferContract` `txID` is pinned in [`tx`]'s tests against
//! `THORChain`'s sourced `createtransaction.json` fixture.

pub mod addr;
pub mod proto;
pub mod sigs;
pub mod tx;

/// TRON `Active` `Permission` maximum keys (chain param `getTotalSignNum`,
/// default 5). Our 3-of-5 ceremony fits.
const MAX_KEYS: usize = 5;

/// Errors across the TRON tx primitives.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TronTxError {
    /// A pubkey was not a valid compressed secp256k1 point.
    #[error("invalid compressed secp256k1 pubkey")]
    BadPubkey,
    /// A base58check `T…` address failed to decode / verify.
    #[error("invalid TRON address: {0}")]
    BadAddress(String),
    /// `threshold` was zero.
    #[error("threshold must be > 0")]
    ZeroThreshold,
    /// The member list was empty.
    #[error("member list is empty")]
    NoMembers,
    /// The member list exceeded the TRON `Permission` key maximum (5).
    #[error("too many members: {0} > {MAX_KEYS}")]
    TooManyMembers(usize),
    /// A member weight was zero.
    #[error("member weight must be > 0")]
    ZeroWeight,
    /// Two members had the same pubkey or address.
    #[error("duplicate member (pubkey or address)")]
    DuplicateMember,
    /// `threshold` exceeded the sum of all member weights (unsatisfiable).
    #[error("threshold {threshold} exceeds total weight {total}")]
    ThresholdUnsatisfiable {
        /// The configured threshold.
        threshold: u64,
        /// The sum of all member weights.
        total: u64,
    },
    /// `permission_id` was not a valid `Active` permission id (≥ 2; id 0 is
    /// the owner permission, id 1 the witness permission).
    #[error("permission_id must be >= 2 (active permission); got {0}")]
    BadPermissionId(u32),
    /// The memo exceeded the configured maximum.
    #[error("memo too long: {0} bytes")]
    MemoTooLong(usize),
    /// A signature did not parse / recover.
    #[error("invalid signature")]
    BadSignature,
    /// A recovered signer is not a member of the permission.
    #[error("signer is not a permission member")]
    NotAMember,
    /// Two signatures recovered to the same member.
    #[error("duplicate signer")]
    DuplicateSigner,
    /// The summed weight of recovered signers fell short of the threshold.
    #[error("threshold not met: {got} < {need}")]
    ThresholdNotMet {
        /// Summed weight of the verified signers.
        got: u64,
        /// The permission threshold.
        need: u64,
    },
    /// Deterministic signing failed (test/dev path only).
    #[error("signing failed")]
    SignFailed,
}

/// One member of a TRON `Active` `Permission`: its derived 20-byte EVM
/// address (the recovery target), compressed pubkey, and signer weight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TronMember {
    /// 20-byte EVM-style address `keccak256(uncompressed_pubkey)[12..]`
    /// (the value a recovered signature yields).
    pub address20: [u8; 20],
    /// 33-byte compressed secp256k1 pubkey.
    pub pubkey: [u8; 33],
    /// Signer weight (≥ 1). The threshold compares against the sum of the
    /// weights of the members that actually signed.
    pub weight: u64,
}

/// A TRON account-permission k-of-n multisig descriptor.
///
/// Members are **sorted by EVM address ascending** (the deterministic
/// `signature[]` assembly order). The TRON account address is NOT derived
/// from the member set — it is a separately-funded account whose `Active`
/// `Permission` is configured by a one-time `AccountPermissionUpdateContract`
/// during the key ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TronMultisig {
    threshold: u64,
    permission_id: u32,
    members: Vec<TronMember>,
}

impl TronMultisig {
    /// Build + validate a descriptor from `(pubkey, weight)` pairs.
    ///
    /// Validates: `threshold > 0`; 1..=5 members; each weight ≥ 1; each
    /// pubkey a valid compressed secp256k1 point; no duplicate pubkeys or
    /// addresses; `threshold ≤ Σ weights`; `permission_id ≥ 2`. Members are
    /// frozen sorted by EVM address ascending.
    ///
    /// # Errors
    /// Returns [`TronTxError`] on any of the above validation failures.
    pub fn new(
        threshold: u64,
        permission_id: u32,
        members: Vec<([u8; 33], u64)>,
    ) -> Result<Self, TronTxError> {
        if threshold == 0 {
            return Err(TronTxError::ZeroThreshold);
        }
        if permission_id < 2 {
            return Err(TronTxError::BadPermissionId(permission_id));
        }
        if members.is_empty() {
            return Err(TronTxError::NoMembers);
        }
        if members.len() > MAX_KEYS {
            return Err(TronTxError::TooManyMembers(members.len()));
        }
        let mut built: Vec<TronMember> = Vec::with_capacity(members.len());
        let mut total: u64 = 0;
        for (pubkey, weight) in members {
            if weight == 0 {
                return Err(TronTxError::ZeroWeight);
            }
            let address20 = addr::evm_address(&pubkey)?;
            if built
                .iter()
                .any(|m| m.pubkey == pubkey || m.address20 == address20)
            {
                return Err(TronTxError::DuplicateMember);
            }
            total += weight;
            built.push(TronMember {
                address20,
                pubkey,
                weight,
            });
        }
        if threshold > total {
            return Err(TronTxError::ThresholdUnsatisfiable { threshold, total });
        }
        built.sort_by_key(|m| m.address20);
        Ok(Self {
            threshold,
            permission_id,
            members: built,
        })
    }

    /// The signing threshold (sum-of-weights).
    #[must_use]
    pub fn threshold(&self) -> u64 {
        self.threshold
    }

    /// The `Active` permission id bound into `Contract.Permission_id`.
    #[must_use]
    pub fn permission_id(&self) -> u32 {
        self.permission_id
    }

    /// The frozen, address-sorted member list.
    #[must_use]
    pub fn members(&self) -> &[TronMember] {
        &self.members
    }

    /// Look up a member by its 20-byte EVM address.
    #[must_use]
    pub fn member_by_address(&self, address20: &[u8; 20]) -> Option<&TronMember> {
        self.members.iter().find(|m| &m.address20 == address20)
    }

    /// Look up a member by its compressed pubkey.
    #[must_use]
    pub fn member_by_pubkey(&self, pubkey: &[u8; 33]) -> Option<&TronMember> {
        self.members.iter().find(|m| &m.pubkey == pubkey)
    }
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

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn descriptor_sorts_members_by_address() {
        let ms = TronMultisig::new(2, 2, vec![(pubkey(3), 1), (pubkey(1), 1), (pubkey(2), 1)])
            .expect("descriptor");
        let addrs: Vec<[u8; 20]> = ms.members().iter().map(|m| m.address20).collect();
        let mut sorted = addrs.clone();
        sorted.sort_unstable();
        assert_eq!(addrs, sorted, "members must be address-ascending");
        assert_eq!(ms.threshold(), 2);
        assert_eq!(ms.permission_id(), 2);
    }

    #[test]
    fn rejects_invalid_descriptors() {
        assert_eq!(
            TronMultisig::new(0, 2, vec![(pubkey(1), 1)]),
            Err(TronTxError::ZeroThreshold)
        );
        assert_eq!(
            TronMultisig::new(1, 1, vec![(pubkey(1), 1)]),
            Err(TronTxError::BadPermissionId(1))
        );
        assert_eq!(TronMultisig::new(1, 2, vec![]), Err(TronTxError::NoMembers));
        assert_eq!(
            TronMultisig::new(1, 2, vec![(pubkey(1), 0)]),
            Err(TronTxError::ZeroWeight)
        );
        assert_eq!(
            TronMultisig::new(1, 2, vec![([0u8; 33], 1)]),
            Err(TronTxError::BadPubkey)
        );
        assert_eq!(
            TronMultisig::new(1, 2, vec![(pubkey(1), 1), (pubkey(1), 1)]),
            Err(TronTxError::DuplicateMember)
        );
        assert_eq!(
            TronMultisig::new(5, 2, vec![(pubkey(1), 1), (pubkey(2), 1)]),
            Err(TronTxError::ThresholdUnsatisfiable {
                threshold: 5,
                total: 2
            })
        );
        // Six members exceed the TRON 5-key permission maximum.
        assert_eq!(
            TronMultisig::new(1, 2, (1..=6).map(|s| (pubkey(s), 1)).collect()),
            Err(TronTxError::TooManyMembers(6))
        );
    }
}
