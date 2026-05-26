//! Safe v1.4.1 k-of-n contract multisig helper crate (Phase 3.2).
//!
//! Pure-logic primitives for the EVM custody family — every Phase 3.2
//! EVM chain (ETH / BSC / AVAX / BASE / POL) uses Safe v1.4.1 as its
//! custody contract. This crate provides:
//!
//! 1. [`digest`] — EIP-712 `safeTxHash` builder. Produces the 32-byte
//!    digest the signer-daemon's `evm-safe-tx` endpoint signs with the
//!    HSM-backed ECDSA key (V5).
//! 2. [`sigs`] — signature aggregation. Safe's `checkSignatures`
//!    iterates concatenated 65-byte ECDSA signatures sorted ASCENDING by
//!    recovered signer address; the aggregator here enforces that
//!    invariant so a wrong order is impossible to construct.
//! 3. [`exec`] — `execTransaction` ABI calldata builder. The
//!    executor (V7) submits the resulting calldata to the chain via
//!    `crates/chain-evm` (V4).
//!
//! Crate has **no RPC dependency** — every function is pure. The
//! `signer-daemon` consumes [`digest`] and [`sigs`] without dragging in
//! `alloy-provider`; the `executor` adds [`exec`] on top.
//!
//! ## Safe domain separator quirk (v1.3+)
//!
//! Safe contracts use a NON-STANDARD EIP-712 domain — only `chainId` +
//! `verifyingContract`, NO `name` or `version`. The implementation here
//! matches the Safe v1.4.1 source verbatim:
//!
//! ```text
//! DOMAIN_TYPEHASH = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
//! ```
//!
//! Any "EIP-712 builder" that defaults to the full `name+version+chainId+
//! verifyingContract` domain would compute a different digest and the
//! Safe's on-chain `checkSignatures` would reject every signature. Hence
//! the hand-rolled implementation below — narrow, auditable, byte-exact.

pub mod digest;
pub mod exec;
pub mod sigs;

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

/// Safe contract operation type (mirrors the on-chain `Enum.Operation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SafeOperation {
    /// Standard `CALL` (default).
    Call = 0,
    /// `DELEGATECALL` — only used for upgrades / extensions. Phase 3.2
    /// custody never delegatecalls.
    DelegateCall = 1,
}

/// A Safe v1.4.1 multisig configuration. Owners + threshold form the
/// signer set; `address` is the Safe proxy contract on the target chain.
///
/// This is a read-only descriptor — the executor / cross-check consults
/// it to validate signatures and ensure on-chain state matches the
/// configured set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeDescriptor {
    /// EIP-55-checksum 20-byte Safe proxy address.
    pub safe_address: Address,
    /// Sorted (ascending) list of owner addresses. Sorted at
    /// construction to match Safe's on-chain signature-order invariant.
    pub owners: Vec<Address>,
    /// k of `owners.len()` — the threshold of valid signatures Safe
    /// requires to execute a transaction.
    pub threshold: u8,
}

impl SafeDescriptor {
    /// Build a `SafeDescriptor` with `owners` sorted in ascending
    /// address order. The Safe contract itself stores owners as a
    /// circular linked list; consumer code that compares against the
    /// on-chain `getOwners()` result must apply the same sort.
    ///
    /// # Errors
    /// Returns `Err` if `threshold == 0`, `threshold > owners.len()`,
    /// or `owners` contains duplicates.
    pub fn new(
        safe_address: Address,
        mut owners: Vec<Address>,
        threshold: u8,
    ) -> Result<Self, SafeDescriptorError> {
        if owners.is_empty() {
            return Err(SafeDescriptorError::NoOwners);
        }
        if threshold == 0 {
            return Err(SafeDescriptorError::ZeroThreshold);
        }
        if usize::from(threshold) > owners.len() {
            return Err(SafeDescriptorError::ThresholdExceedsOwners {
                threshold,
                owners: owners.len(),
            });
        }
        owners.sort();
        for window in owners.windows(2) {
            if window[0] == window[1] {
                return Err(SafeDescriptorError::DuplicateOwner(window[0]));
            }
        }
        Ok(Self {
            safe_address,
            owners,
            threshold,
        })
    }
}

/// Construction-time errors for [`SafeDescriptor`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SafeDescriptorError {
    /// `owners` was empty — Safe requires at least one owner.
    #[error("Safe owners list is empty")]
    NoOwners,
    /// `threshold` was 0 — Safe requires `threshold >= 1`.
    #[error("Safe threshold cannot be zero")]
    ZeroThreshold,
    /// `threshold > owners.len()` — the Safe would be unsatisfiable.
    #[error("threshold {threshold} exceeds owners count {owners}")]
    ThresholdExceedsOwners {
        /// The configured threshold.
        threshold: u8,
        /// The number of owners.
        owners: usize,
    },
    /// `owners` contained the same address twice.
    #[error("duplicate Safe owner: {0}")]
    DuplicateOwner(Address),
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;
    use alloy_primitives::address;

    fn addr(byte: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = byte;
        Address::from(bytes)
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn descriptor_sorts_owners_ascending() {
        let safe = address!("1111111111111111111111111111111111111111");
        let d = SafeDescriptor::new(safe, vec![addr(3), addr(1), addr(2)], 2).expect("ok");
        assert_eq!(d.owners, vec![addr(1), addr(2), addr(3)]);
        assert_eq!(d.safe_address, safe);
        assert_eq!(d.threshold, 2);
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn descriptor_rejects_zero_threshold() {
        let safe = address!("2222222222222222222222222222222222222222");
        let err = SafeDescriptor::new(safe, vec![addr(1), addr(2)], 0).unwrap_err();
        assert_eq!(err, SafeDescriptorError::ZeroThreshold);
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn descriptor_rejects_empty_owners() {
        let safe = address!("3333333333333333333333333333333333333333");
        let err = SafeDescriptor::new(safe, vec![], 1).unwrap_err();
        assert_eq!(err, SafeDescriptorError::NoOwners);
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn descriptor_rejects_threshold_above_owners() {
        let safe = address!("4444444444444444444444444444444444444444");
        let err = SafeDescriptor::new(safe, vec![addr(1), addr(2)], 3).unwrap_err();
        assert_eq!(
            err,
            SafeDescriptorError::ThresholdExceedsOwners {
                threshold: 3,
                owners: 2
            }
        );
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn descriptor_rejects_duplicate_owners() {
        let safe = address!("5555555555555555555555555555555555555555");
        let err = SafeDescriptor::new(safe, vec![addr(1), addr(1)], 1).unwrap_err();
        assert_eq!(err, SafeDescriptorError::DuplicateOwner(addr(1)));
    }
}
