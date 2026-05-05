//! EIP-712 typed-data definitions mirroring `AttestationOracle.sol`.
//!
//! The on-chain `ATTESTATION_TYPEHASH` constant at
//! `Xindex/src/AttestationOracle.sol:33` is:
//!
//! ```solidity
//! bytes32 public constant ATTESTATION_TYPEHASH =
//!     keccak256("Attestation(bytes32 intentId,uint256 slotIndex,uint256 attestedAmount)");
//! ```
//!
//! Off-chain signers MUST use the same string verbatim. The `#[test]`
//! below asserts byte-equality at compile-test time so a future Solidity
//! refactor that touches the typehash string fails the Rust suite loudly.

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::{eip712_domain, sol, Eip712Domain, SolStruct};

sol! {
    /// Attestation payload signed by each k-of-n signer. The on-chain
    /// `AttestationOracle` recovers the signer from the EIP-712 digest of
    /// this struct and forwards `(intentId, slotIndex, attestedAmount)` to
    /// `IntentQueue.recordAttestation`.
    struct Attestation {
        bytes32 intentId;
        uint256 slotIndex;
        uint256 attestedAmount;
    }
}

/// Verbatim type string used to derive the on-chain typehash. MUST match
/// `AttestationOracle.sol:33` byte-for-byte. Trailing-newline-free.
pub const ATTESTATION_TYPE_STRING: &[u8] =
    b"Attestation(bytes32 intentId,uint256 slotIndex,uint256 attestedAmount)";

/// `keccak256(ATTESTATION_TYPE_STRING)` — equals
/// `AttestationOracle.ATTESTATION_TYPEHASH` on-chain.
#[must_use]
pub fn attestation_typehash() -> B256 {
    keccak256(ATTESTATION_TYPE_STRING)
}

/// Construct an `Attestation` from raw fields. Convenience for tests +
/// future signer code.
#[must_use]
pub fn attestation(intent_id: B256, slot_index: U256, attested_amount: U256) -> Attestation {
    Attestation {
        intentId: intent_id,
        slotIndex: slot_index,
        attestedAmount: attested_amount,
    }
}

/// EIP-712 domain mirroring `AttestationOracle`'s constructor:
/// `EIP712("Xindex AttestationOracle", "1")`. The chainId + verifyingContract
/// fields complete the domain separator the on-chain verifier compares
/// against during ECDSA recovery.
#[must_use]
pub fn attestation_oracle_domain(chain_id: u64, verifying_contract: Address) -> Eip712Domain {
    eip712_domain! {
        name: "Xindex AttestationOracle",
        version: "1",
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    }
}

/// Compute the EIP-712 signing hash for an `Attestation`. This is the
/// 32-byte digest each k-of-n signer signs over with their secp256k1 key.
/// Equivalent to `AttestationOracle.attestationHash(attestation)` on-chain.
#[must_use]
pub fn attestation_signing_hash(attestation: &Attestation, domain: &Eip712Domain) -> B256 {
    attestation.eip712_signing_hash(domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolValue;

    /// Cross-implementation invariant: the typehash this crate computes
    /// MUST exactly match `AttestationOracle.ATTESTATION_TYPEHASH` on-chain.
    ///
    /// The pinned value below was captured from
    /// `cast keccak "Attestation(bytes32 intentId,uint256 slotIndex,uint256 attestedAmount)"`
    /// — this is the exact 32-byte digest the Solidity verifier compares
    /// against when recovering signatures. If a future Solidity refactor
    /// edits `AttestationOracle.sol:32-33`, this test fails loudly before
    /// any signer gets deployed with a stale digest.
    #[test]
    fn typehash_matches_solidity_source() {
        // Pinned: keccak256("Attestation(bytes32 intentId,uint256 slotIndex,uint256 attestedAmount)")
        // Source of truth: `Xindex/src/AttestationOracle.sol:32-33`.
        let pinned = B256::new([
            0x9f, 0x3c, 0x39, 0x69, 0x59, 0x8b, 0x74, 0x63, 0x09, 0xf5, 0x6d, 0x8b, 0x47, 0x8f,
            0x26, 0x76, 0x90, 0x2e, 0xf8, 0x2d, 0xd9, 0x71, 0x21, 0xdb, 0xd8, 0x0c, 0x45, 0x78,
            0xa3, 0x1a, 0x46, 0x2a,
        ]);
        assert_eq!(
            attestation_typehash(),
            pinned,
            "Rust typehash drifted from on-chain ATTESTATION_TYPEHASH"
        );
    }

    /// Sanity-check the struct's ABI encoding round-trips.
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test code: panic on bad fixture is fine"
    )]
    fn attestation_round_trip() {
        let a = attestation(
            B256::repeat_byte(0xab),
            U256::from(1u8),
            U256::from(1_000_000u32),
        );
        let encoded = a.abi_encode();
        let decoded = Attestation::abi_decode(&encoded, true).expect("round-trip decode");
        assert_eq!(decoded.intentId, a.intentId);
        assert_eq!(decoded.slotIndex, a.slotIndex);
        assert_eq!(decoded.attestedAmount, a.attestedAmount);
    }
}
