//! EIP-712 typed-data definitions mirroring `AttestationOracle.sol`.
//!
//! The on-chain `ATTESTATION_TYPEHASH` constant at
//! `Xindex/src/AttestationOracle.sol:32-33` is:
//!
//! ```solidity
//! bytes32 public constant ATTESTATION_TYPEHASH =
//!     keccak256("Attestation(bytes32 intentId,uint256 slotIndex,uint256 attestedAmount)");
//! ```
//!
//! Phase 3.0: the two redemption-side typehashes were generalized to
//! per-leg shape (one redemption may span N async legs). Each leg's
//! delivery and refund attestations are signed under a SEPARATE
//! struct/typehash with `legIndex` + `assetId` fields baked into the
//! typed-data payload — defeats leg-index/asset-id confusion across
//! heterogeneous baskets without a runtime `kind` discriminator.
//!
//! Off-chain signers MUST use the same strings verbatim. The `#[test]`
//! suite below asserts byte-equality at compile-test time so a future
//! Solidity refactor that touches any typehash fails the Rust suite
//! loudly.

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
/// `AttestationOracle.sol:32-33` byte-for-byte. Trailing-newline-free.
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

/* -------------------------------------------------------------------------- */
/*       ASYNC-LEG DELIVERY ATTESTATION (burn → USDT, per-leg delivery)       */
/* -------------------------------------------------------------------------- */

sol! {
    /// Per-leg redemption delivery attestation. A SEPARATE struct ⇒
    /// SEPARATE typehash from {Attestation}: a mint signature can never
    /// verify on the redemption path, with no runtime `kind` discriminator
    /// to forget. Phase 3.0: the `legIndex` + `assetId` fields bind each
    /// signature to a specific leg of a specific basket — defeats leg
    /// confusion across heterogeneous baskets. Mirrors
    /// `AttestationOracle.ASYNC_LEG_DELIVERY_TYPEHASH`.
    struct AsyncLegDeliveryAttestation {
        bytes32 redemptionId;
        uint256 legIndex;
        bytes32 assetId;
        uint256 deliveredAmount;
    }
}

/// Verbatim type string. MUST match `AttestationOracle.sol:39-42`.
pub const ASYNC_LEG_DELIVERY_TYPE_STRING: &[u8] =
    b"AsyncLegDeliveryAttestation(bytes32 redemptionId,uint256 legIndex,bytes32 assetId,uint256 deliveredAmount)";

/// `keccak256(ASYNC_LEG_DELIVERY_TYPE_STRING)` — equals
/// `AttestationOracle.ASYNC_LEG_DELIVERY_TYPEHASH` on-chain.
#[must_use]
pub fn redemption_attestation_typehash() -> B256 {
    keccak256(ASYNC_LEG_DELIVERY_TYPE_STRING)
}

/// Construct an `AsyncLegDeliveryAttestation` from raw fields.
#[must_use]
pub fn redemption_attestation(
    redemption_id: B256,
    leg_index: U256,
    asset_id: B256,
    delivered_amount: U256,
) -> AsyncLegDeliveryAttestation {
    AsyncLegDeliveryAttestation {
        redemptionId: redemption_id,
        legIndex: leg_index,
        assetId: asset_id,
        deliveredAmount: delivered_amount,
    }
}

/// EIP-712 signing hash for an `AsyncLegDeliveryAttestation`. Reuses
/// `attestation_oracle_domain` (the oracle's EIP-712 domain is shared
/// across all three typehashes); the per-struct typehash provides the
/// path separation. Equivalent to
/// `AttestationOracle.redemptionAttestationHash(...)` on-chain.
#[must_use]
pub fn redemption_attestation_signing_hash(
    attestation: &AsyncLegDeliveryAttestation,
    domain: &Eip712Domain,
) -> B256 {
    attestation.eip712_signing_hash(domain)
}

/* -------------------------------------------------------------------------- */
/*         ASYNC-LEG REFUND ATTESTATION (burn → USDT, per-leg refund)         */
/* -------------------------------------------------------------------------- */

sol! {
    /// Per-leg refund attestation: signers proved `THORChain` returned the
    /// native asset for THIS leg to our multisig (`REFUND:<inbound_txid>`
    /// outbound) instead of delivering USDT. A THIRD separate struct /
    /// typehash; mutually exclusive with {`AsyncLegDeliveryAttestation`}
    /// at the on-chain queue (per-leg mutex). Mirrors
    /// `AttestationOracle.ASYNC_LEG_REFUND_TYPEHASH`. The signers attest
    /// the actual amount refunded (inbound − `THORChain` fee).
    struct AsyncLegRefundAttestation {
        bytes32 redemptionId;
        uint256 legIndex;
        bytes32 assetId;
        uint256 refundedAmount;
    }
}

/// Verbatim type string. MUST match `AttestationOracle.sol:47-50`.
pub const ASYNC_LEG_REFUND_TYPE_STRING: &[u8] =
    b"AsyncLegRefundAttestation(bytes32 redemptionId,uint256 legIndex,bytes32 assetId,uint256 refundedAmount)";

/// `keccak256(ASYNC_LEG_REFUND_TYPE_STRING)` — equals
/// `AttestationOracle.ASYNC_LEG_REFUND_TYPEHASH` on-chain.
#[must_use]
pub fn refund_attestation_typehash() -> B256 {
    keccak256(ASYNC_LEG_REFUND_TYPE_STRING)
}

/// Construct an `AsyncLegRefundAttestation` from raw fields.
#[must_use]
pub fn refund_attestation(
    redemption_id: B256,
    leg_index: U256,
    asset_id: B256,
    refunded_amount: U256,
) -> AsyncLegRefundAttestation {
    AsyncLegRefundAttestation {
        redemptionId: redemption_id,
        legIndex: leg_index,
        assetId: asset_id,
        refundedAmount: refunded_amount,
    }
}

/// EIP-712 signing hash for an `AsyncLegRefundAttestation`. Reuses
/// `attestation_oracle_domain`. Equivalent to
/// `AttestationOracle.refundAttestationHash(...)` on-chain.
#[must_use]
pub fn refund_attestation_signing_hash(
    attestation: &AsyncLegRefundAttestation,
    domain: &Eip712Domain,
) -> B256 {
    attestation.eip712_signing_hash(domain)
}

sol! {
    /// Per-leg combined streamed-settlement attestation (re-audit-gated
    /// burn-side streaming): a streaming redeem swap partially filled,
    /// delivering `deliveredUsdt` to the `IndexToken` AND refunding
    /// `refundedNative` of the source asset to our custody on ONE leg.
    /// A FOURTH separate struct / typehash; the on-chain queue reads the
    /// resulting `attested && refunded` state as the combined outcome.
    /// Mirrors `AttestationOracle.ASYNC_LEG_STREAMED_SETTLEMENT_TYPEHASH`.
    /// Either amount may be zero (the queue rejects both-zero).
    struct AsyncLegStreamedSettlement {
        bytes32 redemptionId;
        uint256 legIndex;
        bytes32 assetId;
        uint256 deliveredUsdt;
        uint256 refundedNative;
    }
}

/// Verbatim type string. MUST match `AttestationOracle.sol`'s
/// `ASYNC_LEG_STREAMED_SETTLEMENT_TYPEHASH` source string.
pub const ASYNC_LEG_STREAMED_SETTLEMENT_TYPE_STRING: &[u8] = b"AsyncLegStreamedSettlement(bytes32 redemptionId,uint256 legIndex,bytes32 assetId,uint256 deliveredUsdt,uint256 refundedNative)";

/// `keccak256(ASYNC_LEG_STREAMED_SETTLEMENT_TYPE_STRING)` — equals
/// `AttestationOracle.ASYNC_LEG_STREAMED_SETTLEMENT_TYPEHASH` on-chain.
#[must_use]
pub fn streamed_settlement_typehash() -> B256 {
    keccak256(ASYNC_LEG_STREAMED_SETTLEMENT_TYPE_STRING)
}

/// Construct an `AsyncLegStreamedSettlement` from raw fields.
#[must_use]
pub fn streamed_settlement(
    redemption_id: B256,
    leg_index: U256,
    asset_id: B256,
    delivered_usdt: U256,
    refunded_native: U256,
) -> AsyncLegStreamedSettlement {
    AsyncLegStreamedSettlement {
        redemptionId: redemption_id,
        legIndex: leg_index,
        assetId: asset_id,
        deliveredUsdt: delivered_usdt,
        refundedNative: refunded_native,
    }
}

/// EIP-712 signing hash for an `AsyncLegStreamedSettlement`. Reuses
/// `attestation_oracle_domain`. Equivalent to
/// `AttestationOracle.streamedSettlementHash(...)` on-chain.
#[must_use]
pub fn streamed_settlement_signing_hash(
    attestation: &AsyncLegStreamedSettlement,
    domain: &Eip712Domain,
) -> B256 {
    attestation.eip712_signing_hash(domain)
}

sol! {
    /// CTD-1 Redemption Intent Certificate (RIC) — the FIFTH typed-data on
    /// the `attestation_oracle_domain`, **off-chain only** (no on-chain
    /// verification; `DL-CTD-RIC-V2` Q1 / `DL-CTD-2`). k-of-n Set-B signers
    /// (the attestation set) certify the canonical custody-spend for one
    /// redemption leg so an RPC-free custody daemon can verify the spend
    /// destination it is about to sign WITHOUT trusting the coordinator.
    ///
    /// Each operator's observer independently resolves the Asgard inbound
    /// (`immediateTargetHash`) + the amount from its OWN diverse `THORChain`
    /// sources, then signs this; the custody daemon recovers k-of-n signers
    /// and binds the spend to these fields. Unlike the four attestation
    /// typehashes this has NO Solidity counterpart — the pinned test locks
    /// the type string for CROSS-OPERATOR consistency, not a Solidity match.
    ///
    /// - `immediateTargetHash` = keccak of the native-chain Asgard inbound
    ///   the multisig pays (BTC scriptPubKey / address bytes) — the field
    ///   with no on-chain root, hence the k-of-n observer attestation.
    /// - `amountDecimals` pins the unit of `amount` to `chain_registry` (RA-4).
    /// - `vaultResolvedAt` (unix secs) is the observer's Asgard-resolution
    ///   time; the daemon enforces a local `ric_max_age` so a RIC can't be
    ///   replayed onto a rotated vault (recency; replaces the unsourceable
    ///   strict `vaultEpoch`, RA-5).
    struct RedemptionIntentCertificate {
        bytes32 redemptionId;
        uint256 legIndex;
        bytes32 assetId;
        uint256 amount;
        uint8 amountDecimals;
        bytes32 immediateTargetHash;
        bytes32 memoHash;
        bytes32 finalDestinationHash;
        uint64 vaultResolvedAt;
    }
}

/// Verbatim RIC type string. Off-chain only — pinned for cross-operator
/// consistency (every operator's Rust MUST compute the identical digest).
pub const RIC_TYPE_STRING: &[u8] = b"RedemptionIntentCertificate(bytes32 redemptionId,uint256 legIndex,bytes32 assetId,uint256 amount,uint8 amountDecimals,bytes32 immediateTargetHash,bytes32 memoHash,bytes32 finalDestinationHash,uint64 vaultResolvedAt)";

/// `keccak256(RIC_TYPE_STRING)`.
#[must_use]
pub fn ric_typehash() -> B256 {
    keccak256(RIC_TYPE_STRING)
}

/// Construct a `RedemptionIntentCertificate` from raw fields.
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "the RIC binds 9 distinct certified fields; a wrapper struct param would just re-wrap them"
)]
pub fn redemption_intent_certificate(
    redemption_id: B256,
    leg_index: U256,
    asset_id: B256,
    amount: U256,
    amount_decimals: u8,
    immediate_target_hash: B256,
    memo_hash: B256,
    final_destination_hash: B256,
    vault_resolved_at: u64,
) -> RedemptionIntentCertificate {
    RedemptionIntentCertificate {
        redemptionId: redemption_id,
        legIndex: leg_index,
        assetId: asset_id,
        amount,
        amountDecimals: amount_decimals,
        immediateTargetHash: immediate_target_hash,
        memoHash: memo_hash,
        finalDestinationHash: final_destination_hash,
        vaultResolvedAt: vault_resolved_at,
    }
}

/// EIP-712 signing hash for a `RedemptionIntentCertificate`. Reuses
/// `attestation_oracle_domain` — the RIC binds to the same `(chainId,
/// AttestationOracle)` domain even though it is never posted on-chain.
#[must_use]
pub fn ric_signing_hash(ric: &RedemptionIntentCertificate, domain: &Eip712Domain) -> B256 {
    ric.eip712_signing_hash(domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolValue;

    /// The `sol!` macro auto-derives a typehash from the struct definition.
    /// This test asserts byte-equality against the manually-pinned typehash
    /// constant. If a future macro upgrade ever changes how the typehash is
    /// derived (e.g., handling of trailing whitespace, parameter naming),
    /// the two paths would silently diverge — this test catches that.
    #[test]
    fn macro_derived_typehash_matches_constant() {
        let macro_typehash = keccak256(Attestation::eip712_root_type().as_bytes());
        assert_eq!(
            macro_typehash,
            attestation_typehash(),
            "sol! macro-derived typehash drifted from manually-pinned constant"
        );
    }

    /// Cross-implementation invariant: the typehash this crate computes
    /// MUST exactly match `AttestationOracle.ATTESTATION_TYPEHASH` on-chain.
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

    /// Pinned from
    /// `cast keccak "AsyncLegDeliveryAttestation(bytes32 redemptionId,uint256 legIndex,bytes32 assetId,uint256 deliveredAmount)"`.
    /// Source of truth: `Xindex/src/AttestationOracle.sol:39-42`.
    #[test]
    fn redemption_typehash_matches_solidity_source() {
        let pinned = B256::new([
            0xb9, 0x16, 0x6b, 0x72, 0x86, 0x3f, 0x84, 0x0d, 0x15, 0x97, 0x6d, 0xac, 0x19, 0x65,
            0xd0, 0xf3, 0x28, 0x42, 0xfa, 0xbb, 0x80, 0x08, 0xff, 0xb2, 0x6f, 0x64, 0x8d, 0xdd,
            0xef, 0x59, 0x26, 0xce,
        ]);
        assert_eq!(
            redemption_attestation_typehash(),
            pinned,
            "Rust typehash drifted from on-chain ASYNC_LEG_DELIVERY_TYPEHASH"
        );
        assert_eq!(
            keccak256(AsyncLegDeliveryAttestation::eip712_root_type().as_bytes()),
            redemption_attestation_typehash(),
            "sol! macro-derived delivery typehash drifted"
        );
    }

    /// Pinned from
    /// `cast keccak "AsyncLegRefundAttestation(bytes32 redemptionId,uint256 legIndex,bytes32 assetId,uint256 refundedAmount)"`.
    /// Source of truth: `Xindex/src/AttestationOracle.sol:47-50`.
    #[test]
    fn refund_typehash_matches_solidity_source() {
        let pinned = B256::new([
            0x3b, 0xa6, 0x6f, 0x74, 0x26, 0x5d, 0x64, 0x09, 0x85, 0x23, 0x9e, 0x60, 0xe2, 0x2f,
            0xd8, 0x92, 0xca, 0x9b, 0x9d, 0x88, 0xbc, 0xdb, 0x19, 0x1e, 0x59, 0x47, 0x97, 0x38,
            0xe0, 0x9c, 0x41, 0xc6,
        ]);
        assert_eq!(
            refund_attestation_typehash(),
            pinned,
            "Rust typehash drifted from on-chain ASYNC_LEG_REFUND_TYPEHASH"
        );
        assert_eq!(
            keccak256(AsyncLegRefundAttestation::eip712_root_type().as_bytes()),
            refund_attestation_typehash(),
            "sol! macro-derived refund typehash drifted"
        );
    }

    /// Pinned from
    /// `cast keccak "AsyncLegStreamedSettlement(bytes32 redemptionId,uint256 legIndex,bytes32 assetId,uint256 deliveredUsdt,uint256 refundedNative)"`.
    /// Source of truth: `Xindex/src/AttestationOracle.sol`'s
    /// `ASYNC_LEG_STREAMED_SETTLEMENT_TYPEHASH`.
    #[test]
    fn streamed_settlement_typehash_matches_solidity_source() {
        let pinned = B256::new([
            0x8b, 0x30, 0x71, 0x2f, 0x33, 0xfa, 0xc5, 0xba, 0x21, 0x2a, 0x51, 0xbc, 0xcc, 0x8a,
            0xc1, 0x0c, 0xba, 0x09, 0xac, 0xa9, 0x31, 0x33, 0xef, 0x28, 0x42, 0xf0, 0x04, 0x15,
            0x1d, 0x50, 0xf4, 0x33,
        ]);
        assert_eq!(
            streamed_settlement_typehash(),
            pinned,
            "Rust typehash drifted from on-chain ASYNC_LEG_STREAMED_SETTLEMENT_TYPEHASH"
        );
        assert_eq!(
            keccak256(AsyncLegStreamedSettlement::eip712_root_type().as_bytes()),
            streamed_settlement_typehash(),
            "sol! macro-derived streamed-settlement typehash drifted"
        );
    }

    /// RIC (5th typehash, off-chain only — `DL-CTD-2`). No Solidity
    /// counterpart; the pin locks the type string for CROSS-OPERATOR
    /// consistency so every operator's daemon computes the identical RIC
    /// digest. Recompute with `cast keccak "<RIC_TYPE_STRING>"`.
    #[test]
    fn ric_typehash_pinned_and_macro_consistent() {
        let pinned = B256::new([
            0x66, 0x3a, 0xa6, 0x05, 0x67, 0x7f, 0xa5, 0x9b, 0x65, 0x89, 0x17, 0x88, 0x2d, 0xed,
            0x96, 0x78, 0x00, 0x75, 0x71, 0x14, 0xb6, 0x05, 0x25, 0xe2, 0xf2, 0x48, 0x7d, 0xb2,
            0xf4, 0x49, 0xf9, 0x37,
        ]);
        assert_eq!(
            ric_typehash(),
            pinned,
            "RIC type string changed — cross-operator digest drift"
        );
        assert_eq!(
            keccak256(RedemptionIntentCertificate::eip712_root_type().as_bytes()),
            ric_typehash(),
            "sol! macro-derived RIC typehash drifted from RIC_TYPE_STRING"
        );
    }

    /// The FIVE typehashes MUST be pairwise distinct — the type-level
    /// mint↔delivery↔refund↔streamed↔RIC separation the design relies on.
    #[test]
    fn five_typehashes_pairwise_distinct() {
        let all = [
            attestation_typehash(),
            redemption_attestation_typehash(),
            refund_attestation_typehash(),
            streamed_settlement_typehash(),
            ric_typehash(),
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "typehash collision");
            }
        }
    }
}
