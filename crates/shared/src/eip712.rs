//! EIP-712 typed-data definitions mirroring `AttestationOracle.sol`.
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
use serde::{Deserialize, Serialize};

/// Signed source/freshness envelope shared by every settlement report.
/// These fields are flattened into each EIP-712 struct (rather than nested)
/// so Solidity and Rust have one unambiguous root type string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SettlementContext {
    pub evidence_hash: B256,
    pub observed_at: u64,
    pub valid_until: u64,
    pub source_chain_id: U256,
    pub source_block_number: u64,
    pub source_block_hash: B256,
    pub observation_epoch: u64,
}

/// Construct the common signed settlement source/freshness envelope.
#[must_use]
pub const fn settlement_context(
    evidence_hash: B256,
    observed_at: u64,
    valid_until: u64,
    source_chain_id: U256,
    source_block_number: u64,
    source_block_hash: B256,
    observation_epoch: u64,
) -> SettlementContext {
    SettlementContext {
        evidence_hash,
        observed_at,
        valid_until,
        source_chain_id,
        source_block_number,
        source_block_hash,
        observation_epoch,
    }
}

sol! {
    /// Attestation payload signed by each k-of-n signer. The on-chain
    /// `AttestationOracle` recovers the signer from the EIP-712 digest of
    /// this struct and forwards `(intentId, slotIndex, attestedAmount)` to
    /// `IntentQueue.recordAttestation`.
    struct Attestation {
        bytes32 intentId;
        uint256 slotIndex;
        uint256 attestedAmount;
        bytes32 evidenceHash;
        uint64 observedAt;
        uint64 validUntil;
        uint256 sourceChainId;
        uint64 sourceBlockNumber;
        bytes32 sourceBlockHash;
        uint64 observationEpoch;
    }
}

/// Verbatim type string used to derive the on-chain typehash. MUST match
/// `AttestationOracle.sol:32-33` byte-for-byte. Trailing-newline-free.
pub const ATTESTATION_TYPE_STRING: &[u8] = b"Attestation(bytes32 intentId,uint256 slotIndex,uint256 attestedAmount,bytes32 evidenceHash,uint64 observedAt,uint64 validUntil,uint256 sourceChainId,uint64 sourceBlockNumber,bytes32 sourceBlockHash,uint64 observationEpoch)";

/// `keccak256(ATTESTATION_TYPE_STRING)` — equals
/// `AttestationOracle.ATTESTATION_TYPEHASH` on-chain.
#[must_use]
pub fn attestation_typehash() -> B256 {
    keccak256(ATTESTATION_TYPE_STRING)
}

/// Construct an `Attestation` from raw fields. Convenience for tests +
/// future signer code.
#[must_use]
pub fn attestation(
    intent_id: B256,
    slot_index: U256,
    attested_amount: U256,
    context: SettlementContext,
) -> Attestation {
    Attestation {
        intentId: intent_id,
        slotIndex: slot_index,
        attestedAmount: attested_amount,
        evidenceHash: context.evidence_hash,
        observedAt: context.observed_at,
        validUntil: context.valid_until,
        sourceChainId: context.source_chain_id,
        sourceBlockNumber: context.source_block_number,
        sourceBlockHash: context.source_block_hash,
        observationEpoch: context.observation_epoch,
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
        bytes32 evidenceHash;
        uint64 observedAt;
        uint64 validUntil;
        uint256 sourceChainId;
        uint64 sourceBlockNumber;
        bytes32 sourceBlockHash;
        uint64 observationEpoch;
    }
}

/// Verbatim type string. MUST match `AttestationOracle.sol:39-42`.
pub const ASYNC_LEG_DELIVERY_TYPE_STRING: &[u8] = b"AsyncLegDeliveryAttestation(bytes32 redemptionId,uint256 legIndex,bytes32 assetId,uint256 deliveredAmount,bytes32 evidenceHash,uint64 observedAt,uint64 validUntil,uint256 sourceChainId,uint64 sourceBlockNumber,bytes32 sourceBlockHash,uint64 observationEpoch)";

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
    context: SettlementContext,
) -> AsyncLegDeliveryAttestation {
    AsyncLegDeliveryAttestation {
        redemptionId: redemption_id,
        legIndex: leg_index,
        assetId: asset_id,
        deliveredAmount: delivered_amount,
        evidenceHash: context.evidence_hash,
        observedAt: context.observed_at,
        validUntil: context.valid_until,
        sourceChainId: context.source_chain_id,
        sourceBlockNumber: context.source_block_number,
        sourceBlockHash: context.source_block_hash,
        observationEpoch: context.observation_epoch,
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
        bytes32 evidenceHash;
        uint64 observedAt;
        uint64 validUntil;
        uint256 sourceChainId;
        uint64 sourceBlockNumber;
        bytes32 sourceBlockHash;
        uint64 observationEpoch;
    }
}

/// Verbatim type string. MUST match `AttestationOracle.sol:47-50`.
pub const ASYNC_LEG_REFUND_TYPE_STRING: &[u8] = b"AsyncLegRefundAttestation(bytes32 redemptionId,uint256 legIndex,bytes32 assetId,uint256 refundedAmount,bytes32 evidenceHash,uint64 observedAt,uint64 validUntil,uint256 sourceChainId,uint64 sourceBlockNumber,bytes32 sourceBlockHash,uint64 observationEpoch)";

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
    context: SettlementContext,
) -> AsyncLegRefundAttestation {
    AsyncLegRefundAttestation {
        redemptionId: redemption_id,
        legIndex: leg_index,
        assetId: asset_id,
        refundedAmount: refunded_amount,
        evidenceHash: context.evidence_hash,
        observedAt: context.observed_at,
        validUntil: context.valid_until,
        sourceChainId: context.source_chain_id,
        sourceBlockNumber: context.source_block_number,
        sourceBlockHash: context.source_block_hash,
        observationEpoch: context.observation_epoch,
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
        bytes32 evidenceHash;
        uint64 observedAt;
        uint64 validUntil;
        uint256 sourceChainId;
        uint64 sourceBlockNumber;
        bytes32 sourceBlockHash;
        uint64 observationEpoch;
    }
}

/// Verbatim type string. MUST match `AttestationOracle.sol`'s
/// `ASYNC_LEG_STREAMED_SETTLEMENT_TYPEHASH` source string.
pub const ASYNC_LEG_STREAMED_SETTLEMENT_TYPE_STRING: &[u8] = b"AsyncLegStreamedSettlement(bytes32 redemptionId,uint256 legIndex,bytes32 assetId,uint256 deliveredUsdt,uint256 refundedNative,bytes32 evidenceHash,uint64 observedAt,uint64 validUntil,uint256 sourceChainId,uint64 sourceBlockNumber,bytes32 sourceBlockHash,uint64 observationEpoch)";

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
    context: SettlementContext,
) -> AsyncLegStreamedSettlement {
    AsyncLegStreamedSettlement {
        redemptionId: redemption_id,
        legIndex: leg_index,
        assetId: asset_id,
        deliveredUsdt: delivered_usdt,
        refundedNative: refunded_native,
        evidenceHash: context.evidence_hash,
        observedAt: context.observed_at,
        validUntil: context.valid_until,
        sourceChainId: context.source_chain_id,
        sourceBlockNumber: context.source_block_number,
        sourceBlockHash: context.source_block_hash,
        observationEpoch: context.observation_epoch,
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
        bytes32 nativeChainId;
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
pub const RIC_TYPE_STRING: &[u8] = b"RedemptionIntentCertificate(bytes32 redemptionId,uint256 legIndex,bytes32 assetId,bytes32 nativeChainId,uint256 amount,uint8 amountDecimals,bytes32 immediateTargetHash,bytes32 memoHash,bytes32 finalDestinationHash,uint64 vaultResolvedAt)";

/// `keccak256(RIC_TYPE_STRING)`.
#[must_use]
pub fn ric_typehash() -> B256 {
    keccak256(RIC_TYPE_STRING)
}

/// Construct a `RedemptionIntentCertificate` from raw fields.
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "the RIC binds 10 distinct certified fields; a wrapper struct param would just re-wrap them"
)]
pub fn redemption_intent_certificate(
    redemption_id: B256,
    leg_index: U256,
    asset_id: B256,
    native_chain_id: B256,
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
        nativeChainId: native_chain_id,
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

sol! {
    /// CTD-1 Slice C Acquire-Cancel Certificate (ACC) — the SIXTH
    /// typed-data on the `attestation_oracle_domain`, **off-chain only**
    /// (`DL-CTD-2`). A SIBLING of the RIC for the MINT-CANCEL BTC
    /// swap-back: when a pending mint is cancelled, the BTC the protocol
    /// already swapped to acquire the basket asset must be swapped BACK,
    /// a custody spend rooted on the `AcquireCancelled` event — NOT a
    /// `RedeemDispatched`/RIC. A distinct typehash so an ACC can never
    /// authorize a redemption spend (nor a RIC a cancel spend); the
    /// shared PSBT-input gate accepts a RIC XOR an ACC.
    ///
    /// Without this, requiring a RIC on the shared psbt-input endpoint
    /// would either BRICK BTC after every cancelled mint or re-open
    /// CTD-1 via a no-certificate carve-out. The one-shot key is
    /// `(chain_id, cancelId)` — `cancelId` is unique per
    /// `AcquireCancelled`.
    struct AcquireCancelCertificate {
        bytes32 cancelId;
        bytes32 intentId;
        uint256 slotIndex;
        bytes32 assetId;
        bytes32 nativeChainId;
        uint256 amount;
        uint8 amountDecimals;
        bytes32 immediateTargetHash;
        bytes32 memoHash;
        bytes32 finalDestinationHash;
        uint64 vaultResolvedAt;
    }
}

/// Verbatim ACC type string. Off-chain only — pinned for cross-operator
/// consistency (every operator's daemon MUST compute the identical
/// digest). Sibling of [`RIC_TYPE_STRING`].
pub const ACQUIRE_CANCEL_TYPE_STRING: &[u8] = b"AcquireCancelCertificate(bytes32 cancelId,bytes32 intentId,uint256 slotIndex,bytes32 assetId,bytes32 nativeChainId,uint256 amount,uint8 amountDecimals,bytes32 immediateTargetHash,bytes32 memoHash,bytes32 finalDestinationHash,uint64 vaultResolvedAt)";

/// `keccak256(ACQUIRE_CANCEL_TYPE_STRING)`.
#[must_use]
pub fn acquire_cancel_typehash() -> B256 {
    keccak256(ACQUIRE_CANCEL_TYPE_STRING)
}

/// Construct an `AcquireCancelCertificate` from raw fields.
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "the ACC binds 11 distinct certified fields; a wrapper struct param would just re-wrap them"
)]
pub fn acquire_cancel_certificate(
    cancel_id: B256,
    intent_id: B256,
    slot_index: U256,
    asset_id: B256,
    native_chain_id: B256,
    amount: U256,
    amount_decimals: u8,
    immediate_target_hash: B256,
    memo_hash: B256,
    final_destination_hash: B256,
    vault_resolved_at: u64,
) -> AcquireCancelCertificate {
    AcquireCancelCertificate {
        cancelId: cancel_id,
        intentId: intent_id,
        slotIndex: slot_index,
        assetId: asset_id,
        nativeChainId: native_chain_id,
        amount,
        amountDecimals: amount_decimals,
        immediateTargetHash: immediate_target_hash,
        memoHash: memo_hash,
        finalDestinationHash: final_destination_hash,
        vaultResolvedAt: vault_resolved_at,
    }
}

/// EIP-712 signing hash for an `AcquireCancelCertificate`. Reuses
/// `attestation_oracle_domain`, like the RIC.
#[must_use]
pub fn acquire_cancel_signing_hash(acc: &AcquireCancelCertificate, domain: &Eip712Domain) -> B256 {
    acc.eip712_signing_hash(domain)
}

/* -------------------------------------------------------------------------- */
/*        PRICE ATTESTATION (NAV oracle — k-of-n per-asset price quote)        */
/* -------------------------------------------------------------------------- */

sol! {
    /// Per-asset price quote signed by each k-of-n price signer. The on-chain
    /// `PriceAttestationOracle.attestPrice` recovers the signers from the
    /// EIP-712 digest of this struct and stores `(priceWad, supply)` for
    /// `assetId` (after its L1 bounds / L2 Chainlink / L3 challenge-window
    /// guards). Current NAV math consumes `priceWad` and discards `supply`, but
    /// both remain in the deployed signed shape. `timestamp` is the observation time, strictly
    /// increasing per asset (anti-replay). A SEPARATE EIP-712 domain (name
    /// `Xindex PriceAttestationOracle`) and typehash from the mint/redeem
    /// attestations — a price signature can never verify on a custody path.
    struct PriceAttestation {
        bytes32 assetId;
        uint256 priceWad;
        uint256 supply;
        uint256 timestamp;
    }
}

/// Verbatim type string. MUST match `PriceAttestationOracle.sol`'s
/// `PRICE_ATTESTATION_TYPEHASH` source string byte-for-byte.
pub const PRICE_ATTESTATION_TYPE_STRING: &[u8] =
    b"PriceAttestation(bytes32 assetId,uint256 priceWad,uint256 supply,uint256 timestamp)";

/// `keccak256(PRICE_ATTESTATION_TYPE_STRING)` — equals
/// `PriceAttestationOracle.PRICE_ATTESTATION_TYPEHASH` on-chain.
#[must_use]
pub fn price_attestation_typehash() -> B256 {
    keccak256(PRICE_ATTESTATION_TYPE_STRING)
}

/// EIP-712 domain mirroring `PriceAttestationOracle`'s constructor:
/// `EIP712("Xindex PriceAttestationOracle", "1")`. DISTINCT from
/// [`attestation_oracle_domain`] — the price oracle is a separate contract, so
/// its `verifyingContract` + domain name differ and a price signature is
/// non-transferable to the mint/redeem attestation path.
#[must_use]
pub fn price_oracle_domain(chain_id: u64, verifying_contract: Address) -> Eip712Domain {
    eip712_domain! {
        name: "Xindex PriceAttestationOracle",
        version: "1",
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    }
}

/// Construct a `PriceAttestation` from raw fields. `timestamp` widens to the
/// `uint256` the on-chain hash uses (`uint256(timestamp)`); the on-chain
/// `attestPrice` param is `uint64`.
#[must_use]
pub fn price_attestation(
    asset_id: B256,
    price_wad: U256,
    supply: U256,
    timestamp: u64,
) -> PriceAttestation {
    PriceAttestation {
        assetId: asset_id,
        priceWad: price_wad,
        supply,
        timestamp: U256::from(timestamp),
    }
}

/// EIP-712 signing hash for a `PriceAttestation` — the 32-byte digest each
/// k-of-n price signer signs. Equivalent to the on-chain
/// `_hashTypedDataV4(keccak256(abi.encode(PRICE_ATTESTATION_TYPEHASH, ...)))`.
#[must_use]
pub fn price_attestation_signing_hash(att: &PriceAttestation, domain: &Eip712Domain) -> B256 {
    att.eip712_signing_hash(domain)
}

/* -------------------------------------------------------------------------- */
/*           THORCHAIN INBOUND STATE (vault / Router / pause mirror)          */
/* -------------------------------------------------------------------------- */

sol! {
    /// Short-lived snapshot of `THORChain`'s Ethereum inbound state, signed by
    /// each independent registry observer. Field order and integer widths are
    /// consensus-critical and mirror
    /// `ThorchainVaultRegistry.INBOUND_STATE_TYPEHASH` exactly.
    struct InboundState {
        address vault;
        address router;
        uint8 pauseFlags;
        uint64 observedAt;
        uint64 validUntil;
        uint64 sequence;
        bytes32 sourceHash;
    }
}

/// Verbatim type string from
/// `ThorchainVaultRegistry.INBOUND_STATE_TYPEHASH`.
pub const INBOUND_STATE_TYPE_STRING: &[u8] = b"InboundState(address vault,address router,uint8 pauseFlags,uint64 observedAt,uint64 validUntil,uint64 sequence,bytes32 sourceHash)";

/// `keccak256(INBOUND_STATE_TYPE_STRING)`.
#[must_use]
pub fn inbound_state_typehash() -> B256 {
    keccak256(INBOUND_STATE_TYPE_STRING)
}

/// EIP-712 domain shared by both registry-authorized message families.
#[must_use]
pub fn thorchain_registry_domain(chain_id: u64, verifying_contract: Address) -> Eip712Domain {
    eip712_domain! {
        name: "Xindex THORChain Inbound Registry",
        version: "1",
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    }
}

/// Construct the exact typed inbound-state payload accepted by
/// `ThorchainVaultRegistry.attestInbound`.
#[must_use]
pub fn inbound_state(
    vault: Address,
    router: Address,
    pause_flags: u8,
    observed_at: u64,
    valid_until: u64,
    sequence: u64,
    source_hash: B256,
) -> InboundState {
    InboundState {
        vault,
        router,
        pauseFlags: pause_flags,
        observedAt: observed_at,
        validUntil: valid_until,
        sequence,
        sourceHash: source_hash,
    }
}

/// EIP-712 signing digest returned by the on-chain `attestationDigest` view.
#[must_use]
pub fn inbound_state_signing_hash(state: &InboundState, domain: &Eip712Domain) -> B256 {
    state.eip712_signing_hash(domain)
}

/* -------------------------------------------------------------------------- */
/*          THORCHAIN QUOTE AUTHORIZATION (one exact adapter dispatch)         */
/* -------------------------------------------------------------------------- */

sol! {
    /// One-time quote authorization consumed by
    /// `ThorchainVaultRegistry.consumeQuoteAuthorization`. This commits the
    /// exact adapter call, current inbound-state hash, Router memo, expiry,
    /// per-originator nonce, and canonical upstream quote evidence.
    struct QuoteAuthorization {
        address adapter;
        address indexToken;
        address originator;
        address fundingToken;
        address targetToken;
        uint256 amountIn;
        bytes32 custodyHash;
        bytes32 inboundStateHash;
        bytes32 memoHash;
        uint64 dispatchDeadline;
        uint64 quoteNonce;
        bytes32 quoteHash;
    }
}

/// Verbatim type string from
/// `ThorchainVaultRegistry.QUOTE_AUTHORIZATION_TYPEHASH`.
pub const QUOTE_AUTHORIZATION_TYPE_STRING: &[u8] = b"QuoteAuthorization(address adapter,address indexToken,address originator,address fundingToken,address targetToken,uint256 amountIn,bytes32 custodyHash,bytes32 inboundStateHash,bytes32 memoHash,uint64 dispatchDeadline,uint64 quoteNonce,bytes32 quoteHash)";

/// `keccak256(QUOTE_AUTHORIZATION_TYPE_STRING)`.
#[must_use]
pub fn quote_authorization_typehash() -> B256 {
    keccak256(QUOTE_AUTHORIZATION_TYPE_STRING)
}

/// Construct the exact typed quote authorization consumed by the registry.
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "the registry quote type intentionally binds twelve dispatch fields"
)]
pub fn quote_authorization(
    adapter: Address,
    index_token: Address,
    originator: Address,
    funding_token: Address,
    target_token: Address,
    amount_in: U256,
    custody_hash: B256,
    inbound_state_hash: B256,
    memo_hash: B256,
    dispatch_deadline: u64,
    quote_nonce: u64,
    quote_hash: B256,
) -> QuoteAuthorization {
    QuoteAuthorization {
        adapter,
        indexToken: index_token,
        originator,
        fundingToken: funding_token,
        targetToken: target_token,
        amountIn: amount_in,
        custodyHash: custody_hash,
        inboundStateHash: inbound_state_hash,
        memoHash: memo_hash,
        dispatchDeadline: dispatch_deadline,
        quoteNonce: quote_nonce,
        quoteHash: quote_hash,
    }
}

/// EIP-712 signing digest returned by the on-chain
/// `quoteAuthorizationDigest` view.
#[must_use]
pub fn quote_authorization_signing_hash(quote: &QuoteAuthorization, domain: &Eip712Domain) -> B256 {
    quote.eip712_signing_hash(domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;
    use alloy_sol_types::SolValue;

    fn golden_settlement_context() -> SettlementContext {
        settlement_context(
            B256::repeat_byte(0x88),
            1_800_000_000,
            1_800_000_300,
            U256::from(1u64),
            20_000_000,
            B256::repeat_byte(0x99),
            7,
        )
    }

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
        // Pinned from the full source/freshness-bound type string above.
        let pinned = b256!("0x38a3beebbb549601401f995718f0907d2d6f3a1f675928405ce340ced511005f");
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
            golden_settlement_context(),
        );
        let encoded = a.abi_encode();
        let decoded = Attestation::abi_decode(&encoded, true).expect("round-trip decode");
        assert_eq!(decoded.intentId, a.intentId);
        assert_eq!(decoded.slotIndex, a.slotIndex);
        assert_eq!(decoded.attestedAmount, a.attestedAmount);
    }

    /// Pinned from
    /// `cast keccak` of [`ASYNC_LEG_DELIVERY_TYPE_STRING`].
    #[test]
    fn redemption_typehash_matches_solidity_source() {
        let pinned = b256!("0xfc42da1bda871b2b19087408ea6d5062841f1cd398eff721ad13fcb345fd4848");
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
    /// `cast keccak` of [`ASYNC_LEG_REFUND_TYPE_STRING`].
    #[test]
    fn refund_typehash_matches_solidity_source() {
        let pinned = b256!("0x06c4120e08cf70ee7c5c4a9c787c07889c8c964d92b2c0da3356dddb97374d72");
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
    /// `cast keccak` of [`ASYNC_LEG_STREAMED_SETTLEMENT_TYPE_STRING`].
    #[test]
    fn streamed_settlement_typehash_matches_solidity_source() {
        let pinned = b256!("0x20da49cd3741d480bd896044dfa27d536ad6c0a963a771c721159142abb2233a");
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
        assert!(
            std::str::from_utf8(RIC_TYPE_STRING)
                .is_ok_and(|type_string| type_string.contains("bytes32 nativeChainId")),
            "RIC v2 must bind the canonical native-chain identifier"
        );
        let pinned = b256!("0xd5294c4329b536e1f60dc30b921745a04e46e8a3aec40367b7217c7708b91c01");
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

    /// ACC (6th typehash, off-chain only — `DL-CTD-2` Slice C). Sibling
    /// of the RIC for the mint-cancel BTC swap-back; pinned for
    /// cross-operator digest consistency. Recompute with
    /// `cast keccak "<ACQUIRE_CANCEL_TYPE_STRING>"`.
    #[test]
    fn acquire_cancel_typehash_pinned_and_macro_consistent() {
        assert!(
            std::str::from_utf8(ACQUIRE_CANCEL_TYPE_STRING)
                .is_ok_and(|type_string| type_string.contains("bytes32 nativeChainId")),
            "ACC v2 must bind the canonical native-chain identifier"
        );
        let pinned = b256!("0x385923248ee4be4fcacef0eb1fc80894adab9ac5521414b08c733f3d7064cfd1");
        assert_eq!(
            acquire_cancel_typehash(),
            pinned,
            "ACC type string changed — cross-operator digest drift"
        );
        assert_eq!(
            keccak256(AcquireCancelCertificate::eip712_root_type().as_bytes()),
            acquire_cancel_typehash(),
            "sol! macro-derived ACC typehash drifted from ACQUIRE_CANCEL_TYPE_STRING"
        );
    }

    /// The SIX typehashes MUST be pairwise distinct — the type-level
    /// mint↔delivery↔refund↔streamed↔RIC↔ACC separation the design
    /// relies on (a RIC can never authorize a cancel spend, nor vice
    /// versa).
    #[test]
    fn six_typehashes_pairwise_distinct() {
        let all = [
            attestation_typehash(),
            redemption_attestation_typehash(),
            refund_attestation_typehash(),
            streamed_settlement_typehash(),
            ric_typehash(),
            acquire_cancel_typehash(),
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "typehash collision");
            }
        }
    }

    /// The price-oracle typehash MUST byte-match the on-chain constant, and be
    /// distinct from the six custody typehashes (it also lives on a separate
    /// domain, so a price signature can never recover on a custody path).
    /// Pinned: `cast keccak "PriceAttestation(bytes32 assetId,uint256 priceWad,uint256 supply,uint256 timestamp)"`.
    /// Source of truth: `Xindex/src/PriceAttestationOracle.sol`
    /// `PRICE_ATTESTATION_TYPEHASH`.
    #[test]
    fn price_attestation_typehash_matches_solidity_source() {
        assert_eq!(
            price_attestation_typehash(),
            b256!("0x4d3c02568f4c467f395dfac6384daa3f274b9a11899ed5eb2d56ff4b453ebc7e"),
            "Rust typehash drifted from on-chain PRICE_ATTESTATION_TYPEHASH"
        );
        assert_eq!(
            keccak256(PriceAttestation::eip712_root_type().as_bytes()),
            price_attestation_typehash(),
            "sol! macro-derived PriceAttestation typehash drifted"
        );
        assert_ne!(price_attestation_typehash(), attestation_typehash());
    }

    #[test]
    fn registry_typehashes_match_solidity_source() {
        assert_eq!(
            inbound_state_typehash(),
            b256!("0x87a96cf35d2ca185a7bc8a9c0cf8a6eab5dcfffeff6624b24e84f588570fa5b2"),
            "Rust typehash drifted from on-chain INBOUND_STATE_TYPEHASH"
        );
        assert_eq!(
            quote_authorization_typehash(),
            b256!("0x2d94846c56ab8e8c45bd02c25bcb00d0866c0d34aafc52e628960fb0dff82158"),
            "Rust typehash drifted from on-chain QUOTE_AUTHORIZATION_TYPEHASH"
        );
        assert_eq!(
            keccak256(InboundState::eip712_root_type().as_bytes()),
            inbound_state_typehash(),
            "macro-derived inbound-state typehash drifted"
        );
        assert_eq!(
            keccak256(QuoteAuthorization::eip712_root_type().as_bytes()),
            quote_authorization_typehash(),
            "macro-derived quote-authorization typehash drifted"
        );
        assert_ne!(inbound_state_typehash(), quote_authorization_typehash());
        assert_ne!(inbound_state_typehash(), price_attestation_typehash());
    }

    #[test]
    fn seven_onchain_report_typehashes_pairwise_distinct() {
        let all = [
            attestation_typehash(),
            redemption_attestation_typehash(),
            refund_attestation_typehash(),
            streamed_settlement_typehash(),
            price_attestation_typehash(),
            inbound_state_typehash(),
            quote_authorization_typehash(),
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "on-chain report typehash collision");
            }
        }
    }

    /// Fixed domain for the golden-digest vectors: chainId 1,
    /// verifyingContract 0xCC..CC. The digests below are the 32 bytes each
    /// k-of-n signer's HSM actually signs; pinning them locks the FULL
    /// EIP-712 encoding (domain separator + struct hash + the 0x1901 prefix),
    /// not just the typehash the other tests cover. A drift here means a
    /// signature that won't recover to the expected signer on-chain — or, for
    /// the off-chain RIC/ACC, cross-operator digest divergence. Regenerate by
    /// temporarily printing the function outputs for these fixed inputs.
    fn golden_domain() -> Eip712Domain {
        attestation_oracle_domain(1, Address::repeat_byte(0xCC))
    }

    #[test]
    fn attestation_oracle_domain_separator_pinned() {
        assert_eq!(
            golden_domain().separator(),
            b256!("0xc3cbe4ff899fabc043257a4b82dc673b5aef398c5429674c85675413c0fed05d"),
            "EIP-712 domain separator drifted — every signing hash moves with it"
        );
    }

    #[test]
    fn price_oracle_domain_separator_pinned() {
        assert_eq!(
            price_oracle_domain(1, Address::repeat_byte(0xCC)).separator(),
            b256!("0xbd686a5912086b4949853704a9723fa28673e930238d3d3ff43357965d447954"),
            "price-oracle EIP-712 domain separator drifted"
        );
    }

    #[test]
    fn thorchain_registry_domain_separator_pinned() {
        assert_eq!(
            thorchain_registry_domain(1, Address::repeat_byte(0xCC)).separator(),
            b256!("0x996a5a03e4c193b66ae1e12ffa57d5e31fada227204efa31f0362a435054c69e"),
            "THORChain-registry EIP-712 domain separator drifted"
        );
    }

    #[test]
    fn attestation_signing_hash_golden() {
        let a = attestation(
            B256::repeat_byte(0x11),
            U256::from(7u64),
            U256::from(1_000_000u64),
            golden_settlement_context(),
        );
        assert_eq!(
            attestation_signing_hash(&a, &golden_domain()),
            b256!("0xf79590b94efea153c3523972889e57e0ce0e5e44788358365173d21039d12c53"),
            "mint attestation digest drifted"
        );
    }

    #[test]
    fn redemption_attestation_signing_hash_golden() {
        let d = redemption_attestation(
            B256::repeat_byte(0x22),
            U256::from(3u64),
            B256::repeat_byte(0x33),
            U256::from(2_000_000u64),
            golden_settlement_context(),
        );
        assert_eq!(
            redemption_attestation_signing_hash(&d, &golden_domain()),
            b256!("0xde8c0c3987180857488cebbb3f111103c5876da261cd3256b74e65ec3c42ac21"),
            "delivery attestation digest drifted"
        );
    }

    #[test]
    fn refund_attestation_signing_hash_golden() {
        let r = refund_attestation(
            B256::repeat_byte(0x44),
            U256::from(1u64),
            B256::repeat_byte(0x55),
            U256::from(900_000u64),
            golden_settlement_context(),
        );
        assert_eq!(
            refund_attestation_signing_hash(&r, &golden_domain()),
            b256!("0xf5b6eea80d89fa26a802ba7eb84ebcb47f9959a7bce4a01e007204ee00025815"),
            "refund attestation digest drifted"
        );
    }

    #[test]
    fn streamed_settlement_signing_hash_golden() {
        let s = streamed_settlement(
            B256::repeat_byte(0x66),
            U256::from(2u64),
            B256::repeat_byte(0x77),
            U256::from(500_000u64),
            U256::from(400_000u64),
            golden_settlement_context(),
        );
        assert_eq!(
            streamed_settlement_signing_hash(&s, &golden_domain()),
            b256!("0x049017a11b4efbac6a058cc06173ed6eaf43f60607660c708c4fc9c2753839ce"),
            "streamed-settlement digest drifted"
        );
    }

    #[test]
    fn settlement_digest_binds_every_source_context_field() {
        let base = golden_settlement_context();
        let digest = |context| {
            attestation_signing_hash(
                &attestation(
                    B256::repeat_byte(0x11),
                    U256::from(7u64),
                    U256::from(1_000_000u64),
                    context,
                ),
                &golden_domain(),
            )
        };
        let expected = digest(base);
        let mut variants = [base; 7];
        variants[0].evidence_hash = B256::repeat_byte(0x89);
        variants[1].observed_at += 1;
        variants[2].valid_until += 1;
        variants[3].source_chain_id += U256::from(1u8);
        variants[4].source_block_number += 1;
        variants[5].source_block_hash = B256::repeat_byte(0x9a);
        variants[6].observation_epoch += 1;
        for changed in variants {
            assert_ne!(
                digest(changed),
                expected,
                "unsigned settlement context field"
            );
        }
    }

    #[test]
    fn price_attestation_signing_hash_golden() {
        let p = price_attestation(
            B256::repeat_byte(0xAA),
            U256::from(1_234_567_890_123_456_789u64),
            U256::from(2_100_000_000_000_000u64),
            1_800_000_000,
        );
        let domain = price_oracle_domain(1, Address::repeat_byte(0xCC));
        assert_eq!(
            price_attestation_signing_hash(&p, &domain),
            b256!("0x9a61c7b4f6b6a6223539ce3b2e0c3fbe225740133d9a96c9e1665624f4517f43"),
            "price-attestation digest drifted"
        );
    }

    #[test]
    fn inbound_state_signing_hash_golden() {
        let state = inbound_state(
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            0,
            1_800_000_000,
            1_800_000_300,
            42,
            B256::repeat_byte(0x33),
        );
        let domain = thorchain_registry_domain(1, Address::repeat_byte(0xCC));
        assert_eq!(
            inbound_state_signing_hash(&state, &domain),
            b256!("0xa323456ebbd321784271dc2638ce603d5ac218d6b15de7bc80aade6926d6aa02"),
            "inbound-state digest drifted"
        );
    }

    #[test]
    fn quote_authorization_signing_hash_golden() {
        let quote = quote_authorization(
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            Address::repeat_byte(0x33),
            Address::repeat_byte(0x44),
            Address::repeat_byte(0x55),
            U256::from(1_000_000u64),
            B256::repeat_byte(0x66),
            B256::repeat_byte(0x77),
            B256::repeat_byte(0x88),
            1_800_000_060,
            9,
            B256::repeat_byte(0x99),
        );
        let domain = thorchain_registry_domain(1, Address::repeat_byte(0xCC));
        assert_eq!(
            quote_authorization_signing_hash(&quote, &domain),
            b256!("0x357fe06cde537d55739bc06cd25b4b141e47cb09b3003807abc5c500d55b0184"),
            "quote-authorization digest drifted"
        );
    }

    #[test]
    fn ric_signing_hash_golden() {
        let ric = redemption_intent_certificate(
            B256::repeat_byte(0x88),
            U256::from(4u64),
            B256::repeat_byte(0x99),
            B256::repeat_byte(0x98),
            U256::from(3_000_000u64),
            8,
            B256::repeat_byte(0xAA),
            B256::repeat_byte(0xBB),
            B256::repeat_byte(0xCC),
            1_700_000_000,
        );
        assert_eq!(
            ric_signing_hash(&ric, &golden_domain()),
            b256!("0x4ef0bfb67128773bdb18e87440a6a56dbc9b5a5253f4d1de05e26107612bc9e5"),
            "RIC digest drifted — cross-operator divergence"
        );
    }

    #[test]
    fn acquire_cancel_signing_hash_golden() {
        let acc = acquire_cancel_certificate(
            B256::repeat_byte(0xDD),
            B256::repeat_byte(0xEE),
            U256::from(5u64),
            B256::repeat_byte(0x12),
            B256::repeat_byte(0x13),
            U256::from(4_000_000u64),
            6,
            B256::repeat_byte(0x34),
            B256::repeat_byte(0x56),
            B256::repeat_byte(0x78),
            1_800_000_000,
        );
        assert_eq!(
            acquire_cancel_signing_hash(&acc, &golden_domain()),
            b256!("0x0242970a7a5bcc28ae612fdf09cf4be64886e30a9475136eb0ae2155db2a2c0a"),
            "ACC digest drifted — cross-operator divergence"
        );
    }
}
