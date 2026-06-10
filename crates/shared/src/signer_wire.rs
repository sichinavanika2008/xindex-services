//! Coordinator ↔ signer-daemon JSON wire schema (PART 5 / DL-M5-3).
//!
//! The signing surface has FOUR endpoints, each with its own typed
//! request struct. Type-level separation — there is no runtime `kind`
//! discriminator the daemon could forget. The on-chain typehashes are
//! three structurally-distinct EIP-712 messages plus PSBT-input signing
//! for the Bitcoin multisig; this module mirrors that 4-way shape.
//!
//! Fields are hex strings (`0x…`-prefixed) so the schema is robust
//! across languages and tooling, and we never depend on a JSON
//! representation choice for alloy primitives. The daemon parses
//! strings into [`alloy_primitives`] types at the boundary.
//!
//! `xindex-shared` is the one place this schema lives — daemon and
//! coordinator both depend on it, so a wire-shape mismatch is a
//! compile error, never a runtime one.

use serde::{Deserialize, Deserializer, Serialize};

use crate::chain_registry::{ChainId, CustodyFamily};

/// `POST /api/v1/sign/eip712-attestation`
///
/// Mint slot attestation. Mirrors the on-chain
/// `ATTESTATION_TYPEHASH = keccak256("Attestation(bytes32 intentId,uint256 slotIndex,uint256 attestedAmount)")`.
/// The daemon computes the EIP-712 digest itself from its locally-known
/// domain — it never trusts a coordinator-supplied digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationSignRequest {
    /// `bytes32` intent id, `0x`-prefixed 32-byte hex.
    pub intent_id: String,
    /// `uint256` slot index, decimal string (JSON numbers can't represent
    /// 256-bit cleanly).
    pub slot_index: String,
    /// `uint256` attested amount, decimal string.
    pub attested_amount: String,
}

/// `POST /api/v1/sign/eip712-redemption-delivery`
///
/// Per-leg delivery attestation. Mirrors
/// `AttestationOracle.ASYNC_LEG_DELIVERY_TYPEHASH`. The daemon's replay
/// DB is keyed by `(redemption_id, leg_index)` with a delivery-XOR-refund
/// mutex per leg (audit H2) — re-signing a different `delivered_amount`
/// under the same `(redemption_id, leg_index)` is a `Conflict`, and a
/// refund after a delivery on the same leg is a `MutexViolation`; neither
/// reaches the HSM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedemptionDeliverySignRequest {
    /// `bytes32` redemption id, hex.
    pub redemption_id: String,
    /// `uint256` leg index, decimal string.
    pub leg_index: String,
    /// `bytes32` canonical asset id of THIS leg (e.g.
    /// `keccak256("BTC.BTC")`), 0x-prefixed hex. Bound in the typed-data
    /// digest AND re-checked at the on-chain queue; defends against
    /// leg-index confusion across heterogeneous baskets.
    pub asset_id: String,
    /// `uint256` delivered amount in the leg's exit-token units (on-chain
    /// USDT 1e6 for `THORChain` rail), decimal string.
    pub delivered_amount: String,
}

/// `POST /api/v1/sign/eip712-refund`
///
/// Per-leg refund attestation. Mirrors
/// `AttestationOracle.ASYNC_LEG_REFUND_TYPEHASH`. On-chain delivery-XOR-
/// refund at the LEG granularity is enforced at the queue; the daemon's
/// replay DB enforces the same per-leg exclusion locally — pre-flight
/// refuse to sign a refund for a `(redemption_id, leg_index)` that
/// already has a delivery recorded by this daemon, and vice versa.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefundSignRequest {
    /// `bytes32` redemption id, hex.
    pub redemption_id: String,
    /// `uint256` leg index, decimal string.
    pub leg_index: String,
    /// `bytes32` canonical asset id of THIS leg, 0x-prefixed hex.
    pub asset_id: String,
    /// `uint256` refunded amount in the leg's native asset's smallest
    /// units (e.g. sats for BTC), decimal string.
    pub refunded_amount: String,
}

/// `POST /api/v1/sign/psbt-input`
///
/// UTXO-family multisig partial-signature endpoint. The daemon:
///   1. Routes to the per-chain config keyed by `chain_id` (404 if
///      this daemon is not configured for that chain — U8 multi-role).
///   2. Decodes the PSBT.
///   3. Verifies the witness/redeem script at `input_index` matches
///      that chain's configured multisig descriptor (refuses unknown
///      scripts).
///   4. Verifies `vin[0]` of the unsigned tx belongs to that descriptor
///      (the Part-3 refund-address invariant — `THORChain` resolves
///      refund-sender to `vin[0]`'s prev-out).
///   5. Signs the input sighash with its single secp256k1 key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PsbtInputSignRequest {
    /// Which UTXO chain this PSBT is for (selects the daemon's
    /// per-chain descriptor + key + script-kind). Required since U8;
    /// daemon returns `endpoint_disabled` if it has no config for the
    /// requested chain.
    pub chain_id: ChainId,
    /// Base64-encoded PSBT (BIP-174 v0).
    pub psbt_base64: String,
    /// Which input index of the PSBT to partial-sign.
    pub input_index: u32,
    /// Optional output veto (audit M2, defense-in-depth): hex of the
    /// expected payout output's `scriptPubKey`. When `Some`, the daemon
    /// refuses to sign unless at least one output of `psbt.unsigned_tx`
    /// has a byte-identical `scriptPubKey`. Binds the leg's intended
    /// `THORChain` Asgard destination to the PSBT the daemon signs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_destination_spk: Option<String>,
    /// Optional output veto (audit M2): the expected payout amount in
    /// sats. When `Some` (and `expected_destination_spk` is `Some`), the
    /// matched destination output's `value` must equal this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_amount_sats: Option<u64>,
    /// Optional output veto (audit M2): hex of the expected `OP_RETURN`
    /// data payload (the `THORChain` memo bytes). When `Some`, the daemon
    /// refuses unless some `OP_RETURN` output pushes byte-identical data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_memo: Option<String>,
}

/// `POST /api/v1/sign/evm-safe-tx`
///
/// V2 (Phase 3.2): Safe v1.4.1 `execTransaction` digest signing for
/// the EVM custody family. The daemon:
///   1. Routes to the per-chain config keyed by `chain_id` (`endpoint_disabled`
///      if no EVM role is configured for that chain — DL-P3.2-2).
///   2. RE-COMPUTES the `safeTxHash` from the `safe-evm` crate (V3) using
///      the caller-supplied Safe address + nonce + ABI inputs, and refuses
///      the request if the recomputed digest does not match `safe_tx_hash`
///      — defense-in-depth: never blind-sign.
///   3. Replay-keys on `(redemption_id_or_safe_addr, chain_id, nonce)`.
///      `safe_tx_hash` already incorporates `chain_id` via the EIP-712
///      domain separator, so the tuple is over-keyed by design.
///   4. Signs the recomputed digest via `HsmDigestSigner::sign_digest` —
///      the SAME 65-byte ECDSA primitive used by the PSBT-input path.
///
/// Returns [`Eip712SignResponse`] — no new response type is needed; the
/// existing `signature` + `signer_address` fields cover the Safe path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvmSafeTxSignRequest {
    /// EVM `ChainId`. MUST satisfy
    /// `chain_id.custody_family() == CustodyFamily::Evm`; the serde
    /// validator rejects UTXO chain ids at deserialize time with
    /// [`error_codes::NON_EVM_CHAIN`].
    #[serde(deserialize_with = "deserialize_evm_chain_id")]
    pub chain_id: ChainId,
    /// Safe proxy contract address — `0x`-prefixed 20-byte EIP-55
    /// checksum hex. Bound into the EIP-712 domain's `verifyingContract`.
    pub safe_address: String,

    // ─── SafeTransaction ABI inputs (V5) ────────────────────────────────
    // Carried in the wire so the daemon can RE-COMPUTE `safeTxHash` from
    // the inputs locally and reject mismatch (DL-M5-3 / signer-daemon
    // never trusts a coordinator-supplied digest).
    /// `SafeTx.to` — `0x`-prefixed 20-byte address hex.
    pub to: String,
    /// `SafeTx.value` — wei, decimal `U256` string.
    pub value: String,
    /// `SafeTx.data` — `0x`-prefixed bytes hex (may be empty `0x`).
    pub data: String,
    /// `SafeTx.operation` — `0` (Call) or `1` (`DelegateCall`). Phase 3.2
    /// custody never delegatecalls.
    pub operation: u8,
    /// `SafeTx.safeTxGas` — gas budget for the Safe-side call, decimal
    /// `U256` string. `0` = use full available gas at execution time
    /// (Safe v1.3+ default).
    pub safe_tx_gas: String,
    /// `SafeTx.baseGas` — gas charged for Safe overhead, decimal `U256`
    /// string. `0` in Phase 3.2 (no Safe-side refund).
    pub base_gas: String,
    /// `SafeTx.gasPrice` — Safe-side refund price, decimal `U256`
    /// string. **Always 0 in Phase 3.2** (DL-P3.2-7: caller supplies
    /// gas at the tx-broadcast layer, not Safe's refund machinery).
    pub gas_price: String,
    /// `SafeTx.gasToken` — refund token, `0x`-prefixed address hex.
    /// **Always `address(0)` in Phase 3.2** (no Safe-side refund).
    pub gas_token: String,
    /// `SafeTx.refundReceiver` — `0x`-prefixed address hex. **Always
    /// `address(0)` in Phase 3.2** (no refund).
    pub refund_receiver: String,
    /// `SafeTx.nonce` — the Safe's monotonic nonce, decimal `U256`
    /// string (Safe nonces are practically `u64` but the ABI is
    /// `uint256`).
    pub nonce: String,

    /// Pre-computed `safeTxHash` (coordinator's claim).
    /// `keccak256(0x1901 || domainSeparator || structHash)`,
    /// `0x`-prefixed 32-byte hex. The daemon recomputes from the
    /// ABI inputs above and refuses the request with
    /// [`error_codes::SAFE_TX_HASH_MISMATCH`] if it diverges.
    pub safe_tx_hash: String,

    /// Caller-supplied fee in wei (DL-P3.2-7: no oracle integration in
    /// v1; coordinator carries the gas price end-to-end). Decimal
    /// string. NOT part of the Safe digest — passed through for
    /// transport convenience; daemon ignores during signing.
    pub fee_wei: String,
}

/// Serde validator: refuse to deserialize an [`EvmSafeTxSignRequest`]
/// with a non-EVM `chain_id`. This is a defence-in-depth filter — the
/// handler also checks `custody_family()` at runtime, but rejecting at
/// the JSON boundary keeps the type itself an EVM-only carrier.
fn deserialize_evm_chain_id<'de, D>(deserializer: D) -> Result<ChainId, D::Error>
where
    D: Deserializer<'de>,
{
    let chain = ChainId::deserialize(deserializer)?;
    if chain.custody_family() != CustodyFamily::Evm {
        return Err(serde::de::Error::custom(format!(
            "{}: chain '{chain}' is not an EVM custody family chain",
            error_codes::NON_EVM_CHAIN
        )));
    }
    Ok(chain)
}

/// `POST /api/v1/sign/cosmos-tx`
///
/// (Phase 3.3): Cosmos-SDK `LegacyAminoPubKey` k-of-n multisig partial-
/// signature endpoint for the Cosmos custody family (GAIA / ATOM). The
/// daemon:
///   1. Routes to the per-chain config keyed by `chain_id`
///      (`endpoint_disabled` if no Cosmos role is configured).
///   2. Verifies `account_address` matches the daemon's configured
///      multisig account ([`error_codes::WRONG_COSMOS_ACCOUNT`]).
///   3. RE-COMPUTES the `SIGN_MODE_LEGACY_AMINO_JSON` `StdSignDoc`
///      sign-bytes hash from the semantic fields below (via the
///      `cosmos-tx` crate) and refuses if it does not match
///      `sign_doc_hash` ([`error_codes::SIGN_DOC_MISMATCH`]) — the
///      daemon never blind-signs a coordinator-supplied digest
///      (DL-M5-3).
///   4. Replay-keys on `(chain_id, account_address, sequence)` — the
///      `sequence` is the Cosmos monotonic-nonce analogue and is bound
///      into the sign-bytes.
///   5. Signs the recomputed 32-byte sign-bytes hash with its single
///      secp256k1 key, enforces low-S, and returns a 64-byte `r ‖ s`
///      signature + the member pubkey.
///
/// Amino-JSON (not `SIGN_MODE_DIRECT`) is mandatory for the multisig:
/// the amino `StdSignDoc` excludes the signer-set / bitarray, so each
/// member signs the identical sign-bytes independently (DL-P3.3-3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CosmosTxSignRequest {
    /// Cosmos `ChainId`. MUST satisfy
    /// `chain_id.custody_family() == CustodyFamily::Cosmos`; the serde
    /// validator rejects non-Cosmos ids at deserialize time with
    /// [`error_codes::NON_COSMOS_CHAIN`].
    #[serde(deserialize_with = "deserialize_cosmos_chain_id")]
    pub chain_id: ChainId,
    /// The `LegacyAminoPubKey` multisig account address (bech32, e.g.
    /// `cosmos1…`). This is the `MsgSend.from_address` AND the daemon's
    /// configured custody account — mismatch →
    /// [`error_codes::WRONG_COSMOS_ACCOUNT`].
    pub account_address: String,
    /// Cosmos consensus chain-id string bound in the sign-bytes (e.g.
    /// `"cosmoshub-4"`). Distinct from the `chain_id` enum, whose wire
    /// form is `THORChain`'s `"gaia"`.
    pub cosmos_chain_id: String,
    /// `account_number` of the multisig account (decimal `u64` string).
    /// Bound in the amino sign-bytes (fixed per account at first
    /// funding).
    pub account_number: String,
    /// `sequence` of the multisig account (decimal `u64` string). The
    /// monotonic replay coordinate — the daemon refuses to re-sign a
    /// different payload at the same `(chain, account, sequence)`.
    pub sequence: String,

    // ─── MsgSend (single send, single coin — THORChain Cosmos rail) ─────
    /// `MsgSend.to_address` — bech32 recipient (the `THORChain` Asgard
    /// inbound account for a redeem leg).
    pub to_address: String,
    /// Send amount in the native micro-unit (decimal string; `uatom`).
    pub amount: String,
    /// Send + fee denom (`"uatom"` for GAIA — the gas asset on the
    /// `THORChain` Cosmos rail).
    pub denom: String,

    // ─── Fee ────────────────────────────────────────────────────────────
    /// Fee amount in `denom` micro-units (decimal string).
    pub fee_amount: String,
    /// Gas limit (decimal `u64` string).
    pub gas_limit: String,

    /// `THORChain` memo carried in the tx `memo` field (≤250 bytes).
    pub memo: String,

    /// Pre-computed amino `StdSignDoc` sign-bytes hash (coordinator's
    /// claim): `SHA-256(canonical_amino_json)`, `0x`-prefixed 32-byte
    /// hex. The daemon recomputes from the semantic fields above and
    /// refuses with [`error_codes::SIGN_DOC_MISMATCH`] on divergence.
    pub sign_doc_hash: String,
}

/// Serde validator: refuse to deserialize a [`CosmosTxSignRequest`]
/// with a non-Cosmos `chain_id`. Defence-in-depth — the handler also
/// checks `custody_family()` at runtime, but rejecting at the JSON
/// boundary keeps the type a Cosmos-only carrier.
fn deserialize_cosmos_chain_id<'de, D>(deserializer: D) -> Result<ChainId, D::Error>
where
    D: Deserializer<'de>,
{
    let chain = ChainId::deserialize(deserializer)?;
    if chain.custody_family() != CustodyFamily::Cosmos {
        return Err(serde::de::Error::custom(format!(
            "{}: chain '{chain}' is not a Cosmos custody family chain",
            error_codes::NON_COSMOS_CHAIN
        )));
    }
    Ok(chain)
}

/// `POST /api/v1/sign/xrp-tx`
///
/// (Phase 4.4): XRP Ledger native `SignerList` k-of-n multisign partial-
/// signature endpoint for the XRP custody family (XRP / XRP.XRP). The
/// daemon:
///   1. Routes to the per-chain config keyed by `chain_id`
///      (`endpoint_disabled` if no XRP role is configured).
///   2. Verifies `account_address` matches the daemon's configured
///      multisig account ([`error_codes::WRONG_XRP_ACCOUNT`]).
///   3. RE-SERIALIZES the canonical `STObject` Payment body (with an
///      EMPTY `SigningPubKey`, no `TxnSignature`, no `Signers`) from the
///      semantic fields below (via the `xrp-tx` crate) and refuses if it
///      does not match `signing_blob`
///      ([`error_codes::XRP_TX_MISMATCH`]) — the daemon never blind-signs
///      a coordinator-supplied body (DL-M5-3).
///   4. Computes ITS OWN per-signer multi-signing blob locally:
///      `SHA512Half(0x534D5400 ‖ body ‖ my_account_id)`, where
///      `my_account_id` is derived from the daemon's configured member
///      pubkey — never transmitted.
///   5. Replay-keys on `(chain_id, account_address, sequence)` — the
///      `sequence` is the XRPL account-nonce and is bound into the body.
///   6. Signs the recomputed 32-byte blob with its single secp256k1 key,
///      enforces low-S, DER-encodes, verifies the signature against its
///      configured member pubkey, and returns the DER signature + pubkey.
///
/// Divergence from Cosmos (DL-P4.4-2): XRPL multisign has each member
/// sign a DIFFERENT message — the body is shared but the trailing
/// `my_account_id` suffix differs per signer. So the wire carries the
/// SHARED body (`signing_blob`), NOT a per-signer hash; each daemon
/// appends its own `AccountID`. `SigningPubKey` is empty in the signing
/// body and in the final assembled tx (the master key is disabled via
/// `SignerListSet` + `asfDisableMaster` during the key ceremony).
///
/// XRPL mainnet has no `NetworkID` in the signed body, so (unlike Cosmos
/// `cosmos_chain_id`) there is no consensus-chain-id field. A test
/// network with `NetworkID ≥ 1024` would need it pinned analogously.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct XrpTxSignRequest {
    /// XRP `ChainId`. MUST satisfy
    /// `chain_id.custody_family() == CustodyFamily::Xrp`; the serde
    /// validator rejects non-XRP ids at deserialize time with
    /// [`error_codes::NON_XRP_CHAIN`].
    #[serde(deserialize_with = "deserialize_xrp_chain_id")]
    pub chain_id: ChainId,
    /// The `SignerList` multisig account (classic r-address, e.g.
    /// `r…`). This is the `Payment.Account` AND the daemon's configured
    /// custody account — mismatch → [`error_codes::WRONG_XRP_ACCOUNT`].
    pub account_address: String,
    /// `Payment.Destination` — classic r-address recipient (the
    /// `THORChain` Asgard inbound account for a redeem leg).
    pub destination: String,
    /// `Payment.Amount` in drops (decimal `u64` string; 1 XRP = 10^6
    /// drops). No `tfPartialPayment` flag is ever set on a custody send.
    pub amount_drops: String,
    /// `Payment.Fee` in drops (decimal `u64` string). For a multi-signed
    /// tx this is `base_fee × (1 + signer_count)`.
    pub fee_drops: String,
    /// `Payment.Sequence` of the multisig account (decimal `u32` string).
    /// The monotonic replay coordinate — the daemon refuses to re-sign a
    /// different body at the same `(chain, account, sequence)`.
    pub sequence: String,
    /// `Payment.LastLedgerSequence` (decimal `u32` string) — the tx
    /// expiry. Bound into the body, so a retry at the same `sequence`
    /// with a different deadline yields a different body and is refused
    /// as a conflict (the executor must keep one deadline per sequence).
    pub last_ledger_sequence: String,
    /// `THORChain` memo (raw bytes as a UTF-8 string); the `xrp-tx`
    /// builder hex-encodes it into a single `Memos[0].MemoData` field.
    pub memo: String,
    /// The SHARED canonical `STObject` Payment body (empty
    /// `SigningPubKey`, no `TxnSignature`, no `Signers`) the coordinator
    /// claims — `0x`-prefixed hex. The daemon re-serializes from the
    /// semantic fields above and refuses with
    /// [`error_codes::XRP_TX_MISMATCH`] on divergence; it then derives
    /// its own per-signer signing blob by appending its configured
    /// `AccountID`. NOT a digest, and NOT per-signer.
    pub signing_blob: String,
}

/// Serde validator: refuse to deserialize an [`XrpTxSignRequest`] with a
/// non-XRP `chain_id`. Defence-in-depth — the handler also checks
/// `custody_family()` at runtime, but rejecting at the JSON boundary
/// keeps the type an XRP-only carrier.
fn deserialize_xrp_chain_id<'de, D>(deserializer: D) -> Result<ChainId, D::Error>
where
    D: Deserializer<'de>,
{
    let chain = ChainId::deserialize(deserializer)?;
    if chain.custody_family() != CustodyFamily::Xrp {
        return Err(serde::de::Error::custom(format!(
            "{}: chain '{chain}' is not an XRP custody family chain",
            error_codes::NON_XRP_CHAIN
        )));
    }
    Ok(chain)
}

/// Response for the three EIP-712 endpoints.
///
/// `signature` is 65-byte ECDSA `r ‖ s ‖ v` (v ∈ {27,28}) hex-encoded
/// for direct use as one element of the on-chain `attest*` `bytes[]`
/// argument; `signer_address` is the recovery address so the
/// coordinator can verify the signature without trusting the daemon
/// (recover from sig over the locally-recomputed digest, compare).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Eip712SignResponse {
    /// `0x`-prefixed 130-hex-char (65-byte) ECDSA signature.
    pub signature: String,
    /// `0x`-prefixed 20-byte Ethereum address of the signing key.
    pub signer_address: String,
}

/// Response for `psbt-input` signing.
///
/// `pubkey` is the 33-byte compressed signing pubkey (so the
/// coordinator can place the partial sig at the correct descriptor
/// position); `signature` is the Bitcoin-encoded ECDSA signature
/// (DER + 1-byte sighash flag) in hex.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PsbtSignResponse {
    /// `0x`-prefixed 33-byte compressed secp256k1 pubkey.
    pub pubkey: String,
    /// Hex DER+sighash signature (no `0x` prefix to mirror Bitcoin tooling).
    pub signature: String,
}

/// Response for `cosmos-tx` signing (Phase 3.3).
///
/// Cosmos secp256k1 signatures are 64-byte compact `r ‖ s` (low-S
/// normalized, **no recovery byte**) — distinct from the EVM 65-byte
/// `r ‖ s ‖ v` and the Bitcoin DER+sighash encodings. `pubkey` is the
/// 33-byte compressed signing pubkey so the coordinator can place this
/// member's partial signature at the correct `CompactBitArray` position
/// in the aggregated `MultiSignature`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CosmosSignResponse {
    /// `0x`-prefixed 33-byte compressed secp256k1 pubkey.
    pub pubkey: String,
    /// `0x`-prefixed 64-byte (128-hex) compact `r ‖ s` signature, low-S
    /// normalized.
    pub signature: String,
}

/// Response for `xrp-tx` signing (Phase 4.4).
///
/// XRPL secp256k1 signatures are **DER-encoded** (ASN.1
/// `SEQUENCE { INTEGER r, INTEGER s }`), low-S normalized — distinct
/// from the Cosmos 64-byte compact `r ‖ s`, the EVM 65-byte `r ‖ s ‖ v`,
/// and the Bitcoin DER+sighash encodings (XRPL `TxnSignature` carries no
/// sighash byte). `pubkey` is the 33-byte compressed signing pubkey so
/// the coordinator can derive this member's `AccountID`, place the
/// partial signature into the correct `Signer` entry, and sort the
/// `Signers` array by `AccountID` ascending.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct XrpSignResponse {
    /// `0x`-prefixed 33-byte compressed secp256k1 pubkey.
    pub pubkey: String,
    /// Hex DER-encoded ECDSA signature, low-S normalized (no `0x` prefix,
    /// mirrors the XRPL `TxnSignature` hex convention).
    pub signature: String,
}

/// Which of the three Squads V4 on-chain transactions a
/// [`SolanaTxSignRequest`] asks a member to sign. Unlike Cosmos / XRP
/// (all members sign ONE shared body), each Squads tx is a DIFFERENT
/// Solana message signed by ONE member; `tx_kind` selects the daemon's
/// per-kind validation branch (Phase 4.5 S6).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SolanaTxKind {
    /// `vault_transaction_create` (+ `proposal_create`) — defines where
    /// funds go; the daemon validates the inner System transfer.
    Create,
    /// `proposal_approve` — one member's approval vote.
    Approve,
    /// `vault_transaction_execute` — runs the approved transfer.
    Execute,
}

/// `POST /api/v1/sign/solana-tx` (Phase 4.5)
///
/// Squads V4 ed25519 single-member partial signing — the first ed25519
/// custody family. The wire carries the full serialized legacy message
/// (`message_hex`) PLUS the semantic fields the daemon needs to
/// **re-derive and re-validate** that message before signing: the daemon
/// NEVER blind-signs `message_hex`. The per-kind validation (S6) is the
/// security core — a compromised coordinator must not be able to collect
/// `threshold` signatures over any transfer that does not pay the correct
/// user from our vault.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolanaTxSignRequest {
    /// Solana `ChainId`. MUST satisfy
    /// `chain_id.custody_family() == CustodyFamily::Solana`; the serde
    /// validator rejects non-Solana ids with [`error_codes::NON_SOLANA_CHAIN`].
    #[serde(deserialize_with = "deserialize_solana_chain_id")]
    pub chain_id: ChainId,
    /// Which Squads tx shape this is — selects the daemon validation branch.
    pub tx_kind: SolanaTxKind,
    /// The Squads multisig PDA (base58). Must equal the daemon's configured
    /// custody multisig — mismatch → [`error_codes::WRONG_SOLANA_MULTISIG`].
    pub multisig_pda: String,
    /// The expected single ed25519 signer (base58). The daemon refuses if
    /// it is not its configured member key
    /// ([`error_codes::WRONG_SOLANA_MEMBER`]).
    pub member_pubkey: String,
    /// The Squads `transaction_index` (decimal `u64` string) — the replay
    /// coordinate: the daemon refuses a DIFFERENT message at the same
    /// `(chain, multisig, transaction_index, tx_kind, member)`.
    pub transaction_index: String,
    /// The recent blockhash bound into the message (base58).
    pub recent_blockhash: String,
    /// `Create` only: the vault index whose PDA the inner transfer spends
    /// from (the daemon re-derives the vault PDA and checks the source).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_index: Option<u8>,
    /// `Create` only: the inner System-transfer destination (the user's
    /// own Solana address, base58).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inner_destination: Option<String>,
    /// `Create` only: the inner transfer lamports (decimal `u64` string).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inner_amount_lamports: Option<String>,
    /// `Create` only: the SPL-Memo string carried by the inner message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    /// The full serialized legacy message (`0x`-prefixed hex) the
    /// coordinator claims. The daemon RE-BUILDS the message from the
    /// semantic fields and refuses with [`error_codes::SOLANA_TX_MISMATCH`]
    /// on divergence — it signs the bytes IT rebuilt.
    pub message_hex: String,
}

/// Serde validator: refuse a [`SolanaTxSignRequest`] with a non-Solana
/// `chain_id`. Defence-in-depth above the runtime `custody_family` check.
fn deserialize_solana_chain_id<'de, D>(deserializer: D) -> Result<ChainId, D::Error>
where
    D: Deserializer<'de>,
{
    let chain = ChainId::deserialize(deserializer)?;
    if chain.custody_family() != CustodyFamily::Solana {
        return Err(serde::de::Error::custom(format!(
            "{}: chain '{chain}' is not a Solana custody family chain",
            error_codes::NON_SOLANA_CHAIN
        )));
    }
    Ok(chain)
}

/// Response for `solana-tx` signing.
///
/// `pubkey` is the 32-byte ed25519 member pubkey (base58); the coordinator
/// pins it and checks it matches the cosigner it asked. `signature` is the
/// 64-byte ed25519 signature (`0x`-prefixed hex) over the serialized
/// message — the coordinator verifies it before assembling the transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolanaSignResponse {
    /// Base58 32-byte ed25519 member pubkey.
    pub pubkey: String,
    /// `0x`-prefixed 64-byte ed25519 signature.
    pub signature: String,
}

/// Which TRON asset a [`TronTxSignRequest`] moves — selects the contract
/// the daemon rebuilds + validates (Phase 4.6).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TronAssetKind {
    /// Native TRX — a `TransferContract` (`raw_data.contract[0]`).
    Trx,
    /// TRC20 USDT — a `TriggerSmartContract` calling
    /// `transfer(address,uint256)` on the token contract.
    Usdt,
}

/// `POST /api/v1/sign/tron-tx` (Phase 4.6)
///
/// TRON native account-permission k-of-n multisig partial-signature
/// endpoint. Unlike XRP (each member signs a per-signer blob), EVERY TRON
/// member signs the IDENTICAL `txID = sha256(raw_data)`; the daemon:
///   1. Routes to the per-chain config keyed by `chain_id`
///      (`endpoint_disabled` if no TRON role is configured).
///   2. Verifies `owner_address` matches the daemon's configured multisig
///      account ([`error_codes::WRONG_TRON_ACCOUNT`]).
///   3. RE-BUILDS the `raw_data` protobuf from the semantic fields below
///      (via the `tron-tx` crate) and recomputes `txID = sha256(raw_data)`;
///      refuses with [`error_codes::TRON_TX_MISMATCH`] if it does not match
///      `txid` — the daemon never blind-signs a coordinator-supplied hash
///      (DL-M5-3). The destination, amount, memo, and `permission_id` are
///      all bound into the `txID`, so the byte-match is the binding (same
///      posture as the Cosmos / XRP THORChain-routed legs).
///   4. Replay-keys on `(chain_id, owner_address, txid)` — idempotent
///      retry returns the cached signature; the `txID` is the full payload
///      identity (TRON has no nonce, so distinct redemptions yield distinct
///      `txID`s and never collide).
///   5. Signs the recomputed 32-byte `txID` with its single secp256k1 key,
///      produces a 65-byte recoverable `r ‖ s ‖ v` (v = recid 0/1), and
///      VERIFIES it recovers to its configured member address before
///      recording.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TronTxSignRequest {
    /// TRON `ChainId`. MUST satisfy
    /// `chain_id.custody_family() == CustodyFamily::Tron`; the serde
    /// validator rejects non-TRON ids with [`error_codes::NON_TRON_CHAIN`].
    #[serde(deserialize_with = "deserialize_tron_chain_id")]
    pub chain_id: ChainId,
    /// Which asset this leg sends (selects `TransferContract` vs
    /// `TriggerSmartContract`).
    pub asset: TronAssetKind,
    /// The multisig account that owns the funds (base58 `T…` address).
    /// This is `contract[0].owner_address` AND the daemon's configured
    /// custody account — mismatch → [`error_codes::WRONG_TRON_ACCOUNT`].
    pub owner_address: String,
    /// The `THORChain` Asgard inbound (base58 `T…` address) the leg sends
    /// to — for `Trx` the `TransferContract.to_address`; for `Usdt` the
    /// TRC20 `transfer` recipient encoded in the call data. `THORChain` then
    /// swaps to USDT and delivers to the `IndexToken` on Ethereum per the
    /// `memo` (same routing as the Cosmos / XRP legs).
    pub to_address: String,
    /// Send amount in the asset's smallest unit (decimal string): `sun`
    /// for TRX (1 TRX = 10^6 sun), or 6-decimal base units for USDT.
    pub amount: String,
    /// `Usdt` only: the TRC20 contract address (base58 `T…`). Ignored for
    /// `Trx`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<String>,
    /// The active `Permission.id` the multisig signs under (the witness
    /// permission is id 1; active permissions start at 2). Bound INSIDE
    /// `raw_data`, so it is part of the `txID` — all members must agree.
    pub permission_id: u32,
    /// `raw_data.ref_block_bytes` (`0x`-prefixed 2-byte hex) — the low 2
    /// bytes of the TAPOS reference block height.
    pub ref_block_bytes: String,
    /// `raw_data.ref_block_hash` (`0x`-prefixed 8-byte hex) — bytes [8:16]
    /// of the TAPOS reference block id.
    pub ref_block_hash: String,
    /// `raw_data.expiration` in unix milliseconds (decimal `u64` string).
    pub expiration: String,
    /// `raw_data.timestamp` in unix milliseconds (decimal `u64` string).
    pub timestamp: String,
    /// `raw_data.fee_limit` in `sun` (decimal `u64` string). `Usdt` only —
    /// caps the energy spend for the contract call; `0`/ignored for `Trx`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_limit: Option<String>,
    /// `THORChain` memo carried in `raw_data.data` (raw bytes as a UTF-8
    /// string). Empty omits the field.
    pub memo: String,
    /// The `txID = sha256(raw_data)` the coordinator claims, `0x`-prefixed
    /// 32-byte hex. The daemon rebuilds `raw_data` from the semantic fields
    /// above and refuses with [`error_codes::TRON_TX_MISMATCH`] on
    /// divergence; it signs the bytes IT rebuilt.
    pub txid: String,
}

/// Serde validator: refuse a [`TronTxSignRequest`] with a non-TRON
/// `chain_id`. Defence-in-depth above the runtime `custody_family` check.
fn deserialize_tron_chain_id<'de, D>(deserializer: D) -> Result<ChainId, D::Error>
where
    D: Deserializer<'de>,
{
    let chain = ChainId::deserialize(deserializer)?;
    if chain.custody_family() != CustodyFamily::Tron {
        return Err(serde::de::Error::custom(format!(
            "{}: chain '{chain}' is not a TRON custody family chain",
            error_codes::NON_TRON_CHAIN
        )));
    }
    Ok(chain)
}

/// Response for `tron-tx` signing (Phase 4.6).
///
/// TRON signatures are 65-byte recoverable secp256k1 (`r ‖ s ‖ v`, v =
/// raw recovery id 0/1, go-ethereum style) over the 32-byte `txID` — the
/// same primitive the EVM path produces, but appended to
/// `Transaction.signature[]` rather than recovered on-chain. `pubkey` is
/// the 33-byte compressed member pubkey so the coordinator can confirm the
/// signer and sum its `Permission` weight.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TronSignResponse {
    /// `0x`-prefixed 33-byte compressed secp256k1 pubkey.
    pub pubkey: String,
    /// `0x`-prefixed 65-byte recoverable signature (`r ‖ s ‖ v`, v ∈ {0,1}).
    pub signature: String,
}

/// CTD-1 (`DL-CTD-2`): k-of-n Redemption Intent Certificate proof,
/// attached to custody-spend signing requests (PSBT / EVM-Safe /
/// Cosmos / XRP / TRON; Solana stays hard-gated out per RA-2).
///
/// Carries the PLAINTEXT fields of one `RedemptionIntentCertificate`
/// ([`crate::eip712`], the 5th typed-data on the
/// `attestation_oracle_domain`) plus the Set-B signatures over its
/// EIP-712 digest. The RPC-free daemon recomputes the digest from
/// these fields itself — it never trusts a coordinator-supplied
/// digest — recovers each signature, requires ≥ quorum DISTINCT
/// signers from its STATIC whitelist, then binds the spend's
/// destination/amount/memo to the certified values. A compromised
/// coordinator cannot forge k-of-n Set-B signatures, so it can no
/// longer steer a custody spend to a destination the operators'
/// observers did not independently resolve.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntentProof {
    /// `bytes32` redemption id, `0x`-prefixed hex.
    pub redemption_id: String,
    /// `uint256` leg index, decimal string. Must additionally fit
    /// `u32` (the daemon's replay-key width); on-chain leg indices
    /// are bounded by basket size.
    pub leg_index: String,
    /// `bytes32` canonical asset id of THIS leg (e.g.
    /// `keccak256("BTC.BTC")`), `0x`-prefixed hex.
    pub asset_id: String,
    /// `uint256` certified spend amount in the leg's native smallest
    /// units (e.g. sats for BTC), decimal string.
    pub amount: String,
    /// Decimals pinning the unit of `amount` to the chain registry's
    /// native decimals (RA-4) — bound like-for-like at the handler,
    /// never rescaled.
    pub amount_decimals: u8,
    /// `bytes32` keccak of the immediate spend target the multisig
    /// pays (the `THORChain` Asgard inbound: BTC `scriptPubKey`
    /// bytes, EVM router address bytes, …), `0x`-prefixed hex.
    pub immediate_target_hash: String,
    /// `bytes32` keccak of the exact `THORChain` memo bytes, hex.
    pub memo_hash: String,
    /// `bytes32` keccak of the user's final native-chain payout
    /// destination, hex.
    pub final_destination_hash: String,
    /// Unix seconds when the observers resolved the Asgard inbound.
    /// The daemon enforces `now - vault_resolved_at <= ric_max_age`
    /// so a certificate cannot be replayed onto a rotated vault
    /// (RA-5 recency, replacing the unsourceable vault epoch).
    pub vault_resolved_at: u64,
    /// The k-of-n Set-B signatures over the RIC EIP-712 digest, each
    /// a `0x`-prefixed 65-byte recoverable signature (`r ‖ s ‖ v`).
    pub signatures: Vec<String>,
}

/// `GET /api/v1/keys`
///
/// Daemon identity — coordinator pins this and checks every response
/// signer matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeysResponse {
    /// `0x`-prefixed Ethereum address (EIP-712 role). `None` if this
    /// daemon is configured for PSBT-only signing.
    pub eth_address: Option<String>,
    /// `0x`-prefixed compressed pubkey (PSBT role). `None` if this
    /// daemon is configured for EIP-712-only signing.
    pub btc_pubkey: Option<String>,
}

/// `GET /api/v1/health` — daemon liveness + HSM connectivity probe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    /// `true` only if every configured key role's HSM responded to a
    /// no-op probe within the timeout. The daemon refuses to sign if
    /// this is `false`.
    pub ok: bool,
    /// Daemon-reported reason when `ok == false` (e.g.
    /// `"hsm_unreachable"`). Empty when `ok`.
    pub reason: String,
}

/// Stable error-code strings the daemon returns in non-2xx bodies, so
/// the coordinator can branch on the code rather than parse messages.
/// Codes are versioned by being string constants here — adding one is
/// backwards-compatible, renaming one is not.
pub mod error_codes {
    /// The replay DB recorded a different payload for the same identity
    /// tuple. Coordinator MUST NOT retry under the same id — investigate.
    /// HTTP 409.
    pub const CONFLICT_ALREADY_SIGNED_DIFFERENT: &str = "conflict_already_signed_different";
    /// The replay DB recorded a delivery for this redemption; a refund
    /// can no longer be signed (and vice versa). HTTP 409.
    pub const CONFLICT_DELIVERY_REFUND_MUTEX: &str = "conflict_delivery_refund_mutex";
    /// HSM (`Web3Signer` / `YubiHSM2`) refused the request or is unreachable.
    /// HTTP 503.
    pub const HSM_UNAVAILABLE: &str = "hsm_unavailable";
    /// The submitted PSBT did not decode or the input index is out of
    /// range. HTTP 400.
    pub const INVALID_PSBT: &str = "invalid_psbt";
    /// The PSBT input's witness script does not match this daemon's
    /// configured multisig descriptor. HTTP 422.
    pub const WRONG_DESCRIPTOR: &str = "wrong_descriptor";
    /// The PSBT's `vin[0]` is not a multisig UTXO — refusing to sign
    /// because `THORChain` would not resolve a refund back to our
    /// multisig (Part-3 invariant). HTTP 422.
    pub const VIN0_NOT_MULTISIG: &str = "vin0_not_multisig";
    /// A request field is malformed (bad hex, wrong length, etc.). HTTP 400.
    pub const BAD_REQUEST: &str = "bad_request";
    /// The endpoint is not configured for this daemon's role (e.g.
    /// PSBT request to an EIP-712-only daemon). HTTP 404.
    pub const ENDPOINT_DISABLED: &str = "endpoint_disabled";
    /// V2 (Phase 3.2): the request's `safe_address` did not parse as a
    /// 20-byte EIP-55 checksum hex string, or the recomputed
    /// `safeTxHash` did not match the caller-supplied value. HTTP 422.
    pub const WRONG_SAFE_ADDRESS: &str = "wrong_safe_address";
    /// V2 (Phase 3.2): the request's `nonce` did not parse as a
    /// `uint256` decimal string or is outside the practical `u64`
    /// range. HTTP 400.
    pub const NONCE_OUT_OF_RANGE: &str = "nonce_out_of_range";
    /// V2 (Phase 3.2): the request's `chain_id` belongs to the UTXO
    /// custody family — the EVM Safe-tx endpoint only accepts EVM
    /// chains. HTTP 422.
    pub const NON_EVM_CHAIN: &str = "non_evm_chain";
    /// V5 (Phase 3.2): the daemon recomputed `safeTxHash` from the
    /// request's Safe ABI inputs (`to` / `value` / `data` / `operation`
    /// / `safe_tx_gas` / `base_gas` / `gas_price` / `gas_token` /
    /// `refund_receiver` / `nonce`) and the result did not match the
    /// caller-supplied `safe_tx_hash`. Indicates the coordinator
    /// constructed the hash from different inputs than it claims.
    /// HTTP 422.
    pub const SAFE_TX_HASH_MISMATCH: &str = "safe_tx_hash_mismatch";
    /// Phase-1 hardening (H11): the signature the HSM returned does not
    /// recover to this daemon's configured `my_signer_address` over the
    /// recomputed `safeTxHash`. Indicates an HSM key-mapping bug, a
    /// wrong-key signature, or a corrupted/forged signing response — the
    /// daemon refuses to record or return it. HTTP 500.
    pub const SIGNER_RECOVER_MISMATCH: &str = "signer_recover_mismatch";
    /// Phase 3.3: the request's `chain_id` is not a Cosmos custody-family
    /// chain — the `cosmos-tx` endpoint only accepts Cosmos chains. HTTP 422.
    pub const NON_COSMOS_CHAIN: &str = "non_cosmos_chain";
    /// Phase 3.3: the request's `account_address` did not match this
    /// daemon's configured Cosmos multisig account. HTTP 422.
    pub const WRONG_COSMOS_ACCOUNT: &str = "wrong_cosmos_account";
    /// Phase 3.3: the request's `cosmos_chain_id` did not match the
    /// consensus chain-id pinned in this daemon's config. Blocks replay of
    /// a custody-move signature onto another Cosmos chain. HTTP 422.
    pub const WRONG_COSMOS_CHAIN_ID: &str = "wrong_cosmos_chain_id";
    /// Phase 3.3: the daemon recomputed the amino `StdSignDoc` sign-bytes
    /// hash from the request's semantic fields (`cosmos_chain_id` /
    /// `account_number` / `sequence` / `to_address` / `amount` / `denom`
    /// / `fee_amount` / `gas_limit` / `memo`) and the result did not
    /// match the caller-supplied `sign_doc_hash`. HTTP 422.
    pub const SIGN_DOC_MISMATCH: &str = "sign_doc_mismatch";
    /// Phase 4.4: the request's `chain_id` is not an XRP custody-family
    /// chain — the `xrp-tx` endpoint only accepts XRP chains. HTTP 422.
    pub const NON_XRP_CHAIN: &str = "non_xrp_chain";
    /// Phase 4.4: the request's `account_address` did not match this
    /// daemon's configured XRP `SignerList` multisig account. HTTP 422.
    pub const WRONG_XRP_ACCOUNT: &str = "wrong_xrp_account";
    /// Phase 4.4: the daemon re-serialized the canonical `STObject`
    /// Payment body (empty `SigningPubKey`) from the request's semantic
    /// fields (`destination` / `amount_drops` / `fee_drops` / `sequence`
    /// / `last_ledger_sequence` / `memo`) and the result did not match
    /// the caller-supplied `signing_blob`. HTTP 422.
    pub const XRP_TX_MISMATCH: &str = "xrp_tx_mismatch";
    /// Phase 4.5: the request's `chain_id` is not a Solana custody-family
    /// chain — the `solana-tx` endpoint only accepts Solana chains. HTTP 422.
    pub const NON_SOLANA_CHAIN: &str = "non_solana_chain";
    /// Phase 4.5: the request's `multisig_pda` did not match this daemon's
    /// configured Squads multisig. HTTP 422.
    pub const WRONG_SOLANA_MULTISIG: &str = "wrong_solana_multisig";
    /// Phase 4.5: the request's `member_pubkey` is not this daemon's
    /// configured ed25519 member key. HTTP 422.
    pub const WRONG_SOLANA_MEMBER: &str = "wrong_solana_member";
    /// Phase 4.5: the daemon rebuilt the Solana message from the request's
    /// semantic fields and the result did not byte-match `message_hex`.
    /// HTTP 422.
    pub const SOLANA_TX_MISMATCH: &str = "solana_tx_mismatch";
    /// Phase 4.5: the inner System transfer's source is not the daemon's
    /// re-derived vault PDA — refusing to sign a spend from any other
    /// account. HTTP 422.
    pub const SOLANA_NOT_OUR_VAULT: &str = "solana_not_our_vault";
    /// Phase 4.5: the inner transfer destination / amount is not the
    /// permitted redemption value, or the destination is the vault /
    /// a member / the program itself. HTTP 422.
    pub const SOLANA_DEST_NOT_PERMITTED: &str = "solana_dest_not_permitted";
    /// Phase 4.5: the message invokes a program outside the allowlist
    /// (Squads / System / SPL-Memo), or carries an unexpected instruction.
    /// HTTP 422.
    pub const SOLANA_FOREIGN_INSTRUCTION: &str = "solana_foreign_instruction";
    /// Phase 4.6: the request's `chain_id` is not a TRON custody-family
    /// chain — the `tron-tx` endpoint only accepts TRON chains. HTTP 422.
    pub const NON_TRON_CHAIN: &str = "non_tron_chain";
    /// Phase 4.6: the request's `owner_address` did not match this daemon's
    /// configured TRON multisig account. HTTP 422.
    pub const WRONG_TRON_ACCOUNT: &str = "wrong_tron_account";
    /// Phase 4.6: the daemon rebuilt the `raw_data` protobuf from the
    /// request's semantic fields and the recomputed `txID = sha256(raw_data)`
    /// did not match the caller-supplied `txid`. HTTP 422.
    pub const TRON_TX_MISMATCH: &str = "tron_tx_mismatch";
    /// Audit M2: a `PsbtInputSignRequest` carried `expected_*` output
    /// constraints (destination `scriptPubKey` / amount / `OP_RETURN`
    /// memo) and the PSBT's outputs did not satisfy them — the daemon
    /// refuses to sign a spend whose payout does not match the leg's
    /// intent. HTTP 422.
    pub const PSBT_OUTPUTS_MISMATCH: &str = "psbt_outputs_mismatch";
    /// Audit M2b (partial floor): the PSBT carried an output that is
    /// neither the pinned payout, the (zero-value) `OP_RETURN` memo, nor
    /// change back to the daemon's own multisig descriptor. Change can
    /// only return to self, so a malicious coordinator cannot redirect
    /// the residue to an attacker address. HTTP 422.
    pub const PSBT_UNEXPECTED_OUTPUT: &str = "psbt_unexpected_output";
    /// Audit M2b (partial floor): the implied miner fee
    /// (`Σ inputs − Σ outputs`) exceeds the per-chain
    /// `ChainId::max_redeem_fee_sats` ceiling, or an input was missing a
    /// `witness_utxo` so the fee could not be bounded. Stops a malicious
    /// coordinator from burning the residue as an unbounded fee. HTTP 422.
    pub const PSBT_FEE_EXCEEDS_CAP: &str = "psbt_fee_exceeds_cap";
    /// EVM-Safe CTD-1 family floor: the Safe-tx `operation` was
    /// `DelegateCall` (1). An honest redemption always uses `Call` (0); a
    /// `DelegateCall` would execute arbitrary code in the Safe's own
    /// context (owner takeover / asset sweep), so the daemon refuses to
    /// sign it regardless of the recomputed `safeTxHash`. HTTP 422.
    pub const EVM_SAFE_OPERATION_FORBIDDEN: &str = "evm_safe_operation_forbidden";
    /// EVM-Safe CTD-1 family floor: a Safe-tx gas-refund field
    /// (`gas_price` / `gas_token` / `refund_receiver`) was non-zero. Phase
    /// 3.2 has no Safe-side refund — the honest executor zeroes all three
    /// — so a non-zero value is a coordinator-supplied value-extraction
    /// channel (the Safe pays `gasPrice·gasUsed` of `gasToken` to
    /// `refundReceiver`). The daemon refuses to sign it. HTTP 422.
    pub const EVM_SAFE_GAS_REFUND_FORBIDDEN: &str = "evm_safe_gas_refund_forbidden";
    /// CTD-1 (`DL-CTD-2`): the custody-spend request did not carry an
    /// [`super::IntentProof`]. Every `THORChain`-family spend endpoint
    /// (PSBT / EVM-Safe / Cosmos / XRP / TRON) REQUIRES a k-of-n
    /// Redemption Intent Certificate once the RIC gate is wired —
    /// there is no proof-less carve-out. HTTP 422.
    pub const INTENT_PROOF_REQUIRED: &str = "intent_proof_required";
    /// CTD-1: the attached `IntentProof` failed stateless verification
    /// — an unparseable field, a malformed signature, a signer outside
    /// the daemon's static Set-B whitelist, a duplicate signer, or
    /// fewer than `intent_quorum` distinct valid signers over the
    /// recomputed RIC digest. The daemon rejects the WHOLE proof on
    /// any invalid element (strict — an honest relay never attaches
    /// garbage). HTTP 422.
    pub const INTENT_PROOF_INVALID: &str = "intent_proof_invalid";
    /// CTD-1: the request's spend fields (destination / amount / memo
    /// / redemption id / leg index) did not `==`-match the RIC's
    /// certified values — the coordinator asked the daemon to sign a
    /// spend the operators did not certify. HTTP 422.
    pub const INTENT_MISMATCH: &str = "intent_mismatch";
    /// CTD-1: the RIC's `vault_resolved_at` is outside the daemon's
    /// `ric_max_age` window (or future-dated beyond clock-skew
    /// tolerance) — the certified Asgard inbound may belong to a
    /// rotated vault; observers must re-resolve and re-certify.
    /// HTTP 422.
    pub const INTENT_VAULT_STALE: &str = "intent_vault_stale";
    /// CTD-1: a custody spend for this `(chain, redemption_id,
    /// leg_index)` was already authorized under a DIFFERENT RIC digest
    /// — the one-shot rule (one valid RIC ≠ N payouts, RA-1).
    /// Identical retries are answered idempotently; only a re-drive
    /// conflicts. HTTP 409.
    pub const INTENT_ALREADY_SIGNED: &str = "intent_already_signed";
}

/// HTTP error body. The daemon returns this on any non-2xx response;
/// coordinator branches on `code`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorBody {
    /// One of the constants in [`error_codes`].
    pub code: String,
    /// Human-readable detail. May be logged; not parsed by the
    /// coordinator.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    /// Round-tripping every request/response struct through JSON is the
    /// schema contract — a change that breaks this test is a wire
    /// break.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn attestation_request_json_round_trip() {
        let req = AttestationSignRequest {
            intent_id: "0xaa".to_string(),
            slot_index: "0".to_string(),
            attested_amount: "1000000".to_string(),
        };
        let s = serde_json::to_string(&req).expect("serialize");
        let back: AttestationSignRequest = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn redemption_delivery_request_json_round_trip() {
        let req = RedemptionDeliverySignRequest {
            redemption_id: "0xbb".to_string(),
            leg_index: "0".to_string(),
            asset_id: "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                .to_string(),
            delivered_amount: "70000000".to_string(),
        };
        let s = serde_json::to_string(&req).expect("serialize");
        let back: RedemptionDeliverySignRequest = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn refund_request_json_round_trip() {
        let req = RefundSignRequest {
            redemption_id: "0xcc".to_string(),
            leg_index: "0".to_string(),
            asset_id: "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                .to_string(),
            refunded_amount: "99990000".to_string(),
        };
        let s = serde_json::to_string(&req).expect("serialize");
        let back: RefundSignRequest = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn psbt_input_request_json_round_trip() {
        let req = PsbtInputSignRequest {
            chain_id: ChainId::Btc,
            psbt_base64: "cHNidP8BAA==".to_string(),
            input_index: 0,
            expected_destination_spk: Some("0014abcd".to_string()),
            expected_amount_sats: Some(100_000),
            expected_memo: Some("3d3a4554482e55534454".to_string()),
        };
        let s = serde_json::to_string(&req).expect("serialize");
        let back: PsbtInputSignRequest = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, req);
        // chain_id serialised as lowercase string per the ChainId
        // serde-rename convention.
        assert!(s.contains("\"chain_id\":\"btc\""));
    }

    /// U8: `PsbtInputSignRequest` accepts non-BTC chain ids (LTC, BCH,
    /// DOGE, ZEC) on the wire. Per-chain routing happens at the
    /// daemon's request handler.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn psbt_input_request_accepts_every_utxo_chain() {
        for chain in [
            ChainId::Btc,
            ChainId::Ltc,
            ChainId::Bch,
            ChainId::Doge,
            ChainId::Zec,
        ] {
            let req = PsbtInputSignRequest {
                chain_id: chain,
                psbt_base64: "cHNidP8BAA==".to_string(),
                input_index: 0,
                expected_destination_spk: None,
                expected_amount_sats: None,
                expected_memo: None,
            };
            let s = serde_json::to_string(&req).expect("serialize");
            let back: PsbtInputSignRequest = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back, req);
            // Omitted optional veto fields must not appear on the wire.
            assert!(!s.contains("expected_destination_spk"));
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn eip712_response_json_round_trip() {
        let r = Eip712SignResponse {
            signature: format!("0x{}", "ab".repeat(65)),
            signer_address: "0x0000000000000000000000000000000000000001".to_string(),
        };
        let s = serde_json::to_string(&r).expect("serialize");
        let back: Eip712SignResponse = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, r);
    }

    /// V2: `EvmSafeTxSignRequest` round-trips JSON for every EVM
    /// `ChainId` (eth / bsc / avax / base / pol) without losing fields.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn evm_safe_tx_request_round_trip_all_evm_chains() {
        for chain in [
            ChainId::Eth,
            ChainId::Bsc,
            ChainId::Avax,
            ChainId::Base,
            ChainId::Pol,
        ] {
            let req = EvmSafeTxSignRequest {
                chain_id: chain,
                safe_address: "0x1234567890aBcDef1234567890AbCdEf12345678".to_string(),
                to: "0xaabbccddeeff00112233445566778899aabbccdd".to_string(),
                value: "0".to_string(),
                data: "0xdeadbeef".to_string(),
                operation: 0,
                safe_tx_gas: "0".to_string(),
                base_gas: "0".to_string(),
                gas_price: "0".to_string(),
                gas_token: format!("0x{}", "00".repeat(20)),
                refund_receiver: format!("0x{}", "00".repeat(20)),
                nonce: "7".to_string(),
                safe_tx_hash: format!("0x{}", "ab".repeat(32)),
                fee_wei: "1000000000".to_string(),
            };
            let s = serde_json::to_string(&req).expect("serialize");
            let back: EvmSafeTxSignRequest = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back, req);
        }
    }

    /// V2: the serde validator rejects every UTXO `ChainId` on the
    /// `evm-safe-tx` request — defence-in-depth above the runtime
    /// `custody_family` check in the daemon handler.
    #[test]
    fn evm_safe_tx_request_rejects_utxo_chains() {
        for chain in ["btc", "ltc", "bch", "doge", "zec"] {
            let zero_addr = format!("0x{}", "00".repeat(20));
            let json = format!(
                r#"{{"chain_id":"{chain}","safe_address":"{a}","to":"{a}","value":"0","data":"0x","operation":0,"safe_tx_gas":"0","base_gas":"0","gas_price":"0","gas_token":"{a}","refund_receiver":"{a}","nonce":"0","safe_tx_hash":"0x{hash}","fee_wei":"0"}}"#,
                a = zero_addr,
                hash = "00".repeat(32),
            );
            let result: Result<EvmSafeTxSignRequest, _> = serde_json::from_str(&json);
            let err_msg = match result {
                Ok(req) => format!("expected NON_EVM_CHAIN rejection, got: {req:?}"),
                Err(e) => format!("{e}"),
            };
            assert!(
                err_msg.contains(error_codes::NON_EVM_CHAIN),
                "must surface the NON_EVM_CHAIN code; chain='{chain}', got: {err_msg}"
            );
        }
    }

    /// V2: unknown chain string is rejected with the generic
    /// `ChainId` parse error (not the `NON_EVM_CHAIN` code) — sanity
    /// check that the validator order is `parse → custody-family-check`.
    #[test]
    fn evm_safe_tx_request_rejects_unknown_chain() {
        let json = r#"{"chain_id":"ada","safe_address":"0x0","to":"0x0","value":"0","data":"0x","operation":0,"safe_tx_gas":"0","base_gas":"0","gas_price":"0","gas_token":"0x0","refund_receiver":"0x0","nonce":"0","safe_tx_hash":"0x0","fee_wei":"0"}"#;
        let result: Result<EvmSafeTxSignRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn error_body_json_round_trip() {
        let e = ErrorBody {
            code: error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT.to_string(),
            message: "intent already signed with a different amount".to_string(),
        };
        let s = serde_json::to_string(&e).expect("serialize");
        let back: ErrorBody = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, e);
    }

    /// C2: `CosmosTxSignRequest` round-trips JSON for every Cosmos
    /// `ChainId` (gaia today) without losing fields.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn cosmos_tx_request_round_trip_all_cosmos_chains() {
        // Single-chain family today (NOBLE follow-on adds a second row).
        let req = CosmosTxSignRequest {
            chain_id: ChainId::Gaia,
            account_address: "cosmos1vault0account0address0000000000000000".to_string(),
            cosmos_chain_id: "cosmoshub-4".to_string(),
            account_number: "12345".to_string(),
            sequence: "7".to_string(),
            to_address: "cosmos1asgard0inbound0account00000000000000000".to_string(),
            amount: "1000000".to_string(),
            denom: "uatom".to_string(),
            fee_amount: "5000".to_string(),
            gas_limit: "200000".to_string(),
            memo: "=:ETH.USDT:0xabc:0/1/0".to_string(),
            sign_doc_hash: format!("0x{}", "ab".repeat(32)),
        };
        let s = serde_json::to_string(&req).expect("serialize");
        let back: CosmosTxSignRequest = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, req);
        assert!(s.contains("\"chain_id\":\"gaia\""));
    }

    /// C2: the serde validator rejects non-Cosmos `ChainId`s (UTXO + EVM)
    /// on the `cosmos-tx` request — defence-in-depth above the runtime
    /// `custody_family` check in the daemon handler.
    #[test]
    fn cosmos_tx_request_rejects_non_cosmos_chains() {
        for chain in [
            "btc", "ltc", "bch", "doge", "zec", "eth", "bsc", "avax", "base", "pol", "xrp", "sol",
            "tron",
        ] {
            let json = format!(
                r#"{{"chain_id":"{chain}","account_address":"cosmos1x","cosmos_chain_id":"cosmoshub-4","account_number":"0","sequence":"0","to_address":"cosmos1y","amount":"1","denom":"uatom","fee_amount":"0","gas_limit":"200000","memo":"","sign_doc_hash":"0x{hash}"}}"#,
                hash = "00".repeat(32),
            );
            let result: Result<CosmosTxSignRequest, _> = serde_json::from_str(&json);
            let err_msg = match result {
                Ok(req) => format!("expected NON_COSMOS_CHAIN rejection, got: {req:?}"),
                Err(e) => format!("{e}"),
            };
            assert!(
                err_msg.contains(error_codes::NON_COSMOS_CHAIN),
                "must surface the NON_COSMOS_CHAIN code; chain='{chain}', got: {err_msg}"
            );
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn cosmos_sign_response_json_round_trip() {
        let r = CosmosSignResponse {
            pubkey: format!("0x{}", "02".repeat(33)),
            signature: format!("0x{}", "cd".repeat(64)),
        };
        let s = serde_json::to_string(&r).expect("serialize");
        let back: CosmosSignResponse = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, r);
    }

    /// C2: `XrpTxSignRequest` round-trips JSON for every XRP `ChainId`
    /// (xrp today) without losing fields.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn xrp_tx_request_round_trip_all_xrp_chains() {
        // Single-chain family today.
        let req = XrpTxSignRequest {
            chain_id: ChainId::Xrp,
            account_address: "rXindexVaultMultisigAccount000000000".to_string(),
            destination: "rThorchainAsgardInbound00000000000000".to_string(),
            amount_drops: "1000000".to_string(),
            fee_drops: "30".to_string(),
            sequence: "7".to_string(),
            last_ledger_sequence: "9000007".to_string(),
            memo: "=:ETH.USDT:0xabc:0/1/0".to_string(),
            signing_blob: format!("0x{}", "ab".repeat(80)),
        };
        let s = serde_json::to_string(&req).expect("serialize");
        let back: XrpTxSignRequest = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, req);
        assert!(s.contains("\"chain_id\":\"xrp\""));
    }

    /// C2: the serde validator rejects non-XRP `ChainId`s (UTXO + EVM +
    /// Cosmos) on the `xrp-tx` request — defence-in-depth above the
    /// runtime `custody_family` check in the daemon handler.
    #[test]
    fn xrp_tx_request_rejects_non_xrp_chains() {
        for chain in [
            "btc", "ltc", "bch", "doge", "zec", "eth", "bsc", "avax", "base", "pol", "gaia", "sol",
            "tron",
        ] {
            let json = format!(
                r#"{{"chain_id":"{chain}","account_address":"rX","destination":"rY","amount_drops":"1","fee_drops":"30","sequence":"0","last_ledger_sequence":"0","memo":"","signing_blob":"0x{blob}"}}"#,
                blob = "00".repeat(80),
            );
            let result: Result<XrpTxSignRequest, _> = serde_json::from_str(&json);
            let err_msg = match result {
                Ok(req) => format!("expected NON_XRP_CHAIN rejection, got: {req:?}"),
                Err(e) => format!("{e}"),
            };
            assert!(
                err_msg.contains(error_codes::NON_XRP_CHAIN),
                "must surface the NON_XRP_CHAIN code; chain='{chain}', got: {err_msg}"
            );
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn xrp_sign_response_json_round_trip() {
        let r = XrpSignResponse {
            pubkey: format!("0x{}", "02".repeat(33)),
            // DER sigs are variable length (~70-72 bytes); use a plausible hex.
            signature: "3045022100abcd0220ef01".to_string(),
        };
        let s = serde_json::to_string(&r).expect("serialize");
        let back: XrpSignResponse = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, r);
    }

    /// Phase 4.5: a `SolanaTxSignRequest` round-trips JSON for the Solana
    /// chain (sol) including the `Create`-only inner fields.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn solana_tx_request_round_trip() {
        let req = SolanaTxSignRequest {
            chain_id: ChainId::Sol,
            tx_kind: SolanaTxKind::Create,
            multisig_pda: "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf".to_string(),
            member_pubkey: "11111111111111111111111111111111".to_string(),
            transaction_index: "7".to_string(),
            recent_blockhash: "3aMY3wX4pNMJCXBCzmMUaBkNRCWNcPjkD56V67aWwDra".to_string(),
            vault_index: Some(0),
            inner_destination: Some("4xXE3kHs2bP".to_string()),
            inner_amount_lamports: Some("2000000000".to_string()),
            memo: Some("=:ETH.USDT:0xabc:1".to_string()),
            message_hex: format!("0x{}", "ab".repeat(64)),
        };
        let s = serde_json::to_string(&req).expect("serialize");
        let back: SolanaTxSignRequest = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, req);
        assert!(s.contains("\"chain_id\":\"sol\""));
        assert!(s.contains("\"tx_kind\":\"create\""));
    }

    /// Phase 4.5: the serde validator rejects non-Solana `ChainId`s on the
    /// `solana-tx` request — defence-in-depth above the daemon's runtime
    /// `custody_family` check.
    #[test]
    fn solana_tx_request_rejects_non_solana_chains() {
        for chain in [
            "btc", "ltc", "bch", "doge", "zec", "eth", "bsc", "avax", "base", "pol", "gaia", "xrp",
            "tron",
        ] {
            let json = format!(
                r#"{{"chain_id":"{chain}","tx_kind":"approve","multisig_pda":"M","member_pubkey":"K","transaction_index":"0","recent_blockhash":"B","message_hex":"0x00"}}"#
            );
            let result: Result<SolanaTxSignRequest, _> = serde_json::from_str(&json);
            let err_msg = match result {
                Ok(req) => format!("expected NON_SOLANA_CHAIN rejection, got: {req:?}"),
                Err(e) => format!("{e}"),
            };
            assert!(
                err_msg.contains(error_codes::NON_SOLANA_CHAIN),
                "must surface NON_SOLANA_CHAIN; chain='{chain}', got: {err_msg}"
            );
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn solana_sign_response_json_round_trip() {
        let r = SolanaSignResponse {
            pubkey: "11111111111111111111111111111111".to_string(),
            signature: format!("0x{}", "cd".repeat(64)),
        };
        let s = serde_json::to_string(&r).expect("serialize");
        let back: SolanaSignResponse = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, r);
    }

    /// Phase 4.6: a `TronTxSignRequest` round-trips JSON for the TRON chain
    /// for both asset kinds (TRX `TransferContract` + USDT
    /// `TriggerSmartContract`, including the `Usdt`-only fields).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn tron_tx_request_round_trip() {
        for (asset, contract, fee_limit) in [
            (TronAssetKind::Trx, None, None),
            (
                TronAssetKind::Usdt,
                Some("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".to_string()),
                Some("30000000".to_string()),
            ),
        ] {
            let req = TronTxSignRequest {
                chain_id: ChainId::Tron,
                asset,
                owner_address: "TU6nEM4GTca2L5AuDTnY1qp1rkQ2t8NxvM".to_string(),
                to_address: "TJRabPrwbZy45sbavfcjinPJC18kjpRTv8".to_string(),
                amount: "1000000".to_string(),
                contract_address: contract,
                permission_id: 2,
                ref_block_bytes: "0x00b0".to_string(),
                ref_block_hash: "0x3f1bc96dc80e7f61".to_string(),
                expiration: "1548974130000".to_string(),
                timestamp: "1548974072663".to_string(),
                fee_limit,
                memo: "=:ETH.USDT:0xabc:0/1/0".to_string(),
                txid: format!("0x{}", "ab".repeat(32)),
            };
            let s = serde_json::to_string(&req).expect("serialize");
            let back: TronTxSignRequest = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back, req);
            assert!(s.contains("\"chain_id\":\"tron\""));
        }
    }

    /// Phase 4.6: the serde validator rejects non-TRON `ChainId`s on the
    /// `tron-tx` request — defence-in-depth above the daemon's runtime
    /// `custody_family` check.
    #[test]
    fn tron_tx_request_rejects_non_tron_chains() {
        for chain in [
            "btc", "ltc", "bch", "doge", "zec", "eth", "bsc", "avax", "base", "pol", "gaia", "xrp",
            "sol",
        ] {
            let json = format!(
                r#"{{"chain_id":"{chain}","asset":"trx","owner_address":"T1","to_address":"T2","amount":"1","permission_id":2,"ref_block_bytes":"0x00b0","ref_block_hash":"0x3f1bc96dc80e7f61","expiration":"1","timestamp":"1","memo":"","txid":"0x{hash}"}}"#,
                hash = "00".repeat(32),
            );
            let result: Result<TronTxSignRequest, _> = serde_json::from_str(&json);
            let err_msg = match result {
                Ok(req) => format!("expected NON_TRON_CHAIN rejection, got: {req:?}"),
                Err(e) => format!("{e}"),
            };
            assert!(
                err_msg.contains(error_codes::NON_TRON_CHAIN),
                "must surface NON_TRON_CHAIN; chain='{chain}', got: {err_msg}"
            );
        }
    }

    /// CTD-1: an `IntentProof` round-trips JSON without losing fields
    /// — the k-of-n RIC attachment every custody-spend request will
    /// carry once the gate is wired.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn intent_proof_json_round_trip() {
        let proof = IntentProof {
            redemption_id: format!("0x{}", "ab".repeat(32)),
            leg_index: "0".to_string(),
            asset_id: "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                .to_string(),
            amount: "100000000".to_string(),
            amount_decimals: 8,
            immediate_target_hash: format!("0x{}", "cd".repeat(32)),
            memo_hash: format!("0x{}", "ef".repeat(32)),
            final_destination_hash: format!("0x{}", "12".repeat(32)),
            vault_resolved_at: 1_750_000_000,
            signatures: vec![
                format!("0x{}", "ab".repeat(65)),
                format!("0x{}", "cd".repeat(65)),
            ],
        };
        let s = serde_json::to_string(&proof).expect("serialize");
        let back: IntentProof = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, proof);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn tron_sign_response_json_round_trip() {
        let r = TronSignResponse {
            pubkey: format!("0x{}", "02".repeat(33)),
            signature: format!("0x{}", "cd".repeat(65)),
        };
        let s = serde_json::to_string(&r).expect("serialize");
        let back: TronSignResponse = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, r);
    }
}
