//! Key-free Xindex policy boundary for Vultisig Bitcoin custody.
//!
//! This crate deliberately contains no Vultisig SDK, network client, vault,
//! share, credential, signing, or broadcast capability. It validates the full
//! Bitcoin PSBT fields that Xindex must bind before a DKLS participant may
//! release a signing share, derives every per-input `SIGHASH_ALL` digest from
//! that PSBT, and then composes with custody-node's existing RIC/ACC one-shot
//! authorization. The resulting immutable approval provides a primitive that
//! revalidates the exact finalized transaction body, witness shape, aggregate
//! public key and every ECDSA signature. The final receipt can then be consumed
//! into a non-cloneable aggregate-evidence handoff. The executor library offers
//! an optional key-free write-ahead preparation step for that handoff, but no
//! runtime, concrete durable sink, target-bound transport, or broadcaster is
//! wired yet.

mod evidence;

pub use evidence::{
    VultisigBitcoinEvidence, VultisigBitcoinEvidenceRecord, VultisigParticipantIdentity,
    VultisigSessionContext,
};

use std::fmt;

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::constants::ChainHash;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{sha256, Hash as _};
use bitcoin::psbt::{Input as PsbtInput, Psbt, PsbtSighashType};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut};
use xindex_chain_utxo::finalized_inventory::{
    FinalizedBitcoinPolicyInputs, FinalizedBitcoinPolicySource, InventoryError,
};
use xindex_chain_utxo::trusted_observer::Testnet4FinalizedInventoryObserver;
use xindex_custody_core::btc_authorize::BtcSpendAuthorization;
use xindex_custody_core::gates::{CustodyConfig, GateRejection};
use xindex_custody_core::prepare::BindContext;
use xindex_custody_core::replay::ReplayStore;
use xindex_custody_node::btc::authorize_certified_btc_spend;
use xindex_shared::chain_registry::ChainId;

const POLICY_ID_DOMAIN: &[u8] = b"XINDEX/VULTISIG/BTC-SPEND-POLICY/V1";

#[derive(Debug, Clone, PartialEq, Eq)]
struct BitcoinPolicyProvenance {
    finalized: Option<Box<FinalizedBitcoinPolicyInputs>>,
}

impl BitcoinPolicyProvenance {
    fn from_finalized(capability: FinalizedBitcoinPolicyInputs) -> Self {
        Self {
            finalized: Some(Box::new(capability)),
        }
    }

    #[cfg(test)]
    const fn fixture() -> Self {
        Self { finalized: None }
    }

    fn finalized(&self) -> Result<&FinalizedBitcoinPolicyInputs, PolicyError> {
        self.finalized.as_deref().ok_or_else(|| {
            PolicyError::new(
                "vultisig_provenance",
                "test-only Bitcoin spend policy has no finalized inventory provenance",
            )
        })
    }
}

/// One independently observed Bitcoin UTXO that the policy permits spending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinInputPolicy {
    outpoint: OutPoint,
    value_sats: u64,
}

impl BitcoinInputPolicy {
    /// Bind one exact, positive-value UTXO.
    ///
    /// # Errors
    /// Returns a fail-closed policy error when `value_sats` is zero.
    fn new(outpoint: OutPoint, value_sats: u64) -> Result<Self, PolicyError> {
        if value_sats == 0 {
            return Err(PolicyError::new(
                "vultisig_policy_input",
                "permitted input value must be non-zero",
            ));
        }
        Ok(Self {
            outpoint,
            value_sats,
        })
    }

    /// Exact permitted previous output.
    #[must_use]
    pub const fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    /// Independently observed input value in satoshis.
    #[must_use]
    pub const fn value_sats(&self) -> u64 {
        self.value_sats
    }
}

/// Exact Xindex policy for one aggregate-key P2WPKH Bitcoin spend.
///
/// The former raw policy-construction shape is deliberately unreachable from
/// external crates:
///
/// ```compile_fail
/// use bitcoin::blockdata::constants::ChainHash;
/// use bitcoin::ScriptBuf;
/// use xindex_vultisig_adapter::{BitcoinInputPolicy, BitcoinSpendPolicy};
///
/// let _ = BitcoinSpendPolicy::new_testnet4(
///     ChainHash::TESTNET4,
///     Vec::<BitcoinInputPolicy>::new(),
///     ScriptBuf::new(),
///     1,
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinSpendPolicy {
    chain_hash: ChainHash,
    inputs: Vec<BitcoinInputPolicy>,
    custody_script_pubkey: ScriptBuf,
    max_fee_sats: u64,
    provenance: BitcoinPolicyProvenance,
    provenance_id: [u8; 32],
    policy_id: [u8; 32],
}

impl BitcoinSpendPolicy {
    /// Construct a Testnet4-only rehearsal policy from an opaque finalized,
    /// reorg-aware custody-inventory capability.
    ///
    /// Raw outpoints, values, scripts, and chain identity cannot be supplied to
    /// this public constructor. They are copied from `finalized_inputs`, whose
    /// fields have no public constructor or deserialization path.
    ///
    /// # Errors
    /// Returns a fail-closed policy error for a non-Testnet4 capability, an
    /// empty or duplicate input set, a non-P2WPKH custody script, or an invalid
    /// fee ceiling.
    pub fn new_testnet4(
        finalized_inputs: FinalizedBitcoinPolicyInputs,
        max_fee_sats: u64,
    ) -> Result<Self, PolicyError> {
        let observed_chain_hash = finalized_inputs.chain_hash();
        let custody_script_pubkey = finalized_inputs.custody_script_pubkey().clone();
        let inputs = finalized_inputs
            .inputs()
            .iter()
            .map(|input| BitcoinInputPolicy::new(input.outpoint(), input.value_sats()))
            .collect::<Result<Vec<_>, _>>()?;
        let provenance_id = finalized_inputs.provenance_id();
        Self::build(
            observed_chain_hash,
            inputs,
            custody_script_pubkey,
            max_fee_sats,
            BitcoinPolicyProvenance::from_finalized(finalized_inputs),
            provenance_id,
        )
    }

    fn build(
        observed_chain_hash: ChainHash,
        inputs: Vec<BitcoinInputPolicy>,
        custody_script_pubkey: ScriptBuf,
        max_fee_sats: u64,
        provenance: BitcoinPolicyProvenance,
        provenance_id: [u8; 32],
    ) -> Result<Self, PolicyError> {
        if observed_chain_hash != ChainHash::TESTNET4 {
            return Err(PolicyError::new(
                "vultisig_network",
                format!(
                    "observed Bitcoin chain hash {observed_chain_hash} is not Testnet4 {}",
                    ChainHash::TESTNET4
                ),
            ));
        }
        if inputs.is_empty() {
            return Err(PolicyError::new(
                "vultisig_policy_inputs",
                "permitted input set must be non-empty",
            ));
        }
        for (index, input) in inputs.iter().enumerate() {
            if inputs[..index]
                .iter()
                .any(|earlier| earlier.outpoint == input.outpoint)
            {
                return Err(PolicyError::new(
                    "vultisig_policy_inputs",
                    format!("duplicate permitted outpoint {}", input.outpoint),
                ));
            }
        }
        if !custody_script_pubkey.is_p2wpkh() {
            return Err(PolicyError::new(
                "vultisig_policy_custody",
                "Vultisig Bitcoin custody script must be native P2WPKH",
            ));
        }
        if max_fee_sats == 0 {
            return Err(PolicyError::new(
                "vultisig_policy_fee",
                "absolute fee ceiling must be non-zero",
            ));
        }
        let protocol_cap = ChainId::Btc.max_redeem_fee_base_units();
        if max_fee_sats > protocol_cap {
            return Err(PolicyError::new(
                "vultisig_policy_fee",
                format!(
                    "absolute fee ceiling {max_fee_sats} exceeds the protocol BTC cap {protocol_cap}"
                ),
            ));
        }
        let policy_id = compute_policy_id(provenance_id, max_fee_sats);
        Ok(Self {
            chain_hash: observed_chain_hash,
            inputs,
            custody_script_pubkey,
            max_fee_sats,
            provenance,
            provenance_id,
            policy_id,
        })
    }

    #[cfg(test)]
    fn new_testnet4_fixture(
        observed_chain_hash: ChainHash,
        inputs: Vec<BitcoinInputPolicy>,
        custody_script_pubkey: ScriptBuf,
        max_fee_sats: u64,
    ) -> Result<Self, PolicyError> {
        Self::build(
            observed_chain_hash,
            inputs,
            custody_script_pubkey,
            max_fee_sats,
            BitcoinPolicyProvenance::fixture(),
            [0; 32],
        )
    }

    /// Exact rehearsal-chain identity bound into this policy.
    #[must_use]
    pub const fn chain_hash(&self) -> ChainHash {
        self.chain_hash
    }

    /// Complete ordered permitted input set.
    #[must_use]
    pub fn inputs(&self) -> &[BitcoinInputPolicy] {
        &self.inputs
    }

    /// Aggregate-key native P2WPKH custody script.
    #[must_use]
    pub const fn custody_script_pubkey(&self) -> &ScriptBuf {
        &self.custody_script_pubkey
    }

    /// Maximum absolute miner fee in satoshis.
    #[must_use]
    pub const fn max_fee_sats(&self) -> u64 {
        self.max_fee_sats
    }

    /// Finalized inventory provenance identity bound into this policy.
    #[must_use]
    pub const fn provenance_id(&self) -> [u8; 32] {
        self.provenance_id
    }

    /// Domain-separated policy identity: provenance plus exact fee ceiling and
    /// policy version.
    #[must_use]
    pub const fn policy_id(&self) -> [u8; 32] {
        self.policy_id
    }

    fn provenance(&self) -> Result<&FinalizedBitcoinPolicyInputs, PolicyError> {
        self.provenance.finalized()
    }
}

/// Source-pinned Vultisig Bitcoin policy composition root.
///
/// Production construction requires the trusted Testnet4 observer. Callers do
/// not select a finalized-inventory source independently at authorization or
/// final handoff time.
#[derive(Debug, Clone)]
pub struct VultisigBitcoinPolicyRuntime {
    policy_source: FinalizedBitcoinPolicySource,
}

impl VultisigBitcoinPolicyRuntime {
    /// Pin this policy runtime to one authenticated observer inventory.
    #[must_use]
    pub fn from_observer(observer: &Testnet4FinalizedInventoryObserver) -> Self {
        Self {
            policy_source: observer.policy_source(),
        }
    }

    #[cfg(test)]
    const fn from_test_source(policy_source: FinalizedBitcoinPolicySource) -> Self {
        Self { policy_source }
    }

    /// Issue one exact spend policy from the pinned finalized inventory.
    ///
    /// # Errors
    /// Missing/stale inputs or an invalid fee ceiling.
    pub async fn issue_policy(
        &self,
        ordered_outpoints: &[OutPoint],
        max_fee_sats: u64,
    ) -> Result<BitcoinSpendPolicy, AdapterError> {
        let inputs = self
            .policy_source
            .issue_policy_inputs(ordered_outpoints)
            .await?;
        Ok(BitcoinSpendPolicy::new_testnet4(inputs, max_fee_sats)?)
    }

    /// Validate the complete PSBT and consume the custody one-shot against the
    /// same pinned observer source used for final handoff.
    ///
    /// # Errors
    /// Policy, provenance, or custody authorization rejection.
    pub async fn authorize<S: ReplayStore>(
        &self,
        ctx: &BindContext,
        replay: &S,
        config: CustodyConfig<'_>,
        policy: &BitcoinSpendPolicy,
        now_unix: i64,
    ) -> Result<AuthorizedBitcoinSpend, AdapterError> {
        authorize_vultisig_btc_spend(ctx, replay, config, &self.policy_source, policy, now_unix)
            .await
    }
}

/// Immutable result of full PSBT policy validation and local hash derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinPolicyApproval {
    chain_hash: ChainHash,
    unsigned_txid: [u8; 32],
    fee_sats: u64,
    signing_hashes: Vec<[u8; 32]>,
    custody_script_pubkey: ScriptBuf,
    provenance: BitcoinPolicyProvenance,
    provenance_id: [u8; 32],
    policy_id: [u8; 32],
}

impl BitcoinPolicyApproval {
    /// Exact rehearsal-chain identity carried from the validated policy.
    #[must_use]
    pub const fn chain_hash(&self) -> ChainHash {
        self.chain_hash
    }

    /// Unsigned transaction ID committed by the policy decision.
    #[must_use]
    pub const fn unsigned_txid(&self) -> [u8; 32] {
        self.unsigned_txid
    }

    /// Exact implied miner fee.
    #[must_use]
    pub const fn fee_sats(&self) -> u64 {
        self.fee_sats
    }

    /// Locally derived BIP-143 `SIGHASH_ALL` digest for every input, in order.
    #[must_use]
    pub fn signing_hashes(&self) -> &[[u8; 32]] {
        &self.signing_hashes
    }

    /// Finalized inventory provenance identity carried from policy approval.
    #[must_use]
    pub const fn provenance_id(&self) -> [u8; 32] {
        self.provenance_id
    }

    /// Exact domain-separated transaction-policy identity.
    #[must_use]
    pub const fn policy_id(&self) -> [u8; 32] {
        self.policy_id
    }

    fn provenance(&self) -> Result<&FinalizedBitcoinPolicyInputs, PolicyError> {
        self.provenance.finalized()
    }

    fn validate_finalized_transaction_bytes(
        &self,
        transaction_bytes: Vec<u8>,
    ) -> Result<ValidatedBitcoinTransaction, PolicyError> {
        let transaction =
            deserialize::<bitcoin::Transaction>(&transaction_bytes).map_err(|error| {
                PolicyError::new(
                    "vultisig_final_encoding",
                    format!("finalized transaction is not one exact consensus encoding: {error}"),
                )
            })?;
        if serialize(&transaction).as_slice() != transaction_bytes.as_slice() {
            return Err(PolicyError::new(
                "vultisig_final_encoding",
                "finalized transaction bytes are not canonical consensus encoding",
            ));
        }
        let txid = transaction.compute_txid().to_byte_array();
        if txid != self.unsigned_txid {
            return Err(PolicyError::new(
                "vultisig_final_txid",
                "finalized transaction body does not equal the authorized unsigned transaction",
            ));
        }
        if transaction.input.len() != self.signing_hashes.len() {
            return Err(PolicyError::new(
                "vultisig_final_witness",
                "finalized transaction input count does not equal the authorized signing-hash count",
            ));
        }
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let mut aggregate_public_key = [0u8; 33];
        for (index, input) in transaction.input.iter().enumerate() {
            if input.witness.len() != 2 {
                return Err(PolicyError::new(
                    "vultisig_final_witness",
                    format!(
                        "VIN{index} must contain exactly one aggregate signature and one compressed public key"
                    ),
                ));
            }
            let mut witness = input.witness.iter();
            let signature_bytes = witness
                .next()
                .ok_or_else(|| PolicyError::new("vultisig_final_witness", "missing signature"))?;
            let signature = bitcoin::ecdsa::Signature::from_slice(signature_bytes).map_err(|_| {
                PolicyError::new(
                    "vultisig_final_signature",
                    format!("VIN{index} aggregate signature is not strict DER plus a standard sighash byte"),
                )
            })?;
            if signature.sighash_type != EcdsaSighashType::All {
                return Err(PolicyError::new(
                    "vultisig_final_sighash",
                    format!("VIN{index} aggregate signature must use SIGHASH_ALL"),
                ));
            }
            let public_key_bytes = witness.next().ok_or_else(|| {
                PolicyError::new("vultisig_final_witness", "missing aggregate public key")
            })?;
            if public_key_bytes.len() != 33 || !matches!(public_key_bytes[0], 0x02 | 0x03) {
                return Err(PolicyError::new(
                    "vultisig_final_pubkey",
                    format!("VIN{index} aggregate public key is not compressed secp256k1"),
                ));
            }
            let public_key =
                bitcoin::CompressedPublicKey::from_slice(public_key_bytes).map_err(|_| {
                    PolicyError::new(
                        "vultisig_final_pubkey",
                        format!("VIN{index} aggregate public key is not compressed secp256k1"),
                    )
                })?;
            bind_aggregate_public_key(&mut aggregate_public_key, index, public_key_bytes)?;
            if ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash()) != self.custody_script_pubkey {
                return Err(PolicyError::new(
                    "vultisig_final_pubkey",
                    format!(
                        "VIN{index} aggregate public key does not match the authorized custody script"
                    ),
                ));
            }
            let message = bitcoin::secp256k1::Message::from_digest(self.signing_hashes[index]);
            public_key
                .verify(&secp, &message, &signature)
                .map_err(|_| {
                    PolicyError::new(
                        "vultisig_final_signature",
                        format!(
                            "VIN{index} aggregate signature does not verify against the independently derived hash"
                        ),
                    )
                })?;
        }
        Ok(ValidatedBitcoinTransaction {
            chain_hash: self.chain_hash,
            transaction_bytes: transaction_bytes.into_boxed_slice(),
            txid,
            wtxid: transaction.compute_wtxid().to_byte_array(),
            input_count: transaction.input.len(),
            aggregate_public_key,
        })
    }
}

fn bind_aggregate_public_key(
    aggregate_public_key: &mut [u8; 33],
    input_index: usize,
    public_key_bytes: &[u8],
) -> Result<(), PolicyError> {
    if input_index == 0 {
        aggregate_public_key.copy_from_slice(public_key_bytes);
    } else if aggregate_public_key.as_slice() != public_key_bytes {
        return Err(PolicyError::new(
            "vultisig_final_pubkey",
            "every input must use the same authorized aggregate public key",
        ));
    }
    Ok(())
}

async fn validate_finalized_handoff(
    policy_source: &FinalizedBitcoinPolicySource,
    approval: &BitcoinPolicyApproval,
    transaction_bytes: Vec<u8>,
) -> Result<ValidatedBitcoinTransaction, AdapterError> {
    let validated = approval.validate_finalized_transaction_bytes(transaction_bytes)?;
    policy_source.assert_current(approval.provenance()?).await?;
    Ok(validated)
}

#[derive(Debug, PartialEq, Eq)]
struct ValidatedBitcoinTransaction {
    chain_hash: ChainHash,
    transaction_bytes: Box<[u8]>,
    txid: [u8; 32],
    wtxid: [u8; 32],
    input_count: usize,
    aggregate_public_key: [u8; 33],
}

impl ValidatedBitcoinTransaction {
    #[must_use]
    const fn chain_hash(&self) -> ChainHash {
        self.chain_hash
    }

    #[must_use]
    fn transaction_bytes(&self) -> &[u8] {
        &self.transaction_bytes
    }

    #[must_use]
    const fn txid(&self) -> [u8; 32] {
        self.txid
    }

    #[must_use]
    const fn wtxid(&self) -> [u8; 32] {
        self.wtxid
    }

    #[must_use]
    const fn input_count(&self) -> usize {
        self.input_count
    }

    #[must_use]
    const fn aggregate_public_key(&self) -> [u8; 33] {
        self.aggregate_public_key
    }
}

/// Receipt exposed only after both the Vultisig policy and custody one-shot pass.
#[derive(Debug)]
pub struct AuthorizedBitcoinSpend {
    policy: BitcoinPolicyApproval,
    custody: BtcSpendAuthorization,
    policy_source: FinalizedBitcoinPolicySource,
}

impl AuthorizedBitcoinSpend {
    /// Full transaction-policy decision.
    #[must_use]
    pub const fn policy(&self) -> &BitcoinPolicyApproval {
        &self.policy
    }

    /// RIC/ACC verification and consumed one-shot receipt.
    #[must_use]
    pub const fn custody(&self) -> &BtcSpendAuthorization {
        &self.custody
    }

    /// Consume the post-one-shot authorization and revalidate the exact raw
    /// finalized transaction bytes into an opaque broadcast capability.
    ///
    /// The returned value owns the canonical bytes that passed body, witness,
    /// aggregate-key, sighash, and per-input signature verification. A future
    /// broadcaster must accept this capability instead of a bare transaction.
    /// No current runtime consumes it.
    ///
    /// # Errors
    /// Returns a fail-closed provenance or policy rejection when inventory
    /// state is stale, the bytes are not one exact canonical transaction, or
    /// the transaction differs from the approval.
    pub async fn finalize(
        self,
        transaction_bytes: Vec<u8>,
    ) -> Result<FinalizedBitcoinSpend, AdapterError> {
        let validated =
            validate_finalized_handoff(&self.policy_source, &self.policy, transaction_bytes)
                .await?;
        Ok(FinalizedBitcoinSpend {
            transaction: validated,
            custody: self.custody,
            provenance_id: self.policy.provenance_id,
            policy_id: self.policy.policy_id,
        })
    }
}

/// Opaque capability owning the exact finalized bytes validated after the
/// custody one-shot. This type has no public constructor and is not cloneable.
///
/// ```compile_fail
/// use xindex_vultisig_adapter::FinalizedBitcoinSpend;
///
/// fn inspect(capability: &FinalizedBitcoinSpend) {
///     let _ = &capability.transaction;
/// }
/// ```
///
/// ```compile_fail
/// use xindex_vultisig_adapter::FinalizedBitcoinSpend;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<FinalizedBitcoinSpend>();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct FinalizedBitcoinSpend {
    transaction: ValidatedBitcoinTransaction,
    custody: BtcSpendAuthorization,
    provenance_id: [u8; 32],
    policy_id: [u8; 32],
}

impl FinalizedBitcoinSpend {
    /// Exact rehearsal-chain identity carried from the post-one-shot policy.
    #[must_use]
    pub const fn chain_hash(&self) -> ChainHash {
        self.transaction.chain_hash()
    }

    /// Exact canonical consensus bytes that passed final revalidation.
    #[must_use]
    pub fn transaction_bytes(&self) -> &[u8] {
        self.transaction.transaction_bytes()
    }

    /// Transaction ID of the exact approved non-witness body.
    #[must_use]
    pub const fn txid(&self) -> [u8; 32] {
        self.transaction.txid()
    }

    /// Witness transaction ID of the fully signed transaction.
    #[must_use]
    pub const fn wtxid(&self) -> [u8; 32] {
        self.transaction.wtxid()
    }

    /// Number of independently revalidated input witnesses.
    #[must_use]
    pub const fn input_count(&self) -> usize {
        self.transaction.input_count()
    }

    /// Canonical compressed aggregate public key verified in every witness.
    #[must_use]
    pub const fn aggregate_public_key(&self) -> [u8; 33] {
        self.transaction.aggregate_public_key()
    }

    /// Finalized custody-inventory provenance identity checked before handoff.
    #[must_use]
    pub const fn provenance_id(&self) -> [u8; 32] {
        self.provenance_id
    }

    /// Exact transaction-policy identity checked before handoff.
    #[must_use]
    pub const fn policy_id(&self) -> [u8; 32] {
        self.policy_id
    }

    /// RIC/ACC verification and consumed one-shot receipt bound to the bytes.
    #[must_use]
    pub const fn custody(&self) -> &BtcSpendAuthorization {
        &self.custody
    }
}

/// Stable fail-closed Vultisig policy rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    code: &'static str,
    message: String,
}

impl PolicyError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Operator-facing detail.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for PolicyError {}

/// A policy, provenance, or existing custody authorization rejection.
#[derive(Debug, Clone)]
pub enum AdapterError {
    /// The decoded Bitcoin transaction failed Xindex's Vultisig policy.
    Policy(PolicyError),
    /// Finalized custody-inventory provenance is unavailable or stale.
    Provenance(InventoryError),
    /// RIC/ACC verification, output binding, or one-shot consumption failed.
    Custody(GateRejection),
}

impl AdapterError {
    /// Stable machine-readable error code from the rejecting boundary.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Policy(error) => error.code(),
            Self::Provenance(error) => error.code(),
            Self::Custody(error) => error.code,
        }
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(error) => error.fmt(formatter),
            Self::Provenance(error) => error.fmt(formatter),
            Self::Custody(error) => write!(formatter, "{}: {}", error.code, error.message),
        }
    }
}

impl std::error::Error for AdapterError {}

impl From<PolicyError> for AdapterError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<GateRejection> for AdapterError {
    fn from(error: GateRejection) -> Self {
        Self::Custody(error)
    }
}

impl From<InventoryError> for AdapterError {
    fn from(error: InventoryError) -> Self {
        Self::Provenance(error)
    }
}

/// Validate every policy-relevant PSBT field and derive every signing hash.
///
/// This function never accepts a caller-provided digest. Output destination,
/// amount, memo, and order are intentionally bound by
/// [`authorize_vultisig_btc_spend`], which composes this decision with the
/// independently signed RIC/ACC.
///
/// # Errors
/// Returns a fail-closed policy rejection for any transaction, input, PSBT
/// metadata, sighash, or fee mismatch.
fn validate_and_derive_signing_hashes(
    psbt: &Psbt,
    policy: &BitcoinSpendPolicy,
) -> Result<BitcoinPolicyApproval, PolicyError> {
    validate_transaction_envelope(psbt, policy)?;
    for (index, ((tx_input, metadata), expected)) in psbt
        .unsigned_tx
        .input
        .iter()
        .zip(&psbt.inputs)
        .zip(policy.inputs())
        .enumerate()
    {
        validate_unsigned_input(index, tx_input, expected)?;
        validate_psbt_input(index, metadata, expected, policy.custody_script_pubkey())?;
    }
    let fee_sats = implied_fee_sats(psbt, policy)?;
    let signing_hashes = derive_signing_hashes(psbt, policy)?;
    Ok(BitcoinPolicyApproval {
        chain_hash: policy.chain_hash(),
        unsigned_txid: psbt.unsigned_tx.compute_txid().to_byte_array(),
        fee_sats,
        signing_hashes,
        custody_script_pubkey: policy.custody_script_pubkey().clone(),
        provenance: policy.provenance.clone(),
        provenance_id: policy.provenance_id,
        policy_id: policy.policy_id,
    })
}

fn validate_transaction_envelope(
    psbt: &Psbt,
    policy: &BitcoinSpendPolicy,
) -> Result<(), PolicyError> {
    if psbt.version != 0 {
        return Err(PolicyError::new(
            "vultisig_psbt_version",
            format!("PSBT version must be 0, found {}", psbt.version),
        ));
    }
    let tx = &psbt.unsigned_tx;
    if tx.version != Version::TWO {
        return Err(PolicyError::new(
            "vultisig_tx_version",
            format!(
                "Bitcoin transaction version must be 2, found {}",
                tx.version.0
            ),
        ));
    }
    if tx.lock_time != LockTime::ZERO {
        return Err(PolicyError::new(
            "vultisig_tx_locktime",
            format!(
                "Bitcoin transaction locktime must be zero, found {}",
                tx.lock_time.to_consensus_u32()
            ),
        ));
    }
    if tx.input.len() != policy.inputs().len() || psbt.inputs.len() != policy.inputs().len() {
        return Err(PolicyError::new(
            "vultisig_tx_inputs",
            format!(
                "complete ordered input count mismatch: transaction={}, PSBT={}, policy={}",
                tx.input.len(),
                psbt.inputs.len(),
                policy.inputs().len()
            ),
        ));
    }
    if tx.output.len() != psbt.outputs.len() {
        return Err(PolicyError::new(
            "vultisig_psbt_outputs",
            "PSBT output metadata count does not match the unsigned transaction",
        ));
    }
    Ok(())
}

fn validate_unsigned_input(
    index: usize,
    tx_input: &TxIn,
    expected: &BitcoinInputPolicy,
) -> Result<(), PolicyError> {
    if tx_input.previous_output != expected.outpoint() {
        return Err(PolicyError::new(
            "vultisig_tx_inputs",
            format!(
                "VIN{index} outpoint {} does not equal permitted {}",
                tx_input.previous_output,
                expected.outpoint()
            ),
        ));
    }
    if tx_input.sequence != Sequence::MAX {
        return Err(PolicyError::new(
            "vultisig_tx_sequence",
            format!(
                "VIN{index} sequence must be final/non-RBF 0xffffffff, found {:#010x}",
                tx_input.sequence.to_consensus_u32()
            ),
        ));
    }
    if !tx_input.script_sig.is_empty() || !tx_input.witness.is_empty() {
        return Err(PolicyError::new(
            "vultisig_psbt_signed",
            format!("VIN{index} unsigned transaction input already carries signing data"),
        ));
    }
    Ok(())
}

fn validate_psbt_input(
    index: usize,
    metadata: &PsbtInput,
    expected: &BitcoinInputPolicy,
    custody_script_pubkey: &ScriptBuf,
) -> Result<(), PolicyError> {
    if !metadata.partial_sigs.is_empty()
        || metadata.final_script_sig.is_some()
        || metadata.final_script_witness.is_some()
    {
        return Err(PolicyError::new(
            "vultisig_psbt_signed",
            format!("VIN{index} PSBT is already partially or fully signed"),
        ));
    }
    if metadata.redeem_script.is_some()
        || metadata.witness_script.is_some()
        || metadata.tap_key_sig.is_some()
        || !metadata.tap_script_sigs.is_empty()
        || !metadata.tap_scripts.is_empty()
        || !metadata.tap_key_origins.is_empty()
        || metadata.tap_internal_key.is_some()
        || metadata.tap_merkle_root.is_some()
    {
        return Err(PolicyError::new(
            "vultisig_psbt_input",
            format!(
                "VIN{index} carries script-path or Taproot metadata outside the native P2WPKH policy"
            ),
        ));
    }
    if !matches!(
        metadata.sighash_type.map(PsbtSighashType::ecdsa_hash_ty),
        Some(Ok(EcdsaSighashType::All))
    ) {
        return Err(PolicyError::new(
            "vultisig_sighash",
            format!("VIN{index} must explicitly request ECDSA SIGHASH_ALL"),
        ));
    }
    let witness_utxo = metadata.witness_utxo.as_ref().ok_or_else(|| {
        PolicyError::new(
            "vultisig_psbt_input",
            format!("VIN{index} has no witness_utxo"),
        )
    })?;
    if witness_utxo.value.to_sat() != expected.value_sats()
        || witness_utxo.script_pubkey != *custody_script_pubkey
    {
        return Err(PolicyError::new(
            "vultisig_psbt_input",
            format!(
                "VIN{index} witness_utxo does not equal the independently observed value and custody script"
            ),
        ));
    }
    if let Some(previous_tx) = &metadata.non_witness_utxo {
        validate_non_witness_utxo(index, previous_tx, witness_utxo, expected)?;
    }
    Ok(())
}

fn validate_non_witness_utxo(
    index: usize,
    previous_tx: &bitcoin::Transaction,
    witness_utxo: &TxOut,
    expected: &BitcoinInputPolicy,
) -> Result<(), PolicyError> {
    let vout = usize::try_from(expected.outpoint().vout).map_err(|_| {
        PolicyError::new(
            "vultisig_psbt_input",
            format!("VIN{index} previous-output index does not fit usize"),
        )
    })?;
    let previous_output = previous_tx.output.get(vout).ok_or_else(|| {
        PolicyError::new(
            "vultisig_psbt_input",
            format!("VIN{index} non_witness_utxo lacks the selected output"),
        )
    })?;
    if previous_tx.compute_txid() != expected.outpoint().txid || previous_output != witness_utxo {
        return Err(PolicyError::new(
            "vultisig_psbt_input",
            format!("VIN{index} non_witness_utxo conflicts with the exact input policy"),
        ));
    }
    Ok(())
}

fn implied_fee_sats(psbt: &Psbt, policy: &BitcoinSpendPolicy) -> Result<u64, PolicyError> {
    let total_input_sats = policy.inputs().iter().try_fold(0u64, |total, input| {
        total
            .checked_add(input.value_sats())
            .ok_or_else(|| PolicyError::new("vultisig_fee", "Bitcoin input value sum overflow"))
    })?;
    let total_output_sats = psbt
        .unsigned_tx
        .output
        .iter()
        .try_fold(0u64, |total, output| {
            total.checked_add(output.value.to_sat()).ok_or_else(|| {
                PolicyError::new("vultisig_fee", "Bitcoin output value sum overflow")
            })
        })?;
    let fee_sats = total_input_sats
        .checked_sub(total_output_sats)
        .ok_or_else(|| {
            PolicyError::new(
                "vultisig_fee",
                "Bitcoin outputs exceed the exact independently observed input value",
            )
        })?;
    if fee_sats == 0 || fee_sats > policy.max_fee_sats() {
        return Err(PolicyError::new(
            "vultisig_fee",
            format!(
                "implied fee {fee_sats} sats is outside 1..={} sats",
                policy.max_fee_sats()
            ),
        ));
    }
    Ok(fee_sats)
}

fn derive_signing_hashes(
    psbt: &Psbt,
    policy: &BitcoinSpendPolicy,
) -> Result<Vec<[u8; 32]>, PolicyError> {
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let mut signing_hashes = Vec::with_capacity(policy.inputs().len());
    for (index, expected) in policy.inputs().iter().enumerate() {
        let sighash = cache
            .p2wpkh_signature_hash(
                index,
                policy.custody_script_pubkey(),
                Amount::from_sat(expected.value_sats()),
                EcdsaSighashType::All,
            )
            .map_err(|error| {
                PolicyError::new(
                    "vultisig_hash_derivation",
                    format!("failed to derive VIN{index} BIP-143 SIGHASH_ALL: {error}"),
                )
            })?;
        signing_hashes.push(sighash.to_byte_array());
    }
    Ok(signing_hashes)
}

fn compute_policy_id(provenance_id: [u8; 32], max_fee_sats: u64) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(POLICY_ID_DOMAIN.len() + 32 + 8 + 8);
    preimage.extend_from_slice(&(POLICY_ID_DOMAIN.len() as u64).to_be_bytes());
    preimage.extend_from_slice(POLICY_ID_DOMAIN);
    preimage.extend_from_slice(&provenance_id);
    preimage.extend_from_slice(&max_fee_sats.to_be_bytes());
    sha256::Hash::hash(&preimage).to_byte_array()
}

/// Run the full key-free Vultisig policy, then consume the existing custody
/// authorization one-shot and return both immutable receipts.
///
/// The order is load-bearing: transaction policy validation and local signing
/// hash derivation happen before custody-core consumes the RIC/ACC one-shot.
/// No threshold-signing call is present in this crate.
///
/// # Errors
/// Returns [`AdapterError::Policy`] before one-shot consumption for a PSBT
/// policy failure, [`AdapterError::Provenance`] when the finalized inventory is
/// stale or unavailable, or [`AdapterError::Custody`] for the existing
/// certificate, output-binding, replay, or persistence gate.
async fn authorize_vultisig_btc_spend<S: ReplayStore>(
    ctx: &BindContext,
    replay: &S,
    config: CustodyConfig<'_>,
    policy_source: &FinalizedBitcoinPolicySource,
    policy: &BitcoinSpendPolicy,
    now_unix: i64,
) -> Result<AuthorizedBitcoinSpend, AdapterError> {
    if ctx.chain != ChainId::Btc {
        return Err(PolicyError::new(
            "vultisig_chain",
            "Vultisig Bitcoin adapter refuses non-BTC custody chains",
        )
        .into());
    }
    let policy_approval = validate_and_derive_signing_hashes(&ctx.psbt, policy)?;
    policy_source.assert_current(policy.provenance()?).await?;
    let custody = authorize_certified_btc_spend(
        ctx,
        replay,
        config,
        policy.custody_script_pubkey(),
        now_unix,
    )
    .await?;
    Ok(AuthorizedBitcoinSpend {
        policy: policy_approval,
        custody,
        policy_source: policy_source.clone(),
    })
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]

    use super::*;
    use alloy_primitives::Address;
    use bitcoin::absolute::LockTime;
    use bitcoin::blockdata::constants::ChainHash;

    use bitcoin::psbt::Psbt;
    use bitcoin::sighash::EcdsaSighashType;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, Sequence, Transaction, TxIn, TxOut, Txid, WPubkeyHash, Witness};
    use xindex_chain_utxo::finalized_inventory::{
        FinalizedBitcoinBlock, FinalizedBitcoinInventoryTestHarness, FinalizedBitcoinOutput,
        InventoryError, MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
    };
    use xindex_custody_core::btc_bind::canonical_op_return_script;
    use xindex_custody_core::gates::CustodyConfig;
    use xindex_custody_core::prepare::BindContext;
    use xindex_custody_core::replay::InMemoryReplayStore;
    use xindex_shared::intent::IntentPolicy;

    const NOW: i64 = 1_750_000_000;
    const MEMO: &[u8] = b"=:ETH.USDT:0xrecipient:990000";

    fn p2wpkh(tag: u8) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([tag; 20]))
    }

    fn outpoint(tag: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([tag; 32]),
            vout,
        }
    }

    fn policy_for_custody(custody_script_pubkey: ScriptBuf) -> BitcoinSpendPolicy {
        BitcoinSpendPolicy::new_testnet4_fixture(
            ChainHash::TESTNET4,
            vec![
                BitcoinInputPolicy::new(outpoint(0x11, 1), 120_000).expect("input 0"),
                BitcoinInputPolicy::new(outpoint(0x22, 2), 80_000).expect("input 1"),
            ],
            custody_script_pubkey,
            10_000,
        )
        .expect("policy")
    }

    fn policy() -> BitcoinSpendPolicy {
        policy_for_custody(p2wpkh(0xcc))
    }

    async fn finalized_policy_for_custody(
        custody_script_pubkey: ScriptBuf,
    ) -> (
        FinalizedBitcoinInventoryTestHarness,
        FinalizedBitcoinPolicySource,
        BitcoinSpendPolicy,
    ) {
        let store = FinalizedBitcoinInventoryTestHarness::in_memory(
            "vultisig-adapter-test",
            custody_script_pubkey.clone(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect("inventory");
        let source = store.policy_source();
        let block_100 = FinalizedBitcoinBlock::new(
            100,
            bitcoin::BlockHash::from_byte_array([100; 32]),
            bitcoin::BlockHash::from_byte_array([99; 32]),
            vec![
                FinalizedBitcoinOutput::new(
                    outpoint(0x11, 1),
                    120_000,
                    custody_script_pubkey.clone(),
                )
                .expect("input 0"),
                FinalizedBitcoinOutput::new(outpoint(0x22, 2), 80_000, custody_script_pubkey)
                    .expect("input 1"),
            ],
            Vec::new(),
        )
        .expect("block 100");
        store
            .commit_block(block_100.clone())
            .await
            .expect("block 100");
        let mut parent_hash = block_100.block_hash();
        for height in 101u64..=105 {
            let tag = u8::try_from(height).expect("test height");
            let block_hash = bitcoin::BlockHash::from_byte_array([tag; 32]);
            store
                .commit_block(
                    FinalizedBitcoinBlock::new(
                        height,
                        block_hash,
                        parent_hash,
                        Vec::new(),
                        Vec::new(),
                    )
                    .expect("confirmation block"),
                )
                .await
                .expect("confirmation block");
            parent_hash = block_hash;
        }
        let inputs = source
            .issue_policy_inputs(&[outpoint(0x11, 1), outpoint(0x22, 2)])
            .await
            .expect("finalized policy inputs");
        let policy = BitcoinSpendPolicy::new_testnet4(inputs, 10_000).expect("policy");
        (store, source, policy)
    }

    fn psbt_for(policy: &BitcoinSpendPolicy) -> Psbt {
        let inputs = policy
            .inputs()
            .iter()
            .map(|input| TxIn {
                previous_output: input.outpoint(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect();
        let outputs = vec![
            TxOut {
                value: Amount::from_sat(150_000),
                script_pubkey: p2wpkh(0xaa),
            },
            TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: policy.custody_script_pubkey().clone(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: canonical_op_return_script(MEMO).expect("memo"),
            },
        ];
        let mut psbt = Psbt::from_unsigned_tx(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        })
        .expect("psbt");
        for (metadata, input) in psbt.inputs.iter_mut().zip(policy.inputs()) {
            metadata.witness_utxo = Some(TxOut {
                value: Amount::from_sat(input.value_sats()),
                script_pubkey: policy.custody_script_pubkey().clone(),
            });
            metadata.sighash_type = Some(EcdsaSighashType::All.into());
        }
        psbt
    }

    fn expect_code(psbt: &Psbt, policy: &BitcoinSpendPolicy, code: &str) {
        let error = validate_and_derive_signing_hashes(psbt, policy).expect_err("must reject");
        assert_eq!(error.code(), code);
    }

    fn fixed_aggregate_public_key() -> bitcoin::CompressedPublicKey {
        let public_key_bytes = alloy_primitives::hex::decode(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .expect("generator public key");
        bitcoin::CompressedPublicKey::from_slice(&public_key_bytes).expect("aggregate key")
    }

    fn finalized_fixture_for_policy(
        policy: &BitcoinSpendPolicy,
    ) -> (Transaction, BitcoinPolicyApproval) {
        // Verification-only fixed tuple: signature bytes copied from an
        // upstream secp256k1 debug/round-trip fixture are locally verified for
        // message = 1 and aggregate public key = G. No private key or signing
        // operation occurs.
        let compact_signature = alloy_primitives::hex::decode(
            "6673ffad2147741f04772b6f921f0ba6af0c1e77fc439e65c36dedf4092e8898\
             4c1a971652e0ada880120ef8025e709fff2080c4a39aae068d12eed009b68c89",
        )
        .expect("fixed compact signature");
        let signature = bitcoin::ecdsa::Signature::sighash_all(
            bitcoin::secp256k1::ecdsa::Signature::from_compact(&compact_signature)
                .expect("fixed signature"),
        )
        .to_vec();
        let public_key_bytes = alloy_primitives::hex::decode(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .expect("generator public key");
        let mut signing_hash = [0u8; 32];
        signing_hash[31] = 1;

        let psbt = psbt_for(policy);
        let mut approval =
            validate_and_derive_signing_hashes(&psbt, policy).expect("approved fixture");
        approval.signing_hashes.fill(signing_hash);
        let mut transaction = psbt.unsigned_tx;
        for input in &mut transaction.input {
            input.witness =
                Witness::from_slice(&[signature.as_slice(), public_key_bytes.as_slice()]);
        }
        (transaction, approval)
    }

    fn finalized_fixture() -> (Transaction, BitcoinPolicyApproval) {
        let public_key = fixed_aggregate_public_key();
        let policy = policy_for_custody(ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash()));
        finalized_fixture_for_policy(&policy)
    }

    #[test]
    fn policy_requires_exact_testnet4_chain_hash() {
        let input = BitcoinInputPolicy::new(outpoint(0x11, 0), 1).expect("input");
        for wrong_chain in [
            ChainHash::BITCOIN,
            ChainHash::TESTNET3,
            ChainHash::SIGNET,
            ChainHash::REGTEST,
        ] {
            let error = BitcoinSpendPolicy::new_testnet4_fixture(
                wrong_chain,
                vec![input.clone()],
                p2wpkh(0xcc),
                1,
            )
            .expect_err("non-Testnet4 chain identity must fail");
            assert_eq!(error.code(), "vultisig_network");
        }

        let policy = BitcoinSpendPolicy::new_testnet4_fixture(
            ChainHash::TESTNET4,
            vec![input],
            p2wpkh(0xcc),
            1,
        )
        .expect("exact Testnet4 chain hash");
        assert_eq!(policy.chain_hash(), ChainHash::TESTNET4);
    }

    #[test]
    fn honest_psbt_derives_every_hash_and_exact_fee() {
        let policy = policy();
        let psbt = psbt_for(&policy);
        let approval =
            validate_and_derive_signing_hashes(&psbt, &policy).expect("honest PSBT must pass");
        assert_eq!(approval.chain_hash(), ChainHash::TESTNET4);
        assert_eq!(approval.fee_sats(), 1_000);
        let signing_hashes: Vec<_> = approval
            .signing_hashes()
            .iter()
            .map(alloy_primitives::hex::encode)
            .collect();
        assert_eq!(
            signing_hashes,
            [
                "0c8a7b8367a21bb137e1a50a4fb6d110eec0ef4c3929b37535656d60bcb6ebc8",
                "6b826157b987f317ad4389ebc082e822d243253e398741468c87d299ca5f613d",
            ]
        );
        assert_eq!(
            approval.unsigned_txid(),
            psbt.unsigned_tx.compute_txid().to_byte_array()
        );
    }

    #[test]
    fn finalized_transaction_returns_exact_committed_ids() {
        let (transaction, approval) = finalized_fixture();
        let finalized = approval
            .validate_finalized_transaction_bytes(serialize(&transaction))
            .expect("fixed verification fixture must pass");
        assert_eq!(finalized.chain_hash(), ChainHash::TESTNET4);
        assert_eq!(finalized.txid(), transaction.compute_txid().to_byte_array());
        assert_eq!(
            finalized.wtxid(),
            transaction.compute_wtxid().to_byte_array()
        );
        assert_eq!(finalized.input_count(), 2);
    }

    #[test]
    fn finalized_capability_owns_exact_canonical_bytes_after_authorization() {
        let (transaction, approval) = finalized_fixture();
        let canonical_bytes = serialize(&transaction);
        let mut caller_copy = canonical_bytes.clone();
        let validated = approval
            .validate_finalized_transaction_bytes(canonical_bytes.clone())
            .expect("canonical fixed transaction must pass");

        caller_copy[0] ^= 0x01;
        assert_eq!(validated.transaction_bytes(), canonical_bytes);
        assert_eq!(validated.txid(), transaction.compute_txid().to_byte_array());
        assert_eq!(
            validated.wtxid(),
            transaction.compute_wtxid().to_byte_array()
        );

        let mut trailing_bytes = canonical_bytes;
        trailing_bytes.push(0x00);
        let error = approval
            .validate_finalized_transaction_bytes(trailing_bytes)
            .expect_err("trailing bytes must not be detached from the validated transaction");
        assert_eq!(error.code(), "vultisig_final_encoding");
    }

    #[test]
    fn finalized_transaction_rejects_mutated_non_witness_body() {
        let (mut transaction, approval) = finalized_fixture();
        transaction.output[0].value = Amount::from_sat(149_999);
        let error = approval
            .validate_finalized_transaction_bytes(serialize(&transaction))
            .expect_err("mutated settlement amount must fail");
        assert_eq!(error.code(), "vultisig_final_txid");
    }

    #[test]
    fn finalized_transaction_requires_one_complete_p2wpkh_witness_per_input() {
        let (mut transaction, approval) = finalized_fixture();
        transaction.input[1].witness = Witness::new();
        let error = approval
            .validate_finalized_transaction_bytes(serialize(&transaction))
            .expect_err("missing aggregate signature witness must fail");
        assert_eq!(error.code(), "vultisig_final_witness");

        let mut elements = transaction.input[0]
            .witness
            .iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        elements.push(vec![0x01]);
        transaction.input[0].witness = Witness::from_slice(&elements);
        let error = approval
            .validate_finalized_transaction_bytes(serialize(&transaction))
            .expect_err("extra witness stack items must fail");
        assert_eq!(error.code(), "vultisig_final_witness");
    }

    #[test]
    fn finalized_transaction_requires_sighash_all_witness_signatures() {
        let (mut transaction, approval) = finalized_fixture();
        let mut elements = transaction.input[0]
            .witness
            .iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        *elements[0].last_mut().expect("sighash byte") = EcdsaSighashType::Single as u8;
        transaction.input[0].witness =
            Witness::from_slice(&[elements[0].as_slice(), elements[1].as_slice()]);
        let error = approval
            .validate_finalized_transaction_bytes(serialize(&transaction))
            .expect_err("non-ALL aggregate signature must fail");
        assert_eq!(error.code(), "vultisig_final_sighash");

        *elements[0].last_mut().expect("sighash byte") =
            EcdsaSighashType::AllPlusAnyoneCanPay as u8;
        transaction.input[0].witness =
            Witness::from_slice(&[elements[0].as_slice(), elements[1].as_slice()]);
        let error = approval
            .validate_finalized_transaction_bytes(serialize(&transaction))
            .expect_err("ANYONECANPAY aggregate signature must fail");
        assert_eq!(error.code(), "vultisig_final_sighash");
    }

    #[test]
    fn finalized_transaction_requires_the_authorized_aggregate_public_key() {
        let (mut transaction, approval) = finalized_fixture();
        let mut elements = transaction.input[0]
            .witness
            .iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        elements[1][0] = 0x03;
        transaction.input[0].witness =
            Witness::from_slice(&[elements[0].as_slice(), elements[1].as_slice()]);
        let error = approval
            .validate_finalized_transaction_bytes(serialize(&transaction))
            .expect_err("substituted aggregate public key must fail");
        assert_eq!(error.code(), "vultisig_final_pubkey");
    }

    #[test]
    fn finalized_transaction_rejects_uncompressed_witness_public_key() {
        let (mut transaction, approval) = finalized_fixture();
        let mut elements = transaction.input[0]
            .witness
            .iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        elements[1] = bitcoin::secp256k1::PublicKey::from_slice(&elements[1])
            .expect("fixed aggregate public key")
            .serialize_uncompressed()
            .to_vec();
        transaction.input[0].witness =
            Witness::from_slice(&[elements[0].as_slice(), elements[1].as_slice()]);
        let error = approval
            .validate_finalized_transaction_bytes(serialize(&transaction))
            .expect_err("uncompressed witness public key must fail");
        assert_eq!(error.code(), "vultisig_final_pubkey");
    }

    #[test]
    fn finalized_transaction_verifies_each_aggregate_signature() {
        let (mut transaction, approval) = finalized_fixture();
        let mut elements = transaction.input[1]
            .witness
            .iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        elements[0][10] ^= 0x01;
        bitcoin::ecdsa::Signature::from_slice(&elements[0])
            .expect("scalar mutation must remain strict DER");
        transaction.input[1].witness =
            Witness::from_slice(&[elements[0].as_slice(), elements[1].as_slice()]);
        let error = approval
            .validate_finalized_transaction_bytes(serialize(&transaction))
            .expect_err("altered aggregate signature scalar must fail verification");
        assert_eq!(error.code(), "vultisig_final_signature");

        elements[0] = vec![0x30, 0x01, 0x00, EcdsaSighashType::All as u8];
        transaction.input[1].witness =
            Witness::from_slice(&[elements[0].as_slice(), elements[1].as_slice()]);
        let error = approval
            .validate_finalized_transaction_bytes(serialize(&transaction))
            .expect_err("malformed DER aggregate signature must fail parsing");
        assert_eq!(error.code(), "vultisig_final_signature");
    }

    #[test]
    fn finalized_transaction_rejects_high_s_aggregate_signature() {
        let (mut transaction, approval) = finalized_fixture();
        // Strict-DER high-S counterpart of the fixed low-S fixture. It is
        // derived as `curve_order - s`; no key or signing operation is used.
        let high_s = alloy_primitives::hex::decode(
            "304502206673ffad2147741f04772b6f921f0ba6af0c1e77fc439e65c36dedf4092e8898\
             022100b3e568e9ad1f52577fedf107fda18f5ebb8e5c220badf23532bf6fbcc67fb4b8\
             01",
        )
        .expect("fixed tuple's high-S counterpart");
        let public_key = transaction.input[0]
            .witness
            .iter()
            .nth(1)
            .expect("aggregate public key")
            .to_vec();
        transaction.input[0].witness =
            Witness::from_slice(&[high_s.as_slice(), public_key.as_slice()]);
        let error = approval
            .validate_finalized_transaction_bytes(serialize(&transaction))
            .expect_err("non-canonical high-S aggregate signature must fail");
        assert_eq!(error.code(), "vultisig_final_signature");
    }

    #[test]
    fn finalized_transaction_uses_the_matching_hash_for_each_input() {
        let (transaction, mut approval) = finalized_fixture();
        approval.signing_hashes[1][0] ^= 0x01;
        let error = approval
            .validate_finalized_transaction_bytes(serialize(&transaction))
            .expect_err("VIN1 signature must not be verified against the VIN0 hash");
        assert_eq!(error.code(), "vultisig_final_signature");
        assert!(
            error.message().starts_with("VIN1 "),
            "wrong input rejected: {error}"
        );
    }

    #[test]
    fn policy_rejects_empty_duplicate_zero_and_non_p2wpkh_inputs() {
        let empty = BitcoinSpendPolicy::new_testnet4_fixture(
            ChainHash::TESTNET4,
            Vec::new(),
            p2wpkh(0xcc),
            1,
        );
        assert_eq!(empty.expect_err("empty").code(), "vultisig_policy_inputs");

        let exact = BitcoinInputPolicy::new(outpoint(0x11, 0), 1).expect("input");
        let duplicate = BitcoinSpendPolicy::new_testnet4_fixture(
            ChainHash::TESTNET4,
            vec![exact.clone(), exact],
            p2wpkh(0xcc),
            1,
        );
        assert_eq!(
            duplicate.expect_err("duplicate").code(),
            "vultisig_policy_inputs"
        );

        assert_eq!(
            BitcoinInputPolicy::new(outpoint(0x11, 0), 0)
                .expect_err("zero")
                .code(),
            "vultisig_policy_input"
        );
        assert_eq!(
            BitcoinSpendPolicy::new_testnet4_fixture(
                ChainHash::TESTNET4,
                vec![BitcoinInputPolicy::new(outpoint(0x11, 0), 1).expect("input")],
                ScriptBuf::new(),
                1,
            )
            .expect_err("script")
            .code(),
            "vultisig_policy_custody"
        );
        assert_eq!(
            BitcoinSpendPolicy::new_testnet4_fixture(
                ChainHash::TESTNET4,
                vec![BitcoinInputPolicy::new(outpoint(0x11, 0), 1).expect("input")],
                p2wpkh(0xcc),
                0,
            )
            .expect_err("fee")
            .code(),
            "vultisig_policy_fee"
        );
        assert_eq!(
            BitcoinSpendPolicy::new_testnet4_fixture(
                ChainHash::TESTNET4,
                vec![BitcoinInputPolicy::new(outpoint(0x11, 0), 1).expect("input")],
                p2wpkh(0xcc),
                ChainId::Btc.max_redeem_fee_base_units() + 1,
            )
            .expect_err("protocol fee cap")
            .code(),
            "vultisig_policy_fee"
        );
    }

    #[test]
    fn version_and_locktime_mutations_reject() {
        let policy = policy();
        let mut psbt_version = psbt_for(&policy);
        psbt_version.version = 2;
        expect_code(&psbt_version, &policy, "vultisig_psbt_version");

        let mut version = psbt_for(&policy);
        version.unsigned_tx.version = Version::ONE;
        expect_code(&version, &policy, "vultisig_tx_version");

        let mut locktime = psbt_for(&policy);
        locktime.unsigned_tx.lock_time = LockTime::from_consensus(1);
        expect_code(&locktime, &policy, "vultisig_tx_locktime");
    }

    #[test]
    fn input_set_and_order_mutations_reject() {
        let policy = policy();
        let mut wrong = psbt_for(&policy);
        wrong.unsigned_tx.input[0].previous_output = outpoint(0x99, 9);
        expect_code(&wrong, &policy, "vultisig_tx_inputs");

        let mut reordered = psbt_for(&policy);
        reordered.unsigned_tx.input.swap(0, 1);
        reordered.inputs.swap(0, 1);
        expect_code(&reordered, &policy, "vultisig_tx_inputs");

        let mut missing = psbt_for(&policy);
        let _ = missing.unsigned_tx.input.pop();
        let _ = missing.inputs.pop();
        expect_code(&missing, &policy, "vultisig_tx_inputs");
    }

    #[test]
    fn rbf_or_nonfinal_sequence_rejects() {
        let policy = policy();
        let mut psbt = psbt_for(&policy);
        psbt.unsigned_tx.input[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
        expect_code(&psbt, &policy, "vultisig_tx_sequence");

        let mut nonfinal = psbt_for(&policy);
        nonfinal.unsigned_tx.input[0].sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;
        expect_code(&nonfinal, &policy, "vultisig_tx_sequence");
    }

    #[test]
    fn witness_utxo_value_script_and_presence_are_exact() {
        let policy = policy();
        let mut wrong_value = psbt_for(&policy);
        wrong_value.inputs[0]
            .witness_utxo
            .as_mut()
            .expect("witness")
            .value = Amount::from_sat(120_001);
        expect_code(&wrong_value, &policy, "vultisig_psbt_input");

        let mut wrong_script = psbt_for(&policy);
        wrong_script.inputs[0]
            .witness_utxo
            .as_mut()
            .expect("witness")
            .script_pubkey = p2wpkh(0xee);
        expect_code(&wrong_script, &policy, "vultisig_psbt_input");

        let mut missing = psbt_for(&policy);
        missing.inputs[0].witness_utxo = None;
        expect_code(&missing, &policy, "vultisig_psbt_input");

        let mut conflicting_previous = psbt_for(&policy);
        conflicting_previous.inputs[0].non_witness_utxo = Some(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: Amount::from_sat(120_000),
                script_pubkey: policy.custody_script_pubkey().clone(),
            }],
        });
        expect_code(&conflicting_previous, &policy, "vultisig_psbt_input");
    }

    #[test]
    fn sighash_all_must_be_explicit() {
        let policy = policy();
        let mut missing = psbt_for(&policy);
        missing.inputs[0].sighash_type = None;
        expect_code(&missing, &policy, "vultisig_sighash");

        let mut single = psbt_for(&policy);
        single.inputs[0].sighash_type = Some(EcdsaSighashType::Single.into());
        expect_code(&single, &policy, "vultisig_sighash");
    }

    #[test]
    fn partially_or_finalized_psbt_rejects() {
        let policy = policy();
        let mut psbt = psbt_for(&policy);
        psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[b"unexpected"]));
        expect_code(&psbt, &policy, "vultisig_psbt_signed");

        let mut script_path = psbt_for(&policy);
        script_path.inputs[0].witness_script = Some(ScriptBuf::new());
        expect_code(&script_path, &policy, "vultisig_psbt_input");
    }

    #[test]
    fn fee_must_be_positive_and_below_absolute_cap() {
        let policy = policy();
        let mut zero = psbt_for(&policy);
        zero.unsigned_tx.output[1].value = Amount::from_sat(50_000);
        expect_code(&zero, &policy, "vultisig_fee");

        let mut high = psbt_for(&policy);
        high.unsigned_tx.output[1].value = Amount::from_sat(39_000);
        expect_code(&high, &policy, "vultisig_fee");

        let mut underflow = psbt_for(&policy);
        underflow.unsigned_tx.output[1].value = Amount::from_sat(60_000);
        expect_code(&underflow, &policy, "vultisig_fee");
    }

    fn custody_config(intent_policy: &IntentPolicy) -> CustodyConfig<'_> {
        CustodyConfig {
            chain_id: 1,
            verifying_contract: Address::repeat_byte(0x42),
            intent_policy,
        }
    }

    #[tokio::test]
    async fn full_adapter_reaches_custody_gate_only_after_policy_passes() {
        let (_store, source, policy) = finalized_policy_for_custody(p2wpkh(0xcc)).await;
        let runtime = VultisigBitcoinPolicyRuntime::from_test_source(source);
        let intent_policy = IntentPolicy {
            signer_whitelist: Vec::new(),
            intent_quorum: 1,
            ric_max_age_secs: 3_600,
        };
        let replay = InMemoryReplayStore::new();
        let valid = BindContext {
            chain: ChainId::Btc,
            psbt: psbt_for(&policy),
            ric: None,
            acc: None,
        };
        let error = runtime
            .authorize(
                &valid,
                &replay,
                custody_config(&intent_policy),
                &policy,
                NOW,
            )
            .await
            .expect_err("missing RIC must fail at custody boundary");
        assert!(matches!(error, AdapterError::Custody(_)));

        let mut invalid = valid;
        invalid.psbt.unsigned_tx.version = Version::ONE;
        let error = runtime
            .authorize(
                &invalid,
                &replay,
                custody_config(&intent_policy),
                &policy,
                NOW,
            )
            .await
            .expect_err("invalid tx must fail at policy boundary");
        assert!(matches!(error, AdapterError::Policy(_)));
    }

    #[tokio::test]
    async fn stale_reorged_provenance_rejects_before_custody_one_shot() {
        let custody_script = p2wpkh(0xcc);
        let store = FinalizedBitcoinInventoryTestHarness::in_memory(
            "vultisig-authorization-test",
            custody_script.clone(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect("inventory");
        let source = store.policy_source();
        let funding = outpoint(0x11, 1);
        let block_100 = FinalizedBitcoinBlock::new(
            100,
            bitcoin::BlockHash::from_byte_array([100; 32]),
            bitcoin::BlockHash::from_byte_array([99; 32]),
            vec![
                FinalizedBitcoinOutput::new(funding, 200_000, custody_script)
                    .expect("funding output"),
            ],
            Vec::new(),
        )
        .expect("block 100");
        store
            .commit_block(block_100.clone())
            .await
            .expect("block 100");
        let mut parent_hash = block_100.block_hash();
        for height in 101u64..=105 {
            let tag = u8::try_from(height).expect("test height");
            let block_hash = bitcoin::BlockHash::from_byte_array([tag; 32]);
            store
                .commit_block(
                    FinalizedBitcoinBlock::new(
                        height,
                        block_hash,
                        parent_hash,
                        Vec::new(),
                        Vec::new(),
                    )
                    .expect("confirmation block"),
                )
                .await
                .expect("confirmation block");
            parent_hash = block_hash;
        }
        let inputs = source
            .issue_policy_inputs(&[funding])
            .await
            .expect("finalized policy inputs");
        let policy = BitcoinSpendPolicy::new_testnet4(inputs, 10_000).expect("policy");
        let ctx = BindContext {
            chain: ChainId::Btc,
            psbt: psbt_for(&policy),
            ric: None,
            acc: None,
        };
        store
            .rollback_to(100, block_100.block_hash())
            .await
            .expect("rollback");

        let intent_policy = IntentPolicy {
            signer_whitelist: Vec::new(),
            intent_quorum: 1,
            ric_max_age_secs: 3_600,
        };
        let error = authorize_vultisig_btc_spend(
            &ctx,
            &InMemoryReplayStore::new(),
            custody_config(&intent_policy),
            &source,
            &policy,
            NOW,
        )
        .await
        .expect_err("stale provenance must reject before missing RIC");
        assert!(matches!(
            error,
            AdapterError::Provenance(InventoryError::Stale(_))
        ));
    }

    #[tokio::test]
    async fn final_handoff_validates_bytes_then_rechecks_provenance() {
        let public_key = fixed_aggregate_public_key();
        let (store, source, policy) =
            finalized_policy_for_custody(ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash())).await;
        let (transaction, approval) = finalized_fixture_for_policy(&policy);
        store
            .rollback_to(100, bitcoin::BlockHash::from_byte_array([100; 32]))
            .await
            .expect("rollback");

        let malformed = validate_finalized_handoff(&source, &approval, vec![0xff])
            .await
            .expect_err("malformed final bytes must reject before the handoff recheck");
        assert!(matches!(malformed, AdapterError::Policy(_)));

        let stale = validate_finalized_handoff(&source, &approval, serialize(&transaction))
            .await
            .expect_err("valid final bytes still require current provenance before handoff");
        assert!(matches!(
            stale,
            AdapterError::Provenance(InventoryError::Stale(_))
        ));
    }

    #[tokio::test]
    async fn policy_and_approval_carry_provenance_and_versioned_policy_ids() {
        let (_store, _source, policy) = finalized_policy_for_custody(p2wpkh(0xcc)).await;
        let provenance = policy.provenance().expect("production provenance").clone();
        let repriced = BitcoinSpendPolicy::new_testnet4(provenance, 9_000)
            .expect("same provenance with stricter fee ceiling");
        assert_eq!(policy.provenance_id(), repriced.provenance_id());
        assert_ne!(policy.policy_id(), repriced.policy_id());

        let approval = validate_and_derive_signing_hashes(&psbt_for(&policy), &policy)
            .expect("policy approval");
        assert_eq!(approval.provenance_id(), policy.provenance_id());
        assert_eq!(approval.policy_id(), policy.policy_id());
    }

    #[tokio::test]
    async fn non_btc_chain_rejects_before_policy_or_custody() {
        let (_store, source, policy) = finalized_policy_for_custody(p2wpkh(0xcc)).await;
        let intent_policy = IntentPolicy {
            signer_whitelist: Vec::new(),
            intent_quorum: 1,
            ric_max_age_secs: 3_600,
        };
        let ctx = BindContext {
            chain: ChainId::Ltc,
            psbt: psbt_for(&policy),
            ric: None,
            acc: None,
        };
        let error = authorize_vultisig_btc_spend(
            &ctx,
            &InMemoryReplayStore::new(),
            custody_config(&intent_policy),
            &source,
            &policy,
            NOW,
        )
        .await
        .expect_err("LTC must reject");
        assert_eq!(error.code(), "vultisig_chain");
    }
}
