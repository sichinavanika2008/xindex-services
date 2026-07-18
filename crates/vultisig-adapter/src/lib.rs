//! Key-free Xindex policy boundary for Vultisig Bitcoin custody.
//!
//! This crate deliberately contains no Vultisig SDK, network client, vault,
//! share, credential, signing, or broadcast capability. It validates the full
//! Bitcoin PSBT fields that Xindex must bind before a DKLS participant may
//! release a signing share, derives every per-input `SIGHASH_ALL` digest from
//! that PSBT, and then composes with custody-node's existing RIC/ACC one-shot
//! authorization.

use std::fmt;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash as _;
use bitcoin::psbt::{Input as PsbtInput, Psbt, PsbtSighashType};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut};
use xindex_custody_core::btc_authorize::BtcSpendAuthorization;
use xindex_custody_core::gates::{CustodyConfig, GateRejection};
use xindex_custody_core::prepare::BindContext;
use xindex_custody_core::replay::ReplayStore;
use xindex_custody_node::btc::authorize_certified_btc_spend;
use xindex_shared::chain_registry::ChainId;

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
    pub fn new(outpoint: OutPoint, value_sats: u64) -> Result<Self, PolicyError> {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinSpendPolicy {
    inputs: Vec<BitcoinInputPolicy>,
    custody_script_pubkey: ScriptBuf,
    max_fee_sats: u64,
}

impl BitcoinSpendPolicy {
    /// Construct a policy over the complete ordered input set.
    ///
    /// # Errors
    /// Returns a fail-closed policy error for an empty or duplicate input set,
    /// a non-P2WPKH custody script, or a zero fee ceiling.
    pub fn new(
        inputs: Vec<BitcoinInputPolicy>,
        custody_script_pubkey: ScriptBuf,
        max_fee_sats: u64,
    ) -> Result<Self, PolicyError> {
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
        Ok(Self {
            inputs,
            custody_script_pubkey,
            max_fee_sats,
        })
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
}

/// Immutable result of full PSBT policy validation and local hash derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinPolicyApproval {
    unsigned_txid: [u8; 32],
    fee_sats: u64,
    signing_hashes: Vec<[u8; 32]>,
}

impl BitcoinPolicyApproval {
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
}

/// Receipt exposed only after both the Vultisig policy and custody one-shot pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedBitcoinSpend {
    policy: BitcoinPolicyApproval,
    custody: BtcSpendAuthorization,
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

/// A policy rejection or the existing custody authorization rejection.
#[derive(Debug, Clone)]
pub enum AdapterError {
    /// The decoded Bitcoin transaction failed Xindex's Vultisig policy.
    Policy(PolicyError),
    /// RIC/ACC verification, output binding, or one-shot consumption failed.
    Custody(GateRejection),
}

impl AdapterError {
    /// Stable machine-readable error code from the rejecting boundary.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Policy(error) => error.code(),
            Self::Custody(error) => error.code,
        }
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(error) => error.fmt(formatter),
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
        unsigned_txid: psbt.unsigned_tx.compute_txid().to_byte_array(),
        fee_sats,
        signing_hashes,
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

/// Run the full key-free Vultisig policy, then consume the existing custody
/// authorization one-shot and return both immutable receipts.
///
/// The order is load-bearing: transaction policy validation and local signing
/// hash derivation happen before custody-core consumes the RIC/ACC one-shot.
/// No threshold-signing call is present in this crate.
///
/// # Errors
/// Returns [`AdapterError::Policy`] before one-shot consumption for a PSBT
/// policy failure, or [`AdapterError::Custody`] for the existing certificate,
/// output-binding, replay, or persistence gate.
pub async fn authorize_vultisig_btc_spend<S: ReplayStore>(
    ctx: &BindContext,
    replay: &S,
    config: CustodyConfig<'_>,
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
    })
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]

    use super::*;
    use alloy_primitives::Address;
    use bitcoin::absolute::LockTime;
    use bitcoin::psbt::Psbt;
    use bitcoin::sighash::EcdsaSighashType;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, Sequence, Transaction, TxIn, TxOut, Txid, WPubkeyHash, Witness};
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

    fn policy() -> BitcoinSpendPolicy {
        BitcoinSpendPolicy::new(
            vec![
                BitcoinInputPolicy::new(outpoint(0x11, 1), 120_000).expect("input 0"),
                BitcoinInputPolicy::new(outpoint(0x22, 2), 80_000).expect("input 1"),
            ],
            p2wpkh(0xcc),
            10_000,
        )
        .expect("policy")
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

    #[test]
    fn honest_psbt_derives_every_hash_and_exact_fee() {
        let policy = policy();
        let psbt = psbt_for(&policy);
        let approval =
            validate_and_derive_signing_hashes(&psbt, &policy).expect("honest PSBT must pass");
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
    fn policy_rejects_empty_duplicate_zero_and_non_p2wpkh_inputs() {
        let empty = BitcoinSpendPolicy::new(Vec::new(), p2wpkh(0xcc), 1);
        assert_eq!(empty.expect_err("empty").code(), "vultisig_policy_inputs");

        let exact = BitcoinInputPolicy::new(outpoint(0x11, 0), 1).expect("input");
        let duplicate = BitcoinSpendPolicy::new(vec![exact.clone(), exact], p2wpkh(0xcc), 1);
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
            BitcoinSpendPolicy::new(
                vec![BitcoinInputPolicy::new(outpoint(0x11, 0), 1).expect("input")],
                ScriptBuf::new(),
                1,
            )
            .expect_err("script")
            .code(),
            "vultisig_policy_custody"
        );
        assert_eq!(
            BitcoinSpendPolicy::new(
                vec![BitcoinInputPolicy::new(outpoint(0x11, 0), 1).expect("input")],
                p2wpkh(0xcc),
                0,
            )
            .expect_err("fee")
            .code(),
            "vultisig_policy_fee"
        );
        assert_eq!(
            BitcoinSpendPolicy::new(
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
        let policy = policy();
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
        let error = authorize_vultisig_btc_spend(
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
        let error = authorize_vultisig_btc_spend(
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
    async fn non_btc_chain_rejects_before_policy_or_custody() {
        let policy = policy();
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
            &policy,
            NOW,
        )
        .await
        .expect_err("LTC must reject");
        assert_eq!(error.code(), "vultisig_chain");
    }
}
