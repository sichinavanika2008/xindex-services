//! Pure `BitGo` BTC request and transaction-policy adapter.
//!
//! This crate deliberately contains no HTTP client, access token, private-key
//! input, signing operation, approval action, or broadcast method. It builds
//! the exact public JSON payloads for `BitGo`'s multisig build/send endpoints and
//! validates every unsigned, user-signed, and `BitGo`-finalized artifact against
//! the selected native-P2WSH Xindex policy.

use std::str::FromStr;

use alloy_primitives::{keccak256, U256};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::opcodes::all::OP_CHECKMULTISIG;
use bitcoin::psbt::Psbt;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    ecdsa::Signature as BitcoinSignature, Address, Network, OutPoint, PublicKey, ScriptBuf,
    Transaction, Txid,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use xindex_custody_core::btc_bind::{bind_outputs_to_cert, canonical_op_return_script};
use xindex_custody_core::gates::CertifiedSpend;

/// `BitGo` external-chain code for native P2WSH receive/change addresses.
pub const P2WSH_EXTERNAL_CHAIN_CODE: u32 = 20;
/// Maximum standard-relay `THORChain` memo length for the reviewed BTC profile.
pub const MAX_MEMO_BYTES: usize = 80;

/// Fail-closed `BitGo` policy error with a stable machine-readable code.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}: {message}")]
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

    /// Stable policy error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Human-readable failure detail, free of secret material.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Selected `BitGo` Bitcoin asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BitGoCoin {
    /// Bitcoin mainnet. Kept for the future reviewed production route.
    Btc,
    /// Bitcoin Testnet4 in `BitGo`'s test environment.
    Tbtc4,
}

impl BitGoCoin {
    /// `BitGo` asset identifier used in the API path.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Btc => "btc",
            Self::Tbtc4 => "tbtc4",
        }
    }

    /// Bitcoin network used for address encoding.
    #[must_use]
    pub const fn network(self) -> Network {
        match self {
            Self::Btc => Network::Bitcoin,
            Self::Tbtc4 => Network::Testnet,
        }
    }
}

/// Public native-P2WSH wallet policy captured from a reviewed `BitGo` wallet.
#[derive(Debug, Clone)]
pub struct WalletPolicy {
    coin: BitGoCoin,
    wallet_id: String,
    user: PublicKey,
    backup: PublicKey,
    bitgo: PublicKey,
    witness_script: ScriptBuf,
    custody_spk: ScriptBuf,
}

impl WalletPolicy {
    /// Construct the exact 2-of-3 native-P2WSH role-key policy.
    ///
    /// # Errors
    /// Returns an error for an unsafe wallet identifier, wrong address chain,
    /// uncompressed/duplicate role keys, or a witness script that is not the
    /// canonical 2-of-3 script for exactly those three keys.
    pub fn new(
        coin: BitGoCoin,
        wallet_id: impl Into<String>,
        address_chain_code: u32,
        user: PublicKey,
        backup: PublicKey,
        bitgo: PublicKey,
        witness_script: ScriptBuf,
    ) -> Result<Self, PolicyError> {
        let wallet_id = wallet_id.into();
        if wallet_id.is_empty()
            || wallet_id.len() > 128
            || !wallet_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(PolicyError::new(
                "bitgo_wallet_id",
                "wallet id must be 1..=128 path-safe ASCII characters",
            ));
        }
        if address_chain_code != P2WSH_EXTERNAL_CHAIN_CODE {
            return Err(PolicyError::new(
                "bitgo_address_chain",
                format!("native P2WSH requires external chain code {P2WSH_EXTERNAL_CHAIN_CODE}"),
            ));
        }
        if !user.compressed || !backup.compressed || !bitgo.compressed {
            return Err(PolicyError::new(
                "bitgo_wallet_keys",
                "all three custody role keys must be compressed",
            ));
        }
        if user == backup || user == bitgo || backup == bitgo {
            return Err(PolicyError::new(
                "bitgo_wallet_keys",
                "user, backup and BitGo role keys must be distinct",
            ));
        }
        let keys = [user, backup, bitgo];
        if ordered_wallet_keys(&keys, &witness_script).is_none() {
            return Err(PolicyError::new(
                "bitgo_witness_script",
                "witness script is not canonical 2-of-3 over exactly the captured role keys",
            ));
        }
        let custody_spk = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
        Ok(Self {
            coin,
            wallet_id,
            user,
            backup,
            bitgo,
            witness_script,
            custody_spk,
        })
    }

    /// `BitGo` API route for building an unsigned wallet transaction.
    #[must_use]
    pub fn build_endpoint_path(&self) -> String {
        format!(
            "/api/v2/{}/wallet/{}/tx/build",
            self.coin.as_str(),
            self.wallet_id
        )
    }

    /// `BitGo` API route that final-signs and broadcasts a half-signed transaction.
    #[must_use]
    pub fn send_endpoint_path(&self) -> String {
        format!(
            "/api/v2/{}/wallet/{}/tx/send",
            self.coin.as_str(),
            self.wallet_id
        )
    }

    /// Selected `BitGo` Bitcoin coin.
    #[must_use]
    pub const fn coin(&self) -> BitGoCoin {
        self.coin
    }

    /// Reviewed public wallet identifier.
    #[must_use]
    pub fn wallet_id(&self) -> &str {
        &self.wallet_id
    }

    /// Captured user role public key.
    #[must_use]
    pub const fn user_key(&self) -> PublicKey {
        self.user
    }

    /// Captured offline-backup role public key.
    #[must_use]
    pub const fn backup_key(&self) -> PublicKey {
        self.backup
    }

    /// Captured `BitGo` role public key.
    #[must_use]
    pub const fn bitgo_key(&self) -> PublicKey {
        self.bitgo
    }

    /// Exact canonical wallet witness script for the reviewed address.
    #[must_use]
    pub fn witness_script(&self) -> &ScriptBuf {
        &self.witness_script
    }

    /// Native P2WSH custody scriptPubKey committed by the witness script.
    #[must_use]
    pub fn custody_script_pubkey(&self) -> &ScriptBuf {
        &self.custody_spk
    }

    fn role(&self, key: &PublicKey) -> Option<KeyRole> {
        if key == &self.user {
            Some(KeyRole::User)
        } else if key == &self.backup {
            Some(KeyRole::Backup)
        } else if key == &self.bitgo {
            Some(KeyRole::Bitgo)
        } else {
            None
        }
    }

    fn ordered_keys(&self) -> [PublicKey; 3] {
        // Constructor proved this relation; retain a defensive fallback that
        // cannot widen the accepted witness script.
        ordered_wallet_keys(&[self.user, self.backup, self.bitgo], &self.witness_script)
            .unwrap_or([self.user, self.backup, self.bitgo])
    }
}

/// Independently observed native-P2WSH input selected for the `BitGo` build.
#[derive(Debug, Clone)]
pub struct InputPolicy {
    outpoint: OutPoint,
    value_sats: u64,
}

impl InputPolicy {
    /// Bind one positive-value UTXO to the reviewed wallet policy.
    ///
    /// The input script and witness script are wallet-policy properties and
    /// therefore cannot be replaced by provider response data.
    ///
    /// # Errors
    /// Returns an error when the independent input value is zero.
    pub fn new(outpoint: OutPoint, value_sats: u64) -> Result<Self, PolicyError> {
        if value_sats == 0 {
            return Err(PolicyError::new(
                "bitgo_input_value",
                "input value must be non-zero",
            ));
        }
        Ok(Self {
            outpoint,
            value_sats,
        })
    }

    /// Exact selected outpoint.
    #[must_use]
    pub const fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    /// Independently observed value in satoshis.
    #[must_use]
    pub const fn value_sats(&self) -> u64 {
        self.value_sats
    }
}

/// Exact provider-independent spend policy for one `BitGo` transaction.
#[derive(Debug, Clone)]
pub struct SpendPolicy {
    wallet: WalletPolicy,
    input: InputPolicy,
    payout_spk: ScriptBuf,
    payout_sats: u64,
    memo: Vec<u8>,
    memo_spk: ScriptBuf,
    max_fee_sats: u64,
    sequence_id: String,
    require_change: bool,
}

impl SpendPolicy {
    /// Construct one exact certified spend policy.
    ///
    /// # Errors
    /// Returns an error for an invalid payout, empty/oversized memo, zero fee
    /// cap, unsafe sequence identifier, or an input that cannot cover payout
    /// plus a positive fee.
    #[expect(
        clippy::too_many_arguments,
        reason = "one constructor binds every independently certified spend field"
    )]
    pub fn new(
        wallet: WalletPolicy,
        input: InputPolicy,
        payout_spk: ScriptBuf,
        payout_sats: u64,
        memo: Vec<u8>,
        max_fee_sats: u64,
        sequence_id: impl Into<String>,
        require_change: bool,
    ) -> Result<Self, PolicyError> {
        if payout_sats == 0 || payout_spk.is_op_return() {
            return Err(PolicyError::new(
                "bitgo_payout",
                "payout must be non-zero and must not be OP_RETURN",
            ));
        }
        Address::from_script(&payout_spk, wallet.coin.network()).map_err(|_| {
            PolicyError::new(
                "bitgo_payout",
                "payout script is not an address on the selected Bitcoin network",
            )
        })?;
        if memo.is_empty() || memo.len() > MAX_MEMO_BYTES {
            return Err(PolicyError::new(
                "bitgo_memo",
                format!("memo must contain 1..={MAX_MEMO_BYTES} bytes"),
            ));
        }
        if max_fee_sats == 0 {
            return Err(PolicyError::new(
                "bitgo_fee",
                "maximum fee must be non-zero",
            ));
        }
        let available_fee = input.value_sats.checked_sub(payout_sats).ok_or_else(|| {
            PolicyError::new("bitgo_funds", "input does not cover the certified payout")
        })?;
        if available_fee == 0 || max_fee_sats > available_fee {
            return Err(PolicyError::new(
                "bitgo_fee",
                "fee cap must fit inside the input value remaining after payout",
            ));
        }
        let sequence_id = sequence_id.into();
        if sequence_id.is_empty()
            || sequence_id.len() > 128
            || sequence_id.chars().any(char::is_control)
        {
            return Err(PolicyError::new(
                "bitgo_sequence",
                "sequence id must contain 1..=128 non-control characters",
            ));
        }
        let memo_spk = canonical_op_return_script(&memo).map_err(|error| {
            PolicyError::new(
                "bitgo_memo",
                format!("memo cannot be canonically encoded as one data push: {error}"),
            )
        })?;
        Ok(Self {
            wallet,
            input,
            payout_spk,
            payout_sats,
            memo,
            memo_spk,
            max_fee_sats,
            sequence_id,
            require_change,
        })
    }

    /// Reviewed wallet policy.
    #[must_use]
    pub const fn wallet(&self) -> &WalletPolicy {
        &self.wallet
    }

    /// Exact input policy.
    #[must_use]
    pub const fn input(&self) -> &InputPolicy {
        &self.input
    }

    /// Unique idempotency/correlation value shared by build and send requests.
    #[must_use]
    pub fn sequence_id(&self) -> &str {
        &self.sequence_id
    }

    /// Maximum allowed absolute miner fee in satoshis.
    #[must_use]
    pub const fn max_fee_sats(&self) -> u64 {
        self.max_fee_sats
    }
}

/// `BitGo` UTXO transaction output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TxFormat {
    /// BIP-174 PSBT.
    Psbt,
}

/// `BitGo` change-address type locked by the selected policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeAddressType {
    /// Native P2WSH.
    P2wsh,
}

/// One exact `BitGo` transaction recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRecipient {
    /// Bitcoin address or `BitGo` `scriptPubKey:<hex>` pseudo-address.
    pub address: String,
    /// Base-unit amount encoded as a decimal string.
    pub amount: String,
}

/// Exact body for `BitGo`'s multisig `tx/build` endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildRequest {
    /// Payout followed by zero-value `OP_RETURN` recipient.
    pub recipients: Vec<BuildRecipient>,
    /// Idempotent request correlation.
    pub sequence_id: String,
    /// Disable provider change splitting.
    pub no_split_change: bool,
    /// Complete ordered explicit input set.
    pub unspents: Vec<String>,
    /// Exact VIN0 native-P2WSH change address.
    pub change_address: String,
    /// Explicit native-P2WSH change type.
    pub change_address_type: ChangeAddressType,
    /// Require BIP-174 output.
    pub tx_format: TxFormat,
    /// Explicitly prohibit RBF.
    pub is_replaceable_by_fee: bool,
}

/// Half-signed object nested in `BitGo`'s `tx/send` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HalfSigned {
    /// Serialized half-signed Bitcoin transaction hex.
    tx_hex: String,
}

/// Exact body for `BitGo`'s multisig `tx/send` endpoint.
///
/// The endpoint both adds the `BitGo` signature and broadcasts. The adapter does
/// not expose a transport method; callers must cross that authority boundary
/// separately after retaining this reviewed payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SendRequest {
    /// Validated user-signed transaction.
    half_signed: HalfSigned,
    /// Same idempotency/correlation value used for the build.
    sequence_id: String,
}

impl SendRequest {
    /// Validated serialized half-signed transaction hex.
    #[must_use]
    pub fn tx_hex(&self) -> &str {
        &self.half_signed.tx_hex
    }

    /// Same idempotency/correlation value used for the build.
    #[must_use]
    pub fn sequence_id(&self) -> &str {
        &self.sequence_id
    }
}

/// Generate the only accepted `BitGo` build payload for `policy`.
///
/// # Errors
/// Returns an error when either the payout or custody script cannot be encoded
/// as an address on the selected network.
pub fn build_request(policy: &SpendPolicy) -> Result<BuildRequest, PolicyError> {
    let network = policy.wallet.coin.network();
    let payout_address = Address::from_script(&policy.payout_spk, network)
        .map_err(|_| PolicyError::new("bitgo_payout", "payout has no network address"))?;
    let change_address = Address::from_script(&policy.wallet.custody_spk, network)
        .map_err(|_| PolicyError::new("bitgo_change", "custody script has no network address"))?;
    Ok(BuildRequest {
        recipients: vec![
            BuildRecipient {
                address: payout_address.to_string(),
                amount: policy.payout_sats.to_string(),
            },
            BuildRecipient {
                address: format!(
                    "scriptPubKey:{}",
                    alloy_primitives::hex::encode(policy.memo_spk.as_bytes())
                ),
                amount: "0".to_string(),
            },
        ],
        sequence_id: policy.sequence_id.clone(),
        no_split_change: true,
        unspents: vec![format!(
            "{}:{}",
            policy.input.outpoint.txid, policy.input.outpoint.vout
        )],
        change_address: change_address.to_string(),
        change_address_type: ChangeAddressType::P2wsh,
        tx_format: TxFormat::Psbt,
        is_replaceable_by_fee: false,
    })
}

/// Require a captured build payload to equal the generated request byte-for-
/// field, including recipient and input order.
///
/// # Errors
/// Returns `bitgo_build_request` for any mismatch.
pub fn validate_build_request(
    captured: &BuildRequest,
    policy: &SpendPolicy,
) -> Result<(), PolicyError> {
    let expected = build_request(policy)?;
    if captured != &expected {
        return Err(PolicyError::new(
            "bitgo_build_request",
            "captured build request differs from the generated spend policy",
        ));
    }
    Ok(())
}

/// Validate a provider-returned unsigned PSBT before any user signature.
///
/// # Errors
/// Returns a stable fail-closed policy error for any input, native-P2WSH,
/// RBF, output-order, memo, payout, change, unsigned-state, or fee mismatch.
#[expect(
    clippy::too_many_lines,
    reason = "the ordered fail-closed policy is easier to audit as one linear decision"
)]
pub fn validate_unsigned(psbt: &Psbt, policy: &SpendPolicy) -> Result<(), PolicyError> {
    if psbt.unsigned_tx.input.len() != 1 || psbt.inputs.len() != 1 {
        return Err(PolicyError::new(
            "bitgo_inputs",
            "reviewed BitGo BTC profile requires exactly one input",
        ));
    }
    let txin = &psbt.unsigned_tx.input[0];
    if txin.previous_output != policy.input.outpoint {
        return Err(PolicyError::new(
            "bitgo_inputs",
            "VIN0 does not equal the independently selected outpoint",
        ));
    }
    if txin.sequence.is_rbf() {
        return Err(PolicyError::new(
            "bitgo_rbf",
            "VIN0 opts into replace-by-fee",
        ));
    }
    if !txin.script_sig.is_empty() || !txin.witness.is_empty() {
        return Err(PolicyError::new(
            "bitgo_native_p2wsh",
            "unsigned native-P2WSH VIN0 must have empty scriptSig and witness",
        ));
    }
    let metadata = &psbt.inputs[0];
    let witness_utxo = metadata.witness_utxo.as_ref().ok_or_else(|| {
        PolicyError::new("bitgo_inputs", "VIN0 PSBT metadata has no witness_utxo")
    })?;
    if witness_utxo.value.to_sat() != policy.input.value_sats
        || witness_utxo.script_pubkey != policy.wallet.custody_spk
    {
        return Err(PolicyError::new(
            "bitgo_inputs",
            "VIN0 value/script differs from independent wallet evidence",
        ));
    }
    if let Some(previous) = &metadata.non_witness_utxo {
        let Some(output) = previous.output.get(txin.previous_output.vout as usize) else {
            return Err(PolicyError::new(
                "bitgo_inputs",
                "non_witness_utxo does not contain the selected output",
            ));
        };
        if previous.compute_txid() != txin.previous_output.txid || output != witness_utxo {
            return Err(PolicyError::new(
                "bitgo_inputs",
                "non_witness_utxo conflicts with VIN0/witness_utxo",
            ));
        }
    }
    if metadata.redeem_script.is_some()
        || metadata.witness_script.as_ref() != Some(&policy.wallet.witness_script)
        || ScriptBuf::new_p2wsh(&policy.wallet.witness_script.wscript_hash())
            != witness_utxo.script_pubkey
    {
        return Err(PolicyError::new(
            "bitgo_native_p2wsh",
            "VIN0 is not the exact captured native-P2WSH wallet script",
        ));
    }
    if metadata
        .sighash_type
        .is_some_and(|kind| kind.ecdsa_hash_ty() != Ok(EcdsaSighashType::All))
    {
        return Err(PolicyError::new(
            "bitgo_sighash",
            "PSBT requests a sighash type other than SIGHASH_ALL",
        ));
    }
    if !metadata.partial_sigs.is_empty()
        || metadata.final_script_sig.is_some()
        || metadata.final_script_witness.is_some()
        || metadata.tap_key_sig.is_some()
        || !metadata.tap_script_sigs.is_empty()
        || !metadata.tap_scripts.is_empty()
        || !metadata.tap_key_origins.is_empty()
        || metadata.tap_internal_key.is_some()
        || metadata.tap_merkle_root.is_some()
    {
        return Err(PolicyError::new(
            "bitgo_unsigned_state",
            "unsigned native-P2WSH PSBT contains signature/finalization/taproot data",
        ));
    }
    if policy.require_change && psbt.unsigned_tx.output.len() != 3 {
        return Err(PolicyError::new(
            "bitgo_change",
            "spend policy requires a real VOUT1 change output",
        ));
    }
    let certified = CertifiedSpend {
        amount: U256::from(policy.payout_sats),
        immediate_target_hash: keccak256(policy.payout_spk.as_bytes()),
        memo_hash: keccak256(&policy.memo),
        mismatch_code: "bitgo_thorchain_mismatch",
    };
    bind_outputs_to_cert(psbt, &policy.wallet.custody_spk, &certified).map_err(|error| {
        PolicyError::new(
            error.code,
            format!("THORChain output policy: {}", error.message),
        )
    })?;
    let output_sum = psbt
        .unsigned_tx
        .output
        .iter()
        .try_fold(0u64, |sum, output| sum.checked_add(output.value.to_sat()))
        .ok_or_else(|| PolicyError::new("bitgo_fee", "output value sum overflow"))?;
    let fee = policy
        .input
        .value_sats
        .checked_sub(output_sum)
        .ok_or_else(|| {
            PolicyError::new(
                "bitgo_fee",
                "outputs exceed the independently observed input value",
            )
        })?;
    if fee == 0 || fee > policy.max_fee_sats {
        return Err(PolicyError::new(
            "bitgo_fee",
            format!(
                "implied fee {fee} sats is outside 1..={} sats",
                policy.max_fee_sats
            ),
        ));
    }
    Ok(())
}

/// Verify one native-P2WSH ECDSA signature against the unsigned PSBT.
///
/// # Errors
/// Returns an error for non-`SIGHASH_ALL`, high-S, incomplete PSBT metadata,
/// sighash failure, or a signature invalid for `public_key`.
pub fn verify_signature_for_key(
    unsigned: &Psbt,
    input_index: usize,
    public_key: &PublicKey,
    signature: &BitcoinSignature,
) -> Result<(), PolicyError> {
    if signature.sighash_type != EcdsaSighashType::All {
        return Err(PolicyError::new(
            "bitgo_sighash",
            format!("input {input_index} signature is not SIGHASH_ALL"),
        ));
    }
    let mut normalized = signature.signature;
    normalized.normalize_s();
    if normalized != signature.signature {
        return Err(PolicyError::new(
            "bitgo_signature",
            format!("input {input_index} signature is high-S"),
        ));
    }
    let metadata = unsigned.inputs.get(input_index).ok_or_else(|| {
        PolicyError::new(
            "bitgo_signature",
            format!("missing PSBT metadata for input {input_index}"),
        )
    })?;
    let witness_utxo = metadata.witness_utxo.as_ref().ok_or_else(|| {
        PolicyError::new(
            "bitgo_signature",
            format!("input {input_index} has no witness_utxo"),
        )
    })?;
    let witness_script = metadata.witness_script.as_ref().ok_or_else(|| {
        PolicyError::new(
            "bitgo_signature",
            format!("input {input_index} has no witness_script"),
        )
    })?;
    let sighash = SighashCache::new(&unsigned.unsigned_tx)
        .p2wsh_signature_hash(
            input_index,
            witness_script,
            witness_utxo.value,
            EcdsaSighashType::All,
        )
        .map_err(|error| {
            PolicyError::new(
                "bitgo_sighash",
                format!("input {input_index} BIP-143 sighash: {error}"),
            )
        })?;
    Secp256k1::verification_only()
        .verify_ecdsa(
            &Message::from_digest(sighash.to_byte_array()),
            &signature.signature,
            &public_key.inner,
        )
        .map_err(|_| {
            PolicyError::new(
                "bitgo_signature",
                format!("signature is invalid for input {input_index} and captured role key"),
            )
        })
}

/// Validate a BIP-174 user-signed artifact before provider submission.
///
/// # Errors
/// Returns an error unless every input preserves the unsigned policy metadata
/// and contains exactly one valid user `SIGHASH_ALL` partial signature.
pub fn validate_user_signed_psbt(
    unsigned: &Psbt,
    signed: &Psbt,
    policy: &SpendPolicy,
) -> Result<(), PolicyError> {
    validate_unsigned(unsigned, policy)?;
    if signed.inputs.len() != unsigned.inputs.len()
        || signed
            .inputs
            .iter()
            .any(|input| input.partial_sigs.len() != 1)
    {
        return Err(PolicyError::new(
            "bitgo_user_signature",
            "user-signed PSBT does not contain exactly one partial signature per input",
        ));
    }

    // A signer may add only the one required user signature. Comparing the
    // complete PSBT after removing those signatures covers global, input and
    // output metadata, including proprietary/unknown and taproot fields.
    let mut unsigned_projection = signed.clone();
    for input in &mut unsigned_projection.inputs {
        input.partial_sigs.clear();
    }
    if &unsigned_projection != unsigned {
        return Err(PolicyError::new(
            "bitgo_user_signature",
            "user signing changed the unsigned transaction or policy metadata",
        ));
    }

    for (input_index, signed_input) in signed.inputs.iter().enumerate() {
        let signature = signed_input
            .partial_sigs
            .get(&policy.wallet.user)
            .ok_or_else(|| {
                PolicyError::new(
                    "bitgo_user_signature",
                    format!("input {input_index} is not signed by the captured user key"),
                )
            })?;
        verify_signature_for_key(unsigned, input_index, &policy.wallet.user, signature)?;
    }
    Ok(())
}

/// Validate a raw half-signed transaction before provider submission.
///
/// # Errors
/// Returns an error unless it preserves the exact unsigned skeleton and each
/// input has exactly one valid user `SIGHASH_ALL` witness signature.
pub fn validate_user_signed_transaction(
    unsigned: &Psbt,
    signed: &Transaction,
    policy: &SpendPolicy,
) -> Result<(), PolicyError> {
    validate_unsigned(unsigned, policy)?;
    validate_witness_roles(unsigned, signed, &policy.wallet, &[KeyRole::User])
}

/// Build a retained `BitGo` send payload only after the user signature passes.
///
/// # Errors
/// Returns an error when the half-signed transaction fails exact skeleton or
/// cryptographic user-role validation.
pub fn send_request(
    unsigned: &Psbt,
    half_signed: &Transaction,
    policy: &SpendPolicy,
) -> Result<SendRequest, PolicyError> {
    validate_user_signed_transaction(unsigned, half_signed, policy)?;
    Ok(SendRequest {
        half_signed: HalfSigned {
            tx_hex: alloy_primitives::hex::encode(serialize(half_signed)),
        },
        sequence_id: policy.sequence_id.clone(),
    })
}

/// Validate a returned `BitGo`-finalized transaction after the combined
/// final-sign-and-broadcast endpoint.
///
/// # Errors
/// Returns an error unless the final transaction preserves the exact unsigned
/// skeleton, contains exactly valid user + `BitGo` `SIGHASH_ALL` signatures in
/// descriptor order, and has the externally corroborated txid.
pub fn validate_final_transaction(
    unsigned: &Psbt,
    final_tx: &Transaction,
    expected_txid: Txid,
    policy: &SpendPolicy,
) -> Result<(), PolicyError> {
    validate_unsigned(unsigned, policy)?;
    validate_witness_roles(
        unsigned,
        final_tx,
        &policy.wallet,
        &[KeyRole::User, KeyRole::Bitgo],
    )?;
    if final_tx.compute_txid() != expected_txid {
        return Err(PolicyError::new(
            "bitgo_final_txid",
            format!(
                "final transaction txid {} differs from corroborated {expected_txid}",
                final_tx.compute_txid()
            ),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum KeyRole {
    User,
    Backup,
    Bitgo,
}

fn multisig_witness_script(pubkeys: &[PublicKey; 3]) -> ScriptBuf {
    Builder::new()
        .push_int(2)
        .push_key(&pubkeys[0])
        .push_key(&pubkeys[1])
        .push_key(&pubkeys[2])
        .push_int(3)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script()
}

fn ordered_wallet_keys(
    role_keys: &[PublicKey; 3],
    witness_script: &ScriptBuf,
) -> Option<[PublicKey; 3]> {
    const PERMUTATIONS: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    PERMUTATIONS.into_iter().find_map(|order| {
        let ordered = [
            role_keys[order[0]],
            role_keys[order[1]],
            role_keys[order[2]],
        ];
        (multisig_witness_script(&ordered) == *witness_script).then_some(ordered)
    })
}

fn transaction_skeleton_matches(candidate: &Transaction, unsigned: &Transaction) -> bool {
    candidate.version == unsigned.version
        && candidate.lock_time == unsigned.lock_time
        && candidate.output == unsigned.output
        && candidate.input.len() == unsigned.input.len()
        && candidate
            .input
            .iter()
            .zip(&unsigned.input)
            .all(|(candidate_input, unsigned_input)| {
                candidate_input.previous_output == unsigned_input.previous_output
                    && candidate_input.sequence == unsigned_input.sequence
                    && candidate_input.script_sig == unsigned_input.script_sig
                    && !candidate_input.witness.is_empty()
            })
}

fn validate_witness_roles(
    unsigned: &Psbt,
    candidate: &Transaction,
    wallet: &WalletPolicy,
    required_roles: &[KeyRole],
) -> Result<(), PolicyError> {
    if !transaction_skeleton_matches(candidate, &unsigned.unsigned_tx) {
        return Err(PolicyError::new(
            "bitgo_signature_skeleton",
            "signed transaction changed the unsigned skeleton or lacks witness data",
        ));
    }
    let ordered_pubkeys = wallet.ordered_keys();
    for (input_index, txin) in candidate.input.iter().enumerate() {
        let witness_items = txin.witness.iter().collect::<Vec<_>>();
        if witness_items.len() != required_roles.len() + 2
            || witness_items.first().is_none_or(|item| !item.is_empty())
            || witness_items.last().copied() != Some(wallet.witness_script.as_bytes())
        {
            return Err(PolicyError::new(
                "bitgo_signature_witness",
                format!(
                    "input {input_index} witness must be CHECKMULTISIG dummy + {} signature(s) + exact witness script",
                    required_roles.len()
                ),
            ));
        }
        let mut observed_roles = Vec::with_capacity(required_roles.len());
        let mut next_key_index = 0usize;
        for encoded in &witness_items[1..witness_items.len() - 1] {
            let signature = BitcoinSignature::from_slice(encoded).map_err(|_| {
                PolicyError::new(
                    "bitgo_signature",
                    format!("input {input_index} has invalid DER+sighash signature encoding"),
                )
            })?;
            let mut matched = None;
            for (key_index, public_key) in ordered_pubkeys.iter().enumerate().skip(next_key_index) {
                if verify_signature_for_key(unsigned, input_index, public_key, &signature).is_ok() {
                    matched = Some((key_index, *public_key));
                    break;
                }
            }
            let Some((key_index, public_key)) = matched else {
                return Err(PolicyError::new(
                    "bitgo_signature",
                    format!("input {input_index} signature is invalid or out of descriptor order"),
                ));
            };
            next_key_index = key_index + 1;
            observed_roles.push(wallet.role(&public_key).ok_or_else(|| {
                PolicyError::new(
                    "bitgo_signature",
                    "verified signature key has no captured custody role",
                )
            })?);
        }
        observed_roles.sort_unstable();
        let mut expected_roles = required_roles.to_vec();
        expected_roles.sort_unstable();
        if observed_roles != expected_roles {
            return Err(PolicyError::new(
                "bitgo_signature_roles",
                format!(
                    "input {input_index} signatures do not match the exact required custody roles"
                ),
            ));
        }
    }
    Ok(())
}

/// Parse a compressed public key without accepting an uncompressed role key.
///
/// # Errors
/// Returns `bitgo_wallet_keys` for invalid or uncompressed key text.
pub fn parse_compressed_public_key(value: &str) -> Result<PublicKey, PolicyError> {
    let key = PublicKey::from_str(value).map_err(|_| {
        PolicyError::new(
            "bitgo_wallet_keys",
            "custody role key is not a valid Bitcoin public key",
        )
    })?;
    if !key.compressed {
        return Err(PolicyError::new(
            "bitgo_wallet_keys",
            "custody role key must be compressed",
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, Sequence, TxIn, TxOut, Witness,
    };

    const USER_PUBKEY: &str = "03c10ac628c880629ed0fd2a0563a898f4882baca45e15668a4d3064cf1ea37988";
    const BACKUP_PUBKEY: &str =
        "03e56f84be4460080618ef869bb7b07096880760f748ba23efab533c2359f923bd";
    const BITGO_PUBKEY: &str = "020ae81372264b5eac5c9dc7fe0b9a32bad00771c3a2c71f6e2c971823c3182ed6";

    #[expect(clippy::expect_used, reason = "test code")]
    fn wallet() -> WalletPolicy {
        let user = parse_compressed_public_key(USER_PUBKEY).expect("user key");
        let backup = parse_compressed_public_key(BACKUP_PUBKEY).expect("backup key");
        let bitgo = parse_compressed_public_key(BITGO_PUBKEY).expect("BitGo key");
        let script = multisig_witness_script(&[user, backup, bitgo]);
        WalletPolicy::new(
            BitGoCoin::Tbtc4,
            "wallet-1",
            P2WSH_EXTERNAL_CHAIN_CODE,
            user,
            backup,
            bitgo,
            script,
        )
        .expect("wallet policy")
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn policy_with_memo(memo: Vec<u8>) -> SpendPolicy {
        let wallet = wallet();
        let input = InputPolicy::new(
            OutPoint {
                txid: Txid::from_byte_array([0x22; 32]),
                vout: 0,
            },
            200_000,
        )
        .expect("input policy");
        let payout = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0xaa; 20]));
        SpendPolicy::new(
            wallet,
            input,
            payout,
            100_000,
            memo,
            20_000,
            "xindex-redemption-1",
            true,
        )
        .expect("spend policy")
    }

    fn policy() -> SpendPolicy {
        policy_with_memo(b"=:ETH.USDT:0xrecipient:990000".to_vec())
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn psbt_for_policy(policy: &SpendPolicy, old_order: bool) -> Psbt {
        let change = TxOut {
            value: Amount::from_sat(89_000),
            script_pubkey: policy.wallet.custody_spk.clone(),
        };
        let payout = TxOut {
            value: Amount::from_sat(policy.payout_sats),
            script_pubkey: policy.payout_spk.clone(),
        };
        let memo = TxOut {
            value: Amount::ZERO,
            script_pubkey: policy.memo_spk.clone(),
        };
        let outputs = if old_order {
            vec![payout, memo, change]
        } else {
            vec![payout, change, memo]
        };
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: policy.input.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outputs,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("PSBT");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(policy.input.value_sats),
            script_pubkey: policy.wallet.custody_spk.clone(),
        });
        psbt.inputs[0].witness_script = Some(policy.wallet.witness_script.clone());
        psbt
    }

    fn psbt(old_order: bool) -> Psbt {
        psbt_for_policy(&policy(), old_order)
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn request_is_exact_and_uses_bitgo_wire_names() {
        let policy = policy();
        let request = build_request(&policy).expect("build request");
        let json = serde_json::to_value(&request).expect("serialize");
        assert_eq!(json["txFormat"], "psbt");
        assert_eq!(json["changeAddressType"], "p2wsh");
        assert_eq!(json["isReplaceableByFee"], false);
        assert_eq!(json["noSplitChange"], true);
        assert_eq!(json["recipients"][0]["amount"], "100000");
        assert_eq!(json["recipients"][1]["amount"], "0");
        assert_eq!(
            policy.wallet.build_endpoint_path(),
            "/api/v2/tbtc4/wallet/wallet-1/tx/build"
        );
        assert_eq!(
            policy.wallet.send_endpoint_path(),
            "/api/v2/tbtc4/wallet/wallet-1/tx/send"
        );
    }

    #[test]
    fn exact_unsigned_psbt_passes() {
        assert!(validate_unsigned(&psbt(false), &policy()).is_ok());
    }

    #[test]
    fn numeric_memo_uses_the_shared_canonical_encoding() {
        let policy = policy_with_memo(vec![0x01]);
        assert_eq!(policy.memo_spk.as_bytes(), [0x6a, 0x51]);
        assert!(validate_unsigned(&psbt_for_policy(&policy, false), &policy).is_ok());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn nonminimal_numeric_memo_is_rejected_by_the_shared_parser() {
        let policy = policy_with_memo(vec![0x01]);
        let mut candidate = psbt_for_policy(&policy, false);
        candidate.unsigned_tx.output[2].script_pubkey =
            ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x01]);
        let error = validate_unsigned(&candidate, &policy).expect_err("non-minimal memo must fail");
        assert_eq!(error.code(), "bitgo_thorchain_mismatch");
    }

    #[test]
    fn memo_before_change_fails() {
        assert!(validate_unsigned(&psbt(true), &policy()).is_err());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn rbf_input_fails() {
        let mut candidate = psbt(false);
        candidate.unsigned_tx.input[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
        let error = validate_unsigned(&candidate, &policy()).expect_err("RBF must fail");
        assert_eq!(error.code(), "bitgo_rbf");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn fee_above_the_absolute_cap_fails() {
        let mut candidate = psbt(false);
        candidate.unsigned_tx.output[1].value = Amount::from_sat(79_000);
        let error = validate_unsigned(&candidate, &policy()).expect_err("fee cap must fail");
        assert_eq!(error.code(), "bitgo_fee");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn non_all_psbt_sighash_fails() {
        let mut candidate = psbt(false);
        candidate.inputs[0].sighash_type = Some(EcdsaSighashType::Single.into());
        let error =
            validate_unsigned(&candidate, &policy()).expect_err("non-ALL sighash must fail");
        assert_eq!(error.code(), "bitgo_sighash");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn mutated_build_request_fails() {
        let policy = policy();
        let mut request = build_request(&policy).expect("build request");
        request.is_replaceable_by_fee = true;
        let error = validate_build_request(&request, &policy).expect_err("mutation must fail");
        assert_eq!(error.code(), "bitgo_build_request");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn wrong_change_script_fails() {
        let mut candidate = psbt(false);
        candidate.unsigned_tx.output[1].script_pubkey =
            ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0xbb; 20]));
        let error = validate_unsigned(&candidate, &policy()).expect_err("change must fail");
        assert_eq!(error.code(), "psbt_unexpected_output");
    }

    #[test]
    fn synthetic_user_witness_fails() {
        let unsigned = psbt(false);
        let mut signed = unsigned.unsigned_tx.clone();
        signed.input[0].witness = Witness::from_slice(&[b"synthetic-public-witness"]);
        assert!(validate_user_signed_transaction(&unsigned, &signed, &policy()).is_err());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn user_signed_psbt_cannot_mutate_policy_metadata() {
        // Static public signature encoding from BitGo's manual multisig guide;
        // this regression parses existing bytes and never creates or uses a key.
        let encoded = alloy_primitives::hex::decode(
            "3045022100db45a8d94ee2144f7e29baa855d94a2bf0120707a7ab2fc93734ed94af972c460220558d00b91275aafc7805dfaaf9ab796adbe9f4e66dc467f7eb93b790671a323201",
        )
        .expect("static DER+sighash bytes");
        let signature = BitcoinSignature::from_slice(&encoded).expect("Bitcoin signature");
        let policy = policy();
        let unsigned = psbt(false);
        let mut signed = unsigned.clone();
        signed.inputs[0]
            .partial_sigs
            .insert(policy.wallet.user, signature);
        signed.outputs[0].redeem_script = Some(ScriptBuf::new());

        let error = validate_user_signed_psbt(&unsigned, &signed, &policy)
            .expect_err("signer metadata mutation must fail before signature verification");
        assert_eq!(error.code(), "bitgo_user_signature");
        assert_eq!(
            error.message(),
            "user signing changed the unsigned transaction or policy metadata"
        );
    }

    #[test]
    fn wrong_role_keyset_fails_wallet_policy() {
        let user = parse_compressed_public_key(USER_PUBKEY).unwrap_or_else(|_| unreachable!());
        let backup = parse_compressed_public_key(BACKUP_PUBKEY).unwrap_or_else(|_| unreachable!());
        let bitgo = parse_compressed_public_key(BITGO_PUBKEY).unwrap_or_else(|_| unreachable!());
        let script = multisig_witness_script(&[user, backup, bitgo]);
        let wrong_bitgo = parse_compressed_public_key(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap_or_else(|_| unreachable!());
        assert!(WalletPolicy::new(
            BitGoCoin::Tbtc4,
            "wallet-1",
            P2WSH_EXTERNAL_CHAIN_CODE,
            user,
            backup,
            wrong_bitgo,
            script,
        )
        .is_err());
    }

    #[test]
    fn wrong_external_chain_code_fails_wallet_policy() {
        let source = wallet();
        assert!(WalletPolicy::new(
            BitGoCoin::Tbtc4,
            "wallet-1",
            10,
            source.user,
            source.backup,
            source.bitgo,
            source.witness_script,
        )
        .is_err());
    }
}
