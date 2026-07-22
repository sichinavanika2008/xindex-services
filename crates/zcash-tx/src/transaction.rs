//! Transparent-only Zcash Sapling-v4 serialization and ZIP-243 signing hashes.

use bitcoin::hashes::{sha256d, Hash as _};
use bitcoin::{PublicKey, ScriptBuf};
use blake2b_simd::Params;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashSet;

/// NU6.1 consensus branch identifier used by the reviewed Vultisig Recipes
/// profile. The verifier and transaction producer must move together when the
/// active Zcash branch changes.
pub const NU6_1_BRANCH_ID: u32 = 0x4dec_4df0;

const OVERWINTERED_V4: u32 = 0x8000_0004;
const SAPLING_VERSION_GROUP_ID: u32 = 0x892f_2085;
const SIGHASH_ALL: u32 = 1;
const SIGHASH_ALL_BYTE: u8 = 1;
const COMPRESSED_PUBLIC_KEY_PUSH_LENGTH: u8 = 33;
const MAX_MONEY_ZATOSHIS: u64 = 2_100_000_000_000_000;
const MAX_TRANSPARENT_ITEMS: usize = 10_000;
const MAX_SCRIPT_BYTES: usize = 10_000;
const METADATA_MAGIC: &[u8; 3] = b"ZSH";

/// One transparent previous output spent by the transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInput {
    previous_txid: [u8; 32],
    output_index: u32,
    value_zatoshis: u64,
}

impl TransparentInput {
    /// Construct an input. `previous_txid` uses the conventional displayed
    /// byte order; serialization reverses it into the wire outpoint order.
    #[must_use]
    pub const fn new(previous_txid: [u8; 32], output_index: u32, value_zatoshis: u64) -> Self {
        Self {
            previous_txid,
            output_index,
            value_zatoshis,
        }
    }

    /// Previous transaction identifier in conventional displayed byte order.
    #[must_use]
    pub const fn previous_txid(&self) -> [u8; 32] {
        self.previous_txid
    }

    /// Previous transaction output index.
    #[must_use]
    pub const fn output_index(&self) -> u32 {
        self.output_index
    }

    /// Certified previous-output value.
    #[must_use]
    pub const fn value_zatoshis(&self) -> u64 {
        self.value_zatoshis
    }
}

/// One exact transparent output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentOutput {
    value_zatoshis: u64,
    script_pubkey: Vec<u8>,
}

impl TransparentOutput {
    /// Construct an output carrying exact script bytes.
    #[must_use]
    pub fn new(value_zatoshis: u64, script_pubkey: Vec<u8>) -> Self {
        Self {
            value_zatoshis,
            script_pubkey,
        }
    }

    /// Output value in zatoshis.
    #[must_use]
    pub const fn value_zatoshis(&self) -> u64 {
        self.value_zatoshis
    }

    /// Exact output script bytes.
    #[must_use]
    pub fn script_pubkey(&self) -> &[u8] {
        &self.script_pubkey
    }
}

/// Exact transparent-only Sapling-v4 transaction profile implemented by the
/// pinned Vultisig Recipes Zcash SDK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaplingV4Transaction {
    #[serde(with = "compressed_public_key_serde")]
    aggregate_public_key: [u8; 33],
    inputs: Vec<TransparentInput>,
    outputs: Vec<TransparentOutput>,
}

impl SaplingV4Transaction {
    /// Construct and validate a transparent Sapling-v4 transaction.
    ///
    /// # Errors
    /// Invalid key/count/script/value state or output inflation fails closed.
    pub fn new(
        aggregate_public_key: [u8; 33],
        inputs: Vec<TransparentInput>,
        outputs: Vec<TransparentOutput>,
    ) -> Result<Self, ZcashTransactionError> {
        let transaction = Self {
            aggregate_public_key,
            inputs,
            outputs,
        };
        transaction.validate()?;
        Ok(transaction)
    }

    /// Revalidate a value restored from durable storage.
    ///
    /// # Errors
    /// Invalid key/count/script/value state or output inflation fails closed.
    pub fn validate(&self) -> Result<(), ZcashTransactionError> {
        PublicKey::from_slice(&self.aggregate_public_key)
            .map_err(|_| ZcashTransactionError::InvalidPublicKey)?;
        if self.inputs.is_empty() {
            return Err(ZcashTransactionError::NoInputs);
        }
        if self.outputs.is_empty() {
            return Err(ZcashTransactionError::NoOutputs);
        }
        if self.inputs.len() > MAX_TRANSPARENT_ITEMS {
            return Err(ZcashTransactionError::TooManyInputs(self.inputs.len()));
        }
        if self.outputs.len() > MAX_TRANSPARENT_ITEMS {
            return Err(ZcashTransactionError::TooManyOutputs(self.outputs.len()));
        }
        let mut seen_outpoints = HashSet::with_capacity(self.inputs.len());
        for (index, input) in self.inputs.iter().enumerate() {
            if !seen_outpoints.insert((input.previous_txid, input.output_index)) {
                return Err(ZcashTransactionError::DuplicateInput { index });
            }
        }
        for (index, output) in self.outputs.iter().enumerate() {
            if output.script_pubkey.is_empty() || output.script_pubkey.len() > MAX_SCRIPT_BYTES {
                return Err(ZcashTransactionError::InvalidOutputScript {
                    index,
                    length: output.script_pubkey.len(),
                });
            }
        }
        let input_total = checked_input_total(&self.inputs)?;
        let output_total = checked_output_total(&self.outputs)?;
        if output_total > input_total {
            return Err(ZcashTransactionError::OutputInflation {
                inputs: input_total,
                outputs: output_total,
            });
        }
        Ok(())
    }

    /// Aggregate compressed secp256k1 public key committed by every input.
    #[must_use]
    pub const fn aggregate_public_key(&self) -> [u8; 33] {
        self.aggregate_public_key
    }

    /// Ordered transparent inputs.
    #[must_use]
    pub fn inputs(&self) -> &[TransparentInput] {
        &self.inputs
    }

    /// Ordered transparent outputs.
    #[must_use]
    pub fn outputs(&self) -> &[TransparentOutput] {
        &self.outputs
    }

    /// Exact aggregate-key P2PKH script used as ZIP-243 `scriptCode` for every
    /// input in this direct-key profile.
    ///
    /// # Errors
    /// An invalid stored public key fails closed.
    pub fn input_script_code(&self) -> Result<ScriptBuf, ZcashTransactionError> {
        let public_key = PublicKey::from_slice(&self.aggregate_public_key)
            .map_err(|_| ZcashTransactionError::InvalidPublicKey)?;
        Ok(ScriptBuf::new_p2pkh(&public_key.pubkey_hash()))
    }

    /// Implied transparent miner fee.
    ///
    /// # Errors
    /// Invalid totals or output inflation fails closed.
    pub fn fee_zatoshis(&self) -> Result<u64, ZcashTransactionError> {
        self.validate()?;
        let inputs = checked_input_total(&self.inputs)?;
        let outputs = checked_output_total(&self.outputs)?;
        inputs
            .checked_sub(outputs)
            .ok_or(ZcashTransactionError::OutputInflation { inputs, outputs })
    }

    /// Exact unsigned transaction bytes accepted by the pinned Recipes parser.
    ///
    /// # Errors
    /// Invalid transaction state fails closed.
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, ZcashTransactionError> {
        self.validate()?;
        let mut bytes = Vec::new();
        put_u32(&mut bytes, OVERWINTERED_V4);
        put_u32(&mut bytes, SAPLING_VERSION_GROUP_ID);
        write_compact_size(&mut bytes, self.inputs.len() as u64);
        for input in &self.inputs {
            bytes.extend(input.previous_txid.iter().rev());
            put_u32(&mut bytes, input.output_index);
            bytes.push(0);
            put_u32(&mut bytes, u32::MAX);
        }
        write_compact_size(&mut bytes, self.outputs.len() as u64);
        for output in &self.outputs {
            serialize_output(&mut bytes, output);
        }
        put_u32(&mut bytes, 0);
        put_u32(&mut bytes, 0);
        put_u64(&mut bytes, 0);
        bytes.extend_from_slice(&[0, 0, 0]);
        Ok(bytes)
    }

    /// Complete ordered ZIP-243 `BLAKE2b` signing-hash set, one per input.
    ///
    /// # Errors
    /// Invalid transaction state fails closed.
    pub fn signing_hashes(&self) -> Result<Vec<[u8; 32]>, ZcashTransactionError> {
        self.validate()?;
        let script_code = self.input_script_code()?;
        let hash_prevouts = self.hash_prevouts();
        let hash_sequence = self.hash_sequence();
        let hash_outputs = self.hash_outputs();
        let mut hashes = Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            let mut preimage = Vec::new();
            put_u32(&mut preimage, OVERWINTERED_V4);
            put_u32(&mut preimage, SAPLING_VERSION_GROUP_ID);
            preimage.extend_from_slice(&hash_prevouts);
            preimage.extend_from_slice(&hash_sequence);
            preimage.extend_from_slice(&hash_outputs);
            preimage.extend_from_slice(&[0; 96]);
            put_u32(&mut preimage, 0);
            put_u32(&mut preimage, 0);
            put_u64(&mut preimage, 0);
            put_u32(&mut preimage, SIGHASH_ALL);
            preimage.extend(input.previous_txid.iter().rev());
            put_u32(&mut preimage, input.output_index);
            write_compact_size(&mut preimage, script_code.len() as u64);
            preimage.extend_from_slice(script_code.as_bytes());
            put_u64(&mut preimage, input.value_zatoshis);
            put_u32(&mut preimage, u32::MAX);

            let mut personalization = *b"ZcashSigHash\0\0\0\0";
            personalization[12..].copy_from_slice(&NU6_1_BRANCH_ID.to_le_bytes());
            hashes.push(personalized_hash(&preimage, &personalization));
        }
        Ok(hashes)
    }

    /// Exact verifier `transactions` bytes: canonical unsigned bytes followed
    /// by the pinned Recipes `ZSH` public-key/sighash metadata envelope.
    ///
    /// # Errors
    /// Invalid transaction state fails closed.
    pub fn serialize_with_metadata(&self) -> Result<Vec<u8>, ZcashTransactionError> {
        let hashes = self.signing_hashes()?;
        let mut bytes = self.unsigned_bytes()?;
        bytes.extend_from_slice(METADATA_MAGIC);
        bytes.extend_from_slice(&self.aggregate_public_key);
        write_compact_size(&mut bytes, hashes.len() as u64);
        for hash in hashes {
            bytes.extend_from_slice(&hash);
        }
        Ok(bytes)
    }

    /// Stable double-SHA256 identity of the unsigned Sapling-v4 bytes.
    ///
    /// # Errors
    /// Invalid transaction state fails closed.
    pub fn unsigned_txid(&self) -> Result<[u8; 32], ZcashTransactionError> {
        Ok(sha256d::Hash::hash(&self.unsigned_bytes()?).to_byte_array())
    }

    /// Assemble broadcast-ready Sapling-v4 bytes from one already verified
    /// strict-DER low-S signature per transparent input.
    ///
    /// # Errors
    /// Invalid transaction state, signature count, or DER length fails closed.
    pub fn signed_bytes(
        &self,
        der_signatures: &[Vec<u8>],
    ) -> Result<Vec<u8>, ZcashTransactionError> {
        self.validate()?;
        if der_signatures.len() != self.inputs.len() {
            return Err(ZcashTransactionError::SignatureCount {
                expected: self.inputs.len(),
                actual: der_signatures.len(),
            });
        }

        let mut bytes = Vec::new();
        put_u32(&mut bytes, OVERWINTERED_V4);
        put_u32(&mut bytes, SAPLING_VERSION_GROUP_ID);
        write_compact_size(&mut bytes, self.inputs.len() as u64);
        for (input, der_signature) in self.inputs.iter().zip(der_signatures) {
            if der_signature.is_empty() || der_signature.len() > 72 {
                return Err(ZcashTransactionError::InvalidDerLength(der_signature.len()));
            }
            bytes.extend(input.previous_txid.iter().rev());
            put_u32(&mut bytes, input.output_index);

            let mut full_signature = der_signature.clone();
            full_signature.push(SIGHASH_ALL_BYTE);
            let script_length = 1 + full_signature.len() + 1 + self.aggregate_public_key.len();
            write_compact_size(&mut bytes, script_length as u64);
            let signature_push_length = u8::try_from(full_signature.len())
                .map_err(|_| ZcashTransactionError::InvalidDerLength(der_signature.len()))?;
            bytes.push(signature_push_length);
            bytes.extend_from_slice(&full_signature);
            bytes.push(COMPRESSED_PUBLIC_KEY_PUSH_LENGTH);
            bytes.extend_from_slice(&self.aggregate_public_key);
            put_u32(&mut bytes, u32::MAX);
        }
        write_compact_size(&mut bytes, self.outputs.len() as u64);
        for output in &self.outputs {
            serialize_output(&mut bytes, output);
        }
        put_u32(&mut bytes, 0);
        put_u32(&mut bytes, 0);
        put_u64(&mut bytes, 0);
        bytes.extend_from_slice(&[0, 0, 0]);
        Ok(bytes)
    }

    fn hash_prevouts(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(self.inputs.len() * 36);
        for input in &self.inputs {
            bytes.extend(input.previous_txid.iter().rev());
            put_u32(&mut bytes, input.output_index);
        }
        personalized_hash(&bytes, b"ZcashPrevoutHash")
    }

    fn hash_sequence(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(self.inputs.len() * 4);
        for _ in &self.inputs {
            put_u32(&mut bytes, u32::MAX);
        }
        personalized_hash(&bytes, b"ZcashSequencHash")
    }

    fn hash_outputs(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        for output in &self.outputs {
            serialize_output(&mut bytes, output);
        }
        personalized_hash(&bytes, b"ZcashOutputsHash")
    }
}

/// Invalid Zcash transparent transaction state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ZcashTransactionError {
    /// Aggregate key is not a compressed secp256k1 point.
    #[error("aggregate public key is not a compressed secp256k1 point")]
    InvalidPublicKey,
    /// At least one input is required.
    #[error("transparent Zcash transaction has no inputs")]
    NoInputs,
    /// At least one output is required.
    #[error("transparent Zcash transaction has no outputs")]
    NoOutputs,
    /// Input count exceeds the bounded profile.
    #[error("transparent Zcash transaction has too many inputs: {0}")]
    TooManyInputs(usize),
    /// Output count exceeds the bounded profile.
    #[error("transparent Zcash transaction has too many outputs: {0}")]
    TooManyOutputs(usize),
    /// Consensus-invalid duplicate outpoints are rejected before signing.
    #[error("transparent Zcash input {index} duplicates an earlier outpoint")]
    DuplicateInput {
        /// Duplicate transparent input index.
        index: usize,
    },
    /// Output script is empty or exceeds the consensus script bound.
    #[error("Zcash output {index} has invalid script length {length}")]
    InvalidOutputScript {
        /// Output index.
        index: usize,
        /// Observed script length.
        length: usize,
    },
    /// An input value or input sum exceeds the monetary range.
    #[error("transparent Zcash input value sum is invalid")]
    InputValueOverflow,
    /// An output value or output sum exceeds the monetary range.
    #[error("transparent Zcash output value sum is invalid")]
    OutputValueOverflow,
    /// Outputs create value relative to the certified inputs.
    #[error("transparent Zcash outputs {outputs} exceed inputs {inputs}")]
    OutputInflation {
        /// Total input value.
        inputs: u64,
        /// Total output value.
        outputs: u64,
    },
    /// Final assembly did not receive exactly one signature per input.
    #[error("Zcash signature count is {actual}, expected {expected}")]
    SignatureCount {
        /// Required signature count.
        expected: usize,
        /// Supplied signature count.
        actual: usize,
    },
    /// A strict DER ECDSA signature must fit the canonical 70–72-byte range.
    #[error("Zcash DER signature has invalid length {0}")]
    InvalidDerLength(usize),
}

fn checked_input_total(inputs: &[TransparentInput]) -> Result<u64, ZcashTransactionError> {
    inputs.iter().try_fold(0u64, |sum, input| {
        if input.value_zatoshis > MAX_MONEY_ZATOSHIS {
            return Err(ZcashTransactionError::InputValueOverflow);
        }
        sum.checked_add(input.value_zatoshis)
            .filter(|total| *total <= MAX_MONEY_ZATOSHIS)
            .ok_or(ZcashTransactionError::InputValueOverflow)
    })
}

fn checked_output_total(outputs: &[TransparentOutput]) -> Result<u64, ZcashTransactionError> {
    outputs.iter().try_fold(0u64, |sum, output| {
        if output.value_zatoshis > MAX_MONEY_ZATOSHIS {
            return Err(ZcashTransactionError::OutputValueOverflow);
        }
        sum.checked_add(output.value_zatoshis)
            .filter(|total| *total <= MAX_MONEY_ZATOSHIS)
            .ok_or(ZcashTransactionError::OutputValueOverflow)
    })
}

fn serialize_output(bytes: &mut Vec<u8>, output: &TransparentOutput) {
    put_u64(bytes, output.value_zatoshis);
    write_compact_size(bytes, output.script_pubkey.len() as u64);
    bytes.extend_from_slice(&output.script_pubkey);
}

fn personalized_hash(bytes: &[u8], personalization: &[u8; 16]) -> [u8; 32] {
    let mut params = Params::new();
    params.hash_length(32).personal(personalization);
    let digest = params.hash(bytes);
    let mut output = [0u8; 32];
    output.copy_from_slice(digest.as_bytes());
    output
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_compact_size(bytes: &mut Vec<u8>, value: u64) {
    if value < 0xfd {
        bytes.push(value.to_le_bytes()[0]);
    } else if let Ok(compact) = u16::try_from(value) {
        bytes.push(0xfd);
        bytes.extend_from_slice(&compact.to_le_bytes());
    } else if let Ok(compact) = u32::try_from(value) {
        bytes.push(0xfe);
        bytes.extend_from_slice(&compact.to_le_bytes());
    } else {
        bytes.push(0xff);
        bytes.extend_from_slice(&value.to_le_bytes());
    }
}

mod compressed_public_key_serde {
    use serde::de::Error as _;

    use super::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(key)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom("compressed public key must be exactly 33 bytes"))
    }
}
