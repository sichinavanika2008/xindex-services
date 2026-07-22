//! Direct single-key PSBT validation and signing-hash derivation.
//!
//! This is separate from the repository's existing script-multisig path. It
//! models the transaction shapes used by a Vultisig aggregate key: native
//! P2WPKH for BTC/LTC and P2PKH for BCH/DOGE. Zcash uses a different Sapling
//! transaction envelope and is deliberately routed to its own profile.

use bitcoin::consensus::serialize;
use bitcoin::hashes::{sha256d, Hash as _};
use bitcoin::psbt::Psbt;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{PublicKey, ScriptBuf, TxOut};
use std::collections::HashSet;
use xindex_shared::chain_registry::ChainId;

const SIGHASH_ALL: u32 = 0x01;
const SIGHASH_ALL_FORKID: u32 = 0x41;

/// Fail-closed direct-key PSBT validation or sighash error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SingleKeySighashError {
    /// The supplied chain is not one of the five UTXO families.
    #[error("{0:?} is not a UTXO custody chain")]
    WrongFamily(ChainId),
    /// Zcash requires a Sapling transaction rather than Bitcoin PSBT framing.
    #[error("Zcash direct signing requires the separate Sapling transaction profile")]
    ZcashRequiresSaplingProfile,
    /// The configured aggregate public key is not a compressed secp256k1 key.
    #[error("aggregate public key is not a compressed secp256k1 point")]
    InvalidPublicKey,
    /// A direct-key transaction must contain at least one input.
    #[error("direct aggregate-key PSBT has no inputs")]
    NoInputs,
    /// PSBT input maps must correspond one-to-one with transaction inputs.
    #[error("PSBT has {maps} input maps for {transaction} transaction inputs")]
    InputCount {
        /// Unsigned transaction input count.
        transaction: usize,
        /// PSBT input-map count.
        maps: usize,
    },
    /// Consensus-invalid duplicate outpoints are rejected before signing.
    #[error("PSBT transaction input {input} duplicates an earlier outpoint")]
    DuplicateInput {
        /// Duplicate transaction input index.
        input: usize,
    },
    /// The PSBT does not commit exactly to the configured aggregate key.
    #[error("PSBT input {input} BIP-32 public key differs from the configured aggregate key")]
    PublicKeyMismatch {
        /// Input index.
        input: usize,
    },
    /// The PSBT already carries signing/finalization material.
    #[error("PSBT input {input} is not unsigned")]
    AlreadySigned {
        /// Input index.
        input: usize,
    },
    /// The exact mandatory sighash type was not explicitly pinned.
    #[error("PSBT input {input} sighash type is {actual:?}, expected {expected:#x}")]
    SighashType {
        /// Input index.
        input: usize,
        /// Raw supplied sighash flag, or `None` when omitted.
        actual: Option<u32>,
        /// Chain-required raw sighash flag.
        expected: u32,
    },
    /// A `SegWit` direct-key input is missing its exact witness UTXO.
    #[error("PSBT input {input} is missing its witness UTXO")]
    MissingWitnessUtxo {
        /// Input index.
        input: usize,
    },
    /// A legacy direct-key input is missing its full previous transaction.
    #[error("PSBT input {input} is missing its non-witness UTXO")]
    MissingNonWitnessUtxo {
        /// Input index.
        input: usize,
    },
    /// Previous-transaction identity or output index is inconsistent.
    #[error("PSBT input {input} previous output is inconsistent: {message}")]
    PreviousOutput {
        /// Input index.
        input: usize,
        /// Mismatch detail.
        message: String,
    },
    /// The previous output is not the direct-key script required by the chain.
    #[error("PSBT input {input} does not spend the configured aggregate-key {expected} script")]
    ScriptMismatch {
        /// Input index.
        input: usize,
        /// Required script class.
        expected: &'static str,
    },
    /// A script wrapper from the legacy multisig profile leaked into this path.
    #[error("PSBT input {input} contains an unexpected redeem or witness script")]
    UnexpectedScript {
        /// Input index.
        input: usize,
    },
    /// Bitcoin-library sighash calculation failed.
    #[error("PSBT input {input} signing hash failed: {message}")]
    Sighash {
        /// Input index.
        input: usize,
        /// Library error.
        message: String,
    },
}

/// Validate a direct aggregate-key PSBT and derive its complete ordered
/// per-input signing-hash set.
///
/// # Errors
/// Any key/script/profile/sighash/prevout mismatch fails closed. Zcash is
/// explicitly rejected because its Sapling envelope is not a Bitcoin PSBT.
#[expect(
    clippy::too_many_lines,
    reason = "one exhaustive chain-family match keeps each direct-key signing profile explicit"
)]
pub fn derive_single_key_psbt_sighashes(
    chain: ChainId,
    psbt: &Psbt,
    aggregate_public_key: &[u8; 33],
) -> Result<Vec<[u8; 32]>, SingleKeySighashError> {
    match chain {
        ChainId::Btc | ChainId::Ltc | ChainId::Bch | ChainId::Doge => {}
        ChainId::Zec => return Err(SingleKeySighashError::ZcashRequiresSaplingProfile),
        ChainId::Eth
        | ChainId::Bsc
        | ChainId::Avax
        | ChainId::Base
        | ChainId::Pol
        | ChainId::Gaia
        | ChainId::Noble
        | ChainId::Xrp
        | ChainId::Sol
        | ChainId::Tron => return Err(SingleKeySighashError::WrongFamily(chain)),
    }

    let public_key = PublicKey::from_slice(aggregate_public_key)
        .map_err(|_| SingleKeySighashError::InvalidPublicKey)?;
    if psbt.unsigned_tx.input.is_empty() {
        return Err(SingleKeySighashError::NoInputs);
    }
    if psbt.inputs.len() != psbt.unsigned_tx.input.len() {
        return Err(SingleKeySighashError::InputCount {
            transaction: psbt.unsigned_tx.input.len(),
            maps: psbt.inputs.len(),
        });
    }
    let mut seen_outpoints = HashSet::with_capacity(psbt.unsigned_tx.input.len());
    for (input_index, input) in psbt.unsigned_tx.input.iter().enumerate() {
        if !seen_outpoints.insert(input.previous_output) {
            return Err(SingleKeySighashError::DuplicateInput { input: input_index });
        }
    }
    let mut hashes = Vec::with_capacity(psbt.inputs.len());
    for (input_index, input) in psbt.inputs.iter().enumerate() {
        if input.bip32_derivation.len() != 1
            || !input.bip32_derivation.contains_key(&public_key.inner)
        {
            return Err(SingleKeySighashError::PublicKeyMismatch { input: input_index });
        }
        if !input.partial_sigs.is_empty()
            || input.tap_key_sig.is_some()
            || !input.tap_script_sigs.is_empty()
            || input.final_script_sig.is_some()
            || input.final_script_witness.is_some()
            || !psbt.unsigned_tx.input[input_index].script_sig.is_empty()
            || !psbt.unsigned_tx.input[input_index].witness.is_empty()
        {
            return Err(SingleKeySighashError::AlreadySigned { input: input_index });
        }

        let required_sighash = if chain == ChainId::Bch {
            SIGHASH_ALL_FORKID
        } else {
            SIGHASH_ALL
        };
        let actual_sighash = input
            .sighash_type
            .map(bitcoin::psbt::PsbtSighashType::to_u32);
        if actual_sighash != Some(required_sighash) {
            return Err(SingleKeySighashError::SighashType {
                input: input_index,
                actual: actual_sighash,
                expected: required_sighash,
            });
        }

        let hash = match chain {
            ChainId::Btc | ChainId::Ltc => {
                if input.redeem_script.is_some() || input.witness_script.is_some() {
                    return Err(SingleKeySighashError::UnexpectedScript { input: input_index });
                }
                let previous = input
                    .witness_utxo
                    .as_ref()
                    .ok_or(SingleKeySighashError::MissingWitnessUtxo { input: input_index })?;
                let expected_script = ScriptBuf::new_p2wpkh(
                    &public_key
                        .wpubkey_hash()
                        .map_err(|_| SingleKeySighashError::InvalidPublicKey)?,
                );
                if previous.script_pubkey != expected_script {
                    return Err(SingleKeySighashError::ScriptMismatch {
                        input: input_index,
                        expected: "P2WPKH",
                    });
                }
                SighashCache::new(&psbt.unsigned_tx)
                    .p2wpkh_signature_hash(
                        input_index,
                        &previous.script_pubkey,
                        previous.value,
                        EcdsaSighashType::All,
                    )
                    .map_err(|error| SingleKeySighashError::Sighash {
                        input: input_index,
                        message: error.to_string(),
                    })?
                    .to_byte_array()
            }
            ChainId::Bch | ChainId::Doge => {
                if input.redeem_script.is_some() || input.witness_script.is_some() {
                    return Err(SingleKeySighashError::UnexpectedScript { input: input_index });
                }
                let previous = direct_legacy_previous_output(psbt, input_index)?;
                let expected_script = ScriptBuf::new_p2pkh(&public_key.pubkey_hash());
                if previous.script_pubkey != expected_script {
                    return Err(SingleKeySighashError::ScriptMismatch {
                        input: input_index,
                        expected: "P2PKH",
                    });
                }
                if chain == ChainId::Bch {
                    bch_forkid_sighash(psbt, input_index, previous)
                } else {
                    SighashCache::new(&psbt.unsigned_tx)
                        .legacy_signature_hash(
                            input_index,
                            &previous.script_pubkey,
                            EcdsaSighashType::All.to_u32(),
                        )
                        .map_err(|error| SingleKeySighashError::Sighash {
                            input: input_index,
                            message: error.to_string(),
                        })?
                        .to_byte_array()
                }
            }
            ChainId::Zec
            | ChainId::Eth
            | ChainId::Bsc
            | ChainId::Avax
            | ChainId::Base
            | ChainId::Pol
            | ChainId::Gaia
            | ChainId::Noble
            | ChainId::Xrp
            | ChainId::Sol
            | ChainId::Tron => unreachable!("chain family checked before the input loop"),
        };
        hashes.push(hash);
    }
    Ok(hashes)
}

fn direct_legacy_previous_output(
    psbt: &Psbt,
    input_index: usize,
) -> Result<&TxOut, SingleKeySighashError> {
    let input = &psbt.inputs[input_index];
    let previous_tx = input
        .non_witness_utxo
        .as_ref()
        .ok_or(SingleKeySighashError::MissingNonWitnessUtxo { input: input_index })?;
    let outpoint = psbt.unsigned_tx.input[input_index].previous_output;
    if previous_tx.compute_txid() != outpoint.txid {
        return Err(SingleKeySighashError::PreviousOutput {
            input: input_index,
            message: "non-witness transaction txid differs from the input outpoint".to_string(),
        });
    }
    previous_tx
        .output
        .get(usize::try_from(outpoint.vout).unwrap_or(usize::MAX))
        .ok_or_else(|| SingleKeySighashError::PreviousOutput {
            input: input_index,
            message: format!("vout {} is outside the previous transaction", outpoint.vout),
        })
}

fn bch_forkid_sighash(psbt: &Psbt, input_index: usize, previous: &TxOut) -> [u8; 32] {
    let transaction = &psbt.unsigned_tx;

    let mut previous_outputs = Vec::with_capacity(transaction.input.len() * 36);
    let mut sequences = Vec::with_capacity(transaction.input.len() * 4);
    for input in &transaction.input {
        previous_outputs.extend_from_slice(&serialize(&input.previous_output));
        sequences.extend_from_slice(&input.sequence.to_consensus_u32().to_le_bytes());
    }
    let mut outputs = Vec::new();
    for output in &transaction.output {
        outputs.extend_from_slice(&serialize(output));
    }

    let input = &transaction.input[input_index];
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&transaction.version.0.to_le_bytes());
    preimage.extend_from_slice(&sha256d::Hash::hash(&previous_outputs).to_byte_array());
    preimage.extend_from_slice(&sha256d::Hash::hash(&sequences).to_byte_array());
    preimage.extend_from_slice(&serialize(&input.previous_output));
    preimage.extend_from_slice(&serialize(&previous.script_pubkey));
    preimage.extend_from_slice(&previous.value.to_sat().to_le_bytes());
    preimage.extend_from_slice(&input.sequence.to_consensus_u32().to_le_bytes());
    preimage.extend_from_slice(&sha256d::Hash::hash(&outputs).to_byte_array());
    preimage.extend_from_slice(&transaction.lock_time.to_consensus_u32().to_le_bytes());
    preimage.extend_from_slice(&SIGHASH_ALL_FORKID.to_le_bytes());
    sha256d::Hash::hash(&preimage).to_byte_array()
}
