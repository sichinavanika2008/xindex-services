//! PSBT primitives for the K-of-N P2WSH multisig path.
//!
//! Two flows:
//! - [`build_spending_psbt`]: executor-side. Build an unsigned PSBT
//!   spending one or more multisig UTXOs to a target recipient.
//! - [`sign_psbt_input`]: signer-side. Add this signer's partial
//!   signature to a specific input. The N independent signer daemons
//!   each call this with the input(s) they're authorized to sign.
//!
//! Finalization (combining ≥ K partial sigs into a final witness) is
//! delegated to `miniscript::psbt`'s standard machinery via
//! [`finalize_psbt`].

use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use thiserror::Error;

use crate::descriptor::MultisigDescriptor;

/// Errors surfaced by PSBT building or signing.
#[derive(Debug, Error)]
pub enum SignError {
    #[error("input index {0} out of range (psbt has {1} inputs)")]
    InputIndexOutOfRange(usize, usize),
    #[error("missing witness UTXO on input {0}")]
    MissingWitnessUtxo(usize),
    #[error("missing witness script on input {0}")]
    MissingWitnessScript(usize),
    #[error("sighash computation failed: {0}")]
    Sighash(String),
    #[error("psbt finalization failed: {0}")]
    Finalize(String),
    #[error("psbt extraction failed: {0}")]
    Extract(String),
}

/// One UTXO this multisig holds; passed to [`build_spending_psbt`] as
/// input descriptors.
#[derive(Debug, Clone)]
pub struct MultisigUtxo {
    pub outpoint: OutPoint,
    pub value: Amount,
    /// `script_pubkey` of the multisig address (P2WSH). Equal to
    /// `descriptor.address(network).script_pubkey()` — kept here so the
    /// caller doesn't need to re-derive it per UTXO.
    pub script_pubkey: ScriptBuf,
    /// The witness-script that hashes to the `script_pubkey`'s program.
    /// `descriptor.derived_descriptor(secp, 0)?.explicit_script()` →
    /// returns this. Required at sign time for sighash computation.
    pub witness_script: ScriptBuf,
}

/// Build an unsigned PSBT that spends `inputs` to `recipient` for `value`.
/// Change handling is intentionally NOT here — the executor decides
/// fee + change policy at the call site (typically: spend exactly one
/// UTXO ≈ user's redemption amount; any change goes back to the
/// multisig).
///
/// # Errors
/// Returns [`SignError::Sighash`] if the underlying transaction
/// construction rejects the input shape (currently only happens on
/// version / locktime mismatches; we use the canonical Bitcoin
/// transaction `Version::TWO`).
pub fn build_spending_psbt(
    inputs: &[MultisigUtxo],
    recipient: &Address,
    recipient_value: Amount,
    change_to: Option<&Address>,
    change_value: Amount,
) -> Result<Psbt, SignError> {
    let mut tx_inputs = Vec::with_capacity(inputs.len());
    for utxo in inputs {
        tx_inputs.push(TxIn {
            previous_output: utxo.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
    }

    let mut tx_outputs = vec![TxOut {
        value: recipient_value,
        script_pubkey: recipient.script_pubkey(),
    }];
    if let Some(change_addr) = change_to {
        if change_value > Amount::ZERO {
            tx_outputs.push(TxOut {
                value: change_value,
                script_pubkey: change_addr.script_pubkey(),
            });
        }
    }

    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: tx_inputs,
        output: tx_outputs,
    };

    let mut psbt =
        Psbt::from_unsigned_tx(unsigned_tx).map_err(|e| SignError::Sighash(e.to_string()))?;

    // Populate per-input witness UTXO + witness script. Without these
    // the signer can't compute the BIP-143 sighash.
    for (i, utxo) in inputs.iter().enumerate() {
        let input_slot = psbt
            .inputs
            .get_mut(i)
            .ok_or(SignError::InputIndexOutOfRange(i, inputs.len()))?;
        input_slot.witness_utxo = Some(TxOut {
            value: utxo.value,
            script_pubkey: utxo.script_pubkey.clone(),
        });
        input_slot.witness_script = Some(utxo.witness_script.clone());
    }

    Ok(psbt)
}

/// Add this signer's partial ECDSA signature to one input of `psbt`.
///
/// The signer is identified by `secret_key`. The signature is computed
/// against the BIP-143 segwit-v0 sighash of the input, using the
/// witness-script attached to the PSBT input.
///
/// # Errors
/// - [`SignError::InputIndexOutOfRange`] if `input_index` is invalid
/// - [`SignError::MissingWitnessUtxo`] if the PSBT input lacks the
///   `witness_utxo` field (set by [`build_spending_psbt`])
/// - [`SignError::MissingWitnessScript`] if the input lacks the
///   `witness_script` field
/// - [`SignError::Sighash`] if sighash computation fails
pub fn sign_psbt_input(
    psbt: &mut Psbt,
    input_index: usize,
    secret_key: &SecretKey,
    secp: &Secp256k1<All>,
) -> Result<(), SignError> {
    let n_inputs = psbt.inputs.len();
    let input = psbt
        .inputs
        .get(input_index)
        .ok_or(SignError::InputIndexOutOfRange(input_index, n_inputs))?
        .clone();

    let witness_utxo = input
        .witness_utxo
        .clone()
        .ok_or(SignError::MissingWitnessUtxo(input_index))?;
    let witness_script = input
        .witness_script
        .clone()
        .ok_or(SignError::MissingWitnessScript(input_index))?;

    // BIP-143 sighash for segwit-v0.
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = cache
        .p2wsh_signature_hash(
            input_index,
            &witness_script,
            witness_utxo.value,
            EcdsaSighashType::All,
        )
        .map_err(|e| SignError::Sighash(e.to_string()))?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_ecdsa(&msg, secret_key);
    let pubkey = bitcoin::PublicKey::new(secret_key.public_key(secp));

    let ecdsa_sig = bitcoin::ecdsa::Signature {
        signature,
        sighash_type: EcdsaSighashType::All,
    };

    let input_mut = psbt
        .inputs
        .get_mut(input_index)
        .ok_or(SignError::InputIndexOutOfRange(input_index, n_inputs))?;
    input_mut.partial_sigs.insert(pubkey, ecdsa_sig);
    Ok(())
}

/// Finalize a fully-signed PSBT (≥ K partial sigs collected) into a
/// broadcastable `Transaction`.
///
/// # Errors
/// Returns [`SignError::Finalize`] if any input lacks the required
/// number of partial signatures or [`SignError::Extract`] if the
/// finalized transaction is malformed (should not happen after a
/// successful finalize).
pub fn finalize_psbt(
    psbt: &mut Psbt,
    descriptor: &MultisigDescriptor,
) -> Result<Transaction, SignError> {
    miniscript::psbt::PsbtExt::finalize_mut(psbt, descriptor.secp())
        .map_err(|e| SignError::Finalize(format!("{e:?}")))?;
    psbt.clone()
        .extract_tx()
        .map_err(|e| SignError::Extract(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::MultisigDescriptor;
    use bitcoin::secp256k1::{rand, SecretKey};
    use bitcoin::{Network, OutPoint, PublicKey, Txid};
    use std::str::FromStr;

    /// Build a random K-of-N descriptor and return both descriptor and
    /// the underlying secret keys (so tests can sign).
    #[expect(clippy::expect_used, reason = "test code")]
    fn random_descriptor(threshold: usize, n: usize) -> (MultisigDescriptor, Vec<SecretKey>) {
        let secp = Secp256k1::new();
        let sks: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::new(&mut rand::thread_rng()))
            .collect();
        let pks: Vec<PublicKey> = sks
            .iter()
            .map(|sk| PublicKey::new(sk.public_key(&secp)))
            .collect();
        (
            MultisigDescriptor::new(threshold, &pks).expect("descriptor"),
            sks,
        )
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn dummy_outpoint() -> OutPoint {
        OutPoint {
            txid: Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000abc",
            )
            .expect("txid"),
            vout: 0,
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn build_spending_psbt_populates_inputs_and_outputs() {
        let (desc, _) = random_descriptor(3, 5);
        let address = desc.address(Network::Bitcoin).expect("addr");
        let derived = desc.descriptor.at_derivation_index(0).expect("derive");
        let witness_script = derived.explicit_script().expect("script");

        let utxo = MultisigUtxo {
            outpoint: dummy_outpoint(),
            value: Amount::from_sat(1_000_000),
            script_pubkey: address.script_pubkey(),
            witness_script,
        };

        let recipient = Address::from_str("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
            .expect("addr")
            .require_network(Network::Bitcoin)
            .expect("network");

        let psbt = build_spending_psbt(
            std::slice::from_ref(&utxo),
            &recipient,
            Amount::from_sat(950_000),
            None,
            Amount::ZERO,
        )
        .expect("build");

        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.outputs.len(), 1);
        assert!(psbt.inputs[0].witness_utxo.is_some());
        assert!(psbt.inputs[0].witness_script.is_some());
        assert_eq!(psbt.unsigned_tx.output[0].value, Amount::from_sat(950_000));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn sign_psbt_input_records_partial_sig_per_signer() {
        let (desc, sks) = random_descriptor(3, 5);
        let address = desc.address(Network::Bitcoin).expect("addr");
        let derived = desc.descriptor.at_derivation_index(0).expect("derive");
        let witness_script = derived.explicit_script().expect("script");
        let utxo = MultisigUtxo {
            outpoint: dummy_outpoint(),
            value: Amount::from_sat(1_000_000),
            script_pubkey: address.script_pubkey(),
            witness_script,
        };
        let recipient = Address::from_str("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
            .expect("addr")
            .require_network(Network::Bitcoin)
            .expect("network");
        let mut psbt = build_spending_psbt(
            &[utxo],
            &recipient,
            Amount::from_sat(950_000),
            None,
            Amount::ZERO,
        )
        .expect("build");

        // Three signers add their partial sigs (K = 3 of 5).
        for sk in sks.iter().take(3) {
            sign_psbt_input(&mut psbt, 0, sk, desc.secp()).expect("sign");
        }
        assert_eq!(
            psbt.inputs[0].partial_sigs.len(),
            3,
            "expected 3 distinct partial sigs"
        );
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn sign_psbt_input_rejects_invalid_index() {
        let (desc, sks) = random_descriptor(2, 3);
        let address = desc.address(Network::Bitcoin).expect("addr");
        let derived = desc.descriptor.at_derivation_index(0).expect("derive");
        let witness_script = derived.explicit_script().expect("script");
        let utxo = MultisigUtxo {
            outpoint: dummy_outpoint(),
            value: Amount::from_sat(1_000_000),
            script_pubkey: address.script_pubkey(),
            witness_script,
        };
        let recipient = Address::from_str("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
            .expect("addr")
            .require_network(Network::Bitcoin)
            .expect("network");
        let mut psbt = build_spending_psbt(
            &[utxo],
            &recipient,
            Amount::from_sat(950_000),
            None,
            Amount::ZERO,
        )
        .expect("build");
        assert!(matches!(
            sign_psbt_input(&mut psbt, 99, &sks[0], desc.secp()),
            Err(SignError::InputIndexOutOfRange(99, 1))
        ));
    }
}
