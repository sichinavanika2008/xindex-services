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
    /// `OP_RETURN` memo exceeds the 80-byte standard null-data relay
    /// limit. `THORChain` swap memos (`=:ETH.USDT:0x<40>:<dec>` ≈ 60–70 B)
    /// fit comfortably; a longer memo would be non-standard and rejected
    /// by relay policy, so we fail closed before broadcasting.
    #[error("op_return memo {0} bytes exceeds 80-byte standard limit")]
    MemoTooLong(usize),
}

/// Standard-relay maximum for an `OP_RETURN` data push.
pub const MAX_OP_RETURN_BYTES: usize = 80;

/// Per-UTXO spend metadata: either a `SegWit` `witness_script` (BIP-143
/// sighash) or a legacy `redeem_script` + full prevout transaction
/// (pre-BIP-143 sighash preimage requires the full prevout).
#[derive(Debug, Clone)]
pub enum MultisigUtxoSpend {
    /// P2WSH (`SegWit`-v0). Sighash via [`SighashCache::p2wsh_signature_hash`]
    /// — BIP-143. PSBT input carries `witness_utxo` + `witness_script`.
    /// Used by BTC + LTC.
    Witness {
        /// Multi-K-of-N script that hashes (sha256) to the SPK's witness
        /// program. Returned by
        /// `descriptor.at_derivation_index(0)?.explicit_script()`.
        witness_script: ScriptBuf,
    },
    /// P2SH-legacy. Sighash via [`SighashCache::legacy_signature_hash`]
    /// — pre-BIP-143 preimage. PSBT input carries `non_witness_utxo`
    /// (full prevout tx) + `redeem_script`. Used by BCH (post-2017 no
    /// `SegWit` fork), DOGE (pre-`SegWit`), and ZEC transparent t-addr.
    NonWitness {
        /// The full prevout transaction. Required by PSBT
        /// `non_witness_utxo` and by the legacy sighash preimage, which
        /// hashes the prevout outpoint + the redeem-script (vs the
        /// trimmed-down BIP-143 preimage).
        prevout_tx: Transaction,
        /// The script inside the P2SH wrapper —
        /// `multi(K, pk_1, ..., pk_N)`. Hashes (ripemd160(sha256(·)))
        /// to the SPK's 20-byte program.
        redeem_script: ScriptBuf,
    },
}

/// One UTXO this multisig holds; passed to [`build_spending_psbt`] as
/// input descriptors.
#[derive(Debug, Clone)]
pub struct MultisigUtxo {
    pub outpoint: OutPoint,
    pub value: Amount,
    /// `script_pubkey` of the multisig address. For P2WSH this is
    /// `OP_0 <sha256(witness_script)>`; for P2SH-legacy it is
    /// `OP_HASH160 <ripemd160(sha256(redeem_script))> OP_EQUAL`.
    /// Equal to `descriptor.script_pubkey()`.
    pub script_pubkey: ScriptBuf,
    /// Spend metadata — drives both PSBT population and sighash
    /// computation branch.
    pub spend: MultisigUtxoSpend,
}

/// Build an unsigned PSBT that spends `inputs` to `recipient` for `value`.
/// Change handling is intentionally NOT here — the executor decides
/// fee + change policy at the call site (typically: spend exactly one
/// UTXO ≈ user's redemption amount; any change goes back to the
/// multisig).
///
/// `op_return`: optional null-data memo. The burn → USDT reverse flow
/// passes the `THORChain` swap memo (`=:ETH.USDT:<indexToken>:<minOut>`)
/// here so the Asgard deposit carries it. Output order is
/// `[recipient, OP_RETURN?, change?]` — the vault output is `vout[0]`
/// (`THORChain` matches the inbound by the vault address, reads the memo
/// from the `OP_RETURN`). Input order is preserved: `vin[0]` is
/// `inputs[0]`, which the executor guarantees is a multisig UTXO so
/// `THORChain` resolves any slip-refund back to our multisig.
///
/// # Errors
/// [`SignError::MemoTooLong`] if `op_return` exceeds
/// [`MAX_OP_RETURN_BYTES`]; [`SignError::Sighash`] if transaction
/// construction rejects the input shape (version / locktime).
pub fn build_spending_psbt(
    inputs: &[MultisigUtxo],
    recipient: &Address,
    recipient_value: Amount,
    change_to: Option<&Address>,
    change_value: Amount,
    op_return: Option<&[u8]>,
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
    if let Some(memo) = op_return {
        if memo.len() > MAX_OP_RETURN_BYTES {
            return Err(SignError::MemoTooLong(memo.len()));
        }
        let push = bitcoin::script::PushBytesBuf::try_from(memo.to_vec())
            .map_err(|_| SignError::MemoTooLong(memo.len()))?;
        tx_outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(push),
        });
    }
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

    // Populate per-input fields. The shape depends on the spend kind:
    //
    // - Witness (P2WSH): witness_utxo (single TxOut) + witness_script.
    //   BIP-143 sighash needs only the TxOut value + the witness script.
    // - NonWitness (P2SH-legacy): non_witness_utxo (full prevout tx) +
    //   redeem_script. Legacy sighash hashes the full prevout outpoint +
    //   the redeem script.
    //
    // Mixing variants across inputs of the same PSBT is supported by
    // PSBT itself; we do it cleanly here per-input.
    for (i, utxo) in inputs.iter().enumerate() {
        let input_slot = psbt
            .inputs
            .get_mut(i)
            .ok_or(SignError::InputIndexOutOfRange(i, inputs.len()))?;
        match &utxo.spend {
            MultisigUtxoSpend::Witness { witness_script } => {
                input_slot.witness_utxo = Some(TxOut {
                    value: utxo.value,
                    script_pubkey: utxo.script_pubkey.clone(),
                });
                input_slot.witness_script = Some(witness_script.clone());
            }
            MultisigUtxoSpend::NonWitness {
                prevout_tx,
                redeem_script,
            } => {
                input_slot.non_witness_utxo = Some(prevout_tx.clone());
                input_slot.redeem_script = Some(redeem_script.clone());
            }
        }
    }

    Ok(psbt)
}

/// Add this signer's partial ECDSA signature to one input of `psbt`.
///
/// The signer is identified by `secret_key`. The sighash algorithm is
/// chosen from the PSBT input's populated fields:
/// - `witness_utxo` + `witness_script` → BIP-143 `p2wsh_signature_hash`
///   (P2WSH; BTC/LTC).
/// - `non_witness_utxo` + `redeem_script` → legacy `legacy_signature_hash`
///   (P2SH-legacy; BCH/DOGE/ZEC).
///
/// Both branches sign with `SIGHASH_ALL` and insert the resulting
/// ECDSA partial signature into `partial_sigs`; finalization
/// (`finalize_psbt`) combines them into the right witness or `script_sig`
/// shape automatically.
///
/// # Errors
/// - [`SignError::InputIndexOutOfRange`] if `input_index` is invalid
/// - [`SignError::MissingWitnessUtxo`] if no witness OR non-witness
///   prevout is present (signer can't compute either preimage)
/// - [`SignError::MissingWitnessScript`] if the matching script is
///   missing for the populated UTXO kind
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

    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    // Sighash branch: presence of witness_utxo means a `SegWit` input,
    // presence of non_witness_utxo means a legacy input. Exactly one is
    // populated by build_spending_psbt; we fail loud if neither is.
    let sighash_bytes: [u8; 32] = if let Some(witness_utxo) = input.witness_utxo.as_ref() {
        let witness_script = input
            .witness_script
            .as_ref()
            .ok_or(SignError::MissingWitnessScript(input_index))?;
        cache
            .p2wsh_signature_hash(
                input_index,
                witness_script,
                witness_utxo.value,
                EcdsaSighashType::All,
            )
            .map_err(|e| SignError::Sighash(e.to_string()))?
            .to_byte_array()
    } else if input.non_witness_utxo.is_some() {
        let redeem_script = input
            .redeem_script
            .as_ref()
            .ok_or(SignError::MissingWitnessScript(input_index))?;
        cache
            .legacy_signature_hash(input_index, redeem_script, EcdsaSighashType::All.to_u32())
            .map_err(|e| SignError::Sighash(e.to_string()))?
            .to_byte_array()
    } else {
        return Err(SignError::MissingWitnessUtxo(input_index));
    };

    let msg = Message::from_digest(sighash_bytes);
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
            MultisigDescriptor::new_p2wsh(threshold, &pks).expect("descriptor"),
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
            spend: MultisigUtxoSpend::Witness { witness_script },
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
            None,
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
            spend: MultisigUtxoSpend::Witness { witness_script },
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
            None,
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
            spend: MultisigUtxoSpend::Witness { witness_script },
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
            None,
        )
        .expect("build");
        assert!(matches!(
            sign_psbt_input(&mut psbt, 99, &sks[0], desc.secp()),
            Err(SignError::InputIndexOutOfRange(99, 1))
        ));
    }

    /// Build a synthetic prevout transaction whose `vout[0]` pays the
    /// supplied SPK. The hash + value are real; the `witness` /
    /// `script_sig`
    /// fields are empty because nothing about this tx's history matters
    /// to the test — only its serialised bytes and its `vout[0]`
    /// `(value, script_pubkey)`.
    #[expect(clippy::expect_used, reason = "test helper")]
    fn synthetic_prevout(spk: &ScriptBuf, value: Amount) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000001",
                    )
                    .expect("txid"),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value,
                script_pubkey: spk.clone(),
            }],
        }
    }

    /// U5: P2SH-legacy end-to-end round-trip — build a P2SH-legacy
    /// 3-of-5 descriptor, construct a spending PSBT with
    /// `MultisigUtxoSpend::NonWitness`, sign with 3 keys (forces the
    /// `legacy_signature_hash` branch), finalize, and verify the
    /// extracted tx has a non-empty `script_sig` (legacy unlock) and an
    /// empty `witness` (no `SegWit` data).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn p2sh_legacy_psbt_round_trip_signs_with_legacy_sighash() {
        // 3-of-5 P2SH-legacy descriptor.
        let secp = Secp256k1::new();
        let sks: Vec<SecretKey> = (0..5)
            .map(|_| SecretKey::new(&mut rand::thread_rng()))
            .collect();
        let pks: Vec<PublicKey> = sks
            .iter()
            .map(|sk| PublicKey::new(sk.public_key(&secp)))
            .collect();
        let desc = MultisigDescriptor::new_p2sh_legacy(3, &pks).expect("descriptor");

        // SPK = OP_HASH160 <20B> OP_EQUAL, network-independent.
        let spk = desc.script_pubkey().expect("spk");
        // The redeem_script is the multi(K, pks...) script inside the
        // P2SH wrapper. miniscript's `explicit_script` returns it.
        let derived = desc.descriptor.at_derivation_index(0).expect("derive");
        let redeem_script = derived.explicit_script().expect("redeem script");
        // The synthetic prevout pays our SPK.
        let value = Amount::from_sat(1_000_000);
        let prevout_tx = synthetic_prevout(&spk, value);
        let prevout_txid = prevout_tx.compute_txid();
        let utxo = MultisigUtxo {
            outpoint: OutPoint {
                txid: prevout_txid,
                vout: 0,
            },
            value,
            script_pubkey: spk.clone(),
            spend: MultisigUtxoSpend::NonWitness {
                prevout_tx,
                redeem_script,
            },
        };

        // Spend to an arbitrary mainnet P2WPKH address (we're just
        // building a tx; the recipient's network is irrelevant to the
        // legacy sighash branch).
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
            None,
        )
        .expect("build");

        // PSBT shape per U5: non_witness_utxo + redeem_script populated,
        // witness_utxo + witness_script absent.
        assert!(psbt.inputs[0].non_witness_utxo.is_some());
        assert!(psbt.inputs[0].redeem_script.is_some());
        assert!(psbt.inputs[0].witness_utxo.is_none());
        assert!(psbt.inputs[0].witness_script.is_none());

        // Three signers add partial sigs (K = 3 of 5).
        for sk in sks.iter().take(3) {
            sign_psbt_input(&mut psbt, 0, sk, desc.secp()).expect("sign");
        }
        assert_eq!(
            psbt.inputs[0].partial_sigs.len(),
            3,
            "expected 3 distinct legacy partial sigs"
        );

        // Finalize + extract. miniscript's PsbtExt picks the right
        // finalizer (legacy script_sig assembly) automatically.
        let final_tx = finalize_psbt(&mut psbt, &desc).expect("finalize");

        // Legacy: script_sig populated, witness empty.
        assert!(
            !final_tx.input[0].script_sig.is_empty(),
            "legacy spend must have non-empty script_sig"
        );
        assert!(
            final_tx.input[0].witness.is_empty(),
            "legacy spend must have empty witness"
        );
    }
}
