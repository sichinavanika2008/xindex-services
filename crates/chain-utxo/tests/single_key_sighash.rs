#![expect(
    clippy::expect_used,
    reason = "fixed transaction fixtures should fail loudly in tests"
)]

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::hashes::Hash as _;
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use xindex_chain_utxo::single_key::{derive_single_key_psbt_sighashes, SingleKeySighashError};
use xindex_shared::chain_registry::ChainId;

const GENERATOR: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

fn public_key() -> PublicKey {
    PublicKey::from_slice(&GENERATOR).expect("fixed public key")
}

fn tx_input(outpoint: OutPoint) -> TxIn {
    TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}

fn previous_transaction(script_pubkey: ScriptBuf) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![tx_input(OutPoint::null())],
        output: vec![TxOut {
            value: Amount::from_sat(200_000),
            script_pubkey,
        }],
    }
}

fn spending_psbt(chain: ChainId) -> Psbt {
    let public_key = public_key();
    let previous_script = match chain {
        ChainId::Btc | ChainId::Ltc => ScriptBuf::new_p2wpkh(
            &public_key
                .wpubkey_hash()
                .expect("compressed public key has witness hash"),
        ),
        ChainId::Bch | ChainId::Doge | ChainId::Zec => {
            ScriptBuf::new_p2pkh(&public_key.pubkey_hash())
        }
        _ => unreachable!("UTXO fixture chain"),
    };
    let previous = previous_transaction(previous_script.clone());
    let outpoint = OutPoint {
        txid: previous.compute_txid(),
        vout: 0,
    };
    let unsigned = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![tx_input(outpoint)],
        output: vec![TxOut {
            value: Amount::from_sat(199_000),
            script_pubkey: ScriptBuf::new_p2pkh(&public_key.pubkey_hash()),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("PSBT");
    let input = &mut psbt.inputs[0];
    input.bip32_derivation.insert(
        public_key.inner,
        (Fingerprint::default(), DerivationPath::default()),
    );
    match chain {
        ChainId::Btc | ChainId::Ltc => {
            input.witness_utxo = Some(previous.output[0].clone());
            input.sighash_type = Some(EcdsaSighashType::All.into());
        }
        ChainId::Bch => {
            input.non_witness_utxo = Some(previous);
            input.sighash_type = Some(PsbtSighashType::from_u32(0x41));
        }
        ChainId::Doge | ChainId::Zec => {
            input.non_witness_utxo = Some(previous);
            input.sighash_type = Some(EcdsaSighashType::All.into());
        }
        _ => unreachable!("UTXO fixture chain"),
    }
    psbt
}

#[test]
fn bitcoin_and_litecoin_match_native_p2wpkh_sighash() {
    for chain in [ChainId::Btc, ChainId::Ltc] {
        let psbt = spending_psbt(chain);
        let expected = SighashCache::new(&psbt.unsigned_tx)
            .p2wpkh_signature_hash(
                0,
                &psbt.inputs[0]
                    .witness_utxo
                    .as_ref()
                    .expect("witness UTXO")
                    .script_pubkey,
                Amount::from_sat(200_000),
                EcdsaSighashType::All,
            )
            .expect("BIP143")
            .to_byte_array();

        assert_eq!(
            derive_single_key_psbt_sighashes(chain, &psbt, &GENERATOR).expect("derive"),
            vec![expected],
            "{chain:?}"
        );
    }
}

#[test]
fn dogecoin_matches_legacy_sighash() {
    let psbt = spending_psbt(ChainId::Doge);
    let script = &psbt.inputs[0]
        .non_witness_utxo
        .as_ref()
        .expect("previous tx")
        .output[0]
        .script_pubkey;
    let expected = SighashCache::new(&psbt.unsigned_tx)
        .legacy_signature_hash(0, script, EcdsaSighashType::All.to_u32())
        .expect("legacy sighash")
        .to_byte_array();

    assert_eq!(
        derive_single_key_psbt_sighashes(ChainId::Doge, &psbt, &GENERATOR).expect("derive"),
        vec![expected]
    );
}

#[test]
fn bitcoin_cash_uses_forkid_bip143_not_btc_legacy() {
    let psbt = spending_psbt(ChainId::Bch);
    let derived =
        derive_single_key_psbt_sighashes(ChainId::Bch, &psbt, &GENERATOR).expect("BCH derive");
    let script = &psbt.inputs[0]
        .non_witness_utxo
        .as_ref()
        .expect("previous tx")
        .output[0]
        .script_pubkey;
    let wrong_legacy = SighashCache::new(&psbt.unsigned_tx)
        .legacy_signature_hash(0, script, EcdsaSighashType::All.to_u32())
        .expect("legacy")
        .to_byte_array();

    assert_eq!(
        alloy_primitives::hex::encode(derived[0]),
        "781b629374af68fce7067558154599cd88973e537937ca972b0277fad0ece759"
    );
    assert_ne!(derived[0], wrong_legacy);
}

#[test]
fn wrong_key_and_missing_explicit_sighash_fail_closed() {
    let mut psbt = spending_psbt(ChainId::Btc);
    assert!(matches!(
        derive_single_key_psbt_sighashes(ChainId::Btc, &psbt, &[0x03; 33]),
        Err(SingleKeySighashError::InvalidPublicKey
            | SingleKeySighashError::PublicKeyMismatch { .. })
    ));

    psbt.inputs[0].sighash_type = None;
    assert!(matches!(
        derive_single_key_psbt_sighashes(ChainId::Btc, &psbt, &GENERATOR),
        Err(SingleKeySighashError::SighashType { .. })
    ));
}

#[test]
fn mismatched_psbt_input_maps_fail_closed_without_panicking() {
    let mut extra_map = spending_psbt(ChainId::Btc);
    extra_map.inputs.push(extra_map.inputs[0].clone());
    assert!(derive_single_key_psbt_sighashes(ChainId::Btc, &extra_map, &GENERATOR).is_err());

    let mut missing_map = spending_psbt(ChainId::Btc);
    missing_map.inputs.clear();
    assert!(derive_single_key_psbt_sighashes(ChainId::Btc, &missing_map, &GENERATOR).is_err());
}

#[test]
fn duplicate_transaction_inputs_fail_closed() {
    let mut psbt = spending_psbt(ChainId::Btc);
    psbt.unsigned_tx
        .input
        .push(psbt.unsigned_tx.input[0].clone());
    psbt.inputs.push(psbt.inputs[0].clone());

    assert!(derive_single_key_psbt_sighashes(ChainId::Btc, &psbt, &GENERATOR).is_err());
}

#[test]
fn taproot_signature_material_fails_the_unsigned_profile() {
    let mut psbt = spending_psbt(ChainId::Btc);
    psbt.inputs[0].tap_key_sig = Some(
        bitcoin::taproot::Signature::from_slice(&[1; 64]).expect("fixed Schnorr signature bytes"),
    );

    assert!(derive_single_key_psbt_sighashes(ChainId::Btc, &psbt, &GENERATOR).is_err());
}

#[test]
fn zcash_requires_its_separate_sapling_transaction_profile() {
    let psbt = spending_psbt(ChainId::Zec);
    assert!(matches!(
        derive_single_key_psbt_sighashes(ChainId::Zec, &psbt, &GENERATOR),
        Err(SingleKeySighashError::ZcashRequiresSaplingProfile)
    ));
}

#[test]
fn non_utxo_chain_is_rejected() {
    let psbt = spending_psbt(ChainId::Btc);
    assert!(matches!(
        derive_single_key_psbt_sighashes(ChainId::Eth, &psbt, &GENERATOR),
        Err(SingleKeySighashError::WrongFamily(ChainId::Eth))
    ));
}

#[test]
fn fixture_previous_transaction_is_not_the_null_txid() {
    assert_ne!(
        spending_psbt(ChainId::Btc).unsigned_tx.input[0]
            .previous_output
            .txid,
        Txid::all_zeros()
    );
}
