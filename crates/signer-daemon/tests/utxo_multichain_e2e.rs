#![expect(
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::too_many_lines,
    reason = "integration test fixtures fail loudly on malformed cryptographic state"
)]
//! BTC + LTC UTXO-family end-to-end coverage (P3.1-9/P3.1-10).
//!
//! The first test parameterizes the production descriptor, address codec,
//! PSBT builder, BIP-143 signer, and miniscript finalizer over both SegWit
//! chains. The second boots one real signer-daemon with two UTXO roles and
//! proves chain-id routing, distinct key aliases/descriptors, chain-scoped
//! replay isolation, CTD-1 certificate binding, and wrong-role rejection.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, B256};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::{
    absolute, transaction, Address as BitcoinAddress, Amount, Network, OutPoint, PublicKey,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use xindex_chain_utxo::{
    BchCodec, BtcCodec, DogeCodec, LtcCodec, ScriptKind, UtxoAddressCodec, UtxoParams, ZecCodec,
};
use xindex_executor::remote_cosigner::RemoteMultisigCosigner;
use xindex_executor::{ExpectedOutputs, MultisigCosigner, SpendCertificate};
use xindex_multisig::psbt::SighashFlavor;
use xindex_multisig::{
    build_spending_psbt, finalize_psbt, sign_psbt_input, MultisigDescriptor, MultisigUtxo,
    MultisigUtxoSpend, SignError,
};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::IntentProof;
use xindex_signer_daemon::psbt::UtxoSignerConfig;
use xindex_signer_daemon::replay::InMemoryReplayStore;
use xindex_signer_daemon::server::{router, CertVolumePolicy, DaemonConfig, DaemonState};
use xindex_signer_daemon::web3signer::{HsmDigestSigner, HsmError};

mod ric_common;

const ETH_CHAIN_ID: u64 = 31_337;
const VERIFYING_CONTRACT: Address = Address::repeat_byte(0xab);
const INPUT_SATS: u64 = 100_000;
const PAYOUT_SATS: u64 = 90_000;
const CHANGE_SATS: u64 = 9_000;

#[derive(Debug)]
struct ChainFixture {
    chain: ChainId,
    descriptor: MultisigDescriptor,
    keys: Vec<SecretKey>,
    hsm_address: Address,
}

impl ChainFixture {
    fn new(chain: ChainId, key_seed: u8, hsm_address: Address) -> Self {
        let secp = Secp256k1::new();
        let keys = (0..3u8)
            .map(|offset| {
                SecretKey::from_slice(&[key_seed.saturating_add(offset); 32]).expect("secret key")
            })
            .collect::<Vec<_>>();
        let pubkeys = keys
            .iter()
            .map(|key| PublicKey::new(key.public_key(&secp)))
            .collect::<Vec<_>>();
        let descriptor = MultisigDescriptor::new_p2wsh(2, &pubkeys).expect("2-of-3 P2WSH");
        Self {
            chain,
            descriptor,
            keys,
            hsm_address,
        }
    }

    fn my_pubkey(&self) -> PublicKey {
        PublicKey::new(self.keys[0].public_key(self.descriptor.secp()))
    }

    fn signer_config(&self) -> UtxoSignerConfig {
        UtxoSignerConfig {
            chain_id: self.chain,
            network: Network::Bitcoin,
            descriptor: self.descriptor.clone(),
            my_pubkey: self.my_pubkey(),
            hsm_address: self.hsm_address,
        }
    }

    fn canonical_multisig_address(&self) -> String {
        let script = self.descriptor.script_pubkey().expect("multisig script");
        if self.chain == ChainId::Btc {
            BtcCodec::mainnet().encode(&script).expect("BTC address")
        } else {
            assert_eq!(self.chain, ChainId::Ltc);
            LtcCodec::mainnet().encode(&script).expect("LTC address")
        }
    }

    fn decode_multisig_address(&self, address: &str) -> ScriptBuf {
        if self.chain == ChainId::Btc {
            BtcCodec::mainnet().decode(address).expect("BTC decode")
        } else {
            assert_eq!(self.chain, ChainId::Ltc);
            LtcCodec::mainnet().decode(address).expect("LTC decode")
        }
    }
}

#[derive(Debug, Clone)]
struct BuiltSpend {
    psbt: Psbt,
    destination_spk: ScriptBuf,
    change_spk: ScriptBuf,
    memo: Vec<u8>,
}

impl BuiltSpend {
    fn expected_outputs(&self) -> ExpectedOutputs {
        ExpectedOutputs {
            destination_spk: self.destination_spk.clone().into_bytes(),
            amount_sats: PAYOUT_SATS,
            memo: self.memo.clone(),
        }
    }

    fn proof(&self, chain: ChainId, redemption_tag: u8) -> IntentProof {
        ric_common::proof(
            ETH_CHAIN_ID,
            VERIFYING_CONTRACT,
            chain,
            redemption_tag,
            0,
            u128::from(PAYOUT_SATS),
            self.destination_spk.as_bytes(),
            &self.memo,
        )
    }
}

fn build_chain_spend(fixture: &ChainFixture, outpoint_tag: u8) -> BuiltSpend {
    let params = UtxoParams::for_chain(fixture.chain);
    let derived = fixture
        .descriptor
        .descriptor
        .at_derivation_index(0)
        .expect("derive descriptor");
    let witness_script = derived.explicit_script().expect("witness script");
    let change = fixture
        .descriptor
        .address(Network::Bitcoin)
        .expect("change address");
    let recipient = BitcoinAddress::from_str("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
        .expect("recipient")
        .require_network(Network::Bitcoin)
        .expect("recipient network");
    let destination_spk = recipient.script_pubkey();
    let memo = format!(
        "=:ETH.USDT:0x{:040x}:0",
        u8::from(fixture.chain == ChainId::Ltc)
    )
    .into_bytes();
    let utxo = MultisigUtxo {
        outpoint: OutPoint {
            txid: Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([outpoint_tag; 32])),
            vout: 0,
        },
        value: Amount::from_sat(INPUT_SATS),
        script_pubkey: change.script_pubkey(),
        spend: MultisigUtxoSpend::Witness { witness_script },
    };
    let psbt = build_spending_psbt(
        &[utxo],
        &recipient,
        Amount::from_sat(PAYOUT_SATS),
        Some(&change),
        Amount::from_sat(CHANGE_SATS),
        Some(&memo),
        params.op_return_max,
    )
    .expect("build chain PSBT");
    BuiltSpend {
        psbt,
        destination_spk,
        change_spk: change.script_pubkey(),
        memo,
    }
}

fn assert_finalized_spend(spend: &BuiltSpend, tx: &bitcoin::Transaction) {
    let memo_push = bitcoin::script::PushBytesBuf::try_from(spend.memo.clone()).expect("memo push");
    assert_eq!(tx.output.len(), 3, "payout + memo + change");
    assert_eq!(tx.output[0].value, Amount::from_sat(PAYOUT_SATS));
    assert_eq!(tx.output[0].script_pubkey, spend.destination_spk);
    assert_eq!(tx.output[1].value, Amount::ZERO);
    assert_eq!(
        tx.output[1].script_pubkey,
        ScriptBuf::new_op_return(memo_push)
    );
    assert_eq!(tx.output[2].value, Amount::from_sat(CHANGE_SATS));
    assert_eq!(tx.output[2].script_pubkey, spend.change_spk);
    assert!(tx.input[0].script_sig.is_empty(), "P2WSH has no scriptSig");
    assert!(!tx.input[0].witness.is_empty(), "finalized P2WSH witness");
    let output_total = tx
        .output
        .iter()
        .map(|output| output.value.to_sat())
        .sum::<u64>();
    assert_eq!(INPUT_SATS - output_total, 1_000, "exact implied miner fee");
}

#[derive(Default)]
struct MultiChainHsm {
    keys: HashMap<Address, SecretKey>,
    invocations: Mutex<HashMap<Address, usize>>,
}

impl std::fmt::Debug for MultiChainHsm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MultiChainHsm")
            .field("key_aliases", &self.keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl MultiChainHsm {
    fn with_key(mut self, address: Address, key: SecretKey) -> Self {
        self.keys.insert(address, key);
        self
    }

    fn invocation_count(&self, address: Address) -> usize {
        *self
            .invocations
            .lock()
            .expect("invocation lock")
            .get(&address)
            .unwrap_or(&0)
    }
}

#[async_trait::async_trait]
impl HsmDigestSigner for MultiChainHsm {
    async fn sign_digest(&self, address: Address, digest: B256) -> Result<[u8; 65], HsmError> {
        let key = self
            .keys
            .get(&address)
            .ok_or_else(|| HsmError::Decode(format!("unknown test HSM alias {address}")))?;
        *self
            .invocations
            .lock()
            .map_err(|_| HsmError::Decode("invocation lock poisoned".to_string()))?
            .entry(address)
            .or_insert(0) += 1;
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa(&Message::from_digest(digest.0), key);
        let compact = signature.serialize_compact();
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&compact);
        out[64] = 27;
        Ok(out)
    }
}

async fn spawn_two_chain_daemon(
    btc: UtxoSignerConfig,
    ltc: UtxoSignerConfig,
    hsm: Arc<MultiChainHsm>,
) -> String {
    let config = DaemonConfig {
        chain_id: ETH_CHAIN_ID,
        verifying_contract: VERIFYING_CONTRACT,
        eth_address: Address::repeat_byte(0xee),
        intent_policy: ric_common::policy(),
        cert_volume: CertVolumePolicy::unmetered(),
    };
    let state = DaemonState::new(config, Arc::new(InMemoryReplayStore::new()), hsm)
        .with_utxo(btc)
        .with_utxo(ltc);
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind loopback");
    let address = listener.local_addr().expect("loopback address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    format!("http://{address}")
}

async fn sign_via_daemon(
    url: String,
    chain: ChainId,
    expected_pubkey: PublicKey,
    psbt: Psbt,
    expected: ExpectedOutputs,
    proof: IntentProof,
) -> Result<(PublicKey, bitcoin::ecdsa::Signature), String> {
    tokio::task::spawn_blocking(move || {
        let cosigner = RemoteMultisigCosigner::new(chain, url, expected_pubkey);
        let certificate = SpendCertificate::Ric(proof);
        cosigner
            .sign_input(&psbt, 0, Some(&expected), Some(&certificate))
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("join remote signer: {error}"))?
}

#[test]
fn btc_and_ltc_psbt_round_trip_uses_chain_params_and_codecs() {
    let fixtures = [
        ChainFixture::new(ChainId::Btc, 0x11, Address::repeat_byte(0xb1)),
        ChainFixture::new(ChainId::Ltc, 0x41, Address::repeat_byte(0xc1)),
    ];
    let mut canonical_addresses = Vec::new();

    for fixture in &fixtures {
        let params = UtxoParams::for_chain(fixture.chain);
        assert_eq!(params.script_kind, ScriptKind::P2wsh);
        assert_eq!(params.op_return_max, 80);
        assert!(matches!(params.thor_asset, "BTC.BTC" | "LTC.LTC"));

        let canonical = fixture.canonical_multisig_address();
        if fixture.chain == ChainId::Btc {
            assert!(canonical.starts_with("bc1q"));
        } else {
            assert!(canonical.starts_with("ltc1q"));
        }
        assert_eq!(
            fixture.decode_multisig_address(&canonical),
            fixture
                .descriptor
                .script_pubkey()
                .expect("descriptor script")
        );
        canonical_addresses.push(canonical);

        let spend = build_chain_spend(fixture, 0x71);
        let mut psbt = spend.psbt.clone();
        for key in fixture.keys.iter().take(2) {
            sign_psbt_input(&mut psbt, 0, key, fixture.descriptor.secp()).expect("partial sign");
        }
        let finalized = finalize_psbt(&mut psbt, &fixture.descriptor).expect("finalize PSBT");
        assert_finalized_spend(&spend, &finalized);
    }

    assert_ne!(canonical_addresses[0], canonical_addresses[1]);
    assert_ne!(
        fixtures[0].descriptor.to_descriptor_string(),
        fixtures[1].descriptor.to_descriptor_string(),
        "BTC and LTC ceremonies must use distinct keys"
    );
}

#[test]
fn doge_p2sh_legacy_psbt_round_trip_uses_chain_params_and_codec() {
    let secp = Secp256k1::new();
    let custody_keys = (0..5u8)
        .map(|offset| {
            SecretKey::from_slice(&[0x61u8.saturating_add(offset); 32]).expect("custody key")
        })
        .collect::<Vec<_>>();
    let custody_pubkeys = custody_keys
        .iter()
        .map(|key| PublicKey::new(key.public_key(&secp)))
        .collect::<Vec<_>>();
    let custody = MultisigDescriptor::new_p2sh_legacy(3, &custody_pubkeys).expect("DOGE 3-of-5");

    let destination_keys = [0x71u8, 0x72]
        .iter()
        .map(|seed| SecretKey::from_slice(&[*seed; 32]).expect("destination key"))
        .collect::<Vec<_>>();
    let destination_pubkeys = destination_keys
        .iter()
        .map(|key| PublicKey::new(key.public_key(&secp)))
        .collect::<Vec<_>>();
    let destination =
        MultisigDescriptor::new_p2sh_legacy(2, &destination_pubkeys).expect("DOGE destination");

    let params = UtxoParams::for_chain(ChainId::Doge);
    assert_eq!(params.script_kind, ScriptKind::P2shLegacy);
    assert_eq!(params.op_return_max, 80);
    assert_eq!(params.thor_asset, "DOGE.DOGE");
    assert_eq!(params.conf_depth, 40);

    let custody_spk = custody.script_pubkey().expect("custody script");
    let destination_spk = destination.script_pubkey().expect("destination script");
    let codec = DogeCodec::mainnet();
    let custody_address = codec.encode(&custody_spk).expect("DOGE custody address");
    let destination_address = codec
        .encode(&destination_spk)
        .expect("DOGE destination address");
    assert_eq!(
        codec.decode(&custody_address).expect("decode custody"),
        custody_spk
    );
    assert_eq!(
        codec
            .decode(&destination_address)
            .expect("decode destination"),
        destination_spk
    );
    assert_ne!(custody_address, destination_address);

    let derived = custody
        .descriptor
        .at_derivation_index(0)
        .expect("derive custody");
    let redeem_script = derived.explicit_script().expect("redeem script");
    let prevout = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xd0; 32])),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(INPUT_SATS),
            script_pubkey: custody_spk.clone(),
        }],
    };
    let utxo = MultisigUtxo {
        outpoint: OutPoint {
            txid: prevout.compute_txid(),
            vout: 0,
        },
        value: Amount::from_sat(INPUT_SATS),
        script_pubkey: custody_spk.clone(),
        spend: MultisigUtxoSpend::NonWitness {
            prevout_tx: prevout,
            redeem_script,
            sighash_flavor: SighashFlavor::LegacyBtc,
        },
    };

    // `bitcoin::Address` supplies only the network-independent P2SH script to
    // the builder; the assertions above prove the same script's canonical DOGE
    // encoding. This avoids pretending Bitcoin's base58 prefix is a DOGE address.
    let recipient = destination
        .address(Network::Bitcoin)
        .expect("script-equivalent recipient");
    let change = custody
        .address(Network::Bitcoin)
        .expect("script-equivalent change");
    let memo = b"=:ETH.USDT:0x0000000000000000000000000000000000000002:0";
    let mut psbt = build_spending_psbt(
        &[utxo],
        &recipient,
        Amount::from_sat(PAYOUT_SATS),
        Some(&change),
        Amount::from_sat(CHANGE_SATS),
        Some(memo),
        params.op_return_max,
    )
    .expect("build DOGE PSBT");
    assert!(psbt.inputs[0].non_witness_utxo.is_some());
    assert!(psbt.inputs[0].redeem_script.is_some());
    assert!(psbt.inputs[0].witness_utxo.is_none());
    assert!(psbt.inputs[0].witness_script.is_none());

    for key in custody_keys.iter().take(3) {
        sign_psbt_input(&mut psbt, 0, key, custody.secp()).expect("DOGE partial signature");
    }
    let finalized = finalize_psbt(&mut psbt, &custody).expect("finalize DOGE PSBT");
    let memo_push = bitcoin::script::PushBytesBuf::try_from(memo.to_vec()).expect("memo push");
    assert_eq!(finalized.output.len(), 3, "payout + memo + change");
    assert_eq!(finalized.output[0].value, Amount::from_sat(PAYOUT_SATS));
    assert_eq!(finalized.output[0].script_pubkey, destination_spk);
    assert_eq!(finalized.output[1].value, Amount::ZERO);
    assert_eq!(
        finalized.output[1].script_pubkey,
        ScriptBuf::new_op_return(memo_push)
    );
    assert_eq!(finalized.output[2].value, Amount::from_sat(CHANGE_SATS));
    assert_eq!(finalized.output[2].script_pubkey, custody_spk);
    assert!(!finalized.input[0].script_sig.is_empty());
    assert!(finalized.input[0].witness.is_empty());
    let output_total = finalized
        .output
        .iter()
        .map(|output| output.value.to_sat())
        .sum::<u64>();
    assert_eq!(INPUT_SATS - output_total, 1_000, "exact implied DOGE fee");
}

fn assert_unimplemented_legacy_chain_fails_closed(
    chain: ChainId,
    flavor: SighashFlavor,
    key_seed: u8,
) {
    let secp = Secp256k1::new();
    let keys = (0..5u8)
        .map(|offset| SecretKey::from_slice(&[key_seed.saturating_add(offset); 32]).expect("key"))
        .collect::<Vec<_>>();
    let pubkeys = keys
        .iter()
        .map(|key| PublicKey::new(key.public_key(&secp)))
        .collect::<Vec<_>>();
    let descriptor = MultisigDescriptor::new_p2sh_legacy(3, &pubkeys).expect("3-of-5 legacy");
    let script_pubkey = descriptor.script_pubkey().expect("legacy script");
    let params = UtxoParams::for_chain(chain);
    assert_eq!(params.script_kind, ScriptKind::P2shLegacy);

    let canonical = if chain == ChainId::Bch {
        assert_eq!(params.op_return_max, 220);
        assert_eq!(params.thor_asset, "BCH.BCH");
        BchCodec::mainnet()
            .encode(&script_pubkey)
            .expect("BCH address")
    } else {
        assert_eq!(chain, ChainId::Zec);
        assert_eq!(params.op_return_max, 80);
        assert_eq!(params.thor_asset, "ZEC.ZEC");
        ZecCodec::mainnet()
            .encode(&script_pubkey)
            .expect("ZEC address")
    };
    let decoded = if chain == ChainId::Bch {
        BchCodec::mainnet().decode(&canonical).expect("BCH decode")
    } else {
        ZecCodec::mainnet().decode(&canonical).expect("ZEC decode")
    };
    assert_eq!(decoded, script_pubkey, "canonical codec round-trip");

    let derived = descriptor
        .descriptor
        .at_derivation_index(0)
        .expect("derive legacy descriptor");
    let redeem_script = derived.explicit_script().expect("redeem script");
    let prevout = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([key_seed; 32])),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(INPUT_SATS),
            script_pubkey: script_pubkey.clone(),
        }],
    };
    let utxo = MultisigUtxo {
        outpoint: OutPoint {
            txid: prevout.compute_txid(),
            vout: 0,
        },
        value: Amount::from_sat(INPUT_SATS),
        script_pubkey,
        spend: MultisigUtxoSpend::NonWitness {
            prevout_tx: prevout,
            redeem_script,
            sighash_flavor: flavor,
        },
    };
    // The Bitcoin-network address contributes only the descriptor's
    // network-independent P2SH script. The canonical chain encoding was
    // independently round-tripped above.
    let recipient = descriptor
        .address(Network::Bitcoin)
        .expect("script-equivalent recipient");
    let memo = b"=:ETH.USDT:0x0000000000000000000000000000000000000003:0";
    let error = build_spending_psbt(
        &[utxo],
        &recipient,
        Amount::from_sat(99_000),
        None,
        Amount::ZERO,
        Some(memo),
        params.op_return_max,
    )
    .expect_err("unimplemented chain sighash must fail closed");
    assert!(matches!(error, SignError::UnsupportedSighash(got) if got == flavor));
}

#[test]
fn bch_qualification_rejects_unimplemented_forkid_sighash() {
    assert_unimplemented_legacy_chain_fails_closed(ChainId::Bch, SighashFlavor::BchForkId, 0x81);
}

#[test]
fn zec_qualification_rejects_unimplemented_sapling_sighash() {
    assert_unimplemented_legacy_chain_fails_closed(ChainId::Zec, SighashFlavor::ZcashBlake2b, 0x91);
}

#[tokio::test]
async fn one_daemon_routes_btc_and_ltc_with_chain_scoped_replay() {
    let btc = ChainFixture::new(ChainId::Btc, 0x11, Address::repeat_byte(0xb1));
    let ltc = ChainFixture::new(ChainId::Ltc, 0x41, Address::repeat_byte(0xc1));
    let hsm = Arc::new(
        MultiChainHsm::default()
            .with_key(btc.hsm_address, btc.keys[0])
            .with_key(ltc.hsm_address, ltc.keys[0]),
    );
    let url =
        spawn_two_chain_daemon(btc.signer_config(), ltc.signer_config(), Arc::clone(&hsm)).await;

    // Deliberately reuse the same outpoint tuple. Both requests must sign:
    // replay/slashing identity includes ChainId, while each role validates a
    // distinct descriptor and dispatches to a distinct HSM alias.
    let btc_spend = build_chain_spend(&btc, 0xa5);
    let ltc_spend = build_chain_spend(&ltc, 0xa5);
    let btc_wrong_role = btc_spend.clone();

    let (btc_pubkey, btc_signature) = sign_via_daemon(
        url.clone(),
        ChainId::Btc,
        btc.my_pubkey(),
        btc_spend.psbt.clone(),
        btc_spend.expected_outputs(),
        btc_spend.proof(ChainId::Btc, 0x91),
    )
    .await
    .expect("BTC daemon sign");
    let (ltc_pubkey, ltc_signature) = sign_via_daemon(
        url.clone(),
        ChainId::Ltc,
        ltc.my_pubkey(),
        ltc_spend.psbt.clone(),
        ltc_spend.expected_outputs(),
        ltc_spend.proof(ChainId::Ltc, 0x91),
    )
    .await
    .expect("LTC daemon sign with same outpoint");

    assert_eq!(btc_pubkey, btc.my_pubkey());
    assert_eq!(ltc_pubkey, ltc.my_pubkey());
    assert_ne!(btc_pubkey, ltc_pubkey);

    let mut btc_psbt = btc_spend.psbt.clone();
    btc_psbt.inputs[0]
        .partial_sigs
        .insert(btc_pubkey, btc_signature);
    sign_psbt_input(&mut btc_psbt, 0, &btc.keys[1], btc.descriptor.secp())
        .expect("BTC second signer");
    let btc_tx = finalize_psbt(&mut btc_psbt, &btc.descriptor).expect("BTC finalize");
    assert_finalized_spend(&btc_spend, &btc_tx);

    let mut ltc_psbt = ltc_spend.psbt.clone();
    ltc_psbt.inputs[0]
        .partial_sigs
        .insert(ltc_pubkey, ltc_signature);
    sign_psbt_input(&mut ltc_psbt, 0, &ltc.keys[1], ltc.descriptor.secp())
        .expect("LTC second signer");
    let ltc_tx = finalize_psbt(&mut ltc_psbt, &ltc.descriptor).expect("LTC finalize");
    assert_finalized_spend(&ltc_spend, &ltc_tx);

    assert_eq!(hsm.invocation_count(btc.hsm_address), 1);
    assert_eq!(hsm.invocation_count(ltc.hsm_address), 1);

    // A BTC-descriptor PSBT labelled LTC must be rejected by the LTC role
    // before an HSM call. Use a fresh RIC id so replay policy cannot mask the
    // descriptor-routing assertion.
    let error = sign_via_daemon(
        url,
        ChainId::Ltc,
        ltc.my_pubkey(),
        btc_wrong_role.psbt.clone(),
        btc_wrong_role.expected_outputs(),
        btc_wrong_role.proof(ChainId::Ltc, 0x92),
    )
    .await
    .expect_err("wrong descriptor must fail");
    assert!(
        error.contains("422"),
        "expected wrong-role 422, got: {error}"
    );
    assert_eq!(
        hsm.invocation_count(ltc.hsm_address),
        1,
        "wrong-role request must not reach the LTC key"
    );
}
