#![expect(
    clippy::expect_used,
    clippy::items_after_statements,
    clippy::doc_markdown,
    reason = "integration test code: panics on bad fixtures are the appropriate failure mode"
)]
//! CTD-1 Slice D — ADVERSARIAL 3-daemon end-to-end (`DL-CTD-2` /
//! `DL-CTD-E`).
//!
//! Spawns THREE real signer daemons (axum on ephemeral loopback ports,
//! in-memory replay stores, software-keyed HSM frontends) whose Set-B
//! keys are the deterministic `ric_common` trio — i.e. the 2-of-3
//! whitelist every daemon's `intent_policy` pins. Daemon #1 is
//! multi-role: it also carries the BTC custody (Set-A) role behind a
//! real 2-of-3 P2WSH descriptor. Redemption Intent Certificates are
//! collected over the REAL wire (`POST /api/v1/sign/eip712-ric` via
//! `RemoteHsmBackend`), assembled into `IntentProof`s, and presented to
//! the REAL custody endpoint (`POST /api/v1/sign/psbt-input` via
//! `RemoteMultisigCosigner`) — no mocks at any layer.
//!
//! Adversarial scenarios (the malicious-coordinator model — the
//! coordinator controls every request field EXCEPT the k-of-n
//! certificates):
//!  1. Quorum baseline + DEGRADATION: certificates from operators 2+3
//!     alone (operator 1 refusing — e.g. its diverse THORChain sources
//!     disagree) still authorize the spend: k-of-n, not n-of-n.
//!  2. FORGED DESTINATION: a PSBT paying an attacker scriptPubKey under
//!     an honest certificate → 422 `psbt_unexpected_output` (the
//!     exact-set output binding: the attacker output is neither the
//!     certified payout, the memo, nor change-to-self).
//!  3. RE-DRIVE with a DIFFERENT certificate at the same
//!     `(redemptionId, legIndex)` → 409 `intent_already_signed` (the
//!     RA-1 killer), and the Set-B daemons themselves refuse to
//!     EQUIVOCATE (409) when asked to certify the second certificate.
//!  4. AMOUNT-UNIT SLIP: a PSBT paying 1/100th of the certified amount
//!     → 422 `intent_mismatch`.
//!  5. STALE CERTIFICATE (Asgard-rotation guard): a proof older than
//!     `ric_max_age` → 422; a FRESH re-certification of the SAME leg to
//!     the ROTATED vault then succeeds — the rotation never
//!     false-rejects and the stale refusal never consumed the one-shot.
//!  6. SLICE E VOLUME WINDOW over the wire: a Set-B daemon with a
//!     per-chain cap refuses the certification that would exceed it
//!     (422 `volume_cap_exceeded`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{keccak256, Address, B256, U256};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
use bitcoin::{
    absolute, transaction, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Witness,
};
use xindex_executor::remote_cosigner::RemoteMultisigCosigner;
use xindex_executor::{ExpectedOutputs, MultisigCosigner, SpendCertificate};
use xindex_multisig::MultisigDescriptor;
use xindex_shared::chain_registry::ChainId;
use xindex_shared::eip712::redemption_intent_certificate;
use xindex_shared::signer_wire::IntentProof;
use xindex_signer::remote::RemoteHsmBackend;
use xindex_signer_daemon::psbt::UtxoSignerConfig;
use xindex_signer_daemon::replay::InMemoryReplayStore;
use xindex_signer_daemon::server::{router, CertVolumePolicy, DaemonConfig, DaemonState};
use xindex_signer_daemon::web3signer::{HsmDigestSigner, HsmError};

mod ric_common;

const ETH_CHAIN_ID: u64 = 31337;
const MEMO: &[u8] = b"=:ETH.USDT:0xabc:0";

fn verifying_contract() -> Address {
    Address::repeat_byte(0xab)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Software-keyed HSM frontend: the Set-B key is the `ric_common`
/// deterministic trio member for `seed`; the BTC key signs custody
/// sighashes (routed by address mismatch, same as the loopback suite).
struct SoftHsm {
    secp: Secp256k1<All>,
    btc_sk: SecretKey,
    eth: PrivateKeySigner,
}

#[async_trait::async_trait]
impl HsmDigestSigner for SoftHsm {
    async fn sign_digest(&self, address: Address, digest: B256) -> Result<[u8; 65], HsmError> {
        if address == self.eth.address() {
            use alloy::signers::SignerSync;
            let sig = self
                .eth
                .sign_hash_sync(&digest)
                .map_err(|e| HsmError::Decode(format!("eth sign: {e}")))?;
            Ok(sig.as_bytes())
        } else {
            let msg = Message::from_digest(digest.0);
            let sig = self.secp.sign_ecdsa(&msg, &self.btc_sk);
            let mut out = [0u8; 65];
            out[..64].copy_from_slice(&sig.serialize_compact());
            out[64] = 27;
            Ok(out)
        }
    }
}

impl std::fmt::Debug for SoftHsm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftHsm").finish_non_exhaustive()
    }
}

/// Boot one real daemon whose Set-B key is trio member `seed`
/// (41/42/43). `btc` adds the custody role; `caps` is the Slice E
/// per-chain certification volume policy.
async fn spawn_daemon(
    seed: u8,
    btc: Option<UtxoSignerConfig>,
    caps: HashMap<ChainId, u128>,
) -> (String, Address) {
    let eth = PrivateKeySigner::from_slice(&[seed; 32]).expect("set-b key");
    let eth_address = eth.address();
    let secp = Secp256k1::new();
    let btc_sk = SecretKey::from_slice(&[0x11u8; 32]).expect("btc sk");
    let hsm = Arc::new(SoftHsm { secp, btc_sk, eth });

    let mut cert_volume = CertVolumePolicy::unmetered();
    cert_volume.caps = caps;
    let cfg = DaemonConfig {
        chain_id: ETH_CHAIN_ID,
        verifying_contract: verifying_contract(),
        eth_address,
        intent_policy: ric_common::policy(),
        cert_volume,
    };
    let mut state = DaemonState::new(cfg, Arc::new(InMemoryReplayStore::new()), hsm);
    if let Some(btc_cfg) = btc {
        state = state.with_utxo(btc_cfg);
    }
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (format!("http://{addr}"), eth_address)
}

/// The custody daemon's BTC fixtures: a 2-of-3 P2WSH descriptor whose
/// first key the daemon holds.
fn btc_fixtures(secp: &Secp256k1<All>) -> (bitcoin::PublicKey, MultisigDescriptor) {
    let btc_sk_1 = SecretKey::from_slice(&[0x11u8; 32]).expect("sk1");
    let btc_pk_1 = bitcoin::PublicKey::new(btc_sk_1.public_key(secp));
    let sk2 = SecretKey::from_slice(&[0x22u8; 32]).expect("sk2");
    let sk3 = SecretKey::from_slice(&[0x33u8; 32]).expect("sk3");
    let pks = vec![
        btc_pk_1,
        bitcoin::PublicKey::new(sk2.public_key(secp)),
        bitcoin::PublicKey::new(sk3.public_key(secp)),
    ];
    let descriptor = MultisigDescriptor::new_p2wsh(2, &pks).expect("descriptor");
    (btc_pk_1, descriptor)
}

fn utxo_cfg(btc_pk: bitcoin::PublicKey, descriptor: MultisigDescriptor) -> UtxoSignerConfig {
    UtxoSignerConfig {
        chain_id: ChainId::Btc,
        network: Network::Bitcoin,
        descriptor,
        my_pubkey: btc_pk,
        hsm_address: Address::from([0xCC; 20]),
    }
}

/// A spending PSBT: vin\[0\] = our multisig at `prev_byte`-derived
/// outpoint; vout\[0\] = `amount` to `dest_spk`; vout\[1\] = the
/// exact-set OP_RETURN memo (RA-3).
fn build_spend_psbt(
    descriptor: &MultisigDescriptor,
    dest_spk: &ScriptBuf,
    amount_sats: u64,
    prev_byte: u8,
) -> bitcoin::psbt::Psbt {
    let ws = descriptor
        .descriptor
        .at_derivation_index(0)
        .expect("derive")
        .explicit_script()
        .expect("script");
    let address = descriptor.address(Network::Bitcoin).expect("addr");
    let prev_spk = address.script_pubkey();
    let prev_txid =
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([prev_byte; 32]));
    let memo_push = bitcoin::script::PushBytesBuf::try_from(MEMO.to_vec()).expect("push");
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(amount_sats),
                script_pubkey: dest_spk.clone(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return(memo_push),
            },
        ],
    };
    let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx).expect("psbt");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(amount_sats + 1_000),
        script_pubkey: prev_spk,
    });
    psbt.inputs[0].witness_script = Some(ws);
    psbt
}

/// Collect REAL Set-B certificates over the wire from `daemons` and
/// assemble the `IntentProof` — what the per-operator observers + relay
/// produce in production.
async fn wire_proof(
    daemons: &[(String, Address)],
    rid: u8,
    leg_index: u32,
    amount: u64,
    target_spk: &ScriptBuf,
) -> IntentProof {
    let stamp = now_unix();
    let immediate_target_hash = keccak256(target_spk.as_bytes());
    let memo_hash = keccak256(MEMO);
    let final_destination_hash = B256::repeat_byte(0x12);
    let ric = redemption_intent_certificate(
        B256::repeat_byte(rid),
        U256::from(leg_index),
        ChainId::Btc.asset_id_hash(),
        U256::from(amount),
        ChainId::Btc.decimals(),
        immediate_target_hash,
        memo_hash,
        final_destination_hash,
        stamp,
    );
    let mut signatures = Vec::new();
    for (url, addr) in daemons {
        let url = url.clone();
        let addr = *addr;
        let ric = ric.clone();
        let sig = tokio::task::spawn_blocking(move || {
            RemoteHsmBackend::new(url, addr).sign_ric(ChainId::Btc, &ric)
        })
        .await
        .expect("join")
        .expect("wire RIC certification");
        signatures.push(format!("0x{}", alloy_primitives::hex::encode(sig)));
    }
    IntentProof {
        redemption_id: format!("{:#x}", B256::repeat_byte(rid)),
        leg_index: leg_index.to_string(),
        asset_id: format!("{:#x}", ChainId::Btc.asset_id_hash()),
        amount: amount.to_string(),
        amount_decimals: ChainId::Btc.decimals(),
        immediate_target_hash: format!("{immediate_target_hash:#x}"),
        memo_hash: format!("{memo_hash:#x}"),
        final_destination_hash: format!("{final_destination_hash:#x}"),
        vault_resolved_at: stamp,
        signatures,
    }
}

/// Drive the custody daemon's PSBT endpoint as the coordinator would.
async fn custody_sign(
    custody_url: &str,
    btc_pk: bitcoin::PublicKey,
    psbt: &bitcoin::psbt::Psbt,
    expected: ExpectedOutputs,
    proof: IntentProof,
) -> Result<(bitcoin::PublicKey, bitcoin::ecdsa::Signature), String> {
    let url = custody_url.to_string();
    let psbt = psbt.clone();
    tokio::task::spawn_blocking(move || {
        let cosigner = RemoteMultisigCosigner::new(ChainId::Btc, url, btc_pk);
        let certificate = SpendCertificate::Ric(proof);
        cosigner
            .sign_input(&psbt, 0, Some(&expected), Some(&certificate))
            .map_err(|e| e.to_string())
    })
    .await
    .expect("join")
}

fn honest_dest_spk() -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x42; 20]))
}

fn expected_for(spk: &ScriptBuf, amount_sats: u64) -> ExpectedOutputs {
    ExpectedOutputs {
        destination_spk: spk.clone().into_bytes(),
        amount_sats,
        memo: MEMO.to_vec(),
    }
}

/// Scenario 1 — quorum baseline + degradation: certificates collected
/// from operators 2+3 ONLY (operator 1 refusing — e.g. its diverse
/// THORChain sources disagree, the unit-tested observer no-sign path)
/// still authorize operator 1's custody spend. k-of-n, not n-of-n, and
/// the partial signature verifies under the daemon's disclosed pubkey.
#[tokio::test]
async fn quorum_survives_one_refusing_operator_end_to_end() {
    let secp = Secp256k1::new();
    let (btc_pk, descriptor) = btc_fixtures(&secp);
    let (custody_url, _a1) = spawn_daemon(
        41,
        Some(utxo_cfg(btc_pk, descriptor.clone())),
        HashMap::new(),
    )
    .await;
    let d2 = spawn_daemon(42, None, HashMap::new()).await;
    let d3 = spawn_daemon(43, None, HashMap::new()).await;

    let dest = honest_dest_spk();
    let proof = wire_proof(&[d2, d3], 0xd1, 0, 99_000, &dest).await;
    let psbt = build_spend_psbt(&descriptor, &dest, 99_000, 0x71);

    let (got_pk, got_sig) = custody_sign(
        &custody_url,
        btc_pk,
        &psbt,
        expected_for(&dest, 99_000),
        proof,
    )
    .await
    .expect("2-of-3 certificates from the OTHER operators must authorize");
    assert_eq!(got_pk, btc_pk);

    // The signature actually signs this input's BIP-143 sighash.
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    let ws = psbt.inputs[0].witness_script.as_ref().expect("ws");
    let wu = psbt.inputs[0].witness_utxo.as_ref().expect("wu");
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = cache
        .p2wsh_signature_hash(0, ws, wu.value, EcdsaSighashType::All)
        .expect("sighash");
    secp.verify_ecdsa(
        &Message::from_digest(sighash.to_byte_array()),
        &got_sig.signature,
        &got_pk.inner,
    )
    .expect("partial sig must verify under the daemon's disclosed pubkey");
}

/// Scenario 2 — forged destination: the coordinator controls the PSBT
/// and the M2 `expected` pin, but NOT the k-of-n certificate. A PSBT
/// paying an attacker scriptPubKey under an honest certificate is
/// refused 422 before the HSM is touched.
#[tokio::test]
async fn forged_destination_is_refused_422() {
    let secp = Secp256k1::new();
    let (btc_pk, descriptor) = btc_fixtures(&secp);
    let (custody_url, _) = spawn_daemon(
        41,
        Some(utxo_cfg(btc_pk, descriptor.clone())),
        HashMap::new(),
    )
    .await;
    let d2 = spawn_daemon(42, None, HashMap::new()).await;
    let d3 = spawn_daemon(43, None, HashMap::new()).await;

    let honest = honest_dest_spk();
    let attacker = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x66; 20]));
    let proof = wire_proof(&[d2, d3], 0xd2, 0, 99_000, &honest).await;
    // The malicious coordinator redirects the payout AND pins `expected`
    // to its own forged outputs (it controls both request fields).
    let psbt = build_spend_psbt(&descriptor, &attacker, 99_000, 0x72);

    let err = custody_sign(
        &custody_url,
        btc_pk,
        &psbt,
        expected_for(&attacker, 99_000),
        proof,
    )
    .await
    .expect_err("forged destination must be refused");
    assert!(err.contains("422"), "expected 422 in: {err}");
    assert!(
        err.contains("psbt_unexpected_output"),
        "expected psbt_unexpected_output in: {err}"
    );
}

/// Scenario 3 — RA-1 re-drive: a SECOND, DIFFERENT certificate at the
/// same `(redemptionId, legIndex)` is refused 409 by the custody
/// one-shot — and the Set-B daemons themselves refuse to equivocate
/// when asked to certify it.
#[tokio::test]
async fn redrive_with_different_certificate_is_409() {
    let secp = Secp256k1::new();
    let (btc_pk, descriptor) = btc_fixtures(&secp);
    let (custody_url, _) = spawn_daemon(
        41,
        Some(utxo_cfg(btc_pk, descriptor.clone())),
        HashMap::new(),
    )
    .await;
    let d2 = spawn_daemon(42, None, HashMap::new()).await;
    let d3 = spawn_daemon(43, None, HashMap::new()).await;

    let dest = honest_dest_spk();
    let proof_a = wire_proof(&[d2.clone(), d3], 0xd3, 0, 99_000, &dest).await;
    let psbt_a = build_spend_psbt(&descriptor, &dest, 99_000, 0x73);
    custody_sign(
        &custody_url,
        btc_pk,
        &psbt_a,
        expected_for(&dest, 99_000),
        proof_a,
    )
    .await
    .expect("honest first spend authorizes");

    // The Set-B daemon refuses to EQUIVOCATE on a different certificate
    // for the same (chain, redemption, leg)…
    let stamp = now_unix();
    let ric_b = redemption_intent_certificate(
        B256::repeat_byte(0xd3),
        U256::ZERO,
        ChainId::Btc.asset_id_hash(),
        U256::from(50_000u64),
        ChainId::Btc.decimals(),
        keccak256(dest.as_bytes()),
        keccak256(MEMO),
        B256::repeat_byte(0x12),
        stamp,
    );
    let (d2_url, d2_addr) = d2;
    let equivocation = tokio::task::spawn_blocking(move || {
        RemoteHsmBackend::new(d2_url, d2_addr).sign_ric(ChainId::Btc, &ric_b)
    })
    .await
    .expect("join")
    .expect_err("Set-B must refuse to equivocate");
    assert!(
        equivocation.to_string().contains("409"),
        "expected 409 in: {equivocation}"
    );

    // …and even a locally-forged quorum (compromised k-of-n would be
    // needed) cannot re-drive the leg past the custody one-shot.
    let proof_b = ric_common::proof(
        ETH_CHAIN_ID,
        verifying_contract(),
        ChainId::Btc,
        0xd3,
        0,
        50_000,
        dest.as_bytes(),
        MEMO,
    );
    let psbt_b = build_spend_psbt(&descriptor, &dest, 50_000, 0x74);
    let err = custody_sign(
        &custody_url,
        btc_pk,
        &psbt_b,
        expected_for(&dest, 50_000),
        proof_b,
    )
    .await
    .expect_err("re-drive must be refused");
    assert!(err.contains("409"), "expected 409 in: {err}");
    assert!(
        err.contains("intent_already_signed"),
        "expected intent_already_signed in: {err}"
    );
}

/// Scenario 4 — amount-unit slip: a PSBT paying 1/100th of the
/// certified amount (a decimals confusion) never matches the certified
/// payout — 422.
#[tokio::test]
async fn amount_unit_slip_is_refused_422() {
    let secp = Secp256k1::new();
    let (btc_pk, descriptor) = btc_fixtures(&secp);
    let (custody_url, _) = spawn_daemon(
        41,
        Some(utxo_cfg(btc_pk, descriptor.clone())),
        HashMap::new(),
    )
    .await;

    let dest = honest_dest_spk();
    let proof = ric_common::proof(
        ETH_CHAIN_ID,
        verifying_contract(),
        ChainId::Btc,
        0xd4,
        0,
        99_000,
        dest.as_bytes(),
        MEMO,
    );
    let psbt = build_spend_psbt(&descriptor, &dest, 990, 0x75);
    let err = custody_sign(&custody_url, btc_pk, &psbt, expected_for(&dest, 990), proof)
        .await
        .expect_err("unit-slipped amount must be refused");
    assert!(err.contains("422"), "expected 422 in: {err}");
    assert!(
        err.contains("intent_mismatch"),
        "expected intent_mismatch in: {err}"
    );
}

/// Scenario 5 — stale certificate + Asgard rotation: a proof older than
/// the policy's `ric_max_age` is refused (a rotated-away vault must not
/// be payable), and a FRESH re-certification of the SAME leg to the NEW
/// vault then succeeds — rotation never false-rejects, and the stale
/// refusal never consumed the leg's one-shot.
#[tokio::test]
async fn stale_certificate_refused_then_rotation_recertifies() {
    let secp = Secp256k1::new();
    let (btc_pk, descriptor) = btc_fixtures(&secp);
    let (custody_url, _) = spawn_daemon(
        41,
        Some(utxo_cfg(btc_pk, descriptor.clone())),
        HashMap::new(),
    )
    .await;

    let old_vault = honest_dest_spk();
    let now = now_unix();
    // ric_common::policy().ric_max_age_secs == 3600 — stamp well past it.
    let stale = ric_common::proof_at(
        ETH_CHAIN_ID,
        verifying_contract(),
        ChainId::Btc,
        0xd5,
        0,
        99_000,
        old_vault.as_bytes(),
        MEMO,
        now - 4_000,
    );
    let psbt_old = build_spend_psbt(&descriptor, &old_vault, 99_000, 0x76);
    let err = custody_sign(
        &custody_url,
        btc_pk,
        &psbt_old,
        expected_for(&old_vault, 99_000),
        stale,
    )
    .await
    .expect_err("stale certificate must be refused");
    assert!(err.contains("422"), "expected 422 in: {err}");
    assert!(
        err.contains("intent_vault_stale"),
        "expected intent_vault_stale in: {err}"
    );

    // Asgard rotated; the observers re-resolve and re-certify the SAME
    // leg to the NEW vault with a fresh stamp.
    let new_vault = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x55; 20]));
    let fresh = ric_common::proof_at(
        ETH_CHAIN_ID,
        verifying_contract(),
        ChainId::Btc,
        0xd5,
        0,
        99_000,
        new_vault.as_bytes(),
        MEMO,
        now_unix(),
    );
    let psbt_new = build_spend_psbt(&descriptor, &new_vault, 99_000, 0x77);
    custody_sign(
        &custody_url,
        btc_pk,
        &psbt_new,
        expected_for(&new_vault, 99_000),
        fresh,
    )
    .await
    .expect("rotation re-certification must not be false-rejected");
}

/// Scenario 6 — Slice E (`DL-CTD-E`) volume window over the wire: a
/// Set-B daemon capped at 150k sats certifies the first 99k-sat leg and
/// refuses the second with 422 `volume_cap_exceeded`.
#[tokio::test]
async fn set_b_volume_cap_enforced_over_the_wire() {
    let mut caps = HashMap::new();
    caps.insert(ChainId::Btc, 150_000u128);
    let (url, addr) = spawn_daemon(42, None, caps).await;

    let dest = honest_dest_spk();
    let first = wire_proof(&[(url.clone(), addr)], 0xd6, 0, 99_000, &dest).await;
    assert_eq!(first.signatures.len(), 1, "first certification flows");

    let stamp = now_unix();
    let ric = redemption_intent_certificate(
        B256::repeat_byte(0xd7),
        U256::ZERO,
        ChainId::Btc.asset_id_hash(),
        U256::from(99_000u64),
        ChainId::Btc.decimals(),
        keccak256(dest.as_bytes()),
        keccak256(MEMO),
        B256::repeat_byte(0x12),
        stamp,
    );
    let err = tokio::task::spawn_blocking(move || {
        RemoteHsmBackend::new(url, addr).sign_ric(ChainId::Btc, &ric)
    })
    .await
    .expect("join")
    .expect_err("second certification must exceed the window cap");
    let msg = err.to_string();
    assert!(msg.contains("422"), "expected 422 in: {msg}");
    assert!(
        msg.contains("volume_cap_exceeded"),
        "expected volume_cap_exceeded in: {msg}"
    );
}
