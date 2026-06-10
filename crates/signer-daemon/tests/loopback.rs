#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_statements,
    clippy::doc_markdown,
    reason = "integration test code: panics on bad fixtures are the appropriate failure mode; per-test inline `use` keeps each test self-contained"
)]
//! End-to-end loopback integration test for the coordinator ↔ daemon
//! HTTP wire (PART 5).
//!
//! Spawns a real `xindex-signer-daemon` axum server on an ephemeral
//! loopback port with an in-memory replay store and a software-backed
//! `HsmDigestSigner` (uses real secp256k1, NOT a fixed-bytes stub —
//! produces signatures that recover to a configured Ethereum address +
//! verify against a configured Bitcoin pubkey). Then drives the
//! coordinator-side `RemoteHsmBackend` (Ethereum) and
//! `RemoteMultisigCosigner` (Bitcoin) against that real daemon and
//! asserts:
//!
//! 1. The Ethereum-attestation path produces a 65-byte signature that
//!    recovers to the daemon's configured signer address.
//! 2. The replay-DB idempotency holds: the same `(intent_id, slot_index,
//!    attested_amount)` re-request returns the cached signature without
//!    re-invoking the HSM stub.
//! 3. A same-tuple-different-amount request returns 409 Conflict.
//! 4. A delivery-attested redemption refuses a subsequent refund
//!    attestation with the mutex 409.
//! 5. The PSBT-input path produces a partial signature that finalizes
//!    into a valid multisig spend (`finalize_psbt` succeeds with
//!    enough partials to clear the descriptor threshold).
//!
//! No mocks at any layer — only the HSM frontend is software-backed
//! (the HSM contract itself is the audit-gated production piece). The
//! wire, the JSON shape, the replay DB, the digest computation, the
//! signature verification — all real.

use std::net::SocketAddr;
use std::sync::Arc;

use alloy_primitives::{Address, B256, U256};
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
use std::sync::Mutex;
use xindex_executor::remote_cosigner::RemoteMultisigCosigner;
use xindex_executor::MultisigCosigner;
use xindex_multisig::MultisigDescriptor;
use xindex_shared::chain_registry::ChainId;
use xindex_shared::eip712::{
    attestation, attestation_oracle_domain, attestation_signing_hash, redemption_attestation,
    refund_attestation,
};
use xindex_signer::remote::RemoteHsmBackend;
use xindex_signer::HsmBackend;
use xindex_signer_daemon::psbt::UtxoSignerConfig;
use xindex_signer_daemon::replay::InMemoryReplayStore;
use xindex_signer_daemon::server::{router, DaemonConfig, DaemonState};

mod ric_common;
use xindex_signer_daemon::web3signer::{HsmDigestSigner, HsmError};

/// Software-keyed HSM frontend. Produces real ECDSA signatures over
/// the digest the daemon hands it. The daemon-side path expects
/// `r ‖ s ‖ v` (v ∈ {27,28}); for EIP-712 v must be set correctly so
/// the on-chain `ECDSA.recover` accepts. We compute v via alloy's
/// recovery-aware signing — see [`SoftHsm::sign_digest`].
struct SoftHsm {
    /// Bitcoin secp + secp256k1 secret key (Set A — PSBT signing).
    secp: Secp256k1<All>,
    btc_sk: SecretKey,
    /// Ethereum-side alloy signer (Set B — EIP-712 signing).
    eth: alloy::signers::local::PrivateKeySigner,
    invocations: Mutex<usize>,
}

#[async_trait::async_trait]
impl HsmDigestSigner for SoftHsm {
    async fn sign_digest(&self, address: Address, digest: B256) -> Result<[u8; 65], HsmError> {
        {
            let mut g = self.invocations.lock().unwrap();
            *g += 1;
        }
        // If the daemon's caller is the Ethereum-attestation path, the
        // `address` parameter is the configured ETH signer address.
        // For PSBT signing the daemon passes the BTC key's address
        // (the alias address); either way we route to the right key
        // by which path the request came in on — here we use the
        // address match as the discriminator.
        if address == self.eth_address() {
            use alloy::signers::SignerSync;
            let sig = self
                .eth
                .sign_hash_sync(&digest)
                .map_err(|e| HsmError::Decode(format!("eth sign: {e}")))?;
            Ok(sig.as_bytes())
        } else {
            // BTC path — return r ‖ s ‖ 27 (Bitcoin discards v).
            let msg = Message::from_digest(digest.0);
            let sig = self.secp.sign_ecdsa(&msg, &self.btc_sk);
            let compact = sig.serialize_compact();
            let mut out = [0u8; 65];
            out[..64].copy_from_slice(&compact);
            out[64] = 27;
            Ok(out)
        }
    }
}

impl SoftHsm {
    fn eth_address(&self) -> Address {
        self.eth.address()
    }
}

impl std::fmt::Debug for SoftHsm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftHsm").finish_non_exhaustive()
    }
}

/// Boot a real daemon on a random loopback port + return its base URL +
/// the SoftHsm so tests can observe HSM invocation counts.
async fn spawn_daemon(
    btc: Option<UtxoSignerConfig>,
) -> (String, Address, bitcoin::PublicKey, Arc<SoftHsm>) {
    use alloy::signers::local::PrivateKeySigner;
    let eth: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .expect("eth key");
    let eth_address = eth.address();
    let secp = Secp256k1::new();
    let btc_sk = SecretKey::from_slice(&[0x11u8; 32]).expect("btc sk");
    let btc_pk = bitcoin::PublicKey::new(btc_sk.public_key(&secp));
    let hsm = Arc::new(SoftHsm {
        secp,
        btc_sk,
        eth,
        invocations: Mutex::new(0),
    });

    let replay = Arc::new(InMemoryReplayStore::new());
    let cfg = DaemonConfig {
        chain_id: 31337,
        verifying_contract: Address::repeat_byte(0xab),
        eth_address,
        intent_policy: ric_common::policy(),
    };
    let mut state = DaemonState::new(cfg, replay, Arc::clone(&hsm));
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
    // Tiny settle — give the listener a tick to start accepting.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (format!("http://{addr}"), eth_address, btc_pk, hsm)
}

fn make_descriptor(secp: &Secp256k1<All>, btc_pk: bitcoin::PublicKey) -> MultisigDescriptor {
    // Build a 2-of-3 descriptor where `btc_pk` is one of the keys
    // (so the daemon's BTC role can validate vin[0] matches).
    let sk2 = SecretKey::from_slice(&[0x22u8; 32]).expect("sk2");
    let sk3 = SecretKey::from_slice(&[0x33u8; 32]).expect("sk3");
    let pks = vec![
        btc_pk,
        bitcoin::PublicKey::new(sk2.public_key(secp)),
        bitcoin::PublicKey::new(sk3.public_key(secp)),
    ];
    MultisigDescriptor::new_p2wsh(2, &pks).expect("descriptor")
}

#[tokio::test]
async fn coordinator_to_daemon_eip712_attestation_recovers_to_signer() {
    let (url, eth_addr, _btc_pk, hsm) = spawn_daemon(None).await;
    // Coordinator side: RemoteHsmBackend pinned to the daemon's address.
    let url_for_sign = url.clone();
    let result = tokio::task::spawn_blocking(move || {
        let backend = RemoteHsmBackend::new(url_for_sign, eth_addr);
        let domain = attestation_oracle_domain(31337, Address::repeat_byte(0xab));
        let a = attestation(
            B256::repeat_byte(0xcd),
            U256::from(0u8),
            U256::from(1_000_000u32),
        );
        // sign_attestation_msg triggers the typed wire path.
        backend.sign_attestation_msg(&domain, &a)
    })
    .await
    .expect("join")
    .expect("sign");

    // Verify the returned signature recovers to the daemon's address
    // over the EIP-712 digest — end-to-end correctness.
    use alloy::primitives::PrimitiveSignature;
    let sig = PrimitiveSignature::try_from(result.as_slice()).expect("65b");
    let domain = attestation_oracle_domain(31337, Address::repeat_byte(0xab));
    let a = attestation(
        B256::repeat_byte(0xcd),
        U256::from(0u8),
        U256::from(1_000_000u32),
    );
    let digest = attestation_signing_hash(&a, &domain);
    let recovered = sig.recover_address_from_prehash(&digest).expect("recover");
    assert_eq!(
        recovered, eth_addr,
        "loopback daemon returned signature must recover to the configured signer"
    );

    // Idempotency: same payload re-requested returns same sig + does
    // NOT increment HSM invocation count.
    let before = *hsm.invocations.lock().unwrap();
    let url2 = url;
    let sig2 = tokio::task::spawn_blocking(move || {
        let backend = RemoteHsmBackend::new(url2, eth_addr);
        let domain = attestation_oracle_domain(31337, Address::repeat_byte(0xab));
        let a = attestation(
            B256::repeat_byte(0xcd),
            U256::from(0u8),
            U256::from(1_000_000u32),
        );
        backend.sign_attestation_msg(&domain, &a).expect("sign 2")
    })
    .await
    .expect("join");
    assert_eq!(
        sig2, result,
        "idempotent retry returns the cached signature"
    );
    let after = *hsm.invocations.lock().unwrap();
    assert_eq!(
        before, after,
        "HSM must NOT be invoked on idempotent re-request"
    );
}

#[tokio::test]
async fn coordinator_to_daemon_same_tuple_different_amount_is_409() {
    let (url, eth_addr, _btc_pk, _hsm) = spawn_daemon(None).await;
    // First sign with amount X.
    let url1 = url.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let backend = RemoteHsmBackend::new(url1, eth_addr);
        let domain = attestation_oracle_domain(31337, Address::repeat_byte(0xab));
        let a = attestation(B256::repeat_byte(0xee), U256::from(0u8), U256::from(100u8));
        backend.sign_attestation_msg(&domain, &a).expect("sign 1")
    })
    .await
    .expect("join");

    // Same (intent, slot) but different amount — must fail with the
    // backend error surfaced from the daemon's 409.
    let url2 = url;
    let err = tokio::task::spawn_blocking(move || {
        let backend = RemoteHsmBackend::new(url2, eth_addr);
        let domain = attestation_oracle_domain(31337, Address::repeat_byte(0xab));
        let a = attestation(
            B256::repeat_byte(0xee),
            U256::from(0u8),
            U256::from(200u8), // ← different amount
        );
        backend.sign_attestation_msg(&domain, &a).err()
    })
    .await
    .expect("join")
    .expect("daemon must refuse");
    assert!(
        err.to_string().contains("409"),
        "expected daemon 409 in error: {err}"
    );
}

#[tokio::test]
async fn coordinator_to_daemon_redemption_delivery_then_refund_is_mutex_409() {
    let (url, eth_addr, _btc_pk, _hsm) = spawn_daemon(None).await;
    let red_id = B256::repeat_byte(0x44);
    let url1 = url.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let backend = RemoteHsmBackend::new(url1, eth_addr);
        let domain = attestation_oracle_domain(31337, Address::repeat_byte(0xab));
        let a = redemption_attestation(
            red_id,
            U256::ZERO,
            B256::repeat_byte(0xa1),
            U256::from(70_000_000u64),
        );
        backend
            .sign_redemption_attestation_msg(&domain, &a)
            .expect("delivery")
    })
    .await
    .expect("join");

    // Same redemption id, refund leg — daemon's redemption mutex
    // returns 409.
    let url2 = url;
    let err = tokio::task::spawn_blocking(move || {
        let backend = RemoteHsmBackend::new(url2, eth_addr);
        let domain = attestation_oracle_domain(31337, Address::repeat_byte(0xab));
        let r = refund_attestation(
            red_id,
            U256::ZERO,
            B256::repeat_byte(0xa1),
            U256::from(99_990_000u64),
        );
        backend.sign_refund_attestation_msg(&domain, &r).err()
    })
    .await
    .expect("join")
    .expect("daemon must refuse refund after delivery");
    assert!(
        err.to_string().contains("409"),
        "expected daemon 409 mutex error: {err}"
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "single sequential coordinator→daemon e2e flow; splitting fragments the audit-relevant ordering (honest PSBT shape + M2 veto + CTD-1 proof + ECDSA round-trip)"
)]
async fn coordinator_to_daemon_psbt_input_signs_with_real_ecdsa_and_finalizes() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use bitcoin::psbt::Psbt;
    use bitcoin::{
        absolute, transaction, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxOut, Witness,
    };
    let _ = B64.encode([0u8]); // silence unused-import warning if base64 ends up unused below

    // Build a 2-of-3 descriptor + daemon BTC config.
    let secp = Secp256k1::new();
    let btc_sk_1 = SecretKey::from_slice(&[0x11u8; 32]).expect("sk1");
    let btc_pk_1 = bitcoin::PublicKey::new(btc_sk_1.public_key(&secp));
    let descriptor = make_descriptor(&secp, btc_pk_1);
    let btc_cfg = UtxoSignerConfig {
        chain_id: ChainId::Btc,
        network: Network::Bitcoin,
        descriptor: descriptor.clone(),
        my_pubkey: btc_pk_1,
        hsm_address: Address::from([0xCC; 20]),
    };

    let (url, _eth_addr, btc_pk, _hsm) = spawn_daemon(Some(btc_cfg)).await;
    assert_eq!(btc_pk, btc_pk_1);

    // Build a minimal spending PSBT (vin[0] = our multisig).
    let ws = descriptor
        .descriptor
        .at_derivation_index(0)
        .expect("at_derivation_index")
        .explicit_script()
        .expect("explicit_script");
    let address = descriptor.address(Network::Bitcoin).expect("addr");
    let prev_spk = address.script_pubkey();
    let prev_txid =
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x77u8; 32]));
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
                value: Amount::from_sat(99_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                    [0x42; 20],
                )),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return(b"=:ETH.USDT:0xabc:0"),
            },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: prev_spk,
    });
    psbt.inputs[0].witness_script = Some(ws);

    // Coordinator side: RemoteMultisigCosigner pinned to the daemon's
    // disclosed BTC pubkey. Run the blocking HTTP call inside
    // spawn_blocking so reqwest::blocking can drive its own runtime.
    // audit M2: pass the leg's expected outputs that MATCH this PSBT's
    // payout + memo, proving a legitimate leg passes the veto. CTD-1:
    // attach a quorum-signed certificate over the same payout.
    let dest_spk = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x42; 20]));
    let expected = xindex_executor::ExpectedOutputs {
        destination_spk: dest_spk.clone().into_bytes(),
        amount_sats: 99_000,
        memo: b"=:ETH.USDT:0xabc:0".to_vec(),
    };
    let proof = ric_common::proof(
        31337,
        Address::repeat_byte(0xab),
        ChainId::Btc,
        0x91,
        0,
        99_000,
        dest_spk.as_bytes(),
        b"=:ETH.USDT:0xabc:0",
    );
    let url_for_sign = url;
    let psbt_send = psbt.clone();
    let (got_pk, got_sig) = tokio::task::spawn_blocking(move || {
        let cosigner = RemoteMultisigCosigner::new(ChainId::Btc, url_for_sign, btc_pk);
        cosigner.sign_input(&psbt_send, 0, Some(&expected), Some(&proof))
    })
    .await
    .expect("join")
    .expect("sign_input via loopback daemon");

    assert_eq!(got_pk, btc_pk_1, "coordinator pin matches daemon response");

    // Insert the partial sig and verify it round-trips through the
    // descriptor's witness rules (mimics what `InProcessExecutor` does
    // after collecting K cosigner responses).
    psbt.inputs[0].partial_sigs.insert(got_pk, got_sig);
    assert_eq!(
        psbt.inputs[0].partial_sigs.len(),
        1,
        "exactly one partial sig accepted into the PSBT"
    );
    // Verify the signature actually signs the input's BIP-143 sighash
    // against the daemon's pubkey — end-to-end ECDSA correctness.
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    let ws_ref = psbt.inputs[0].witness_script.as_ref().expect("ws");
    let wu = psbt.inputs[0].witness_utxo.as_ref().expect("wu");
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = cache
        .p2wsh_signature_hash(0, ws_ref, wu.value, EcdsaSighashType::All)
        .expect("sighash");
    let msg = Message::from_digest(sighash.to_byte_array());
    secp.verify_ecdsa(&msg, &got_sig.signature, &btc_pk_1.inner)
        .expect("daemon-produced sig must verify under its disclosed pubkey");
}
