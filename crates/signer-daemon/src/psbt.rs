//! PSBT-input signing endpoint (PART 5 / DL-M5-3).
//!
//! Decodes a base64 PSBT, locates the requested input, validates the
//! input's witness script matches the daemon's configured multisig
//! descriptor (refuses signing for any other script — `wrong_descriptor`),
//! validates `vin[0]` is itself a multisig UTXO (the Part-3
//! refund-address invariant — `vin0_not_multisig`), computes the
//! BIP-143 P2WSH sighash, consults the replay/slashing DB on the
//! `(input_txid, input_vout)` tuple, asks the HSM frontend to sign
//! the 32-byte sighash raw, and returns a Bitcoin-encoded partial
//! signature (DER + `SIGHASH_ALL` byte) + the signer pubkey.
//!
//! The replay-DB `payload_hash` is `keccak256(input_txid ‖
//! input_vout_le_u32 ‖ sighash)` so distinct *consuming* transactions
//! (different sighashes) sharing the same outpoint correctly register
//! as different payloads and the second is a 409 `Conflict`.

use std::sync::Arc;

use alloy_primitives::Address;
use axum::{extract::State, http::StatusCode, response::Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bitcoin::hashes::Hash;
use bitcoin::{
    ecdsa::Signature as BtcEcdsaSig,
    psbt::Psbt,
    secp256k1::{self, Message},
    sighash::{EcdsaSighashType, SighashCache},
    Network,
};
use xindex_multisig::MultisigDescriptor;
use xindex_shared::signer_wire::{error_codes, ErrorBody, PsbtInputSignRequest, PsbtSignResponse};

use crate::replay::{CheckOutcome, ReplayStore};
use crate::server::DaemonState;
use crate::web3signer::HsmDigestSigner;

/// Bitcoin-role configuration. The daemon refuses any PSBT input whose
/// witness script doesn't match `descriptor`'s derived `witness_script`,
/// and refuses any PSBT whose `vin[0]` is not itself spending a
/// multisig UTXO under the same descriptor (Part-3 refund invariant).
#[derive(Debug)]
pub struct BtcSignerConfig {
    /// Network the multisig lives on (mainnet / signet / testnet /
    /// regtest). Used only for the configured address — the descriptor
    /// already determines the script.
    pub network: Network,
    /// The 3-of-5 multisig descriptor this daemon's BTC key sits in.
    pub descriptor: MultisigDescriptor,
    /// This daemon's compressed secp256k1 BTC pubkey (Set A per
    /// `docs/runbooks/key-ceremony.md`). Must appear in `descriptor`.
    pub my_pubkey: bitcoin::PublicKey,
    /// Address used to identify this BTC key inside the HSM frontend
    /// (same secp256k1 curve as Ethereum; HSM frontends commonly
    /// address keys by ETH-style 20-byte hash regardless of usage).
    pub hsm_address: Address,
}

/// Helper: produce `(StatusCode, Json<ErrorBody>)` shorthands.
fn err(
    code: &str,
    status: StatusCode,
    message: impl Into<String>,
) -> (StatusCode, Json<ErrorBody>) {
    (
        status,
        Json(ErrorBody {
            code: code.to_string(),
            message: message.into(),
        }),
    )
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| {
            #[expect(
                clippy::cast_possible_wrap,
                reason = "unix secs within i64 range for centuries"
            )]
            let v = d.as_secs() as i64;
            v
        })
}

/// Daemon-side dependency: the BTC config + the HSM frontend +
/// the replay store. Passed via `DaemonState`'s additional bitcoin
/// role payload. Kept generic to preserve static dispatch.
#[derive(Debug)]
pub struct BtcSignerState<S: ReplayStore + 'static, H: HsmDigestSigner + 'static> {
    pub config: Arc<BtcSignerConfig>,
    pub replay: Arc<S>,
    pub hsm: Arc<H>,
}

impl<S: ReplayStore + 'static, H: HsmDigestSigner + 'static> Clone for BtcSignerState<S, H> {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            replay: Arc::clone(&self.replay),
            hsm: Arc::clone(&self.hsm),
        }
    }
}

/// Axum handler. Pulls the BTC role out of `DaemonState`; if the
/// daemon was started without a BTC role this route is not registered
/// and the request reaches a 404 from the router itself.
///
/// # Errors
/// Returns an `(StatusCode, Json<ErrorBody>)` tuple with one of the
/// stable `error_codes` constants from [`xindex_shared::signer_wire`]:
/// `invalid_psbt` (400), `wrong_descriptor` / `vin0_not_multisig`
/// (422), `conflict_already_signed_different` (409), `hsm_unavailable`
/// (503), `endpoint_disabled` (404).
#[expect(
    clippy::too_many_lines,
    reason = "single sequential validate-then-sign pipeline; splitting fragments the audit-relevant ordering of checks"
)]
pub async fn handle_psbt_input<S, H>(
    State(state): State<DaemonState<S, H>>,
    Json(req): Json<PsbtInputSignRequest>,
) -> Result<Json<PsbtSignResponse>, (StatusCode, Json<ErrorBody>)>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    let btc = state.btc.as_ref().ok_or_else(|| {
        err(
            error_codes::ENDPOINT_DISABLED,
            StatusCode::NOT_FOUND,
            "BTC role not enabled on this daemon",
        )
    })?;

    // 1. Decode PSBT.
    let raw = B64.decode(req.psbt_base64.as_bytes()).map_err(|e| {
        err(
            error_codes::INVALID_PSBT,
            StatusCode::BAD_REQUEST,
            format!("base64: {e}"),
        )
    })?;
    let psbt = Psbt::deserialize(&raw).map_err(|e| {
        err(
            error_codes::INVALID_PSBT,
            StatusCode::BAD_REQUEST,
            format!("psbt deserialize: {e}"),
        )
    })?;

    let idx = req.input_index as usize;
    if idx >= psbt.inputs.len() {
        return Err(err(
            error_codes::INVALID_PSBT,
            StatusCode::BAD_REQUEST,
            format!("input_index {idx} ≥ inputs.len {}", psbt.inputs.len()),
        ));
    }

    // 2. Validate this input's witness_script matches our descriptor.
    let expected_ws = derive_witness_script(&btc.descriptor).map_err(|e| {
        err(
            error_codes::WRONG_DESCRIPTOR,
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("descriptor witness_script: {e}"),
        )
    })?;
    let input = &psbt.inputs[idx];
    let input_ws = input.witness_script.as_ref().ok_or_else(|| {
        err(
            error_codes::INVALID_PSBT,
            StatusCode::BAD_REQUEST,
            "input missing witness_script",
        )
    })?;
    if input_ws.as_bytes() != expected_ws.as_bytes() {
        return Err(err(
            error_codes::WRONG_DESCRIPTOR,
            StatusCode::UNPROCESSABLE_ENTITY,
            "input witness_script does not match daemon descriptor",
        ));
    }

    // 3. Validate vin[0] is itself a multisig UTXO (Part-3 invariant —
    //    THORChain resolves refund-sender to vin[0].prevout's address).
    let vin0 = &psbt.inputs[0];
    let vin0_ws = vin0.witness_script.as_ref().ok_or_else(|| {
        err(
            error_codes::VIN0_NOT_MULTISIG,
            StatusCode::UNPROCESSABLE_ENTITY,
            "vin[0] missing witness_script",
        )
    })?;
    if vin0_ws.as_bytes() != expected_ws.as_bytes() {
        return Err(err(
            error_codes::VIN0_NOT_MULTISIG,
            StatusCode::UNPROCESSABLE_ENTITY,
            "vin[0] not spending a multisig UTXO",
        ));
    }

    // 4. witness_utxo must be present for SegWit sighash.
    let witness_utxo = input.witness_utxo.as_ref().ok_or_else(|| {
        err(
            error_codes::INVALID_PSBT,
            StatusCode::BAD_REQUEST,
            "input missing witness_utxo",
        )
    })?;

    // 5. Compute the BIP-143 P2WSH sighash.
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = cache
        .p2wsh_signature_hash(idx, input_ws, witness_utxo.value, EcdsaSighashType::All)
        .map_err(|e| {
            err(
                error_codes::INVALID_PSBT,
                StatusCode::BAD_REQUEST,
                format!("sighash: {e}"),
            )
        })?;
    let sighash_bytes: [u8; 32] = sighash.to_byte_array();

    // 6. Replay-DB key = the outpoint this input is spending.
    let txin = psbt.unsigned_tx.input.get(idx).ok_or_else(|| {
        err(
            error_codes::INVALID_PSBT,
            StatusCode::BAD_REQUEST,
            "missing tx input",
        )
    })?;
    let prev_txid: [u8; 32] = *txin.previous_output.txid.as_ref();
    let prev_vout: u32 = txin.previous_output.vout;
    let payload_hash = hash_psbt_payload(&prev_txid, prev_vout, &sighash_bytes);

    // 7. Replay check.
    let outcome = state
        .replay
        .check_psbt_input(prev_txid, prev_vout, payload_hash)
        .await
        .map_err(|e| {
            err(
                error_codes::BAD_REQUEST,
                StatusCode::BAD_REQUEST,
                format!("replay db: {e}"),
            )
        })?;
    match outcome {
        CheckOutcome::Idempotent(rec) => {
            return Ok(Json(decode_stored_response(
                rec.signature.as_slice(),
                &btc.my_pubkey,
            )));
        }
        CheckOutcome::Conflict { .. } => {
            return Err(err(
                error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT,
                StatusCode::CONFLICT,
                "outpoint already signed for a different sighash (different consuming tx)",
            ));
        }
        CheckOutcome::FirstTime => {}
    }

    // 8. Sign the 32-byte sighash via the HSM frontend (raw secp256k1
    //    over the digest, no further hashing).
    let raw_sig = state
        .hsm
        .sign_digest(btc.hsm_address, sighash_bytes.into())
        .await
        .map_err(|e| {
            err(
                error_codes::HSM_UNAVAILABLE,
                StatusCode::SERVICE_UNAVAILABLE,
                e.to_string(),
            )
        })?;
    // r ‖ s ‖ v → take r ‖ s as compact (64 bytes); discard v (Bitcoin
    // ECDSA uses no recovery byte).
    let mut compact = [0u8; 64];
    compact.copy_from_slice(&raw_sig[..64]);
    let secp_sig = secp256k1::ecdsa::Signature::from_compact(&compact).map_err(|e| {
        err(
            error_codes::HSM_UNAVAILABLE,
            StatusCode::SERVICE_UNAVAILABLE,
            format!("HSM returned non-ECDSA: {e}"),
        )
    })?;
    // Belt-and-suspenders: verify HSM signature against our pubkey + sighash.
    let msg = Message::from_digest(sighash_bytes);
    let secp = btc.descriptor.secp();
    if secp
        .verify_ecdsa(&msg, &secp_sig, &btc.my_pubkey.inner)
        .is_err()
    {
        return Err(err(
            error_codes::HSM_UNAVAILABLE,
            StatusCode::SERVICE_UNAVAILABLE,
            "HSM signature did not verify against configured pubkey",
        ));
    }
    let btc_sig = BtcEcdsaSig {
        signature: secp_sig,
        sighash_type: EcdsaSighashType::All,
    };
    let sig_bytes = btc_sig.to_vec(); // DER + sighash-flag byte
    let response = PsbtSignResponse {
        pubkey: format!(
            "0x{}",
            alloy_primitives::hex::encode(btc.my_pubkey.to_bytes())
        ),
        signature: alloy_primitives::hex::encode(&sig_bytes),
    };
    // 9. Record (sig_bytes is what we hand back; storing it makes
    //    idempotent re-queries observable).
    state
        .replay
        .record_psbt_input(
            prev_txid,
            prev_vout,
            payload_hash,
            sig_bytes,
            now_unix_secs(),
        )
        .await
        .map_err(|e| {
            err(
                error_codes::BAD_REQUEST,
                StatusCode::BAD_REQUEST,
                format!("replay record: {e}"),
            )
        })?;
    Ok(Json(response))
}

/// Derive the descriptor's `witness_script` (the script all our P2WSH
/// inputs spend from). Pure — depends only on the configured pubkeys
/// + threshold, no derivation index.
fn derive_witness_script(descriptor: &MultisigDescriptor) -> Result<bitcoin::ScriptBuf, String> {
    descriptor
        .descriptor
        .at_derivation_index(0)
        .map_err(|e| e.to_string())?
        .explicit_script()
        .map_err(|e| e.to_string())
}

/// `payload_hash = keccak256(prev_txid ‖ prev_vout_le_u32 ‖ sighash)`.
/// Including the sighash means a *different* consuming tx of the same
/// outpoint is detected as a payload conflict, not silently
/// double-signed.
fn hash_psbt_payload(prev_txid: &[u8; 32], prev_vout: u32, sighash: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 68];
    buf[..32].copy_from_slice(prev_txid);
    buf[32..36].copy_from_slice(&prev_vout.to_le_bytes());
    buf[36..68].copy_from_slice(sighash);
    alloy_primitives::keccak256(buf).into()
}

/// Rebuild the wire response from a stored DER+sighash signature.
fn decode_stored_response(stored: &[u8], pubkey: &bitcoin::PublicKey) -> PsbtSignResponse {
    PsbtSignResponse {
        pubkey: format!("0x{}", alloy_primitives::hex::encode(pubkey.to_bytes())),
        signature: alloy_primitives::hex::encode(stored),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::InMemoryReplayStore;
    use crate::server::{DaemonConfig, DaemonState};
    use crate::web3signer::{HsmDigestSigner, HsmError};
    use alloy_primitives::B256;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use bitcoin::{
        secp256k1::{All, Secp256k1, SecretKey},
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use std::sync::Mutex;
    use tower::ServiceExt;

    /// Software-keyed `HsmDigestSigner` for tests — produces a real
    /// secp256k1 signature so the daemon's r||s||v → compact → DER
    /// conversion + verify-against-pubkey path actually runs.
    struct SoftHsm {
        secp: Secp256k1<All>,
        secret: SecretKey,
        public: bitcoin::PublicKey,
        seen: Mutex<u32>,
    }

    impl std::fmt::Debug for SoftHsm {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SoftHsm").finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl HsmDigestSigner for SoftHsm {
        async fn sign_digest(&self, _addr: Address, digest: B256) -> Result<[u8; 65], HsmError> {
            #[expect(clippy::unwrap_used, reason = "test code")]
            {
                *self.seen.lock().unwrap() += 1;
            }
            let msg = Message::from_digest(digest.0);
            let sig = self.secp.sign_ecdsa(&msg, &self.secret);
            let compact = sig.serialize_compact();
            let mut out = [0u8; 65];
            out[..64].copy_from_slice(&compact);
            out[64] = 27; // arbitrary v (Bitcoin discards)
            let _ = self.public; // silence lint
            Ok(out)
        }
    }

    fn make_descriptor(
        secp: &Secp256k1<All>,
        n: usize,
        k: usize,
    ) -> (MultisigDescriptor, Vec<SecretKey>) {
        let sks: Vec<SecretKey> = (1u8..=u8::try_from(n).unwrap_or(5))
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[31] = i;
                #[expect(clippy::expect_used, reason = "test code")]
                SecretKey::from_slice(&bytes).expect("valid")
            })
            .collect();
        let pks: Vec<bitcoin::PublicKey> = sks
            .iter()
            .map(|sk| bitcoin::PublicKey::new(sk.public_key(secp)))
            .collect();
        #[expect(clippy::expect_used, reason = "test code")]
        let desc = MultisigDescriptor::new_p2wsh(k, &pks).expect("descriptor");
        (desc, sks)
    }

    /// Build a minimal valid spending PSBT: one input spending a
    /// `previous_output` that's a P2WSH funded with our descriptor;
    /// one output. The `witness_utxo` + `witness_script` populate the
    /// fields the daemon expects.
    #[expect(clippy::expect_used, reason = "test code")]
    fn build_test_psbt(
        descriptor: &MultisigDescriptor,
        prev_txid: bitcoin::Txid,
        prev_vout: u32,
        value: Amount,
        recipient_script: ScriptBuf,
    ) -> Psbt {
        let witness_script = derive_witness_script(descriptor).expect("ws");
        let address = descriptor.address(Network::Bitcoin).expect("addr");
        let prev_spk = address.script_pubkey();

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: prev_vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: value - Amount::from_sat(1_000),
                script_pubkey: recipient_script,
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value,
            script_pubkey: prev_spk,
        });
        psbt.inputs[0].witness_script = Some(witness_script);
        psbt
    }

    fn build_state_with_btc(
        descriptor: MultisigDescriptor,
        my_pubkey: bitcoin::PublicKey,
        hsm: Arc<SoftHsm>,
    ) -> (DaemonState<InMemoryReplayStore, SoftHsm>, Router) {
        let replay = Arc::new(InMemoryReplayStore::new());
        let btc = Some(Arc::new(BtcSignerConfig {
            network: Network::Bitcoin,
            descriptor,
            my_pubkey,
            hsm_address: Address::repeat_byte(0xcd),
        }));
        let state = DaemonState {
            config: DaemonConfig {
                chain_id: 31337,
                verifying_contract: Address::repeat_byte(0xab),
                eth_address: Address::repeat_byte(0xcd),
            },
            replay,
            hsm,
            btc,
        };
        let app = Router::new()
            .route(
                "/api/v1/sign/psbt-input",
                post(handle_psbt_input::<InMemoryReplayStore, SoftHsm>),
            )
            .with_state(state.clone());
        (state, app)
    }

    async fn post_psbt(app: &Router, b64: String, idx: u32) -> (StatusCode, serde_json::Value) {
        #[expect(clippy::expect_used, reason = "test code")]
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/sign/psbt-input")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"psbt_base64": b64, "input_index": idx}).to_string(),
                    ))
                    .expect("req"),
            )
            .await
            .expect("send");
        let status = resp.status();
        #[expect(clippy::expect_used, reason = "test code")]
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn first_sign_records_and_returns_valid_partial_sig() {
        let secp = Secp256k1::new();
        let (desc, sks) = make_descriptor(&secp, 3, 2);
        let my_pubkey = bitcoin::PublicKey::new(sks[0].public_key(&secp));
        let hsm = Arc::new(SoftHsm {
            secp: secp.clone(),
            secret: sks[0],
            public: my_pubkey,
            seen: Mutex::new(0),
        });
        let (_state, app) = build_state_with_btc(desc.clone(), my_pubkey, Arc::clone(&hsm));

        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x11u8; 32]));
        let psbt = build_test_psbt(
            &desc,
            prev_txid,
            0,
            Amount::from_sat(100_000),
            ScriptBuf::new_op_return(b"x"),
        );
        let b64 = B64.encode(psbt.serialize());

        let (status, body) = post_psbt(&app, b64.clone(), 0).await;
        assert_eq!(status, StatusCode::OK);
        let sig_hex = body["signature"].as_str().expect("signature");
        // DER signatures are 70-72 bytes + 1 sighash byte → 71-73 bytes.
        let sig_bytes = alloy_primitives::hex::decode(sig_hex).expect("sig hex");
        assert!(
            sig_bytes.len() >= 70 && sig_bytes.len() <= 73,
            "sig len {}",
            sig_bytes.len()
        );
        assert_eq!(
            *sig_bytes.last().expect("last"),
            EcdsaSighashType::All as u8
        );
        let pk_hex = body["pubkey"].as_str().expect("pubkey");
        assert_eq!(
            pk_hex,
            format!("0x{}", alloy_primitives::hex::encode(my_pubkey.to_bytes()))
        );

        // Idempotent: re-post returns the same signature without
        // re-invoking the HSM.
        #[expect(clippy::unwrap_used, reason = "test code")]
        let before = *hsm.seen.lock().unwrap();
        let (status2, body2) = post_psbt(&app, b64, 0).await;
        assert_eq!(status2, StatusCode::OK);
        assert_eq!(body2["signature"], body["signature"]);
        #[expect(clippy::unwrap_used, reason = "test code")]
        let after = *hsm.seen.lock().unwrap();
        assert_eq!(before, after, "HSM must not be invoked on idempotent retry");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn different_consuming_tx_same_outpoint_is_409() {
        let secp = Secp256k1::new();
        let (desc, sks) = make_descriptor(&secp, 3, 2);
        let my_pubkey = bitcoin::PublicKey::new(sks[0].public_key(&secp));
        let hsm = Arc::new(SoftHsm {
            secp: secp.clone(),
            secret: sks[0],
            public: my_pubkey,
            seen: Mutex::new(0),
        });
        let (_state, app) = build_state_with_btc(desc.clone(), my_pubkey, hsm);
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x22u8; 32]));
        let psbt_a = build_test_psbt(
            &desc,
            prev_txid,
            0,
            Amount::from_sat(100_000),
            ScriptBuf::new_op_return(b"a"),
        );
        let psbt_b = build_test_psbt(
            &desc,
            prev_txid,
            0,
            Amount::from_sat(100_000),
            ScriptBuf::new_op_return(b"b"), // different output → different sighash
        );
        let (s1, _) = post_psbt(&app, B64.encode(psbt_a.serialize()), 0).await;
        assert_eq!(s1, StatusCode::OK);
        let (s2, body2) = post_psbt(&app, B64.encode(psbt_b.serialize()), 0).await;
        assert_eq!(s2, StatusCode::CONFLICT);
        assert_eq!(
            body2["code"].as_str().expect("code"),
            error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT
        );
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn mismatched_witness_script_is_422_wrong_descriptor() {
        let secp = Secp256k1::new();
        let (desc, sks) = make_descriptor(&secp, 3, 2);
        let my_pubkey = bitcoin::PublicKey::new(sks[0].public_key(&secp));
        let hsm = Arc::new(SoftHsm {
            secp: secp.clone(),
            secret: sks[0],
            public: my_pubkey,
            seen: Mutex::new(0),
        });
        let (_state, app) = build_state_with_btc(desc.clone(), my_pubkey, hsm);
        // Build a PSBT but tamper the witness_script to something
        // unrelated → daemon refuses.
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x33u8; 32]));
        let mut psbt = build_test_psbt(
            &desc,
            prev_txid,
            0,
            Amount::from_sat(100_000),
            ScriptBuf::new_op_return(b"x"),
        );
        psbt.inputs[0].witness_script = Some(ScriptBuf::from_bytes(vec![0x00, 0x01, 0x02]));
        let (status, body) = post_psbt(&app, B64.encode(psbt.serialize()), 0).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["code"].as_str().expect("code"),
            error_codes::WRONG_DESCRIPTOR
        );
    }
}
