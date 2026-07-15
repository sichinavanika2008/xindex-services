//! Remote (daemon-backed) [`MultisigCosigner`] impl (PART 5 / DL-M5-1).
//!
//! Serializes the PSBT, posts to a signer-daemon's
//! `/api/v1/sign/psbt-input`, parses the typed [`PsbtSignResponse`],
//! verifies the daemon returned the expected compressed pubkey, and
//! hands back the `(pubkey, bitcoin::ecdsa::Signature)` pair that
//! [`InProcessExecutor::execute_capturing_tx`] composes into a
//! finalized 3-of-5 transaction. Production drop-in for
//! `InProcessExecutor`'s in-heap secret keys.
//!
//! The daemon side enforces the security-critical properties
//! (replay/slashing DB, descriptor match, `vin[0]` invariant); the
//! coordinator-side responsibility here is purely transport + pin.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bitcoin::ecdsa::Signature as BtcEcdsaSig;
use bitcoin::psbt::Psbt;
use xindex_ops::network::{blocking_client_builder, read_bounded_blocking, HttpClientPolicy};
use xindex_ops::tls::{
    exact_pinned_blocking_client_builder, load_cert_chain, load_private_key, pinned_cert_store,
};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{PsbtInputSignRequest, PsbtSignResponse};

use crate::redeem::{ExecuteError, ExpectedOutputs, MultisigCosigner, SpendCertificate};

const DEFAULT_TIMEOUT_SECS: u64 = 10;
const MAX_SIGNER_RESPONSE_BYTES: usize = 64 * 1024;

/// HTTP client implementing [`MultisigCosigner`] against one signer
/// daemon's PSBT-input endpoint. Holds the publicly-disclosed pubkey
/// (Set A per `docs/runbooks/key-ceremony.md`) — pinned and verified
/// against every daemon response. Bound to one UTXO chain (since U8 —
/// daemons are multi-role internally but each cosigner instance speaks
/// for one chain on behalf of the coordinator).
#[derive(Clone)]
pub struct RemoteMultisigCosigner {
    chain_id: ChainId,
    base_url: String,
    expected_pubkey: bitcoin::PublicKey,
    inner: Result<reqwest::blocking::Client, String>,
}

impl std::fmt::Debug for RemoteMultisigCosigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteMultisigCosigner")
            .field("chain_id", &self.chain_id)
            .field("base_url", &"<redacted>")
            .field("expected_pubkey", &self.expected_pubkey)
            .finish_non_exhaustive()
    }
}

impl RemoteMultisigCosigner {
    /// Construct against `base_url` (e.g. `http://127.0.0.1:9101`).
    /// `chain_id` selects which of the daemon's per-chain configs to
    /// dispatch against (U8 multi-role). `expected_pubkey` is the
    /// daemon's disclosed Set-A pubkey FOR THIS CHAIN; every response
    /// is verified to match it. A misdirected daemon returning the
    /// wrong pubkey is a hard fail, never accepted.
    #[must_use]
    pub fn new(
        chain_id: ChainId,
        base_url: impl Into<String>,
        expected_pubkey: bitcoin::PublicKey,
    ) -> Self {
        Self::with_timeout(
            chain_id,
            base_url,
            expected_pubkey,
            Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        )
    }

    #[must_use]
    pub fn with_timeout(
        chain_id: ChainId,
        base_url: impl Into<String>,
        expected_pubkey: bitcoin::PublicKey,
        timeout: Duration,
    ) -> Self {
        let inner = blocking_client_builder(HttpClientPolicy {
            connect_timeout: timeout.min(Duration::from_secs(1)),
            request_timeout: timeout,
            max_response_bytes: MAX_SIGNER_RESPONSE_BYTES,
        })
        .and_then(|builder| {
            builder
                .build()
                .map_err(|_| xindex_ops::network::NetworkError::ClientBuild)
        })
        .map_err(|error| error.to_string());
        Self {
            chain_id,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            expected_pubkey,
            inner,
        }
    }

    /// Build a production client with an exact daemon leaf bundle and a
    /// coordinator client certificate. Plaintext and system-root fallback are
    /// deliberately unavailable.
    ///
    /// # Errors
    /// Invalid HTTPS URL, PEM identity/peer material, or TLS client build.
    pub fn with_mtls_pem(
        chain_id: ChainId,
        base_url: impl Into<String>,
        expected_pubkey: bitcoin::PublicKey,
        client_cert_pem: &[u8],
        client_key_pem: &[u8],
        daemon_peer_bundle_pem: &[u8],
        timeout: Duration,
    ) -> Result<Self, ExecuteError> {
        let base_url = base_url.into();
        let parsed = reqwest::Url::parse(&base_url)
            .map_err(|error| ExecuteError::Configuration(format!("cosigner URL: {error}")))?;
        if parsed.scheme() != "https" {
            return Err(ExecuteError::Configuration(
                "production cosigner URL must use https".to_string(),
            ));
        }
        let pins = pinned_cert_store(&[daemon_peer_bundle_pem.to_vec()])
            .map_err(|error| ExecuteError::Configuration(format!("cosigner exact pin: {error}")))?;
        let builder = exact_pinned_blocking_client_builder(
            HttpClientPolicy {
                connect_timeout: timeout.min(Duration::from_secs(1)),
                request_timeout: timeout,
                max_response_bytes: MAX_SIGNER_RESPONSE_BYTES,
            },
            load_cert_chain(client_cert_pem).map_err(|error| {
                ExecuteError::Configuration(format!("cosigner client cert: {error}"))
            })?,
            load_private_key(client_key_pem).map_err(|error| {
                ExecuteError::Configuration(format!("cosigner client key: {error}"))
            })?,
            pins,
        )
        .map_err(|error| ExecuteError::Configuration(format!("cosigner mTLS: {error}")))?;
        let inner = builder
            .build()
            .map_err(|_| ExecuteError::Configuration("build cosigner mTLS client".to_string()))?;
        Ok(Self {
            chain_id,
            base_url: base_url.trim_end_matches('/').to_string(),
            expected_pubkey,
            inner: Ok(inner),
        })
    }
}

impl MultisigCosigner for RemoteMultisigCosigner {
    fn cosigner_pubkey(&self) -> bitcoin::PublicKey {
        self.expected_pubkey
    }

    fn sign_input(
        &self,
        psbt: &Psbt,
        input_index: usize,
        expected: Option<&ExpectedOutputs>,
        certificate: Option<&SpendCertificate>,
    ) -> Result<(bitcoin::PublicKey, BtcEcdsaSig), ExecuteError> {
        let bytes = psbt.serialize();
        let idx_u32 = u32::try_from(input_index).map_err(|_| {
            ExecuteError::InvalidMemo(format!("input_index {input_index} > u32::MAX"))
        })?;
        // Strict XOR onto the wire: the enum makes a both-certificates
        // request unrepresentable (the daemon would 422 it anyway).
        let (intent_proof, acquire_cancel_proof) = match certificate {
            Some(SpendCertificate::Ric(p)) => (Some(p.clone()), None),
            Some(SpendCertificate::Acc(p)) => (None, Some(p.clone())),
            None => (None, None),
        };
        let req = PsbtInputSignRequest {
            chain_id: self.chain_id,
            psbt_base64: B64.encode(&bytes),
            input_index: idx_u32,
            expected_destination_spk: expected
                .map(|e| alloy_primitives::hex::encode(&e.destination_spk)),
            expected_amount_sats: expected.map(|e| e.amount_sats),
            expected_memo: expected.map(|e| alloy_primitives::hex::encode(&e.memo)),
            intent_proof,
            acquire_cancel_proof,
        };
        let inner = self.inner.as_ref().map_err(|_| {
            ExecuteError::Configuration("daemon HTTP client unavailable".to_string())
        })?;
        let resp = inner
            .post(format!("{}/api/v1/sign/psbt-input", self.base_url))
            .json(&req)
            .send()
            .map_err(|e| {
                ExecuteError::InvalidMemo(format!("daemon transport: {}", transport_class(&e)))
            })?;
        let status = resp.status();
        if !status.is_success() {
            return Err(ExecuteError::InvalidMemo(format!(
                "daemon http {}",
                status.as_u16()
            )));
        }
        let response_body = read_bounded_blocking(resp, MAX_SIGNER_RESPONSE_BYTES)
            .map_err(|_| ExecuteError::InvalidMemo("daemon response body".to_string()))?;
        let parsed: PsbtSignResponse = serde_json::from_slice(&response_body)
            .map_err(|_| ExecuteError::InvalidMemo("daemon response json malformed".to_string()))?;

        // Pin the pubkey: a misdirected daemon returning a different
        // signer is a hard fail.
        let pk_hex = parsed.pubkey.strip_prefix("0x").unwrap_or(&parsed.pubkey);
        let pk_bytes = alloy_primitives::hex::decode(pk_hex)
            .map_err(|e| ExecuteError::InvalidMemo(format!("daemon pubkey hex: {e}")))?;
        let pk = bitcoin::PublicKey::from_slice(&pk_bytes)
            .map_err(|e| ExecuteError::InvalidMemo(format!("daemon pubkey: {e}")))?;
        if pk != self.expected_pubkey {
            return Err(ExecuteError::InvalidMemo(format!(
                "daemon returned pubkey {pk}, expected {}",
                self.expected_pubkey
            )));
        }

        // Decode DER+sighash signature.
        let sig_bytes = alloy_primitives::hex::decode(&parsed.signature)
            .map_err(|e| ExecuteError::InvalidMemo(format!("daemon signature hex: {e}")))?;
        let btc_sig = BtcEcdsaSig::from_slice(&sig_bytes)
            .map_err(|e| ExecuteError::InvalidMemo(format!("daemon signature: {e}")))?;
        Ok((pk, btc_sig))
    }
}

fn transport_class(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() {
        "body"
    } else if error.is_request() {
        "request"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{
        absolute, secp256k1::Message, transaction, Amount, Network, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Witness,
    };
    use xindex_multisig::MultisigDescriptor;

    #[test]
    fn production_cosigner_rejects_plaintext_before_loading_identity() {
        let secp = Secp256k1::new();
        let (_, keys) = make_descriptor(&secp);
        let pubkey = bitcoin::PublicKey::new(keys[0].public_key(&secp));
        let result = RemoteMultisigCosigner::with_mtls_pem(
            ChainId::Btc,
            "http://cosigner.example",
            pubkey,
            b"invalid",
            b"invalid",
            b"invalid",
            Duration::from_secs(1),
        );
        assert!(matches!(result, Err(ExecuteError::Configuration(_))));
    }

    fn make_descriptor(secp: &Secp256k1<All>) -> (MultisigDescriptor, Vec<SecretKey>) {
        let sks: Vec<SecretKey> = (1u8..=3u8)
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
        let desc = MultisigDescriptor::new_p2wsh(2, &pks).expect("descriptor");
        (desc, sks)
    }

    /// Build a minimal valid PSBT shape the cosigner's `sign_input`
    /// can serialize over the wire. We only check that the daemon
    /// returns a valid `(pubkey, signature)` pair the cosigner parses
    /// correctly; the daemon's own correctness is exercised
    /// separately in `xindex-signer-daemon::psbt::tests`.
    #[expect(clippy::expect_used, reason = "test code")]
    fn build_psbt(descriptor: &MultisigDescriptor) -> Psbt {
        let ws = descriptor
            .descriptor
            .at_derivation_index(0)
            .expect("at_derivation_index")
            .explicit_script()
            .expect("explicit_script");
        let address = descriptor.address(Network::Bitcoin).expect("addr");
        let prev_spk = address.script_pubkey();
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x11u8; 32]));
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
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: ScriptBuf::new_op_return(b"y"),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: prev_spk,
        });
        psbt.inputs[0].witness_script = Some(ws);
        psbt
    }

    /// Compute a real ECDSA signature over the PSBT's first input so
    /// the test response carries a DER signature the cosigner can
    /// parse end-to-end (not a hand-rolled bogus blob).
    fn real_sig_for(
        secp: &Secp256k1<All>,
        sk: &SecretKey,
        psbt: &Psbt,
    ) -> bitcoin::ecdsa::Signature {
        use bitcoin::hashes::Hash;
        #[expect(clippy::expect_used, reason = "test code")]
        let ws = psbt.inputs[0].witness_script.as_ref().expect("ws");
        #[expect(clippy::expect_used, reason = "test code")]
        let wu = psbt.inputs[0].witness_utxo.as_ref().expect("wu");
        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        #[expect(clippy::expect_used, reason = "test code")]
        let sighash = cache
            .p2wsh_signature_hash(0, ws, wu.value, EcdsaSighashType::All)
            .expect("sighash");
        let msg = Message::from_digest(sighash.to_byte_array());
        let secp_sig = secp.sign_ecdsa(&msg, sk);
        bitcoin::ecdsa::Signature {
            signature: secp_sig,
            sighash_type: EcdsaSighashType::All,
        }
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sign_input_round_trip_via_mock_daemon() {
        let secp = Secp256k1::new();
        let (desc, sks) = make_descriptor(&secp);
        let pk = bitcoin::PublicKey::new(sks[0].public_key(&secp));
        let psbt = build_psbt(&desc);
        let sig = real_sig_for(&secp, &sks[0], &psbt);
        let sig_hex = alloy_primitives::hex::encode(sig.to_vec());

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v1/sign/psbt-input"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "pubkey": format!("0x{}", alloy_primitives::hex::encode(pk.to_bytes())),
                    "signature": sig_hex,
                })),
            )
            .mount(&server)
            .await;

        let url = server.uri();
        let psbt_clone = psbt.clone();
        let (got_pk, got_sig) = tokio::task::spawn_blocking(move || {
            let cosigner = RemoteMultisigCosigner::new(ChainId::Btc, url, pk);
            cosigner.sign_input(&psbt_clone, 0, None, None)
        })
        .await
        .expect("join")
        .expect("sign_input");

        assert_eq!(got_pk, pk);
        assert_eq!(got_sig.signature, sig.signature);
        assert_eq!(got_sig.sighash_type as u8, EcdsaSighashType::All as u8);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn daemon_returning_wrong_pubkey_is_hard_fail() {
        let secp = Secp256k1::new();
        let (desc, sks) = make_descriptor(&secp);
        let pk = bitcoin::PublicKey::new(sks[0].public_key(&secp));
        let other = bitcoin::PublicKey::new(sks[1].public_key(&secp));
        let psbt = build_psbt(&desc);
        let sig = real_sig_for(&secp, &sks[0], &psbt);
        let sig_hex = alloy_primitives::hex::encode(sig.to_vec());

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v1/sign/psbt-input"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "pubkey": format!("0x{}", alloy_primitives::hex::encode(other.to_bytes())),
                    "signature": sig_hex,
                })),
            )
            .mount(&server)
            .await;
        let url = server.uri();
        let psbt_clone = psbt.clone();
        let err = tokio::task::spawn_blocking(move || {
            RemoteMultisigCosigner::new(ChainId::Btc, url, pk).sign_input(
                &psbt_clone,
                0,
                None,
                None,
            )
        })
        .await
        .expect("join")
        .expect_err("must reject wrong pubkey");
        assert!(err.to_string().contains("expected"));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn daemon_5xx_surfaces_as_execute_error() {
        let secp = Secp256k1::new();
        let (desc, sks) = make_descriptor(&secp);
        let pk = bitcoin::PublicKey::new(sks[0].public_key(&secp));
        let psbt = build_psbt(&desc);

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v1/sign/psbt-input"))
            .respond_with(wiremock::ResponseTemplate::new(503).set_body_string("hsm offline"))
            .mount(&server)
            .await;
        let url = server.uri();
        let psbt_clone = psbt.clone();
        let err = tokio::task::spawn_blocking(move || {
            RemoteMultisigCosigner::new(ChainId::Btc, url, pk).sign_input(
                &psbt_clone,
                0,
                None,
                None,
            )
        })
        .await
        .expect("join")
        .expect_err("must surface 503");
        assert!(err.to_string().contains("503"));
    }
}
