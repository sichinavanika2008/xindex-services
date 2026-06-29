//! BTC redeem leg under Turnkey enclave custody (`DL-CUSTODY-TURNKEY-1`).
//!
//! The Turnkey replacement for the 3-of-5 P2WSH multisig flow
//! ([`crate::redeem`]). Under Turnkey the BTC custody key is a single P-256/
//! secp256k1 key in an attested enclave, so the custody address is **P2WPKH**
//! (single-sig), not P2WSH multisig. Turnkey is a RAW signer — *we* build the
//! transaction and compute the sighash; Turnkey signs that exact hash via
//! `SIGN_RAW_PAYLOAD`; *we* assemble the witness and broadcast. The flow:
//!
//! 1. Select a custody UTXO covering amount + fee.
//! 2. Build the unsigned spend: `[Asgard vault, OP_RETURN(memo), change→self]`.
//! 3. Compute the BIP-143 P2WPKH sighash for the input.
//! 4. Store the prepared spend in the SHARED prepare store keyed by the sighash
//!    hex — the approver-watcher looks it up by the activity's signing payload
//!    (which IS this sighash) and binds it to the k-of-n RIC.
//! 5. `sign_raw_payload(payload = sighash)` → a `CONSENSUS_NEEDED` activity; the
//!    approver votes; Turnkey returns `r,s,v` once consensus is met.
//! 6. Assemble the P2WPKH witness `[DER(sig)+SIGHASH_ALL, pubkey]`, broadcast.
//!
//! Fail-closed: a rejected/failed activity ⇒ no signature ⇒ no broadcast.
//!
//! PROVISIONAL until the Turnkey dev-env: the `// RECONCILE AT DEV-ENV` markers
//! in [`xindex_turnkey_client`] (`NO_OP` hash function, activity correlation).

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{B256, U256};
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::ecdsa::Signature as SecpSignature;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, CompressedPublicKey, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use thiserror::Error;
use tracing::{debug, info};

use xindex_chain_utxo::{UtxoChainClient, UtxoEntry, UtxoError, UtxoParams};
use xindex_custody_core::prepare::{BindContext, PrepareStore, PreparedSpend};
use xindex_shared::chain_registry::ChainId;
use xindex_turnkey_client::{Activity, SignRawPayloadParams, TurnkeyApi};

use crate::redeem::RedeemTask;

/// `SIGHASH_ALL` flag byte appended to the DER signature in the P2WPKH witness
/// (matches the `EcdsaSighashType::All` used to compute the sighash). A literal
/// avoids a lint-tripping `u32`→`u8` cast.
const SIGHASH_ALL_FLAG: u8 = 0x01;

/// Errors surfaced by the Turnkey BTC redeem executor.
#[derive(Debug, Error)]
pub enum TurnkeyBtcError {
    /// Redeem amount converted to satoshis exceeds `u64::MAX` or is zero.
    #[error("invalid amount: {0}")]
    InvalidAmount(String),
    /// The `OP_RETURN` memo exceeds the per-chain null-data relay limit.
    #[error("op_return memo {0} bytes exceeds the per-chain limit")]
    MemoTooLong(usize),
    /// No custody UTXO covers the requested amount + fee.
    #[error("no UTXO covers amount {needed_sats} sats (have {available_sats})")]
    InsufficientFunds {
        /// Amount + fee required.
        needed_sats: u64,
        /// Total available across all custody UTXOs.
        available_sats: u64,
    },
    /// Bitcoin chain access failed.
    #[error("bitcoin chain error: {0}")]
    Chain(#[from] UtxoError),
    /// Failed to persist the prepared spend (the approver would then have no
    /// context and fail-close, so we abort BEFORE submitting to Turnkey).
    #[error("prepare store: {0}")]
    Prepare(String),
    /// A Turnkey API call failed.
    #[error("turnkey api: {0}")]
    Turnkey(String),
    /// Sighash computation failed.
    #[error("sighash: {0}")]
    Sighash(String),
    /// The signing activity was rejected / failed (the approver voted REJECT,
    /// or a Turnkey policy denied it) — no signature, no broadcast.
    #[error("signing activity {activity_id} terminated without a signature")]
    Rejected {
        /// The Turnkey activity id.
        activity_id: String,
    },
    /// Polling exhausted before the activity reached a terminal state.
    #[error("signing activity {activity_id} did not complete after polling")]
    PollTimeout {
        /// The Turnkey activity id.
        activity_id: String,
    },
    /// The activity completed but carried no signature result.
    #[error("signing activity {activity_id} completed without a signature result")]
    NoSignature {
        /// The Turnkey activity id.
        activity_id: String,
    },
    /// Assembling the secp256k1 signature from Turnkey's `(r,s)` failed.
    #[error("signature assembly: {0}")]
    Signature(String),
}

/// Static per-executor configuration. One executor per Turnkey custody key.
#[derive(Debug, Clone)]
pub struct TurnkeyBtcRedeemConfig {
    /// The UTXO chain this executor serves (`Btc` first; same shape for
    /// `Ltc`).
    pub chain: ChainId,
    /// The P2WPKH custody address (UTXO source + change destination). The
    /// caller derives it from `custody_pubkey`; they must agree.
    pub custody_address: Address,
    /// The compressed custody public key (assembles the witness).
    pub custody_pubkey: CompressedPublicKey,
    /// The Turnkey `signWith` selector (private-key id / wallet-account
    /// address) for this custody key.
    pub sign_with: String,
    /// Flat fee budget (sats) for the single-input spend.
    pub fee_sats: u64,
    /// Delay between activity status polls.
    pub poll_interval: Duration,
    /// Max status polls before [`TurnkeyBtcError::PollTimeout`].
    pub poll_max_attempts: u32,
}

/// Turnkey BTC redeem executor. The executor builds + assembles + broadcasts;
/// Turnkey signs the sighash, gated by the approver-watcher.
pub struct TurnkeyBtcRedeemExecutor<T, C, P> {
    config: TurnkeyBtcRedeemConfig,
    turnkey: Arc<T>,
    chain: C,
    prepare: Arc<P>,
}

impl<T, C, P> std::fmt::Debug for TurnkeyBtcRedeemExecutor<T, C, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnkeyBtcRedeemExecutor")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// The result of a completed Turnkey BTC redeem leg.
#[derive(Debug, Clone)]
pub struct TurnkeyBtcRedeemOutcome {
    /// Originating dispatch id (broadcast registry key).
    pub dispatch_id: B256,
    /// Originating redemption id (attestation correlation).
    pub redemption_id: B256,
    /// The broadcast transaction id.
    pub txid: Txid,
    /// The Turnkey signing activity id.
    pub activity_id: String,
}

impl<T: TurnkeyApi, C: UtxoChainClient, P: PrepareStore> TurnkeyBtcRedeemExecutor<T, C, P> {
    /// Construct.
    #[must_use]
    pub fn new(config: TurnkeyBtcRedeemConfig, turnkey: Arc<T>, chain: C, prepare: Arc<P>) -> Self {
        Self {
            config,
            turnkey,
            chain,
            prepare,
        }
    }

    /// Borrow the configuration.
    #[must_use]
    pub fn config(&self) -> &TurnkeyBtcRedeemConfig {
        &self.config
    }

    /// Execute one BTC redeem leg through Turnkey: select UTXO → build spend →
    /// sighash → prepare → sign (gated) → assemble witness → broadcast.
    ///
    /// `asgard` is the `THORChain` BTC inbound vault, resolved live by the
    /// caller (rejected upstream if the registry is stale / halted).
    ///
    /// # Errors
    /// Any [`TurnkeyBtcError`] variant.
    pub async fn execute_leg(
        &self,
        task: &RedeemTask,
        asgard: &Address,
    ) -> Result<TurnkeyBtcRedeemOutcome, TurnkeyBtcError> {
        let params = UtxoParams::for_chain(self.config.chain);
        if task.memo.len() > params.op_return_max {
            return Err(TurnkeyBtcError::MemoTooLong(task.memo.len()));
        }
        let recipient_value = amount_to_sats(task.amount)?;
        let needed = recipient_value
            .checked_add(Amount::from_sat(self.config.fee_sats))
            .ok_or_else(|| TurnkeyBtcError::InvalidAmount("fee overflow".to_string()))?;

        let utxos = self.chain.get_address_utxos(&self.config.custody_address)?;
        let selected = select_utxo(&utxos, needed)?;

        let dust = Amount::from_sat(params.dust_sats);
        let raw_change = selected.value.checked_sub(needed).unwrap_or(Amount::ZERO);
        let change_value = if raw_change >= dust {
            raw_change
        } else {
            Amount::ZERO
        };

        let custody_spk = self.config.custody_address.script_pubkey();
        let psbt = build_p2wpkh_psbt(&P2wpkhSpend {
            outpoint: OutPoint {
                txid: selected.txid,
                vout: selected.vout,
            },
            utxo_value: selected.value,
            custody_spk: &custody_spk,
            recipient: asgard,
            recipient_value,
            change_value,
            memo: &task.memo,
            max_op_return: params.op_return_max,
        })?;

        // BIP-143 P2WPKH sighash for the single input.
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .p2wpkh_signature_hash(0, &custody_spk, selected.value, EcdsaSighashType::All)
            .map_err(|e| TurnkeyBtcError::Sighash(e.to_string()))?
            .to_byte_array();
        let payload_hex = format!("0x{}", alloy_primitives::hex::encode(sighash));

        // Persist the prepared spend keyed by the sighash BEFORE signing — the
        // approver looks it up by the activity's payload (== this sighash) and
        // binds it to the RIC; a missing context fail-closes the signature.
        self.prepare
            .put(
                payload_hex.clone(),
                PreparedSpend::Btc(Box::new(BindContext {
                    chain: self.config.chain,
                    psbt: psbt.clone(),
                    ric: task.intent_proof.clone(),
                    acc: None,
                })),
            )
            .await
            .map_err(|e| TurnkeyBtcError::Prepare(e.to_string()))?;

        // Submit the sign request; the approver gates the CONSENSUS_NEEDED
        // activity before Turnkey returns the signature.
        let activity = self
            .turnkey
            .sign_raw_payload(&SignRawPayloadParams::hex_no_op(
                &self.config.sign_with,
                &payload_hex,
            ))
            .await
            .map_err(|e| TurnkeyBtcError::Turnkey(e.to_string()))?;
        let completed = self.await_signature(activity).await?;
        let result = completed
            .sign_result()
            .ok_or_else(|| TurnkeyBtcError::NoSignature {
                activity_id: completed.id.clone(),
            })?;
        let (r, s, _v) = result
            .rsv()
            .map_err(|e| TurnkeyBtcError::Turnkey(e.to_string()))?;

        let witness = assemble_p2wpkh_witness(r, s, &self.config.custody_pubkey)?;
        let mut tx = psbt.unsigned_tx.clone();
        tx.input[0].witness = witness;
        let txid = self.chain.broadcast(&tx)?;
        info!(
            redemption_id = %task.redemption_id,
            %txid,
            activity = %completed.id,
            "BTC→Asgard redemption deposit broadcast (Turnkey)"
        );
        Ok(TurnkeyBtcRedeemOutcome {
            dispatch_id: task.dispatch_id,
            redemption_id: task.redemption_id,
            txid,
            activity_id: completed.id,
        })
    }

    /// Poll the signing activity to a signature. Returns the completed activity,
    /// or a fail-closed error on reject / failure / timeout.
    async fn await_signature(&self, activity: Activity) -> Result<Activity, TurnkeyBtcError> {
        let mut current = activity;
        for _ in 0..self.config.poll_max_attempts {
            if current.status.is_completed() {
                return Ok(current);
            }
            if current.status.is_terminal() {
                // Terminal but not completed ⇒ Rejected / Failed.
                return Err(TurnkeyBtcError::Rejected {
                    activity_id: current.id,
                });
            }
            debug!(activity = %current.id, status = ?current.status, "awaiting consensus");
            tokio::time::sleep(self.config.poll_interval).await;
            current = self
                .turnkey
                .get_activity(&current.id)
                .await
                .map_err(|e| TurnkeyBtcError::Turnkey(e.to_string()))?;
        }
        Err(TurnkeyBtcError::PollTimeout {
            activity_id: current.id,
        })
    }
}

/// Convert the on-chain `amount` (8-decimal native sats) to a [`Amount`].
fn amount_to_sats(amount: U256) -> Result<Amount, TurnkeyBtcError> {
    let sats: u64 = amount
        .try_into()
        .map_err(|e| TurnkeyBtcError::InvalidAmount(format!("> u64::MAX: {e}")))?;
    if sats == 0 {
        return Err(TurnkeyBtcError::InvalidAmount("zero".to_string()));
    }
    Ok(Amount::from_sat(sats))
}

/// Pick the smallest UTXO that covers `needed`.
fn select_utxo(utxos: &[UtxoEntry], needed: Amount) -> Result<&UtxoEntry, TurnkeyBtcError> {
    let mut chosen: Option<&UtxoEntry> = None;
    let mut total_available: u64 = 0;
    for utxo in utxos {
        total_available = total_available.saturating_add(utxo.value.to_sat());
        if utxo.value >= needed && chosen.is_none_or(|existing| utxo.value < existing.value) {
            chosen = Some(utxo);
        }
    }
    chosen.ok_or(TurnkeyBtcError::InsufficientFunds {
        needed_sats: needed.to_sat(),
        available_sats: total_available,
    })
}

/// Inputs to [`build_p2wpkh_psbt`], grouped to stay under the positional-arg
/// limit.
struct P2wpkhSpend<'a> {
    /// The custody UTXO being spent.
    outpoint: OutPoint,
    /// Its value (BIP-143 sighash + change math).
    utxo_value: Amount,
    /// The custody P2WPKH `scriptPubKey` (input prevout + change output).
    custody_spk: &'a ScriptBuf,
    /// The `THORChain` Asgard vault (payout output).
    recipient: &'a Address,
    /// The payout amount, sats.
    recipient_value: Amount,
    /// The change amount back to custody (0 ⇒ no change output).
    change_value: Amount,
    /// The `THORChain` swap memo (`OP_RETURN`).
    memo: &'a [u8],
    /// Per-chain `OP_RETURN` byte cap.
    max_op_return: usize,
}

/// Build the unsigned single-input P2WPKH spend:
/// `[Asgard vault, OP_RETURN(memo), change→custody]`. `vin[0]` is the custody
/// UTXO so `THORChain` resolves any slip-refund back to custody.
fn build_p2wpkh_psbt(spend: &P2wpkhSpend) -> Result<Psbt, TurnkeyBtcError> {
    let &P2wpkhSpend {
        outpoint,
        utxo_value,
        custody_spk,
        recipient,
        recipient_value,
        change_value,
        memo,
        max_op_return,
    } = spend;
    if memo.len() > max_op_return {
        return Err(TurnkeyBtcError::MemoTooLong(memo.len()));
    }
    let mut outputs = vec![TxOut {
        value: recipient_value,
        script_pubkey: recipient.script_pubkey(),
    }];
    let push = bitcoin::script::PushBytesBuf::try_from(memo.to_vec())
        .map_err(|_| TurnkeyBtcError::MemoTooLong(memo.len()))?;
    outputs.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(push),
    });
    if change_value > Amount::ZERO {
        outputs.push(TxOut {
            value: change_value,
            script_pubkey: custody_spk.clone(),
        });
    }

    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: outputs,
    };

    let mut psbt =
        Psbt::from_unsigned_tx(unsigned_tx).map_err(|e| TurnkeyBtcError::Sighash(e.to_string()))?;
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: utxo_value,
        script_pubkey: custody_spk.clone(),
    });
    Ok(psbt)
}

/// Assemble the P2WPKH witness `[DER(sig)+SIGHASH_ALL, compressed_pubkey]` from
/// Turnkey's `(r, s)`. The signature is low-S normalized (BIP-62).
fn assemble_p2wpkh_witness(
    r: [u8; 32],
    s: [u8; 32],
    pubkey: &CompressedPublicKey,
) -> Result<Witness, TurnkeyBtcError> {
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(&r);
    rs[32..].copy_from_slice(&s);
    let mut sig =
        SecpSignature::from_compact(&rs).map_err(|e| TurnkeyBtcError::Signature(e.to_string()))?;
    sig.normalize_s();
    // P2WPKH witness item 0 = DER signature + the 1-byte SIGHASH_ALL flag.
    let mut sig_with_flag = sig.serialize_der().to_vec();
    sig_with_flag.push(SIGHASH_ALL_FLAG);
    let mut witness = Witness::new();
    witness.push(&sig_with_flag);
    witness.push(pubkey.to_bytes());
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoin::Network;
    use std::sync::Mutex;
    use xindex_turnkey_client::TurnkeyError;

    /// Stub Turnkey: `sign_raw_payload` returns `on_sign`; `get_activity`
    /// returns `on_get`. Records nothing else.
    struct StubTurnkey {
        on_sign: Activity,
        on_get: Activity,
    }

    impl TurnkeyApi for StubTurnkey {
        async fn sign_raw_payload(
            &self,
            _params: &SignRawPayloadParams,
        ) -> Result<Activity, TurnkeyError> {
            Ok(self.on_sign.clone())
        }
        async fn get_activity(&self, _activity_id: &str) -> Result<Activity, TurnkeyError> {
            Ok(self.on_get.clone())
        }
        async fn approve_activity(&self, _fingerprint: &str) -> Result<Activity, TurnkeyError> {
            Err(TurnkeyError::Http("stub: approve unused".into()))
        }
        async fn reject_activity(&self, _fingerprint: &str) -> Result<Activity, TurnkeyError> {
            Err(TurnkeyError::Http("stub: reject unused".into()))
        }
    }

    /// Fake UTXO chain: one spendable UTXO; records broadcasts.
    #[derive(Default)]
    struct FakeBtc {
        utxos: Mutex<Vec<UtxoEntry>>,
        broadcasts: Mutex<Vec<Transaction>>,
    }

    impl UtxoChainClient for FakeBtc {
        #[expect(clippy::expect_used, reason = "test code")]
        fn get_address_utxos(&self, _addr: &Address) -> Result<Vec<UtxoEntry>, UtxoError> {
            Ok(self.utxos.lock().expect("lock").clone())
        }
        fn get_tx_status(
            &self,
            _txid: &Txid,
        ) -> Result<xindex_chain_utxo::UtxoTxStatus, UtxoError> {
            Err(UtxoError::Upstream("unused".to_string()))
        }
        fn get_tip_height(&self) -> Result<u32, UtxoError> {
            Err(UtxoError::Upstream("unused".to_string()))
        }
        #[expect(clippy::expect_used, reason = "test code")]
        fn broadcast(&self, tx: &Transaction) -> Result<Txid, UtxoError> {
            let txid = tx.compute_txid();
            self.broadcasts.lock().expect("lock").push(tx.clone());
            Ok(txid)
        }
    }

    fn custody() -> (CompressedPublicKey, Address) {
        #[expect(clippy::expect_used, reason = "test code")]
        let sk = SecretKey::from_slice(&[7u8; 32]).expect("sk");
        let secp = Secp256k1::new();
        let pk = CompressedPublicKey(PublicKey::from_secret_key(&secp, &sk));
        let addr = Address::p2wpkh(&pk, Network::Bitcoin);
        (pk, addr)
    }

    fn config() -> TurnkeyBtcRedeemConfig {
        let (custody_pubkey, custody_address) = custody();
        TurnkeyBtcRedeemConfig {
            chain: ChainId::Btc,
            custody_address,
            custody_pubkey,
            sign_with: "custody-key".to_string(),
            fee_sats: 1_000,
            poll_interval: Duration::ZERO,
            poll_max_attempts: 5,
        }
    }

    fn task() -> RedeemTask {
        RedeemTask {
            dispatch_id: B256::repeat_byte(0xd1),
            redemption_id: B256::repeat_byte(0xd2),
            target_token: alloy_primitives::Address::ZERO,
            amount: U256::from(100_000u64),
            memo: b"=:ETH.USDT:0xrecipient:990000".to_vec(),
            intent_proof: None,
        }
    }

    fn asgard() -> Address {
        let (_pk, addr) = custody();
        addr
    }

    fn fake_btc() -> FakeBtc {
        let f = FakeBtc::default();
        #[expect(clippy::expect_used, reason = "test code")]
        let mut u = f.utxos.lock().expect("lock");
        u.push(UtxoEntry {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 0,
            value: Amount::from_sat(200_000),
            confirmations: 6,
            block_hash: None,
        });
        drop(u);
        f
    }

    /// An activity carrying a valid `(r,s)` signature result.
    fn completed_with_sig() -> Activity {
        #[expect(clippy::expect_used, reason = "test code")]
        serde_json::from_value(serde_json::json!({
            "id": "act-1", "status": "ACTIVITY_STATUS_COMPLETED",
            "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", "fingerprint": "fp-1",
            "result": { "signRawPayloadResult": {
                "r": &"11".repeat(32), "s": &"22".repeat(32), "v": "00"
            }}
        }))
        .expect("activity")
    }

    fn status_activity(status: &str) -> Activity {
        #[expect(clippy::expect_used, reason = "test code")]
        serde_json::from_value(serde_json::json!({
            "id": "act-1", "status": status,
            "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", "fingerprint": "fp-1"
        }))
        .expect("activity")
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn happy_path_prepares_signs_and_broadcasts() {
        let turnkey = Arc::new(StubTurnkey {
            on_sign: completed_with_sig(),
            on_get: completed_with_sig(),
        });
        let prepare = Arc::new(xindex_custody_core::prepare::InMemoryPrepareStore::new());
        let exec =
            TurnkeyBtcRedeemExecutor::new(config(), turnkey, fake_btc(), Arc::clone(&prepare));
        let outcome = exec.execute_leg(&task(), &asgard()).await.expect("leg");
        assert_eq!(outcome.activity_id, "act-1");
        assert_eq!(outcome.dispatch_id, B256::repeat_byte(0xd1));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn consensus_then_completed_broadcasts() {
        let turnkey = Arc::new(StubTurnkey {
            on_sign: status_activity("ACTIVITY_STATUS_CONSENSUS_NEEDED"),
            on_get: completed_with_sig(),
        });
        let prepare = Arc::new(xindex_custody_core::prepare::InMemoryPrepareStore::new());
        let exec = TurnkeyBtcRedeemExecutor::new(config(), turnkey, fake_btc(), prepare);
        let outcome = exec.execute_leg(&task(), &asgard()).await.expect("leg");
        assert_eq!(outcome.activity_id, "act-1");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rejected_activity_does_not_broadcast() {
        let chain = fake_btc();
        let turnkey = Arc::new(StubTurnkey {
            on_sign: status_activity("ACTIVITY_STATUS_CONSENSUS_NEEDED"),
            on_get: status_activity("ACTIVITY_STATUS_REJECTED"),
        });
        let prepare = Arc::new(xindex_custody_core::prepare::InMemoryPrepareStore::new());
        // Build the executor with a chain whose broadcasts we can inspect.
        let exec = TurnkeyBtcRedeemExecutor::new(config(), turnkey, chain, prepare);
        let err = exec
            .execute_leg(&task(), &asgard())
            .await
            .expect_err("rejected");
        assert!(matches!(err, TurnkeyBtcError::Rejected { .. }));
        assert!(exec.chain.broadcasts.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn insufficient_funds_rejected() {
        // The only UTXO (200k) cannot cover a 1M payout + fee.
        let turnkey = Arc::new(StubTurnkey {
            on_sign: completed_with_sig(),
            on_get: completed_with_sig(),
        });
        let prepare = Arc::new(xindex_custody_core::prepare::InMemoryPrepareStore::new());
        let exec = TurnkeyBtcRedeemExecutor::new(config(), turnkey, fake_btc(), prepare);
        let mut big = task();
        big.amount = U256::from(1_000_000u64);
        let err = exec.execute_leg(&big, &asgard()).await.expect_err("funds");
        assert!(matches!(err, TurnkeyBtcError::InsufficientFunds { .. }));
    }
}
