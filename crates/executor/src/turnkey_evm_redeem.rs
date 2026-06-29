//! EVM redeem leg under Turnkey enclave custody (`DL-CUSTODY-TURNKEY-1`).
//!
//! The Turnkey replacement for the Safe + cosigner-fleet flow
//! ([`crate::evm_redeem`]). Under Turnkey the EVM custody key is a single-sig
//! enclave key (an EOA), so a redeem leg is a single `depositWithExpiry` call
//! to the `THORChain` Router — no Safe, no k-of-n aggregation. Turnkey is a RAW
//! signer: *we* build the transaction and compute its signing hash; Turnkey
//! signs that hash via `SIGN_RAW_PAYLOAD` (gated by the approver-watcher); *we*
//! assemble the signed RLP. The flow:
//!
//! 1. Build the `Router.depositWithExpiry(vault, 0, amount, memo, expiry)`
//!    calldata (the same ABI the approver's `decide_evm_deposit` binder checks).
//! 2. Build the unsigned EIP-1559 / legacy tx (nonce + fee are caller-supplied,
//!    DL-P3.2-7 — no oracle).
//! 3. Store the prepared spend in the SHARED prepare store keyed by the signing
//!    hash hex — the approver looks it up by the activity payload and binds it
//!    to the k-of-n RIC.
//! 4. `sign_raw_payload(payload = signing_hash)` → consensus → `r,s,v`.
//! 5. Assemble the signed tx (EIP-1559 `y_parity` / EIP-155 legacy `v`) and
//!    return the raw bytes; the binary submits via `EvmChainClient::submit_raw`
//!    (mirrors [`crate::evm_redeem`], which also returns rather than submits).
//!
//! Fail-closed: a rejected/failed activity ⇒ no signature ⇒ no raw tx.

use std::sync::Arc;
use std::time::Duration;

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy::eips::eip2718::Encodable2718;
use alloy::eips::eip2930::AccessList;
use alloy_primitives::{Address, Bytes, PrimitiveSignature, TxKind, B256, U256};
use alloy_sol_types::SolCall;
use thiserror::Error;
use tracing::{debug, info};

use xindex_chain_evm::EvmTxFee;
use xindex_custody_core::prepare::{EvmPrepared, PrepareStore, PreparedSpend};
use xindex_shared::chain_registry::{ChainId, EvmTxType};
use xindex_shared::thorchain_router::depositWithExpiryCall;
use xindex_turnkey_client::{Activity, SignRawPayloadParams, TurnkeyApi};

use crate::evm_redeem::EvmRedeemTask;

/// Errors surfaced by the Turnkey EVM redeem executor.
#[derive(Debug, Error)]
pub enum TurnkeyEvmError {
    /// The task's chain is not in the EVM custody family.
    #[error("chain {0:?} is not an EVM custody chain")]
    NotEvmChain(ChainId),
    /// No `THORChain` Router address registered for this chain.
    #[error("no THORChain Router address registered for chain {0:?}")]
    NoRouterAddress(ChainId),
    /// Failed to persist the prepared spend (the approver would then fail
    /// closed, so we abort BEFORE signing).
    #[error("prepare store: {0}")]
    Prepare(String),
    /// A Turnkey API call failed.
    #[error("turnkey api: {0}")]
    Turnkey(String),
    /// The signing activity was rejected / failed — no signature, no tx.
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
}

/// Static per-executor configuration. One executor per Turnkey custody key.
#[derive(Debug, Clone)]
pub struct TurnkeyEvmRedeemConfig {
    /// The Turnkey `signWith` selector (private-key id / wallet-account
    /// address) for this custody key.
    pub sign_with: String,
    /// Seconds-from-now `depositWithExpiry` expiry (`THORChain` rejects
    /// < 60 min; 2 hours default).
    pub expiry_offset_secs: u64,
    /// Delay between activity status polls.
    pub poll_interval: Duration,
    /// Max status polls before [`TurnkeyEvmError::PollTimeout`].
    pub poll_max_attempts: u32,
}

/// Turnkey EVM redeem executor. Builds + signs (via Turnkey, gated by the
/// approver); returns the raw signed tx for the binary to broadcast.
pub struct TurnkeyEvmRedeemExecutor<T, P> {
    config: TurnkeyEvmRedeemConfig,
    turnkey: Arc<T>,
    prepare: Arc<P>,
}

impl<T, P> std::fmt::Debug for TurnkeyEvmRedeemExecutor<T, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnkeyEvmRedeemExecutor")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// The result of a completed Turnkey EVM redeem leg.
#[derive(Debug, Clone)]
pub struct TurnkeyEvmRedeemOutcome {
    /// Originating dispatch id (broadcast registry key).
    pub dispatch_id: B256,
    /// Originating redemption id (attestation correlation).
    pub redemption_id: B256,
    /// The transaction signing hash (also the prepare-store key).
    pub signing_hash: B256,
    /// The raw, signed, 2718-encoded transaction to broadcast.
    pub raw_tx: Bytes,
    /// The Turnkey signing activity id.
    pub activity_id: String,
}

/// An unsigned EVM tx, per envelope type.
enum Unsigned {
    Eip1559(Box<TxEip1559>),
    Legacy(Box<TxLegacy>),
}

impl Unsigned {
    fn signature_hash(&self) -> B256 {
        match self {
            Self::Eip1559(t) => t.signature_hash(),
            Self::Legacy(t) => t.signature_hash(),
        }
    }

    /// Attach the signature and 2718-encode to broadcastable bytes.
    fn into_raw(self, sig: PrimitiveSignature) -> Bytes {
        let envelope = match self {
            Self::Eip1559(t) => TxEnvelope::from(t.into_signed(sig)),
            Self::Legacy(t) => TxEnvelope::from(t.into_signed(sig)),
        };
        envelope.encoded_2718().into()
    }
}

impl<T: TurnkeyApi, P: PrepareStore> TurnkeyEvmRedeemExecutor<T, P> {
    /// Construct.
    #[must_use]
    pub fn new(config: TurnkeyEvmRedeemConfig, turnkey: Arc<T>, prepare: Arc<P>) -> Self {
        Self {
            config,
            turnkey,
            prepare,
        }
    }

    /// Borrow the configuration.
    #[must_use]
    pub fn config(&self) -> &TurnkeyEvmRedeemConfig {
        &self.config
    }

    /// Execute one EVM redeem leg through Turnkey: build → hash → prepare →
    /// sign (gated) → assemble the raw signed tx.
    ///
    /// `vault` is the `THORChain` Asgard vault on `task.chain` (the
    /// `depositWithExpiry` arg), resolved live by the caller. `nonce` and `fee`
    /// are caller-supplied (DL-P3.2-7).
    ///
    /// # Errors
    /// Any [`TurnkeyEvmError`] variant.
    pub async fn execute_leg(
        &self,
        task: &EvmRedeemTask,
        vault: Address,
        nonce: u64,
        fee: EvmTxFee,
    ) -> Result<TurnkeyEvmRedeemOutcome, TurnkeyEvmError> {
        let router = task
            .chain
            .thorchain_router_address()
            .ok_or(TurnkeyEvmError::NoRouterAddress(task.chain))?;
        let evm_chain_id = task
            .chain
            .evm_chain_id()
            .ok_or(TurnkeyEvmError::NotEvmChain(task.chain))?;
        let tx_type = task
            .chain
            .tx_type()
            .ok_or(TurnkeyEvmError::NotEvmChain(task.chain))?;

        let expiry = U256::from(now_secs().saturating_add(self.config.expiry_offset_secs));
        let calldata = depositWithExpiryCall {
            vault,
            asset: Address::ZERO,
            amount: task.amount_wei,
            memo: task.memo.clone(),
            expiry,
        }
        .abi_encode();

        let unsigned = build_unsigned(
            tx_type,
            evm_chain_id,
            nonce,
            &fee,
            router,
            task.amount_wei,
            calldata.clone(),
        );
        let signing_hash = unsigned.signature_hash();
        let payload_hex = format!("0x{}", alloy_primitives::hex::encode(signing_hash));

        // Persist the prepared spend keyed by the signing hash BEFORE signing —
        // the approver binds against it; a missing context fail-closes.
        // spend_identity = the account nonce (a re-drive advances it → one-shot).
        self.prepare
            .put(
                payload_hex.clone(),
                PreparedSpend::Evm(EvmPrepared {
                    chain: task.chain,
                    to: router,
                    value: task.amount_wei,
                    data: calldata,
                    ric: task.intent_proof.clone(),
                    spend_identity: nonce.to_be_bytes().to_vec(),
                }),
            )
            .await
            .map_err(|e| TurnkeyEvmError::Prepare(e.to_string()))?;

        let activity = self
            .turnkey
            .sign_raw_payload(&SignRawPayloadParams::hex_no_op(
                &self.config.sign_with,
                &payload_hex,
            ))
            .await
            .map_err(|e| TurnkeyEvmError::Turnkey(e.to_string()))?;
        let completed = self.await_signature(activity).await?;
        let result = completed
            .sign_result()
            .ok_or_else(|| TurnkeyEvmError::NoSignature {
                activity_id: completed.id.clone(),
            })?;
        let (r, s, v) = result
            .rsv()
            .map_err(|e| TurnkeyEvmError::Turnkey(e.to_string()))?;
        // Turnkey returns a recovery id (0/1); EIP-1559 uses y_parity, and the
        // legacy assembler derives the EIP-155 v from parity + chain_id.
        let sig = PrimitiveSignature::from_scalars_and_parity(B256::from(r), B256::from(s), v == 1);
        let raw_tx = unsigned.into_raw(sig);
        info!(
            redemption_id = %task.redemption_id,
            activity = %completed.id,
            "EVM redeem tx signed (Turnkey); raw tx ready to broadcast"
        );
        Ok(TurnkeyEvmRedeemOutcome {
            dispatch_id: task.dispatch_id,
            redemption_id: task.redemption_id,
            signing_hash,
            raw_tx,
            activity_id: completed.id,
        })
    }

    /// Poll the signing activity to a signature. Fail-closed on reject /
    /// failure / timeout.
    async fn await_signature(&self, activity: Activity) -> Result<Activity, TurnkeyEvmError> {
        let mut current = activity;
        for _ in 0..self.config.poll_max_attempts {
            if current.status.is_completed() {
                return Ok(current);
            }
            if current.status.is_terminal() {
                return Err(TurnkeyEvmError::Rejected {
                    activity_id: current.id,
                });
            }
            debug!(activity = %current.id, status = ?current.status, "awaiting consensus");
            tokio::time::sleep(self.config.poll_interval).await;
            current = self
                .turnkey
                .get_activity(&current.id)
                .await
                .map_err(|e| TurnkeyEvmError::Turnkey(e.to_string()))?;
        }
        Err(TurnkeyEvmError::PollTimeout {
            activity_id: current.id,
        })
    }
}

/// Build the unsigned tx for the chain's envelope type.
fn build_unsigned(
    tx_type: EvmTxType,
    evm_chain_id: u64,
    nonce: u64,
    fee: &EvmTxFee,
    router: Address,
    value: U256,
    calldata: Vec<u8>,
) -> Unsigned {
    let to = TxKind::Call(router);
    let input = Bytes::from(calldata);
    match tx_type {
        EvmTxType::Eip1559 => Unsigned::Eip1559(Box::new(TxEip1559 {
            chain_id: evm_chain_id,
            nonce,
            gas_limit: fee.gas_limit,
            max_fee_per_gas: fee.max_fee_per_gas,
            max_priority_fee_per_gas: fee.max_priority_fee_per_gas,
            to,
            value,
            access_list: AccessList::default(),
            input,
        })),
        EvmTxType::Legacy => Unsigned::Legacy(Box::new(TxLegacy {
            chain_id: Some(evm_chain_id),
            nonce,
            gas_price: fee.gas_price,
            gas_limit: fee.gas_limit,
            to,
            value,
            input,
        })),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use xindex_custody_core::prepare::InMemoryPrepareStore;
    use xindex_turnkey_client::TurnkeyError;

    struct StubTurnkey {
        on_sign: Activity,
        on_get: Activity,
        sign_calls: Mutex<u32>,
    }

    impl StubTurnkey {
        fn new(on_sign: Activity, on_get: Activity) -> Self {
            Self {
                on_sign,
                on_get,
                sign_calls: Mutex::new(0),
            }
        }
    }

    impl TurnkeyApi for StubTurnkey {
        #[expect(clippy::expect_used, reason = "test code")]
        async fn sign_raw_payload(
            &self,
            _params: &SignRawPayloadParams,
        ) -> Result<Activity, TurnkeyError> {
            *self.sign_calls.lock().expect("lock") += 1;
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

    fn config() -> TurnkeyEvmRedeemConfig {
        TurnkeyEvmRedeemConfig {
            sign_with: "custody-key".to_string(),
            expiry_offset_secs: 7_200,
            poll_interval: Duration::ZERO,
            poll_max_attempts: 5,
        }
    }

    fn task(chain: ChainId) -> EvmRedeemTask {
        EvmRedeemTask {
            dispatch_id: B256::repeat_byte(0xd1),
            redemption_id: B256::repeat_byte(0xd2),
            chain,
            memo: "=:ETH.USDT:0xrecipient:990000".to_string(),
            amount_wei: U256::from(1_000_000_000_000_000_000u64),
            intent_proof: None,
        }
    }

    fn vault() -> Address {
        Address::repeat_byte(0x11)
    }

    fn completed_with_sig() -> Activity {
        #[expect(clippy::expect_used, reason = "test code")]
        serde_json::from_value(serde_json::json!({
            "id": "act-1", "status": "ACTIVITY_STATUS_COMPLETED",
            "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", "fingerprint": "fp-1",
            "result": { "signRawPayloadResult": {
                "r": &"11".repeat(32), "s": &"22".repeat(32), "v": "01"
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

    fn fee() -> EvmTxFee {
        EvmTxFee {
            gas_limit: 300_000,
            max_fee_per_gas: 50_000_000_000,
            max_priority_fee_per_gas: 1_500_000_000,
            gas_price: 5_000_000_000,
        }
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn eip1559_happy_path_produces_raw_tx_and_prepares() {
        let turnkey = Arc::new(StubTurnkey::new(completed_with_sig(), completed_with_sig()));
        let prepare = Arc::new(InMemoryPrepareStore::new());
        let exec = TurnkeyEvmRedeemExecutor::new(config(), turnkey, Arc::clone(&prepare));
        let outcome = exec
            .execute_leg(&task(ChainId::Eth), vault(), 7, fee())
            .await
            .expect("leg");
        assert!(!outcome.raw_tx.is_empty(), "raw signed tx must be produced");
        // EIP-1559 envelope is type-0x02 (first byte).
        assert_eq!(outcome.raw_tx[0], 0x02);
        // The prepared spend is keyed by the signing hash.
        let key = format!("0x{}", alloy_primitives::hex::encode(outcome.signing_hash));
        let stored = prepare.get(&key).await.expect("get");
        assert!(matches!(stored, Some(PreparedSpend::Evm(_))));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn legacy_chain_produces_raw_tx() {
        // BSC is legacy (type-0): the raw tx is RLP, first byte ≥ 0xc0 (list).
        let turnkey = Arc::new(StubTurnkey::new(completed_with_sig(), completed_with_sig()));
        let prepare = Arc::new(InMemoryPrepareStore::new());
        let exec = TurnkeyEvmRedeemExecutor::new(config(), turnkey, prepare);
        let outcome = exec
            .execute_leg(&task(ChainId::Bsc), vault(), 0, fee())
            .await
            .expect("leg");
        assert!(!outcome.raw_tx.is_empty());
        assert!(outcome.raw_tx[0] >= 0xc0, "legacy tx is a bare RLP list");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn consensus_then_completed() {
        let turnkey = Arc::new(StubTurnkey::new(
            status_activity("ACTIVITY_STATUS_CONSENSUS_NEEDED"),
            completed_with_sig(),
        ));
        let prepare = Arc::new(InMemoryPrepareStore::new());
        let exec = TurnkeyEvmRedeemExecutor::new(config(), turnkey, prepare);
        let outcome = exec
            .execute_leg(&task(ChainId::Eth), vault(), 7, fee())
            .await
            .expect("leg");
        assert!(!outcome.raw_tx.is_empty());
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rejected_activity_yields_no_raw_tx() {
        let turnkey = Arc::new(StubTurnkey::new(
            status_activity("ACTIVITY_STATUS_CONSENSUS_NEEDED"),
            status_activity("ACTIVITY_STATUS_REJECTED"),
        ));
        let prepare = Arc::new(InMemoryPrepareStore::new());
        let exec = TurnkeyEvmRedeemExecutor::new(config(), turnkey, prepare);
        let err = exec
            .execute_leg(&task(ChainId::Eth), vault(), 7, fee())
            .await
            .expect_err("rejected");
        assert!(matches!(err, TurnkeyEvmError::Rejected { .. }));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn non_evm_chain_rejected() {
        let turnkey = Arc::new(StubTurnkey::new(completed_with_sig(), completed_with_sig()));
        let prepare = Arc::new(InMemoryPrepareStore::new());
        let exec = TurnkeyEvmRedeemExecutor::new(config(), turnkey, prepare);
        let err = exec
            .execute_leg(&task(ChainId::Btc), vault(), 0, fee())
            .await
            .expect_err("non-evm");
        assert!(matches!(
            err,
            TurnkeyEvmError::NoRouterAddress(_) | TurnkeyEvmError::NotEvmChain(_)
        ));
    }
}
