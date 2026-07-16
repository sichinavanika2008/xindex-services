//! Fail-closed orchestration around the irreversible provider send boundary.

use std::fmt;
use std::str::FromStr;

use alloy_primitives::B256;
use bitcoin::hashes::Hash as _;
use bitcoin::Txid;
use serde::Serialize;
use xindex_bitgo_adapter::{
    send_request, spend_policy_commitment, validate_final_transaction, PolicyError, SpendPolicy,
};
use xindex_custody_core::btc_authorize::{
    authorize_btc_spend, BtcCertificateSubject, BtcSpendAuthorization,
};
use xindex_custody_core::gates::CustodyConfig;
use xindex_custody_core::prepare::BindContext;
use xindex_custody_core::replay::ReplayStore;
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::IntentProof;

use crate::{
    ApprovalSnapshot, BitGoClient, BitGoClientError, BitGoWorkflowStore, BuildReservation,
    EvidenceError, EvidenceManifest, ProviderSendOutcome, SendReservation, TransferSnapshot,
    TransferState, WorkflowError, WorkflowPhase, WorkflowRecord,
};

/// Redacted coordinator failure.
#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    /// Bounded provider transport or response validation failed.
    #[error(transparent)]
    Client(#[from] BitGoClientError),
    /// Durable workflow validation or persistence failed.
    #[error(transparent)]
    Workflow(#[from] WorkflowError),
    /// Provider-independent transaction policy rejected an artifact.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// A locally generated request could not be encoded for byte comparison.
    #[error("BitGo coordinator request encoding failed")]
    Encoding,
    /// Provider-neutral intent verification or one-shot consumption rejected.
    #[error("custody intent gate rejected BitGo spend: {code}: {message}")]
    CustodyRejected {
        /// Stable custody-gate rejection code.
        code: &'static str,
        /// Redacted operator-facing rejection detail.
        message: String,
    },
    /// A successful custody gate returned a receipt outside the BTC/RIC profile.
    #[error("custody intent gate returned an invalid BitGo authorization receipt")]
    InvalidCustodyReceipt,
}

/// Result of crossing, or safely refusing to re-cross, the send boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// A fully validated final transaction is durably retained.
    Broadcast {
        /// Provider transfer identifier.
        transfer_id: String,
        /// Exact Bitcoin transaction ID.
        txid: Txid,
        /// `true` only for the call that persisted the provider response.
        newly_recorded: bool,
    },
    /// The provider accepted the send but requires approval.
    PendingApproval {
        /// Provider pending-approval identifier.
        approval_id: String,
        /// `true` only for the call that persisted the `202` response.
        newly_recorded: bool,
    },
    /// An independent approver rejected the transaction.
    Rejected {
        /// Provider pending-approval identifier.
        approval_id: String,
        /// `true` only for the call that persisted the terminal transition.
        newly_recorded: bool,
    },
    /// A prior send reservation exists, so the coordinator performed only a
    /// read-only sequence lookup and deliberately refused to send again.
    ReconciliationRequired {
        /// Durable phase that prohibited another send.
        phase: WorkflowPhase,
        /// Provider transfer returned by the exact sequence-ID lookup.
        transfer: TransferSnapshot,
    },
}

/// The only component allowed to call `BitGo`'s final-sign-and-broadcast API.
///
/// It reserves the irreversible boundary in `SQLite` first. Any retry after
/// that reservation performs a read-only sequence lookup and never posts the
/// half-signed transaction again.
#[derive(Clone)]
pub struct BitGoCoordinator {
    client: BitGoClient,
    store: BitGoWorkflowStore,
}

impl fmt::Debug for BitGoCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitGoCoordinator")
            .field("client", &self.client)
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl BitGoCoordinator {
    /// Bind one redacted transport to one durable workflow store.
    #[must_use]
    pub const fn new(client: BitGoClient, store: BitGoWorkflowStore) -> Self {
        Self { client, store }
    }

    /// Build the canonical manifest using the environment and HMAC version
    /// pinned by this coordinator's transport.
    ///
    /// # Errors
    /// Policy mismatch, corrupt durable artifacts, or database failure.
    pub async fn evidence_manifest(
        &self,
        policy: &SpendPolicy,
    ) -> Result<EvidenceManifest, EvidenceError> {
        self.store
            .evidence_manifest(
                self.client.environment(),
                self.client.auth_version(),
                policy,
            )
            .await
    }

    /// Reserve the immutable policy, build once when needed, validate the
    /// provider PSBT, and retain the exact response before returning it.
    ///
    /// Identical calls after `Built` return stored state without provider I/O.
    /// A crash in `BuildReserved` may safely retry the non-signing build call.
    ///
    /// # Errors
    /// Policy conflict, provider failure, invalid PSBT, or persistence failure.
    pub async fn build(&self, policy: &SpendPolicy) -> Result<WorkflowRecord, CoordinatorError> {
        match self.store.reserve_build(policy).await? {
            BuildReservation::Created
            | BuildReservation::Existing(WorkflowPhase::BuildReserved) => {
                let wallet_response = self.client.wallet(policy.wallet()).await?;
                let (snapshot, raw_wallet_response) = wallet_response.into_evidence_parts();
                self.store
                    .record_wallet(policy, &snapshot, &raw_wallet_response)
                    .await?;
                let response = self.client.build_transaction(policy).await?;
                let (capture, raw_response) = response.into_evidence_parts();
                self.store
                    .complete_build(policy, &capture, &raw_response)
                    .await?;
            }
            BuildReservation::Existing(_) => {}
        }
        self.store
            .load(policy.sequence_id())
            .await
            .map_err(Into::into)
    }

    /// Verify the exact stored PSBT against a k-of-n redemption-intent
    /// certificate, consume the existing `(BTC, redemption, leg)` replay
    /// one-shot, and durably bind the resulting receipt to this workflow.
    ///
    /// The non-signing provider build occurs first. The one-shot is consumed
    /// before the workflow becomes `IntentAuthorized`; a crash between those
    /// stores is recoverable because the same certificate and unsigned txid are
    /// idempotent in the replay store. User-signature capture remains blocked
    /// until this method completes.
    ///
    /// # Errors
    /// Missing/unsafe workflow state, invalid or stale RIC, output mismatch,
    /// one-shot conflict, corrupt receipt, or persistence failure.
    pub async fn authorize_redeem<S: ReplayStore>(
        &self,
        policy: &SpendPolicy,
        intent_proof: &IntentProof,
        replay: &S,
        config: CustodyConfig<'_>,
        now_unix: i64,
    ) -> Result<WorkflowRecord, CoordinatorError> {
        let record = self.store.load_for_policy(policy).await?;
        match record.phase() {
            WorkflowPhase::Built => {}
            WorkflowPhase::IntentAuthorized
            | WorkflowPhase::UserSigned
            | WorkflowPhase::SendReserved
            | WorkflowPhase::PendingApproval
            | WorkflowPhase::Rejected
            | WorkflowPhase::Broadcast => return Ok(record),
            phase @ WorkflowPhase::BuildReserved => {
                return Err(WorkflowError::InvalidTransition { phase }.into())
            }
        }
        let psbt = record.unsigned_psbt()?.ok_or(WorkflowError::CorruptState)?;
        let context = BindContext {
            chain: ChainId::Btc,
            psbt,
            ric: Some(intent_proof.clone()),
            acc: None,
        };
        let authorization = authorize_btc_spend(
            &context,
            replay,
            config,
            policy.wallet().custody_script_pubkey(),
            now_unix,
        )
        .await
        .map_err(|rejection| CoordinatorError::CustodyRejected {
            code: rejection.code,
            message: rejection.message,
        })?;
        let receipt = canonical_intent_authorization(policy, intent_proof, config, &authorization)?;
        self.store
            .record_intent_authorization(
                policy,
                Txid::from_byte_array(authorization.spend_txid()),
                authorization.valid_until_unix(),
                &receipt,
            )
            .await?;
        self.store
            .load(policy.sequence_id())
            .await
            .map_err(Into::into)
    }

    /// Revalidate and durably retain one exact user-signed transaction.
    /// No provider call occurs.
    ///
    /// # Errors
    /// Missing/corrupt build, invalid signature, policy conflict, or storage failure.
    pub async fn record_user_signed(
        &self,
        policy: &SpendPolicy,
        half_signed: &bitcoin::Transaction,
    ) -> Result<WorkflowRecord, CoordinatorError> {
        let record = self.store.load(policy.sequence_id()).await?;
        let unsigned = record.unsigned_psbt()?.ok_or(WorkflowError::CorruptState)?;
        self.store
            .record_user_signed(policy, &unsigned, half_signed)
            .await?;
        self.store
            .load(policy.sequence_id())
            .await
            .map_err(Into::into)
    }

    /// Atomically reserve and perform at most one provider send. Later calls
    /// reconcile by sequence ID and cannot post the transaction again.
    ///
    /// # Errors
    /// Unsafe phase/policy, corrupt stored artifact, provider failure, invalid
    /// final transaction, or persistence failure.
    pub async fn submit(&self, policy: &SpendPolicy) -> Result<SubmitOutcome, CoordinatorError> {
        match self.store.reserve_send(policy).await? {
            SendReservation::Acquired => self.submit_reserved(policy).await,
            SendReservation::Existing(WorkflowPhase::Broadcast) => {
                self.validated_stored_broadcast(policy).await
            }
            SendReservation::Existing(WorkflowPhase::Rejected) => {
                self.validated_stored_rejection(policy).await
            }
            SendReservation::Existing(phase) => self.reconcile_reserved(policy, phase).await,
        }
    }

    async fn submit_reserved(
        &self,
        policy: &SpendPolicy,
    ) -> Result<SubmitOutcome, CoordinatorError> {
        let record = self.store.load(policy.sequence_id()).await?;
        if record.phase() != WorkflowPhase::SendReserved {
            return Err(WorkflowError::InvalidTransition {
                phase: record.phase(),
            }
            .into());
        }
        let unsigned = record.unsigned_psbt()?.ok_or(WorkflowError::CorruptState)?;
        let half_signed = record
            .half_signed_transaction()?
            .ok_or(WorkflowError::CorruptState)?;
        let request = send_request(&unsigned, &half_signed, policy)?;
        let encoded = serde_json::to_vec(&request).map_err(|_| CoordinatorError::Encoding)?;
        if record.send_request_bytes() != Some(encoded.as_slice()) {
            return Err(WorkflowError::CorruptState.into());
        }

        let response = self.client.send_transaction(policy, &request).await?;
        let (outcome, raw_response) = response.into_evidence_parts();
        match outcome {
            ProviderSendOutcome::Broadcast {
                transfer_id,
                txid,
                transaction,
            } => {
                self.store
                    .record_broadcast(policy, &transfer_id, txid, &transaction, &raw_response)
                    .await?;
                Ok(SubmitOutcome::Broadcast {
                    transfer_id,
                    txid,
                    newly_recorded: true,
                })
            }
            ProviderSendOutcome::PendingApproval { approval_id } => {
                self.store
                    .record_pending_approval(policy, &approval_id, &raw_response)
                    .await?;
                Ok(SubmitOutcome::PendingApproval {
                    approval_id,
                    newly_recorded: true,
                })
            }
        }
    }

    async fn reconcile_reserved(
        &self,
        policy: &SpendPolicy,
        phase: WorkflowPhase,
    ) -> Result<SubmitOutcome, CoordinatorError> {
        if phase == WorkflowPhase::PendingApproval {
            return self.reconcile_pending_approval(policy).await;
        }
        let response = self.client.transfer_by_sequence_id(policy).await?;
        let (transfer, raw_response) = response.into_evidence_parts();
        self.store
            .record_transfer_lookup(policy, &raw_response)
            .await?;
        Ok(SubmitOutcome::ReconciliationRequired { phase, transfer })
    }

    async fn reconcile_pending_approval(
        &self,
        policy: &SpendPolicy,
    ) -> Result<SubmitOutcome, CoordinatorError> {
        let record = self.store.load(policy.sequence_id()).await?;
        let approval_id = record
            .pending_approval_id()
            .ok_or(WorkflowError::CorruptState)?
            .to_owned();
        let response = self.client.pending_approval(policy, &approval_id).await?;
        let (approval, raw_approval) = response.into_evidence_parts();
        match approval {
            ApprovalSnapshot::Pending { .. } => {
                self.store
                    .record_approval_lookup(policy, &approval_id, &raw_approval)
                    .await?;
                Ok(SubmitOutcome::PendingApproval {
                    approval_id,
                    newly_recorded: false,
                })
            }
            ApprovalSnapshot::Rejected { .. } => {
                self.store
                    .record_approval_rejected(policy, &approval_id, &raw_approval)
                    .await?;
                Ok(SubmitOutcome::Rejected {
                    approval_id,
                    newly_recorded: true,
                })
            }
            ApprovalSnapshot::Approved {
                txid, transaction, ..
            } => {
                self.store
                    .record_approval_lookup(policy, &approval_id, &raw_approval)
                    .await?;
                let response = self
                    .client
                    .transfer_by_approval_id(policy, &approval_id)
                    .await?;
                let (transfer, raw_transfer) = response.into_evidence_parts();
                self.store
                    .record_approval_transfer_lookup(policy, &approval_id, &raw_transfer)
                    .await?;
                if !matches!(
                    transfer.state(),
                    TransferState::Signed | TransferState::Unconfirmed | TransferState::Confirmed
                ) || transfer.txid().and_then(|value| Txid::from_str(value).ok()) != Some(txid)
                {
                    return Err(BitGoClientError::InvalidResponse {
                        field: "approval.transfer",
                    }
                    .into());
                }
                let transfer_id = transfer.transfer_id().to_owned();
                self.store
                    .record_approved_broadcast(policy, &transfer_id, txid, &transaction)
                    .await?;
                Ok(SubmitOutcome::Broadcast {
                    transfer_id,
                    txid,
                    newly_recorded: true,
                })
            }
        }
    }

    async fn validated_stored_broadcast(
        &self,
        policy: &SpendPolicy,
    ) -> Result<SubmitOutcome, CoordinatorError> {
        let record = self.store.load(policy.sequence_id()).await?;
        let unsigned = record.unsigned_psbt()?.ok_or(WorkflowError::CorruptState)?;
        let transaction = record
            .final_transaction()?
            .ok_or(WorkflowError::CorruptState)?;
        let txid = record.txid().ok_or(WorkflowError::CorruptState)?;
        validate_final_transaction(&unsigned, &transaction, txid, policy)?;
        let transfer_id = record
            .transfer_id()
            .ok_or(WorkflowError::CorruptState)?
            .to_owned();
        Ok(SubmitOutcome::Broadcast {
            transfer_id,
            txid,
            newly_recorded: false,
        })
    }

    async fn validated_stored_rejection(
        &self,
        policy: &SpendPolicy,
    ) -> Result<SubmitOutcome, CoordinatorError> {
        let record = self.store.load(policy.sequence_id()).await?;
        if record.phase() != WorkflowPhase::Rejected {
            return Err(WorkflowError::InvalidTransition {
                phase: record.phase(),
            }
            .into());
        }
        let approval_id = record
            .pending_approval_id()
            .ok_or(WorkflowError::CorruptState)?
            .to_owned();
        Ok(SubmitOutcome::Rejected {
            approval_id,
            newly_recorded: false,
        })
    }
}

#[derive(Serialize)]
struct CanonicalIntentVerifier {
    ethereum_chain_id: u64,
    verifying_contract: String,
    intent_quorum: usize,
    ric_max_age_secs: u64,
    signer_whitelist: Vec<String>,
}

#[derive(Serialize)]
struct CanonicalIntentAuthorization<'a> {
    schema_version: u32,
    native_chain: &'static str,
    sequence_id: &'a str,
    policy_commitment: String,
    redemption_id: String,
    leg_index: u32,
    certificate_digest: String,
    unsigned_txid: String,
    valid_until_unix: u64,
    verifier: CanonicalIntentVerifier,
    verified_signers: Vec<String>,
    intent_proof: &'a IntentProof,
}

fn canonical_intent_authorization(
    policy: &SpendPolicy,
    intent_proof: &IntentProof,
    config: CustodyConfig<'_>,
    authorization: &BtcSpendAuthorization,
) -> Result<Vec<u8>, CoordinatorError> {
    if authorization.chain() != ChainId::Btc {
        return Err(CoordinatorError::InvalidCustodyReceipt);
    }
    let (redemption_id, leg_index) = match authorization.subject() {
        BtcCertificateSubject::Redemption {
            redemption_id,
            leg_index,
        } => (*redemption_id, *leg_index),
        BtcCertificateSubject::AcquireCancel { .. } => {
            return Err(CoordinatorError::InvalidCustodyReceipt)
        }
    };
    let mut signer_whitelist = config
        .intent_policy
        .signer_whitelist
        .iter()
        .map(|address| format!("{address:#x}"))
        .collect::<Vec<_>>();
    signer_whitelist.sort_unstable();
    let mut verified_signers = authorization
        .verified_signers()
        .iter()
        .map(|address| format!("{address:#x}"))
        .collect::<Vec<_>>();
    verified_signers.sort_unstable();
    let artifact = CanonicalIntentAuthorization {
        schema_version: 1,
        native_chain: "btc",
        sequence_id: policy.sequence_id(),
        policy_commitment: hex_b256(spend_policy_commitment(policy)),
        redemption_id: hex_b256(redemption_id),
        leg_index,
        certificate_digest: hex_b256(authorization.certificate_digest()),
        unsigned_txid: Txid::from_byte_array(authorization.spend_txid()).to_string(),
        valid_until_unix: authorization.valid_until_unix(),
        verifier: CanonicalIntentVerifier {
            ethereum_chain_id: config.chain_id,
            verifying_contract: format!("{:#x}", config.verifying_contract),
            intent_quorum: config.intent_policy.intent_quorum,
            ric_max_age_secs: config.intent_policy.ric_max_age_secs,
            signer_whitelist,
        },
        verified_signers,
        intent_proof,
    };
    serde_json::to_vec(&artifact).map_err(|_| CoordinatorError::Encoding)
}

fn hex_b256(value: B256) -> String {
    format!("{value:#x}")
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test assertions and fixtures")]

    use std::str::FromStr;
    use std::time::Duration;

    use alloy_primitives::Address as EvmAddress;
    use bitcoin::hashes::Hash as _;
    use bitcoin::opcodes::all::OP_CHECKMULTISIG;
    use bitcoin::script::Builder;
    use bitcoin::{
        absolute::LockTime, psbt::Psbt, transaction::Version, Address, Amount, OutPoint, ScriptBuf,
        Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer};
    use xindex_bitgo_adapter::{
        build_request, parse_compressed_public_key, BitGoCoin, InputPolicy, SpendPolicy,
        WalletPolicy, P2WSH_EXTERNAL_CHAIN_CODE,
    };
    use xindex_custody_core::gates::CustodyConfig;
    use xindex_custody_core::replay::InMemoryReplayStore;
    use xindex_ops::network::HttpClientPolicy;
    use xindex_shared::chain_registry::ChainId;
    use xindex_shared::intent::IntentPolicy;
    use xindex_shared::signer_wire::IntentProof;

    use super::{BitGoCoordinator, CoordinatorError, SubmitOutcome};
    use crate::{
        BitGoClient, BitGoEnvironment, BitGoWorkflowStore, WorkflowError, WorkflowPhase,
        OFFICIAL_FINAL_TX, OFFICIAL_FINAL_TXID,
    };

    const USER_PUBKEY: &str = "03c10ac628c880629ed0fd2a0563a898f4882baca45e15668a4d3064cf1ea37988";
    const BACKUP_PUBKEY: &str =
        "03e56f84be4460080618ef869bb7b07096880760f748ba23efab533c2359f923bd";
    const BITGO_PUBKEY: &str = "020ae81372264b5eac5c9dc7fe0b9a32bad00771c3a2c71f6e2c971823c3182ed6";

    fn policy() -> SpendPolicy {
        let user = parse_compressed_public_key(USER_PUBKEY).expect("user key");
        let backup = parse_compressed_public_key(BACKUP_PUBKEY).expect("backup key");
        let bitgo = parse_compressed_public_key(BITGO_PUBKEY).expect("BitGo key");
        let witness_script = Builder::new()
            .push_int(2)
            .push_key(&user)
            .push_key(&backup)
            .push_key(&bitgo)
            .push_int(3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        let wallet = WalletPolicy::new(
            BitGoCoin::Tbtc4,
            "wallet-1",
            P2WSH_EXTERNAL_CHAIN_CODE,
            user,
            backup,
            bitgo,
            witness_script,
        )
        .expect("wallet policy");
        let input = InputPolicy::new(
            OutPoint {
                txid: Txid::from_byte_array([0x22; 32]),
                vout: 0,
            },
            200_000,
        )
        .expect("input policy");
        SpendPolicy::new(
            wallet,
            input,
            ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0xaa; 20])),
            100_000,
            b"=:ETH.USDT:0xrecipient:990000".to_vec(),
            20_000,
            "xindex-redemption-1",
            true,
        )
        .expect("spend policy")
    }

    fn unsigned_psbt(policy: &SpendPolicy) -> Psbt {
        let request = build_request(policy).expect("build request");
        let payout = Address::from_str(&request.recipients[0].address)
            .expect("payout address")
            .require_network(policy.wallet().coin().network())
            .expect("payout network")
            .script_pubkey();
        let memo = ScriptBuf::from_bytes(
            alloy_primitives::hex::decode(
                request.recipients[1]
                    .address
                    .strip_prefix("scriptPubKey:")
                    .expect("memo prefix"),
            )
            .expect("memo script"),
        );
        let transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: policy.input().outpoint(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: payout,
                },
                TxOut {
                    value: Amount::from_sat(89_000),
                    script_pubkey: policy.wallet().custody_script_pubkey().clone(),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: memo,
                },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(transaction).expect("PSBT");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(policy.input().value_sats()),
            script_pubkey: policy.wallet().custody_script_pubkey().clone(),
        });
        psbt.inputs[0].witness_script = Some(policy.wallet().witness_script().clone());
        psbt
    }

    fn client(server: &MockServer) -> BitGoClient {
        BitGoClient::new_for_test(
            BitGoEnvironment::Test,
            &server.uri(),
            "test-token",
            HttpClientPolicy {
                connect_timeout: Duration::from_secs(1),
                request_timeout: Duration::from_secs(3),
                max_response_bytes: 64 * 1024,
            },
        )
        .expect("client")
    }

    async fn build_mock(server: &MockServer, psbt: &Psbt) {
        Mock::given(method("GET"))
            .and(path("/api/v2/tbtc4/wallet/wallet-1"))
            .and(header(
                "authorization",
                crate::test_support::test_authorization(),
            ))
            .and(header("bitgo-auth-version", "2.0"))
            .respond_with(crate::test_support::signed_json_response(
                200,
                json!({
                    "id": "wallet-1",
                    "coin": "tbtc4",
                    "type": "hot",
                    "multisigType": "onchain",
                    "m": 2,
                    "n": 3,
                    "keys": ["user-key", "backup-key", "bitgo-key"]
                }),
            ))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v2/tbtc4/wallet/wallet-1/tx/build"))
            .and(header(
                "authorization",
                crate::test_support::test_authorization(),
            ))
            .and(header("bitgo-auth-version", "2.0"))
            .respond_with(crate::test_support::signed_json_response(
                200,
                json!({
                    "txHex": alloy_primitives::hex::encode(psbt.serialize())
                }),
            ))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn coordinator_at_pending(
        server: &MockServer,
    ) -> (BitGoCoordinator, BitGoWorkflowStore, SpendPolicy) {
        let policy = policy();
        let psbt = unsigned_psbt(&policy);
        build_mock(server, &psbt).await;
        let store = BitGoWorkflowStore::in_memory().await.expect("store");
        let coordinator = BitGoCoordinator::new(client(server), store.clone());
        coordinator.build(&policy).await.expect("build");
        store
            .record_user_signed_fixture(&policy, &psbt)
            .await
            .expect("user-signed fixture");
        store.reserve_send(&policy).await.expect("reserve send");
        store
            .record_pending_approval(&policy, "approval-1", br#"{"state":"pending"}"#)
            .await
            .expect("pending approval");
        (coordinator, store, policy)
    }

    #[tokio::test]
    async fn completed_build_is_reused_without_another_provider_post() {
        let server = MockServer::start().await;
        let policy = policy();
        let psbt = unsigned_psbt(&policy);
        build_mock(&server, &psbt).await;
        let store = BitGoWorkflowStore::in_memory().await.expect("store");
        let coordinator = BitGoCoordinator::new(client(&server), store);

        let first = coordinator.build(&policy).await.expect("first build");
        let second = coordinator.build(&policy).await.expect("stored build");

        assert_eq!(first.phase(), WorkflowPhase::Built);
        assert_eq!(second.phase(), WorkflowPhase::Built);
        assert_eq!(second.unsigned_psbt().expect("decode"), Some(psbt));
        server.verify().await;
    }

    #[tokio::test]
    async fn invalid_intent_never_authorizes_the_built_workflow() {
        let server = MockServer::start().await;
        let policy = policy();
        let psbt = unsigned_psbt(&policy);
        build_mock(&server, &psbt).await;
        let store = BitGoWorkflowStore::in_memory().await.expect("store");
        let coordinator = BitGoCoordinator::new(client(&server), store.clone());
        coordinator.build(&policy).await.expect("build");
        let intent_policy = IntentPolicy {
            signer_whitelist: vec![EvmAddress::repeat_byte(0x11)],
            intent_quorum: 1,
            ric_max_age_secs: 3_600,
        };
        let proof = IntentProof {
            redemption_id: format!("{:#x}", alloy_primitives::B256::repeat_byte(0x21)),
            leg_index: "0".to_owned(),
            asset_id: format!("{:#x}", ChainId::Btc.asset_id_hash()),
            amount: "100000".to_owned(),
            amount_decimals: ChainId::Btc.decimals(),
            immediate_target_hash: format!("{:#x}", alloy_primitives::B256::repeat_byte(0x22)),
            memo_hash: format!("{:#x}", alloy_primitives::B256::repeat_byte(0x23)),
            final_destination_hash: format!("{:#x}", alloy_primitives::B256::repeat_byte(0x24)),
            vault_resolved_at: 1_750_000_000,
            signatures: Vec::new(),
        };
        let replay = InMemoryReplayStore::new();
        let result = coordinator
            .authorize_redeem(
                &policy,
                &proof,
                &replay,
                CustodyConfig {
                    chain_id: 1,
                    verifying_contract: EvmAddress::repeat_byte(0x42),
                    intent_policy: &intent_policy,
                },
                1_750_000_000,
            )
            .await;

        assert!(matches!(
            result,
            Err(CoordinatorError::CustodyRejected { .. })
        ));
        assert_eq!(
            store
                .load(policy.sequence_id())
                .await
                .expect("workflow")
                .phase(),
            WorkflowPhase::Built
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn synthetic_signature_fails_before_provider_send() {
        let server = MockServer::start().await;
        let policy = policy();
        let psbt = unsigned_psbt(&policy);
        build_mock(&server, &psbt).await;
        let store = BitGoWorkflowStore::in_memory().await.expect("store");
        let coordinator = BitGoCoordinator::new(client(&server), store.clone());
        coordinator.build(&policy).await.expect("build");

        let mut synthetic = psbt.unsigned_tx.clone();
        synthetic.input[0].witness = Witness::from_slice(&[b"synthetic-public-witness"]);
        let signed = coordinator.record_user_signed(&policy, &synthetic).await;
        assert!(matches!(signed, Err(CoordinatorError::Workflow(_))));
        assert_eq!(
            store
                .load(policy.sequence_id())
                .await
                .expect("workflow")
                .phase(),
            WorkflowPhase::Built
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn pending_approval_reconciliation_is_read_only() {
        let server = MockServer::start().await;
        let (coordinator, store, policy) = coordinator_at_pending(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/v2/pendingapprovals/approval-1"))
            .and(header(
                "authorization",
                crate::test_support::test_authorization(),
            ))
            .respond_with(crate::test_support::signed_json_response(
                200,
                json!({
                    "id": "approval-1",
                    "coin": "tbtc4",
                    "wallet": "wallet-1",
                    "info": {
                        "type": "transactionRequest",
                        "transactionRequest": { "sourceWallet": "wallet-1" }
                    },
                    "state": "pending"
                }),
            ))
            .expect(1)
            .mount(&server)
            .await;

        assert!(matches!(
            coordinator.submit(&policy).await,
            Ok(SubmitOutcome::PendingApproval {
                approval_id,
                newly_recorded: false
            }) if approval_id == "approval-1"
        ));
        assert_eq!(
            store
                .load(policy.sequence_id())
                .await
                .expect("workflow")
                .phase(),
            WorkflowPhase::PendingApproval
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn rejected_approval_is_terminal_without_a_second_provider_call() {
        let server = MockServer::start().await;
        let (coordinator, store, policy) = coordinator_at_pending(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/v2/pendingapprovals/approval-1"))
            .respond_with(crate::test_support::signed_json_response(
                200,
                json!({
                    "id": "approval-1",
                    "coin": "tbtc4",
                    "wallet": "wallet-1",
                    "info": {
                        "type": "transactionRequest",
                        "transactionRequest": { "sourceWallet": "wallet-1" }
                    },
                    "state": "rejected"
                }),
            ))
            .expect(1)
            .mount(&server)
            .await;

        assert!(matches!(
            coordinator.submit(&policy).await,
            Ok(SubmitOutcome::Rejected {
                approval_id,
                newly_recorded: true
            }) if approval_id == "approval-1"
        ));
        assert!(matches!(
            coordinator.submit(&policy).await,
            Ok(SubmitOutcome::Rejected {
                approval_id,
                newly_recorded: false
            }) if approval_id == "approval-1"
        ));
        assert_eq!(
            store
                .load(policy.sequence_id())
                .await
                .expect("workflow")
                .phase(),
            WorkflowPhase::Rejected
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn approved_rebuild_must_still_match_the_original_exact_policy() {
        let server = MockServer::start().await;
        let (coordinator, store, policy) = coordinator_at_pending(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/v2/pendingapprovals/approval-1"))
            .respond_with(crate::test_support::signed_json_response(
                200,
                json!({
                    "id": "approval-1",
                    "coin": "tbtc4",
                    "wallet": "wallet-1",
                    "info": {
                        "type": "transactionRequest",
                        "transactionRequest": {
                            "sourceWallet": "wallet-1",
                            "validTransaction": OFFICIAL_FINAL_TX,
                            "validTransactionHash": OFFICIAL_FINAL_TXID
                        }
                    },
                    "state": "approved"
                }),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v2/pendingapprovals/approval-1/transfer"))
            .respond_with(crate::test_support::signed_json_response(
                200,
                json!({
                    "transfer": {
                        "id": "transfer-1",
                        "coin": "tbtc4",
                        "wallet": "wallet-1",
                        "state": "signed",
                        "sequenceId": "xindex-redemption-1",
                        "pendingApproval": "approval-1",
                        "txid": OFFICIAL_FINAL_TXID
                    }
                }),
            ))
            .expect(1)
            .mount(&server)
            .await;

        assert!(matches!(
            coordinator.submit(&policy).await,
            Err(CoordinatorError::Workflow(WorkflowError::Policy(_)))
        ));
        assert_eq!(
            store
                .load(policy.sequence_id())
                .await
                .expect("workflow")
                .phase(),
            WorkflowPhase::PendingApproval
        );
        server.verify().await;
    }
}
