//! Mandatory key-free Bitcoin Testnet4 Vultisig lifecycle composition.
//!
//! This module is the only workspace composition root that joins strict
//! finalized-inventory authorization, the durable Vultisig connector, local
//! aggregate-signature verification, exact evidence persistence, terminal
//! connector cleanup, broadcast ambiguity handling, and configured-source
//! finality. It contains no key, share, signing, or generic raw-byte broadcast
//! interface.

use std::error::Error;
use std::fmt;

use bitcoin::consensus::deserialize;
use bitcoin::hashes::{sha256, Hash as _};
use bitcoin::{Transaction, Txid};
use xindex_chain_utxo::trusted_observer::FinalizedBitcoinTransactionObservation;
use xindex_custody_core::gates::CustodyConfig;
use xindex_custody_core::prepare::BindContext;
use xindex_custody_core::replay::ReplayStore;
use xindex_shared::chain_registry::ChainId;
use xindex_vultisig_adapter::{
    AdapterError, AuthorizedBitcoinSpend, AuthorizedVultisigBitcoinKeysign,
    VultisigBitcoinEvidenceConfig, VultisigBitcoinPolicyRuntime, VultisigVaultConfig,
};
use xindex_vultisig_connector::{
    CompletedVultisigKeysign, VultisigConnector, VultisigConnectorError,
    VultisigKeysignHandoffAcknowledgement, VultisigKeysignTerminalReceipt,
};

use crate::vultisig_broadcast::{
    DurableVultisigConnectorHandoff, PreparedVultisigBitcoinBroadcast,
    VultisigBitcoinBroadcastRuntime, VultisigBitcoinBroadcastState,
    VultisigBroadcastPreparationError, VultisigBroadcastRuntimeError,
    VultisigConnectorHandoffCandidate,
};

const DOWNSTREAM_CONSUMER_DOMAIN: &[u8] = b"XINDEX/VULTISIG/BTC-BROADCAST-RUNTIME-CONSUMER/V1";

/// One strict Bitcoin operation prepared in the connector journal before any
/// verifier or relay network request.
#[expect(
    missing_debug_implementations,
    reason = "Debug would expose the sealed request and strict finalizer"
)]
pub struct PreparedVultisigBitcoinRuntimeKeysign {
    connector: xindex_vultisig_connector::PreparedVultisigKeysign,
    finalizer: AuthorizedBitcoinSpend,
}

impl PreparedVultisigBitcoinRuntimeKeysign {
    /// Exact durable Vultisig session allocated for this operation.
    #[must_use]
    pub fn session_id(&self) -> &str {
        self.connector.session_id()
    }

    /// Strict pre-signing operation identity.
    #[must_use]
    pub fn operation_id(&self) -> Option<[u8; 32]> {
        self.connector.bitcoin_operation_id()
    }
}

/// Connector cleanup receipt plus the matching durable broadcast identity.
///
/// A `Prepared` result owns the only handle accepted by initial submission.
/// Accepted/finalized recovery results carry no misleading prepared handle.
#[expect(
    missing_debug_implementations,
    reason = "Debug is omitted from the opaque prepared broadcast handle"
)]
pub struct ReadyVultisigBitcoinBroadcast {
    prepared: Option<PreparedVultisigBitcoinBroadcast>,
    evidence_id: [u8; 32],
    txid: Txid,
    state: VultisigBitcoinBroadcastState,
    terminal_receipt: VultisigKeysignTerminalReceipt,
}

impl ReadyVultisigBitcoinBroadcast {
    /// Aggregate-evidence identity persisted before connector cleanup.
    #[must_use]
    pub const fn evidence_id(&self) -> [u8; 32] {
        self.evidence_id
    }

    /// Exact transaction ID validated by both the adapter and broadcast store.
    #[must_use]
    pub const fn txid(&self) -> Txid {
        self.txid
    }

    /// Durable broadcast lifecycle state at handoff recovery.
    #[must_use]
    pub const fn state(&self) -> VultisigBitcoinBroadcastState {
        self.state
    }

    /// Commitment-only proof that the live connector row was redacted.
    #[must_use]
    pub const fn terminal_receipt(&self) -> &VultisigKeysignTerminalReceipt {
        &self.terminal_receipt
    }
}

/// Fail-closed integrated-runtime failure.
#[derive(Debug)]
pub enum VultisigBitcoinRuntimeError {
    /// Finalized-inventory, strict transaction policy, or custody rejection.
    Authorization(AdapterError),
    /// Durable connector topology, transport, session, or cleanup failure.
    Connector(VultisigConnectorError),
    /// Evidence validation or atomic connector/broadcast persistence failure.
    BroadcastPreparation(VultisigBroadcastPreparationError),
    /// Broadcast lifecycle, reconciliation, or finality failure.
    Broadcast(VultisigBroadcastRuntimeError),
    /// A supposedly strict Bitcoin connector capability was incomplete.
    Incomplete(&'static str),
}

impl fmt::Display for VultisigBitcoinRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(error) => error.fmt(formatter),
            Self::Connector(error) => error.fmt(formatter),
            Self::BroadcastPreparation(error) => error.fmt(formatter),
            Self::Broadcast(error) => error.fmt(formatter),
            Self::Incomplete(message) => write!(
                formatter,
                "incomplete Vultisig Bitcoin runtime state: {message}"
            ),
        }
    }
}

impl Error for VultisigBitcoinRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Authorization(error) => Some(error),
            Self::Connector(error) => Some(error),
            Self::BroadcastPreparation(error) => Some(error),
            Self::Broadcast(error) => Some(error),
            Self::Incomplete(_) => None,
        }
    }
}

impl From<AdapterError> for VultisigBitcoinRuntimeError {
    fn from(error: AdapterError) -> Self {
        Self::Authorization(error)
    }
}

impl From<VultisigConnectorError> for VultisigBitcoinRuntimeError {
    fn from(error: VultisigConnectorError) -> Self {
        Self::Connector(error)
    }
}

impl From<VultisigBroadcastRuntimeError> for VultisigBitcoinRuntimeError {
    fn from(error: VultisigBroadcastRuntimeError) -> Self {
        Self::Broadcast(error)
    }
}

/// Concrete mandatory composition of policy, signing-session, persistence,
/// broadcast, recovery, and finality boundaries for Bitcoin Testnet4.
#[derive(Debug)]
pub struct VultisigBitcoinRuntime {
    policy: VultisigBitcoinPolicyRuntime,
    connector: VultisigConnector,
    broadcast: VultisigBitcoinBroadcastRuntime,
}

impl VultisigBitcoinRuntime {
    /// Bind the three independently configured, source/target-pinned runtimes.
    #[must_use]
    pub const fn new(
        policy: VultisigBitcoinPolicyRuntime,
        connector: VultisigConnector,
        broadcast: VultisigBitcoinBroadcastRuntime,
    ) -> Self {
        Self {
            policy,
            connector,
            broadcast,
        }
    }

    /// Close both durable `SQLite` pools for an orderly process restart.
    pub async fn close(self) {
        let Self {
            policy: _,
            connector,
            broadcast,
        } = self;
        connector.close().await;
        broadcast.close().await;
    }

    /// Authorize one exact PSBT and persist its sealed connector session before
    /// any verifier or relay request.
    ///
    /// The ordered permitted outpoints come only from the PSBT and are resolved
    /// through the observer-pinned finalized inventory. No caller-supplied UTXO
    /// value or signing hash is accepted.
    ///
    /// # Errors
    /// Strict policy/custody rejection, request mismatch, connector topology,
    /// randomness, or durable journal failure.
    #[expect(
        clippy::too_many_arguments,
        reason = "the single entry keeps every authorization input at one mandatory boundary"
    )]
    pub async fn authorize_and_prepare<S: ReplayStore>(
        &self,
        context: &BindContext,
        replay: &S,
        custody: CustodyConfig<'_>,
        max_fee_sats: u64,
        vault: VultisigVaultConfig,
        evidence: VultisigBitcoinEvidenceConfig,
        now_unix: i64,
    ) -> Result<PreparedVultisigBitcoinRuntimeKeysign, VultisigBitcoinRuntimeError> {
        let outpoints = context
            .psbt
            .unsigned_tx
            .input
            .iter()
            .map(|input| input.previous_output)
            .collect::<Vec<_>>();
        let policy = self.policy.issue_policy(&outpoints, max_fee_sats).await?;
        let authorized = self
            .policy
            .authorize_keysign(context, replay, custody, &policy, vault, evidence, now_unix)
            .await?;
        self.prepare_authorized(authorized).await
    }

    async fn prepare_authorized(
        &self,
        authorized: AuthorizedVultisigBitcoinKeysign,
    ) -> Result<PreparedVultisigBitcoinRuntimeKeysign, VultisigBitcoinRuntimeError> {
        let (request, finalizer) = authorized.into_parts();
        let prepared = self.connector.prepare(request).await.map_err(|failure| {
            let (_, error) = failure.into_parts();
            VultisigBitcoinRuntimeError::Connector(error)
        })?;
        Ok(PreparedVultisigBitcoinRuntimeKeysign {
            connector: prepared,
            finalizer,
        })
    }

    /// Drive one fresh durable connector session, persist the exact evidence
    /// and transaction, then atomically redact the connector live row.
    ///
    /// # Errors
    /// Any connector, local signature, strict finalization, evidence,
    /// persistence, or terminal-cleanup failure. Dropped connector capabilities
    /// remain recoverable from their journal; a committed broadcast handoff is
    /// found by completion ID on the next recovery.
    pub async fn sign_and_persist(
        &self,
        prepared: PreparedVultisigBitcoinRuntimeKeysign,
    ) -> Result<ReadyVultisigBitcoinBroadcast, VultisigBitcoinRuntimeError> {
        let PreparedVultisigBitcoinRuntimeKeysign {
            connector,
            finalizer,
        } = prepared;
        let completed = self.connector.sign(connector).await.map_err(|failure| {
            let (_, error) = failure.into_parts();
            VultisigBitcoinRuntimeError::Connector(error)
        })?;
        self.finish_with_finalizer(completed, finalizer).await
    }

    /// Recover one exact connector session without repeating an uncertain
    /// verifier or relay-start POST. If no broadcast handoff was committed,
    /// current finalized inventory and the same custody one-shot are rechecked
    /// before evidence persistence.
    ///
    /// # Errors
    /// Missing/corrupt recovery state, observation failure, current-policy
    /// drift, completion failure, persistence, or connector cleanup failure.
    pub async fn recover_and_persist<S: ReplayStore>(
        &self,
        session_id: &str,
        replay: &S,
        custody: CustodyConfig<'_>,
        now_unix: i64,
    ) -> Result<ReadyVultisigBitcoinBroadcast, VultisigBitcoinRuntimeError> {
        let pending = self.connector.recover(session_id).await?;
        let recovery =
            pending
                .bitcoin_recovery_material()?
                .ok_or(VultisigBitcoinRuntimeError::Incomplete(
                    "recovered connector session is not strict Bitcoin",
                ))?;
        let completed = self.connector.resume(pending).await.map_err(|failure| {
            let (_, error) = failure.into_parts();
            VultisigBitcoinRuntimeError::Connector(error)
        })?;
        if let Some(handoff) = self
            .broadcast
            .connector_handoff(completed.completion_id())
            .await?
        {
            return self.acknowledge_existing(completed, handoff).await;
        }
        let finalizer = self
            .policy
            .recover_authorization(&recovery, replay, custody, now_unix)
            .await?;
        self.finish_with_finalizer(completed, finalizer).await
    }

    async fn finish_with_finalizer(
        &self,
        completed: CompletedVultisigKeysign,
        finalizer: AuthorizedBitcoinSpend,
    ) -> Result<ReadyVultisigBitcoinBroadcast, VultisigBitcoinRuntimeError> {
        if let Some(handoff) = self
            .broadcast
            .connector_handoff(completed.completion_id())
            .await?
        {
            return self.acknowledge_existing(completed, handoff).await;
        }
        require_bitcoin_completion(&completed, self.connector.target_id())?;
        let session = completed.bitcoin_session_context().cloned().ok_or(
            VultisigBitcoinRuntimeError::Incomplete(
                "completed session has no reviewed Bitcoin topology",
            ),
        )?;
        let operation_id =
            completed
                .bitcoin_operation_id()
                .ok_or(VultisigBitcoinRuntimeError::Incomplete(
                    "completed session has no strict Bitcoin operation identity",
                ))?;
        let exact_bytes = completed.transaction().bytes().to_vec();
        let transaction_sha256 = sha256::Hash::hash(&exact_bytes).to_byte_array();
        let finalized = finalizer.finalize(exact_bytes).await?;
        let evidence = finalized
            .bind_vultisig_evidence(&session)
            .map_err(AdapterError::from)?;
        let connector = VultisigConnectorHandoffCandidate {
            connector_target_id: self.connector.target_id(),
            completion_id: completed.completion_id(),
            session_id: completed.receipt().session_id(),
            wire_sha256: completed.receipt().wire_sha256(),
            operation_id,
            transaction_sha256,
        };
        let (prepared, handoff) = self
            .broadcast
            .prepare_connector_handoff(evidence, connector)
            .await
            .map_err(|failure| {
                let (_, error) = failure.into_parts();
                VultisigBitcoinRuntimeError::BroadcastPreparation(error)
            })?;
        self.acknowledge(completed, handoff, Some(prepared)).await
    }

    async fn acknowledge_existing(
        &self,
        completed: CompletedVultisigKeysign,
        handoff: DurableVultisigConnectorHandoff,
    ) -> Result<ReadyVultisigBitcoinBroadcast, VultisigBitcoinRuntimeError> {
        validate_existing_handoff(&completed, self.connector.target_id(), &handoff)?;
        let prepared = if handoff.state() == VultisigBitcoinBroadcastState::Prepared {
            Some(
                self.broadcast
                    .resume_prepared(handoff.evidence_id())
                    .await?,
            )
        } else {
            None
        };
        self.acknowledge(completed, handoff, prepared).await
    }

    async fn acknowledge(
        &self,
        completed: CompletedVultisigKeysign,
        handoff: DurableVultisigConnectorHandoff,
        prepared: Option<PreparedVultisigBitcoinBroadcast>,
    ) -> Result<ReadyVultisigBitcoinBroadcast, VultisigBitcoinRuntimeError> {
        let txid = transaction_id(completed.transaction().bytes())?;
        let acknowledgement = VultisigKeysignHandoffAcknowledgement::new(
            completed.completion_id(),
            downstream_consumer_id(),
            handoff.receipt_id(),
        )?;
        let acknowledged = self
            .connector
            .acknowledge_handoff(completed, acknowledgement)
            .await
            .map_err(|failure| {
                let (_, error) = failure.into_parts();
                VultisigBitcoinRuntimeError::Connector(error)
            })?;
        Ok(ReadyVultisigBitcoinBroadcast {
            prepared,
            evidence_id: handoff.evidence_id(),
            txid,
            state: handoff.state(),
            terminal_receipt: acknowledged.terminal_receipt().clone(),
        })
    }

    /// Submit a newly prepared handoff through the sealed exact-byte target.
    /// Accepted or finalized recovery results are idempotent; a submitting row
    /// remains explicit ambiguity and must use reconciliation.
    ///
    /// # Errors
    /// Target authentication, persistence, transport, response, or ambiguous
    /// state failure.
    pub async fn submit(
        &self,
        ready: ReadyVultisigBitcoinBroadcast,
    ) -> Result<VultisigBitcoinBroadcastState, VultisigBitcoinRuntimeError> {
        match (ready.state, ready.prepared) {
            (VultisigBitcoinBroadcastState::Prepared, Some(prepared)) => {
                self.broadcast.submit(prepared).await.map_err(|failure| {
                    let (_, error) = failure.into_parts();
                    VultisigBitcoinRuntimeError::Broadcast(error)
                })
            }
            (VultisigBitcoinBroadcastState::Submitting, _) => {
                Err(VultisigBroadcastRuntimeError::AmbiguousState.into())
            }
            (
                state @ (VultisigBitcoinBroadcastState::Accepted
                | VultisigBitcoinBroadcastState::Finalized),
                _,
            ) => Ok(state),
            (VultisigBitcoinBroadcastState::Prepared, None) => {
                Err(VultisigBitcoinRuntimeError::Incomplete(
                    "prepared handoff has no durable submission handle",
                ))
            }
        }
    }

    /// List connector sessions whose recovery remains observation-only.
    ///
    /// # Errors
    /// Connector journal failure or corruption.
    pub async fn recoverable_sessions(&self) -> Result<Vec<String>, VultisigBitcoinRuntimeError> {
        Ok(self.connector.recoverable_sessions().await?)
    }

    /// Recover submission-ready integrated rows after downstream persistence
    /// and connector cleanup survived process loss.
    ///
    /// Rows whose connector cleanup has not committed are omitted because they
    /// remain reachable through [`Self::recoverable_sessions`] and
    /// [`Self::recover_and_persist`]. Standalone broadcast-library rows are
    /// never admitted into this integrated recovery path.
    ///
    /// # Errors
    /// Broadcast/connector store failure, corrupt handoff, or tombstone
    /// disagreement.
    pub async fn discover_prepared_broadcasts(
        &self,
    ) -> Result<Vec<ReadyVultisigBitcoinBroadcast>, VultisigBitcoinRuntimeError> {
        let handoffs = self
            .broadcast
            .discover_prepared_connector_handoffs()
            .await?;
        let mut recovered = Vec::with_capacity(handoffs.len());
        for handoff in handoffs {
            let Some(terminal_receipt) = self
                .connector
                .terminal_handoff(handoff.session_id())
                .await?
            else {
                continue;
            };
            validate_terminal_handoff(&terminal_receipt, &handoff)?;
            let prepared = self
                .broadcast
                .resume_prepared(handoff.evidence_id())
                .await?;
            recovered.push(ReadyVultisigBitcoinBroadcast {
                txid: prepared.txid(),
                evidence_id: handoff.evidence_id(),
                state: handoff.state(),
                prepared: Some(prepared),
                terminal_receipt,
            });
        }
        Ok(recovered)
    }

    /// Reconcile one durable ambiguous submission by exact stored bytes.
    ///
    /// # Errors
    /// Target/store failure, absence, or byte conflict.
    pub async fn reconcile(
        &self,
        evidence_id: [u8; 32],
    ) -> Result<VultisigBitcoinBroadcastState, VultisigBitcoinRuntimeError> {
        Ok(self.broadcast.reconcile(evidence_id).await?)
    }

    /// Explicitly recover one ambiguous submission. Only an authenticated 404
    /// permits the same stored bytes to be posted once.
    ///
    /// # Errors
    /// Target/store failure, conflict, or response mismatch.
    pub async fn recover_ambiguous(
        &self,
        evidence_id: [u8; 32],
    ) -> Result<VultisigBitcoinBroadcastState, VultisigBitcoinRuntimeError> {
        Ok(self.broadcast.recover_ambiguous(evidence_id).await?)
    }

    /// Consume one opaque observer finality capability and close the durable
    /// broadcast lifecycle.
    ///
    /// # Errors
    /// Source-set, exact transaction, confirmation, state, or store mismatch.
    pub async fn finalize(
        &self,
        evidence_id: [u8; 32],
        observation: FinalizedBitcoinTransactionObservation,
    ) -> Result<VultisigBitcoinBroadcastState, VultisigBitcoinRuntimeError> {
        Ok(self.broadcast.finalize(evidence_id, observation).await?)
    }
}

fn require_bitcoin_completion(
    completed: &CompletedVultisigKeysign,
    connector_target_id: [u8; 32],
) -> Result<(), VultisigBitcoinRuntimeError> {
    if connector_target_id == [0; 32]
        || completed.transaction().chain() != ChainId::Btc
        || completed.completion_id() == [0; 32]
        || completed.receipt().wire_sha256() == [0; 32]
        || completed.bitcoin_operation_id().is_none()
        || completed.bitcoin_session_context().is_none()
    {
        return Err(VultisigBitcoinRuntimeError::Incomplete(
            "connector completion is not a strict Bitcoin handoff",
        ));
    }
    Ok(())
}

fn validate_existing_handoff(
    completed: &CompletedVultisigKeysign,
    connector_target_id: [u8; 32],
    handoff: &DurableVultisigConnectorHandoff,
) -> Result<(), VultisigBitcoinRuntimeError> {
    require_bitcoin_completion(completed, connector_target_id)?;
    let transaction_sha256 = sha256::Hash::hash(completed.transaction().bytes()).to_byte_array();
    if handoff.connector_target_id() != connector_target_id
        || handoff.completion_id() != completed.completion_id()
        || handoff.session_id() != completed.receipt().session_id()
        || handoff.wire_sha256() != completed.receipt().wire_sha256()
        || Some(handoff.operation_id()) != completed.bitcoin_operation_id()
        || handoff.transaction_sha256() != transaction_sha256
    {
        return Err(VultisigBitcoinRuntimeError::Incomplete(
            "durable broadcast handoff differs from connector completion",
        ));
    }
    Ok(())
}

fn validate_terminal_handoff(
    terminal: &VultisigKeysignTerminalReceipt,
    handoff: &DurableVultisigConnectorHandoff,
) -> Result<(), VultisigBitcoinRuntimeError> {
    if terminal.session_id() != handoff.session_id()
        || terminal.completion_id() != handoff.completion_id()
        || terminal.downstream_consumer_id() != downstream_consumer_id()
        || terminal.downstream_receipt_id() != handoff.receipt_id()
    {
        return Err(VultisigBitcoinRuntimeError::Incomplete(
            "connector tombstone differs from durable broadcast handoff",
        ));
    }
    Ok(())
}

fn downstream_consumer_id() -> [u8; 32] {
    sha256::Hash::hash(DOWNSTREAM_CONSUMER_DOMAIN).to_byte_array()
}

fn transaction_id(bytes: &[u8]) -> Result<Txid, VultisigBitcoinRuntimeError> {
    let transaction = deserialize::<Transaction>(bytes).map_err(|_| {
        VultisigBitcoinRuntimeError::Incomplete(
            "locally verified connector transaction no longer decodes",
        )
    })?;
    Ok(transaction.compute_txid())
}

#[cfg(all(test, unix))]
mod tests {
    #![expect(clippy::expect_used, reason = "key-free lifecycle regression")]

    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use base64::Engine as _;
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use serde_json::json;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use xindex_chain_utxo::finalized_inventory::MIN_FINALIZED_BITCOIN_CONFIRMATIONS;
    use xindex_vultisig_adapter::test_utils::key_free_bitcoin_runtime_fixture;
    use xindex_vultisig_connector::{
        PinnedVultisigRelay, PinnedVultisigVerifier, ReviewedVultisigVerifierRelease,
        VultisigVerifierCapability,
    };

    use super::*;
    use crate::vultisig_broadcast::{
        SqliteVultisigBitcoinBroadcastStore, Testnet4EsploraBroadcastTarget,
        VultisigBitcoinFinalityPolicy,
    };

    const GENERATOR: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    static DATABASE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn private_database(label: &str) -> PathBuf {
        let suffix = DATABASE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let parent = std::env::temp_dir().join(format!(
            "xindex-vultisig-runtime-{label}-{}-{suffix}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&parent)
            .expect("private database parent");
        parent
            .canonicalize()
            .expect("canonical private database parent")
            .join("runtime.sqlite")
    }

    fn remove_database(path: &Path) {
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let candidate = PathBuf::from(format!("{}{suffix}", path.display()));
            if let Err(error) = std::fs::remove_file(&candidate) {
                assert_eq!(
                    error.kind(),
                    std::io::ErrorKind::NotFound,
                    "remove {}: {error}",
                    candidate.display()
                );
            }
        }
        std::fs::remove_dir(path.parent().expect("database parent"))
            .expect("remove private database parent");
    }

    fn fixed_signature_response() -> serde_json::Value {
        let mut message = [0u8; 32];
        message[31] = 1;
        let compact = alloy_primitives::hex::decode(
            "6673ffad2147741f04772b6f921f0ba6af0c1e77fc439e65c36dedf4092e8898\
             4c1a971652e0ada880120ef8025e709fff2080c4a39aae068d12eed009b68c89",
        )
        .expect("fixed compact signature");
        let signature = Signature::from_slice(&compact).expect("fixed signature");
        let expected = VerifyingKey::from_sec1_bytes(&GENERATOR).expect("generator key");
        let recovery_id = [0u8, 1]
            .into_iter()
            .find(|candidate| {
                RecoveryId::from_byte(*candidate).is_some_and(|recovery_id| {
                    VerifyingKey::recover_from_prehash(&message, &signature, recovery_id)
                        .is_ok_and(|recovered| recovered == expected)
                })
            })
            .expect("fixed tuple recovery ID");
        json!({
            "msg": base64::engine::general_purpose::STANDARD.encode(message),
            "r": alloy_primitives::hex::encode(&compact[..32]),
            "s": alloy_primitives::hex::encode(&compact[32..]),
            "der_signature": alloy_primitives::hex::encode(signature.to_der().as_bytes()),
            "recovery_id": format!("{recovery_id:02x}")
        })
    }

    async fn mount_successful_keysign(server: &MockServer) {
        let verifier_success = |task_id: &'static str| {
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {"task_ids": [task_id]},
                "error": {},
                "status": 200,
                "timestamp": "2026-07-21T00:00:00Z",
                "version": "1.0.0"
            }))
        };
        Mock::given(method("POST"))
            .and(path_regex(r"^/verifier-a/plugin-signer/sign$"))
            .respond_with(verifier_success("task-a"))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/verifier-b/plugin-signer/sign$"))
            .respond_with(verifier_success("task-b"))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(
                r"^/relay/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!(["verifier-b-node", "verifier-a-node"])),
            )
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(
                r"^/relay/start/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            ))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(
                r"^/relay/complete/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!(["verifier-a-node", "verifier-b-node"])),
            )
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(
                r"^/relay/complete/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/keysign$",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(fixed_signature_response()))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn open_runtime(
        policy: VultisigBitcoinPolicyRuntime,
        server: &MockServer,
        connector_database: &Path,
        broadcast_database: &Path,
    ) -> VultisigBitcoinRuntime {
        let release = ReviewedVultisigVerifierRelease::new(
            [0x31; 32],
            [0x42; 32],
            &[VultisigVerifierCapability::UpstreamHashDerivation],
        )
        .expect("reviewed test release");
        let relay = PinnedVultisigRelay::new_loopback(&format!("{}/relay", server.uri()))
            .expect("loopback relay");
        let verifiers = vec![
            PinnedVultisigVerifier::new_loopback_with_release(
                &format!("{}/verifier-a", server.uri()),
                "token-a",
                "verifier-a-",
                release,
            )
            .expect("verifier A"),
            PinnedVultisigVerifier::new_loopback_with_release(
                &format!("{}/verifier-b", server.uri()),
                "token-b",
                "verifier-b-",
                release,
            )
            .expect("verifier B"),
        ];
        let connector = VultisigConnector::open(relay, verifiers, connector_database)
            .await
            .expect("durable connector")
            .with_test_timing();
        let store = SqliteVultisigBitcoinBroadcastStore::connect(broadcast_database)
            .await
            .expect("durable broadcast store");
        let target = Testnet4EsploraBroadcastTarget::new_loopback(&format!("{}/api", server.uri()))
            .expect("loopback broadcast target");
        let finality =
            VultisigBitcoinFinalityPolicy::new([0x66; 32], MIN_FINALIZED_BITCOIN_CONFIRMATIONS)
                .expect("finality policy");
        VultisigBitcoinRuntime::new(
            policy,
            connector,
            VultisigBitcoinBroadcastRuntime::new(store, target, finality),
        )
    }

    #[tokio::test]
    async fn strict_keysign_handoff_is_submission_ready_after_restart() {
        let server = MockServer::start().await;
        mount_successful_keysign(&server).await;
        let fixture = key_free_bitcoin_runtime_fixture().await;
        let connector_database = private_database("connector");
        let broadcast_database = private_database("broadcast");
        let restart_policy = fixture.policy_runtime.clone();
        let runtime = open_runtime(
            fixture.policy_runtime,
            &server,
            &connector_database,
            &broadcast_database,
        )
        .await;

        let prepared = runtime
            .prepare_authorized(fixture.authorized)
            .await
            .expect("persist connector authorization");
        let session_id = prepared.session_id().to_string();
        let operation_id = prepared
            .operation_id()
            .expect("strict operation commitment");
        let ready = runtime
            .sign_and_persist(prepared)
            .await
            .expect("verified durable handoff");

        assert_ne!(operation_id, [0; 32]);
        assert_ne!(ready.evidence_id(), [0; 32]);
        assert_eq!(ready.state(), VultisigBitcoinBroadcastState::Prepared);
        assert_eq!(ready.terminal_receipt().session_id(), session_id);
        assert_ne!(ready.terminal_receipt().downstream_consumer_id(), [0; 32]);
        assert_ne!(ready.terminal_receipt().downstream_receipt_id(), [0; 32]);
        let evidence_id = ready.evidence_id();
        let txid = ready.txid();
        assert!(runtime
            .recoverable_sessions()
            .await
            .expect("recoverable sessions")
            .is_empty());

        drop(ready);
        runtime.close().await;
        let reopened = open_runtime(
            restart_policy,
            &server,
            &connector_database,
            &broadcast_database,
        )
        .await;
        let discovered = reopened
            .discover_prepared_broadcasts()
            .await
            .expect("restart-ready broadcast discovery");
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].evidence_id(), evidence_id);
        assert_eq!(discovered[0].txid(), txid);
        assert_eq!(discovered[0].terminal_receipt().session_id(), session_id);

        drop(discovered);
        reopened.close().await;
        remove_database(&connector_database);
        remove_database(&broadcast_database);
    }
}
