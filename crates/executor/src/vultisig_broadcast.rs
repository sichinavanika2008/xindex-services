//! Key-free, target-bound Vultisig Bitcoin broadcast runtime.
//!
//! [`VultisigBitcoinBroadcastRuntime::prepare`] consumes
//! [`VultisigBitcoinEvidence`], repeats the exact
//! Testnet4/canonical-byte/txid/wtxid checks, and durably persists the complete
//! serialized evidence record plus exact canonical bytes in a target-bound
//! `SQLite` row before returning an opaque, non-cloneable capability. The same
//! sealed runtime is the only network path: it consumes that durable capability
//! and submits lower hex generated directly from the persisted bytes.
//!
//! The evidence record intentionally carries the signed transaction bytes for
//! audit. Rust types cannot make those bytes globally non-copyable or make the
//! wider system non-bypassable. The enforced boundary here is narrower: the
//! concrete runtime has no public raw-byte submission method, does not use a
//! generic UTXO client or parsed-transaction broadcast API, and never rebuilds
//! a transaction. `submitting` is a durable ambiguous state; it is never reset
//! to `prepared` after a possible network attempt.
//! Only a `prepared` row persisted by this concrete runtime is a restart
//! capability. If a panic, abort, or host crash occurs after the database commit
//! but before `prepare` returns its in-memory handle, the row can be discovered
//! and resumed without reconstructing evidence or accepting caller-supplied
//! bytes.
//! [`VultisigBitcoinBroadcastRuntime::finalize`] is the terminal path: it
//! consumes an opaque configured-source observation and atomically records the
//! matching block/finality evidence in an
//! `accepted -> finalized` transition. The observer source-set identity and
//! confirmation floor are immutable fields of the prepared row.
//!
//! This library remains optional composition code, not deployment wiring,
//! endpoint approval, an independent Bitcoin consensus implementation, or
//! production approval. The configured HTTPS target is trusted for chain view
//! and transaction availability even though exact Testnet4 genesis and exact
//! returned transaction bytes are checked locally.
//!
//! The legacy P2WSH executor remains separate. Vultisig custody is aggregate-key
//! P2WPKH, and a legacy transaction, PSBT, or byte buffer cannot be converted
//! into the capability accepted here.

use std::error::Error;
use std::fmt;
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::blockdata::constants::{genesis_block, ChainHash};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{sha256, Hash as _};
use bitcoin::{Block, BlockHash, Network, Transaction, Txid, Wtxid};
use reqwest::{Client, StatusCode, Url};
use serde_json::Value;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqlitePool, SqlitePoolOptions,
    SqliteRow, SqliteSynchronous,
};
use sqlx::Row;
use thiserror::Error as ThisError;
use xindex_chain_utxo::finalized_inventory::MIN_FINALIZED_BITCOIN_CONFIRMATIONS;
use xindex_chain_utxo::trusted_observer::FinalizedBitcoinTransactionObservation;
#[cfg(test)]
use xindex_ops::network::async_client;
use xindex_ops::network::{read_bounded_async, HttpClientPolicy, NetworkError};
use xindex_ops::tls::{exact_pinned_https_async_client_builder, PinnedCertStore};
use xindex_vultisig_adapter::VultisigBitcoinEvidence;

const TARGET_ID_DOMAIN: &[u8] = b"XINDEX/BTC/TESTNET4-ESPLORA-BROADCAST-TARGET/V2";
#[cfg(test)]
const LOOPBACK_OPERATOR_ID: &str = "loopback-test-only";
#[cfg(test)]
const LOOPBACK_OPERATOR_IDENTITY_SHA256: [u8; 32] = [0x54; 32];
#[cfg(test)]
const LOOPBACK_PIN_SET_ID: [u8; 32] = [0x55; 32];
const MAX_TEXT_RESPONSE_BYTES: usize = 256;
const MAX_TRANSACTION_BYTES: usize = 4_000_000;
const MAX_EVIDENCE_RECORD_BYTES: usize = 8_100_000;
const REQUIRED_EVIDENCE_FIELDS: [&str; 19] = [
    "schema",
    "network",
    "chainGenesisHash",
    "evidenceIdSha256",
    "upstreamReleaseManifestSha256",
    "vaultId",
    "configuredDklsParticipants",
    "threshold",
    "sessionId",
    "reshareEpoch",
    "aggregatePublicKey",
    "policyId",
    "provenanceId",
    "txid",
    "wtxid",
    "transactionSha256",
    "transactionHex",
    "inputCount",
    "custodyAuthorization",
];

/// Opaque capability naming one fully validated, durably prepared,
/// target-bound broadcast row.
///
/// This type is intentionally non-cloneable, exposes no transaction bytes, and
/// has no public constructor. It does not represent a broadcast, mempool
/// acceptance, confirmation, settlement, or finality.
///
/// ```compile_fail
/// use xindex_executor::PreparedVultisigBitcoinBroadcast;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<PreparedVultisigBitcoinBroadcast>();
/// ```
///
/// ```compile_fail
/// use xindex_executor::PreparedVultisigBitcoinBroadcast;
///
/// fn cannot_extract_bytes(prepared: &PreparedVultisigBitcoinBroadcast) {
///     let _ = &prepared.evidence;
/// }
/// ```
///
/// ```compile_fail
/// use std::fmt::Debug;
/// use xindex_executor::PreparedVultisigBitcoinBroadcast;
///
/// fn requires_debug<T: Debug>() {}
/// requires_debug::<PreparedVultisigBitcoinBroadcast>();
/// ```
#[expect(
    missing_debug_implementations,
    reason = "Debug is deliberately omitted from this opaque durable-row capability"
)]
pub struct PreparedVultisigBitcoinBroadcast {
    target_id: [u8; 32],
    chain_hash: ChainHash,
    txid: Txid,
    wtxid: Wtxid,
    evidence_id: [u8; 32],
}

impl PreparedVultisigBitcoinBroadcast {
    /// Exact Testnet4 chain identity carried by the validated evidence.
    #[must_use]
    pub const fn chain_hash(&self) -> ChainHash {
        self.chain_hash
    }

    /// Locally recomputed transaction ID.
    #[must_use]
    pub const fn txid(&self) -> Txid {
        self.txid
    }

    /// Locally recomputed witness transaction ID.
    #[must_use]
    pub const fn wtxid(&self) -> Wtxid {
        self.wtxid
    }

    /// Domain-separated content identity of the write-ahead evidence record.
    #[must_use]
    pub const fn evidence_id(&self) -> [u8; 32] {
        self.evidence_id
    }
}

/// Fail-closed reason for refusing durable Vultisig broadcast preparation.
#[derive(Debug)]
pub enum VultisigBroadcastPreparationError {
    /// The evidence did not carry the exact Bitcoin Testnet4 genesis hash.
    WrongChain {
        /// Chain hash carried by the evidence.
        actual: ChainHash,
    },
    /// Exact evidence bytes were not one complete consensus transaction.
    Decode {
        /// Decoder detail for operator diagnosis.
        message: String,
    },
    /// Decoding and consensus re-encoding did not reproduce the exact bytes.
    NonCanonicalEncoding,
    /// The locally recomputed non-witness transaction ID differed from evidence.
    TxidMismatch {
        /// Transaction ID committed by the evidence.
        expected: Txid,
        /// Transaction ID recomputed from the exact bytes.
        actual: Txid,
    },
    /// The locally recomputed witness transaction ID differed from evidence.
    WtxidMismatch {
        /// Witness transaction ID committed by the evidence.
        expected: Wtxid,
        /// Witness transaction ID recomputed from the exact bytes.
        actual: Wtxid,
    },
    /// The sealed runtime could not establish or verify durable state.
    Persistence(VultisigBroadcastRuntimeError),
}

impl fmt::Display for VultisigBroadcastPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongChain { actual } => write!(
                formatter,
                "Vultisig Bitcoin preparation requires Testnet4 chain hash {}, found {actual}",
                ChainHash::TESTNET4
            ),
            Self::Decode { message } => {
                write!(
                    formatter,
                    "Vultisig Bitcoin transaction decode failed: {message}"
                )
            }
            Self::NonCanonicalEncoding => formatter.write_str(
                "Vultisig Bitcoin transaction bytes are not canonical consensus encoding",
            ),
            Self::TxidMismatch { expected, actual } => write!(
                formatter,
                "Vultisig evidence txid mismatch: expected {expected}, recomputed {actual}"
            ),
            Self::WtxidMismatch { expected, actual } => write!(
                formatter,
                "Vultisig evidence wtxid mismatch: expected {expected}, recomputed {actual}"
            ),
            Self::Persistence(error) => write!(
                formatter,
                "Vultisig evidence durable preparation failed: {error}"
            ),
        }
    }
}

impl Error for VultisigBroadcastPreparationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Persistence(error) => Some(error),
            Self::WrongChain { .. }
            | Self::Decode { .. }
            | Self::NonCanonicalEncoding
            | Self::TxidMismatch { .. }
            | Self::WtxidMismatch { .. } => None,
        }
    }
}

/// A preparation failure that retains the original evidence capability.
///
/// Ordinary failures before persistence preserve the evidence for retry. If an
/// error is observed after the row committed, the same row is also recoverable
/// through target-scoped prepared-row discovery. Panics, aborts, hangs, and
/// process or host failure are outside the in-memory retention guarantee but do
/// not erase an already committed row.
pub struct VultisigBroadcastPreparationFailure {
    evidence: Box<VultisigBitcoinEvidence>,
    error: VultisigBroadcastPreparationError,
}

impl fmt::Debug for VultisigBroadcastPreparationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VultisigBroadcastPreparationFailure")
            .field("evidence", &"<redacted>")
            .field("error", &self.error)
            .finish()
    }
}

impl VultisigBroadcastPreparationFailure {
    /// Borrow the original, non-cloneable evidence capability.
    #[must_use]
    pub fn evidence(&self) -> &VultisigBitcoinEvidence {
        &self.evidence
    }

    /// Inspect the fail-closed reason without surrendering the evidence.
    #[must_use]
    pub const fn error(&self) -> &VultisigBroadcastPreparationError {
        &self.error
    }

    /// Recover ownership of the original evidence for reconciliation or retry.
    #[must_use]
    pub fn into_evidence(self) -> VultisigBitcoinEvidence {
        *self.evidence
    }

    /// Recover both the original evidence and the failure reason.
    #[must_use]
    pub fn into_parts(self) -> (VultisigBitcoinEvidence, VultisigBroadcastPreparationError) {
        (*self.evidence, self.error)
    }
}

impl fmt::Display for VultisigBroadcastPreparationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl Error for VultisigBroadcastPreparationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

struct PreparationCandidate<'a> {
    chain_hash: ChainHash,
    transaction_bytes: &'a [u8],
    expected_txid: Txid,
    expected_wtxid: Wtxid,
    evidence_id: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PreparedIdentities {
    txid: Txid,
    wtxid: Wtxid,
    evidence_id: [u8; 32],
}

fn validate_preparation(
    candidate: &PreparationCandidate<'_>,
) -> Result<PreparedIdentities, VultisigBroadcastPreparationError> {
    if candidate.chain_hash != ChainHash::TESTNET4 {
        return Err(VultisigBroadcastPreparationError::WrongChain {
            actual: candidate.chain_hash,
        });
    }

    let transaction = deserialize::<Transaction>(candidate.transaction_bytes).map_err(|error| {
        VultisigBroadcastPreparationError::Decode {
            message: error.to_string(),
        }
    })?;
    require_canonical_encoding(candidate.transaction_bytes, &transaction)?;

    let txid = transaction.compute_txid();
    if txid != candidate.expected_txid {
        return Err(VultisigBroadcastPreparationError::TxidMismatch {
            expected: candidate.expected_txid,
            actual: txid,
        });
    }
    let wtxid = transaction.compute_wtxid();
    if wtxid != candidate.expected_wtxid {
        return Err(VultisigBroadcastPreparationError::WtxidMismatch {
            expected: candidate.expected_wtxid,
            actual: wtxid,
        });
    }

    Ok(PreparedIdentities {
        txid,
        wtxid,
        evidence_id: candidate.evidence_id,
    })
}

fn require_canonical_encoding(
    transaction_bytes: &[u8],
    transaction: &Transaction,
) -> Result<(), VultisigBroadcastPreparationError> {
    if serialize(transaction).as_slice() != transaction_bytes {
        return Err(VultisigBroadcastPreparationError::NonCanonicalEncoding);
    }
    Ok(())
}

/// Immutable finality authority bound into every prepared broadcast row.
///
/// The source-set identity must come from the reviewed
/// [`xindex_chain_utxo::trusted_observer::Testnet4ObserverConfig`]. This value
/// binds configuration; it does not by itself prove that the configured
/// sources are independent operators or full nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VultisigBitcoinFinalityPolicy {
    source_set_id: [u8; 32],
    minimum_confirmations: u32,
}

impl VultisigBitcoinFinalityPolicy {
    /// Bind the exact observer source set and minimum accepted confirmation
    /// floor.
    ///
    /// # Errors
    /// A zero source-set placeholder or a confirmation floor below the
    /// protocol minimum is rejected.
    pub fn new(
        source_set_id: [u8; 32],
        minimum_confirmations: u32,
    ) -> Result<Self, VultisigBroadcastRuntimeError> {
        if source_set_id == [0; 32] {
            return Err(VultisigBroadcastRuntimeError::Config(
                "finality source-set identity must not be zero",
            ));
        }
        if minimum_confirmations < MIN_FINALIZED_BITCOIN_CONFIRMATIONS {
            return Err(VultisigBroadcastRuntimeError::Config(
                "finality confirmation floor is below the protocol minimum",
            ));
        }
        Ok(Self {
            source_set_id,
            minimum_confirmations,
        })
    }

    /// Exact configured observer source-set identity.
    #[must_use]
    pub const fn source_set_id(&self) -> [u8; 32] {
        self.source_set_id
    }

    /// Minimum confirmations required by this runtime.
    #[must_use]
    pub const fn minimum_confirmations(&self) -> u32 {
        self.minimum_confirmations
    }
}

/// Durable lifecycle of one target-bound Vultisig Bitcoin broadcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VultisigBitcoinBroadcastState {
    /// Complete evidence and exact bytes are durable; no submission started.
    Prepared,
    /// Submission may have occurred and must be reconciled after uncertainty.
    Submitting,
    /// The target returned the committed txid or exact raw bytes were observed.
    Accepted,
    /// The configured observer source set proved exact inclusion and finality.
    Finalized,
}

impl VultisigBitcoinBroadcastState {
    fn parse(value: &str) -> Result<Self, VultisigBroadcastRuntimeError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "submitting" => Ok(Self::Submitting),
            "accepted" => Ok(Self::Accepted),
            "finalized" => Ok(Self::Finalized),
            _ => Err(VultisigBroadcastRuntimeError::CorruptStore(
                "stored broadcast state is invalid",
            )),
        }
    }
}

/// Fail-closed error from the concrete store, target, or sealed runtime.
///
/// Error text intentionally omits endpoint URLs, evidence JSON, and transaction
/// bytes. A `Transport` error while a row is `submitting` is ambiguous and the
/// durable row remains in that state.
#[derive(Debug, ThisError)]
pub enum VultisigBroadcastRuntimeError {
    /// Static target configuration is unsafe.
    #[error("Vultisig broadcast configuration is invalid: {0}")]
    Config(&'static str),
    /// `SQLite` operation failed.
    #[error("Vultisig broadcast SQLite operation failed")]
    Sqlite(#[source] sqlx::Error),
    /// Executor migrations failed.
    #[error("Vultisig broadcast migration failed")]
    Migration(#[source] sqlx::migrate::MigrateError),
    /// A stored row is malformed, inconsistent, or non-canonical.
    #[error("Vultisig broadcast store corruption: {0}")]
    CorruptStore(&'static str),
    /// The evidence ID already names different immutable content.
    #[error("Vultisig evidence ID conflicts with different stored content")]
    EvidenceConflict,
    /// HTTP transport was uncertain; endpoint details are redacted.
    #[error("Vultisig broadcast transport failed: {0}")]
    Transport(&'static str),
    /// A bounded HTTP response exceeded its configured limit.
    #[error("Vultisig broadcast response exceeded its configured bound")]
    ResponseTooLarge,
    /// The target returned a non-success status.
    #[error("Vultisig broadcast target returned HTTP {0}")]
    Http(u16),
    /// The target did not authenticate exact Testnet4 genesis bytes.
    #[error("Vultisig broadcast target failed exact Testnet4 genesis authentication")]
    WrongGenesis,
    /// The response was syntactically invalid.
    #[error("Vultisig broadcast target response was invalid: {0}")]
    InvalidResponse(&'static str),
    /// POST returned a different txid; the durable state remains ambiguous.
    #[error("Vultisig broadcast response txid did not equal the committed txid")]
    ResponseTxidMismatch,
    /// Reconciliation returned a different canonical transaction.
    #[error("Vultisig broadcast reconciliation returned conflicting transaction bytes")]
    ConflictingTransaction,
    /// Finality evidence did not match the durable transaction or policy.
    #[error("Vultisig broadcast finality evidence mismatch: {0}")]
    FinalityMismatch(&'static str),
    /// Another caller or a prior process already began submission.
    #[error("Vultisig broadcast is already in durable submitting/ambiguous state")]
    AmbiguousState,
    /// The identical evidence already reached endpoint acceptance.
    #[error("Vultisig broadcast is already in durable accepted state")]
    AlreadyAccepted,
    /// Recovery was requested for a row that never entered submission.
    #[error("Vultisig broadcast recovery requires durable submitting state")]
    NotAmbiguous,
    /// Finality was requested before endpoint acceptance.
    #[error("Vultisig broadcast finality requires durable accepted state")]
    NotAccepted,
    /// Prepared-handle recovery was requested for a non-prepared row.
    #[error("Vultisig broadcast handle recovery requires durable prepared state")]
    NotPrepared,
    /// No row exists for the supplied evidence identity.
    #[error("Vultisig broadcast evidence identity is not stored")]
    NotFound,
}

impl From<sqlx::Error> for VultisigBroadcastRuntimeError {
    fn from(error: sqlx::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<sqlx::migrate::MigrateError> for VultisigBroadcastRuntimeError {
    fn from(error: sqlx::migrate::MigrateError) -> Self {
        Self::Migration(error)
    }
}

/// A runtime submission failure that retains the submitted identity handle.
///
/// The handle lets the caller inspect the committed identities, but it does
/// **not** prove that the durable row is still `prepared`: failures after the
/// compare-and-set claim deliberately leave the row `submitting`. Such rows
/// must be reconciled or explicitly recovered by evidence ID and can never be
/// reset or retried through [`VultisigBitcoinBroadcastRuntime::submit`]. Debug
/// output redacts the handle; the evidence record and exact signed bytes remain
/// only in the validated durable row.
pub struct VultisigBroadcastSubmissionFailure {
    prepared: PreparedVultisigBitcoinBroadcast,
    error: VultisigBroadcastRuntimeError,
}

impl fmt::Debug for VultisigBroadcastSubmissionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VultisigBroadcastSubmissionFailure")
            .field("prepared", &"<redacted>")
            .field("error", &self.error)
            .finish()
    }
}

impl VultisigBroadcastSubmissionFailure {
    /// Borrow the retained identity handle without exposing its bytes.
    ///
    /// The durable row may already be `submitting`; consult [`Self::error`].
    #[must_use]
    pub const fn prepared(&self) -> &PreparedVultisigBitcoinBroadcast {
        &self.prepared
    }

    /// Inspect the fail-closed runtime error.
    #[must_use]
    pub const fn error(&self) -> &VultisigBroadcastRuntimeError {
        &self.error
    }

    /// Recover ownership of the submitted identity handle.
    ///
    /// This does not assert that the durable row remains `prepared`.
    #[must_use]
    pub fn into_prepared(self) -> PreparedVultisigBitcoinBroadcast {
        self.prepared
    }

    /// Recover the submitted identity handle and runtime error together.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        PreparedVultisigBitcoinBroadcast,
        VultisigBroadcastRuntimeError,
    ) {
        (self.prepared, self.error)
    }
}

impl fmt::Display for VultisigBroadcastSubmissionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl Error for VultisigBroadcastSubmissionFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FinalityCandidate {
    chain_hash: ChainHash,
    txid: Txid,
    wtxid: Wtxid,
    exact_transaction_sha256: [u8; 32],
    block_hash: BlockHash,
    block_height: u32,
    corroborated_tip: u32,
    confirmations: u32,
    required_confirmations: u32,
    source_set_id: [u8; 32],
    evidence_hash: [u8; 32],
}

impl From<&FinalizedBitcoinTransactionObservation> for FinalityCandidate {
    fn from(observation: &FinalizedBitcoinTransactionObservation) -> Self {
        Self {
            chain_hash: observation.chain_hash(),
            txid: observation.txid(),
            wtxid: observation.wtxid(),
            exact_transaction_sha256: observation.exact_transaction_sha256(),
            block_hash: observation.block_hash(),
            block_height: observation.block_height(),
            corroborated_tip: observation.corroborated_tip(),
            confirmations: observation.confirmations(),
            required_confirmations: observation.required_confirmations(),
            source_set_id: observation.source_set_id(),
            evidence_hash: observation.evidence_hash(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StoredFinality {
    block_hash: BlockHash,
    block_height: u32,
    corroborated_tip: u32,
    confirmations: u32,
    required_confirmations: u32,
    evidence_hash: [u8; 32],
}

#[derive(Clone)]
struct StoredVultisigBroadcast {
    evidence_id: [u8; 32],
    target_id: [u8; 32],
    finality_source_set_id: [u8; 32],
    minimum_finality_confirmations: u32,
    chain_hash: [u8; 32],
    txid: Txid,
    wtxid: Wtxid,
    evidence_record: Vec<u8>,
    evidence_record_sha256: [u8; 32],
    tx_bytes: Vec<u8>,
    state: VultisigBitcoinBroadcastState,
    finality: Option<StoredFinality>,
}

impl fmt::Debug for StoredVultisigBroadcast {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredVultisigBroadcast")
            .field("evidence_id", &self.evidence_id)
            .field("target_id", &self.target_id)
            .field("finality_source_set_id", &self.finality_source_set_id)
            .field(
                "minimum_finality_confirmations",
                &self.minimum_finality_confirmations,
            )
            .field("chain_hash", &self.chain_hash)
            .field("txid", &self.txid)
            .field("wtxid", &self.wtxid)
            .field("state", &self.state)
            .field("finality", &self.finality)
            .field("evidence_record", &"<redacted>")
            .field("evidence_record_sha256", &self.evidence_record_sha256)
            .field("tx_bytes", &"<redacted>")
            .finish()
    }
}

/// Concrete asynchronous `SQLite` write-ahead store for sealed Vultisig
/// broadcasts.
///
/// Rows bind one evidence ID to one target identity, one observer finality
/// policy, and immutable complete content. Reads repeat length, JSON identity,
/// canonical transaction, txid, wtxid, and terminal-finality validation. The
/// only forward state transitions use SQL compare-and-set updates.
#[derive(Clone)]
pub struct SqliteVultisigBitcoinBroadcastStore {
    pool: SqlitePool,
    #[cfg(unix)]
    secure_binding: Option<Arc<SecureSqliteBinding>>,
}

impl fmt::Debug for SqliteVultisigBitcoinBroadcastStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteVultisigBitcoinBroadcastStore")
            .finish_non_exhaustive()
    }
}

impl SqliteVultisigBitcoinBroadcastStore {
    /// Open an owner-only file-backed `SQLite` path with full synchronous
    /// writes and apply executor migrations.
    ///
    /// This boundary accepts an absolute canonical filesystem path, not a
    /// `SQLite` URL. Its already-existing parent must be a canonical 0700
    /// directory. The database is securely created as 0600 when absent and
    /// must remain one regular, non-symlink, non-hard-linked file owned by the
    /// parent owner. Unexpected journal/WAL/SHM files and later path identity
    /// or metadata changes fail closed. Equivalent metadata enforcement is not
    /// currently available on non-Unix platforms, so production opening is
    /// rejected there.
    ///
    /// These checks do not provide encrypted/authenticated storage and do not
    /// protect against an attacker already controlling the service UID.
    ///
    /// # Errors
    /// Unsafe path, `SQLite` failure, or migration failure.
    pub async fn connect(
        database_path: impl AsRef<Path>,
    ) -> Result<Self, VultisigBroadcastRuntimeError> {
        let database_path = database_path.as_ref();
        validate_production_database_path(database_path)?;
        open_secure_broadcast_store(database_path).await
    }

    #[cfg(test)]
    async fn connect_memory_for_test() -> Result<Self, VultisigBroadcastRuntimeError> {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .journal_mode(SqliteJournalMode::Memory)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        disable_and_verify_trusted_schema(&pool).await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self {
            pool,
            #[cfg(unix)]
            secure_binding: None,
        })
    }

    fn revalidate_storage(&self) -> Result<(), VultisigBroadcastRuntimeError> {
        #[cfg(unix)]
        {
            match &self.secure_binding {
                Some(binding) => validate_secure_sqlite_binding(binding),
                #[cfg(test)]
                None => Ok(()),
                #[cfg(not(test))]
                None => Err(VultisigBroadcastRuntimeError::Config(
                    "production broadcast storage requires a secure file binding",
                )),
            }
        }
        #[cfg(all(not(unix), test))]
        {
            Ok(())
        }
        #[cfg(all(not(unix), not(test)))]
        {
            Err(VultisigBroadcastRuntimeError::Config(
                "secure broadcast storage currently requires Unix file metadata",
            ))
        }
    }

    /// Load and fully validate the durable lifecycle state, if present.
    ///
    /// # Errors
    /// `SQLite` failure or any malformed/inconsistent stored field.
    pub async fn state(
        &self,
        evidence_id: [u8; 32],
    ) -> Result<Option<VultisigBitcoinBroadcastState>, VultisigBroadcastRuntimeError> {
        Ok(self
            .load(evidence_id)
            .await?
            .map(|broadcast| broadcast.state))
    }

    async fn persist_evidence(
        &self,
        evidence: &VultisigBitcoinEvidence,
        identities: PreparedIdentities,
        target_id: [u8; 32],
        finality_policy: VultisigBitcoinFinalityPolicy,
    ) -> Result<StoredVultisigBroadcast, VultisigBroadcastRuntimeError> {
        let record = serde_json::to_vec(evidence.record()).map_err(|_| {
            VultisigBroadcastRuntimeError::CorruptStore("evidence record serialization failed")
        })?;
        let candidate = StoredVultisigBroadcast {
            evidence_id: identities.evidence_id,
            target_id,
            finality_source_set_id: finality_policy.source_set_id,
            minimum_finality_confirmations: finality_policy.minimum_confirmations,
            chain_hash: *evidence.chain_hash().as_bytes(),
            txid: identities.txid,
            wtxid: identities.wtxid,
            evidence_record_sha256: sha256::Hash::hash(&record).to_byte_array(),
            evidence_record: record,
            tx_bytes: evidence.transaction_bytes().to_vec(),
            state: VultisigBitcoinBroadcastState::Prepared,
            finality: None,
        };
        self.persist_candidate(&candidate).await
    }

    async fn persist_candidate(
        &self,
        candidate: &StoredVultisigBroadcast,
    ) -> Result<StoredVultisigBroadcast, VultisigBroadcastRuntimeError> {
        self.revalidate_storage()?;
        validate_stored(candidate)?;
        if candidate.state != VultisigBitcoinBroadcastState::Prepared
            || candidate.finality.is_some()
        {
            return Err(VultisigBroadcastRuntimeError::CorruptStore(
                "durable preparation candidate is not prepared",
            ));
        }
        let result = sqlx::query(
            "INSERT INTO vultisig_bitcoin_broadcasts
             (evidence_id, target_id, finality_source_set_id,
              minimum_finality_confirmations, chain_hash, txid, wtxid,
              evidence_record, evidence_record_sha256, tx_bytes, state)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared')
             ON CONFLICT(evidence_id) DO NOTHING",
        )
        .bind(candidate.evidence_id.as_slice())
        .bind(candidate.target_id.as_slice())
        .bind(candidate.finality_source_set_id.as_slice())
        .bind(i64::from(candidate.minimum_finality_confirmations))
        .bind(candidate.chain_hash.as_slice())
        .bind(candidate.txid.as_byte_array().as_slice())
        .bind(candidate.wtxid.as_byte_array().as_slice())
        .bind(candidate.evidence_record.as_slice())
        .bind(candidate.evidence_record_sha256.as_slice())
        .bind(candidate.tx_bytes.as_slice())
        .execute(&self.pool)
        .await?;
        self.revalidate_storage()?;
        let stored = self.load(candidate.evidence_id).await?.ok_or(
            VultisigBroadcastRuntimeError::CorruptStore("inserted broadcast row is missing"),
        )?;
        if !same_immutable_content(&stored, candidate) {
            return Err(VultisigBroadcastRuntimeError::EvidenceConflict);
        }
        if result.rows_affected() > 1 {
            return Err(VultisigBroadcastRuntimeError::CorruptStore(
                "broadcast insert affected multiple rows",
            ));
        }
        match stored.state {
            VultisigBitcoinBroadcastState::Prepared => Ok(stored),
            VultisigBitcoinBroadcastState::Submitting => {
                Err(VultisigBroadcastRuntimeError::AmbiguousState)
            }
            VultisigBitcoinBroadcastState::Accepted | VultisigBitcoinBroadcastState::Finalized => {
                Err(VultisigBroadcastRuntimeError::AlreadyAccepted)
            }
        }
    }

    async fn load(
        &self,
        evidence_id: [u8; 32],
    ) -> Result<Option<StoredVultisigBroadcast>, VultisigBroadcastRuntimeError> {
        self.revalidate_storage()?;
        let row = sqlx::query(
            "SELECT evidence_id, target_id, finality_source_set_id,
                    minimum_finality_confirmations, chain_hash, txid, wtxid,
                    evidence_record, evidence_record_sha256, tx_bytes, state,
                    finality_block_hash, finality_block_height, finality_tip,
                    finality_confirmations, finality_required_confirmations,
                    finality_evidence_hash
             FROM vultisig_bitcoin_broadcasts WHERE evidence_id = ?",
        )
        .bind(evidence_id.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        self.revalidate_storage()?;
        row.map(|row| {
            let stored = decode_stored_row(&row)?;
            validate_stored(&stored)?;
            if stored.evidence_id != evidence_id {
                return Err(VultisigBroadcastRuntimeError::CorruptStore(
                    "queried evidence ID does not match stored row",
                ));
            }
            Ok(stored)
        })
        .transpose()
    }

    async fn prepared_for_runtime(
        &self,
        target_id: [u8; 32],
        finality_policy: VultisigBitcoinFinalityPolicy,
    ) -> Result<Vec<StoredVultisigBroadcast>, VultisigBroadcastRuntimeError> {
        self.revalidate_storage()?;
        let rows = sqlx::query(
            "SELECT evidence_id, target_id, finality_source_set_id,
                    minimum_finality_confirmations, chain_hash, txid, wtxid,
                    evidence_record, evidence_record_sha256, tx_bytes, state,
                    finality_block_hash, finality_block_height, finality_tip,
                    finality_confirmations, finality_required_confirmations,
                    finality_evidence_hash
             FROM vultisig_bitcoin_broadcasts
             WHERE target_id = ? AND finality_source_set_id = ?
               AND minimum_finality_confirmations = ? AND state = 'prepared'
             ORDER BY evidence_id",
        )
        .bind(target_id.as_slice())
        .bind(finality_policy.source_set_id.as_slice())
        .bind(i64::from(finality_policy.minimum_confirmations))
        .fetch_all(&self.pool)
        .await?;
        self.revalidate_storage()?;
        rows.into_iter()
            .map(|row| {
                let stored = decode_stored_row(&row)?;
                validate_stored(&stored)?;
                if stored.target_id != target_id
                    || stored.finality_source_set_id != finality_policy.source_set_id
                    || stored.minimum_finality_confirmations
                        != finality_policy.minimum_confirmations
                    || stored.state != VultisigBitcoinBroadcastState::Prepared
                {
                    return Err(VultisigBroadcastRuntimeError::CorruptStore(
                        "prepared-row discovery returned an inconsistent row",
                    ));
                }
                Ok(stored)
            })
            .collect()
    }

    async fn begin_submission(
        &self,
        evidence_id: [u8; 32],
    ) -> Result<BeginSubmission, VultisigBroadcastRuntimeError> {
        self.revalidate_storage()?;
        let result = sqlx::query(
            "UPDATE vultisig_bitcoin_broadcasts SET state = 'submitting'
             WHERE evidence_id = ? AND state = 'prepared'",
        )
        .bind(evidence_id.as_slice())
        .execute(&self.pool)
        .await?;
        self.revalidate_storage()?;
        if result.rows_affected() == 1 {
            return Ok(BeginSubmission::Acquired);
        }
        self.state(evidence_id)
            .await?
            .map(BeginSubmission::Existing)
            .ok_or(VultisigBroadcastRuntimeError::NotFound)
    }

    async fn mark_accepted(
        &self,
        evidence_id: [u8; 32],
    ) -> Result<(), VultisigBroadcastRuntimeError> {
        self.revalidate_storage()?;
        let result = sqlx::query(
            "UPDATE vultisig_bitcoin_broadcasts SET state = 'accepted'
             WHERE evidence_id = ? AND state = 'submitting'",
        )
        .bind(evidence_id.as_slice())
        .execute(&self.pool)
        .await?;
        self.revalidate_storage()?;
        if result.rows_affected() == 1
            || self.state(evidence_id).await? == Some(VultisigBitcoinBroadcastState::Accepted)
        {
            return Ok(());
        }
        Err(VultisigBroadcastRuntimeError::CorruptStore(
            "accepted transition did not start from submitting",
        ))
    }

    async fn mark_finalized(
        &self,
        evidence_id: [u8; 32],
        finality: &StoredFinality,
    ) -> Result<(), VultisigBroadcastRuntimeError> {
        self.revalidate_storage()?;
        let result = sqlx::query(
            "UPDATE vultisig_bitcoin_broadcasts
             SET state = 'finalized', finality_block_hash = ?,
                 finality_block_height = ?, finality_tip = ?,
                 finality_confirmations = ?, finality_required_confirmations = ?,
                 finality_evidence_hash = ?
             WHERE evidence_id = ? AND state = 'accepted'",
        )
        .bind(finality.block_hash.as_byte_array().as_slice())
        .bind(i64::from(finality.block_height))
        .bind(i64::from(finality.corroborated_tip))
        .bind(i64::from(finality.confirmations))
        .bind(i64::from(finality.required_confirmations))
        .bind(finality.evidence_hash.as_slice())
        .bind(evidence_id.as_slice())
        .execute(&self.pool)
        .await?;
        self.revalidate_storage()?;
        if result.rows_affected() == 1 {
            return Ok(());
        }
        match self.state(evidence_id).await? {
            Some(VultisigBitcoinBroadcastState::Finalized) => Ok(()),
            Some(
                VultisigBitcoinBroadcastState::Prepared | VultisigBitcoinBroadcastState::Submitting,
            ) => Err(VultisigBroadcastRuntimeError::NotAccepted),
            Some(VultisigBitcoinBroadcastState::Accepted) => {
                Err(VultisigBroadcastRuntimeError::CorruptStore(
                    "finalized transition did not advance accepted state",
                ))
            }
            None => Err(VultisigBroadcastRuntimeError::NotFound),
        }
    }
}

fn validate_production_database_path(
    database_path: &Path,
) -> Result<(), VultisigBroadcastRuntimeError> {
    let rendered = database_path.to_string_lossy().to_ascii_lowercase();
    if database_path.as_os_str().is_empty()
        || !database_path.is_absolute()
        || database_path.file_name().is_none()
        || rendered == ":memory:"
        || rendered.starts_with("file:")
        || rendered.starts_with("sqlite:")
        || rendered.contains('?')
        || rendered.contains('#')
        || rendered.contains("%3a")
        || rendered.contains("%3f")
        || rendered.contains("%3d")
    {
        return Err(VultisigBroadcastRuntimeError::Config(
            "production store requires an absolute non-URI filesystem path",
        ));
    }
    Ok(())
}

async fn disable_and_verify_trusted_schema(
    pool: &SqlitePool,
) -> Result<(), VultisigBroadcastRuntimeError> {
    sqlx::query("PRAGMA trusted_schema = OFF")
        .execute(pool)
        .await?;
    let trusted_schema: i64 = sqlx::query_scalar("PRAGMA trusted_schema")
        .fetch_one(pool)
        .await?;
    let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(pool)
        .await?;
    if trusted_schema != 0 || foreign_keys != 1 {
        return Err(VultisigBroadcastRuntimeError::Config(
            "SQLite fail-closed connection settings were not applied",
        ));
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SecureFileIdentity {
    device: u64,
    inode: u64,
    owner: u32,
}

#[cfg(unix)]
#[derive(Debug, Clone)]
struct SecureSqliteBinding {
    path: PathBuf,
    parent: SecureFileIdentity,
    database: SecureFileIdentity,
}

#[cfg(unix)]
async fn open_secure_broadcast_store(
    database_path: &Path,
) -> Result<SqliteVultisigBitcoinBroadcastStore, VultisigBroadcastRuntimeError> {
    let binding = Arc::new(prepare_secure_sqlite_file(database_path)?);
    let options = SqliteConnectOptions::new()
        .filename(database_path)
        .create_if_missing(false)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Delete)
        .locking_mode(SqliteLockingMode::Exclusive)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    let store = SqliteVultisigBitcoinBroadcastStore {
        pool,
        secure_binding: Some(binding),
    };
    if let Err(error) = store.revalidate_storage() {
        store.pool.close().await;
        return Err(error);
    }
    if let Err(error) = disable_and_verify_trusted_schema(&store.pool).await {
        store.pool.close().await;
        return Err(error);
    }
    if let Err(error) = store.revalidate_storage() {
        store.pool.close().await;
        return Err(error);
    }
    if let Err(error) = sqlx::migrate!("./migrations").run(&store.pool).await {
        store.pool.close().await;
        return Err(error.into());
    }
    if let Err(error) = store.revalidate_storage() {
        store.pool.close().await;
        return Err(error);
    }
    Ok(store)
}

#[cfg(not(unix))]
async fn open_secure_broadcast_store(
    _database_path: &Path,
) -> Result<SqliteVultisigBitcoinBroadcastStore, VultisigBroadcastRuntimeError> {
    Err(VultisigBroadcastRuntimeError::Config(
        "secure broadcast storage currently requires Unix file metadata",
    ))
}

#[cfg(unix)]
fn prepare_secure_sqlite_file(
    database_path: &Path,
) -> Result<SecureSqliteBinding, VultisigBroadcastRuntimeError> {
    let parent = database_path
        .parent()
        .ok_or(VultisigBroadcastRuntimeError::Config(
            "SQLite database path has no parent directory",
        ))?;
    let parent_identity = secure_sqlite_parent_identity(parent)?;
    reject_preexisting_sqlite_sidecars(database_path)?;

    match std::fs::symlink_metadata(database_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(database_path)
                .map_err(|_| {
                    VultisigBroadcastRuntimeError::Config(
                        "cannot securely create SQLite broadcast database",
                    )
                })?;
            file.sync_all().map_err(|_| {
                VultisigBroadcastRuntimeError::Config("cannot sync new SQLite broadcast database")
            })?;
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| {
                    VultisigBroadcastRuntimeError::Config(
                        "cannot sync SQLite broadcast database directory",
                    )
                })?;
        }
        Err(_) => {
            return Err(VultisigBroadcastRuntimeError::Config(
                "cannot inspect SQLite broadcast database",
            ));
        }
    }

    let database_identity = secure_sqlite_file_identity(database_path)?;
    if database_identity.owner != parent_identity.owner {
        return Err(VultisigBroadcastRuntimeError::Config(
            "SQLite database and private parent have different owners",
        ));
    }
    Ok(SecureSqliteBinding {
        path: database_path.to_path_buf(),
        parent: parent_identity,
        database: database_identity,
    })
}

#[cfg(unix)]
fn secure_sqlite_parent_identity(
    parent: &Path,
) -> Result<SecureFileIdentity, VultisigBroadcastRuntimeError> {
    let canonical_parent = parent.canonicalize().map_err(|_| {
        VultisigBroadcastRuntimeError::Config("SQLite database parent cannot be canonicalized")
    })?;
    if canonical_parent != parent {
        return Err(VultisigBroadcastRuntimeError::Config(
            "SQLite database parent must be a canonical non-symlink path",
        ));
    }
    let metadata = std::fs::symlink_metadata(parent).map_err(|_| {
        VultisigBroadcastRuntimeError::Config("SQLite database parent is unavailable")
    })?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(VultisigBroadcastRuntimeError::Config(
            "SQLite database parent must be a private owner-only 0700 directory",
        ));
    }
    Ok(SecureFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
    })
}

#[cfg(unix)]
fn secure_sqlite_file_identity(
    database_path: &Path,
) -> Result<SecureFileIdentity, VultisigBroadcastRuntimeError> {
    let metadata = std::fs::symlink_metadata(database_path).map_err(|_| {
        VultisigBroadcastRuntimeError::Config("cannot inspect SQLite broadcast database")
    })?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(VultisigBroadcastRuntimeError::Config(
            "SQLite database must be one owner-only 0600 regular file with no links",
        ));
    }
    Ok(SecureFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
    })
}

#[cfg(unix)]
fn sqlite_sidecar_path(database_path: &Path, suffix: &str) -> PathBuf {
    let mut path = database_path.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

#[cfg(unix)]
fn reject_preexisting_sqlite_sidecars(
    database_path: &Path,
) -> Result<(), VultisigBroadcastRuntimeError> {
    for suffix in ["-journal", "-wal", "-shm"] {
        match std::fs::symlink_metadata(sqlite_sidecar_path(database_path, suffix)) {
            Ok(_) => {
                return Err(VultisigBroadcastRuntimeError::Config(
                    "unexpected preexisting SQLite sidecar exists",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(VultisigBroadcastRuntimeError::Config(
                    "cannot inspect SQLite broadcast sidecar",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_sqlite_runtime_sidecars(
    database_path: &Path,
    expected_owner: u32,
) -> Result<(), VultisigBroadcastRuntimeError> {
    for suffix in ["-wal", "-shm"] {
        match std::fs::symlink_metadata(sqlite_sidecar_path(database_path, suffix)) {
            Ok(_) => {
                return Err(VultisigBroadcastRuntimeError::Config(
                    "unexpected SQLite WAL sidecar exists",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(VultisigBroadcastRuntimeError::Config(
                    "cannot inspect SQLite runtime sidecar",
                ));
            }
        }
    }

    match std::fs::symlink_metadata(sqlite_sidecar_path(database_path, "-journal")) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.nlink() == 1
                && metadata.uid() == expected_owner
                && metadata.permissions().mode() & 0o7777 == 0o600 =>
        {
            Ok(())
        }
        Ok(_) => Err(VultisigBroadcastRuntimeError::Config(
            "SQLite rollback journal must be one owner-only 0600 regular file",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(VultisigBroadcastRuntimeError::Config(
            "cannot inspect SQLite rollback journal",
        )),
    }
}

#[cfg(unix)]
fn validate_secure_sqlite_binding(
    binding: &SecureSqliteBinding,
) -> Result<(), VultisigBroadcastRuntimeError> {
    let parent = binding
        .path
        .parent()
        .ok_or(VultisigBroadcastRuntimeError::Config(
            "SQLite database path has no parent directory",
        ))?;
    let current_parent = secure_sqlite_parent_identity(parent)?;
    if current_parent != binding.parent {
        return Err(VultisigBroadcastRuntimeError::Config(
            "SQLite database parent identity changed after opening",
        ));
    }
    let current_database = secure_sqlite_file_identity(&binding.path)?;
    if current_database != binding.database || current_database.owner != current_parent.owner {
        return Err(VultisigBroadcastRuntimeError::Config(
            "SQLite database file identity changed after opening",
        ));
    }
    validate_sqlite_runtime_sidecars(&binding.path, current_database.owner)
}

fn decode_stored_row(
    row: &SqliteRow,
) -> Result<StoredVultisigBroadcast, VultisigBroadcastRuntimeError> {
    Ok(StoredVultisigBroadcast {
        evidence_id: exact_array(row.try_get::<Vec<u8>, _>("evidence_id")?)?,
        target_id: exact_array(row.try_get::<Vec<u8>, _>("target_id")?)?,
        finality_source_set_id: exact_array(row.try_get::<Vec<u8>, _>("finality_source_set_id")?)?,
        minimum_finality_confirmations: exact_u32(row.try_get("minimum_finality_confirmations")?)?,
        chain_hash: exact_array(row.try_get::<Vec<u8>, _>("chain_hash")?)?,
        txid: Txid::from_byte_array(exact_array(row.try_get::<Vec<u8>, _>("txid")?)?),
        wtxid: Wtxid::from_byte_array(exact_array(row.try_get::<Vec<u8>, _>("wtxid")?)?),
        evidence_record: row.try_get("evidence_record")?,
        evidence_record_sha256: exact_array(row.try_get::<Vec<u8>, _>("evidence_record_sha256")?)?,
        tx_bytes: row.try_get("tx_bytes")?,
        state: VultisigBitcoinBroadcastState::parse(row.try_get("state")?)?,
        finality: decode_stored_finality(row)?,
    })
}

fn decode_stored_finality(
    row: &SqliteRow,
) -> Result<Option<StoredFinality>, VultisigBroadcastRuntimeError> {
    let block_hash = row.try_get::<Option<Vec<u8>>, _>("finality_block_hash")?;
    let block_height = row.try_get::<Option<i64>, _>("finality_block_height")?;
    let corroborated_tip = row.try_get::<Option<i64>, _>("finality_tip")?;
    let confirmations = row.try_get::<Option<i64>, _>("finality_confirmations")?;
    let required_confirmations =
        row.try_get::<Option<i64>, _>("finality_required_confirmations")?;
    let evidence_hash = row.try_get::<Option<Vec<u8>>, _>("finality_evidence_hash")?;
    match (
        block_hash,
        block_height,
        corroborated_tip,
        confirmations,
        required_confirmations,
        evidence_hash,
    ) {
        (None, None, None, None, None, None) => Ok(None),
        (
            Some(block_hash),
            Some(block_height),
            Some(corroborated_tip),
            Some(confirmations),
            Some(required_confirmations),
            Some(evidence_hash),
        ) => Ok(Some(StoredFinality {
            block_hash: BlockHash::from_byte_array(exact_array(block_hash)?),
            block_height: exact_u32(block_height)?,
            corroborated_tip: exact_u32(corroborated_tip)?,
            confirmations: exact_u32(confirmations)?,
            required_confirmations: exact_u32(required_confirmations)?,
            evidence_hash: exact_array(evidence_hash)?,
        })),
        _ => Err(VultisigBroadcastRuntimeError::CorruptStore(
            "stored finality evidence is incomplete",
        )),
    }
}

fn exact_array(bytes: Vec<u8>) -> Result<[u8; 32], VultisigBroadcastRuntimeError> {
    bytes.try_into().map_err(|_| {
        VultisigBroadcastRuntimeError::CorruptStore("stored identity length is not 32 bytes")
    })
}

fn exact_u32(value: i64) -> Result<u32, VultisigBroadcastRuntimeError> {
    u32::try_from(value).map_err(|_| {
        VultisigBroadcastRuntimeError::CorruptStore("stored integer is outside u32 range")
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BeginSubmission {
    Acquired,
    Existing(VultisigBitcoinBroadcastState),
}

fn same_immutable_content(left: &StoredVultisigBroadcast, right: &StoredVultisigBroadcast) -> bool {
    left.evidence_id == right.evidence_id
        && left.target_id == right.target_id
        && left.finality_source_set_id == right.finality_source_set_id
        && left.minimum_finality_confirmations == right.minimum_finality_confirmations
        && left.chain_hash == right.chain_hash
        && left.txid == right.txid
        && left.wtxid == right.wtxid
        && left.evidence_record == right.evidence_record
        && left.evidence_record_sha256 == right.evidence_record_sha256
        && left.tx_bytes == right.tx_bytes
}

fn validate_stored(stored: &StoredVultisigBroadcast) -> Result<(), VultisigBroadcastRuntimeError> {
    if stored.finality_source_set_id == [0; 32]
        || stored.minimum_finality_confirmations < MIN_FINALIZED_BITCOIN_CONFIRMATIONS
    {
        return Err(VultisigBroadcastRuntimeError::CorruptStore(
            "stored finality policy is invalid",
        ));
    }
    if stored.chain_hash != *ChainHash::TESTNET4.as_bytes() {
        return Err(VultisigBroadcastRuntimeError::CorruptStore(
            "stored chain is not exact Testnet4",
        ));
    }
    if stored.tx_bytes.is_empty() || stored.tx_bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(VultisigBroadcastRuntimeError::CorruptStore(
            "stored transaction length is invalid",
        ));
    }
    if stored.evidence_record.is_empty() || stored.evidence_record.len() > MAX_EVIDENCE_RECORD_BYTES
    {
        return Err(VultisigBroadcastRuntimeError::CorruptStore(
            "stored evidence record length is invalid",
        ));
    }
    if sha256::Hash::hash(&stored.evidence_record).to_byte_array() != stored.evidence_record_sha256
    {
        return Err(VultisigBroadcastRuntimeError::CorruptStore(
            "stored evidence record digest is inconsistent",
        ));
    }
    let transaction: Transaction = deserialize(&stored.tx_bytes).map_err(|_| {
        VultisigBroadcastRuntimeError::CorruptStore("stored transaction cannot be decoded")
    })?;
    if serialize(&transaction) != stored.tx_bytes {
        return Err(VultisigBroadcastRuntimeError::CorruptStore(
            "stored transaction is not canonical",
        ));
    }
    if transaction.compute_txid() != stored.txid {
        return Err(VultisigBroadcastRuntimeError::CorruptStore(
            "stored transaction txid is inconsistent",
        ));
    }
    if transaction.compute_wtxid() != stored.wtxid {
        return Err(VultisigBroadcastRuntimeError::CorruptStore(
            "stored transaction wtxid is inconsistent",
        ));
    }
    match (stored.state, stored.finality) {
        (VultisigBitcoinBroadcastState::Finalized, Some(finality)) => {
            let candidate = FinalityCandidate {
                chain_hash: ChainHash::TESTNET4,
                txid: stored.txid,
                wtxid: stored.wtxid,
                exact_transaction_sha256: sha256::Hash::hash(&stored.tx_bytes).to_byte_array(),
                block_hash: finality.block_hash,
                block_height: finality.block_height,
                corroborated_tip: finality.corroborated_tip,
                confirmations: finality.confirmations,
                required_confirmations: finality.required_confirmations,
                source_set_id: stored.finality_source_set_id,
                evidence_hash: finality.evidence_hash,
            };
            validate_finality_candidate(stored, &candidate)?;
        }
        (VultisigBitcoinBroadcastState::Finalized, None) => {
            return Err(VultisigBroadcastRuntimeError::CorruptStore(
                "finalized row is missing finality evidence",
            ));
        }
        (_, Some(_)) => {
            return Err(VultisigBroadcastRuntimeError::CorruptStore(
                "non-finalized row contains finality evidence",
            ));
        }
        (_, None) => {}
    }
    validate_evidence_json(stored)
}

fn validate_finality_candidate(
    stored: &StoredVultisigBroadcast,
    candidate: &FinalityCandidate,
) -> Result<StoredFinality, VultisigBroadcastRuntimeError> {
    if candidate.chain_hash != ChainHash::TESTNET4
        || stored.chain_hash != *candidate.chain_hash.as_bytes()
    {
        return Err(VultisigBroadcastRuntimeError::FinalityMismatch(
            "chain identity differs",
        ));
    }
    if candidate.source_set_id != stored.finality_source_set_id {
        return Err(VultisigBroadcastRuntimeError::FinalityMismatch(
            "observer source set differs",
        ));
    }
    if candidate.txid != stored.txid || candidate.wtxid != stored.wtxid {
        return Err(VultisigBroadcastRuntimeError::FinalityMismatch(
            "transaction identity differs",
        ));
    }
    if candidate.exact_transaction_sha256 != sha256::Hash::hash(&stored.tx_bytes).to_byte_array() {
        return Err(VultisigBroadcastRuntimeError::FinalityMismatch(
            "exact transaction bytes differ",
        ));
    }
    if candidate.required_confirmations < stored.minimum_finality_confirmations
        || candidate.confirmations < candidate.required_confirmations
        || candidate.confirmations < MIN_FINALIZED_BITCOIN_CONFIRMATIONS
    {
        return Err(VultisigBroadcastRuntimeError::FinalityMismatch(
            "confirmation floor is not satisfied",
        ));
    }
    let confirmations = candidate
        .corroborated_tip
        .checked_sub(candidate.block_height)
        .and_then(|depth| depth.checked_add(1));
    if confirmations != Some(candidate.confirmations) {
        return Err(VultisigBroadcastRuntimeError::FinalityMismatch(
            "confirmation arithmetic is inconsistent",
        ));
    }
    if candidate.evidence_hash == [0; 32] {
        return Err(VultisigBroadcastRuntimeError::FinalityMismatch(
            "observation evidence identity is zero",
        ));
    }
    Ok(StoredFinality {
        block_hash: candidate.block_hash,
        block_height: candidate.block_height,
        corroborated_tip: candidate.corroborated_tip,
        confirmations: candidate.confirmations,
        required_confirmations: candidate.required_confirmations,
        evidence_hash: candidate.evidence_hash,
    })
}

fn validate_evidence_json(
    stored: &StoredVultisigBroadcast,
) -> Result<(), VultisigBroadcastRuntimeError> {
    let value: Value = serde_json::from_slice(&stored.evidence_record).map_err(|_| {
        VultisigBroadcastRuntimeError::CorruptStore("stored evidence record is not valid JSON")
    })?;
    let object = value
        .as_object()
        .ok_or(VultisigBroadcastRuntimeError::CorruptStore(
            "stored evidence record is not an object",
        ))?;
    let field = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .ok_or(VultisigBroadcastRuntimeError::CorruptStore(
                "stored evidence record is missing an identity field",
            ))
    };
    if object.len() != REQUIRED_EVIDENCE_FIELDS.len()
        || REQUIRED_EVIDENCE_FIELDS
            .iter()
            .any(|required| !object.contains_key(*required))
        || field("schema")? != "xindex.vultisig.bitcoin.aggregate-signature-evidence.v1"
        || field("network")? != "bitcoin-testnet4"
        || !object
            .get("configuredDklsParticipants")
            .is_some_and(Value::is_array)
        || !object.get("threshold").is_some_and(Value::is_u64)
        || !object.get("reshareEpoch").is_some_and(Value::is_u64)
        || !object.get("inputCount").is_some_and(Value::is_u64)
        || !object
            .get("custodyAuthorization")
            .is_some_and(Value::is_object)
        || field("evidenceIdSha256")? != encode_lower_hex(&stored.evidence_id)
        || field("chainGenesisHash")? != ChainHash::TESTNET4.to_string()
        || field("txid")? != stored.txid.to_string()
        || field("wtxid")? != stored.wtxid.to_string()
        || field("transactionHex")? != encode_lower_hex(&stored.tx_bytes)
        || field("transactionSha256")? != sha256::Hash::hash(&stored.tx_bytes).to_string()
    {
        return Err(VultisigBroadcastRuntimeError::CorruptStore(
            "stored evidence record identities are inconsistent",
        ));
    }
    Ok(())
}

const fn broadcast_http_policy() -> HttpClientPolicy {
    HttpClientPolicy {
        connect_timeout: Duration::from_secs(3),
        request_timeout: Duration::from_secs(20),
        max_response_bytes: MAX_TRANSACTION_BYTES,
    }
}

fn validate_operator_identity(
    operator_id: &str,
    operator_identity_record_sha256: [u8; 32],
) -> Result<(), VultisigBroadcastRuntimeError> {
    let bytes = operator_id.as_bytes();
    let mut previous_was_separator = false;
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !bytes.iter().all(|byte| {
            if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
                previous_was_separator = false;
                true
            } else if matches!(byte, b'-' | b'_' | b'.' | b':') && !previous_was_separator {
                previous_was_separator = true;
                true
            } else {
                false
            }
        })
    {
        return Err(VultisigBroadcastRuntimeError::Config(
            "operator ID must be a canonical lowercase ASCII identity",
        ));
    }
    if operator_identity_record_sha256 == [0; 32] {
        return Err(VultisigBroadcastRuntimeError::Config(
            "reviewed operator identity record digest must be nonzero",
        ));
    }
    Ok(())
}

fn normalize_production_target_url(base_url: &str) -> Result<Url, VultisigBroadcastRuntimeError> {
    normalize_target_url(base_url, false)
}

#[cfg(test)]
fn normalize_loopback_target_url(base_url: &str) -> Result<Url, VultisigBroadcastRuntimeError> {
    normalize_target_url(base_url, true)
}

fn normalize_target_url(
    base_url: &str,
    allow_loopback_http: bool,
) -> Result<Url, VultisigBroadcastRuntimeError> {
    let mut parsed = Url::parse(base_url)
        .map_err(|_| VultisigBroadcastRuntimeError::Config("target URL is invalid"))?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(VultisigBroadcastRuntimeError::Config(
            "target must not contain credentials, query, or fragment",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or(VultisigBroadcastRuntimeError::Config(
            "target URL has no hostname",
        ))?;
    let identity_host = host.trim_end_matches('.').to_ascii_lowercase();
    if identity_host.is_empty() {
        return Err(VultisigBroadcastRuntimeError::Config(
            "target URL has no hostname",
        ));
    }
    let ip_host = identity_host.parse::<std::net::IpAddr>().is_ok();
    let localhost = identity_host == "localhost" || identity_host.ends_with(".localhost");
    let loopback_http = allow_loopback_http
        && parsed.scheme() == "http"
        && (identity_host == "127.0.0.1" || identity_host == "::1" || localhost);
    if !loopback_http && parsed.scheme() != "https" {
        return Err(VultisigBroadcastRuntimeError::Config(
            "target must use authenticated HTTPS",
        ));
    }
    if !allow_loopback_http && (ip_host || localhost) {
        return Err(VultisigBroadcastRuntimeError::Config(
            "production target identity requires a non-loopback DNS hostname",
        ));
    }
    if allow_loopback_http && parsed.scheme() == "http" && !loopback_http {
        return Err(VultisigBroadcastRuntimeError::Config(
            "plaintext test target must be loopback-only",
        ));
    }
    parsed
        .set_host(Some(&identity_host))
        .map_err(|_| VultisigBroadcastRuntimeError::Config("target hostname is invalid"))?;
    if parsed.scheme() == "https" && parsed.port() == Some(443) {
        parsed
            .set_port(None)
            .map_err(|()| VultisigBroadcastRuntimeError::Config("target port is invalid"))?;
    }
    if !parsed.path().ends_with('/') {
        let normalized = format!("{}/", parsed.path());
        parsed.set_path(&normalized);
    }
    Ok(parsed)
}

/// Exact Testnet4 Esplora-style broadcast target.
///
/// Production construction accepts only a normalized HTTPS non-loopback DNS
/// URL, a canonical operator identity plus its reviewed record digest, and an
/// explicit exact-leaf certificate pin set. The HTTP client uses only those
/// explicit roots and pins while retaining normal `WebPKI` chain, time,
/// purpose, and hostname verification. Debug and errors redact URL and
/// certificate material.
#[derive(Clone)]
pub struct Testnet4EsploraBroadcastTarget {
    base_url: Url,
    client: Client,
    target_id: [u8; 32],
}

impl fmt::Debug for Testnet4EsploraBroadcastTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Testnet4EsploraBroadcastTarget")
            .field("base_url", &"<redacted>")
            .field("client", &"<redacted>")
            .field("target_id", &self.target_id)
            .finish()
    }
}

impl Testnet4EsploraBroadcastTarget {
    /// Construct a bounded, no-redirect production target from one exact HTTPS
    /// DNS-host base URL and reviewed operator identity.
    ///
    /// There is intentionally no unpinned production constructor:
    ///
    /// ```compile_fail
    /// use xindex_executor::Testnet4EsploraBroadcastTarget;
    ///
    /// let _ = Testnet4EsploraBroadcastTarget::new("https://esplora.example/api");
    /// ```
    ///
    /// # Errors
    /// Unsafe URL/operator identity, zero identity-record digest, invalid exact
    /// pin trust bundle, or HTTP client construction.
    pub fn new(
        base_url: &str,
        operator_id: &str,
        operator_identity_record_sha256: [u8; 32],
        pinned_server: PinnedCertStore,
    ) -> Result<Self, VultisigBroadcastRuntimeError> {
        let parsed = normalize_production_target_url(base_url)?;
        validate_operator_identity(operator_id, operator_identity_record_sha256)?;
        let pin_set_id = pinned_server.exact_leaf_pin_set_id();
        let builder =
            exact_pinned_https_async_client_builder(broadcast_http_policy(), pinned_server)
                .map_err(|_| {
                    VultisigBroadcastRuntimeError::Config(
                        "exact-pinned target TLS client configuration is invalid",
                    )
                })?;
        let client = builder.build().map_err(|_| {
            VultisigBroadcastRuntimeError::Config(
                "exact-pinned target HTTP client configuration is invalid",
            )
        })?;
        let target_id = compute_target_id(
            &parsed,
            operator_id,
            operator_identity_record_sha256,
            pin_set_id,
        );
        Ok(Self {
            base_url: parsed,
            client,
            target_id,
        })
    }

    #[cfg(test)]
    fn new_loopback(base_url: &str) -> Result<Self, VultisigBroadcastRuntimeError> {
        let parsed = normalize_loopback_target_url(base_url)?;
        let client = async_client(broadcast_http_policy())
            .map_err(|_| VultisigBroadcastRuntimeError::Transport("client_build"))?;
        let target_id = compute_target_id(
            &parsed,
            LOOPBACK_OPERATOR_ID,
            LOOPBACK_OPERATOR_IDENTITY_SHA256,
            LOOPBACK_PIN_SET_ID,
        );
        Ok(Self {
            base_url: parsed,
            client,
            target_id,
        })
    }

    /// Domain-separated identity of the normalized URL, exact Testnet4 chain,
    /// operator ID, reviewed operator-record digest, and exact pin-set ID.
    #[must_use]
    pub const fn target_id(&self) -> [u8; 32] {
        self.target_id
    }

    async fn authenticate_testnet4(&self) -> Result<(), VultisigBroadcastRuntimeError> {
        let hash_bytes = self
            .get_success("block-height/0", MAX_TEXT_RESPONSE_BYTES)
            .await?;
        let hash_text = std::str::from_utf8(&hash_bytes)
            .map_err(|_| VultisigBroadcastRuntimeError::WrongGenesis)?
            .trim();
        let hash = BlockHash::from_str(hash_text)
            .map_err(|_| VultisigBroadcastRuntimeError::WrongGenesis)?;
        let raw = self
            .get_success(&format!("block/{hash}/raw"), MAX_TEXT_RESPONSE_BYTES * 4)
            .await?;
        let block: Block =
            deserialize(&raw).map_err(|_| VultisigBroadcastRuntimeError::WrongGenesis)?;
        let expected = genesis_block(Network::Testnet4);
        if hash != expected.block_hash()
            || block.block_hash() != expected.block_hash()
            || serialize(&block) != raw
            || raw != serialize(&expected)
            || ChainHash::from_genesis_block_hash(block.block_hash()) != ChainHash::TESTNET4
        {
            return Err(VultisigBroadcastRuntimeError::WrongGenesis);
        }
        Ok(())
    }

    async fn submit_exact(
        &self,
        stored: &StoredVultisigBroadcast,
    ) -> Result<(), VultisigBroadcastRuntimeError> {
        let url = self.join("tx")?;
        let body = encode_lower_hex(&stored.tx_bytes);
        let response = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(body)
            .send()
            .await
            .map_err(|error| VultisigBroadcastRuntimeError::Transport(transport_class(&error)))?;
        let status = response.status();
        let bytes = read_response(response, MAX_TEXT_RESPONSE_BYTES).await?;
        if !status.is_success() {
            return Err(VultisigBroadcastRuntimeError::Http(status.as_u16()));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| VultisigBroadcastRuntimeError::InvalidResponse("txid is not UTF-8"))?
            .trim();
        let returned = Txid::from_str(text)
            .map_err(|_| VultisigBroadcastRuntimeError::InvalidResponse("txid is invalid"))?;
        if returned != stored.txid {
            return Err(VultisigBroadcastRuntimeError::ResponseTxidMismatch);
        }
        Ok(())
    }

    async fn reconcile_exact(
        &self,
        stored: &StoredVultisigBroadcast,
    ) -> Result<Reconciliation, VultisigBroadcastRuntimeError> {
        let url = self.join(&format!("tx/{}/raw", stored.txid))?;
        let response =
            self.client.get(url).send().await.map_err(|error| {
                VultisigBroadcastRuntimeError::Transport(transport_class(&error))
            })?;
        if response.status() == StatusCode::NOT_FOUND {
            let _ = read_response(response, MAX_TEXT_RESPONSE_BYTES).await?;
            return Ok(Reconciliation::Absent);
        }
        let status = response.status();
        let bytes = read_response(response, MAX_TRANSACTION_BYTES).await?;
        if !status.is_success() {
            return Err(VultisigBroadcastRuntimeError::Http(status.as_u16()));
        }
        let transaction: Transaction = deserialize(&bytes).map_err(|_| {
            VultisigBroadcastRuntimeError::InvalidResponse("raw transaction is invalid")
        })?;
        if serialize(&transaction) != bytes || bytes != stored.tx_bytes {
            return Err(VultisigBroadcastRuntimeError::ConflictingTransaction);
        }
        if transaction.compute_txid() != stored.txid || transaction.compute_wtxid() != stored.wtxid
        {
            return Err(VultisigBroadcastRuntimeError::ConflictingTransaction);
        }
        Ok(Reconciliation::Exact)
    }

    async fn get_success(
        &self,
        path: &str,
        limit: usize,
    ) -> Result<Vec<u8>, VultisigBroadcastRuntimeError> {
        let response = self
            .client
            .get(self.join(path)?)
            .send()
            .await
            .map_err(|error| VultisigBroadcastRuntimeError::Transport(transport_class(&error)))?;
        let status = response.status();
        let bytes = read_response(response, limit).await?;
        if !status.is_success() {
            return Err(VultisigBroadcastRuntimeError::Http(status.as_u16()));
        }
        Ok(bytes)
    }

    fn join(&self, path: &str) -> Result<Url, VultisigBroadcastRuntimeError> {
        self.base_url
            .join(path)
            .map_err(|_| VultisigBroadcastRuntimeError::Config("target path is invalid"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reconciliation {
    Exact,
    Absent,
}

/// Concrete sealed composition of target-bound `SQLite` state and exact-byte
/// Testnet4 Esplora transport.
#[derive(Debug, Clone)]
pub struct VultisigBitcoinBroadcastRuntime {
    store: SqliteVultisigBitcoinBroadcastStore,
    target: Testnet4EsploraBroadcastTarget,
    finality_policy: VultisigBitcoinFinalityPolicy,
}

impl VultisigBitcoinBroadcastRuntime {
    /// Bind one concrete durable store to one exact target and observer
    /// finality policy.
    #[must_use]
    pub const fn new(
        store: SqliteVultisigBitcoinBroadcastStore,
        target: Testnet4EsploraBroadcastTarget,
        finality_policy: VultisigBitcoinFinalityPolicy,
    ) -> Self {
        Self {
            store,
            target,
            finality_policy,
        }
    }

    /// Consume aggregate evidence, repeat the exact Testnet4/canonical
    /// transaction/txid/wtxid checks, and durably persist a target-bound row
    /// before returning an opaque, non-cloneable handle.
    ///
    /// Identical retries remain idempotent only while the durable row is still
    /// `prepared`. Reusing the evidence identity with different content or a
    /// different target fails closed. An identical row already in
    /// `submitting` returns [`VultisigBroadcastRuntimeError::AmbiguousState`];
    /// one already in `accepted` returns
    /// [`VultisigBroadcastRuntimeError::AlreadyAccepted`] rather than minting a
    /// misleading prepared handle. If the process crashes after the database
    /// commit but before this future returns, the committed prepared row is
    /// recoverable through [`Self::discover_prepared`] or
    /// [`Self::resume_prepared`]. This method performs no network request.
    ///
    /// A bare transaction cannot substitute for aggregate evidence:
    ///
    /// ```compile_fail
    /// use bitcoin::Transaction;
    /// use xindex_executor::VultisigBitcoinBroadcastRuntime;
    ///
    /// async fn cannot_prepare_bare_transaction(
    ///     runtime: &VultisigBitcoinBroadcastRuntime,
    ///     transaction: Transaction,
    /// ) {
    ///     let _ = runtime.prepare(transaction).await;
    /// }
    /// ```
    ///
    /// # Errors
    /// Validation, serialization, or durable-store failure. Every ordinary
    /// error retains the original evidence capability for retry; an already
    /// committed row is independently discoverable.
    pub async fn prepare(
        &self,
        evidence: VultisigBitcoinEvidence,
    ) -> Result<PreparedVultisigBitcoinBroadcast, VultisigBroadcastPreparationFailure> {
        let candidate = PreparationCandidate {
            chain_hash: evidence.chain_hash(),
            transaction_bytes: evidence.transaction_bytes(),
            expected_txid: Txid::from_byte_array(evidence.txid()),
            expected_wtxid: Wtxid::from_byte_array(evidence.wtxid()),
            evidence_id: evidence.record().evidence_id_sha256(),
        };
        let identities = match validate_preparation(&candidate) {
            Ok(identities) => identities,
            Err(error) => {
                return Err(VultisigBroadcastPreparationFailure {
                    evidence: Box::new(evidence),
                    error,
                });
            }
        };
        match self
            .store
            .persist_evidence(
                &evidence,
                identities,
                self.target.target_id,
                self.finality_policy,
            )
            .await
        {
            Ok(stored) => match stored.state {
                VultisigBitcoinBroadcastState::Prepared => Ok(prepared_handle(&stored)),
                VultisigBitcoinBroadcastState::Submitting => {
                    Err(VultisigBroadcastPreparationFailure {
                        evidence: Box::new(evidence),
                        error: VultisigBroadcastPreparationError::Persistence(
                            VultisigBroadcastRuntimeError::AmbiguousState,
                        ),
                    })
                }
                VultisigBitcoinBroadcastState::Accepted
                | VultisigBitcoinBroadcastState::Finalized => {
                    Err(VultisigBroadcastPreparationFailure {
                        evidence: Box::new(evidence),
                        error: VultisigBroadcastPreparationError::Persistence(
                            VultisigBroadcastRuntimeError::AlreadyAccepted,
                        ),
                    })
                }
            },
            Err(error) => Err(VultisigBroadcastPreparationFailure {
                evidence: Box::new(evidence),
                error: VultisigBroadcastPreparationError::Persistence(error),
            }),
        }
    }

    /// Discover every fully validated durable `prepared` row bound to this
    /// runtime's exact target identity.
    ///
    /// This is the crash-recovery path for a commit completed before
    /// [`Self::prepare`] returned its in-memory handle. Discovery performs no
    /// network request and exposes no transaction or evidence bytes.
    ///
    /// # Errors
    /// Store failure or malformed/inconsistent durable content.
    pub async fn discover_prepared(
        &self,
    ) -> Result<Vec<PreparedVultisigBitcoinBroadcast>, VultisigBroadcastRuntimeError> {
        self.store
            .prepared_for_runtime(self.target.target_id, self.finality_policy)
            .await
            .map(|rows| rows.iter().map(prepared_handle).collect())
    }

    /// Recover one opaque handle from a fully validated durable `prepared` row.
    ///
    /// This method performs no network request. Accepted and finalized rows are
    /// not prepared; submitting rows require ambiguity reconciliation instead.
    ///
    /// # Errors
    /// Missing, non-prepared, target-conflicting, or corrupt durable state.
    pub async fn resume_prepared(
        &self,
        evidence_id: [u8; 32],
    ) -> Result<PreparedVultisigBitcoinBroadcast, VultisigBroadcastRuntimeError> {
        let stored = self.load_for_target(evidence_id).await?;
        if stored.state != VultisigBitcoinBroadcastState::Prepared {
            return Err(VultisigBroadcastRuntimeError::NotPrepared);
        }
        Ok(prepared_handle(&stored))
    }

    /// Consume a durable prepared handle, authenticate exact Testnet4, durably
    /// claim the single submission with CAS, and POST exact stored bytes. Any
    /// uncertainty after the CAS leaves `submitting` durable.
    ///
    /// # Errors
    /// Missing/conflicting/corrupt durable state, target authentication, CAS,
    /// response, or transport failure.
    pub async fn submit(
        &self,
        prepared: PreparedVultisigBitcoinBroadcast,
    ) -> Result<VultisigBitcoinBroadcastState, VultisigBroadcastSubmissionFailure> {
        let evidence_id = prepared.evidence_id;
        let stored = match self.load_for_target(evidence_id).await {
            Ok(stored) => stored,
            Err(error) => {
                return Err(VultisigBroadcastSubmissionFailure { prepared, error });
            }
        };
        if !handle_matches_stored(&prepared, &stored) {
            let error = VultisigBroadcastRuntimeError::EvidenceConflict;
            return Err(VultisigBroadcastSubmissionFailure { prepared, error });
        }
        self.submit_stored(evidence_id)
            .await
            .map_err(|error| VultisigBroadcastSubmissionFailure { prepared, error })
    }

    async fn submit_stored(
        &self,
        evidence_id: [u8; 32],
    ) -> Result<VultisigBitcoinBroadcastState, VultisigBroadcastRuntimeError> {
        let stored = self.load_for_target(evidence_id).await?;
        if matches!(
            stored.state,
            VultisigBitcoinBroadcastState::Accepted | VultisigBitcoinBroadcastState::Finalized
        ) {
            return Ok(stored.state);
        }
        if stored.state == VultisigBitcoinBroadcastState::Submitting {
            return Err(VultisigBroadcastRuntimeError::AmbiguousState);
        }
        self.target.authenticate_testnet4().await?;
        match self.store.begin_submission(evidence_id).await? {
            BeginSubmission::Acquired => {}
            BeginSubmission::Existing(VultisigBitcoinBroadcastState::Accepted) => {
                return Ok(VultisigBitcoinBroadcastState::Accepted);
            }
            BeginSubmission::Existing(VultisigBitcoinBroadcastState::Finalized) => {
                return Ok(VultisigBitcoinBroadcastState::Finalized);
            }
            BeginSubmission::Existing(VultisigBitcoinBroadcastState::Submitting) => {
                return Err(VultisigBroadcastRuntimeError::AmbiguousState);
            }
            BeginSubmission::Existing(VultisigBitcoinBroadcastState::Prepared) => {
                return Err(VultisigBroadcastRuntimeError::CorruptStore(
                    "submission CAS did not advance state",
                ));
            }
        }
        let claimed = self.load_for_target(evidence_id).await?;
        self.target.submit_exact(&claimed).await?;
        self.store.mark_accepted(evidence_id).await?;
        Ok(VultisigBitcoinBroadcastState::Accepted)
    }

    /// Reconcile a durable ambiguous row by requiring byte-identical raw
    /// transaction bytes. Absence or transport uncertainty remains ambiguous.
    ///
    /// # Errors
    /// Non-ambiguous state, target/store failure, or conflicting bytes.
    pub async fn reconcile(
        &self,
        evidence_id: [u8; 32],
    ) -> Result<VultisigBitcoinBroadcastState, VultisigBroadcastRuntimeError> {
        let stored = self.load_for_target(evidence_id).await?;
        if matches!(
            stored.state,
            VultisigBitcoinBroadcastState::Accepted | VultisigBitcoinBroadcastState::Finalized
        ) {
            return Ok(stored.state);
        }
        if stored.state != VultisigBitcoinBroadcastState::Submitting {
            return Err(VultisigBroadcastRuntimeError::NotAmbiguous);
        }
        self.target.authenticate_testnet4().await?;
        match self.target.reconcile_exact(&stored).await? {
            Reconciliation::Exact => {
                self.store.mark_accepted(evidence_id).await?;
                Ok(VultisigBitcoinBroadcastState::Accepted)
            }
            Reconciliation::Absent => Err(VultisigBroadcastRuntimeError::AmbiguousState),
        }
    }

    /// Explicit recovery operation for a durable ambiguous row. It first
    /// authenticates Testnet4 and reconciles. Only an explicit 404 permits one
    /// same-byte POST from the stored row; no transaction is rebuilt.
    ///
    /// # Errors
    /// Non-ambiguous state, transport/store failure, conflicting bytes, or a
    /// response txid mismatch. The state remains `submitting` on uncertainty.
    pub async fn recover_ambiguous(
        &self,
        evidence_id: [u8; 32],
    ) -> Result<VultisigBitcoinBroadcastState, VultisigBroadcastRuntimeError> {
        let stored = self.load_for_target(evidence_id).await?;
        if matches!(
            stored.state,
            VultisigBitcoinBroadcastState::Accepted | VultisigBitcoinBroadcastState::Finalized
        ) {
            return Ok(stored.state);
        }
        if stored.state != VultisigBitcoinBroadcastState::Submitting {
            return Err(VultisigBroadcastRuntimeError::NotAmbiguous);
        }
        self.target.authenticate_testnet4().await?;
        match self.target.reconcile_exact(&stored).await? {
            Reconciliation::Exact => {}
            Reconciliation::Absent => self.target.submit_exact(&stored).await?,
        }
        self.store.mark_accepted(evidence_id).await?;
        Ok(VultisigBitcoinBroadcastState::Accepted)
    }

    /// Consume an opaque configured-source observation and durably advance an
    /// accepted exact-byte broadcast to terminal `finalized` state.
    ///
    /// The observation must match the runtime-bound source-set identity, meet
    /// the runtime confirmation floor, and bind the exact stored transaction,
    /// txid, and wtxid. No endpoint request or transaction submission occurs.
    /// Repeating finalization for an already finalized row is idempotent after
    /// the new observation passes the same validation.
    ///
    /// # Errors
    /// Missing/corrupt state, pre-acceptance state, source-policy mismatch, or
    /// transaction/finality mismatch.
    pub async fn finalize(
        &self,
        evidence_id: [u8; 32],
        observation: FinalizedBitcoinTransactionObservation,
    ) -> Result<VultisigBitcoinBroadcastState, VultisigBroadcastRuntimeError> {
        self.finalize_candidate(evidence_id, FinalityCandidate::from(&observation))
            .await
    }

    async fn finalize_candidate(
        &self,
        evidence_id: [u8; 32],
        candidate: FinalityCandidate,
    ) -> Result<VultisigBitcoinBroadcastState, VultisigBroadcastRuntimeError> {
        let stored = self.load_for_target(evidence_id).await?;
        let finality = validate_finality_candidate(&stored, &candidate)?;
        match stored.state {
            VultisigBitcoinBroadcastState::Accepted => {
                self.store.mark_finalized(evidence_id, &finality).await?;
                Ok(VultisigBitcoinBroadcastState::Finalized)
            }
            VultisigBitcoinBroadcastState::Finalized => {
                Ok(VultisigBitcoinBroadcastState::Finalized)
            }
            VultisigBitcoinBroadcastState::Prepared | VultisigBitcoinBroadcastState::Submitting => {
                Err(VultisigBroadcastRuntimeError::NotAccepted)
            }
        }
    }

    async fn load_for_target(
        &self,
        evidence_id: [u8; 32],
    ) -> Result<StoredVultisigBroadcast, VultisigBroadcastRuntimeError> {
        let stored = self
            .store
            .load(evidence_id)
            .await?
            .ok_or(VultisigBroadcastRuntimeError::NotFound)?;
        if stored.target_id != self.target.target_id
            || stored.finality_source_set_id != self.finality_policy.source_set_id
            || stored.minimum_finality_confirmations != self.finality_policy.minimum_confirmations
        {
            return Err(VultisigBroadcastRuntimeError::EvidenceConflict);
        }
        Ok(stored)
    }
}

fn prepared_handle(stored: &StoredVultisigBroadcast) -> PreparedVultisigBitcoinBroadcast {
    PreparedVultisigBitcoinBroadcast {
        target_id: stored.target_id,
        chain_hash: ChainHash::TESTNET4,
        txid: stored.txid,
        wtxid: stored.wtxid,
        evidence_id: stored.evidence_id,
    }
}

fn handle_matches_stored(
    prepared: &PreparedVultisigBitcoinBroadcast,
    stored: &StoredVultisigBroadcast,
) -> bool {
    prepared.target_id == stored.target_id
        && prepared.chain_hash.as_bytes() == &stored.chain_hash
        && prepared.txid == stored.txid
        && prepared.wtxid == stored.wtxid
        && prepared.evidence_id == stored.evidence_id
}

fn compute_target_id(
    url: &Url,
    operator_id: &str,
    operator_identity_record_sha256: [u8; 32],
    pin_set_id: [u8; 32],
) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(TARGET_ID_DOMAIN);
    push_target_id_field(&mut preimage, url.as_str().as_bytes());
    push_target_id_field(&mut preimage, ChainHash::TESTNET4.as_bytes());
    push_target_id_field(&mut preimage, operator_id.as_bytes());
    push_target_id_field(&mut preimage, &operator_identity_record_sha256);
    push_target_id_field(&mut preimage, &pin_set_id);
    sha256::Hash::hash(&preimage).to_byte_array()
}

fn push_target_id_field(preimage: &mut Vec<u8>, value: &[u8]) {
    preimage.extend_from_slice(&(value.len() as u64).to_be_bytes());
    preimage.extend_from_slice(value);
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

async fn read_response(
    response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, VultisigBroadcastRuntimeError> {
    read_bounded_async(response, limit)
        .await
        .map_err(|error| match error {
            NetworkError::ResponseTooLarge { .. } => {
                VultisigBroadcastRuntimeError::ResponseTooLarge
            }
            _ => VultisigBroadcastRuntimeError::Transport("response_body"),
        })
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
    #![expect(clippy::expect_used, reason = "test code")]

    #[cfg(unix)]
    use std::os::unix::fs::{symlink, DirBuilderExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    use wiremock::matchers::{body_bytes, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const TEST_FINALITY_SOURCE_SET_ID: [u8; 32] = [0x66; 32];

    fn test_finality_policy() -> VultisigBitcoinFinalityPolicy {
        VultisigBitcoinFinalityPolicy::new(
            TEST_FINALITY_SOURCE_SET_ID,
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .expect("valid test finality policy")
    }

    fn synthetic_transaction() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([0x11; 32]), 1),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[&[0x01, 0x02][..], &[0x03][..]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(42_000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn candidate<'a>(
        transaction: &Transaction,
        bytes: &'a [u8],
        evidence_id: [u8; 32],
    ) -> PreparationCandidate<'a> {
        PreparationCandidate {
            chain_hash: ChainHash::TESTNET4,
            transaction_bytes: bytes,
            expected_txid: transaction.compute_txid(),
            expected_wtxid: transaction.compute_wtxid(),
            evidence_id,
        }
    }

    fn stored_candidate(
        transaction: &Transaction,
        evidence_id: [u8; 32],
        target_id: [u8; 32],
    ) -> StoredVultisigBroadcast {
        let tx_bytes = serialize(transaction);
        let txid = transaction.compute_txid();
        let wtxid = transaction.compute_wtxid();
        let evidence_record = serde_json::to_vec(&serde_json::json!({
            "schema": "xindex.vultisig.bitcoin.aggregate-signature-evidence.v1",
            "network": "bitcoin-testnet4",
            "chainGenesisHash": ChainHash::TESTNET4.to_string(),
            "evidenceIdSha256": encode_lower_hex(&evidence_id),
            "upstreamReleaseManifestSha256": encode_lower_hex(&[0x01; 32]),
            "vaultId": "key-free-test-vault",
            "configuredDklsParticipants": [],
            "threshold": 0,
            "sessionId": "key-free-test-session",
            "reshareEpoch": 0,
            "aggregatePublicKey": "",
            "policyId": encode_lower_hex(&[0x02; 32]),
            "provenanceId": encode_lower_hex(&[0x03; 32]),
            "txid": txid.to_string(),
            "wtxid": wtxid.to_string(),
            "transactionSha256": sha256::Hash::hash(&tx_bytes).to_string(),
            "transactionHex": encode_lower_hex(&tx_bytes),
            "inputCount": transaction.input.len(),
            "custodyAuthorization": {},
        }))
        .expect("serialize synthetic evidence record");
        StoredVultisigBroadcast {
            evidence_id,
            target_id,
            finality_source_set_id: TEST_FINALITY_SOURCE_SET_ID,
            minimum_finality_confirmations: MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
            chain_hash: *ChainHash::TESTNET4.as_bytes(),
            txid,
            wtxid,
            evidence_record_sha256: sha256::Hash::hash(&evidence_record).to_byte_array(),
            evidence_record,
            tx_bytes,
            state: VultisigBitcoinBroadcastState::Prepared,
            finality: None,
        }
    }

    fn finality_candidate(stored: &StoredVultisigBroadcast) -> FinalityCandidate {
        FinalityCandidate {
            chain_hash: ChainHash::TESTNET4,
            txid: stored.txid,
            wtxid: stored.wtxid,
            exact_transaction_sha256: sha256::Hash::hash(&stored.tx_bytes).to_byte_array(),
            block_hash: BlockHash::from_byte_array([0x71; 32]),
            block_height: 100,
            corroborated_tip: 105,
            confirmations: 6,
            required_confirmations: 6,
            source_set_id: TEST_FINALITY_SOURCE_SET_ID,
            evidence_hash: [0x72; 32],
        }
    }

    async fn mount_genesis(server: &MockServer) {
        let genesis = genesis_block(Network::Testnet4);
        let hash = genesis.block_hash();
        Mock::given(method("GET"))
            .and(path("/api/block-height/0"))
            .respond_with(ResponseTemplate::new(200).set_body_string(hash.to_string()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/block/{hash}/raw")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(serialize(&genesis)))
            .mount(server)
            .await;
    }

    fn loopback_target(server: &MockServer) -> Testnet4EsploraBroadcastTarget {
        Testnet4EsploraBroadcastTarget::new_loopback(&format!("{}/api", server.uri()))
            .expect("loopback test target")
    }

    static DATABASE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[cfg(unix)]
    fn temporary_private_directory(label: &str) -> PathBuf {
        let suffix = DATABASE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("canonical test temporary directory");
        let path = root.join(format!(
            "xindex-vultisig-broadcast-{label}-{}-{suffix}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("private test database parent");
        path.canonicalize().expect("canonical private test parent")
    }

    #[cfg(unix)]
    fn temporary_database() -> PathBuf {
        temporary_private_directory("store").join("broadcast.sqlite")
    }

    #[cfg(unix)]
    fn remove_database_files(path: &Path) {
        for candidate in [
            path.to_path_buf(),
            PathBuf::from(format!("{}-journal", path.display())),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            match std::fs::remove_file(candidate) {
                Ok(()) | Err(_) => {}
            }
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }

    #[cfg(unix)]
    fn create_mode_file(path: &Path, mode: u32) {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .expect("create adversarial test file");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("set adversarial test file mode");
        file.sync_all().expect("sync adversarial test file");
    }

    #[cfg(unix)]
    fn remove_private_tree(path: &Path) {
        let canonical_temp = std::env::temp_dir()
            .canonicalize()
            .expect("canonical test temporary directory");
        assert!(path.starts_with(&canonical_temp));
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn successful_preparation_validation_returns_exact_identities() {
        let transaction = synthetic_transaction();
        let bytes = serialize(&transaction);
        let evidence_id = [0x22; 32];
        let identities = validate_preparation(&candidate(&transaction, &bytes, evidence_id))
            .expect("valid evidence view must prepare");

        assert_eq!(identities.txid, transaction.compute_txid());
        assert_eq!(identities.wtxid, transaction.compute_wtxid());
        assert_eq!(identities.evidence_id, evidence_id);
        assert_ne!(
            identities.txid.to_byte_array(),
            identities.wtxid.to_byte_array()
        );
    }

    #[test]
    fn exact_testnet4_chain_is_required() {
        let transaction = synthetic_transaction();
        let bytes = serialize(&transaction);
        let mut wrong_chain = candidate(&transaction, &bytes, [0x44; 32]);
        wrong_chain.chain_hash = ChainHash::TESTNET3;
        let error = validate_preparation(&wrong_chain).expect_err("Testnet3 evidence must fail");

        assert!(matches!(
            error,
            VultisigBroadcastPreparationError::WrongChain {
                actual: ChainHash::TESTNET3
            }
        ));
    }

    #[test]
    fn evidence_txid_and_wtxid_mismatches_fail_validation() {
        let transaction = synthetic_transaction();
        let bytes = serialize(&transaction);
        let mut wrong_txid = candidate(&transaction, &bytes, [0x55; 32]);
        wrong_txid.expected_txid = Txid::from_byte_array([0x66; 32]);
        let txid_error =
            validate_preparation(&wrong_txid).expect_err("substituted evidence txid must fail");
        assert!(matches!(
            txid_error,
            VultisigBroadcastPreparationError::TxidMismatch { .. }
        ));

        let mut wrong_wtxid = candidate(&transaction, &bytes, [0x55; 32]);
        wrong_wtxid.expected_wtxid = Wtxid::from_byte_array([0x77; 32]);
        let wtxid_error =
            validate_preparation(&wrong_wtxid).expect_err("substituted evidence wtxid must fail");
        assert!(matches!(
            wtxid_error,
            VultisigBroadcastPreparationError::WtxidMismatch { .. }
        ));
    }

    #[test]
    fn malformed_and_noncanonical_encodings_fail_closed() {
        let transaction = synthetic_transaction();
        let malformed = [0xff];
        let malformed_candidate = PreparationCandidate {
            chain_hash: ChainHash::TESTNET4,
            transaction_bytes: &malformed,
            expected_txid: transaction.compute_txid(),
            expected_wtxid: transaction.compute_wtxid(),
            evidence_id: [0x88; 32],
        };

        let malformed_error = validate_preparation(&malformed_candidate)
            .expect_err("malformed consensus bytes must fail");
        assert!(matches!(
            malformed_error,
            VultisigBroadcastPreparationError::Decode { .. }
        ));

        // rust-bitcoin's decoder rejects known non-minimal encodings before
        // this comparison. Exercise the independent re-encoding guard directly
        // so it cannot silently disappear if decoder behavior later changes.
        let mut noncanonical = serialize(&transaction);
        noncanonical.push(0x00);
        let canonical_error = require_canonical_encoding(noncanonical.as_slice(), &transaction)
            .expect_err("byte mismatch must fail canonicality");
        assert!(matches!(
            canonical_error,
            VultisigBroadcastPreparationError::NonCanonicalEncoding
        ));
    }

    #[test]
    fn production_target_rejects_unsafe_urls_and_redacts_debug() {
        for rejected in [
            "http://esplora.example/api",
            "https://127.0.0.1/api",
            "https://localhost/api",
            "https://node.localhost/api",
            "https://node.localhost./api",
            "https://user:secret@esplora.example/api",
            "https://esplora.example/api?token=secret",
            "https://esplora.example/api#fragment",
            "not-a-url",
        ] {
            let error =
                normalize_production_target_url(rejected).expect_err("unsafe target URL must fail");
            assert!(!error.to_string().contains(rejected));
        }
        let base_url = normalize_production_target_url("https://ESPLORA.example/api")
            .expect("valid HTTPS DNS target");
        let target = Testnet4EsploraBroadcastTarget {
            target_id: compute_target_id(&base_url, "operator-a", [0x31; 32], [0x32; 32]),
            base_url,
            client: async_client(broadcast_http_policy()).expect("test client"),
        };
        let debug = format!("{target:?}");
        assert!(!debug.contains("esplora.example"));
        assert!(!debug.contains("operator-a"));
    }

    #[test]
    fn production_target_requires_canonical_operator_identity() {
        for rejected in [
            "",
            "Operator-a",
            "operator a",
            "-operator-a",
            "operator-a-",
            "operator/a",
        ] {
            assert!(matches!(
                validate_operator_identity(rejected, [0x41; 32]),
                Err(VultisigBroadcastRuntimeError::Config(_))
            ));
        }
        assert!(matches!(
            validate_operator_identity("operator-a", [0; 32]),
            Err(VultisigBroadcastRuntimeError::Config(_))
        ));
        validate_operator_identity("operator-a:testnet4", [0x41; 32])
            .expect("canonical reviewed operator identity");
    }

    #[test]
    fn target_identity_binds_normalized_url_operator_record_and_pin_set() {
        let normalized = normalize_production_target_url("https://ESPLORA.EXAMPLE.:443/api")
            .expect("normalized production URL");
        let equivalent = normalize_production_target_url("https://esplora.example/api/")
            .expect("equivalent production URL");
        assert_eq!(normalized, equivalent);

        let identity = compute_target_id(&normalized, "operator-a", [0x51; 32], [0x52; 32]);
        assert_eq!(
            identity,
            compute_target_id(&equivalent, "operator-a", [0x51; 32], [0x52; 32])
        );
        let different_url = normalize_production_target_url("https://esplora.example/v2/")
            .expect("different production URL");
        assert_ne!(
            identity,
            compute_target_id(&different_url, "operator-a", [0x51; 32], [0x52; 32])
        );
        assert_ne!(
            identity,
            compute_target_id(&normalized, "operator-b", [0x51; 32], [0x52; 32])
        );
        assert_ne!(
            identity,
            compute_target_id(&normalized, "operator-a", [0x53; 32], [0x52; 32])
        );
        assert_ne!(
            identity,
            compute_target_id(&normalized, "operator-a", [0x51; 32], [0x54; 32])
        );
    }

    #[tokio::test]
    async fn production_store_rejects_non_path_and_memory_bypass_inputs() {
        let encoded_absolute = std::env::temp_dir().join("store%3Fmode%3Dmemory.sqlite");
        for rejected in [
            PathBuf::new(),
            PathBuf::from("relative.sqlite"),
            PathBuf::from(":memory:"),
            PathBuf::from("file::memory:?cache=shared"),
            PathBuf::from("file:///tmp/store.sqlite?mode=memory"),
            PathBuf::from("sqlite:///tmp/store.sqlite?mode%3Dmemory"),
            encoded_absolute,
        ] {
            assert!(matches!(
                SqliteVultisigBitcoinBroadcastStore::connect(&rejected).await,
                Err(VultisigBroadcastRuntimeError::Config(_))
            ));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn production_store_requires_canonical_private_parent() {
        let permissive_parent = temporary_private_directory("permissive-parent");
        std::fs::set_permissions(&permissive_parent, std::fs::Permissions::from_mode(0o755))
            .expect("make parent permissive");
        assert!(matches!(
            SqliteVultisigBitcoinBroadcastStore::connect(
                permissive_parent.join("broadcast.sqlite")
            )
            .await,
            Err(VultisigBroadcastRuntimeError::Config(_))
        ));
        remove_private_tree(&permissive_parent);

        let root = temporary_private_directory("noncanonical-parent");
        let real_parent = root.join("real");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&real_parent)
            .expect("real private parent");
        let noncanonical = real_parent.join("..").join("real").join("broadcast.sqlite");
        assert!(matches!(
            SqliteVultisigBitcoinBroadcastStore::connect(&noncanonical).await,
            Err(VultisigBroadcastRuntimeError::Config(_))
        ));

        let alias_parent = root.join("alias");
        symlink(&real_parent, &alias_parent).expect("symlinked parent");
        assert!(matches!(
            SqliteVultisigBitcoinBroadcastStore::connect(alias_parent.join("broadcast.sqlite"))
                .await,
            Err(VultisigBroadcastRuntimeError::Config(_))
        ));
        remove_private_tree(&root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn production_store_rejects_database_links_and_wrong_mode() {
        let symlink_parent = temporary_private_directory("database-symlink");
        let symlink_target = symlink_parent.join("actual.sqlite");
        create_mode_file(&symlink_target, 0o600);
        let symlink_path = symlink_parent.join("broadcast.sqlite");
        symlink(&symlink_target, &symlink_path).expect("database symlink");
        assert!(matches!(
            SqliteVultisigBitcoinBroadcastStore::connect(&symlink_path).await,
            Err(VultisigBroadcastRuntimeError::Config(_))
        ));
        remove_private_tree(&symlink_parent);

        let hardlink_parent = temporary_private_directory("database-hardlink");
        let hardlink_target = hardlink_parent.join("actual.sqlite");
        create_mode_file(&hardlink_target, 0o600);
        let hardlink_path = hardlink_parent.join("broadcast.sqlite");
        std::fs::hard_link(&hardlink_target, &hardlink_path).expect("database hard link");
        assert!(matches!(
            SqliteVultisigBitcoinBroadcastStore::connect(&hardlink_path).await,
            Err(VultisigBroadcastRuntimeError::Config(_))
        ));
        remove_private_tree(&hardlink_parent);

        let mode_parent = temporary_private_directory("database-mode");
        let mode_path = mode_parent.join("broadcast.sqlite");
        create_mode_file(&mode_path, 0o640);
        assert!(matches!(
            SqliteVultisigBitcoinBroadcastStore::connect(&mode_path).await,
            Err(VultisigBroadcastRuntimeError::Config(_))
        ));
        remove_private_tree(&mode_parent);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn production_store_rejects_every_preexisting_sidecar() {
        for suffix in ["-journal", "-wal", "-shm"] {
            let parent = temporary_private_directory("preexisting-sidecar");
            let database_path = parent.join("broadcast.sqlite");
            create_mode_file(&database_path, 0o600);
            create_mode_file(&sqlite_sidecar_path(&database_path, suffix), 0o600);
            assert!(matches!(
                SqliteVultisigBitcoinBroadcastStore::connect(&database_path).await,
                Err(VultisigBroadcastRuntimeError::Config(_))
            ));
            remove_private_tree(&parent);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn production_store_uses_fail_closed_sqlite_settings() {
        let database_path = temporary_database();
        let store = SqliteVultisigBitcoinBroadcastStore::connect(&database_path)
            .await
            .expect("secure store");
        let trusted_schema: i64 = sqlx::query_scalar("PRAGMA trusted_schema")
            .fetch_one(&store.pool)
            .await
            .expect("trusted_schema");
        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&store.pool)
            .await
            .expect("foreign_keys");
        let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(&store.pool)
            .await
            .expect("synchronous");
        let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&store.pool)
            .await
            .expect("journal_mode");
        let locking_mode: String = sqlx::query_scalar("PRAGMA locking_mode")
            .fetch_one(&store.pool)
            .await
            .expect("locking_mode");
        assert_eq!(trusted_schema, 0);
        assert_eq!(foreign_keys, 1);
        assert_eq!(synchronous, 2);
        assert_eq!(journal_mode, "delete");
        assert_eq!(locking_mode, "exclusive");
        store.revalidate_storage().expect("secure metadata");
        store.pool.close().await;
        drop(store);
        remove_database_files(&database_path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn production_store_rejects_path_replacement_after_open() {
        let database_path = temporary_database();
        let parent = database_path
            .parent()
            .expect("database parent")
            .to_path_buf();
        let moved_path = parent.join("moved.sqlite");
        let store = SqliteVultisigBitcoinBroadcastStore::connect(&database_path)
            .await
            .expect("secure store");
        std::fs::rename(&database_path, &moved_path).expect("move opened database path");
        create_mode_file(&database_path, 0o600);
        assert!(matches!(
            store.state([0x71; 32]).await,
            Err(VultisigBroadcastRuntimeError::Config(_))
        ));
        store.pool.close().await;
        drop(store);
        remove_private_tree(&parent);
    }

    #[tokio::test]
    async fn target_rejects_wrong_genesis() {
        let server = MockServer::start().await;
        let wrong = genesis_block(Network::Bitcoin);
        let hash = wrong.block_hash();
        Mock::given(method("GET"))
            .and(path("/api/block-height/0"))
            .respond_with(ResponseTemplate::new(200).set_body_string(hash.to_string()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/block/{hash}/raw")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(serialize(&wrong)))
            .mount(&server)
            .await;

        let error = loopback_target(&server)
            .authenticate_testnet4()
            .await
            .expect_err("mainnet genesis must fail");
        assert!(matches!(error, VultisigBroadcastRuntimeError::WrongGenesis));
    }

    #[tokio::test]
    async fn target_posts_lower_hex_of_exact_bytes_and_requires_exact_txid() {
        let server = MockServer::start().await;
        let target = loopback_target(&server);
        let stored = stored_candidate(&synthetic_transaction(), [0x10; 32], target.target_id());
        Mock::given(method("POST"))
            .and(path("/api/tx"))
            .and(body_bytes(encode_lower_hex(&stored.tx_bytes)))
            .respond_with(ResponseTemplate::new(200).set_body_string(stored.txid.to_string()))
            .expect(1)
            .mount(&server)
            .await;

        target
            .submit_exact(&stored)
            .await
            .expect("exact-byte submission");
    }

    #[tokio::test]
    async fn target_rejects_wrong_response_txid() {
        let server = MockServer::start().await;
        let target = loopback_target(&server);
        let stored = stored_candidate(&synthetic_transaction(), [0x11; 32], target.target_id());
        Mock::given(method("POST"))
            .and(path("/api/tx"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(Txid::from_byte_array([0x99; 32]).to_string()),
            )
            .mount(&server)
            .await;

        assert!(matches!(
            target.submit_exact(&stored).await,
            Err(VultisigBroadcastRuntimeError::ResponseTxidMismatch)
        ));
    }

    #[tokio::test]
    async fn reconciliation_accepts_only_exact_canonical_bytes() {
        let exact_server = MockServer::start().await;
        let exact_target = loopback_target(&exact_server);
        let exact = stored_candidate(
            &synthetic_transaction(),
            [0x12; 32],
            exact_target.target_id(),
        );
        Mock::given(method("GET"))
            .and(path(format!("/api/tx/{}/raw", exact.txid)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(exact.tx_bytes.clone()))
            .mount(&exact_server)
            .await;
        assert_eq!(
            exact_target
                .reconcile_exact(&exact)
                .await
                .expect("exact raw reconciliation"),
            Reconciliation::Exact
        );

        let conflict_server = MockServer::start().await;
        let conflict_target = loopback_target(&conflict_server);
        let conflict = stored_candidate(
            &synthetic_transaction(),
            [0x13; 32],
            conflict_target.target_id(),
        );
        let mut conflicting_transaction = synthetic_transaction();
        conflicting_transaction.output[0].value = Amount::from_sat(41_999);
        Mock::given(method("GET"))
            .and(path(format!("/api/tx/{}/raw", conflict.txid)))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(serialize(&conflicting_transaction)),
            )
            .mount(&conflict_server)
            .await;
        assert!(matches!(
            conflict_target.reconcile_exact(&conflict).await,
            Err(VultisigBroadcastRuntimeError::ConflictingTransaction)
        ));
    }

    #[tokio::test]
    async fn durable_prepare_is_idempotent_and_rejects_conflicts_and_corruption() {
        let store = SqliteVultisigBitcoinBroadcastStore::connect_memory_for_test()
            .await
            .expect("store");
        let candidate = stored_candidate(&synthetic_transaction(), [0x20; 32], [0x21; 32]);
        store
            .persist_candidate(&candidate)
            .await
            .expect("initial prepare");
        store
            .persist_candidate(&candidate)
            .await
            .expect("same-content prepare is idempotent");

        let mut conflict = candidate.clone();
        conflict.target_id = [0x22; 32];
        assert!(matches!(
            store.persist_candidate(&conflict).await,
            Err(VultisigBroadcastRuntimeError::EvidenceConflict)
        ));

        let mut record_conflict = candidate.clone();
        record_conflict.evidence_record.push(b' ');
        record_conflict.evidence_record_sha256 =
            sha256::Hash::hash(&record_conflict.evidence_record).to_byte_array();
        assert!(matches!(
            store.persist_candidate(&record_conflict).await,
            Err(VultisigBroadcastRuntimeError::EvidenceConflict)
        ));

        let mut bytes_conflict = stored_candidate(
            &{
                let mut changed = synthetic_transaction();
                changed.output[0].value = Amount::from_sat(41_999);
                changed
            },
            candidate.evidence_id,
            candidate.target_id,
        );
        bytes_conflict.evidence_record = candidate.evidence_record.clone();
        bytes_conflict.evidence_record_sha256 = candidate.evidence_record_sha256;
        assert!(matches!(
            store.persist_candidate(&bytes_conflict).await,
            Err(VultisigBroadcastRuntimeError::CorruptStore(_)
                | VultisigBroadcastRuntimeError::EvidenceConflict)
        ));

        let corrupted = vec![b'0'; candidate.evidence_record.len()];
        sqlx::query(
            "UPDATE vultisig_bitcoin_broadcasts SET evidence_record = ? WHERE evidence_id = ?",
        )
        .bind(corrupted)
        .bind(candidate.evidence_id.as_slice())
        .execute(&store.pool)
        .await
        .expect("inject corruption");
        assert!(matches!(
            store.state(candidate.evidence_id).await,
            Err(VultisigBroadcastRuntimeError::CorruptStore(_))
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sqlite_store_survives_restart_without_resetting_submitting() {
        let database_path = temporary_database();
        let candidate = stored_candidate(&synthetic_transaction(), [0x30; 32], [0x31; 32]);
        let store = SqliteVultisigBitcoinBroadcastStore::connect(&database_path)
            .await
            .expect("first open");
        store.persist_candidate(&candidate).await.expect("prepare");
        assert_eq!(
            store
                .begin_submission(candidate.evidence_id)
                .await
                .expect("claim"),
            BeginSubmission::Acquired
        );
        store.pool.close().await;
        drop(store);

        let reopened = SqliteVultisigBitcoinBroadcastStore::connect(&database_path)
            .await
            .expect("restart open");
        assert_eq!(
            reopened
                .state(candidate.evidence_id)
                .await
                .expect("restart state"),
            Some(VultisigBitcoinBroadcastState::Submitting)
        );
        reopened.pool.close().await;
        drop(reopened);
        remove_database_files(&database_path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn crash_after_commit_before_handle_return_is_discoverable_and_resumable() {
        let server = MockServer::start().await;
        mount_genesis(&server).await;
        let target = loopback_target(&server);
        let database_path = temporary_database();
        let candidate = stored_candidate(&synthetic_transaction(), [0x35; 32], target.target_id());
        let first_store = SqliteVultisigBitcoinBroadcastStore::connect(&database_path)
            .await
            .expect("first open");
        first_store
            .persist_candidate(&candidate)
            .await
            .expect("durable prepared row");
        first_store.pool.close().await;
        drop(first_store);

        let reopened = SqliteVultisigBitcoinBroadcastStore::connect(&database_path)
            .await
            .expect("restart open");
        let runtime =
            VultisigBitcoinBroadcastRuntime::new(reopened.clone(), target, test_finality_policy());
        let discovered = runtime
            .discover_prepared()
            .await
            .expect("discover committed row after simulated crash");
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].evidence_id(), candidate.evidence_id);
        assert_eq!(discovered[0].txid(), candidate.txid);
        assert!(server
            .received_requests()
            .await
            .expect("recorded requests")
            .is_empty());

        let resumed = runtime
            .resume_prepared(candidate.evidence_id)
            .await
            .expect("recover opaque handle");
        assert_eq!(resumed.evidence_id(), candidate.evidence_id);
        assert!(server
            .received_requests()
            .await
            .expect("recorded requests")
            .is_empty());

        Mock::given(method("POST"))
            .and(path("/api/tx"))
            .and(body_bytes(encode_lower_hex(&candidate.tx_bytes)))
            .respond_with(ResponseTemplate::new(200).set_body_string(candidate.txid.to_string()))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            runtime
                .submit(resumed)
                .await
                .expect("resume durable prepared row"),
            VultisigBitcoinBroadcastState::Accepted
        );
        assert!(runtime
            .discover_prepared()
            .await
            .expect("accepted row is not discoverable as prepared")
            .is_empty());
        assert!(matches!(
            runtime.resume_prepared(candidate.evidence_id).await,
            Err(VultisigBroadcastRuntimeError::NotPrepared)
        ));
        reopened.pool.close().await;
        drop(runtime);
        drop(reopened);
        remove_database_files(&database_path);
    }

    #[tokio::test]
    async fn submission_cannot_start_without_a_durable_prepared_row() {
        let server = MockServer::start().await;
        let target = loopback_target(&server);
        let store = SqliteVultisigBitcoinBroadcastStore::connect_memory_for_test()
            .await
            .expect("store");
        let candidate = stored_candidate(&synthetic_transaction(), [0x39; 32], target.target_id());
        let forged_only_inside_module_test = prepared_handle(&candidate);
        let runtime = VultisigBitcoinBroadcastRuntime::new(store, target, test_finality_policy());

        let error = runtime
            .submit(forged_only_inside_module_test)
            .await
            .expect_err("a handle without its durable row must fail closed");
        assert!(matches!(
            error.error(),
            VultisigBroadcastRuntimeError::NotFound
        ));
        assert!(server
            .received_requests()
            .await
            .expect("recorded requests")
            .is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn concurrent_submission_cas_allows_one_exact_post() {
        let server = MockServer::start().await;
        mount_genesis(&server).await;
        let target = loopback_target(&server);
        let database_path = temporary_database();
        let store = SqliteVultisigBitcoinBroadcastStore::connect(&database_path)
            .await
            .expect("store");
        let candidate = stored_candidate(&synthetic_transaction(), [0x40; 32], target.target_id());
        store.persist_candidate(&candidate).await.expect("prepare");
        Mock::given(method("POST"))
            .and(path("/api/tx"))
            .and(body_bytes(encode_lower_hex(&candidate.tx_bytes)))
            .respond_with(ResponseTemplate::new(200).set_body_string(candidate.txid.to_string()))
            .expect(1)
            .mount(&server)
            .await;
        let runtime =
            VultisigBitcoinBroadcastRuntime::new(store.clone(), target, test_finality_policy());
        let first_handle = runtime
            .resume_prepared(candidate.evidence_id)
            .await
            .expect("first durable handle");
        let second_handle = runtime
            .resume_prepared(candidate.evidence_id)
            .await
            .expect("second durable handle");
        let first = runtime.submit(first_handle);
        let second = runtime.submit(second_handle);
        let (first_result, second_result) = tokio::join!(first, second);
        let accepted = [first_result.as_ref(), second_result.as_ref()]
            .iter()
            .filter(|result| matches!(result, Ok(VultisigBitcoinBroadcastState::Accepted)))
            .count();
        assert!(accepted >= 1);
        assert_eq!(
            store
                .state(candidate.evidence_id)
                .await
                .expect("final state"),
            Some(VultisigBitcoinBroadcastState::Accepted)
        );
        store.pool.close().await;
        drop(runtime);
        drop(store);
        remove_database_files(&database_path);
    }

    #[tokio::test]
    async fn wrong_post_response_leaves_durable_ambiguous_state() {
        let server = MockServer::start().await;
        mount_genesis(&server).await;
        let target = loopback_target(&server);
        let store = SqliteVultisigBitcoinBroadcastStore::connect_memory_for_test()
            .await
            .expect("store");
        let candidate = stored_candidate(&synthetic_transaction(), [0x45; 32], target.target_id());
        store.persist_candidate(&candidate).await.expect("prepare");
        Mock::given(method("POST"))
            .and(path("/api/tx"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(Txid::from_byte_array([0x98; 32]).to_string()),
            )
            .mount(&server)
            .await;
        let runtime =
            VultisigBitcoinBroadcastRuntime::new(store.clone(), target, test_finality_policy());
        let handle = runtime
            .resume_prepared(candidate.evidence_id)
            .await
            .expect("durable handle");
        assert!(matches!(
            runtime
                .submit(handle)
                .await
                .map_err(|failure| failure.into_parts().1),
            Err(VultisigBroadcastRuntimeError::ResponseTxidMismatch)
        ));
        assert_eq!(
            store
                .state(candidate.evidence_id)
                .await
                .expect("ambiguous state"),
            Some(VultisigBitcoinBroadcastState::Submitting)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn crash_ambiguity_reconciles_exact_bytes_after_restart() {
        let server = MockServer::start().await;
        mount_genesis(&server).await;
        let target = loopback_target(&server);
        let database_path = temporary_database();
        let candidate = stored_candidate(&synthetic_transaction(), [0x50; 32], target.target_id());
        let first_store = SqliteVultisigBitcoinBroadcastStore::connect(&database_path)
            .await
            .expect("first store");
        first_store
            .persist_candidate(&candidate)
            .await
            .expect("prepare");
        assert_eq!(
            first_store
                .begin_submission(candidate.evidence_id)
                .await
                .expect("submission began before crash"),
            BeginSubmission::Acquired
        );
        first_store.pool.close().await;
        drop(first_store);

        Mock::given(method("GET"))
            .and(path(format!("/api/tx/{}/raw", candidate.txid)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(candidate.tx_bytes.clone()))
            .mount(&server)
            .await;
        let restarted_store = SqliteVultisigBitcoinBroadcastStore::connect(&database_path)
            .await
            .expect("restarted store");
        let runtime = VultisigBitcoinBroadcastRuntime::new(
            restarted_store.clone(),
            target,
            test_finality_policy(),
        );
        assert!(matches!(
            runtime.resume_prepared(candidate.evidence_id).await,
            Err(VultisigBroadcastRuntimeError::NotPrepared)
        ));
        assert_eq!(
            runtime
                .reconcile(candidate.evidence_id)
                .await
                .expect("exact restart reconciliation"),
            VultisigBitcoinBroadcastState::Accepted
        );
        restarted_store.pool.close().await;
        drop(restarted_store);
        remove_database_files(&database_path);
    }

    #[tokio::test]
    async fn explicit_recovery_resubmits_only_after_absence_check() {
        let server = MockServer::start().await;
        mount_genesis(&server).await;
        let target = loopback_target(&server);
        let store = SqliteVultisigBitcoinBroadcastStore::connect_memory_for_test()
            .await
            .expect("store");
        let candidate = stored_candidate(&synthetic_transaction(), [0x60; 32], target.target_id());
        store.persist_candidate(&candidate).await.expect("prepare");
        assert_eq!(
            store
                .begin_submission(candidate.evidence_id)
                .await
                .expect("ambiguous claim"),
            BeginSubmission::Acquired
        );
        Mock::given(method("GET"))
            .and(path(format!("/api/tx/{}/raw", candidate.txid)))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/tx"))
            .and(body_bytes(encode_lower_hex(&candidate.tx_bytes)))
            .respond_with(ResponseTemplate::new(200).set_body_string(candidate.txid.to_string()))
            .expect(1)
            .mount(&server)
            .await;
        let runtime =
            VultisigBitcoinBroadcastRuntime::new(store.clone(), target, test_finality_policy());
        assert_eq!(
            runtime
                .recover_ambiguous(candidate.evidence_id)
                .await
                .expect("explicit exact-byte recovery"),
            VultisigBitcoinBroadcastState::Accepted
        );
    }

    #[test]
    fn finality_validation_binds_source_set_exact_bytes_and_confirmation_floor() {
        assert!(matches!(
            VultisigBitcoinFinalityPolicy::new([0; 32], MIN_FINALIZED_BITCOIN_CONFIRMATIONS),
            Err(VultisigBroadcastRuntimeError::Config(_))
        ));
        assert!(matches!(
            VultisigBitcoinFinalityPolicy::new(
                TEST_FINALITY_SOURCE_SET_ID,
                MIN_FINALIZED_BITCOIN_CONFIRMATIONS - 1
            ),
            Err(VultisigBroadcastRuntimeError::Config(_))
        ));

        let candidate = stored_candidate(&synthetic_transaction(), [0x73; 32], [0x74; 32]);
        let valid = finality_candidate(&candidate);
        validate_finality_candidate(&candidate, &valid).expect("matching finality capability");

        let mut wrong_source = valid;
        wrong_source.source_set_id = [0x75; 32];
        assert!(matches!(
            validate_finality_candidate(&candidate, &wrong_source),
            Err(VultisigBroadcastRuntimeError::FinalityMismatch(_))
        ));

        let mut wrong_bytes = valid;
        wrong_bytes.exact_transaction_sha256 = [0x76; 32];
        assert!(matches!(
            validate_finality_candidate(&candidate, &wrong_bytes),
            Err(VultisigBroadcastRuntimeError::FinalityMismatch(_))
        ));

        let mut below_floor = valid;
        below_floor.confirmations = 5;
        below_floor.corroborated_tip = 104;
        assert!(matches!(
            validate_finality_candidate(&candidate, &below_floor),
            Err(VultisigBroadcastRuntimeError::FinalityMismatch(_))
        ));
    }

    #[tokio::test]
    async fn durable_finality_requires_acceptance_and_is_terminal() {
        let store = SqliteVultisigBitcoinBroadcastStore::connect_memory_for_test()
            .await
            .expect("store");
        let target = Testnet4EsploraBroadcastTarget::new_loopback("http://127.0.0.1:9/api")
            .expect("non-contacted loopback target");
        let candidate = stored_candidate(&synthetic_transaction(), [0x77; 32], target.target_id());
        store.persist_candidate(&candidate).await.expect("prepare");
        let finality = finality_candidate(&candidate);
        let runtime =
            VultisigBitcoinBroadcastRuntime::new(store.clone(), target, test_finality_policy());

        assert!(matches!(
            runtime
                .finalize_candidate(candidate.evidence_id, finality)
                .await,
            Err(VultisigBroadcastRuntimeError::NotAccepted)
        ));
        assert_eq!(
            store
                .begin_submission(candidate.evidence_id)
                .await
                .expect("claim"),
            BeginSubmission::Acquired
        );
        store
            .mark_accepted(candidate.evidence_id)
            .await
            .expect("accept");
        runtime
            .finalize_candidate(candidate.evidence_id, finality)
            .await
            .expect("finalize");
        runtime
            .finalize_candidate(candidate.evidence_id, finality)
            .await
            .expect("idempotent finality");
        assert_eq!(
            store
                .state(candidate.evidence_id)
                .await
                .expect("final state"),
            Some(VultisigBitcoinBroadcastState::Finalized)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn finalized_state_and_evidence_survive_restart() {
        let database_path = temporary_database();
        let candidate = stored_candidate(&synthetic_transaction(), [0x79; 32], [0x7a; 32]);
        let finality = validate_finality_candidate(&candidate, &finality_candidate(&candidate))
            .expect("valid finality evidence");
        let store = SqliteVultisigBitcoinBroadcastStore::connect(&database_path)
            .await
            .expect("first store");
        store.persist_candidate(&candidate).await.expect("prepare");
        store
            .begin_submission(candidate.evidence_id)
            .await
            .expect("claim");
        store
            .mark_accepted(candidate.evidence_id)
            .await
            .expect("accept");
        store
            .mark_finalized(candidate.evidence_id, &finality)
            .await
            .expect("finalize");
        store.pool.close().await;
        drop(store);

        let reopened = SqliteVultisigBitcoinBroadcastStore::connect(&database_path)
            .await
            .expect("restart store");
        let stored = reopened
            .load(candidate.evidence_id)
            .await
            .expect("load finalized row")
            .expect("finalized row");
        assert_eq!(stored.state, VultisigBitcoinBroadcastState::Finalized);
        assert_eq!(stored.finality, Some(finality));
        reopened.pool.close().await;
        drop(reopened);
        remove_database_files(&database_path);
    }
}
