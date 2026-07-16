//! Durable write-ahead workflow for `BitGo` build and broadcast authorization.

use std::fmt;

use alloy_primitives::B256;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::psbt::Psbt;
use bitcoin::{Transaction, Txid};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx::{FromRow, Sqlite, Transaction as SqliteTransaction};
use xindex_bitgo_adapter::{
    build_request, send_request, spend_policy_commitment, validate_final_transaction, PolicyError,
    SpendPolicy,
};

use crate::{BuildCapture, WalletSnapshot};

/// Durable provider workflow phase. Transitions are monotonic; in particular,
/// a pending approval never releases the irreversible send reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowPhase {
    /// Exact policy and build request are reserved before provider I/O.
    BuildReserved,
    /// Provider PSBT was validated and durably retained.
    Built,
    /// Exact PSBT passed the independent intent gate and consumed its one-shot.
    IntentAuthorized,
    /// One exact user-signed transaction was validated and retained.
    UserSigned,
    /// Irreversible final-sign-and-broadcast call was claimed write-ahead.
    SendReserved,
    /// `BitGo` returned `202` and the request awaits approval/rebuild handling.
    PendingApproval,
    /// An independently resolved provider approval rejected the transaction.
    Rejected,
    /// Returned final transaction was validated and durably retained.
    Broadcast,
}

impl WorkflowPhase {
    fn parse(value: &str) -> Result<Self, WorkflowError> {
        match value {
            "build_reserved" => Ok(Self::BuildReserved),
            "built" => Ok(Self::Built),
            "intent_authorized" => Ok(Self::IntentAuthorized),
            "user_signed" => Ok(Self::UserSigned),
            "send_reserved" => Ok(Self::SendReserved),
            "pending_approval" => Ok(Self::PendingApproval),
            "rejected" => Ok(Self::Rejected),
            "broadcast" => Ok(Self::Broadcast),
            _ => Err(WorkflowError::CorruptState),
        }
    }
}

/// Result of reserving a build sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildReservation {
    /// This caller created the durable reservation.
    Created,
    /// An identical policy already owns the sequence in this phase.
    Existing(WorkflowPhase),
}

/// Result of atomically claiming the irreversible send boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendReservation {
    /// This caller may perform exactly one send request.
    Acquired,
    /// A send was already claimed; reconcile instead of sending again.
    Existing(WorkflowPhase),
}

/// Redacted durable-workflow failure.
#[derive(Debug, thiserror::Error)]
pub enum WorkflowError {
    /// A public production store must survive process restart.
    #[error("BitGo workflow database must be durable")]
    NonDurableDatabase,
    /// `SQLite` connection or statement failure. Database details are omitted.
    #[error("BitGo workflow database operation failed")]
    Database,
    /// Embedded migration failure.
    #[error("BitGo workflow database migration failed")]
    Migration,
    /// Local JSON serialization failure.
    #[error("BitGo workflow artifact encoding failed")]
    Encoding,
    /// Stored bytes or phase do not satisfy the schema-level invariants.
    #[error("BitGo workflow contains corrupt state")]
    CorruptState,
    /// The sequence ID is already bound to different immutable policy/artifacts.
    #[error("BitGo workflow sequence conflicts with existing immutable state")]
    Conflict,
    /// The requested transition is unsafe from the current durable phase.
    #[error("BitGo workflow transition is invalid from phase {phase:?}")]
    InvalidTransition {
        /// Current durable phase.
        phase: WorkflowPhase,
    },
    /// The independently verified intent expired before user-signature capture.
    #[error("BitGo workflow intent authorization expired before user signing")]
    AuthorizationExpired,
    /// Existing transaction-policy validation failed.
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

/// One durable workflow snapshot. Verified provider-response envelopes remain
/// in the database and append-only artifact table; this type exposes only
/// execution material.
#[derive(Clone)]
pub struct WorkflowRecord {
    sequence_id: String,
    policy_commitment: B256,
    phase: WorkflowPhase,
    build_request: Vec<u8>,
    build_response: Option<Vec<u8>>,
    unsigned_psbt: Option<Vec<u8>>,
    authorization_receipt: Option<Vec<u8>>,
    authorization_valid_until_unix: Option<i64>,
    half_signed_tx: Option<Vec<u8>>,
    send_request: Option<Vec<u8>>,
    send_response: Option<Vec<u8>>,
    pending_approval_id: Option<String>,
    transfer_id: Option<String>,
    txid: Option<[u8; 32]>,
    final_tx: Option<Vec<u8>>,
}

impl fmt::Debug for WorkflowRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowRecord")
            .field("sequence_id", &self.sequence_id)
            .field("policy_commitment", &self.policy_commitment)
            .field("phase", &self.phase)
            .field("build_request_bytes", &self.build_request.len())
            .field(
                "build_response_bytes",
                &byte_len(self.build_response.as_deref()),
            )
            .field(
                "unsigned_psbt_bytes",
                &byte_len(self.unsigned_psbt.as_deref()),
            )
            .field(
                "authorization_receipt_bytes",
                &byte_len(self.authorization_receipt.as_deref()),
            )
            .field(
                "authorization_valid_until_unix",
                &self.authorization_valid_until_unix,
            )
            .field(
                "half_signed_tx_bytes",
                &byte_len(self.half_signed_tx.as_deref()),
            )
            .field(
                "send_request_bytes",
                &byte_len(self.send_request.as_deref()),
            )
            .field(
                "send_response_bytes",
                &byte_len(self.send_response.as_deref()),
            )
            .field("pending_approval_id", &self.pending_approval_id)
            .field("transfer_id", &self.transfer_id)
            .field("txid", &self.txid.map(alloy_primitives::hex::encode))
            .field("final_tx_bytes", &byte_len(self.final_tx.as_deref()))
            .finish()
    }
}

impl WorkflowRecord {
    /// Stable idempotency key shared by build, send, and reconciliation.
    #[must_use]
    pub fn sequence_id(&self) -> &str {
        &self.sequence_id
    }

    /// Commitment to every independently certified spend-policy field.
    #[must_use]
    pub const fn policy_commitment(&self) -> B256 {
        self.policy_commitment
    }

    /// Current durable phase.
    #[must_use]
    pub const fn phase(&self) -> WorkflowPhase {
        self.phase
    }

    /// Decode the validated provider PSBT retained by the workflow.
    ///
    /// # Errors
    /// Corrupt stored BIP-174 bytes.
    pub fn unsigned_psbt(&self) -> Result<Option<Psbt>, WorkflowError> {
        self.unsigned_psbt
            .as_deref()
            .map(|bytes| Psbt::deserialize(bytes).map_err(|_| WorkflowError::CorruptState))
            .transpose()
    }

    /// Expiry of the independently verified intent authorization, if present.
    #[must_use]
    pub fn authorization_valid_until_unix(&self) -> Option<u64> {
        self.authorization_valid_until_unix
            .and_then(|value| u64::try_from(value).ok())
    }

    /// Decode the exact validated user-signed transaction.
    ///
    /// # Errors
    /// Corrupt stored Bitcoin transaction bytes.
    pub fn half_signed_transaction(&self) -> Result<Option<Transaction>, WorkflowError> {
        self.half_signed_tx
            .as_deref()
            .map(|bytes| deserialize(bytes).map_err(|_| WorkflowError::CorruptState))
            .transpose()
    }

    pub(crate) fn send_request_bytes(&self) -> Option<&[u8]> {
        self.send_request.as_deref()
    }

    /// Pending approval identifier, if the provider returned `202`.
    #[must_use]
    pub fn pending_approval_id(&self) -> Option<&str> {
        self.pending_approval_id.as_deref()
    }

    /// Provider transfer identifier after validated finalization.
    #[must_use]
    pub fn transfer_id(&self) -> Option<&str> {
        self.transfer_id.as_deref()
    }

    /// Bitcoin transaction ID after validated finalization.
    #[must_use]
    pub fn txid(&self) -> Option<Txid> {
        self.txid.map(Txid::from_byte_array)
    }

    /// Decode the exact final transaction retained after provider finalization.
    ///
    /// # Errors
    /// Corrupt stored Bitcoin transaction bytes.
    pub fn final_transaction(&self) -> Result<Option<Transaction>, WorkflowError> {
        self.final_tx
            .as_deref()
            .map(|bytes| deserialize(bytes).map_err(|_| WorkflowError::CorruptState))
            .transpose()
    }
}

fn byte_len(value: Option<&[u8]>) -> Option<usize> {
    value.map(<[u8]>::len)
}

/// SQLite-backed workflow and append-only provider artifact log.
#[derive(Clone)]
pub struct BitGoWorkflowStore {
    pool: SqlitePool,
}

impl fmt::Debug for BitGoWorkflowStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitGoWorkflowStore")
            .finish_non_exhaustive()
    }
}

impl BitGoWorkflowStore {
    /// Connect to one durable `SQLite` database and apply embedded migrations.
    ///
    /// # Errors
    /// Non-durable URL, database connection, or migration failure.
    pub async fn connect(database_url: &str) -> Result<Self, WorkflowError> {
        if is_in_memory_database_url(database_url) {
            return Err(WorkflowError::NonDurableDatabase);
        }
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .map_err(|_| WorkflowError::Database)?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|_| WorkflowError::Migration)?;
        Ok(Self { pool })
    }

    /// Reserve the sequence ID against the exact independent policy before
    /// any provider request. Identical retries are idempotent.
    ///
    /// # Errors
    /// Database failure or sequence/policy conflict.
    pub async fn reserve_build(
        &self,
        policy: &SpendPolicy,
    ) -> Result<BuildReservation, WorkflowError> {
        let commitment = spend_policy_commitment(policy);
        let request = encode_json(&build_request(policy)?)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| WorkflowError::Database)?;
        let inserted = sqlx::query(
            "INSERT INTO bitgo_workflows
                (sequence_id, policy_commitment, phase, build_request,
                 created_at_unix, updated_at_unix)
             VALUES (?, ?, 'build_reserved', ?, strftime('%s','now'), strftime('%s','now'))
             ON CONFLICT(sequence_id) DO NOTHING",
        )
        .bind(policy.sequence_id())
        .bind(commitment.as_slice())
        .bind(&request)
        .execute(&mut *transaction)
        .await
        .map_err(|_| WorkflowError::Database)?
        .rows_affected()
            == 1;
        let outcome = if inserted {
            append_artifact(
                &mut transaction,
                policy.sequence_id(),
                ArtifactKind::BuildRequest,
                &request,
            )
            .await?;
            BuildReservation::Created
        } else {
            let record = load_in_transaction(&mut transaction, policy.sequence_id()).await?;
            require_policy(&record, commitment, &request)?;
            BuildReservation::Existing(record.phase)
        };
        transaction
            .commit()
            .await
            .map_err(|_| WorkflowError::Database)?;
        Ok(outcome)
    }

    /// Retain the exact wallet response and one canonical snapshot of the
    /// validated hot/on-chain 2-of-3 topology before accepting a build.
    /// Identical observations are idempotent; changed provider key IDs fail.
    ///
    /// # Errors
    /// Policy mismatch, wallet rebinding, database failure, or unsafe phase.
    pub async fn record_wallet(
        &self,
        policy: &SpendPolicy,
        snapshot: &WalletSnapshot,
        raw_response: &[u8],
    ) -> Result<(), WorkflowError> {
        let commitment = spend_policy_commitment(policy);
        let build = encode_json(&build_request(policy)?)?;
        let canonical = canonical_wallet_snapshot(snapshot, policy)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| WorkflowError::Database)?;
        let record = load_in_transaction(&mut transaction, policy.sequence_id()).await?;
        require_policy(&record, commitment, &build)?;
        if record.phase != WorkflowPhase::BuildReserved {
            return Err(WorkflowError::InvalidTransition {
                phase: record.phase,
            });
        }
        let existing: Vec<(Vec<u8>,)> = sqlx::query_as(
            "SELECT payload FROM bitgo_workflow_artifacts
             WHERE sequence_id = ? AND kind = 'wallet_snapshot'
             ORDER BY ordinal ASC",
        )
        .bind(policy.sequence_id())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| WorkflowError::Database)?;
        match existing.as_slice() {
            [] => {}
            [(bytes,)] if bytes == &canonical => {}
            [(_bytes,)] => return Err(WorkflowError::Conflict),
            _ => return Err(WorkflowError::CorruptState),
        }
        append_artifact(
            &mut transaction,
            policy.sequence_id(),
            ArtifactKind::WalletResponse,
            raw_response,
        )
        .await?;
        append_artifact(
            &mut transaction,
            policy.sequence_id(),
            ArtifactKind::WalletSnapshot,
            &canonical,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| WorkflowError::Database)
    }

    /// Promote a reservation after the provider PSBT passes the exact adapter policy.
    /// A second byte-different provider envelope for the same valid PSBT is
    /// retained as another artifact without replacing the first response.
    ///
    /// # Errors
    /// Database, policy conflict, corrupt artifact, or invalid transition.
    pub async fn complete_build(
        &self,
        policy: &SpendPolicy,
        capture: &BuildCapture,
        raw_response: &[u8],
    ) -> Result<(), WorkflowError> {
        let commitment = spend_policy_commitment(policy);
        let request = encode_json(capture.request())?;
        let expected_request = encode_json(&build_request(policy)?)?;
        if request != expected_request {
            return Err(WorkflowError::Conflict);
        }
        xindex_bitgo_adapter::validate_unsigned(capture.psbt(), policy)?;
        let psbt = capture.psbt().serialize();
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| WorkflowError::Database)?;
        let record = load_in_transaction(&mut transaction, policy.sequence_id()).await?;
        require_policy(&record, commitment, &request)?;
        require_single_artifact(
            &mut transaction,
            policy.sequence_id(),
            ArtifactKind::WalletSnapshot,
        )
        .await?;
        match record.phase {
            WorkflowPhase::BuildReserved => {
                let changed = sqlx::query(
                    "UPDATE bitgo_workflows
                     SET phase = 'built', build_response = ?, unsigned_psbt = ?,
                         updated_at_unix = strftime('%s','now')
                     WHERE sequence_id = ? AND phase = 'build_reserved'",
                )
                .bind(raw_response)
                .bind(&psbt)
                .bind(policy.sequence_id())
                .execute(&mut *transaction)
                .await
                .map_err(|_| WorkflowError::Database)?
                .rows_affected();
                if changed != 1 {
                    return Err(WorkflowError::Conflict);
                }
            }
            phase
                if phase_at_least_built(phase)
                    && record.unsigned_psbt.as_deref() == Some(&psbt) => {}
            phase => return Err(WorkflowError::InvalidTransition { phase }),
        }
        append_artifact(
            &mut transaction,
            policy.sequence_id(),
            ArtifactKind::BuildResponse,
            raw_response,
        )
        .await?;
        append_artifact(
            &mut transaction,
            policy.sequence_id(),
            ArtifactKind::UnsignedPsbt,
            &psbt,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| WorkflowError::Database)
    }

    /// Bind the exact built PSBT to a receipt produced only after the
    /// provider-neutral custody gate consumed its intent one-shot.
    ///
    /// This transition is crate-private so external callers cannot manufacture
    /// the workflow authority required before user signing; the public entry
    /// point is `BitGoCoordinator::authorize_redeem`.
    ///
    /// # Errors
    /// Policy/txid mismatch, conflicting receipt, unsafe phase, or database
    /// failure.
    pub(crate) async fn record_intent_authorization(
        &self,
        policy: &SpendPolicy,
        spend_txid: Txid,
        valid_until_unix: u64,
        receipt: &[u8],
    ) -> Result<(), WorkflowError> {
        if receipt.is_empty() {
            return Err(WorkflowError::CorruptState);
        }
        let valid_until_unix =
            i64::try_from(valid_until_unix).map_err(|_| WorkflowError::CorruptState)?;
        let commitment = spend_policy_commitment(policy);
        let build = encode_json(&build_request(policy)?)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| WorkflowError::Database)?;
        let record = load_in_transaction(&mut transaction, policy.sequence_id()).await?;
        require_policy(&record, commitment, &build)?;
        let unsigned = record.unsigned_psbt()?.ok_or(WorkflowError::CorruptState)?;
        if unsigned.unsigned_tx.compute_txid() != spend_txid {
            return Err(WorkflowError::Conflict);
        }
        match record.phase {
            WorkflowPhase::Built => {
                let changed = sqlx::query(
                    "UPDATE bitgo_workflows
                     SET phase = 'intent_authorized', authorization_receipt = ?,
                         authorization_valid_until_unix = ?,
                         updated_at_unix = strftime('%s','now')
                     WHERE sequence_id = ? AND phase = 'built'",
                )
                .bind(receipt)
                .bind(valid_until_unix)
                .bind(policy.sequence_id())
                .execute(&mut *transaction)
                .await
                .map_err(|_| WorkflowError::Database)?
                .rows_affected();
                if changed != 1 {
                    return Err(WorkflowError::Conflict);
                }
            }
            phase
                if phase_at_least_authorized(phase)
                    && record.authorization_receipt.as_deref() == Some(receipt)
                    && record.authorization_valid_until_unix == Some(valid_until_unix) => {}
            phase => return Err(WorkflowError::InvalidTransition { phase }),
        }
        append_artifact(
            &mut transaction,
            policy.sequence_id(),
            ArtifactKind::IntentAuthorization,
            receipt,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| WorkflowError::Database)
    }

    /// Validate and durably retain the exact user-signed transaction and send
    /// body. No provider call occurs here.
    ///
    /// # Errors
    /// Signature/policy rejection, database failure, or unsafe transition.
    pub async fn record_user_signed(
        &self,
        policy: &SpendPolicy,
        unsigned: &Psbt,
        half_signed: &Transaction,
    ) -> Result<(), WorkflowError> {
        let record = self.load_for_policy(policy).await?;
        if !matches!(
            record.phase,
            WorkflowPhase::IntentAuthorized
                | WorkflowPhase::UserSigned
                | WorkflowPhase::SendReserved
                | WorkflowPhase::PendingApproval
                | WorkflowPhase::Rejected
                | WorkflowPhase::Broadcast
        ) {
            return Err(WorkflowError::InvalidTransition {
                phase: record.phase,
            });
        }
        let request = send_request(unsigned, half_signed, policy)?;
        self.record_user_signed_bytes(
            policy,
            &unsigned.serialize(),
            &serialize(half_signed),
            &encode_json(&request)?,
        )
        .await
    }

    async fn record_user_signed_bytes(
        &self,
        policy: &SpendPolicy,
        unsigned: &[u8],
        half_signed: &[u8],
        request: &[u8],
    ) -> Result<(), WorkflowError> {
        let commitment = spend_policy_commitment(policy);
        let build = encode_json(&build_request(policy)?)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| WorkflowError::Database)?;
        let record = load_in_transaction(&mut transaction, policy.sequence_id()).await?;
        require_policy(&record, commitment, &build)?;
        if record.unsigned_psbt.as_deref() != Some(unsigned) {
            return Err(WorkflowError::Conflict);
        }
        match record.phase {
            WorkflowPhase::IntentAuthorized => {
                require_single_artifact(
                    &mut transaction,
                    policy.sequence_id(),
                    ArtifactKind::IntentAuthorization,
                )
                .await?;
                let valid_until = record
                    .authorization_valid_until_unix
                    .ok_or(WorkflowError::CorruptState)?;
                let (now_unix,): (i64,) =
                    sqlx::query_as("SELECT CAST(strftime('%s','now') AS INTEGER)")
                        .fetch_one(&mut *transaction)
                        .await
                        .map_err(|_| WorkflowError::Database)?;
                if now_unix > valid_until {
                    return Err(WorkflowError::AuthorizationExpired);
                }
                let changed = sqlx::query(
                    "UPDATE bitgo_workflows
                     SET phase = 'user_signed', half_signed_tx = ?, send_request = ?,
                         updated_at_unix = strftime('%s','now')
                     WHERE sequence_id = ? AND phase = 'intent_authorized'",
                )
                .bind(half_signed)
                .bind(request)
                .bind(policy.sequence_id())
                .execute(&mut *transaction)
                .await
                .map_err(|_| WorkflowError::Database)?
                .rows_affected();
                if changed != 1 {
                    return Err(WorkflowError::Conflict);
                }
            }
            phase
                if matches!(
                    phase,
                    WorkflowPhase::UserSigned
                        | WorkflowPhase::SendReserved
                        | WorkflowPhase::PendingApproval
                        | WorkflowPhase::Rejected
                        | WorkflowPhase::Broadcast
                ) && record.half_signed_tx.as_deref() == Some(half_signed)
                    && record.send_request.as_deref() == Some(request) => {}
            phase => return Err(WorkflowError::InvalidTransition { phase }),
        }
        append_artifact(
            &mut transaction,
            policy.sequence_id(),
            ArtifactKind::UserSignedTx,
            half_signed,
        )
        .await?;
        append_artifact(
            &mut transaction,
            policy.sequence_id(),
            ArtifactKind::SendRequest,
            request,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| WorkflowError::Database)
    }

    #[cfg(test)]
    pub(crate) async fn record_user_signed_fixture(
        &self,
        policy: &SpendPolicy,
        unsigned: &Psbt,
    ) -> Result<(), WorkflowError> {
        self.record_intent_authorization_fixture(policy, unsigned, 9_223_372_036_854_775_807_u64)
            .await?;
        self.record_user_signed_bytes(
            policy,
            &unsigned.serialize(),
            b"validated-half-signed-test-fixture",
            br#"{"halfSigned":{"txHex":"test-fixture"}}"#,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn record_intent_authorization_fixture(
        &self,
        policy: &SpendPolicy,
        unsigned: &Psbt,
        valid_until_unix: u64,
    ) -> Result<(), WorkflowError> {
        self.record_intent_authorization(
            policy,
            unsigned.unsigned_tx.compute_txid(),
            valid_until_unix,
            b"validated-intent-authorization-test-fixture",
        )
        .await
    }

    /// Atomically reserve the one irreversible `BitGo` final-sign-and-broadcast call.
    /// A caller receiving `Existing` must reconcile and must not resend.
    ///
    /// # Errors
    /// Database/policy conflict or an unsafe pre-signature phase.
    pub async fn reserve_send(
        &self,
        policy: &SpendPolicy,
    ) -> Result<SendReservation, WorkflowError> {
        let commitment = spend_policy_commitment(policy);
        let build = encode_json(&build_request(policy)?)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| WorkflowError::Database)?;
        let record = load_in_transaction(&mut transaction, policy.sequence_id()).await?;
        require_policy(&record, commitment, &build)?;
        let outcome = match record.phase {
            WorkflowPhase::UserSigned => {
                let changed = sqlx::query(
                    "UPDATE bitgo_workflows
                     SET phase = 'send_reserved', updated_at_unix = strftime('%s','now')
                     WHERE sequence_id = ? AND phase = 'user_signed'",
                )
                .bind(policy.sequence_id())
                .execute(&mut *transaction)
                .await
                .map_err(|_| WorkflowError::Database)?
                .rows_affected();
                if changed != 1 {
                    return Err(WorkflowError::Conflict);
                }
                SendReservation::Acquired
            }
            phase @ (WorkflowPhase::SendReserved
            | WorkflowPhase::PendingApproval
            | WorkflowPhase::Rejected
            | WorkflowPhase::Broadcast) => SendReservation::Existing(phase),
            phase => return Err(WorkflowError::InvalidTransition { phase }),
        };
        transaction
            .commit()
            .await
            .map_err(|_| WorkflowError::Database)?;
        Ok(outcome)
    }

    /// Record an accepted request awaiting approval. This never releases the
    /// send reservation and therefore cannot authorize a blind retry.
    ///
    /// # Errors
    /// Invalid identifier, database failure, or unsafe transition.
    pub async fn record_pending_approval(
        &self,
        policy: &SpendPolicy,
        pending_approval_id: &str,
        raw_response: &[u8],
    ) -> Result<(), WorkflowError> {
        if !safe_provider_id(pending_approval_id) {
            return Err(WorkflowError::CorruptState);
        }
        let commitment = spend_policy_commitment(policy);
        let build = encode_json(&build_request(policy)?)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| WorkflowError::Database)?;
        let record = load_in_transaction(&mut transaction, policy.sequence_id()).await?;
        require_policy(&record, commitment, &build)?;
        match record.phase {
            WorkflowPhase::SendReserved => {
                let changed = sqlx::query(
                    "UPDATE bitgo_workflows
                     SET phase = 'pending_approval', pending_approval_id = ?, send_response = ?,
                         updated_at_unix = strftime('%s','now')
                     WHERE sequence_id = ? AND phase = 'send_reserved'",
                )
                .bind(pending_approval_id)
                .bind(raw_response)
                .bind(policy.sequence_id())
                .execute(&mut *transaction)
                .await
                .map_err(|_| WorkflowError::Database)?
                .rows_affected();
                if changed != 1 {
                    return Err(WorkflowError::Conflict);
                }
            }
            WorkflowPhase::PendingApproval
                if record.pending_approval_id.as_deref() == Some(pending_approval_id) => {}
            phase => return Err(WorkflowError::InvalidTransition { phase }),
        }
        append_artifact(
            &mut transaction,
            policy.sequence_id(),
            ArtifactKind::SendResponse,
            raw_response,
        )
        .await?;
        append_artifact(
            &mut transaction,
            policy.sequence_id(),
            ArtifactKind::PendingApproval,
            pending_approval_id.as_bytes(),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| WorkflowError::Database)
    }

    /// Retain one read-only pending-approval lookup while preserving the send lock.
    ///
    /// # Errors
    /// Approval mismatch, database failure, or unsafe phase.
    pub async fn record_approval_lookup(
        &self,
        policy: &SpendPolicy,
        approval_id: &str,
        raw_response: &[u8],
    ) -> Result<(), WorkflowError> {
        self.record_approval_artifact(
            policy,
            approval_id,
            ArtifactKind::PendingApprovalLookup,
            raw_response,
        )
        .await
    }

    /// Retain one read-only transfer-by-approval lookup while preserving the send lock.
    ///
    /// # Errors
    /// Approval mismatch, database failure, or unsafe phase.
    pub async fn record_approval_transfer_lookup(
        &self,
        policy: &SpendPolicy,
        approval_id: &str,
        raw_response: &[u8],
    ) -> Result<(), WorkflowError> {
        self.record_approval_artifact(
            policy,
            approval_id,
            ArtifactKind::ApprovalTransferLookup,
            raw_response,
        )
        .await
    }

    async fn record_approval_artifact(
        &self,
        policy: &SpendPolicy,
        approval_id: &str,
        kind: ArtifactKind,
        raw_response: &[u8],
    ) -> Result<(), WorkflowError> {
        if !safe_provider_id(approval_id) {
            return Err(WorkflowError::CorruptState);
        }
        let commitment = spend_policy_commitment(policy);
        let build = encode_json(&build_request(policy)?)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| WorkflowError::Database)?;
        let record = load_in_transaction(&mut transaction, policy.sequence_id()).await?;
        require_policy(&record, commitment, &build)?;
        if record.phase != WorkflowPhase::PendingApproval
            || record.pending_approval_id.as_deref() != Some(approval_id)
        {
            return Err(WorkflowError::InvalidTransition {
                phase: record.phase,
            });
        }
        append_artifact(&mut transaction, policy.sequence_id(), kind, raw_response).await?;
        transaction
            .commit()
            .await
            .map_err(|_| WorkflowError::Database)
    }

    /// Mark an independently rejected approval as terminal and retain its response.
    ///
    /// # Errors
    /// Approval mismatch, database failure, or unsafe phase.
    pub async fn record_approval_rejected(
        &self,
        policy: &SpendPolicy,
        approval_id: &str,
        raw_response: &[u8],
    ) -> Result<(), WorkflowError> {
        if !safe_provider_id(approval_id) {
            return Err(WorkflowError::CorruptState);
        }
        let commitment = spend_policy_commitment(policy);
        let build = encode_json(&build_request(policy)?)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| WorkflowError::Database)?;
        let record = load_in_transaction(&mut transaction, policy.sequence_id()).await?;
        require_policy(&record, commitment, &build)?;
        if record.pending_approval_id.as_deref() != Some(approval_id) {
            return Err(WorkflowError::Conflict);
        }
        match record.phase {
            WorkflowPhase::PendingApproval => {
                let changed = sqlx::query(
                    "UPDATE bitgo_workflows
                     SET phase = 'rejected', updated_at_unix = strftime('%s','now')
                     WHERE sequence_id = ? AND phase = 'pending_approval'",
                )
                .bind(policy.sequence_id())
                .execute(&mut *transaction)
                .await
                .map_err(|_| WorkflowError::Database)?
                .rows_affected();
                if changed != 1 {
                    return Err(WorkflowError::Conflict);
                }
            }
            WorkflowPhase::Rejected => {}
            phase => return Err(WorkflowError::InvalidTransition { phase }),
        }
        append_artifact(
            &mut transaction,
            policy.sequence_id(),
            ArtifactKind::PendingApprovalLookup,
            raw_response,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| WorkflowError::Database)
    }

    /// Validate and persist the exact final transaction returned by `BitGo`.
    ///
    /// # Errors
    /// Policy/signature/txid mismatch, database failure, or unsafe transition.
    pub async fn record_broadcast(
        &self,
        policy: &SpendPolicy,
        transfer_id: &str,
        txid: Txid,
        final_tx: &Transaction,
        raw_response: &[u8],
    ) -> Result<(), WorkflowError> {
        self.record_broadcast_inner(
            policy,
            transfer_id,
            txid,
            final_tx,
            WorkflowPhase::SendReserved,
            Some(raw_response),
        )
        .await
    }

    pub(crate) async fn record_approved_broadcast(
        &self,
        policy: &SpendPolicy,
        transfer_id: &str,
        txid: Txid,
        final_tx: &Transaction,
    ) -> Result<(), WorkflowError> {
        self.record_broadcast_inner(
            policy,
            transfer_id,
            txid,
            final_tx,
            WorkflowPhase::PendingApproval,
            None,
        )
        .await
    }

    async fn record_broadcast_inner(
        &self,
        policy: &SpendPolicy,
        transfer_id: &str,
        txid: Txid,
        final_tx: &Transaction,
        source_phase: WorkflowPhase,
        raw_response: Option<&[u8]>,
    ) -> Result<(), WorkflowError> {
        if !safe_provider_id(transfer_id) {
            return Err(WorkflowError::CorruptState);
        }
        let commitment = spend_policy_commitment(policy);
        let build = encode_json(&build_request(policy)?)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| WorkflowError::Database)?;
        let record = load_in_transaction(&mut transaction, policy.sequence_id()).await?;
        require_policy(&record, commitment, &build)?;
        let unsigned = record.unsigned_psbt()?.ok_or(WorkflowError::CorruptState)?;
        validate_final_transaction(&unsigned, final_tx, txid, policy)?;
        let txid_bytes = txid.to_byte_array();
        let final_bytes = serialize(final_tx);
        match record.phase {
            phase if phase == source_phase => {
                let changed = match source_phase {
                    WorkflowPhase::SendReserved => sqlx::query(
                        "UPDATE bitgo_workflows
                         SET phase = 'broadcast', send_response = ?, transfer_id = ?, txid = ?,
                             final_tx = ?, updated_at_unix = strftime('%s','now')
                         WHERE sequence_id = ? AND phase = 'send_reserved'",
                    )
                    .bind(raw_response.ok_or(WorkflowError::CorruptState)?)
                    .bind(transfer_id)
                    .bind(&txid_bytes[..])
                    .bind(&final_bytes)
                    .bind(policy.sequence_id())
                    .execute(&mut *transaction)
                    .await
                    .map_err(|_| WorkflowError::Database)?
                    .rows_affected(),
                    WorkflowPhase::PendingApproval => sqlx::query(
                        "UPDATE bitgo_workflows
                         SET phase = 'broadcast', transfer_id = ?, txid = ?, final_tx = ?,
                             updated_at_unix = strftime('%s','now')
                         WHERE sequence_id = ? AND phase = 'pending_approval'",
                    )
                    .bind(transfer_id)
                    .bind(&txid_bytes[..])
                    .bind(&final_bytes)
                    .bind(policy.sequence_id())
                    .execute(&mut *transaction)
                    .await
                    .map_err(|_| WorkflowError::Database)?
                    .rows_affected(),
                    phase => return Err(WorkflowError::InvalidTransition { phase }),
                };
                if changed != 1 {
                    return Err(WorkflowError::Conflict);
                }
            }
            WorkflowPhase::Broadcast
                if record.transfer_id.as_deref() == Some(transfer_id)
                    && record.txid == Some(txid_bytes)
                    && record.final_tx.as_deref() == Some(&final_bytes) => {}
            phase => return Err(WorkflowError::InvalidTransition { phase }),
        }
        if let Some(raw_response) = raw_response {
            append_artifact(
                &mut transaction,
                policy.sequence_id(),
                ArtifactKind::SendResponse,
                raw_response,
            )
            .await?;
        }
        append_artifact(
            &mut transaction,
            policy.sequence_id(),
            ArtifactKind::FinalTx,
            &final_bytes,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| WorkflowError::Database)
    }

    /// Retain one bounded transfer lookup without mutating workflow authority.
    ///
    /// # Errors
    /// Missing/conflicting workflow or database failure.
    pub async fn record_transfer_lookup(
        &self,
        policy: &SpendPolicy,
        raw_response: &[u8],
    ) -> Result<(), WorkflowError> {
        let commitment = spend_policy_commitment(policy);
        let build = encode_json(&build_request(policy)?)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| WorkflowError::Database)?;
        let record = load_in_transaction(&mut transaction, policy.sequence_id()).await?;
        require_policy(&record, commitment, &build)?;
        append_artifact(
            &mut transaction,
            policy.sequence_id(),
            ArtifactKind::TransferLookup,
            raw_response,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| WorkflowError::Database)
    }

    /// Load one workflow by sequence ID.
    ///
    /// # Errors
    /// Missing/corrupt row or database failure.
    pub async fn load(&self, sequence_id: &str) -> Result<WorkflowRecord, WorkflowError> {
        load_from_pool(&self.pool, sequence_id).await
    }

    /// Load a workflow only if its full immutable policy still matches.
    pub(crate) async fn load_for_policy(
        &self,
        policy: &SpendPolicy,
    ) -> Result<WorkflowRecord, WorkflowError> {
        let commitment = spend_policy_commitment(policy);
        let build = encode_json(&build_request(policy)?)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| WorkflowError::Database)?;
        let record = load_in_transaction(&mut transaction, policy.sequence_id()).await?;
        require_policy(&record, commitment, &build)?;
        transaction
            .commit()
            .await
            .map_err(|_| WorkflowError::Database)?;
        Ok(record)
    }

    pub(crate) async fn evidence_snapshot(
        &self,
        policy: &SpendPolicy,
    ) -> Result<(WorkflowRecord, Vec<EvidenceArtifactRow>), WorkflowError> {
        let commitment = spend_policy_commitment(policy);
        let build = encode_json(&build_request(policy)?)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| WorkflowError::Database)?;
        let record = load_in_transaction(&mut transaction, policy.sequence_id()).await?;
        require_policy(&record, commitment, &build)?;
        let rows = sqlx::query_as::<_, RawEvidenceArtifactRow>(
            "SELECT ordinal, kind, payload_sha256, payload, created_at_unix
             FROM bitgo_workflow_artifacts
             WHERE sequence_id = ?
             ORDER BY ordinal ASC",
        )
        .bind(policy.sequence_id())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| WorkflowError::Database)?;
        let mut artifacts = Vec::with_capacity(rows.len());
        for (expected_ordinal, row) in rows.into_iter().enumerate() {
            let ordinal = u64::try_from(row.ordinal).map_err(|_| WorkflowError::CorruptState)?;
            if ordinal
                != u64::try_from(expected_ordinal).map_err(|_| WorkflowError::CorruptState)?
            {
                return Err(WorkflowError::CorruptState);
            }
            let kind = ArtifactKind::parse(&row.kind)?;
            let payload_sha256: [u8; 32] = row
                .payload_sha256
                .try_into()
                .map_err(|_| WorkflowError::CorruptState)?;
            if <[u8; 32]>::from(Sha256::digest(&row.payload)) != payload_sha256 {
                return Err(WorkflowError::CorruptState);
            }
            artifacts.push(EvidenceArtifactRow {
                ordinal,
                kind: kind.as_str().to_owned(),
                payload_sha256,
                payload_bytes: u64::try_from(row.payload.len())
                    .map_err(|_| WorkflowError::CorruptState)?,
                created_at_unix: u64::try_from(row.created_at_unix)
                    .map_err(|_| WorkflowError::CorruptState)?,
            });
        }
        if artifacts.is_empty() {
            return Err(WorkflowError::CorruptState);
        }
        transaction
            .commit()
            .await
            .map_err(|_| WorkflowError::Database)?;
        Ok((record, artifacts))
    }

    #[cfg(test)]
    pub(crate) async fn in_memory() -> Result<Self, WorkflowError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .map_err(|_| WorkflowError::Database)?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|_| WorkflowError::Migration)?;
        Ok(Self { pool })
    }
}

#[derive(FromRow)]
struct RawWorkflowRow {
    sequence_id: String,
    policy_commitment: Vec<u8>,
    phase: String,
    build_request: Vec<u8>,
    build_response: Option<Vec<u8>>,
    unsigned_psbt: Option<Vec<u8>>,
    authorization_receipt: Option<Vec<u8>>,
    authorization_valid_until_unix: Option<i64>,
    half_signed_tx: Option<Vec<u8>>,
    send_request: Option<Vec<u8>>,
    send_response: Option<Vec<u8>>,
    pending_approval_id: Option<String>,
    transfer_id: Option<String>,
    txid: Option<Vec<u8>>,
    final_tx: Option<Vec<u8>>,
}

#[derive(FromRow)]
struct RawEvidenceArtifactRow {
    ordinal: i64,
    kind: String,
    payload_sha256: Vec<u8>,
    payload: Vec<u8>,
    created_at_unix: i64,
}

pub(crate) struct EvidenceArtifactRow {
    pub(crate) ordinal: u64,
    pub(crate) kind: String,
    pub(crate) payload_sha256: [u8; 32],
    pub(crate) payload_bytes: u64,
    pub(crate) created_at_unix: u64,
}

impl TryFrom<RawWorkflowRow> for WorkflowRecord {
    type Error = WorkflowError;

    fn try_from(row: RawWorkflowRow) -> Result<Self, Self::Error> {
        let policy_commitment = B256::from_slice(
            row.policy_commitment
                .get(..32)
                .filter(|_| row.policy_commitment.len() == 32)
                .ok_or(WorkflowError::CorruptState)?,
        );
        let txid = row
            .txid
            .map(|bytes| bytes.try_into().map_err(|_| WorkflowError::CorruptState))
            .transpose()?;
        let phase = WorkflowPhase::parse(&row.phase)?;
        let has_authorization = match (
            row.authorization_receipt.as_deref(),
            row.authorization_valid_until_unix,
        ) {
            (None, None) => false,
            (Some(receipt), Some(valid_until)) if !receipt.is_empty() && valid_until >= 0 => true,
            _ => return Err(WorkflowError::CorruptState),
        };
        if has_authorization != phase_at_least_authorized(phase) {
            return Err(WorkflowError::CorruptState);
        }
        Ok(Self {
            sequence_id: row.sequence_id,
            policy_commitment,
            phase,
            build_request: row.build_request,
            build_response: row.build_response,
            unsigned_psbt: row.unsigned_psbt,
            authorization_receipt: row.authorization_receipt,
            authorization_valid_until_unix: row.authorization_valid_until_unix,
            half_signed_tx: row.half_signed_tx,
            send_request: row.send_request,
            send_response: row.send_response,
            pending_approval_id: row.pending_approval_id,
            transfer_id: row.transfer_id,
            txid,
            final_tx: row.final_tx,
        })
    }
}

const WORKFLOW_COLUMNS: &str =
    "sequence_id, policy_commitment, phase, build_request, build_response, unsigned_psbt,
     authorization_receipt, authorization_valid_until_unix, half_signed_tx, send_request,
     send_response, pending_approval_id, transfer_id, txid, final_tx";

async fn load_from_pool(
    pool: &SqlitePool,
    sequence_id: &str,
) -> Result<WorkflowRecord, WorkflowError> {
    let query = format!("SELECT {WORKFLOW_COLUMNS} FROM bitgo_workflows WHERE sequence_id = ?");
    let row = sqlx::query_as::<_, RawWorkflowRow>(&query)
        .bind(sequence_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| WorkflowError::Database)?
        .ok_or(WorkflowError::CorruptState)?;
    row.try_into()
}

async fn load_in_transaction(
    transaction: &mut SqliteTransaction<'_, Sqlite>,
    sequence_id: &str,
) -> Result<WorkflowRecord, WorkflowError> {
    let query = format!("SELECT {WORKFLOW_COLUMNS} FROM bitgo_workflows WHERE sequence_id = ?");
    let row = sqlx::query_as::<_, RawWorkflowRow>(&query)
        .bind(sequence_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| WorkflowError::Database)?
        .ok_or(WorkflowError::CorruptState)?;
    row.try_into()
}

fn require_policy(
    record: &WorkflowRecord,
    commitment: B256,
    build_request: &[u8],
) -> Result<(), WorkflowError> {
    if record.policy_commitment != commitment || record.build_request != build_request {
        Err(WorkflowError::Conflict)
    } else {
        Ok(())
    }
}

const fn phase_at_least_built(phase: WorkflowPhase) -> bool {
    !matches!(phase, WorkflowPhase::BuildReserved)
}

const fn phase_at_least_authorized(phase: WorkflowPhase) -> bool {
    !matches!(phase, WorkflowPhase::BuildReserved | WorkflowPhase::Built)
}

#[derive(Clone, Copy)]
enum ArtifactKind {
    BuildRequest,
    WalletResponse,
    WalletSnapshot,
    BuildResponse,
    UnsignedPsbt,
    IntentAuthorization,
    UserSignedTx,
    SendRequest,
    SendResponse,
    PendingApproval,
    PendingApprovalLookup,
    ApprovalTransferLookup,
    FinalTx,
    TransferLookup,
}

impl ArtifactKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BuildRequest => "build_request",
            Self::WalletResponse => "wallet_response",
            Self::WalletSnapshot => "wallet_snapshot",
            Self::BuildResponse => "build_response",
            Self::UnsignedPsbt => "unsigned_psbt",
            Self::IntentAuthorization => "intent_authorization",
            Self::UserSignedTx => "user_signed_tx",
            Self::SendRequest => "send_request",
            Self::SendResponse => "send_response",
            Self::PendingApproval => "pending_approval",
            Self::PendingApprovalLookup => "pending_approval_lookup",
            Self::ApprovalTransferLookup => "approval_transfer_lookup",
            Self::FinalTx => "final_tx",
            Self::TransferLookup => "transfer_lookup",
        }
    }

    fn parse(value: &str) -> Result<Self, WorkflowError> {
        match value {
            "build_request" => Ok(Self::BuildRequest),
            "wallet_response" => Ok(Self::WalletResponse),
            "wallet_snapshot" => Ok(Self::WalletSnapshot),
            "build_response" => Ok(Self::BuildResponse),
            "unsigned_psbt" => Ok(Self::UnsignedPsbt),
            "intent_authorization" => Ok(Self::IntentAuthorization),
            "user_signed_tx" => Ok(Self::UserSignedTx),
            "send_request" => Ok(Self::SendRequest),
            "send_response" => Ok(Self::SendResponse),
            "pending_approval" => Ok(Self::PendingApproval),
            "pending_approval_lookup" => Ok(Self::PendingApprovalLookup),
            "approval_transfer_lookup" => Ok(Self::ApprovalTransferLookup),
            "final_tx" => Ok(Self::FinalTx),
            "transfer_lookup" => Ok(Self::TransferLookup),
            _ => Err(WorkflowError::CorruptState),
        }
    }
}

async fn require_single_artifact(
    transaction: &mut SqliteTransaction<'_, Sqlite>,
    sequence_id: &str,
    kind: ArtifactKind,
) -> Result<(), WorkflowError> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM bitgo_workflow_artifacts
         WHERE sequence_id = ? AND kind = ?",
    )
    .bind(sequence_id)
    .bind(kind.as_str())
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| WorkflowError::Database)?;
    if count == 1 {
        Ok(())
    } else {
        Err(WorkflowError::CorruptState)
    }
}

async fn append_artifact(
    transaction: &mut SqliteTransaction<'_, Sqlite>,
    sequence_id: &str,
    kind: ArtifactKind,
    payload: &[u8],
) -> Result<(), WorkflowError> {
    let hash: [u8; 32] = Sha256::digest(payload).into();
    let existing: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT payload FROM bitgo_workflow_artifacts
         WHERE sequence_id = ? AND kind = ? AND payload_sha256 = ?",
    )
    .bind(sequence_id)
    .bind(kind.as_str())
    .bind(&hash[..])
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| WorkflowError::Database)?;
    if let Some((bytes,)) = existing {
        return if bytes == payload {
            Ok(())
        } else {
            Err(WorkflowError::CorruptState)
        };
    }
    let (ordinal,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(MAX(ordinal) + 1, 0)
         FROM bitgo_workflow_artifacts WHERE sequence_id = ?",
    )
    .bind(sequence_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| WorkflowError::Database)?;
    sqlx::query(
        "INSERT INTO bitgo_workflow_artifacts
            (sequence_id, ordinal, kind, payload_sha256, payload, created_at_unix)
         VALUES (?, ?, ?, ?, ?, strftime('%s','now'))",
    )
    .bind(sequence_id)
    .bind(ordinal)
    .bind(kind.as_str())
    .bind(&hash[..])
    .bind(payload)
    .execute(&mut **transaction)
    .await
    .map_err(|_| WorkflowError::Database)?;
    Ok(())
}

fn encode_json(value: &impl Serialize) -> Result<Vec<u8>, WorkflowError> {
    serde_json::to_vec(value).map_err(|_| WorkflowError::Encoding)
}

#[derive(Serialize)]
struct CanonicalWalletSnapshot<'a> {
    schema_version: u32,
    wallet_id: &'a str,
    coin: &'static str,
    wallet_type: &'static str,
    multisig_type: &'static str,
    m: u8,
    n: u8,
    key_ids: &'a [String; 3],
}

fn canonical_wallet_snapshot(
    snapshot: &WalletSnapshot,
    policy: &SpendPolicy,
) -> Result<Vec<u8>, WorkflowError> {
    let key_ids = snapshot.key_ids();
    if snapshot.wallet_id() != policy.wallet().wallet_id()
        || snapshot.coin() != policy.wallet().coin()
        || key_ids.iter().any(|key| !safe_provider_id(key))
        || key_ids[0] == key_ids[1]
        || key_ids[0] == key_ids[2]
        || key_ids[1] == key_ids[2]
    {
        return Err(WorkflowError::Conflict);
    }
    encode_json(&CanonicalWalletSnapshot {
        schema_version: 1,
        wallet_id: snapshot.wallet_id(),
        coin: snapshot.coin().as_str(),
        wallet_type: "hot",
        multisig_type: "onchain",
        m: 2,
        n: 3,
        key_ids,
    })
}

fn is_in_memory_database_url(database_url: &str) -> bool {
    let normalized = database_url.to_ascii_lowercase();
    normalized.contains(":memory:")
        || normalized
            .split_once('?')
            .is_some_and(|(_, query)| query.split('&').any(|part| part == "mode=memory"))
}

fn safe_provider_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use bitcoin::hashes::Hash as _;
    use bitcoin::opcodes::all::OP_CHECKMULTISIG;
    use bitcoin::script::Builder;
    use bitcoin::{
        absolute::LockTime, psbt::Psbt, transaction::Version, Address, Amount, OutPoint, ScriptBuf,
        Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use xindex_bitgo_adapter::{
        build_request, parse_compressed_public_key, BitGoCoin, InputPolicy, SpendPolicy,
        WalletPolicy, P2WSH_EXTERNAL_CHAIN_CODE,
    };

    use super::{
        BitGoWorkflowStore, BuildCapture, BuildReservation, SendReservation, WorkflowError,
        WorkflowPhase,
    };
    use crate::{BitGoAuthVersion, BitGoEnvironment, WalletSnapshot};

    const USER_PUBKEY: &str = "03c10ac628c880629ed0fd2a0563a898f4882baca45e15668a4d3064cf1ea37988";
    const BACKUP_PUBKEY: &str =
        "03e56f84be4460080618ef869bb7b07096880760f748ba23efab533c2359f923bd";
    const BITGO_PUBKEY: &str = "020ae81372264b5eac5c9dc7fe0b9a32bad00771c3a2c71f6e2c971823c3182ed6";

    fn policy(memo: &[u8]) -> SpendPolicy {
        let user = parse_compressed_public_key(USER_PUBKEY).expect("user");
        let backup = parse_compressed_public_key(BACKUP_PUBKEY).expect("backup");
        let bitgo = parse_compressed_public_key(BITGO_PUBKEY).expect("BitGo");
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
        .expect("wallet");
        SpendPolicy::new(
            wallet,
            InputPolicy::new(
                OutPoint {
                    txid: Txid::from_byte_array([0x22; 32]),
                    vout: 0,
                },
                200_000,
            )
            .expect("input"),
            ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0xaa; 20])),
            100_000,
            memo.to_vec(),
            20_000,
            "xindex-redemption-1",
            true,
        )
        .expect("policy")
    }

    fn capture(policy: &SpendPolicy, change_sats: u64) -> BuildCapture {
        let request = build_request(policy).expect("request");
        let payout = Address::from_script(
            &ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0xaa; 20])),
            policy.wallet().coin().network(),
        )
        .expect("payout")
        .script_pubkey();
        let memo = ScriptBuf::from_bytes(
            alloy_primitives::hex::decode(
                request.recipients[1]
                    .address
                    .strip_prefix("scriptPubKey:")
                    .expect("memo prefix"),
            )
            .expect("memo"),
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
                    value: Amount::from_sat(change_sats),
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
        BuildCapture { request, psbt }
    }

    fn wallet_snapshot(key_ids: [&str; 3]) -> WalletSnapshot {
        WalletSnapshot {
            wallet_id: "wallet-1".to_owned(),
            coin: BitGoCoin::Tbtc4,
            key_ids: key_ids.map(str::to_owned),
        }
    }

    async fn record_wallet(store: &BitGoWorkflowStore, policy: &SpendPolicy) {
        store
            .record_wallet(
                policy,
                &wallet_snapshot(["user-key", "backup-key", "bitgo-key"]),
                br#"{"id":"wallet-1","coin":"tbtc4"}"#,
            )
            .await
            .expect("wallet evidence");
    }

    async fn record_authorization(store: &BitGoWorkflowStore, policy: &SpendPolicy, psbt: &Psbt) {
        store
            .record_intent_authorization_fixture(policy, psbt, 9_223_372_036_854_775_807_u64)
            .await
            .expect("intent authorization");
    }

    #[tokio::test]
    async fn public_connect_rejects_in_memory_databases() {
        assert!(matches!(
            BitGoWorkflowStore::connect("sqlite::memory:").await,
            Err(WorkflowError::NonDurableDatabase)
        ));
        assert!(matches!(
            BitGoWorkflowStore::connect("sqlite://workflow?mode=memory&cache=shared").await,
            Err(WorkflowError::NonDurableDatabase)
        ));
    }

    #[tokio::test]
    async fn reservation_is_idempotent_and_rejects_policy_rebinding() {
        let store = BitGoWorkflowStore::in_memory().await.expect("store");
        let first = policy(b"=:ETH.USDT:0xrecipient:990000");
        assert_eq!(
            store.reserve_build(&first).await.expect("reserve"),
            BuildReservation::Created
        );
        assert_eq!(
            store.reserve_build(&first).await.expect("idempotent"),
            BuildReservation::Existing(WorkflowPhase::BuildReserved)
        );
        let conflict = policy(b"=:ETH.USDC:0xrecipient:990000");
        assert!(matches!(
            store.reserve_build(&conflict).await,
            Err(WorkflowError::Conflict)
        ));
    }

    #[tokio::test]
    async fn build_completion_is_durable_and_idempotent() {
        let store = BitGoWorkflowStore::in_memory().await.expect("store");
        let policy = policy(b"=:ETH.USDT:0xrecipient:990000");
        let capture = capture(&policy, 89_000);
        store.reserve_build(&policy).await.expect("reserve");
        record_wallet(&store, &policy).await;
        store
            .complete_build(&policy, &capture, br#"{"txHex":"first"}"#)
            .await
            .expect("complete");
        store
            .complete_build(&policy, &capture, br#"{"txHex":"same-psbt-retry"}"#)
            .await
            .expect("idempotent retry");
        let record = store.load(policy.sequence_id()).await.expect("load");
        assert_eq!(record.phase(), WorkflowPhase::Built);
        assert_eq!(record.unsigned_psbt().expect("decode"), Some(capture.psbt));
        let manifest = store
            .evidence_manifest(BitGoEnvironment::Test, BitGoAuthVersion::V2, &policy)
            .await
            .expect("evidence manifest");
        assert_eq!(manifest.workflow_phase(), "built");
        assert_eq!(manifest.artifacts().len(), 6);
        assert!(manifest.signing_digest().is_ok());
    }

    #[tokio::test]
    async fn build_requires_one_immutable_wallet_snapshot() {
        let store = BitGoWorkflowStore::in_memory().await.expect("store");
        let policy = policy(b"=:ETH.USDT:0xrecipient:990000");
        let capture = capture(&policy, 89_000);
        store.reserve_build(&policy).await.expect("reserve");
        assert!(matches!(
            store
                .complete_build(&policy, &capture, br#"{"txHex":"build"}"#)
                .await,
            Err(WorkflowError::CorruptState)
        ));

        record_wallet(&store, &policy).await;
        store
            .record_wallet(
                &policy,
                &wallet_snapshot(["changed-user", "backup-key", "bitgo-key"]),
                br#"{"id":"wallet-1","coin":"tbtc4","changed":true}"#,
            )
            .await
            .expect_err("provider key rebinding must fail");
        store
            .complete_build(&policy, &capture, br#"{"txHex":"build"}"#)
            .await
            .expect("complete with immutable wallet evidence");
    }

    #[tokio::test]
    async fn user_signature_requires_durable_intent_authorization() {
        let store = BitGoWorkflowStore::in_memory().await.expect("store");
        let policy = policy(b"=:ETH.USDT:0xrecipient:990000");
        let capture = capture(&policy, 89_000);
        store.reserve_build(&policy).await.expect("reserve");
        record_wallet(&store, &policy).await;
        store
            .complete_build(&policy, &capture, br#"{"txHex":"build"}"#)
            .await
            .expect("complete");

        assert!(matches!(
            store
                .record_user_signed_bytes(
                    &policy,
                    &capture.psbt.serialize(),
                    b"validated-half-signed-fixture",
                    br#"{"halfSigned":{"txHex":"fixture"}}"#,
                )
                .await,
            Err(WorkflowError::InvalidTransition {
                phase: WorkflowPhase::Built
            })
        ));

        record_authorization(&store, &policy, &capture.psbt).await;
        let authorized = store.load(policy.sequence_id()).await.expect("authorized");
        assert_eq!(authorized.phase(), WorkflowPhase::IntentAuthorized);
        store
            .record_user_signed_bytes(
                &policy,
                &capture.psbt.serialize(),
                b"validated-half-signed-fixture",
                br#"{"halfSigned":{"txHex":"fixture"}}"#,
            )
            .await
            .expect("user signed");
        let manifest = store
            .evidence_manifest(BitGoEnvironment::Test, BitGoAuthVersion::V2, &policy)
            .await
            .expect("manifest");
        assert!(manifest
            .artifacts()
            .iter()
            .any(|artifact| artifact.kind() == "intent_authorization"));
    }

    #[tokio::test]
    async fn expired_intent_authorization_cannot_accept_user_signature() {
        let store = BitGoWorkflowStore::in_memory().await.expect("store");
        let policy = policy(b"=:ETH.USDT:0xrecipient:990000");
        let capture = capture(&policy, 89_000);
        store.reserve_build(&policy).await.expect("reserve");
        record_wallet(&store, &policy).await;
        store
            .complete_build(&policy, &capture, br#"{"txHex":"build"}"#)
            .await
            .expect("complete");
        store
            .record_intent_authorization_fixture(&policy, &capture.psbt, 0)
            .await
            .expect("expired authorization fixture");

        assert!(matches!(
            store
                .record_user_signed_bytes(
                    &policy,
                    &capture.psbt.serialize(),
                    b"validated-half-signed-fixture",
                    br#"{"halfSigned":{"txHex":"fixture"}}"#,
                )
                .await,
            Err(WorkflowError::AuthorizationExpired)
        ));
        assert_eq!(
            store
                .load(policy.sequence_id())
                .await
                .expect("workflow")
                .phase(),
            WorkflowPhase::IntentAuthorized
        );
    }

    #[tokio::test]
    async fn send_reservation_is_atomic_and_never_blindly_released() {
        let store = BitGoWorkflowStore::in_memory().await.expect("store");
        let policy = policy(b"=:ETH.USDT:0xrecipient:990000");
        let capture = capture(&policy, 89_000);
        store.reserve_build(&policy).await.expect("reserve");
        record_wallet(&store, &policy).await;
        store
            .complete_build(&policy, &capture, br#"{"txHex":"build"}"#)
            .await
            .expect("complete");
        record_authorization(&store, &policy, &capture.psbt).await;
        store
            .record_user_signed_bytes(
                &policy,
                &capture.psbt.serialize(),
                b"validated-half-signed-fixture",
                br#"{"halfSigned":{"txHex":"fixture"}}"#,
            )
            .await
            .expect("user signed");
        assert_eq!(
            store.reserve_send(&policy).await.expect("first claim"),
            SendReservation::Acquired
        );
        assert_eq!(
            store.reserve_send(&policy).await.expect("second claim"),
            SendReservation::Existing(WorkflowPhase::SendReserved)
        );
        let record = store.load(policy.sequence_id()).await.expect("load");
        assert_eq!(record.phase(), WorkflowPhase::SendReserved);
    }

    #[tokio::test]
    async fn pending_approval_never_releases_the_send_reservation() {
        let store = BitGoWorkflowStore::in_memory().await.expect("store");
        let policy = policy(b"=:ETH.USDT:0xrecipient:990000");
        let first = capture(&policy, 89_000);
        store.reserve_build(&policy).await.expect("reserve");
        record_wallet(&store, &policy).await;
        store
            .complete_build(&policy, &first, br#"{"txHex":"first"}"#)
            .await
            .expect("complete");
        record_authorization(&store, &policy, &first.psbt).await;
        store
            .record_user_signed_bytes(
                &policy,
                &first.psbt.serialize(),
                b"validated-half-signed-fixture",
                br#"{"halfSigned":{"txHex":"fixture"}}"#,
            )
            .await
            .expect("user signed");
        store.reserve_send(&policy).await.expect("send reserve");
        store
            .record_pending_approval(&policy, "approval-1", br#"{"id":"approval-1"}"#)
            .await
            .expect("pending");

        assert_eq!(
            store.reserve_send(&policy).await.expect("second claim"),
            SendReservation::Existing(WorkflowPhase::PendingApproval)
        );
        let record = store.load(policy.sequence_id()).await.expect("load");
        assert_eq!(record.phase(), WorkflowPhase::PendingApproval);
        assert_eq!(record.pending_approval_id(), Some("approval-1"));
    }

    #[tokio::test]
    async fn rejected_approval_is_terminal_and_retains_lookup_evidence() {
        let store = BitGoWorkflowStore::in_memory().await.expect("store");
        let policy = policy(b"=:ETH.USDT:0xrecipient:990000");
        let capture = capture(&policy, 89_000);
        store.reserve_build(&policy).await.expect("reserve");
        record_wallet(&store, &policy).await;
        store
            .complete_build(&policy, &capture, br#"{"txHex":"build"}"#)
            .await
            .expect("complete");
        record_authorization(&store, &policy, &capture.psbt).await;
        store
            .record_user_signed_bytes(
                &policy,
                &capture.psbt.serialize(),
                b"validated-half-signed-fixture",
                br#"{"halfSigned":{"txHex":"fixture"}}"#,
            )
            .await
            .expect("user signed");
        store.reserve_send(&policy).await.expect("send reserve");
        store
            .record_pending_approval(&policy, "approval-1", br#"{"state":"pending"}"#)
            .await
            .expect("pending");
        store
            .record_approval_rejected(&policy, "approval-1", br#"{"state":"rejected"}"#)
            .await
            .expect("rejected");

        assert_eq!(
            store.reserve_send(&policy).await.expect("terminal claim"),
            SendReservation::Existing(WorkflowPhase::Rejected)
        );
        let manifest = store
            .evidence_manifest(BitGoEnvironment::Test, BitGoAuthVersion::V2, &policy)
            .await
            .expect("manifest");
        assert_eq!(manifest.workflow_phase(), "rejected");
        assert!(manifest
            .artifacts()
            .iter()
            .any(|artifact| artifact.kind() == "pending_approval_lookup"));
    }
}
