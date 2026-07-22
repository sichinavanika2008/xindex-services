//! Durable authority-owned storage for sealed Vultisig keysign operations.
//!
//! The public adapter deliberately has no deserializer for
//! [`AuthorizedVultisigKeysign`]. This journal is the persistence authority: it
//! accepts only a live authorization capability, stores its private recovery
//! record before network use, and can rehydrate that record only from its own
//! target-bound database. A caller cannot turn arbitrary JSON into an
//! authorization through the Rust API.

use std::collections::HashSet;
use std::fmt;
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_primitives::hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqlitePool, SqlitePoolOptions,
    SqliteSynchronous,
};
use sqlx::Row as _;
use xindex_custody_core::prepare::PreparedSpend;
use xindex_shared::chain_registry::ChainId;

use crate::request::{
    build_from_parts, restore_bitcoin_authorization, BitcoinAuthorizationBinding,
    VultisigBitcoinEvidenceConfig, VultisigPublicKey, VultisigVaultConfig,
};
use crate::AuthorizedVultisigKeysign;

const AUTHORIZATION_SCHEMA: &str = "xindex-vultisig-keysign-authorization-v2";
const MAX_AUTHORIZATION_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONNECTOR_STATE_BYTES: usize = 1024 * 1024;
const MAX_PREPARE_KEY_BYTES: usize = 4 * 1024;

/// Fail-closed durable keysign journal error.
#[derive(Debug, thiserror::Error)]
pub enum VultisigKeysignJournalError {
    /// Static storage or target configuration is unsafe.
    #[error("invalid Vultisig keysign journal configuration: {0}")]
    Config(&'static str),
    /// Durable storage failed.
    #[error("Vultisig keysign journal storage failed")]
    Storage,
    /// Stored state is malformed or disagrees with its commitments.
    #[error("Vultisig keysign journal is corrupt: {0}")]
    Corrupt(&'static str),
    /// Another in-process capability already owns the session.
    #[error("Vultisig keysign journal session is already active")]
    Active,
}

impl From<sqlx::Error> for VultisigKeysignJournalError {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}

impl From<sqlx::migrate::MigrateError> for VultisigKeysignJournalError {
    fn from(_: sqlx::migrate::MigrateError) -> Self {
        Self::Storage
    }
}

/// Opaque non-cloneable ownership claim for one durable journal row.
#[expect(
    missing_debug_implementations,
    reason = "Debug is deliberately omitted from the durable session claim"
)]
pub struct VultisigKeysignJournalClaim {
    session_id: String,
    active_sessions: Arc<Mutex<HashSet<String>>>,
}

impl VultisigKeysignJournalClaim {
    /// Exact `UUIDv4` session owned by this claim.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

impl Drop for VultisigKeysignJournalClaim {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active_sessions.lock() {
            active.remove(&self.session_id);
        }
    }
}

/// One recovered authorization, connector state, and exclusive local claim.
#[expect(
    missing_debug_implementations,
    reason = "Debug would expose the recovered sealed authorization"
)]
pub struct RecoveredVultisigKeysign {
    request: AuthorizedVultisigKeysign,
    connector_state: Box<[u8]>,
    claim: VultisigKeysignJournalClaim,
}

/// Commitment-only tombstone proving that one completed signing session was
/// durably accepted by its downstream consumer.
///
/// The terminal row retains no authorization, transaction, encryption key, or
/// connector state. Its fixed-width identities are sufficient to prevent the
/// session from becoming fresh work again and to reconcile a cancellation
/// after the terminal database commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VultisigKeysignTerminalReceipt {
    session: String,
    completion: [u8; 32],
    downstream_consumer: [u8; 32],
    downstream_receipt: [u8; 32],
}

impl VultisigKeysignTerminalReceipt {
    /// Exact completed Vultisig session.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session
    }

    /// Domain-separated commitment to the locally verified transaction and
    /// exact relay/verifier receipt.
    #[must_use]
    pub const fn completion_id(&self) -> [u8; 32] {
        self.completion
    }

    /// Stable identity of the downstream persistence boundary.
    #[must_use]
    pub const fn downstream_consumer_id(&self) -> [u8; 32] {
        self.downstream_consumer
    }

    /// Exact durable receipt issued by that downstream boundary.
    #[must_use]
    pub const fn downstream_receipt_id(&self) -> [u8; 32] {
        self.downstream_receipt
    }
}

impl RecoveredVultisigKeysign {
    /// Consume the recovery result into the sealed request, connector-owned
    /// state, and its exclusive local claim.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        AuthorizedVultisigKeysign,
        Box<[u8]>,
        VultisigKeysignJournalClaim,
    ) {
        (self.request, self.connector_state, self.claim)
    }
}

/// Target-bound, file-backed journal for authorized keysign operations.
///
/// The database is not an encrypted or independently authenticated store. Its
/// Unix metadata boundary rejects other-user access, links, permissive modes,
/// unexpected sidecars, and path replacement, but same-UID modification or a
/// copied database remains an operational trust residual.
#[derive(Clone)]
pub struct SqliteVultisigKeysignJournal {
    pool: SqlitePool,
    target_id: [u8; 32],
    active_sessions: Arc<Mutex<HashSet<String>>>,
    #[cfg(unix)]
    secure_binding: Arc<SecureSqliteBinding>,
}

impl fmt::Debug for SqliteVultisigKeysignJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteVultisigKeysignJournal")
            .field("target_id", &self.target_id)
            .finish_non_exhaustive()
    }
}

impl SqliteVultisigKeysignJournal {
    /// Open an owner-only journal bound to one exact connector target.
    ///
    /// `database_path` must be an absolute canonical path below an existing
    /// canonical 0700 directory. The database is created as 0600 when absent.
    /// Production opening is rejected on non-Unix platforms because equivalent
    /// owner/link/mode checks are not implemented there.
    ///
    /// # Errors
    /// Unsafe path metadata, target mismatch, migration, or `SQLite` failure.
    pub async fn connect(
        database_path: impl AsRef<Path>,
        target_id: [u8; 32],
    ) -> Result<Self, VultisigKeysignJournalError> {
        if target_id == [0; 32] {
            return Err(VultisigKeysignJournalError::Config(
                "connector target identity must be non-zero",
            ));
        }
        open_secure_journal(database_path.as_ref(), target_id).await
    }

    /// Persist the sealed authorization and connector state before network use.
    ///
    /// A session ID and exact authorization may each be inserted only once.
    /// Existing rows must be recovered; they are never treated as a fresh
    /// preparation that may POST again under a different session identity.
    ///
    /// # Errors
    /// Invalid session/state, duplicate session/authorization, corrupt storage,
    /// or write failure.
    pub async fn persist(
        &self,
        session_id: &str,
        request: &AuthorizedVultisigKeysign,
        connector_state: &[u8],
    ) -> Result<VultisigKeysignJournalClaim, VultisigKeysignJournalError> {
        validate_session_id(session_id)?;
        validate_connector_state(connector_state)?;
        let claim = self.claim(session_id)?;
        if self.terminal_handoff(session_id).await?.is_some() {
            return Err(VultisigKeysignJournalError::Corrupt(
                "session already reached terminal handoff",
            ));
        }
        let authorization = serde_json::to_vec(&StoredAuthorization::from_request(request)?)
            .map_err(|_| VultisigKeysignJournalError::Corrupt("authorization encode failed"))?;
        if authorization.is_empty() || authorization.len() > MAX_AUTHORIZATION_BYTES {
            return Err(VultisigKeysignJournalError::Corrupt(
                "authorization size is invalid",
            ));
        }
        let authorization_sha256: [u8; 32] = Sha256::digest(&authorization).into();
        let connector_state_sha256: [u8; 32] = Sha256::digest(connector_state).into();
        self.revalidate_storage()?;
        let terminal_authorization_exists: i64 = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM vultisig_keysign_terminal_handoffs
                 WHERE authorization_sha256 = ?
             )",
        )
        .bind(authorization_sha256.as_slice())
        .fetch_one(&self.pool)
        .await?;
        if terminal_authorization_exists != 0 {
            return Err(VultisigKeysignJournalError::Corrupt(
                "authorization already reached terminal handoff",
            ));
        }
        let result = sqlx::query(
            "INSERT INTO vultisig_keysign_journal
             (session_id, target_id, authorization, authorization_sha256,
              connector_state, connector_state_sha256)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT DO NOTHING",
        )
        .bind(session_id)
        .bind(self.target_id.as_slice())
        .bind(&authorization)
        .bind(authorization_sha256.as_slice())
        .bind(connector_state)
        .bind(connector_state_sha256.as_slice())
        .execute(&self.pool)
        .await?;
        self.revalidate_storage()?;
        if result.rows_affected() != 1 {
            return Err(VultisigKeysignJournalError::Corrupt(
                "session or authorization already has a durable row",
            ));
        }
        Ok(claim)
    }

    /// Replace the connector-owned state for the claimed session durably.
    ///
    /// # Errors
    /// Foreign/stale claim, invalid state, missing row, or write failure.
    pub async fn checkpoint(
        &self,
        claim: &VultisigKeysignJournalClaim,
        connector_state: &[u8],
    ) -> Result<(), VultisigKeysignJournalError> {
        self.validate_claim(claim)?;
        validate_connector_state(connector_state)?;
        let state_sha256: [u8; 32] = Sha256::digest(connector_state).into();
        self.revalidate_storage()?;
        let result = sqlx::query(
            "UPDATE vultisig_keysign_journal
             SET connector_state = ?, connector_state_sha256 = ?,
                 updated_at_unix = unixepoch()
             WHERE session_id = ? AND target_id = ?",
        )
        .bind(connector_state)
        .bind(state_sha256.as_slice())
        .bind(claim.session_id())
        .bind(self.target_id.as_slice())
        .execute(&self.pool)
        .await?;
        self.revalidate_storage()?;
        if result.rows_affected() != 1 {
            return Err(VultisigKeysignJournalError::Corrupt(
                "claimed session row is missing or target-mismatched",
            ));
        }
        Ok(())
    }

    /// Atomically replace one claimed secret-bearing live row with a
    /// commitment-only terminal handoff tombstone.
    ///
    /// The caller must first durably persist the completed transaction and
    /// exact session receipt in the named downstream consumer. A failed or
    /// cancelled transaction leaves the live row intact and recoverable once
    /// the in-process claim is dropped.
    ///
    /// # Errors
    /// A foreign/stale claim, zero commitment, missing/corrupt live row,
    /// duplicate terminal handoff, or storage failure fails closed.
    pub async fn acknowledge_handoff(
        &self,
        claim: &VultisigKeysignJournalClaim,
        completion_id: [u8; 32],
        downstream_consumer_id: [u8; 32],
        downstream_receipt_id: [u8; 32],
    ) -> Result<VultisigKeysignTerminalReceipt, VultisigKeysignJournalError> {
        self.validate_claim(claim)?;
        validate_terminal_commitment(completion_id)?;
        validate_terminal_commitment(downstream_consumer_id)?;
        validate_terminal_commitment(downstream_receipt_id)?;
        self.revalidate_storage()?;

        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT target_id, authorization, authorization_sha256,
                    connector_state, connector_state_sha256
             FROM vultisig_keysign_journal WHERE session_id = ?",
        )
        .bind(claim.session_id())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(VultisigKeysignJournalError::Corrupt(
            "claimed session row is missing",
        ))?;
        let target_id = exact_array::<32>(row.try_get::<Vec<u8>, _>("target_id")?)?;
        if target_id != self.target_id {
            return Err(VultisigKeysignJournalError::Corrupt(
                "stored connector target differs from the open journal",
            ));
        }
        let authorization_sha256 =
            exact_array::<32>(row.try_get::<Vec<u8>, _>("authorization_sha256")?)?;
        let authorization: Vec<u8> = row.try_get("authorization")?;
        if authorization.is_empty()
            || authorization.len() > MAX_AUTHORIZATION_BYTES
            || <[u8; 32]>::from(Sha256::digest(&authorization)) != authorization_sha256
        {
            return Err(VultisigKeysignJournalError::Corrupt(
                "authorization commitment is invalid",
            ));
        }
        let connector_state_sha256 =
            exact_array::<32>(row.try_get::<Vec<u8>, _>("connector_state_sha256")?)?;
        let connector_state: Vec<u8> = row.try_get("connector_state")?;
        validate_connector_state(&connector_state)?;
        if <[u8; 32]>::from(Sha256::digest(&connector_state)) != connector_state_sha256 {
            return Err(VultisigKeysignJournalError::Corrupt(
                "connector-state commitment is invalid",
            ));
        }
        let existing: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM vultisig_keysign_terminal_handoffs WHERE session_id = ?",
        )
        .bind(claim.session_id())
        .fetch_optional(&mut *transaction)
        .await?;
        if existing.is_some() {
            return Err(VultisigKeysignJournalError::Corrupt(
                "session already reached terminal handoff",
            ));
        }

        let inserted = sqlx::query(
            "INSERT INTO vultisig_keysign_terminal_handoffs
             (session_id, target_id, authorization_sha256,
              connector_state_sha256, completion_id,
              downstream_consumer_id, downstream_receipt_id)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(claim.session_id())
        .bind(self.target_id.as_slice())
        .bind(authorization_sha256.as_slice())
        .bind(connector_state_sha256.as_slice())
        .bind(completion_id.as_slice())
        .bind(downstream_consumer_id.as_slice())
        .bind(downstream_receipt_id.as_slice())
        .execute(&mut *transaction)
        .await?;
        let deleted = sqlx::query(
            "DELETE FROM vultisig_keysign_journal
             WHERE session_id = ? AND target_id = ?
               AND authorization_sha256 = ? AND connector_state_sha256 = ?",
        )
        .bind(claim.session_id())
        .bind(self.target_id.as_slice())
        .bind(authorization_sha256.as_slice())
        .bind(connector_state_sha256.as_slice())
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() != 1 || deleted.rows_affected() != 1 {
            return Err(VultisigKeysignJournalError::Corrupt(
                "terminal handoff did not replace exactly one live row",
            ));
        }
        transaction.commit().await?;
        self.revalidate_storage()?;

        Ok(VultisigKeysignTerminalReceipt {
            session: claim.session_id().to_string(),
            completion: completion_id,
            downstream_consumer: downstream_consumer_id,
            downstream_receipt: downstream_receipt_id,
        })
    }

    /// Read a commitment-only terminal receipt for crash/cancellation
    /// reconciliation.
    ///
    /// # Errors
    /// Invalid session identity, target mismatch, coexisting live/terminal
    /// state, malformed commitments, or storage failure.
    pub async fn terminal_handoff(
        &self,
        session_id: &str,
    ) -> Result<Option<VultisigKeysignTerminalReceipt>, VultisigKeysignJournalError> {
        validate_session_id(session_id)?;
        self.revalidate_storage()?;
        let row = sqlx::query(
            "SELECT target_id, authorization_sha256, connector_state_sha256,
                    completion_id, downstream_consumer_id, downstream_receipt_id
             FROM vultisig_keysign_terminal_handoffs WHERE session_id = ?",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            self.revalidate_storage()?;
            return Ok(None);
        };
        let target_id = exact_array::<32>(row.try_get::<Vec<u8>, _>("target_id")?)?;
        if target_id != self.target_id {
            return Err(VultisigKeysignJournalError::Corrupt(
                "stored connector target differs from the open journal",
            ));
        }
        let _authorization_sha256 =
            exact_array::<32>(row.try_get::<Vec<u8>, _>("authorization_sha256")?)?;
        let _connector_state_sha256 =
            exact_array::<32>(row.try_get::<Vec<u8>, _>("connector_state_sha256")?)?;
        let completion_id = exact_array::<32>(row.try_get::<Vec<u8>, _>("completion_id")?)?;
        let downstream_consumer_id =
            exact_array::<32>(row.try_get::<Vec<u8>, _>("downstream_consumer_id")?)?;
        let downstream_receipt_id =
            exact_array::<32>(row.try_get::<Vec<u8>, _>("downstream_receipt_id")?)?;
        validate_terminal_commitment(completion_id)?;
        validate_terminal_commitment(downstream_consumer_id)?;
        validate_terminal_commitment(downstream_receipt_id)?;
        let live: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM vultisig_keysign_journal WHERE session_id = ?")
                .bind(session_id)
                .fetch_optional(&self.pool)
                .await?;
        self.revalidate_storage()?;
        if live.is_some() {
            return Err(VultisigKeysignJournalError::Corrupt(
                "live and terminal session rows coexist",
            ));
        }
        Ok(Some(VultisigKeysignTerminalReceipt {
            session: session_id.to_string(),
            completion: completion_id,
            downstream_consumer: downstream_consumer_id,
            downstream_receipt: downstream_receipt_id,
        }))
    }

    /// List inactive session rows available for explicit recovery.
    ///
    /// # Errors
    /// Storage failure or malformed session/target data.
    pub async fn recoverable_sessions(&self) -> Result<Vec<String>, VultisigKeysignJournalError> {
        self.revalidate_storage()?;
        let rows = sqlx::query(
            "SELECT session_id, target_id FROM vultisig_keysign_journal ORDER BY session_id",
        )
        .fetch_all(&self.pool)
        .await?;
        self.revalidate_storage()?;
        let active = self
            .active_sessions
            .lock()
            .map_err(|_| VultisigKeysignJournalError::Storage)?;
        let mut sessions = Vec::with_capacity(rows.len());
        for row in rows {
            let session_id: String = row.try_get("session_id")?;
            validate_session_id(&session_id)?;
            let target_id = exact_array(row.try_get::<Vec<u8>, _>("target_id")?)?;
            if target_id != self.target_id {
                return Err(VultisigKeysignJournalError::Corrupt(
                    "stored connector target differs from the open journal",
                ));
            }
            if !active.contains(&session_id) {
                sessions.push(session_id);
            }
        }
        Ok(sessions)
    }

    /// Recover the exact sealed authorization and most recent connector state.
    ///
    /// Recovery acquires an in-process ownership claim. Dropping the returned
    /// claim makes the same durable row recoverable again; no row is deleted.
    ///
    /// # Errors
    /// Missing/active session, target mismatch, corruption, or storage failure.
    pub async fn recover(
        &self,
        session_id: &str,
    ) -> Result<RecoveredVultisigKeysign, VultisigKeysignJournalError> {
        validate_session_id(session_id)?;
        let claim = self.claim(session_id)?;
        self.revalidate_storage()?;
        let row = sqlx::query(
            "SELECT target_id, authorization, authorization_sha256,
                    connector_state, connector_state_sha256
             FROM vultisig_keysign_journal WHERE session_id = ?",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(VultisigKeysignJournalError::Corrupt(
            "requested session row is missing",
        ))?;
        self.revalidate_storage()?;
        let target_id = exact_array(row.try_get::<Vec<u8>, _>("target_id")?)?;
        if target_id != self.target_id {
            return Err(VultisigKeysignJournalError::Corrupt(
                "stored connector target differs from the open journal",
            ));
        }
        let authorization: Vec<u8> = row.try_get("authorization")?;
        let authorization_sha256 =
            exact_array::<32>(row.try_get::<Vec<u8>, _>("authorization_sha256")?)?;
        let actual_authorization_sha256: [u8; 32] = Sha256::digest(&authorization).into();
        if authorization.is_empty()
            || authorization.len() > MAX_AUTHORIZATION_BYTES
            || actual_authorization_sha256 != authorization_sha256
        {
            return Err(VultisigKeysignJournalError::Corrupt(
                "authorization commitment is invalid",
            ));
        }
        let connector_state: Vec<u8> = row.try_get("connector_state")?;
        let connector_state_sha256 =
            exact_array::<32>(row.try_get::<Vec<u8>, _>("connector_state_sha256")?)?;
        validate_connector_state(&connector_state)?;
        let actual_connector_state_sha256: [u8; 32] = Sha256::digest(&connector_state).into();
        if actual_connector_state_sha256 != connector_state_sha256 {
            return Err(VultisigKeysignJournalError::Corrupt(
                "connector-state commitment is invalid",
            ));
        }
        let stored = serde_json::from_slice::<StoredAuthorization>(&authorization)
            .map_err(|_| VultisigKeysignJournalError::Corrupt("authorization decode failed"))?;
        let request = stored.into_request()?;
        Ok(RecoveredVultisigKeysign {
            request,
            connector_state: connector_state.into_boxed_slice(),
            claim,
        })
    }

    /// Close all `SQLite` connections after the caller has dropped outstanding
    /// session claims.
    pub async fn close(self) {
        self.pool.close().await;
    }

    fn claim(
        &self,
        session_id: &str,
    ) -> Result<VultisigKeysignJournalClaim, VultisigKeysignJournalError> {
        let mut active = self
            .active_sessions
            .lock()
            .map_err(|_| VultisigKeysignJournalError::Storage)?;
        if !active.insert(session_id.to_string()) {
            return Err(VultisigKeysignJournalError::Active);
        }
        drop(active);
        Ok(VultisigKeysignJournalClaim {
            session_id: session_id.to_string(),
            active_sessions: Arc::clone(&self.active_sessions),
        })
    }

    fn validate_claim(
        &self,
        claim: &VultisigKeysignJournalClaim,
    ) -> Result<(), VultisigKeysignJournalError> {
        if !Arc::ptr_eq(&self.active_sessions, &claim.active_sessions) {
            return Err(VultisigKeysignJournalError::Corrupt(
                "session claim belongs to another journal",
            ));
        }
        let active = self
            .active_sessions
            .lock()
            .map_err(|_| VultisigKeysignJournalError::Storage)?;
        if !active.contains(claim.session_id()) {
            return Err(VultisigKeysignJournalError::Corrupt(
                "session claim is no longer active",
            ));
        }
        Ok(())
    }

    fn revalidate_storage(&self) -> Result<(), VultisigKeysignJournalError> {
        #[cfg(unix)]
        {
            validate_secure_sqlite_binding(&self.secure_binding)
        }
        #[cfg(not(unix))]
        {
            Err(VultisigKeysignJournalError::Config(
                "secure keysign journal storage requires Unix metadata",
            ))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredAuthorization {
    schema: String,
    prepare_key: String,
    spend_json: String,
    chain: ChainId,
    vault_ecdsa_public_key: String,
    signing_public_key_scheme: String,
    signing_public_key: String,
    plugin_id: String,
    policy_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bitcoin_authorization: Option<StoredBitcoinAuthorization>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredBitcoinAuthorization {
    max_fee_sats: u64,
    initial_policy_id: String,
    initial_provenance_id: String,
    upstream_release_manifest_sha256: String,
    vault_id: String,
    threshold: u16,
    reshare_epoch: u64,
    operation_id: String,
}

impl StoredBitcoinAuthorization {
    fn from_binding(binding: &BitcoinAuthorizationBinding) -> Self {
        Self {
            max_fee_sats: binding.max_fee_sats,
            initial_policy_id: hex::encode(binding.initial_policy_id),
            initial_provenance_id: hex::encode(binding.initial_provenance_id),
            upstream_release_manifest_sha256: hex::encode(
                binding.evidence.upstream_release_manifest_sha256(),
            ),
            vault_id: binding.evidence.vault_id().to_string(),
            threshold: binding.evidence.threshold(),
            reshare_epoch: binding.evidence.reshare_epoch(),
            operation_id: hex::encode(binding.operation_id),
        }
    }

    fn into_binding(self) -> Result<BitcoinAuthorizationBinding, VultisigKeysignJournalError> {
        let evidence = VultisigBitcoinEvidenceConfig::new(
            exact_hex_array::<32>(&self.upstream_release_manifest_sha256)?,
            self.vault_id,
            self.threshold,
            self.reshare_epoch,
        )
        .map_err(|_| {
            VultisigKeysignJournalError::Corrupt("stored Bitcoin evidence config is invalid")
        })?;
        Ok(BitcoinAuthorizationBinding {
            max_fee_sats: self.max_fee_sats,
            initial_policy_id: exact_hex_array::<32>(&self.initial_policy_id)?,
            initial_provenance_id: exact_hex_array::<32>(&self.initial_provenance_id)?,
            evidence,
            operation_id: exact_hex_array::<32>(&self.operation_id)?,
        })
    }
}

impl StoredAuthorization {
    fn from_request(
        request: &AuthorizedVultisigKeysign,
    ) -> Result<Self, VultisigKeysignJournalError> {
        if request.prepare_key.is_empty() || request.prepare_key.len() > MAX_PREPARE_KEY_BYTES {
            return Err(VultisigKeysignJournalError::Corrupt(
                "authorized prepare key size is invalid",
            ));
        }
        let spend_json = String::from_utf8(request.spend.encode_durable()?)
            .map_err(|_| VultisigKeysignJournalError::Corrupt("prepared spend is not JSON"))?;
        let (signing_public_key_scheme, signing_public_key) = match request
            .config
            .signing_public_key
        {
            VultisigPublicKey::Secp256k1(bytes) => ("secp256k1".to_string(), hex::encode(bytes)),
            VultisigPublicKey::Ed25519(bytes) => ("ed25519".to_string(), hex::encode(bytes)),
        };
        Ok(Self {
            schema: AUTHORIZATION_SCHEMA.to_string(),
            prepare_key: request.prepare_key.clone(),
            spend_json,
            chain: request.config.chain,
            vault_ecdsa_public_key: hex::encode(request.config.vault_ecdsa_public_key),
            signing_public_key_scheme,
            signing_public_key,
            plugin_id: request.config.plugin_id.clone(),
            policy_id: request.config.policy_id.clone(),
            bitcoin_authorization: request
                .bitcoin_authorization
                .as_ref()
                .map(StoredBitcoinAuthorization::from_binding),
        })
    }

    fn into_request(self) -> Result<AuthorizedVultisigKeysign, VultisigKeysignJournalError> {
        if self.schema != AUTHORIZATION_SCHEMA
            || self.prepare_key.is_empty()
            || self.prepare_key.len() > MAX_PREPARE_KEY_BYTES
        {
            return Err(VultisigKeysignJournalError::Corrupt(
                "authorization schema or prepare key is invalid",
            ));
        }
        let vault_ecdsa_public_key = exact_hex_array::<33>(&self.vault_ecdsa_public_key)?;
        let signing_public_key = match self.signing_public_key_scheme.as_str() {
            "secp256k1" => {
                VultisigPublicKey::Secp256k1(exact_hex_array::<33>(&self.signing_public_key)?)
            }
            "ed25519" => {
                VultisigPublicKey::Ed25519(exact_hex_array::<32>(&self.signing_public_key)?)
            }
            _ => {
                return Err(VultisigKeysignJournalError::Corrupt(
                    "stored signing-key scheme is invalid",
                ));
            }
        };
        let config = VultisigVaultConfig::new(
            self.chain,
            vault_ecdsa_public_key,
            signing_public_key,
            self.plugin_id,
            self.policy_id,
        )
        .map_err(|_| VultisigKeysignJournalError::Corrupt("stored vault config is invalid"))?;
        let spend = PreparedSpend::decode_durable(self.spend_json.as_bytes()).map_err(|_| {
            VultisigKeysignJournalError::Corrupt("stored prepared spend is invalid")
        })?;
        let mut request = build_from_parts(self.prepare_key, spend, config)
            .map_err(|_| VultisigKeysignJournalError::Corrupt("stored authorization is invalid"))?;
        if let Some(bitcoin_authorization) = self.bitcoin_authorization {
            restore_bitcoin_authorization(&mut request, bitcoin_authorization.into_binding()?)
                .map_err(|_| {
                    VultisigKeysignJournalError::Corrupt(
                        "stored Bitcoin authorization commitment is invalid",
                    )
                })?;
        }
        Ok(request)
    }
}

impl From<xindex_custody_core::prepare::PrepareError> for VultisigKeysignJournalError {
    fn from(_: xindex_custody_core::prepare::PrepareError) -> Self {
        Self::Corrupt("prepared-spend persistence failed")
    }
}

fn validate_connector_state(state: &[u8]) -> Result<(), VultisigKeysignJournalError> {
    if state.is_empty() || state.len() > MAX_CONNECTOR_STATE_BYTES {
        return Err(VultisigKeysignJournalError::Corrupt(
            "connector-state size is invalid",
        ));
    }
    Ok(())
}

fn validate_session_id(session_id: &str) -> Result<(), VultisigKeysignJournalError> {
    if session_id.len() != 36
        || !session_id
            .bytes()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
            })
        || session_id.as_bytes()[14] != b'4'
        || !matches!(session_id.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
    {
        return Err(VultisigKeysignJournalError::Corrupt(
            "session ID is not a canonical UUIDv4",
        ));
    }
    Ok(())
}

fn validate_terminal_commitment(commitment: [u8; 32]) -> Result<(), VultisigKeysignJournalError> {
    if commitment == [0; 32] {
        return Err(VultisigKeysignJournalError::Corrupt(
            "terminal handoff commitment is zero",
        ));
    }
    Ok(())
}

fn exact_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], VultisigKeysignJournalError> {
    bytes
        .try_into()
        .map_err(|_| VultisigKeysignJournalError::Corrupt("stored fixed-width field is invalid"))
}

fn exact_hex_array<const N: usize>(value: &str) -> Result<[u8; N], VultisigKeysignJournalError> {
    if value.len() != N * 2
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(VultisigKeysignJournalError::Corrupt(
            "stored key encoding is invalid",
        ));
    }
    exact_array(
        hex::decode(value)
            .map_err(|_| VultisigKeysignJournalError::Corrupt("stored key encoding is invalid"))?,
    )
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SecureFileIdentity {
    device: u64,
    inode: u64,
    owner: u32,
}

#[cfg(unix)]
#[derive(Debug)]
struct SecureSqliteBinding {
    path: PathBuf,
    parent: SecureFileIdentity,
    database: SecureFileIdentity,
}

#[cfg(unix)]
async fn open_secure_journal(
    database_path: &Path,
    target_id: [u8; 32],
) -> Result<SqliteVultisigKeysignJournal, VultisigKeysignJournalError> {
    if !database_path.is_absolute() || database_path.file_name().is_none() {
        return Err(VultisigKeysignJournalError::Config(
            "journal database path must be an absolute file path",
        ));
    }
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
    let journal = SqliteVultisigKeysignJournal {
        pool,
        target_id,
        active_sessions: Arc::new(Mutex::new(HashSet::new())),
        secure_binding: binding,
    };
    if let Err(error) = initialize_journal(&journal).await {
        journal.pool.close().await;
        return Err(error);
    }
    Ok(journal)
}

#[cfg(not(unix))]
async fn open_secure_journal(
    _database_path: &Path,
    _target_id: [u8; 32],
) -> Result<SqliteVultisigKeysignJournal, VultisigKeysignJournalError> {
    Err(VultisigKeysignJournalError::Config(
        "secure keysign journal storage requires Unix metadata",
    ))
}

async fn initialize_journal(
    journal: &SqliteVultisigKeysignJournal,
) -> Result<(), VultisigKeysignJournalError> {
    journal.revalidate_storage()?;
    sqlx::query("PRAGMA trusted_schema = OFF")
        .execute(&journal.pool)
        .await?;
    let trusted_schema: i64 = sqlx::query_scalar("PRAGMA trusted_schema")
        .fetch_one(&journal.pool)
        .await?;
    if trusted_schema != 0 {
        return Err(VultisigKeysignJournalError::Config(
            "SQLite trusted_schema could not be disabled",
        ));
    }
    sqlx::migrate!("./migrations").run(&journal.pool).await?;
    journal.revalidate_storage()?;
    sqlx::query(
        "INSERT INTO vultisig_keysign_journal_config (singleton, target_id)
         VALUES (1, ?) ON CONFLICT(singleton) DO NOTHING",
    )
    .bind(journal.target_id.as_slice())
    .execute(&journal.pool)
    .await?;
    let stored_target: Vec<u8> = sqlx::query_scalar(
        "SELECT target_id FROM vultisig_keysign_journal_config WHERE singleton = 1",
    )
    .fetch_one(&journal.pool)
    .await?;
    if exact_array::<32>(stored_target)? != journal.target_id {
        return Err(VultisigKeysignJournalError::Config(
            "journal is bound to another connector target",
        ));
    }
    journal.revalidate_storage()
}

#[cfg(unix)]
fn prepare_secure_sqlite_file(
    database_path: &Path,
) -> Result<SecureSqliteBinding, VultisigKeysignJournalError> {
    let parent = database_path
        .parent()
        .ok_or(VultisigKeysignJournalError::Config(
            "journal database path has no parent",
        ))?;
    let parent_identity = secure_parent_identity(parent)?;
    reject_preexisting_sidecars(database_path)?;
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
                    VultisigKeysignJournalError::Config("cannot securely create journal database")
                })?;
            file.sync_all().map_err(|_| {
                VultisigKeysignJournalError::Config("cannot sync new journal database")
            })?;
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| {
                    VultisigKeysignJournalError::Config("cannot sync journal database directory")
                })?;
        }
        Err(_) => {
            return Err(VultisigKeysignJournalError::Config(
                "cannot inspect journal database",
            ));
        }
    }
    let database_identity = secure_database_identity(database_path)?;
    if database_identity.owner != parent_identity.owner {
        return Err(VultisigKeysignJournalError::Config(
            "journal database and parent have different owners",
        ));
    }
    Ok(SecureSqliteBinding {
        path: database_path.to_path_buf(),
        parent: parent_identity,
        database: database_identity,
    })
}

#[cfg(unix)]
fn secure_parent_identity(
    parent: &Path,
) -> Result<SecureFileIdentity, VultisigKeysignJournalError> {
    let canonical = parent.canonicalize().map_err(|_| {
        VultisigKeysignJournalError::Config("journal parent cannot be canonicalized")
    })?;
    if canonical != parent {
        return Err(VultisigKeysignJournalError::Config(
            "journal parent must be a canonical non-symlink path",
        ));
    }
    let metadata = std::fs::symlink_metadata(parent)
        .map_err(|_| VultisigKeysignJournalError::Config("journal parent is unavailable"))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(VultisigKeysignJournalError::Config(
            "journal parent must be an owner-only 0700 directory",
        ));
    }
    Ok(SecureFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
    })
}

#[cfg(unix)]
fn secure_database_identity(
    database_path: &Path,
) -> Result<SecureFileIdentity, VultisigKeysignJournalError> {
    let metadata = std::fs::symlink_metadata(database_path)
        .map_err(|_| VultisigKeysignJournalError::Config("cannot inspect journal database"))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(VultisigKeysignJournalError::Config(
            "journal database must be one owner-only 0600 regular file",
        ));
    }
    Ok(SecureFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
    })
}

#[cfg(unix)]
fn sidecar_path(database_path: &Path, suffix: &str) -> PathBuf {
    let mut path = database_path.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

#[cfg(unix)]
fn reject_preexisting_sidecars(database_path: &Path) -> Result<(), VultisigKeysignJournalError> {
    for suffix in ["-journal", "-wal", "-shm"] {
        match std::fs::symlink_metadata(sidecar_path(database_path, suffix)) {
            Ok(_) => {
                return Err(VultisigKeysignJournalError::Config(
                    "unexpected preexisting SQLite sidecar exists",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(VultisigKeysignJournalError::Config(
                    "cannot inspect SQLite sidecar",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_runtime_sidecars(
    database_path: &Path,
    expected_owner: u32,
) -> Result<(), VultisigKeysignJournalError> {
    for suffix in ["-wal", "-shm"] {
        match std::fs::symlink_metadata(sidecar_path(database_path, suffix)) {
            Ok(_) => {
                return Err(VultisigKeysignJournalError::Config(
                    "unexpected SQLite WAL sidecar exists",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(VultisigKeysignJournalError::Config(
                    "cannot inspect SQLite runtime sidecar",
                ));
            }
        }
    }
    match std::fs::symlink_metadata(sidecar_path(database_path, "-journal")) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.nlink() == 1
                && metadata.uid() == expected_owner
                && metadata.permissions().mode() & 0o7777 == 0o600 =>
        {
            Ok(())
        }
        Ok(_) => Err(VultisigKeysignJournalError::Config(
            "SQLite journal sidecar is not owner-only",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(VultisigKeysignJournalError::Config(
            "cannot inspect SQLite journal sidecar",
        )),
    }
}

#[cfg(unix)]
fn validate_secure_sqlite_binding(
    binding: &SecureSqliteBinding,
) -> Result<(), VultisigKeysignJournalError> {
    let parent = binding
        .path
        .parent()
        .ok_or(VultisigKeysignJournalError::Config(
            "journal database path has no parent",
        ))?;
    let current_parent = secure_parent_identity(parent)?;
    if current_parent != binding.parent {
        return Err(VultisigKeysignJournalError::Config(
            "journal parent identity changed after opening",
        ));
    }
    let current_database = secure_database_identity(&binding.path)?;
    if current_database != binding.database || current_database.owner != current_parent.owner {
        return Err(VultisigKeysignJournalError::Config(
            "journal database identity changed after opening",
        ));
    }
    validate_runtime_sidecars(&binding.path, current_database.owner)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "deterministic journal tests")]

    #[cfg(unix)]
    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use alloy_primitives::{Address, U256};
    use bitcoin::absolute::LockTime;
    use bitcoin::bip32::{DerivationPath, Fingerprint};
    use bitcoin::hashes::Hash as _;
    use bitcoin::psbt::Psbt;
    use bitcoin::sighash::EcdsaSighashType;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use xindex_custody_core::evm_tx::{build_unsigned, EvmUnsignedParams};
    use xindex_custody_core::prepare::{BindContext, EvmPrepared, EvmSigning, PreparedSpend};
    use xindex_shared::chain_registry::ChainId;

    use super::*;
    use crate::request::{
        attach_bitcoin_authorization, build_from_parts, VultisigBitcoinEvidenceConfig,
        VultisigPublicKey, VultisigVaultConfig,
    };

    const GENERATOR: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    const SESSION_ID: &str = "123e4567-e89b-42d3-a456-426614174002";
    const SECOND_SESSION_ID: &str = "223e4567-e89b-42d3-a456-426614174003";
    static DATABASE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn authorized_request() -> AuthorizedVultisigKeysign {
        let signing = EvmSigning {
            nonce: 7,
            gas_limit: 120_000,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 2_000_000_000,
            gas_price: 0,
        };
        let prepared = EvmPrepared {
            chain: ChainId::Eth,
            to: Address::repeat_byte(0x22),
            value: U256::from(9),
            data: vec![0xde, 0xad, 0xbe, 0xef],
            signing: signing.clone(),
            ric: None,
            spend_identity: 7u64.to_be_bytes().to_vec(),
        };
        let unsigned = build_unsigned(&EvmUnsignedParams {
            chain: prepared.chain,
            nonce: signing.nonce,
            gas_limit: signing.gas_limit,
            max_fee_per_gas: signing.max_fee_per_gas,
            max_priority_fee_per_gas: signing.max_priority_fee_per_gas,
            gas_price: signing.gas_price,
            to: prepared.to,
            value: prepared.value,
            data: &prepared.data,
        })
        .expect("valid EVM fixture");
        let config = VultisigVaultConfig::new(
            ChainId::Eth,
            GENERATOR,
            VultisigPublicKey::Secp256k1(GENERATOR),
            "123e4567-e89b-12d3-a456-426614174000",
            "123e4567-e89b-12d3-a456-426614174001",
        )
        .expect("valid vault fixture");
        build_from_parts(
            format!(
                "0x{}",
                alloy_primitives::hex::encode(unsigned.signature_hash())
            ),
            PreparedSpend::Evm(prepared),
            config,
        )
        .expect("authorized fixture")
    }

    fn strict_bitcoin_request() -> AuthorizedVultisigKeysign {
        let public_key = PublicKey::from_slice(&GENERATOR).expect("fixed public key");
        let previous_script =
            ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash().expect("compressed public key"));
        let mut psbt = Psbt::from_unsigned_tx(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([0x81; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(199_000),
                script_pubkey: ScriptBuf::new_p2pkh(&public_key.pubkey_hash()),
            }],
        })
        .expect("PSBT");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(200_000),
            script_pubkey: previous_script,
        });
        psbt.inputs[0].sighash_type = Some(EcdsaSighashType::All.into());
        psbt.inputs[0].bip32_derivation.insert(
            public_key.inner,
            (Fingerprint::default(), DerivationPath::default()),
        );
        let signing_hash = xindex_chain_utxo::single_key::derive_single_key_psbt_sighashes(
            ChainId::Btc,
            &psbt,
            &GENERATOR,
        )
        .expect("Bitcoin signing hash")[0];
        let config = VultisigVaultConfig::new(
            ChainId::Btc,
            GENERATOR,
            VultisigPublicKey::Secp256k1(GENERATOR),
            "123e4567-e89b-12d3-a456-426614174000",
            "123e4567-e89b-12d3-a456-426614174001",
        )
        .expect("Bitcoin vault config");
        let mut request = build_from_parts(
            format!("0x{}", hex::encode(signing_hash)),
            PreparedSpend::DirectUtxo(Box::new(BindContext {
                chain: ChainId::Btc,
                psbt,
                ric: None,
                acc: None,
            })),
            config,
        )
        .expect("Bitcoin request");
        attach_bitcoin_authorization(
            &mut request,
            10_000,
            [0x82; 32],
            [0x83; 32],
            VultisigBitcoinEvidenceConfig::new([0x84; 32], "vault-testnet4-runtime", 2, 3)
                .expect("evidence config"),
        )
        .expect("strict Bitcoin binding");
        request
    }

    #[test]
    fn durable_authorization_roundtrip_retains_strict_bitcoin_recovery() {
        let request = strict_bitcoin_request();
        let expected_operation = request
            .bitcoin_operation_id()
            .expect("strict operation identity");
        let stored = StoredAuthorization::from_request(&request).expect("store authorization");
        let encoded = serde_json::to_vec(&stored).expect("encode authorization");
        let decoded: StoredAuthorization =
            serde_json::from_slice(&encoded).expect("decode authorization");
        let recovered = decoded.into_request().expect("recover authorization");
        assert_eq!(recovered.bitcoin_operation_id(), Some(expected_operation));
        let material = recovered
            .bitcoin_recovery_material()
            .expect("valid recovery")
            .expect("Bitcoin recovery");
        assert_eq!(material.max_fee_sats(), 10_000);
        assert_eq!(material.operation_id(), expected_operation);
    }

    #[cfg(unix)]
    fn temporary_database(label: &str) -> PathBuf {
        let suffix = DATABASE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("canonical temporary directory");
        let parent = root.join(format!(
            "xindex-vultisig-keysign-journal-{label}-{}-{suffix}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&parent)
            .expect("private journal parent");
        parent
            .canonicalize()
            .expect("canonical journal parent")
            .join("keysign.sqlite")
    }

    #[cfg(unix)]
    fn remove_database(path: &Path) {
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", path.display(), suffix));
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }

    #[cfg(unix)]
    async fn assert_direct_live_insert_rejected(
        journal: &SqliteVultisigKeysignJournal,
        session_id: &str,
        target_id: [u8; 32],
        authorization_sha256: &[u8],
    ) {
        let result = sqlx::query(
            "INSERT INTO vultisig_keysign_journal
             (session_id, target_id, authorization, authorization_sha256,
              connector_state, connector_state_sha256)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(session_id)
        .bind(target_id.as_slice())
        .bind(b"authorization".as_slice())
        .bind(authorization_sha256)
        .bind(b"connector-state".as_slice())
        .bind([0x36; 32].as_slice())
        .execute(&journal.pool)
        .await;
        assert!(result.is_err(), "database invariant must reject reuse");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restart_recovers_exact_authorization_and_latest_state() {
        let database = temporary_database("restart");
        let target_id = [0x11; 32];
        let original = authorized_request();
        let expected_transaction = original.transaction_bytes().to_vec();
        let journal = SqliteVultisigKeysignJournal::connect(&database, target_id)
            .await
            .expect("open journal");
        let claim = journal
            .persist(SESSION_ID, &original, br#"{"phase":"uncertain"}"#)
            .await
            .expect("persist before POST");
        journal
            .checkpoint(&claim, br#"{"phase":"waiting"}"#)
            .await
            .expect("durable phase update");
        drop(claim);
        journal.close().await;

        let reopened = SqliteVultisigKeysignJournal::connect(&database, target_id)
            .await
            .expect("reopen journal");
        assert_eq!(
            reopened
                .recoverable_sessions()
                .await
                .expect("list recoverable"),
            vec![SESSION_ID.to_string()]
        );
        let recovered = reopened
            .recover(SESSION_ID)
            .await
            .expect("recover exact row");
        let (request, state, recovered_claim) = recovered.into_parts();
        assert_eq!(request.transaction_bytes(), expected_transaction);
        assert_eq!(&*state, br#"{"phase":"waiting"}"#);

        drop(recovered_claim);
        reopened.close().await;
        remove_database(&database);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn target_change_and_duplicate_active_claim_fail_closed() {
        let database = temporary_database("binding");
        let other_database = temporary_database("foreign-claim");
        let journal = SqliteVultisigKeysignJournal::connect(&database, [0x22; 32])
            .await
            .expect("open journal");
        let request = authorized_request();
        let claim = journal
            .persist(SESSION_ID, &request, b"state")
            .await
            .expect("persist row");
        assert!(matches!(
            journal
                .persist(SECOND_SESSION_ID, &request, b"other-state")
                .await,
            Err(VultisigKeysignJournalError::Corrupt(
                "session or authorization already has a durable row"
            ))
        ));
        let other_journal = SqliteVultisigKeysignJournal::connect(&other_database, [0x22; 32])
            .await
            .expect("open other journal");
        assert!(matches!(
            other_journal.checkpoint(&claim, b"foreign").await,
            Err(VultisigKeysignJournalError::Corrupt(
                "session claim belongs to another journal"
            ))
        ));
        other_journal.close().await;
        remove_database(&other_database);
        assert!(matches!(
            journal.recover(SESSION_ID).await,
            Err(VultisigKeysignJournalError::Active)
        ));
        drop(claim);
        assert!(matches!(
            journal.persist(SESSION_ID, &request, b"state").await,
            Err(VultisigKeysignJournalError::Corrupt(
                "session or authorization already has a durable row"
            ))
        ));
        let recovered = journal
            .recover(SESSION_ID)
            .await
            .expect("dropped claim makes the row recoverable, not fresh");
        let (_, _, recovered_claim) = recovered.into_parts();
        drop(recovered_claim);
        journal.close().await;

        assert!(matches!(
            SqliteVultisigKeysignJournal::connect(&database, [0x23; 32]).await,
            Err(VultisigKeysignJournalError::Config(_))
        ));
        remove_database(&database);
    }

    #[tokio::test]
    async fn migration_refuses_preexisting_cross_session_authorization_reuse() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open in-memory legacy journal");
        sqlx::raw_sql(include_str!(
            "../migrations/20260721000000_create_vultisig_keysign_journal.sql"
        ))
        .execute(&pool)
        .await
        .expect("install initial journal schema");
        sqlx::raw_sql(include_str!(
            "../migrations/20260721010000_create_vultisig_keysign_terminal_handoffs.sql"
        ))
        .execute(&pool)
        .await
        .expect("install session-only terminal schema");

        let authorization_sha256 = [0x51; 32];
        let connector_state_sha256 = [0x52; 32];
        sqlx::query(
            "INSERT INTO vultisig_keysign_journal
             (session_id, target_id, authorization, authorization_sha256,
              connector_state, connector_state_sha256)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(SESSION_ID)
        .bind([0x53; 32].as_slice())
        .bind(b"authorization".as_slice())
        .bind(authorization_sha256.as_slice())
        .bind(b"connector-state".as_slice())
        .bind(connector_state_sha256.as_slice())
        .execute(&pool)
        .await
        .expect("insert legacy live authorization");
        sqlx::query(
            "INSERT INTO vultisig_keysign_terminal_handoffs
             (session_id, target_id, authorization_sha256,
              connector_state_sha256, completion_id,
              downstream_consumer_id, downstream_receipt_id)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(SECOND_SESSION_ID)
        .bind([0x53; 32].as_slice())
        .bind(authorization_sha256.as_slice())
        .bind(connector_state_sha256.as_slice())
        .bind([0x54; 32].as_slice())
        .bind([0x55; 32].as_slice())
        .bind([0x56; 32].as_slice())
        .execute(&pool)
        .await
        .expect("insert legacy terminal reuse");

        let migration = sqlx::raw_sql(include_str!(
            "../migrations/20260721020000_prevent_duplicate_vultisig_authorizations.sql"
        ))
        .execute(&pool)
        .await;
        assert!(
            migration.is_err(),
            "upgrade must fail closed on an existing cross-session reuse"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_handoff_redacts_live_state_and_permanently_blocks_reuse() {
        let database = temporary_database("terminal-handoff");
        let target_id = [0x31; 32];
        let completion_id = [0x32; 32];
        let downstream_consumer_id = [0x33; 32];
        let downstream_receipt_id = [0x34; 32];
        let request = authorized_request();
        let journal = SqliteVultisigKeysignJournal::connect(&database, target_id)
            .await
            .expect("open journal");
        let claim = journal
            .persist(SESSION_ID, &request, br#"{"phase":"finalizing"}"#)
            .await
            .expect("persist finalizing row");

        let receipt = journal
            .acknowledge_handoff(
                &claim,
                completion_id,
                downstream_consumer_id,
                downstream_receipt_id,
            )
            .await
            .expect("atomically acknowledge and redact");
        assert_eq!(receipt.session_id(), SESSION_ID);
        assert_eq!(receipt.completion_id(), completion_id);
        assert_eq!(receipt.downstream_consumer_id(), downstream_consumer_id);
        assert_eq!(receipt.downstream_receipt_id(), downstream_receipt_id);

        let live_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM vultisig_keysign_journal WHERE session_id = ?",
        )
        .bind(SESSION_ID)
        .fetch_one(&journal.pool)
        .await
        .expect("count live rows");
        assert_eq!(live_rows, 0, "secret-bearing live row must be removed");
        let terminal_authorization_sha256: Vec<u8> = sqlx::query_scalar(
            "SELECT authorization_sha256
             FROM vultisig_keysign_terminal_handoffs WHERE session_id = ?",
        )
        .bind(SESSION_ID)
        .fetch_one(&journal.pool)
        .await
        .expect("read terminal authorization commitment");
        assert_direct_live_insert_rejected(&journal, SESSION_ID, target_id, &[0x35; 32]).await;
        assert_direct_live_insert_rejected(
            &journal,
            SECOND_SESSION_ID,
            target_id,
            &terminal_authorization_sha256,
        )
        .await;
        assert!(journal
            .recoverable_sessions()
            .await
            .expect("list recoverable")
            .is_empty());
        drop(claim);
        assert!(matches!(
            journal.recover(SESSION_ID).await,
            Err(VultisigKeysignJournalError::Corrupt(
                "requested session row is missing"
            ))
        ));
        assert_eq!(
            journal
                .terminal_handoff(SESSION_ID)
                .await
                .expect("read terminal receipt"),
            Some(receipt.clone())
        );

        journal.close().await;
        let reopened = SqliteVultisigKeysignJournal::connect(&database, target_id)
            .await
            .expect("reopen terminal journal");
        assert_eq!(
            reopened
                .terminal_handoff(SESSION_ID)
                .await
                .expect("read terminal receipt after restart"),
            Some(receipt)
        );

        assert!(matches!(
            reopened
                .persist(SESSION_ID, &request, br#"{"phase":"fresh"}"#)
                .await,
            Err(VultisigKeysignJournalError::Corrupt(
                "session already reached terminal handoff"
            ))
        ));
        assert!(matches!(
            reopened
                .persist(SECOND_SESSION_ID, &request, br#"{"phase":"fresh"}"#)
                .await,
            Err(VultisigKeysignJournalError::Corrupt(
                "authorization already reached terminal handoff"
            ))
        ));
        reopened.close().await;
        remove_database(&database);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_handoff_rejects_unbound_or_foreign_acknowledgements() {
        let database = temporary_database("terminal-validation");
        let foreign_database = temporary_database("terminal-foreign");
        let target_id = [0x41; 32];
        let request = authorized_request();
        let journal = SqliteVultisigKeysignJournal::connect(&database, target_id)
            .await
            .expect("open journal");
        let claim = journal
            .persist(SESSION_ID, &request, br#"{"phase":"finalizing"}"#)
            .await
            .expect("persist finalizing row");

        assert!(matches!(
            journal
                .acknowledge_handoff(&claim, [0; 32], [1; 32], [2; 32])
                .await,
            Err(VultisigKeysignJournalError::Corrupt(
                "terminal handoff commitment is zero"
            ))
        ));
        let foreign = SqliteVultisigKeysignJournal::connect(&foreign_database, target_id)
            .await
            .expect("open foreign journal");
        assert!(matches!(
            foreign
                .acknowledge_handoff(&claim, [1; 32], [2; 32], [3; 32])
                .await,
            Err(VultisigKeysignJournalError::Corrupt(
                "session claim belongs to another journal"
            ))
        ));
        assert_eq!(
            journal
                .recoverable_sessions()
                .await
                .expect("active session remains hidden"),
            Vec::<String>::new()
        );

        foreign.close().await;
        remove_database(&foreign_database);
        drop(claim);
        assert_eq!(
            journal
                .recoverable_sessions()
                .await
                .expect("failed acknowledgement leaves row recoverable"),
            vec![SESSION_ID.to_string()]
        );
        journal.close().await;
        remove_database(&database);
    }
}
