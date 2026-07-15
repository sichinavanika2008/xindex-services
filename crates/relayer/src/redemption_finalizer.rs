//! Durable terminal-redemption journal mirror and `finalizeBurn` outbox.
//!
//! The production worker copies one canonical finalized-observer block at a
//! time. Cursor advancement, lifecycle derivation, and job creation share one
//! `SQLite` transaction. A crash can therefore leave a job either wholly absent
//! with the cursor unadvanced, or durably recoverable from `posting`.

use alloy_primitives::{Address, B256};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use thiserror::Error;
use xindex_chain_eth::finalized_observer::{FinalizedCheckpoint, FinalizedRedemptionEvent};

type StoredCheckpointRow = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type StoredEventRow = (i64, i64, String, Vec<u8>, Option<Vec<u8>>, Option<i64>);
type StoredJobRow = (Vec<u8>, Vec<u8>, String, i64, i64, i64, i64, i64, i64);

#[derive(Debug, Error)]
pub enum RedemptionFinalizerError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] sqlx::Error),
    #[error("migration: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("invalid finalizer transition: {0}")]
    Transition(String),
    #[error("corrupt finalizer state: {0}")]
    Decode(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizationJobState {
    Queued,
    Posting,
    Posted,
    Superseded,
}

impl FinalizationJobState {
    fn decode(raw: &str) -> Result<Self, RedemptionFinalizerError> {
        match raw {
            "queued" => Ok(Self::Queued),
            "posting" => Ok(Self::Posting),
            "posted" => Ok(Self::Posted),
            "superseded" => Ok(Self::Superseded),
            _ => Err(RedemptionFinalizerError::Decode(format!(
                "unknown finalization job state {raw}"
            ))),
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(self, Self::Posted | Self::Superseded)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizationJob {
    pub redemption_id: B256,
    pub index_token: Address,
    pub state: FinalizationJobState,
    pub attempts: u64,
    pub next_attempt_at: u64,
    pub trigger_block: u64,
    pub trigger_log_index: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StuckRedemption {
    pub redemption_id: B256,
    pub index_token: Address,
    pub deadline: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizerStats {
    pub pending_redemptions: u64,
    pub active_jobs: u64,
    pub stuck: Vec<StuckRedemption>,
}

#[derive(Clone)]
pub struct SqliteRedemptionFinalizerStore {
    pool: SqlitePool,
    source_id: String,
}

impl std::fmt::Debug for SqliteRedemptionFinalizerStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteRedemptionFinalizerStore")
            .field("source_id", &self.source_id)
            .finish_non_exhaustive()
    }
}

impl SqliteRedemptionFinalizerStore {
    /// Open the dedicated durable finalizer database for one observer source.
    ///
    /// # Errors
    ///
    /// Returns an error when the source identity is unsafe, the database cannot
    /// be opened, or its migrations cannot be applied.
    pub async fn connect(
        database_url: &str,
        source_id: &str,
    ) -> Result<Self, RedemptionFinalizerError> {
        validate_source_id(source_id)?;
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self {
            pool,
            source_id: source_id.to_string(),
        })
    }

    /// Return the highest locally mirrored finalized checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails or stored checkpoint bytes are
    /// malformed.
    pub async fn last_checkpoint(
        &self,
    ) -> Result<Option<FinalizedCheckpoint>, RedemptionFinalizerError> {
        let row: Option<StoredCheckpointRow> = sqlx::query_as(
            "SELECT block_number, block_hash, parent_hash,
                    header_evidence_hash, logs_evidence_hash
             FROM redemption_finalizer_blocks
             WHERE source_id = ? ORDER BY block_number DESC LIMIT 1",
        )
        .bind(&self.source_id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(decode_checkpoint).transpose()
    }

    /// Return the locally mirrored hash for an exact source height.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails, the height exceeds the database
    /// representation, or stored hash bytes are malformed.
    pub async fn checkpoint_hash(
        &self,
        block_number: u64,
    ) -> Result<Option<B256>, RedemptionFinalizerError> {
        let value: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT block_hash FROM redemption_finalizer_blocks
             WHERE source_id = ? AND block_number = ?",
        )
        .bind(&self.source_id)
        .bind(to_i64(block_number, "block number")?)
        .fetch_optional(&self.pool)
        .await?;
        value
            .map(|bytes| decode_b256(&bytes, "checkpoint hash"))
            .transpose()
    }

    /// Atomically mirror one canonical source block and derive any terminal
    /// responsibility it creates.
    ///
    /// # Errors
    ///
    /// Returns an error when the checkpoint or event sequence is invalid, does
    /// not extend the local journal, conflicts with retained state, or cannot be
    /// committed atomically.
    pub async fn commit_source_block(
        &self,
        checkpoint: FinalizedCheckpoint,
        events: &[FinalizedRedemptionEvent],
        now: u64,
    ) -> Result<(), RedemptionFinalizerError> {
        validate_checkpoint(checkpoint, now)?;
        validate_event_order(events)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let previous: Option<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT block_number, block_hash FROM redemption_finalizer_blocks
             WHERE source_id = ? ORDER BY block_number DESC LIMIT 1",
        )
        .bind(&self.source_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some((previous_number, previous_hash)) = previous {
            let previous_number = from_i64(previous_number, "previous block")?;
            let previous_hash = decode_b256(&previous_hash, "previous block hash")?;
            if checkpoint.block_number == previous_number && checkpoint.block_hash == previous_hash
            {
                transaction.rollback().await?;
                return Ok(());
            }
            if checkpoint.block_number != previous_number.saturating_add(1)
                || checkpoint.parent_hash != previous_hash
            {
                return Err(RedemptionFinalizerError::Transition(format!(
                    "source block {} does not extend {}",
                    checkpoint.block_number, previous_number
                )));
            }
        }
        insert_checkpoint(&mut transaction, &self.source_id, checkpoint, now).await?;
        for event in events {
            insert_event(
                &mut transaction,
                &self.source_id,
                checkpoint.block_number,
                *event,
            )
            .await?;
            apply_event(
                &mut transaction,
                &self.source_id,
                checkpoint.block_number,
                *event,
                now,
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Roll the mirror back to a source-verified common ancestor and rebuild
    /// all derived redemptions/jobs from retained canonical events.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested ancestor is not retained with the
    /// supplied hash or the rollback/rebuild transaction fails.
    pub async fn rollback_to(
        &self,
        ancestor_number: u64,
        ancestor_hash: B256,
        now: u64,
    ) -> Result<(), RedemptionFinalizerError> {
        if self.checkpoint_hash(ancestor_number).await? != Some(ancestor_hash) {
            return Err(RedemptionFinalizerError::Transition(
                "rollback target is not a retained matching ancestor".to_string(),
            ));
        }
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let height = to_i64(ancestor_number, "ancestor block")?;
        sqlx::query(
            "DELETE FROM redemption_finalizer_events
             WHERE source_id = ? AND source_block > ?",
        )
        .bind(&self.source_id)
        .bind(height)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM redemption_finalizer_blocks
             WHERE source_id = ? AND block_number > ?",
        )
        .bind(&self.source_id)
        .bind(height)
        .execute(&mut *transaction)
        .await?;
        rebuild_derived(&mut transaction, &self.source_id, now).await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Requeue jobs whose worker crashed after claiming durable ownership.
    ///
    /// # Errors
    ///
    /// Returns an error when the timestamp cannot be represented or the
    /// recovery update fails.
    pub async fn recover_inflight(&self, now: u64) -> Result<u64, RedemptionFinalizerError> {
        let result = sqlx::query(
            "UPDATE redemption_finalizer_jobs
             SET state = 'queued', next_attempt_at = ?, updated_at = ?,
                 last_error = 'worker_restarted'
             WHERE source_id = ? AND state = 'posting'",
        )
        .bind(to_i64(now, "current time")?)
        .bind(to_i64(now, "current time")?)
        .bind(&self.source_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Atomically claim the oldest due finalization job.
    ///
    /// # Errors
    ///
    /// Returns an error when persisted job data is malformed or durable claim
    /// ownership cannot be acquired.
    pub async fn claim_next(
        &self,
        now: u64,
    ) -> Result<Option<FinalizationJob>, RedemptionFinalizerError> {
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let row: Option<StoredJobRow> = sqlx::query_as(
            "SELECT redemption_id, index_token, state, attempts,
                    next_attempt_at, trigger_block, trigger_log_index,
                    created_at, updated_at
             FROM redemption_finalizer_jobs
             WHERE source_id = ? AND state = 'queued' AND next_attempt_at <= ?
             ORDER BY trigger_block ASC, trigger_log_index ASC LIMIT 1",
        )
        .bind(&self.source_id)
        .bind(to_i64(now, "current time")?)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(mut job) = row.as_ref().map(decode_job).transpose()? else {
            transaction.commit().await?;
            return Ok(None);
        };
        let result = sqlx::query(
            "UPDATE redemption_finalizer_jobs
             SET state = 'posting', attempts = attempts + 1, updated_at = ?
             WHERE source_id = ? AND redemption_id = ? AND state = 'queued'",
        )
        .bind(to_i64(now, "current time")?)
        .bind(&self.source_id)
        .bind(job.redemption_id.as_slice())
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(RedemptionFinalizerError::Transition(
                "queued finalization job lost ownership".to_string(),
            ));
        }
        transaction.commit().await?;
        job.state = FinalizationJobState::Posting;
        job.attempts = job.attempts.saturating_add(1);
        job.updated_at = now;
        Ok(Some(job))
    }

    /// Return a claimed job to the durable queue after a classified failure.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid retry envelope, a database failure, or
    /// when the caller no longer owns a non-terminal posting job.
    pub async fn retry(
        &self,
        job: &FinalizationJob,
        next_attempt_at: u64,
        error: &str,
        now: u64,
    ) -> Result<(), RedemptionFinalizerError> {
        if next_attempt_at < now || error.is_empty() || error.len() > 512 {
            return Err(RedemptionFinalizerError::Transition(
                "invalid retry time or error class".to_string(),
            ));
        }
        let result = sqlx::query(
            "UPDATE redemption_finalizer_jobs
             SET state = 'queued', next_attempt_at = ?, last_error = ?, updated_at = ?
             WHERE source_id = ? AND redemption_id = ? AND index_token = ?
               AND state = 'posting'",
        )
        .bind(to_i64(next_attempt_at, "next attempt")?)
        .bind(error)
        .bind(to_i64(now, "current time")?)
        .bind(&self.source_id)
        .bind(job.redemption_id.as_slice())
        .bind(job.index_token.as_slice())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 1 {
            return Ok(());
        }
        let state: Option<String> = sqlx::query_scalar(
            "SELECT state FROM redemption_finalizer_jobs
             WHERE source_id = ? AND redemption_id = ? AND index_token = ?",
        )
        .bind(&self.source_id)
        .bind(job.redemption_id.as_slice())
        .bind(job.index_token.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        if state
            .as_deref()
            .map(FinalizationJobState::decode)
            .transpose()?
            .is_some_and(FinalizationJobState::is_terminal)
        {
            Ok(())
        } else {
            Err(RedemptionFinalizerError::Transition(
                "finalization job was not owned for retry".to_string(),
            ))
        }
    }

    /// Read pending-job and exact-deadline stuck-redemption metrics.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails or stored counters, identities, or
    /// deadlines cannot be decoded safely.
    pub async fn stats(&self, now: u64) -> Result<FinalizerStats, RedemptionFinalizerError> {
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM redemption_finalizer_redemptions
             WHERE source_id = ? AND resolved = 0",
        )
        .bind(&self.source_id)
        .fetch_one(&self.pool)
        .await?;
        let active_jobs: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM redemption_finalizer_jobs
             WHERE source_id = ? AND state IN ('queued', 'posting')",
        )
        .bind(&self.source_id)
        .fetch_one(&self.pool)
        .await?;
        let rows: Vec<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT redemption_id, index_token, deadline
             FROM redemption_finalizer_redemptions
             WHERE source_id = ? AND resolved = 0 AND settlement_observed = 0
               AND deadline <= ?
             ORDER BY redemption_id ASC",
        )
        .bind(&self.source_id)
        .bind(to_i64(now, "current time")?)
        .fetch_all(&self.pool)
        .await?;
        let stuck = rows
            .into_iter()
            .map(|(redemption_id, index_token, deadline)| {
                Ok(StuckRedemption {
                    redemption_id: decode_b256(&redemption_id, "stuck redemption id")?,
                    index_token: decode_address(&index_token, "stuck index token")?,
                    deadline: from_i64(deadline, "stuck deadline")?,
                })
            })
            .collect::<Result<Vec<_>, RedemptionFinalizerError>>()?;
        Ok(FinalizerStats {
            pending_redemptions: from_i64(pending, "pending redemption count")?,
            active_jobs: from_i64(active_jobs, "active finalization job count")?,
            stuck,
        })
    }
}

async fn insert_checkpoint(
    transaction: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    source_id: &str,
    checkpoint: FinalizedCheckpoint,
    now: u64,
) -> Result<(), RedemptionFinalizerError> {
    sqlx::query(
        "INSERT INTO redemption_finalizer_blocks
            (source_id, block_number, block_hash, parent_hash,
             header_evidence_hash, logs_evidence_hash, processed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(source_id)
    .bind(to_i64(checkpoint.block_number, "block number")?)
    .bind(checkpoint.block_hash.as_slice())
    .bind(checkpoint.parent_hash.as_slice())
    .bind(checkpoint.header_evidence_hash.as_slice())
    .bind(checkpoint.logs_evidence_hash.as_slice())
    .bind(to_i64(now, "current time")?)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_event(
    transaction: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    source_id: &str,
    source_block: u64,
    event: FinalizedRedemptionEvent,
) -> Result<(), RedemptionFinalizerError> {
    let (kind, redemption_id, index_token, deadline) = event_shape(event);
    let index_token = index_token.map(|address| address.to_vec());
    sqlx::query(
        "INSERT INTO redemption_finalizer_events
            (source_id, source_block, source_log_index, event_kind,
             redemption_id, index_token, deadline)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(source_id)
    .bind(to_i64(source_block, "source block")?)
    .bind(to_i64(event.log_index(), "source log index")?)
    .bind(kind)
    .bind(redemption_id.as_slice())
    .bind(index_token.as_deref())
    .bind(
        deadline
            .map(|value| to_i64(value, "redemption deadline"))
            .transpose()?,
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "explicit exhaustive arms preserve the audited lifecycle transition ledger"
)]
async fn apply_event(
    transaction: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    source_id: &str,
    source_block: u64,
    event: FinalizedRedemptionEvent,
    now: u64,
) -> Result<(), RedemptionFinalizerError> {
    match event {
        FinalizedRedemptionEvent::Created {
            redemption_id,
            index_token,
            deadline,
            log_index,
            ..
        } => {
            let result = sqlx::query(
                "INSERT OR IGNORE INTO redemption_finalizer_redemptions
                    (source_id, redemption_id, index_token, deadline,
                     settlement_observed, resolved, created_block,
                     created_log_index, updated_at)
                 VALUES (?, ?, ?, ?, 0, 0, ?, ?, ?)",
            )
            .bind(source_id)
            .bind(redemption_id.as_slice())
            .bind(index_token.as_slice())
            .bind(to_i64(deadline, "redemption deadline")?)
            .bind(to_i64(source_block, "created block")?)
            .bind(to_i64(log_index, "created log index")?)
            .bind(to_i64(now, "current time")?)
            .execute(&mut **transaction)
            .await?;
            if result.rows_affected() != 1 {
                return Err(RedemptionFinalizerError::Transition(
                    "redemption creation identity already exists".to_string(),
                ));
            }
        }
        FinalizedRedemptionEvent::LegResolved {
            redemption_id,
            log_index,
            ..
        } => {
            let index_token: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT index_token FROM redemption_finalizer_redemptions
                 WHERE source_id = ? AND redemption_id = ? AND resolved = 0",
            )
            .bind(source_id)
            .bind(redemption_id.as_slice())
            .fetch_optional(&mut **transaction)
            .await?;
            let index_token = index_token.ok_or_else(|| {
                RedemptionFinalizerError::Transition(
                    "leg resolution lacks an unresolved canonical creation".to_string(),
                )
            })?;
            sqlx::query(
                "UPDATE redemption_finalizer_redemptions
                 SET settlement_observed = 1, updated_at = ?
                 WHERE source_id = ? AND redemption_id = ?",
            )
            .bind(to_i64(now, "current time")?)
            .bind(source_id)
            .bind(redemption_id.as_slice())
            .execute(&mut **transaction)
            .await?;
            sqlx::query(
                "INSERT OR IGNORE INTO redemption_finalizer_jobs
                    (source_id, redemption_id, index_token, state, attempts,
                     next_attempt_at, last_error, trigger_block,
                     trigger_log_index, created_at, updated_at)
                 VALUES (?, ?, ?, 'queued', 0, ?, NULL, ?, ?, ?, ?)",
            )
            .bind(source_id)
            .bind(redemption_id.as_slice())
            .bind(&index_token)
            .bind(to_i64(now, "current time")?)
            .bind(to_i64(source_block, "trigger block")?)
            .bind(to_i64(log_index, "trigger log index")?)
            .bind(to_i64(now, "current time")?)
            .bind(to_i64(now, "current time")?)
            .execute(&mut **transaction)
            .await?;
            let stored_token: Vec<u8> = sqlx::query_scalar(
                "SELECT index_token FROM redemption_finalizer_jobs
                 WHERE source_id = ? AND redemption_id = ?",
            )
            .bind(source_id)
            .bind(redemption_id.as_slice())
            .fetch_one(&mut **transaction)
            .await?;
            if stored_token != index_token {
                return Err(RedemptionFinalizerError::Transition(
                    "finalization job index token conflict".to_string(),
                ));
            }
        }
        FinalizedRedemptionEvent::Finalized { redemption_id, .. } => {
            let result = sqlx::query(
                "UPDATE redemption_finalizer_redemptions
                 SET resolved = 1, updated_at = ?
                 WHERE source_id = ? AND redemption_id = ? AND resolved = 0",
            )
            .bind(to_i64(now, "current time")?)
            .bind(source_id)
            .bind(redemption_id.as_slice())
            .execute(&mut **transaction)
            .await?;
            if result.rows_affected() != 1 {
                return Err(RedemptionFinalizerError::Transition(
                    "finalized event lacks an unresolved canonical creation".to_string(),
                ));
            }
            let result = sqlx::query(
                "UPDATE redemption_finalizer_jobs
                 SET state = 'posted', updated_at = ?
                 WHERE source_id = ? AND redemption_id = ?",
            )
            .bind(to_i64(now, "current time")?)
            .bind(source_id)
            .bind(redemption_id.as_slice())
            .execute(&mut **transaction)
            .await?;
            if result.rows_affected() != 1 {
                return Err(RedemptionFinalizerError::Transition(
                    "finalized event lacks a durable finalization job".to_string(),
                ));
            }
        }
        FinalizedRedemptionEvent::StuckCancelled { redemption_id, .. } => {
            let result = sqlx::query(
                "UPDATE redemption_finalizer_redemptions
                 SET resolved = 1, updated_at = ?
                 WHERE source_id = ? AND redemption_id = ? AND resolved = 0",
            )
            .bind(to_i64(now, "current time")?)
            .bind(source_id)
            .bind(redemption_id.as_slice())
            .execute(&mut **transaction)
            .await?;
            if result.rows_affected() != 1 {
                return Err(RedemptionFinalizerError::Transition(
                    "stuck-cancel event lacks an unresolved canonical creation".to_string(),
                ));
            }
            sqlx::query(
                "UPDATE redemption_finalizer_jobs
                 SET state = 'superseded', updated_at = ?
                 WHERE source_id = ? AND redemption_id = ?
                   AND state IN ('queued', 'posting')",
            )
            .bind(to_i64(now, "current time")?)
            .bind(source_id)
            .bind(redemption_id.as_slice())
            .execute(&mut **transaction)
            .await?;
        }
    }
    Ok(())
}

async fn rebuild_derived(
    transaction: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    source_id: &str,
    now: u64,
) -> Result<(), RedemptionFinalizerError> {
    sqlx::query("DELETE FROM redemption_finalizer_jobs WHERE source_id = ?")
        .bind(source_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM redemption_finalizer_redemptions WHERE source_id = ?")
        .bind(source_id)
        .execute(&mut **transaction)
        .await?;
    let rows: Vec<StoredEventRow> = sqlx::query_as(
        "SELECT source_block, source_log_index, event_kind, redemption_id,
                index_token, deadline
         FROM redemption_finalizer_events WHERE source_id = ?
         ORDER BY source_block ASC, source_log_index ASC",
    )
    .bind(source_id)
    .fetch_all(&mut **transaction)
    .await?;
    for row in rows {
        let source_block = from_i64(row.0, "event source block")?;
        let event = decode_mirrored_event(row)?;
        apply_event(transaction, source_id, source_block, event, now).await?;
    }
    Ok(())
}

fn decode_mirrored_event(
    row: StoredEventRow,
) -> Result<FinalizedRedemptionEvent, RedemptionFinalizerError> {
    let (_, log_index, kind, redemption_id, index_token, deadline) = row;
    let redemption_id = decode_b256(&redemption_id, "mirrored redemption id")?;
    let log_index = from_i64(log_index, "mirrored log index")?;
    let placeholder_hash = B256::repeat_byte(1);
    match kind.as_str() {
        "created" => Ok(FinalizedRedemptionEvent::Created {
            redemption_id,
            index_token: decode_address(
                index_token.as_deref().ok_or_else(|| {
                    RedemptionFinalizerError::Decode("created mirror lacks index token".to_string())
                })?,
                "mirrored index token",
            )?,
            deadline: from_i64(
                deadline.ok_or_else(|| {
                    RedemptionFinalizerError::Decode("created mirror lacks deadline".to_string())
                })?,
                "mirrored deadline",
            )?,
            transaction_hash: placeholder_hash,
            transaction_index: 0,
            log_index,
        }),
        "leg_resolved" if index_token.is_none() && deadline.is_none() => {
            Ok(FinalizedRedemptionEvent::LegResolved {
                redemption_id,
                transaction_hash: placeholder_hash,
                transaction_index: 0,
                log_index,
            })
        }
        "finalized" if index_token.is_none() && deadline.is_none() => {
            Ok(FinalizedRedemptionEvent::Finalized {
                redemption_id,
                transaction_hash: placeholder_hash,
                transaction_index: 0,
                log_index,
            })
        }
        "stuck_cancelled" if index_token.is_none() && deadline.is_none() => {
            Ok(FinalizedRedemptionEvent::StuckCancelled {
                redemption_id,
                transaction_hash: placeholder_hash,
                transaction_index: 0,
                log_index,
            })
        }
        _ => Err(RedemptionFinalizerError::Decode(
            "invalid mirrored event shape".to_string(),
        )),
    }
}

fn event_shape(
    event: FinalizedRedemptionEvent,
) -> (&'static str, B256, Option<Address>, Option<u64>) {
    match event {
        FinalizedRedemptionEvent::Created {
            redemption_id,
            index_token,
            deadline,
            ..
        } => ("created", redemption_id, Some(index_token), Some(deadline)),
        FinalizedRedemptionEvent::LegResolved { redemption_id, .. } => {
            ("leg_resolved", redemption_id, None, None)
        }
        FinalizedRedemptionEvent::Finalized { redemption_id, .. } => {
            ("finalized", redemption_id, None, None)
        }
        FinalizedRedemptionEvent::StuckCancelled { redemption_id, .. } => {
            ("stuck_cancelled", redemption_id, None, None)
        }
    }
}

fn validate_checkpoint(
    checkpoint: FinalizedCheckpoint,
    now: u64,
) -> Result<(), RedemptionFinalizerError> {
    if checkpoint.block_hash == B256::ZERO
        || checkpoint.parent_hash == B256::ZERO
        || checkpoint.header_evidence_hash == B256::ZERO
        || checkpoint.logs_evidence_hash == B256::ZERO
        || now == 0
    {
        return Err(RedemptionFinalizerError::Transition(
            "checkpoint contains a zero hash/time".to_string(),
        ));
    }
    Ok(())
}

fn validate_event_order(
    events: &[FinalizedRedemptionEvent],
) -> Result<(), RedemptionFinalizerError> {
    let mut previous = None;
    for event in events {
        if event.redemption_id() == B256::ZERO {
            return Err(RedemptionFinalizerError::Transition(
                "redemption event has zero identity".to_string(),
            ));
        }
        if previous.is_some_and(|index| event.log_index() <= index) {
            return Err(RedemptionFinalizerError::Transition(
                "redemption events are not in strict log order".to_string(),
            ));
        }
        if let FinalizedRedemptionEvent::Created {
            index_token,
            deadline,
            ..
        } = event
        {
            if index_token.is_zero() || *deadline == 0 {
                return Err(RedemptionFinalizerError::Transition(
                    "redemption creation has a zero field".to_string(),
                ));
            }
        }
        previous = Some(event.log_index());
    }
    Ok(())
}

fn validate_source_id(source_id: &str) -> Result<(), RedemptionFinalizerError> {
    if source_id.is_empty()
        || source_id.len() > 128
        || !source_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RedemptionFinalizerError::Transition(
            "source id must be safe ASCII".to_string(),
        ));
    }
    Ok(())
}

fn decode_checkpoint(
    row: &StoredCheckpointRow,
) -> Result<FinalizedCheckpoint, RedemptionFinalizerError> {
    Ok(FinalizedCheckpoint {
        block_number: from_i64(row.0, "checkpoint number")?,
        block_hash: decode_b256(&row.1, "checkpoint hash")?,
        parent_hash: decode_b256(&row.2, "checkpoint parent")?,
        header_evidence_hash: decode_b256(&row.3, "checkpoint header evidence")?,
        logs_evidence_hash: decode_b256(&row.4, "checkpoint logs evidence")?,
    })
}

fn decode_job(row: &StoredJobRow) -> Result<FinalizationJob, RedemptionFinalizerError> {
    Ok(FinalizationJob {
        redemption_id: decode_b256(&row.0, "job redemption id")?,
        index_token: decode_address(&row.1, "job index token")?,
        state: FinalizationJobState::decode(&row.2)?,
        attempts: from_i64(row.3, "job attempts")?,
        next_attempt_at: from_i64(row.4, "job next attempt")?,
        trigger_block: from_i64(row.5, "job trigger block")?,
        trigger_log_index: from_i64(row.6, "job trigger log index")?,
        created_at: from_i64(row.7, "job created at")?,
        updated_at: from_i64(row.8, "job updated at")?,
    })
}

fn decode_b256(bytes: &[u8], label: &str) -> Result<B256, RedemptionFinalizerError> {
    B256::try_from(bytes)
        .map_err(|error| RedemptionFinalizerError::Decode(format!("{label}: {error}")))
}

fn decode_address(bytes: &[u8], label: &str) -> Result<Address, RedemptionFinalizerError> {
    Address::try_from(bytes)
        .map_err(|error| RedemptionFinalizerError::Decode(format!("{label}: {error}")))
}

fn to_i64(value: u64, label: &str) -> Result<i64, RedemptionFinalizerError> {
    i64::try_from(value)
        .map_err(|error| RedemptionFinalizerError::Decode(format!("{label}: {error}")))
}

fn from_i64(value: i64, label: &str) -> Result<u64, RedemptionFinalizerError> {
    u64::try_from(value)
        .map_err(|error| RedemptionFinalizerError::Decode(format!("{label}: {error}")))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use super::*;

    fn checkpoint(number: u8, parent: u8) -> FinalizedCheckpoint {
        FinalizedCheckpoint {
            block_number: u64::from(number),
            block_hash: B256::repeat_byte(number),
            parent_hash: B256::repeat_byte(parent),
            header_evidence_hash: B256::repeat_byte(number.saturating_add(40)),
            logs_evidence_hash: B256::repeat_byte(number.saturating_add(80)),
        }
    }

    fn created(id: u8, log_index: u64) -> FinalizedRedemptionEvent {
        FinalizedRedemptionEvent::Created {
            redemption_id: B256::repeat_byte(id),
            index_token: Address::repeat_byte(id.saturating_add(1)),
            deadline: 150,
            transaction_hash: B256::repeat_byte(id.saturating_add(2)),
            transaction_index: 0,
            log_index,
        }
    }

    fn resolved(id: u8, log_index: u64) -> FinalizedRedemptionEvent {
        FinalizedRedemptionEvent::LegResolved {
            redemption_id: B256::repeat_byte(id),
            transaction_hash: B256::repeat_byte(id.saturating_add(3)),
            transaction_index: 0,
            log_index,
        }
    }

    fn finalized(id: u8, log_index: u64) -> FinalizedRedemptionEvent {
        FinalizedRedemptionEvent::Finalized {
            redemption_id: B256::repeat_byte(id),
            transaction_hash: B256::repeat_byte(id.saturating_add(4)),
            transaction_index: 0,
            log_index,
        }
    }

    async fn file_store(label: &str) -> (SqliteRedemptionFinalizerStore, String) {
        let path = std::env::temp_dir().join(format!(
            "xindex-redemption-finalizer-{label}-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let store = SqliteRedemptionFinalizerStore::connect(&url, "observer-a")
            .await
            .expect("store");
        (store, path.to_string_lossy().into_owned())
    }

    #[tokio::test]
    async fn accepted_job_survives_crash_provider_outage_and_finalized_replay() {
        let (store, path) = file_store("restart").await;
        store
            .commit_source_block(checkpoint(10, 9), &[created(1, 1)], 100)
            .await
            .expect("created");
        store
            .commit_source_block(checkpoint(11, 10), &[resolved(1, 2)], 101)
            .await
            .expect("resolved");
        let first = store.claim_next(102).await.expect("claim").expect("job");
        assert_eq!(first.attempts, 1);
        drop(store);

        let url = format!("sqlite://{path}?mode=rwc");
        let reopened = SqliteRedemptionFinalizerStore::connect(&url, "observer-a")
            .await
            .expect("reopen");
        assert_eq!(reopened.recover_inflight(103).await.expect("recover"), 1);
        let second = reopened
            .claim_next(103)
            .await
            .expect("reclaim")
            .expect("job");
        assert_eq!(second.attempts, 2);
        reopened
            .retry(&second, 110, "provider_unavailable", 104)
            .await
            .expect("retry");
        assert!(reopened.claim_next(109).await.expect("not due").is_none());
        reopened
            .commit_source_block(checkpoint(12, 11), &[finalized(1, 3)], 110)
            .await
            .expect("finalized");
        assert!(reopened.claim_next(111).await.expect("terminal").is_none());
        let stats = reopened.stats(200).await.expect("stats");
        assert_eq!(stats.pending_redemptions, 0);
        assert_eq!(stats.active_jobs, 0);
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn rollback_rebuilds_only_retained_responsibility_and_exact_stuck_boundary() {
        let store = SqliteRedemptionFinalizerStore::connect("sqlite::memory:", "observer-a")
            .await
            .expect("store");
        let block_10 = checkpoint(10, 9);
        store
            .commit_source_block(block_10, &[created(1, 1)], 100)
            .await
            .expect("created");
        assert_eq!(store.stats(149).await.expect("fresh").stuck.len(), 0);
        assert_eq!(store.stats(150).await.expect("boundary").stuck.len(), 1);
        store
            .commit_source_block(checkpoint(11, 10), &[resolved(1, 2)], 151)
            .await
            .expect("resolved");
        assert!(store.claim_next(151).await.expect("claim").is_some());
        store
            .rollback_to(10, block_10.block_hash, 152)
            .await
            .expect("rollback");
        assert!(store.claim_next(152).await.expect("rolled back").is_none());
        store
            .commit_source_block(
                FinalizedCheckpoint {
                    block_hash: B256::repeat_byte(21),
                    ..checkpoint(11, 10)
                },
                &[resolved(1, 2)],
                153,
            )
            .await
            .expect("replacement");
        assert!(store
            .claim_next(153)
            .await
            .expect("replacement job")
            .is_some());
    }
}
