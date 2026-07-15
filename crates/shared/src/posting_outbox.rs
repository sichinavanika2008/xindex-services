//! Durable posting responsibility shared by collectors and supervised workers.
//!
//! A quorum is acknowledged only after its complete serialized payload is in
//! this outbox. Active generations are unique per logical identity, survive a
//! restart, and move through `queued -> posting -> posted` or an explicit
//! `expired`/`superseded` terminal state.

use alloy_primitives::B256;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use thiserror::Error;

const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Durable outbox failure. Callers fail closed for every variant.
#[derive(Debug, Error)]
pub enum PostingOutboxError {
    /// Underlying `SQLite` failure.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] sqlx::Error),
    /// Shared-schema migration failure.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// Stored bytes or integers violate the expected schema.
    #[error("decode error: {0}")]
    Decode(String),
    /// A requested transition is unsafe from the current state.
    #[error("invalid transition: {0}")]
    InvalidTransition(String),
    /// Restart recovery would allocate more active jobs than the caller's
    /// reviewed cache bound.
    #[error("{kind} has more than {limit} active posting jobs")]
    ActiveLimitExceeded { kind: String, limit: usize },
}

/// Durable posting-job state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostingJobState {
    Queued,
    Posting,
    Posted,
    Expired,
    Superseded,
}

impl PostingJobState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Posting => "posting",
            Self::Posted => "posted",
            Self::Expired => "expired",
            Self::Superseded => "superseded",
        }
    }

    fn decode(raw: &str) -> Result<Self, PostingOutboxError> {
        match raw {
            "queued" => Ok(Self::Queued),
            "posting" => Ok(Self::Posting),
            "posted" => Ok(Self::Posted),
            "expired" => Ok(Self::Expired),
            "superseded" => Ok(Self::Superseded),
            _ => Err(PostingOutboxError::Decode(format!(
                "unknown posting state {raw}"
            ))),
        }
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Posted | Self::Expired | Self::Superseded)
    }
}

/// Complete recoverable posting job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostingJob {
    pub kind: String,
    pub identity: Vec<u8>,
    pub generation: u64,
    pub payload_hash: B256,
    pub payload: Vec<u8>,
    pub state: PostingJobState,
    pub expires_at: u64,
    pub attempts: u64,
    pub next_attempt_at: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Borrowed values used for one transactional enqueue.
#[derive(Debug, Clone, Copy)]
pub struct NewPostingJob<'a> {
    pub kind: &'a str,
    pub identity: &'a [u8],
    pub generation: u64,
    pub payload_hash: B256,
    pub payload: &'a [u8],
    pub expires_at: u64,
    pub now: u64,
}

/// Result of durably accepting one generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostingEnqueueOutcome {
    Queued,
    Idempotent {
        state: PostingJobState,
    },
    Conflict {
        previous_generation: u64,
        previous_payload_hash: B256,
        previous_state: PostingJobState,
    },
}

/// SQLite-backed durable posting outbox.
#[derive(Clone)]
pub struct SqlitePostingOutbox {
    pool: SqlitePool,
}

impl std::fmt::Debug for SqlitePostingOutbox {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqlitePostingOutbox")
            .finish_non_exhaustive()
    }
}

impl SqlitePostingOutbox {
    /// Open the durable database and apply the shared schema migrations.
    ///
    /// # Errors
    /// Returns [`PostingOutboxError`] if the database cannot be opened or its
    /// schema cannot be migrated.
    pub async fn connect(database_url: &str) -> Result<Self, PostingOutboxError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    /// Atomically retire an expired active generation and enqueue a strictly
    /// newer complete payload. A live conflicting generation remains closed.
    ///
    /// # Errors
    /// Returns [`PostingOutboxError`] for malformed input, corrupt state, or a
    /// database failure.
    pub async fn enqueue(
        &self,
        job: NewPostingJob<'_>,
    ) -> Result<PostingEnqueueOutcome, PostingOutboxError> {
        validate_new_job(job)?;
        let generation_i = to_i64(job.generation, "job generation")?;
        let expires_i = to_i64(job.expires_at, "job expiry")?;
        let now_i = to_i64(job.now, "current time")?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        expire_due_in(&mut transaction, job.kind, now_i).await?;

        let exact: Option<(Vec<u8>, Vec<u8>, String)> = sqlx::query_as(
            "SELECT payload_hash, payload, state FROM posting_outbox_jobs
             WHERE job_kind = ? AND identity = ? AND generation = ?",
        )
        .bind(job.kind)
        .bind(job.identity)
        .bind(generation_i)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some((previous_hash, previous_payload, state_raw)) = exact {
            let previous_payload_hash = decode_b256(&previous_hash, "posting payload hash")?;
            let previous_state = PostingJobState::decode(&state_raw)?;
            let outcome =
                if previous_payload_hash == job.payload_hash && previous_payload == job.payload {
                    PostingEnqueueOutcome::Idempotent {
                        state: previous_state,
                    }
                } else {
                    PostingEnqueueOutcome::Conflict {
                        previous_generation: job.generation,
                        previous_payload_hash,
                        previous_state,
                    }
                };
            transaction.commit().await?;
            return Ok(outcome);
        }

        let active: Option<(i64, Vec<u8>, String)> = sqlx::query_as(
            "SELECT generation, payload_hash, state FROM posting_outbox_jobs
             WHERE job_kind = ? AND identity = ? AND state IN ('queued', 'posting')",
        )
        .bind(job.kind)
        .bind(job.identity)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some((previous_generation, previous_hash, state_raw)) = active {
            let outcome = PostingEnqueueOutcome::Conflict {
                previous_generation: from_i64(previous_generation, "active job generation")?,
                previous_payload_hash: decode_b256(&previous_hash, "active job payload hash")?,
                previous_state: PostingJobState::decode(&state_raw)?,
            };
            transaction.commit().await?;
            return Ok(outcome);
        }

        let latest: Option<(i64, Vec<u8>, String)> = sqlx::query_as(
            "SELECT generation, payload_hash, state FROM posting_outbox_jobs
             WHERE job_kind = ? AND identity = ?
             ORDER BY generation DESC LIMIT 1",
        )
        .bind(job.kind)
        .bind(job.identity)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some((previous_generation_i, previous_hash, state_raw)) = latest {
            let previous_generation = from_i64(previous_generation_i, "latest job generation")?;
            if job.generation <= previous_generation {
                let outcome = PostingEnqueueOutcome::Conflict {
                    previous_generation,
                    previous_payload_hash: decode_b256(&previous_hash, "latest job payload hash")?,
                    previous_state: PostingJobState::decode(&state_raw)?,
                };
                transaction.commit().await?;
                return Ok(outcome);
            }
        }

        sqlx::query(
            "INSERT INTO posting_outbox_jobs
                (job_kind, identity, generation, payload_hash, payload, state,
                 expires_at, attempts, next_attempt_at, last_error, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, 'queued', ?, 0, ?, NULL, ?, ?)",
        )
        .bind(job.kind)
        .bind(job.identity)
        .bind(generation_i)
        .bind(job.payload_hash.as_slice())
        .bind(job.payload)
        .bind(expires_i)
        .bind(now_i)
        .bind(now_i)
        .bind(now_i)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(PostingEnqueueOutcome::Queued)
    }

    /// Requeue jobs left in `posting` by a process crash. Call once at worker
    /// startup before claiming responsibility.
    ///
    /// # Errors
    /// Returns [`PostingOutboxError`] for an invalid kind/time, corrupt state,
    /// or a database failure.
    pub async fn recover_inflight(&self, kind: &str, now: u64) -> Result<u64, PostingOutboxError> {
        validate_kind(kind)?;
        let now_i = to_i64(now, "current time")?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        expire_due_in(&mut transaction, kind, now_i).await?;
        let result = sqlx::query(
            "UPDATE posting_outbox_jobs
             SET state = 'queued', next_attempt_at = ?, updated_at = ?,
                 last_error = 'worker_restarted'
             WHERE job_kind = ? AND state = 'posting' AND expires_at > ?",
        )
        .bind(now_i)
        .bind(now_i)
        .bind(kind)
        .bind(now_i)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(result.rows_affected())
    }

    /// Atomically claim the next due queued job and increment its durable
    /// attempt counter.
    ///
    /// # Errors
    /// Returns [`PostingOutboxError`] for invalid input, corrupt state, or a
    /// database failure.
    pub async fn claim_next(
        &self,
        kind: &str,
        now: u64,
    ) -> Result<Option<PostingJob>, PostingOutboxError> {
        validate_kind(kind)?;
        let now_i = to_i64(now, "current time")?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        expire_due_in(&mut transaction, kind, now_i).await?;
        let row = sqlx::query_as::<_, PostingJobRow>(
            "SELECT job_kind, identity, generation, payload_hash, payload, state,
                    expires_at, attempts, next_attempt_at, created_at, updated_at
             FROM posting_outbox_jobs
             WHERE job_kind = ? AND state = 'queued' AND next_attempt_at <= ?
             ORDER BY generation ASC LIMIT 1",
        )
        .bind(kind)
        .bind(now_i)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(mut job) = row.map(decode_job).transpose()? else {
            transaction.commit().await?;
            return Ok(None);
        };
        sqlx::query(
            "UPDATE posting_outbox_jobs
             SET state = 'posting', attempts = attempts + 1, updated_at = ?
             WHERE job_kind = ? AND identity = ? AND generation = ? AND state = 'queued'",
        )
        .bind(now_i)
        .bind(&job.kind)
        .bind(&job.identity)
        .bind(to_i64(job.generation, "job generation")?)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        job.state = PostingJobState::Posting;
        job.attempts = job.attempts.saturating_add(1);
        job.updated_at = now;
        Ok(Some(job))
    }

    /// Load all active jobs for restart recovery or an in-memory response
    /// index. Expired jobs are transitioned before the read.
    ///
    /// # Errors
    /// Returns [`PostingOutboxError`] for invalid input, corrupt state, or a
    /// database failure.
    pub async fn load_active(
        &self,
        kind: &str,
        now: u64,
    ) -> Result<Vec<PostingJob>, PostingOutboxError> {
        validate_kind(kind)?;
        let now_i = to_i64(now, "current time")?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        expire_due_in(&mut transaction, kind, now_i).await?;
        let rows = sqlx::query_as::<_, PostingJobRow>(
            "SELECT job_kind, identity, generation, payload_hash, payload, state,
                    expires_at, attempts, next_attempt_at, created_at, updated_at
             FROM posting_outbox_jobs
             WHERE job_kind = ? AND state IN ('queued', 'posting')
             ORDER BY generation ASC",
        )
        .bind(kind)
        .fetch_all(&mut *transaction)
        .await?;
        transaction.commit().await?;
        rows.into_iter().map(decode_job).collect()
    }

    /// Load active jobs with a fail-closed restart/cache allocation bound.
    /// The query reads at most `limit + 1` rows, so a pre-fix oversized
    /// database cannot first allocate the full unbounded result.
    ///
    /// # Errors
    /// Zero/oversized limits, corrupt state/database failures, or more than
    /// `limit` active rows.
    pub async fn load_active_bounded(
        &self,
        kind: &str,
        now: u64,
        limit: usize,
    ) -> Result<Vec<PostingJob>, PostingOutboxError> {
        validate_kind(kind)?;
        let query_limit = limit.checked_add(1).ok_or_else(|| {
            PostingOutboxError::InvalidTransition("active load limit overflow".to_string())
        })?;
        if limit == 0 {
            return Err(PostingOutboxError::InvalidTransition(
                "active load limit must be non-zero".to_string(),
            ));
        }
        let query_limit = i64::try_from(query_limit).map_err(|error| {
            PostingOutboxError::InvalidTransition(format!(
                "active load limit does not fit SQLite: {error}"
            ))
        })?;
        let now_i = to_i64(now, "current time")?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        expire_due_in(&mut transaction, kind, now_i).await?;
        let rows = sqlx::query_as::<_, PostingJobRow>(
            "SELECT job_kind, identity, generation, payload_hash, payload, state,
                    expires_at, attempts, next_attempt_at, created_at, updated_at
             FROM posting_outbox_jobs
             WHERE job_kind = ? AND state IN ('queued', 'posting')
             ORDER BY generation ASC
             LIMIT ?",
        )
        .bind(kind)
        .bind(query_limit)
        .fetch_all(&mut *transaction)
        .await?;
        transaction.commit().await?;
        if rows.len() > limit {
            return Err(PostingOutboxError::ActiveLimitExceeded {
                kind: kind.to_string(),
                limit,
            });
        }
        rows.into_iter().map(decode_job).collect()
    }

    /// Return a failed posting attempt to the queue with a durable retry time.
    ///
    /// # Errors
    /// Returns [`PostingOutboxError`] if the retry is invalid, the caller no
    /// longer owns the job, or the database fails.
    pub async fn retry(
        &self,
        job: &PostingJob,
        next_attempt_at: u64,
        error: &str,
        now: u64,
    ) -> Result<(), PostingOutboxError> {
        if next_attempt_at < now || error.is_empty() || error.len() > 512 {
            return Err(PostingOutboxError::InvalidTransition(
                "invalid retry time or error class".to_string(),
            ));
        }
        let result = sqlx::query(
            "UPDATE posting_outbox_jobs
             SET state = 'queued', next_attempt_at = ?, last_error = ?, updated_at = ?
             WHERE job_kind = ? AND identity = ? AND generation = ?
               AND payload_hash = ? AND state = 'posting'",
        )
        .bind(to_i64(next_attempt_at, "next attempt")?)
        .bind(error)
        .bind(to_i64(now, "current time")?)
        .bind(&job.kind)
        .bind(&job.identity)
        .bind(to_i64(job.generation, "job generation")?)
        .bind(job.payload_hash.as_slice())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(PostingOutboxError::InvalidTransition(
                "posting job was not owned for retry".to_string(),
            ))
        }
    }

    /// Complete a job with one explicit terminal state. Repeating the exact
    /// terminal transition is idempotent.
    ///
    /// # Errors
    /// Returns [`PostingOutboxError`] for a nonterminal target, an invalid
    /// ownership transition, corrupt state, or a database failure.
    pub async fn finish(
        &self,
        job: &PostingJob,
        terminal: PostingJobState,
        now: u64,
    ) -> Result<(), PostingOutboxError> {
        if !terminal.is_terminal() {
            return Err(PostingOutboxError::InvalidTransition(
                "finish requires a terminal state".to_string(),
            ));
        }
        let result = sqlx::query(
            "UPDATE posting_outbox_jobs SET state = ?, updated_at = ?
             WHERE job_kind = ? AND identity = ? AND generation = ?
               AND payload_hash = ? AND state IN ('queued', 'posting')",
        )
        .bind(terminal.as_str())
        .bind(to_i64(now, "current time")?)
        .bind(&job.kind)
        .bind(&job.identity)
        .bind(to_i64(job.generation, "job generation")?)
        .bind(job.payload_hash.as_slice())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 1 {
            return Ok(());
        }
        let state: Option<String> = sqlx::query_scalar(
            "SELECT state FROM posting_outbox_jobs
             WHERE job_kind = ? AND identity = ? AND generation = ? AND payload_hash = ?",
        )
        .bind(&job.kind)
        .bind(&job.identity)
        .bind(to_i64(job.generation, "job generation")?)
        .bind(job.payload_hash.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        if state.as_deref() == Some(terminal.as_str()) {
            Ok(())
        } else {
            Err(PostingOutboxError::InvalidTransition(
                "posting job cannot enter requested terminal state".to_string(),
            ))
        }
    }
}

type PostingJobRow = (
    String,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    String,
    i64,
    i64,
    i64,
    i64,
    i64,
);

fn decode_job(row: PostingJobRow) -> Result<PostingJob, PostingOutboxError> {
    Ok(PostingJob {
        kind: row.0,
        identity: row.1,
        generation: from_i64(row.2, "job generation")?,
        payload_hash: decode_b256(&row.3, "job payload hash")?,
        payload: row.4,
        state: PostingJobState::decode(&row.5)?,
        expires_at: from_i64(row.6, "job expiry")?,
        attempts: from_i64(row.7, "job attempts")?,
        next_attempt_at: from_i64(row.8, "next attempt")?,
        created_at: from_i64(row.9, "job creation")?,
        updated_at: from_i64(row.10, "job update")?,
    })
}

async fn expire_due_in(
    transaction: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    kind: &str,
    now_i: i64,
) -> Result<(), PostingOutboxError> {
    sqlx::query(
        "UPDATE posting_outbox_jobs
         SET state = 'expired', updated_at = ?
         WHERE job_kind = ? AND state IN ('queued', 'posting') AND expires_at <= ?",
    )
    .bind(now_i)
    .bind(kind)
    .bind(now_i)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn validate_new_job(job: NewPostingJob<'_>) -> Result<(), PostingOutboxError> {
    validate_kind(job.kind)?;
    if job.identity.is_empty()
        || job.identity.len() > 256
        || job.generation == 0
        || job.generation != job.expires_at
        || job.expires_at <= job.now
        || job.payload_hash == B256::ZERO
        || job.payload.is_empty()
        || job.payload.len() > MAX_PAYLOAD_BYTES
    {
        return Err(PostingOutboxError::InvalidTransition(
            "invalid posting job identity, generation, hash, payload, or expiry".to_string(),
        ));
    }
    Ok(())
}

fn validate_kind(kind: &str) -> Result<(), PostingOutboxError> {
    if kind.is_empty()
        || kind.len() > 64
        || !kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(PostingOutboxError::InvalidTransition(
            "invalid posting job kind".to_string(),
        ));
    }
    Ok(())
}

fn to_i64(value: u64, field: &str) -> Result<i64, PostingOutboxError> {
    i64::try_from(value).map_err(|error| {
        PostingOutboxError::Decode(format!("{field} does not fit SQLite: {error}"))
    })
}

fn from_i64(value: i64, field: &str) -> Result<u64, PostingOutboxError> {
    u64::try_from(value)
        .map_err(|error| PostingOutboxError::Decode(format!("{field} is negative: {error}")))
}

fn decode_b256(bytes: &[u8], field: &str) -> Result<B256, PostingOutboxError> {
    B256::try_from(bytes)
        .map_err(|error| PostingOutboxError::Decode(format!("{field} is not 32 bytes: {error}")))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use super::*;

    async fn outbox(label: &str) -> (SqlitePostingOutbox, String) {
        let path = std::env::temp_dir().join(format!(
            "xindex-posting-outbox-{label}-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let outbox = SqlitePostingOutbox::connect(&url).await.expect("outbox");
        (outbox, path.to_string_lossy().into_owned())
    }

    fn new_job<'a>(
        identity: &'a [u8],
        generation: u64,
        hash: B256,
        payload: &'a [u8],
        now: u64,
    ) -> NewPostingJob<'a> {
        NewPostingJob {
            kind: "registry_inbound",
            identity,
            generation,
            payload_hash: hash,
            payload,
            expires_at: generation,
            now,
        }
    }

    #[tokio::test]
    async fn accepted_job_survives_crash_and_retries_until_terminal() {
        let (outbox, path) = outbox("restart").await;
        let identity = 7u64.to_be_bytes();
        let hash = B256::repeat_byte(0x11);
        assert_eq!(
            outbox
                .enqueue(new_job(&identity, 200, hash, b"quorum-a", 100))
                .await
                .expect("enqueue"),
            PostingEnqueueOutcome::Queued
        );
        assert_eq!(
            outbox
                .enqueue(new_job(&identity, 200, hash, b"quorum-a", 101))
                .await
                .expect("duplicate"),
            PostingEnqueueOutcome::Idempotent {
                state: PostingJobState::Queued
            }
        );
        let first = outbox
            .claim_next("registry_inbound", 102)
            .await
            .expect("claim")
            .expect("job");
        assert_eq!(first.attempts, 1);
        drop(outbox);

        let url = format!("sqlite://{path}?mode=rwc");
        let reopened = SqlitePostingOutbox::connect(&url).await.expect("reopen");
        assert_eq!(
            reopened
                .recover_inflight("registry_inbound", 103)
                .await
                .expect("recover"),
            1
        );
        let second = reopened
            .claim_next("registry_inbound", 103)
            .await
            .expect("reclaim")
            .expect("job");
        assert_eq!(second.attempts, 2);
        reopened
            .retry(&second, 110, "provider_unavailable", 104)
            .await
            .expect("retry");
        assert!(reopened
            .claim_next("registry_inbound", 109)
            .await
            .expect("not due")
            .is_none());
        let third = reopened
            .claim_next("registry_inbound", 110)
            .await
            .expect("due")
            .expect("job");
        reopened
            .finish(&third, PostingJobState::Posted, 111)
            .await
            .expect("posted");
        assert!(reopened
            .load_active("registry_inbound", 112)
            .await
            .expect("active")
            .is_empty());
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn live_conflict_fails_closed_then_exact_expiry_allows_one_new_generation() {
        let (outbox, path) = outbox("generation").await;
        let identity = 9u64.to_be_bytes();
        let old = B256::repeat_byte(0x21);
        let left_hash = B256::repeat_byte(0x22);
        let right_hash = B256::repeat_byte(0x23);
        outbox
            .enqueue(new_job(&identity, 120, old, b"old", 100))
            .await
            .expect("old");
        assert!(matches!(
            outbox
                .enqueue(new_job(&identity, 180, left_hash, b"left", 119))
                .await
                .expect("live conflict"),
            PostingEnqueueOutcome::Conflict { .. }
        ));

        let left = outbox.clone();
        let right = outbox.clone();
        let (a, b) = tokio::join!(
            left.enqueue(new_job(&identity, 180, left_hash, b"left", 120)),
            right.enqueue(new_job(&identity, 181, right_hash, b"right", 120))
        );
        let outcomes = [a.expect("left"), b.expect("right")];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PostingEnqueueOutcome::Queued))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PostingEnqueueOutcome::Conflict { .. }))
                .count(),
            1
        );
        drop(outbox);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn bounded_restart_load_never_allocates_past_limit() {
        let (outbox, path) = outbox("bounded-load").await;
        for identity in 1u8..=3 {
            outbox
                .enqueue(new_job(
                    &[identity],
                    200 + u64::from(identity),
                    B256::repeat_byte(identity),
                    &[identity],
                    100,
                ))
                .await
                .expect("enqueue");
        }
        assert!(matches!(
            outbox.load_active_bounded("registry_inbound", 100, 2).await,
            Err(PostingOutboxError::ActiveLimitExceeded { limit: 2, .. })
        ));
        assert_eq!(
            outbox
                .load_active_bounded("registry_inbound", 100, 3)
                .await
                .expect("bounded load")
                .len(),
            3
        );
        drop(outbox);
        let _ = std::fs::remove_file(path);
    }
}
