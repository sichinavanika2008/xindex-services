//! Durable, finalized-only Ethereum event facts with explicit reorg rollback.

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolEvent;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use thiserror::Error;

use crate::bindings::{IntentQueue, ThorchainAdapter};
use crate::finalized_rpc::FinalizedLog;
use crate::observer::{CancelFacts, LegFacts, ObservedCancel, ObservedLeg, RedeemLegSource};

type StoredLegRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64);
type StoredCheckpointRow = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type StoredDispatchRow = (
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
);
type StoredMintRow = (
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
);

#[derive(Debug, Error)]
pub enum FinalizedObserverError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] sqlx::Error),
    #[error("migration: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("invalid observer transition: {0}")]
    Transition(String),
    #[error("corrupt observer state: {0}")]
    Decode(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedCheckpoint {
    pub block_number: u64,
    pub block_hash: B256,
    pub parent_hash: B256,
    pub header_evidence_hash: B256,
    pub logs_evidence_hash: B256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedLegEvent {
    pub dispatch_id: B256,
    pub redemption_id: B256,
    pub leg_index: u32,
    pub target_token: Address,
    pub facts: LegFacts,
    pub transaction_hash: B256,
    pub transaction_index: u64,
    pub log_index: u64,
}

/// One current-protocol mint intent paired with the adapter `Acquired` event
/// from the exact same finalized Ethereum transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedMintEvent {
    pub intent_id: B256,
    pub slot_index: u32,
    pub slot_asset_id: B256,
    pub slot_expected_amount: U256,
    pub index_token: Address,
    pub originator: Address,
    pub funding_token: Address,
    pub amount_in: U256,
    pub deadline: u64,
    pub acquire_memo: Vec<u8>,
    pub acquire_vault: Address,
    pub transaction_hash: B256,
    pub transaction_index: u64,
    pub intent_log_index: u64,
    pub acquire_log_index: u64,
}

/// Complete retained canonical mint dispatch used by settlement observers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedMintRecord {
    pub intent_id: B256,
    pub slot_index: u32,
    pub slot_asset_id: B256,
    pub index_token: Address,
    pub funding_token: Address,
    pub amount_in: U256,
    pub deadline: u64,
    pub acquire_memo: Vec<u8>,
    pub acquire_vault: Address,
    pub observed_at: u64,
    pub source_block: u64,
    pub source_block_hash: B256,
    pub source_transaction_hash: B256,
    pub source_transaction_index: u64,
    pub intent_log_index: u64,
    pub acquire_log_index: u64,
}

/// Complete canonical dispatch facts consumed by the custody coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedDispatchRecord {
    pub dispatch_id: B256,
    pub redemption_id: B256,
    pub leg_index: u32,
    pub target_token: Address,
    pub facts: LegFacts,
    pub observed_at: u64,
    pub source_block: u64,
    pub source_block_hash: B256,
    pub source_transaction_hash: B256,
    pub source_transaction_index: u64,
    pub source_log_index: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedCancelEvent {
    pub cancel_id: B256,
    pub facts: CancelFacts,
    pub log_index: u64,
}

#[derive(Debug, Clone)]
pub struct SqliteFinalizedObserverStore {
    pool: SqlitePool,
    observer_id: String,
}

impl SqliteFinalizedObserverStore {
    /// Open durable state for one contract/role observer.
    ///
    /// # Errors
    /// Unsafe identity, database connection, or migration failure.
    pub async fn connect(
        database_url: &str,
        observer_id: &str,
    ) -> Result<Self, FinalizedObserverError> {
        validate_observer_id(observer_id)?;
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self {
            pool,
            observer_id: observer_id.to_string(),
        })
    }

    /// Latest durably committed canonical checkpoint.
    ///
    /// # Errors
    /// Database or stored-value decode failure.
    pub async fn last_checkpoint(
        &self,
    ) -> Result<Option<FinalizedCheckpoint>, FinalizedObserverError> {
        let row: Option<StoredCheckpointRow> = sqlx::query_as(
            "SELECT block_number, block_hash, parent_hash,
                    header_evidence_hash, logs_evidence_hash
             FROM evm_observer_blocks WHERE observer_id = ?
             ORDER BY block_number DESC LIMIT 1",
        )
        .bind(&self.observer_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(decode_checkpoint).transpose()
    }

    /// Stored hash at a retained height, used to locate a common ancestor.
    ///
    /// # Errors
    /// Database or stored hash decode failure.
    pub async fn checkpoint_hash(
        &self,
        block_number: u64,
    ) -> Result<Option<B256>, FinalizedObserverError> {
        let row: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT block_hash FROM evm_observer_blocks
             WHERE observer_id = ? AND block_number = ?",
        )
        .bind(&self.observer_id)
        .bind(to_i64(block_number, "block number")?)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|bytes| decode_b256(&bytes, "checkpoint hash"))
            .transpose()
    }

    /// Atomically append one canonical block and all relevant decoded events.
    /// Events become visible only together with the checkpoint.
    ///
    /// # Errors
    /// Non-contiguous/wrong-parent blocks, conflicting event identities, or
    /// database/decode failure.
    #[expect(
        clippy::too_many_lines,
        reason = "one SQL transaction deliberately makes the checkpoint and all decoded event classes atomic"
    )]
    pub async fn commit_block(
        &self,
        checkpoint: FinalizedCheckpoint,
        observed_at: u64,
        mints: &[FinalizedMintEvent],
        legs: &[FinalizedLegEvent],
        cancels: &[FinalizedCancelEvent],
    ) -> Result<(), FinalizedObserverError> {
        validate_checkpoint_input(&checkpoint, observed_at)?;
        let mut transaction = self.pool.begin().await?;
        let previous: Option<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT block_number, block_hash FROM evm_observer_blocks
             WHERE observer_id = ? ORDER BY block_number DESC LIMIT 1",
        )
        .bind(&self.observer_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some((number_i, hash)) = previous {
            let number = from_i64(number_i, "previous block")?;
            let hash = decode_b256(&hash, "previous block hash")?;
            if checkpoint.block_number == number && checkpoint.block_hash == hash {
                transaction.rollback().await?;
                return Ok(());
            }
            if checkpoint.block_number != number.saturating_add(1) || checkpoint.parent_hash != hash
            {
                return Err(FinalizedObserverError::Transition(format!(
                    "block {} does not extend {}",
                    checkpoint.block_number, number
                )));
            }
        }
        sqlx::query(
            "INSERT INTO evm_observer_blocks
                (observer_id, block_number, block_hash, parent_hash,
                 header_evidence_hash, logs_evidence_hash, processed_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&self.observer_id)
        .bind(to_i64(checkpoint.block_number, "block number")?)
        .bind(checkpoint.block_hash.as_slice())
        .bind(checkpoint.parent_hash.as_slice())
        .bind(checkpoint.header_evidence_hash.as_slice())
        .bind(checkpoint.logs_evidence_hash.as_slice())
        .bind(to_i64(observed_at, "observation time")?)
        .execute(&mut *transaction)
        .await?;
        for event in mints {
            validate_mint(event)?;
            let result = sqlx::query(
                "INSERT OR IGNORE INTO evm_observer_mints
                    (observer_id, intent_id, slot_index, slot_asset_id,
                     slot_expected_amount, index_token, originator,
                     funding_token, amount_in, deadline, acquire_memo,
                     acquire_vault, observed_at, source_block,
                     source_block_hash, source_transaction_hash,
                     source_transaction_index, intent_log_index,
                     acquire_log_index)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&self.observer_id)
            .bind(event.intent_id.as_slice())
            .bind(i64::from(event.slot_index))
            .bind(event.slot_asset_id.as_slice())
            .bind(event.slot_expected_amount.to_be_bytes::<32>().as_slice())
            .bind(event.index_token.as_slice())
            .bind(event.originator.as_slice())
            .bind(event.funding_token.as_slice())
            .bind(event.amount_in.to_be_bytes::<32>().as_slice())
            .bind(to_i64(event.deadline, "mint deadline")?)
            .bind(&event.acquire_memo)
            .bind(event.acquire_vault.as_slice())
            .bind(to_i64(observed_at, "observation time")?)
            .bind(to_i64(checkpoint.block_number, "source block")?)
            .bind(checkpoint.block_hash.as_slice())
            .bind(event.transaction_hash.as_slice())
            .bind(to_i64(event.transaction_index, "transaction index")?)
            .bind(to_i64(event.intent_log_index, "intent log index")?)
            .bind(to_i64(event.acquire_log_index, "acquire log index")?)
            .execute(&mut *transaction)
            .await?;
            if result.rows_affected() == 0 {
                return Err(FinalizedObserverError::Transition(
                    "conflicting/repeated mint event identity".to_string(),
                ));
            }
        }
        for event in legs {
            validate_leg(event)?;
            let result = sqlx::query(
                "INSERT OR IGNORE INTO evm_observer_legs
                    (observer_id, dispatch_id, redemption_id, leg_index,
                     target_token, amount, memo, final_destination, observed_at,
                     source_block, source_block_hash, source_transaction_hash,
                     source_transaction_index, source_log_index)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&self.observer_id)
            .bind(event.dispatch_id.as_slice())
            .bind(event.redemption_id.as_slice())
            .bind(i64::from(event.leg_index))
            .bind(event.target_token.as_slice())
            .bind(event.facts.amount.to_be_bytes::<32>().as_slice())
            .bind(&event.facts.memo)
            .bind(event.facts.final_destination.as_slice())
            .bind(to_i64(observed_at, "observation time")?)
            .bind(to_i64(checkpoint.block_number, "source block")?)
            .bind(checkpoint.block_hash.as_slice())
            .bind(event.transaction_hash.as_slice())
            .bind(to_i64(event.transaction_index, "transaction index")?)
            .bind(to_i64(event.log_index, "log index")?)
            .execute(&mut *transaction)
            .await?;
            if result.rows_affected() == 0 {
                return Err(FinalizedObserverError::Transition(
                    "conflicting/repeated redemption event identity".to_string(),
                ));
            }
        }
        for event in cancels {
            let result = sqlx::query(
                "INSERT OR IGNORE INTO evm_observer_cancels
                    (observer_id, cancel_id, intent_id, slot_index, observed_at,
                     source_block, source_block_hash, source_log_index)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&self.observer_id)
            .bind(event.cancel_id.as_slice())
            .bind(event.facts.intent_id.as_slice())
            .bind(i64::from(event.facts.slot_index))
            .bind(to_i64(observed_at, "observation time")?)
            .bind(to_i64(checkpoint.block_number, "source block")?)
            .bind(checkpoint.block_hash.as_slice())
            .bind(to_i64(event.log_index, "log index")?)
            .execute(&mut *transaction)
            .await?;
            if result.rows_affected() == 0 {
                return Err(FinalizedObserverError::Transition(
                    "conflicting/repeated cancellation event identity".to_string(),
                ));
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Roll back block journal and derived facts above a verified common
    /// ancestor. The deletion is atomic.
    ///
    /// # Errors
    /// Ancestor hash mismatch/absence or database failure.
    pub async fn rollback_to(
        &self,
        ancestor_number: u64,
        ancestor_hash: B256,
    ) -> Result<(), FinalizedObserverError> {
        let retained = self.checkpoint_hash(ancestor_number).await?;
        if retained != Some(ancestor_hash) {
            return Err(FinalizedObserverError::Transition(
                "rollback target is not a retained matching ancestor".to_string(),
            ));
        }
        let height = to_i64(ancestor_number, "ancestor block")?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "DELETE FROM evm_observer_mints
             WHERE observer_id = ? AND source_block > ?",
        )
        .bind(&self.observer_id)
        .bind(height)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM evm_observer_legs
             WHERE observer_id = ? AND source_block > ?",
        )
        .bind(&self.observer_id)
        .bind(height)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM evm_observer_cancels
             WHERE observer_id = ? AND source_block > ?",
        )
        .bind(&self.observer_id)
        .bind(height)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM evm_observer_blocks
             WHERE observer_id = ? AND block_number > ?",
        )
        .bind(&self.observer_id)
        .bind(height)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// All retained canonical cancellation facts, for restoring the observer's
    /// in-memory compatibility view after restart.
    ///
    /// # Errors
    /// Database or decode failure.
    pub async fn all_cancels(&self) -> Result<Vec<(B256, ObservedCancel)>, FinalizedObserverError> {
        let rows: Vec<(Vec<u8>, Vec<u8>, i64, i64)> = sqlx::query_as(
            "SELECT cancel_id, intent_id, slot_index, observed_at
             FROM evm_observer_cancels WHERE observer_id = ?",
        )
        .bind(&self.observer_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(cancel, intent, slot, observed)| {
                Ok((
                    decode_b256(&cancel, "cancel id")?,
                    ObservedCancel {
                        facts: CancelFacts {
                            intent_id: decode_b256(&intent, "intent id")?,
                            slot_index: u32::try_from(slot).map_err(|error| {
                                FinalizedObserverError::Decode(format!(
                                    "slot index out of range: {error}"
                                ))
                            })?,
                        },
                        observed_at: from_i64(observed, "cancel observed at")?,
                    },
                ))
            })
            .collect()
    }

    /// Read one exact finalized mint/adapter dispatch pair.
    ///
    /// # Errors
    /// Database or stored-value decode failure.
    pub async fn mint(
        &self,
        intent_id: B256,
        slot_index: u32,
    ) -> Result<Option<FinalizedMintRecord>, FinalizedObserverError> {
        let row: Option<StoredMintRow> = sqlx::query_as(
            "SELECT intent_id, slot_index, slot_asset_id, index_token,
                    funding_token, amount_in, deadline, acquire_memo,
                    acquire_vault, observed_at, source_block,
                    source_block_hash, source_transaction_hash,
                    source_transaction_index, intent_log_index,
                    acquire_log_index
             FROM evm_observer_mints
             WHERE observer_id = ? AND intent_id = ? AND slot_index = ?",
        )
        .bind(&self.observer_id)
        .bind(intent_id.as_slice())
        .bind(i64::from(slot_index))
        .fetch_optional(&self.pool)
        .await?;
        row.map(decode_mint).transpose()
    }

    /// List all retained canonical mint dispatches in deterministic order.
    ///
    /// # Errors
    /// Database or stored-value decode failure.
    pub async fn all_mints(&self) -> Result<Vec<FinalizedMintRecord>, FinalizedObserverError> {
        let rows: Vec<StoredMintRow> = sqlx::query_as(
            "SELECT intent_id, slot_index, slot_asset_id, index_token,
                    funding_token, amount_in, deadline, acquire_memo,
                    acquire_vault, observed_at, source_block,
                    source_block_hash, source_transaction_hash,
                    source_transaction_index, intent_log_index,
                    acquire_log_index
             FROM evm_observer_mints WHERE observer_id = ?
             ORDER BY source_block ASC, intent_log_index ASC",
        )
        .bind(&self.observer_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(decode_mint).collect()
    }

    /// Read the complete canonical dispatch for one redemption leg.
    ///
    /// # Errors
    /// Database or stored-value decode failure.
    pub async fn dispatch(
        &self,
        redemption_id: B256,
        leg_index: u32,
    ) -> Result<Option<FinalizedDispatchRecord>, FinalizedObserverError> {
        let row: Option<StoredDispatchRow> = sqlx::query_as(
            "SELECT dispatch_id, redemption_id, leg_index, target_token,
                    amount, memo, final_destination, observed_at, source_block,
                    source_block_hash, source_transaction_hash,
                    source_transaction_index, source_log_index
             FROM evm_observer_legs
             WHERE observer_id = ? AND redemption_id = ? AND leg_index = ?",
        )
        .bind(&self.observer_id)
        .bind(redemption_id.as_slice())
        .bind(i64::from(leg_index))
        .fetch_optional(&self.pool)
        .await?;
        row.map(decode_dispatch).transpose()
    }

    /// List every retained canonical dispatch in deterministic chain order.
    /// Callers combine this with their independent one-shot registry, so a
    /// transient failure is retried on the next scan without advancing a
    /// lossy cursor.
    ///
    /// # Errors
    /// Database or stored-value decode failure.
    pub async fn all_dispatches(
        &self,
    ) -> Result<Vec<FinalizedDispatchRecord>, FinalizedObserverError> {
        let rows: Vec<StoredDispatchRow> = sqlx::query_as(
            "SELECT dispatch_id, redemption_id, leg_index, target_token,
                    amount, memo, final_destination, observed_at, source_block,
                    source_block_hash, source_transaction_hash,
                    source_transaction_index, source_log_index
             FROM evm_observer_legs WHERE observer_id = ?
             ORDER BY source_block ASC, source_log_index ASC",
        )
        .bind(&self.observer_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(decode_dispatch).collect()
    }
}

/// Decode the exact adapter event allowlist from one finalized block. Any
/// unexpected address/topic or malformed ABI is a hard failure; the caller
/// must not advance its checkpoint with a partial event set.
///
/// # Errors
/// Address/topic mismatch, duplicate log identity, ABI decode failure, or a
/// slot index that cannot fit the service's canonical `u32` wire shape.
pub fn decode_adapter_logs(
    adapter: Address,
    redemption_leg_index: u32,
    logs: &[FinalizedLog],
) -> Result<(Vec<FinalizedLegEvent>, Vec<FinalizedCancelEvent>), FinalizedObserverError> {
    let mut legs = Vec::new();
    let mut cancels = Vec::new();
    let mut identities = std::collections::HashSet::new();
    for log in logs {
        if log.address != adapter || !identities.insert((log.transaction_hash, log.log_index)) {
            return Err(FinalizedObserverError::Decode(
                "unexpected adapter address or duplicate log identity".to_string(),
            ));
        }
        match log.topics.first().copied() {
            Some(topic) if topic == ThorchainAdapter::RedeemDispatched::SIGNATURE_HASH => {
                let event = ThorchainAdapter::RedeemDispatched::decode_raw_log(
                    log.topics.iter().copied(),
                    &log.data,
                    true,
                )
                .map_err(|error| {
                    FinalizedObserverError::Decode(format!(
                        "RedeemDispatched at log {}: {error}",
                        log.log_index
                    ))
                })?;
                legs.push(FinalizedLegEvent {
                    dispatch_id: event.dispatchId,
                    redemption_id: event.redemptionId,
                    leg_index: redemption_leg_index,
                    target_token: event.targetToken,
                    facts: LegFacts {
                        amount: event.amount,
                        memo: event.memo.as_bytes().to_vec(),
                        final_destination: event.destination,
                    },
                    transaction_hash: log.transaction_hash,
                    transaction_index: log.transaction_index,
                    log_index: log.log_index,
                });
            }
            Some(topic) if topic == ThorchainAdapter::AcquireCancelled::SIGNATURE_HASH => {
                let event = ThorchainAdapter::AcquireCancelled::decode_raw_log(
                    log.topics.iter().copied(),
                    &log.data,
                    true,
                )
                .map_err(|error| {
                    FinalizedObserverError::Decode(format!(
                        "AcquireCancelled at log {}: {error}",
                        log.log_index
                    ))
                })?;
                cancels.push(FinalizedCancelEvent {
                    cancel_id: event.cancelId,
                    facts: CancelFacts {
                        intent_id: event.intentId,
                        slot_index: u32::try_from(event.slotIndex).map_err(|error| {
                            FinalizedObserverError::Decode(format!(
                                "AcquireCancelled slot index: {error}"
                            ))
                        })?,
                    },
                    log_index: log.log_index,
                });
            }
            _ => {
                return Err(FinalizedObserverError::Decode(format!(
                    "unexpected adapter event topic at log {}",
                    log.log_index
                )))
            }
        }
    }
    legs.sort_by_key(|event| event.log_index);
    cancels.sort_by_key(|event| event.log_index);
    Ok((legs, cancels))
}

/// Complete decoded event classes for one finalized protocol block.
pub type DecodedProtocolLogs = (
    Vec<FinalizedMintEvent>,
    Vec<FinalizedLegEvent>,
    Vec<FinalizedCancelEvent>,
);

/// Decode the complete launch-protocol event allowlist and pair each
/// `MintIntentCreated` with exactly one adapter `Acquired` log in the same
/// transaction. Unpaired/ambiguous acquisitions, multi-slot intents, wrong
/// asset metadata, and any unexpected address/topic fail the whole block.
///
/// # Errors
/// Malformed ABI, duplicate identity, unexpected address/topic, an ambiguous
/// same-transaction pair, or a mint outside the single BTC-slot launch scope.
#[expect(
    clippy::too_many_lines,
    reason = "the single allowlist decoder keeps address/topic classification and same-transaction pairing fail-closed"
)]
pub fn decode_protocol_logs(
    adapter: Address,
    intent_queue: Address,
    redemption_leg_index: u32,
    mint_asset_id: B256,
    logs: &[FinalizedLog],
) -> Result<DecodedProtocolLogs, FinalizedObserverError> {
    let mut identities = std::collections::HashSet::new();
    let mut adapter_settlement_logs = Vec::new();
    let mut acquisitions = Vec::new();
    let mut intents = Vec::new();
    for log in logs {
        if !identities.insert((log.transaction_hash, log.log_index)) {
            return Err(FinalizedObserverError::Decode(
                "duplicate finalized log identity".to_string(),
            ));
        }
        let topic = log.topics.first().copied().ok_or_else(|| {
            FinalizedObserverError::Decode("finalized log has no topic0".to_string())
        })?;
        if log.address == adapter {
            if topic == ThorchainAdapter::Acquired::SIGNATURE_HASH {
                let event = ThorchainAdapter::Acquired::decode_raw_log(
                    log.topics.iter().copied(),
                    &log.data,
                    true,
                )
                .map_err(|error| {
                    FinalizedObserverError::Decode(format!(
                        "Acquired at log {}: {error}",
                        log.log_index
                    ))
                })?;
                acquisitions.push((event, log));
            } else if topic == ThorchainAdapter::RedeemDispatched::SIGNATURE_HASH
                || topic == ThorchainAdapter::AcquireCancelled::SIGNATURE_HASH
            {
                adapter_settlement_logs.push(log.clone());
            } else {
                return Err(FinalizedObserverError::Decode(format!(
                    "unexpected adapter event topic at log {}",
                    log.log_index
                )));
            }
        } else if log.address == intent_queue {
            if topic != IntentQueue::MintIntentCreated::SIGNATURE_HASH {
                return Err(FinalizedObserverError::Decode(format!(
                    "unexpected intent-queue event topic at log {}",
                    log.log_index
                )));
            }
            let event = IntentQueue::MintIntentCreated::decode_raw_log(
                log.topics.iter().copied(),
                &log.data,
                true,
            )
            .map_err(|error| {
                FinalizedObserverError::Decode(format!(
                    "MintIntentCreated at log {}: {error}",
                    log.log_index
                ))
            })?;
            intents.push((event, log));
        } else {
            return Err(FinalizedObserverError::Decode(format!(
                "unexpected protocol log address at log {}",
                log.log_index
            )));
        }
    }

    let (legs, cancels) =
        decode_adapter_logs(adapter, redemption_leg_index, &adapter_settlement_logs)?;
    let mut used_acquisitions = std::collections::HashSet::new();
    let mut mints = Vec::with_capacity(intents.len());
    for (intent, log) in intents {
        if intent.slotAssetIds.len() != 1
            || intent.slotExpectedAmounts.len() != 1
            || intent.slotAssetIds[0] != mint_asset_id
            || !intent.slotExpectedAmounts[0].is_zero()
        {
            return Err(FinalizedObserverError::Decode(
                "mint intent is outside the single zero-preview BTC launch slot".to_string(),
            ));
        }
        let candidates: Vec<_> = acquisitions
            .iter()
            .enumerate()
            .filter(|(_, (acquired, acquired_log))| {
                acquired_log.transaction_hash == log.transaction_hash
                    && acquired_log.transaction_index == log.transaction_index
                    && acquired_log.log_index < log.log_index
                    && acquired.fundingToken == intent.fundingToken
                    && acquired.amountIn == intent.amountIn
            })
            .collect();
        if candidates.len() != 1 {
            return Err(FinalizedObserverError::Decode(format!(
                "mint intent at log {} has {} matching Acquired events",
                log.log_index,
                candidates.len()
            )));
        }
        let (acquisition_index, (acquired, acquired_log)) = candidates[0];
        if !used_acquisitions.insert(acquisition_index) {
            return Err(FinalizedObserverError::Decode(
                "one Acquired event matched multiple mint intents".to_string(),
            ));
        }
        mints.push(FinalizedMintEvent {
            intent_id: intent.intentId,
            slot_index: 0,
            slot_asset_id: intent.slotAssetIds[0],
            slot_expected_amount: intent.slotExpectedAmounts[0],
            index_token: intent.indexToken,
            originator: intent.originator,
            funding_token: intent.fundingToken,
            amount_in: intent.amountIn,
            deadline: intent.deadline,
            acquire_memo: acquired.memo.as_bytes().to_vec(),
            acquire_vault: acquired.vault,
            transaction_hash: log.transaction_hash,
            transaction_index: log.transaction_index,
            intent_log_index: log.log_index,
            acquire_log_index: acquired_log.log_index,
        });
    }
    if used_acquisitions.len() != acquisitions.len() {
        return Err(FinalizedObserverError::Decode(
            "finalized block contains an unpaired Acquired event".to_string(),
        ));
    }
    mints.sort_by_key(|event| event.intent_log_index);
    Ok((mints, legs, cancels))
}

impl RedeemLegSource for SqliteFinalizedObserverStore {
    async fn leg_facts(
        &self,
        redemption_id: B256,
        leg_index: u32,
    ) -> Result<Option<ObservedLeg>, String> {
        let row: Option<StoredLegRow> = sqlx::query_as(
            "SELECT amount, memo, final_destination, observed_at
             FROM evm_observer_legs
             WHERE observer_id = ? AND redemption_id = ? AND leg_index = ?",
        )
        .bind(&self.observer_id)
        .bind(redemption_id.as_slice())
        .bind(i64::from(leg_index))
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| error.to_string())?;
        row.map(|(amount, memo, destination, observed)| {
            Ok(ObservedLeg {
                facts: LegFacts {
                    amount: U256::from_be_slice(&amount),
                    memo,
                    final_destination: Address::try_from(destination.as_slice())
                        .map_err(|error| error.to_string())?,
                },
                observed_at: u64::try_from(observed).map_err(|error| error.to_string())?,
            })
        })
        .transpose()
    }
}

fn validate_observer_id(observer_id: &str) -> Result<(), FinalizedObserverError> {
    if observer_id.is_empty()
        || observer_id.len() > 128
        || !observer_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(FinalizedObserverError::Transition(
            "observer id must be safe ASCII".to_string(),
        ));
    }
    Ok(())
}

fn validate_checkpoint_input(
    checkpoint: &FinalizedCheckpoint,
    observed_at: u64,
) -> Result<(), FinalizedObserverError> {
    if checkpoint.block_hash == B256::ZERO
        || checkpoint.parent_hash == B256::ZERO
        || checkpoint.header_evidence_hash == B256::ZERO
        || checkpoint.logs_evidence_hash == B256::ZERO
        || observed_at == 0
    {
        return Err(FinalizedObserverError::Transition(
            "zero checkpoint hash/time".to_string(),
        ));
    }
    Ok(())
}

fn validate_leg(event: &FinalizedLegEvent) -> Result<(), FinalizedObserverError> {
    if event.dispatch_id == B256::ZERO
        || event.redemption_id == B256::ZERO
        || event.target_token == Address::ZERO
        || event.facts.amount.is_zero()
        || event.facts.memo.is_empty()
        || event.facts.final_destination == Address::ZERO
        || event.transaction_hash == B256::ZERO
    {
        return Err(FinalizedObserverError::Transition(
            "redemption event contains a zero/empty field".to_string(),
        ));
    }
    Ok(())
}

fn validate_mint(event: &FinalizedMintEvent) -> Result<(), FinalizedObserverError> {
    if event.intent_id == B256::ZERO
        || event.slot_asset_id == B256::ZERO
        || !event.slot_expected_amount.is_zero()
        || event.index_token == Address::ZERO
        || event.originator == Address::ZERO
        || event.funding_token == Address::ZERO
        || event.amount_in.is_zero()
        || event.deadline == 0
        || event.acquire_memo.is_empty()
        || event.acquire_vault == Address::ZERO
        || event.transaction_hash == B256::ZERO
        || event.acquire_log_index >= event.intent_log_index
    {
        return Err(FinalizedObserverError::Transition(
            "mint event contains an invalid/zero field or ordering".to_string(),
        ));
    }
    Ok(())
}

fn decode_mint(row: StoredMintRow) -> Result<FinalizedMintRecord, FinalizedObserverError> {
    let (
        intent_id,
        slot_index,
        slot_asset_id,
        index_token,
        funding_token,
        amount_in,
        deadline,
        acquire_memo,
        acquire_vault,
        observed_at,
        source_block,
        source_block_hash,
        source_transaction_hash,
        source_transaction_index,
        intent_log_index,
        acquire_log_index,
    ) = row;
    Ok(FinalizedMintRecord {
        intent_id: decode_b256(&intent_id, "intent id")?,
        slot_index: u32::try_from(slot_index).map_err(|error| {
            FinalizedObserverError::Decode(format!("mint slot index out of range: {error}"))
        })?,
        slot_asset_id: decode_b256(&slot_asset_id, "mint asset id")?,
        index_token: decode_address(&index_token, "mint index token")?,
        funding_token: decode_address(&funding_token, "mint funding token")?,
        amount_in: U256::from_be_slice(&amount_in),
        deadline: from_i64(deadline, "mint deadline")?,
        acquire_memo,
        acquire_vault: decode_address(&acquire_vault, "mint acquire vault")?,
        observed_at: from_i64(observed_at, "mint observed at")?,
        source_block: from_i64(source_block, "mint source block")?,
        source_block_hash: decode_b256(&source_block_hash, "mint source block hash")?,
        source_transaction_hash: decode_b256(
            &source_transaction_hash,
            "mint source transaction hash",
        )?,
        source_transaction_index: from_i64(source_transaction_index, "mint transaction index")?,
        intent_log_index: from_i64(intent_log_index, "mint intent log index")?,
        acquire_log_index: from_i64(acquire_log_index, "mint acquire log index")?,
    })
}

fn decode_dispatch(
    row: StoredDispatchRow,
) -> Result<FinalizedDispatchRecord, FinalizedObserverError> {
    let (
        dispatch_id,
        redemption_id,
        leg_index,
        target_token,
        amount,
        memo,
        final_destination,
        observed_at,
        source_block,
        source_block_hash,
        source_transaction_hash,
        source_transaction_index,
        source_log_index,
    ) = row;
    Ok(FinalizedDispatchRecord {
        dispatch_id: decode_b256(&dispatch_id, "dispatch id")?,
        redemption_id: decode_b256(&redemption_id, "redemption id")?,
        leg_index: u32::try_from(leg_index).map_err(|error| {
            FinalizedObserverError::Decode(format!("leg index out of range: {error}"))
        })?,
        target_token: decode_address(&target_token, "target token")?,
        facts: LegFacts {
            amount: U256::from_be_slice(&amount),
            memo,
            final_destination: decode_address(&final_destination, "final destination")?,
        },
        observed_at: from_i64(observed_at, "dispatch observed at")?,
        source_block: from_i64(source_block, "dispatch source block")?,
        source_block_hash: decode_b256(&source_block_hash, "dispatch source block hash")?,
        source_transaction_hash: decode_b256(
            &source_transaction_hash,
            "dispatch source transaction hash",
        )?,
        source_transaction_index: from_i64(source_transaction_index, "transaction index")?,
        source_log_index: from_i64(source_log_index, "log index")?,
    })
}

fn decode_checkpoint(
    (number, hash, parent, header_evidence, logs_evidence): StoredCheckpointRow,
) -> Result<FinalizedCheckpoint, FinalizedObserverError> {
    Ok(FinalizedCheckpoint {
        block_number: from_i64(number, "checkpoint block")?,
        block_hash: decode_b256(&hash, "checkpoint hash")?,
        parent_hash: decode_b256(&parent, "checkpoint parent")?,
        header_evidence_hash: decode_b256(&header_evidence, "header evidence hash")?,
        logs_evidence_hash: decode_b256(&logs_evidence, "logs evidence hash")?,
    })
}

fn decode_b256(bytes: &[u8], label: &str) -> Result<B256, FinalizedObserverError> {
    B256::try_from(bytes).map_err(|error| {
        FinalizedObserverError::Decode(format!("{label} is not 32 bytes: {error}"))
    })
}

fn decode_address(bytes: &[u8], label: &str) -> Result<Address, FinalizedObserverError> {
    Address::try_from(bytes).map_err(|error| {
        FinalizedObserverError::Decode(format!("{label} is not 20 bytes: {error}"))
    })
}

fn to_i64(value: u64, label: &str) -> Result<i64, FinalizedObserverError> {
    i64::try_from(value)
        .map_err(|error| FinalizedObserverError::Decode(format!("{label}: {error}")))
}

fn from_i64(value: i64, label: &str) -> Result<u64, FinalizedObserverError> {
    u64::try_from(value)
        .map_err(|error| FinalizedObserverError::Decode(format!("{label}: {error}")))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use super::*;

    fn redeem_log(adapter: Address, log_index: u64) -> FinalizedLog {
        let event = ThorchainAdapter::RedeemDispatched {
            dispatchId: B256::repeat_byte(21),
            redemptionId: B256::repeat_byte(22),
            targetToken: Address::repeat_byte(23),
            amount: U256::from(100u64),
            destination: Address::repeat_byte(24),
            memo: "=:ETH.USDT:0x1111111111111111111111111111111111111111:1/1/1".to_string(),
        };
        let encoded = event.encode_log_data();
        FinalizedLog {
            address: adapter,
            topics: encoded.topics().to_vec(),
            data: encoded.data,
            block_number: 10,
            block_hash: B256::repeat_byte(10),
            transaction_hash: B256::repeat_byte(11),
            transaction_index: 2,
            log_index,
        }
    }

    fn leg(id: u8, log_index: u64) -> FinalizedLegEvent {
        FinalizedLegEvent {
            dispatch_id: B256::repeat_byte(id.saturating_add(20)),
            redemption_id: B256::repeat_byte(id),
            leg_index: 0,
            target_token: Address::repeat_byte(3),
            facts: LegFacts {
                amount: U256::from(100u64),
                memo: b"=:ETH.USDT:0x111:1/1/1".to_vec(),
                final_destination: Address::repeat_byte(2),
            },
            transaction_hash: B256::repeat_byte(id.saturating_add(40)),
            transaction_index: 0,
            log_index,
        }
    }

    fn mint(id: u8, intent_log_index: u64) -> FinalizedMintEvent {
        FinalizedMintEvent {
            intent_id: B256::repeat_byte(id),
            slot_index: 0,
            slot_asset_id: B256::repeat_byte(0xa1),
            slot_expected_amount: U256::ZERO,
            index_token: Address::repeat_byte(2),
            originator: Address::repeat_byte(3),
            funding_token: Address::repeat_byte(4),
            amount_in: U256::from(1_000_000u64),
            deadline: 2_000,
            acquire_memo: b"=:BTC.BTC:bc1qcustody:1/1/1".to_vec(),
            acquire_vault: Address::repeat_byte(5),
            transaction_hash: B256::repeat_byte(id.saturating_add(40)),
            transaction_index: 0,
            intent_log_index,
            acquire_log_index: intent_log_index.saturating_sub(1),
        }
    }

    #[tokio::test]
    async fn restart_and_reorg_rollback_preserve_only_canonical_facts() {
        let store = SqliteFinalizedObserverStore::connect("sqlite::memory:", "adapter-btc")
            .await
            .expect("store");
        let block_10 = FinalizedCheckpoint {
            block_number: 10,
            block_hash: B256::repeat_byte(10),
            parent_hash: B256::repeat_byte(9),
            header_evidence_hash: B256::repeat_byte(110),
            logs_evidence_hash: B256::repeat_byte(210),
        };
        store
            .commit_block(block_10, 1_000, &[mint(1, 2)], &[leg(1, 0)], &[])
            .await
            .expect("block 10");
        store
            .commit_block(
                FinalizedCheckpoint {
                    block_number: 11,
                    block_hash: B256::repeat_byte(11),
                    parent_hash: block_10.block_hash,
                    header_evidence_hash: B256::repeat_byte(111),
                    logs_evidence_hash: B256::repeat_byte(211),
                },
                1_010,
                &[mint(2, 2)],
                &[leg(2, 0)],
                &[],
            )
            .await
            .expect("block 11");
        assert!(store
            .leg_facts(B256::repeat_byte(2), 0)
            .await
            .expect("lookup")
            .is_some());
        assert_eq!(
            store
                .mint(B256::repeat_byte(2), 0)
                .await
                .expect("mint lookup")
                .expect("mint present")
                .source_transaction_hash,
            B256::repeat_byte(42)
        );
        assert_eq!(
            store
                .dispatch(B256::repeat_byte(2), 0)
                .await
                .expect("dispatch")
                .expect("present")
                .dispatch_id,
            B256::repeat_byte(22)
        );
        store
            .rollback_to(10, block_10.block_hash)
            .await
            .expect("rollback");
        assert!(store
            .leg_facts(B256::repeat_byte(2), 0)
            .await
            .expect("lookup")
            .is_none());
        assert!(store
            .mint(B256::repeat_byte(2), 0)
            .await
            .expect("mint lookup")
            .is_none());
        assert_eq!(
            store.last_checkpoint().await.expect("checkpoint"),
            Some(block_10)
        );
    }

    #[test]
    fn adapter_log_decoder_rejects_wrong_address_topic_and_duplicate_identity() {
        let adapter = Address::repeat_byte(7);
        let valid = redeem_log(adapter, 3);
        let (legs, cancels) =
            decode_adapter_logs(adapter, 0, std::slice::from_ref(&valid)).expect("valid event");
        assert!(cancels.is_empty());
        assert_eq!(legs.len(), 1);
        assert_eq!(legs[0].dispatch_id, B256::repeat_byte(21));
        assert_eq!(legs[0].transaction_index, 2);

        let mut wrong_address = valid.clone();
        wrong_address.address = Address::repeat_byte(8);
        assert!(decode_adapter_logs(adapter, 0, &[wrong_address]).is_err());

        let mut wrong_topic = valid.clone();
        wrong_topic.topics[0] = B256::repeat_byte(9);
        assert!(decode_adapter_logs(adapter, 0, &[wrong_topic]).is_err());

        assert!(decode_adapter_logs(adapter, 0, &[valid.clone(), valid]).is_err());
    }

    #[test]
    fn protocol_decoder_pairs_exact_same_transaction_mint_and_acquire() {
        let adapter = Address::repeat_byte(7);
        let queue = Address::repeat_byte(8);
        let asset = B256::repeat_byte(0xa1);
        let tx_hash = B256::repeat_byte(0x44);
        let acquired = ThorchainAdapter::Acquired {
            fundingToken: Address::repeat_byte(4),
            amountIn: U256::from(1_000_000u64),
            memo: "=:BTC.BTC:bc1qcustody:1/1/1".to_string(),
            vault: Address::repeat_byte(5),
        };
        let acquired_data = acquired.encode_log_data();
        let acquired_log = FinalizedLog {
            address: adapter,
            topics: acquired_data.topics().to_vec(),
            data: acquired_data.data,
            block_number: 10,
            block_hash: B256::repeat_byte(10),
            transaction_hash: tx_hash,
            transaction_index: 1,
            log_index: 2,
        };
        let intent = IntentQueue::MintIntentCreated {
            intentId: B256::repeat_byte(1),
            indexToken: Address::repeat_byte(2),
            originator: Address::repeat_byte(3),
            fundingToken: Address::repeat_byte(4),
            amountIn: U256::from(1_000_000u64),
            deadline: 2_000,
            slotAssetIds: vec![asset],
            slotExpectedAmounts: vec![U256::ZERO],
        };
        let intent_data = intent.encode_log_data();
        let intent_log = FinalizedLog {
            address: queue,
            topics: intent_data.topics().to_vec(),
            data: intent_data.data,
            block_number: 10,
            block_hash: B256::repeat_byte(10),
            transaction_hash: tx_hash,
            transaction_index: 1,
            log_index: 5,
        };
        let (mints, legs, cancels) = decode_protocol_logs(
            adapter,
            queue,
            0,
            asset,
            &[acquired_log.clone(), intent_log.clone()],
        )
        .expect("pair");
        assert!(legs.is_empty());
        assert!(cancels.is_empty());
        assert_eq!(mints.len(), 1);
        assert_eq!(mints[0].transaction_hash, tx_hash);
        assert_eq!(mints[0].acquire_log_index, 2);
        assert_eq!(mints[0].intent_log_index, 5);

        assert!(decode_protocol_logs(
            adapter,
            queue,
            0,
            B256::repeat_byte(0xff),
            &[acquired_log.clone(), intent_log.clone()],
        )
        .is_err());
        let mut wrong_order = acquired_log.clone();
        wrong_order.log_index = 6;
        assert!(
            decode_protocol_logs(adapter, queue, 0, asset, &[wrong_order, intent_log]).is_err()
        );
        assert!(decode_protocol_logs(adapter, queue, 0, asset, &[acquired_log]).is_err());
    }
}
