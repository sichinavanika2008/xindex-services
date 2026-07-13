//! Durable one-shot claims for physical native-chain arrivals.
//!
//! A public custody address can receive unrelated or same-valued outputs. A
//! signer must therefore bind the exact observed transaction/output to one
//! mint delivery or redemption refund before releasing its HSM signature.

use std::collections::HashMap;

use alloy_primitives::B256;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::chain_registry::ChainId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NativeFlowKind {
    MintDelivery,
    RedemptionRefund,
}

impl NativeFlowKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::MintDelivery => "mint_delivery",
            Self::RedemptionRefund => "redemption_refund",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeInflowClaim {
    pub kind: NativeFlowKind,
    pub lifecycle_id: B256,
    pub leg_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeInflowOutcome {
    Consumed,
    AlreadyByThisLifecycle,
    Conflict { existing: NativeInflowClaim },
}

#[derive(Debug, Error)]
pub enum NativeInflowError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] sqlx::Error),
    #[error("migration: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("corrupt native-inflow state: {0}")]
    Decode(String),
}

pub trait NativeInflowStore: Send + Sync {
    fn consume(
        &self,
        chain: ChainId,
        tx_hash: B256,
        output_index: u32,
        claim: NativeInflowClaim,
        consumed_at: u64,
    ) -> impl std::future::Future<Output = Result<NativeInflowOutcome, NativeInflowError>> + Send;
}

#[derive(Debug, Default)]
pub struct InMemoryNativeInflow {
    inner: Mutex<HashMap<(ChainId, B256, u32), NativeInflowClaim>>,
}

impl InMemoryNativeInflow {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl NativeInflowStore for InMemoryNativeInflow {
    async fn consume(
        &self,
        chain: ChainId,
        tx_hash: B256,
        output_index: u32,
        claim: NativeInflowClaim,
        consumed_at: u64,
    ) -> Result<NativeInflowOutcome, NativeInflowError> {
        validate_claim(tx_hash, claim, consumed_at)?;
        let mut state = self.inner.lock().await;
        match state.get(&(chain, tx_hash, output_index)).copied() {
            None => {
                if let Some(existing) = state.values().copied().find(|existing| *existing == claim)
                {
                    return Ok(NativeInflowOutcome::Conflict { existing });
                }
                state.insert((chain, tx_hash, output_index), claim);
                Ok(NativeInflowOutcome::Consumed)
            }
            Some(existing) if existing == claim => Ok(NativeInflowOutcome::AlreadyByThisLifecycle),
            Some(existing) => Ok(NativeInflowOutcome::Conflict { existing }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SqliteNativeInflow {
    pool: SqlitePool,
}

impl SqliteNativeInflow {
    /// Open the durable ledger and apply its embedded migrations.
    ///
    /// # Errors
    /// Returns [`NativeInflowError`] if `SQLite` cannot be opened or a
    /// migration cannot be applied.
    pub async fn connect(database_url: &str) -> Result<Self, NativeInflowError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }
}

impl NativeInflowStore for SqliteNativeInflow {
    async fn consume(
        &self,
        chain: ChainId,
        tx_hash: B256,
        output_index: u32,
        claim: NativeInflowClaim,
        consumed_at: u64,
    ) -> Result<NativeInflowOutcome, NativeInflowError> {
        validate_claim(tx_hash, claim, consumed_at)?;
        let result = sqlx::query(
            "INSERT OR IGNORE INTO consumed_native_inflow
                (chain_id, tx_hash, output_index, flow_kind, lifecycle_id,
                 leg_index, consumed_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(chain.to_string())
        .bind(tx_hash.as_slice())
        .bind(i64::from(output_index))
        .bind(claim.kind.as_str())
        .bind(claim.lifecycle_id.as_slice())
        .bind(i64::from(claim.leg_index))
        .bind(to_i64(consumed_at, "consumed_at")?)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 1 {
            return Ok(NativeInflowOutcome::Consumed);
        }
        let row: Option<(String, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT flow_kind, lifecycle_id, leg_index
             FROM consumed_native_inflow
             WHERE chain_id = ? AND tx_hash = ? AND output_index = ?",
        )
        .bind(chain.to_string())
        .bind(tx_hash.as_slice())
        .bind(i64::from(output_index))
        .fetch_optional(&self.pool)
        .await?;
        let physical_match = row.is_some();
        let (kind, lifecycle, leg) = match row {
            Some(row) => row,
            None => sqlx::query_as(
                "SELECT flow_kind, lifecycle_id, leg_index
                 FROM consumed_native_inflow
                 WHERE flow_kind = ? AND lifecycle_id = ? AND leg_index = ?",
            )
            .bind(claim.kind.as_str())
            .bind(claim.lifecycle_id.as_slice())
            .bind(i64::from(claim.leg_index))
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| {
                NativeInflowError::Decode(
                    "ignored native claim has no physical or logical conflict row".to_string(),
                )
            })?,
        };
        let existing = NativeInflowClaim {
            kind: parse_kind(&kind)?,
            lifecycle_id: B256::try_from(lifecycle.as_slice()).map_err(|error| {
                NativeInflowError::Decode(format!("lifecycle id is not bytes32: {error}"))
            })?,
            leg_index: u32::try_from(leg).map_err(|error| {
                NativeInflowError::Decode(format!("leg index out of range: {error}"))
            })?,
        };
        if physical_match && existing == claim {
            Ok(NativeInflowOutcome::AlreadyByThisLifecycle)
        } else {
            Ok(NativeInflowOutcome::Conflict { existing })
        }
    }
}

#[derive(Debug)]
pub enum AnyNativeInflow {
    Memory(InMemoryNativeInflow),
    Sqlite(SqliteNativeInflow),
}

impl AnyNativeInflow {
    #[must_use]
    pub fn memory() -> Self {
        Self::Memory(InMemoryNativeInflow::new())
    }

    /// Open the production SQLite-backed ledger.
    ///
    /// # Errors
    /// Returns [`NativeInflowError`] if `SQLite` cannot be opened or a
    /// migration cannot be applied.
    pub async fn connect(database_url: &str) -> Result<Self, NativeInflowError> {
        Ok(Self::Sqlite(
            SqliteNativeInflow::connect(database_url).await?,
        ))
    }
}

impl NativeInflowStore for AnyNativeInflow {
    async fn consume(
        &self,
        chain: ChainId,
        tx_hash: B256,
        output_index: u32,
        claim: NativeInflowClaim,
        consumed_at: u64,
    ) -> Result<NativeInflowOutcome, NativeInflowError> {
        match self {
            Self::Memory(store) => {
                store
                    .consume(chain, tx_hash, output_index, claim, consumed_at)
                    .await
            }
            Self::Sqlite(store) => {
                store
                    .consume(chain, tx_hash, output_index, claim, consumed_at)
                    .await
            }
        }
    }
}

fn validate_claim(
    tx_hash: B256,
    claim: NativeInflowClaim,
    consumed_at: u64,
) -> Result<(), NativeInflowError> {
    if tx_hash == B256::ZERO || claim.lifecycle_id == B256::ZERO || consumed_at == 0 {
        return Err(NativeInflowError::Decode(
            "native inflow claim contains zero identity/time".to_string(),
        ));
    }
    Ok(())
}

fn parse_kind(raw: &str) -> Result<NativeFlowKind, NativeInflowError> {
    match raw {
        "mint_delivery" => Ok(NativeFlowKind::MintDelivery),
        "redemption_refund" => Ok(NativeFlowKind::RedemptionRefund),
        _ => Err(NativeInflowError::Decode(
            "unknown native inflow flow kind".to_string(),
        )),
    }
}

fn to_i64(value: u64, label: &str) -> Result<i64, NativeInflowError> {
    i64::try_from(value).map_err(|error| NativeInflowError::Decode(format!("{label}: {error}")))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use super::*;

    async fn exercise(store: &impl NativeInflowStore) {
        let physical = B256::repeat_byte(1);
        let first = NativeInflowClaim {
            kind: NativeFlowKind::MintDelivery,
            lifecycle_id: B256::repeat_byte(2),
            leg_index: 0,
        };
        let other = NativeInflowClaim {
            kind: NativeFlowKind::RedemptionRefund,
            lifecycle_id: B256::repeat_byte(3),
            leg_index: 0,
        };
        assert_eq!(
            store
                .consume(ChainId::Btc, physical, 4, first, 100)
                .await
                .expect("first"),
            NativeInflowOutcome::Consumed
        );
        assert_eq!(
            store
                .consume(ChainId::Btc, physical, 4, first, 101)
                .await
                .expect("retry"),
            NativeInflowOutcome::AlreadyByThisLifecycle
        );
        assert_eq!(
            store
                .consume(ChainId::Btc, B256::repeat_byte(9), 5, first, 101,)
                .await
                .expect("logical conflict"),
            NativeInflowOutcome::Conflict { existing: first }
        );
        assert_eq!(
            store
                .consume(ChainId::Btc, physical, 4, other, 102)
                .await
                .expect("conflict"),
            NativeInflowOutcome::Conflict { existing: first }
        );
    }

    #[tokio::test]
    async fn memory_is_one_shot() {
        exercise(&InMemoryNativeInflow::new()).await;
    }

    #[tokio::test]
    async fn sqlite_is_one_shot() {
        exercise(
            &SqliteNativeInflow::connect("sqlite::memory:")
                .await
                .expect("sqlite"),
        )
        .await;
    }
}
