//! Bind-prepare side-channel (Cobo `request_id` ↔ our unsigned spend + cert).
//!
//! Because the Cobo TSS-Node callback request carries only the signing
//! request (the provider's policy engine cannot see destination/amount/memo),
//! the executor stores the unsigned spend + its k-of-n certificate here BEFORE
//! submitting the transfer to Cobo, keyed by a correlation id it echoes
//! through as the Cobo `request_id`. The callback retrieves the prepared
//! context by that id and binds the spend; a missing context is a fail-closed
//! REJECT.
//!
//! [`PreparedSpend`] is the per-family payload: the BTC PSBT, an EVM
//! `depositWithExpiry` call, or an account-model send. Two stores implement
//! [`PrepareStore`]: [`InMemoryPrepareStore`] (dev/test, process-local) and
//! [`SqlitePrepareStore`] (production — the executor and callback are SEPARATE
//! processes, so the context must live in a shared backend). Both are fallible:
//! a store error surfaces to the executor (abort the submit) and fail-closes
//! the callback to REJECT.

use std::collections::HashMap;
use std::future::Future;
use std::str::FromStr;

use alloy_primitives::{Address, U256};
use bitcoin::psbt::Psbt;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use tokio::sync::Mutex;
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{AcquireCancelProof, IntentProof};

/// A prepare-store failure.
#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    /// Backing-store (sqlite) error.
    #[error("prepare store db error: {0}")]
    Db(String),
    /// (De)serialization of the stored spend failed.
    #[error("prepare decode error: {0}")]
    Decode(String),
}

/// The unsigned BTC spend + its authorizing certificate. Consumed by
/// [`crate::btc::decide_redeem_spend`].
#[derive(Debug, Clone)]
pub struct BindContext {
    /// Custody chain of the spend.
    pub chain: ChainId,
    /// The unsigned PSBT the executor will submit to Cobo.
    pub psbt: Psbt,
    /// The k-of-n RIC authorizing a redeem spend (XOR [`Self::acc`]).
    pub ric: Option<IntentProof>,
    /// The k-of-n ACC authorizing a mint-cancel swap-back (XOR [`Self::ric`]).
    pub acc: Option<AcquireCancelProof>,
}

/// The unsigned EVM `Router.depositWithExpiry` call + its RIC. Owned mirror of
/// [`crate::evm::EvmDeposit`].
#[derive(Debug, Clone)]
pub struct EvmPrepared {
    /// EVM chain this spend settles on.
    pub chain: ChainId,
    /// Transaction recipient (must be the registry-pinned Router).
    pub to: Address,
    /// Transaction `value` (native deposit carries `msg.value`).
    pub value: U256,
    /// ABI-encoded `depositWithExpiry` calldata.
    pub data: Vec<u8>,
    /// The k-of-n RIC authorizing the redeem leg.
    pub ric: Option<IntentProof>,
    /// One-shot spend identity bound into the signed tx (the EVM account nonce).
    pub spend_identity: Vec<u8>,
}

/// The unsigned account-model send (Cosmos / XRP / TRON) + its RIC. Owned
/// mirror of [`crate::account::AccountSend`].
#[derive(Debug, Clone)]
pub struct AccountPrepared {
    /// Account-model chain this send settles on.
    pub chain: ChainId,
    /// Destination address as serialized into the signed tx.
    pub to_address: String,
    /// Decimal send amount in native smallest units.
    pub amount_dec: String,
    /// Exact `THORChain` memo carried as a transaction field.
    pub memo: String,
    /// The k-of-n RIC authorizing the redeem leg.
    pub ric: Option<IntentProof>,
    /// One-shot spend identity (sequence for Cosmos/XRP, txid for TRON).
    pub spend_identity: Vec<u8>,
}

/// The unsigned spend + certificate stored at prepare time, dispatched on by
/// the callback once Cobo asks to sign under the correlated `request_id`.
#[derive(Debug, Clone)]
pub enum PreparedSpend {
    /// A BTC redeem / swap-back PSBT. Boxed — a PSBT is far larger than the
    /// other variants (`clippy::large_enum_variant`).
    Btc(Box<BindContext>),
    /// An EVM `depositWithExpiry` redeem leg.
    Evm(EvmPrepared),
    /// An account-model (Cosmos / XRP / TRON) redeem send.
    Account(AccountPrepared),
}

/// Prepare-store API. The executor `put`s the unsigned spend + cert keyed by
/// the Cobo `request_id` before submitting to Cobo; the callback `get`s it to
/// bind the spend. AFIT + `Send`, static dispatch — same shape as
/// [`xindex_custody_core::replay::ReplayStore`].
pub trait PrepareStore: Send + Sync {
    /// Store `spend` under `request_id` (overwrites a prior prepare).
    ///
    /// # Errors
    /// [`PrepareError`] on a store or serialization failure — the executor
    /// MUST NOT submit to Cobo if this fails (the callback would then have no
    /// context and fail-close).
    fn put(
        &self,
        request_id: String,
        spend: PreparedSpend,
    ) -> impl Future<Output = Result<(), PrepareError>> + Send;

    /// Retrieve the prepared spend, or `None` if absent. The callback
    /// fail-closes to REJECT on `Ok(None)` AND on `Err(_)`.
    ///
    /// # Errors
    /// [`PrepareError`] on a store or deserialization failure.
    fn get(
        &self,
        request_id: &str,
    ) -> impl Future<Output = Result<Option<PreparedSpend>, PrepareError>> + Send;
}

/// In-memory prepare store (dev/test, process-local). Production = the
/// [`SqlitePrepareStore`].
#[derive(Debug, Default)]
pub struct InMemoryPrepareStore {
    inner: Mutex<HashMap<String, PreparedSpend>>,
}

impl InMemoryPrepareStore {
    /// A fresh, empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl PrepareStore for InMemoryPrepareStore {
    async fn put(&self, request_id: String, spend: PreparedSpend) -> Result<(), PrepareError> {
        self.inner.lock().await.insert(request_id, spend);
        Ok(())
    }

    async fn get(&self, request_id: &str) -> Result<Option<PreparedSpend>, PrepareError> {
        Ok(self.inner.lock().await.get(request_id).cloned())
    }
}

/// Sqlite-backed prepare store (production). A single shared DB file lets the
/// executor process `put` and the callback process `get` the same context.
/// Mirrors [`xindex_custody_core::replay`]'s sqlite setup.
#[derive(Debug)]
pub struct SqlitePrepareStore {
    pool: SqlitePool,
}

impl SqlitePrepareStore {
    /// Connect to `database_url` and apply migrations.
    ///
    /// # Errors
    /// [`PrepareError::Db`] on pool/connect or migration failure.
    pub async fn connect(database_url: &str) -> Result<Self, PrepareError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .map_err(|e| PrepareError::Db(e.to_string()))?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| PrepareError::Db(e.to_string()))?;
        Ok(Self { pool })
    }
}

impl PrepareStore for SqlitePrepareStore {
    async fn put(&self, request_id: String, spend: PreparedSpend) -> Result<(), PrepareError> {
        let json = serde_json::to_string(&StoredSpend::from_spend(&spend))
            .map_err(|e| PrepareError::Decode(e.to_string()))?;
        sqlx::query(
            "INSERT OR REPLACE INTO prepared_spends (request_id, spend_json, created_at_unix) \
             VALUES (?, ?, strftime('%s','now'))",
        )
        .bind(&request_id)
        .bind(&json)
        .execute(&self.pool)
        .await
        .map_err(|e| PrepareError::Db(e.to_string()))?;
        Ok(())
    }

    async fn get(&self, request_id: &str) -> Result<Option<PreparedSpend>, PrepareError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT spend_json FROM prepared_spends WHERE request_id = ?")
                .bind(request_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| PrepareError::Db(e.to_string()))?;
        match row {
            None => Ok(None),
            Some((json,)) => {
                let stored: StoredSpend =
                    serde_json::from_str(&json).map_err(|e| PrepareError::Decode(e.to_string()))?;
                Ok(Some(stored.into_spend()?))
            }
        }
    }
}

/// Serde-stable blob form of a [`PreparedSpend`]. `Psbt` / `Address` / `U256`
/// have no serde derive in this workspace, so they are carried as hex/decimal
/// strings; `ChainId` / `IntentProof` / `AcquireCancelProof` serialize natively.
#[derive(Serialize, Deserialize)]
struct StoredSpend {
    kind: String,
    chain: ChainId,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    psbt_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    ric: Option<IntentProof>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    acc: Option<AcquireCancelProof>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    to_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    value_dec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    data_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    to_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    amount_dec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    memo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    spend_identity_hex: Option<String>,
}

fn require<T>(field: Option<T>, name: &str) -> Result<T, PrepareError> {
    field.ok_or_else(|| PrepareError::Decode(format!("stored spend missing field {name}")))
}

impl StoredSpend {
    fn from_spend(spend: &PreparedSpend) -> Self {
        let base = |chain: ChainId, kind: &str| Self {
            kind: kind.to_string(),
            chain,
            psbt_hex: None,
            ric: None,
            acc: None,
            to_hex: None,
            value_dec: None,
            data_hex: None,
            to_address: None,
            amount_dec: None,
            memo: None,
            spend_identity_hex: None,
        };
        match spend {
            PreparedSpend::Btc(ctx) => Self {
                psbt_hex: Some(alloy_primitives::hex::encode(ctx.psbt.serialize())),
                ric: ctx.ric.clone(),
                acc: ctx.acc.clone(),
                ..base(ctx.chain, "btc")
            },
            PreparedSpend::Evm(e) => Self {
                to_hex: Some(format!("{:#x}", e.to)),
                value_dec: Some(e.value.to_string()),
                data_hex: Some(alloy_primitives::hex::encode(&e.data)),
                ric: e.ric.clone(),
                spend_identity_hex: Some(alloy_primitives::hex::encode(&e.spend_identity)),
                ..base(e.chain, "evm")
            },
            PreparedSpend::Account(a) => Self {
                to_address: Some(a.to_address.clone()),
                amount_dec: Some(a.amount_dec.clone()),
                memo: Some(a.memo.clone()),
                ric: a.ric.clone(),
                spend_identity_hex: Some(alloy_primitives::hex::encode(&a.spend_identity)),
                ..base(a.chain, "account")
            },
        }
    }

    fn into_spend(self) -> Result<PreparedSpend, PrepareError> {
        let hexd = |o: Option<String>, name: &str| -> Result<Vec<u8>, PrepareError> {
            let s = require(o, name)?;
            alloy_primitives::hex::decode(&s)
                .map_err(|e| PrepareError::Decode(format!("bad hex {name}: {e}")))
        };
        match self.kind.as_str() {
            "btc" => {
                let psbt = Psbt::deserialize(&hexd(self.psbt_hex, "psbt_hex")?)
                    .map_err(|e| PrepareError::Decode(format!("bad psbt: {e}")))?;
                Ok(PreparedSpend::Btc(Box::new(BindContext {
                    chain: self.chain,
                    psbt,
                    ric: self.ric,
                    acc: self.acc,
                })))
            }
            "evm" => {
                let to = Address::from_str(&require(self.to_hex, "to_hex")?)
                    .map_err(|e| PrepareError::Decode(format!("bad to: {e}")))?;
                let value = U256::from_str_radix(&require(self.value_dec, "value_dec")?, 10)
                    .map_err(|e| PrepareError::Decode(format!("bad value: {e}")))?;
                Ok(PreparedSpend::Evm(EvmPrepared {
                    chain: self.chain,
                    to,
                    value,
                    data: hexd(self.data_hex, "data_hex")?,
                    ric: self.ric,
                    spend_identity: hexd(self.spend_identity_hex, "spend_identity_hex")?,
                }))
            }
            "account" => Ok(PreparedSpend::Account(AccountPrepared {
                chain: self.chain,
                to_address: require(self.to_address, "to_address")?,
                amount_dec: require(self.amount_dec, "amount_dec")?,
                memo: require(self.memo, "memo")?,
                ric: self.ric,
                spend_identity: hexd(self.spend_identity_hex, "spend_identity_hex")?,
            })),
            other => Err(PrepareError::Decode(format!(
                "unknown stored spend kind {other}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute::LockTime, transaction::Version, Transaction};

    fn empty_psbt() -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        #[expect(clippy::expect_used, reason = "test code")]
        Psbt::from_unsigned_tx(tx).expect("unsigned psbt")
    }

    fn btc_spend() -> PreparedSpend {
        PreparedSpend::Btc(Box::new(BindContext {
            chain: ChainId::Btc,
            psbt: empty_psbt(),
            ric: None,
            acc: None,
        }))
    }

    fn evm_spend() -> PreparedSpend {
        PreparedSpend::Evm(EvmPrepared {
            chain: ChainId::Eth,
            to: Address::repeat_byte(0xaa),
            value: U256::from(123_456_u64),
            data: vec![1, 2, 3, 4],
            ric: None,
            spend_identity: vec![9, 9],
        })
    }

    fn account_spend() -> PreparedSpend {
        PreparedSpend::Account(AccountPrepared {
            chain: ChainId::Gaia,
            to_address: "cosmos1exampledestination".to_string(),
            amount_dec: "1000000".to_string(),
            memo: "=:ETH.USDT:0xrecipient:990000".to_string(),
            ric: None,
            spend_identity: vec![7],
        })
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn in_memory_put_then_get_roundtrips() {
        let store = InMemoryPrepareStore::new();
        store
            .put("req-1".to_string(), btc_spend())
            .await
            .expect("put");
        let got = store.get("req-1").await.expect("get");
        assert!(matches!(got, Some(PreparedSpend::Btc(_))));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn in_memory_missing_is_none() {
        let store = InMemoryPrepareStore::new();
        assert!(store.get("absent").await.expect("get").is_none());
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_roundtrips_all_families() {
        let store = SqlitePrepareStore::connect("sqlite::memory:")
            .await
            .expect("connect");

        store
            .put("b".to_string(), btc_spend())
            .await
            .expect("put btc");
        assert!(matches!(
            store.get("b").await.expect("get btc"),
            Some(PreparedSpend::Btc(_))
        ));

        store
            .put("e".to_string(), evm_spend())
            .await
            .expect("put evm");
        let got_evm = store.get("e").await.expect("get evm");
        assert!(
            matches!(&got_evm, Some(PreparedSpend::Evm(_))),
            "expected Evm, got {got_evm:?}"
        );
        if let Some(PreparedSpend::Evm(e)) = got_evm {
            assert_eq!(e.to, Address::repeat_byte(0xaa));
            assert_eq!(e.value, U256::from(123_456_u64));
            assert_eq!(e.data, vec![1, 2, 3, 4]);
            assert_eq!(e.spend_identity, vec![9, 9]);
        }

        store
            .put("a".to_string(), account_spend())
            .await
            .expect("put account");
        let got_acct = store.get("a").await.expect("get account");
        assert!(
            matches!(&got_acct, Some(PreparedSpend::Account(_))),
            "expected Account, got {got_acct:?}"
        );
        if let Some(PreparedSpend::Account(a)) = got_acct {
            assert_eq!(a.to_address, "cosmos1exampledestination");
            assert_eq!(a.amount_dec, "1000000");
            assert_eq!(a.spend_identity, vec![7]);
        }
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sqlite_missing_is_none() {
        let store = SqlitePrepareStore::connect("sqlite::memory:")
            .await
            .expect("connect");
        assert!(store.get("absent").await.expect("get").is_none());
    }
}
