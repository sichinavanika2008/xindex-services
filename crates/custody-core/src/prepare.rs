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
use xindex_shared::signer_wire::{AcquireCancelProof, IntentProof, TronAssetKind};

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

/// The unsigned BTC spend + its authorizing certificate. Consumed by the BTC
/// decision core (`decide_redeem_spend`) in `xindex-custody-node`.
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

/// The operational (non-cert-bound) inputs the EVM signing hash depends on.
/// The approver reconstructs the unsigned tx from these + the RIC-bound
/// `to`/`value`/`data` and asserts the recomputed hash equals the signing
/// request (TK-01); `gas_limit`/`max_fee_per_gas` bound the fee (TK-02). The
/// envelope type + EIP-155 chain id are DERIVED from `EvmPrepared::chain`, never
/// stored (the approver uses the canonical value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmSigning {
    /// Account nonce.
    pub nonce: u64,
    /// Gas units the tx may consume.
    pub gas_limit: u64,
    /// EIP-1559 max-fee-per-gas (wei); unused for a legacy chain.
    pub max_fee_per_gas: u128,
    /// EIP-1559 priority fee (wei); unused for a legacy chain.
    pub max_priority_fee_per_gas: u128,
    /// Legacy gas price (wei); unused for an EIP-1559 chain.
    pub gas_price: u128,
}

/// The unsigned EVM `Router.depositWithExpiry` call + its RIC. Owned mirror of
/// the EVM decision core's `EvmDeposit` (in `xindex-custody-node`).
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
    /// The operational signing-hash inputs (TK-01/TK-02).
    pub signing: EvmSigning,
    /// The k-of-n RIC authorizing the redeem leg.
    pub ric: Option<IntentProof>,
    /// One-shot spend identity bound into the signed tx (the EVM account nonce).
    pub spend_identity: Vec<u8>,
}

/// Per-family signing-hash inputs an approver needs to independently
/// reconstruct an account-model tx and recompute its signing payload (TK-01),
/// plus the custody-funded fee it range-checks (TK-02). The security-relevant
/// destination / amount / memo live on [`AccountPrepared`] itself (they bind to
/// the RIC); this carries the remaining operational fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccountSigning {
    /// Cosmos amino `MsgSend` sign-doc inputs.
    Cosmos {
        /// Custody account (`MsgSend.from_address`).
        from_address: String,
        /// Consensus chain id bound into the sign-bytes.
        cosmos_chain_id: String,
        /// Account number.
        account_number: u64,
        /// Account sequence.
        sequence: u64,
        /// Native micro-denom.
        denom: String,
        /// Custody-funded fee amount (micro-denom).
        fee_amount: u128,
        /// Gas limit.
        gas_limit: u64,
    },
    /// XRP single-sign `Payment` inputs.
    Xrp {
        /// Custody classic r-address (`Account`).
        account_address: String,
        /// Custody compressed secp256k1 pubkey (`SigningPubKey`, 33 bytes; a
        /// `Vec` because serde has no const-generic `[u8; 33]` impl).
        signing_pub_key: Vec<u8>,
        /// Account `Sequence`.
        sequence: u32,
        /// `LastLedgerSequence` deadline.
        last_ledger_sequence: u32,
        /// Custody-funded fee (`Fee`, drops).
        fee_drops: u128,
    },
    /// TRON `raw_data` inputs (`txID = SHA-256(raw_data)`).
    Tron {
        /// Custody `owner_address` (base58check `T…`).
        owner_address: String,
        /// Which asset moves (TRX or TRC20 USDT).
        asset: TronAssetKind,
        /// USDT only: the TRC20 contract address.
        contract_address: Option<String>,
        /// TAPOS `ref_block_bytes`.
        ref_block_bytes: [u8; 2],
        /// TAPOS `ref_block_hash`.
        ref_block_hash: [u8; 8],
        /// `expiration` (unix ms).
        expiration: u64,
        /// `timestamp` (unix ms).
        timestamp: u64,
        /// `fee_limit` (energy cap, sun; 0 for a TRX send).
        fee_limit: u64,
        /// `Contract.Permission_id`.
        permission_id: u32,
    },
    /// Solana legacy-message inputs (`recent_blockhash` is not cert-bound).
    Solana {
        /// Custody fee-payer pubkey (message account 0).
        from_pubkey: [u8; 32],
        /// The recent blockhash bound into the message.
        recent_blockhash: [u8; 32],
    },
}

impl AccountSigning {
    /// The custody-funded fee this spend pays, in the chain's base fee unit
    /// (uatom / drops / sun), for the per-chain fee-cap range check (TK-02).
    /// `None` for Solana (no message-level fee field in v1).
    #[must_use]
    pub fn declared_fee_base_units(&self) -> Option<u128> {
        match self {
            Self::Cosmos { fee_amount, .. } => Some(*fee_amount),
            Self::Xrp { fee_drops, .. } => Some(*fee_drops),
            Self::Tron { fee_limit, .. } => Some(u128::from(*fee_limit)),
            Self::Solana { .. } => None,
        }
    }
}

/// The unsigned account-model send (Cosmos / XRP / TRON / Solana) + its RIC.
/// Owned mirror of the account decision core's `AccountSend` (in
/// `xindex-custody-node`).
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
    /// The per-family operational signing-hash inputs (TK-01/TK-02).
    pub signing: AccountSigning,
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
    #[serde(skip_serializing_if = "Option::is_none", default)]
    evm_signing: Option<EvmSigning>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    account_signing: Option<AccountSigning>,
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
            evm_signing: None,
            account_signing: None,
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
                evm_signing: Some(e.signing.clone()),
                ric: e.ric.clone(),
                spend_identity_hex: Some(alloy_primitives::hex::encode(&e.spend_identity)),
                ..base(e.chain, "evm")
            },
            PreparedSpend::Account(a) => Self {
                to_address: Some(a.to_address.clone()),
                amount_dec: Some(a.amount_dec.clone()),
                memo: Some(a.memo.clone()),
                account_signing: Some(a.signing.clone()),
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
                    signing: require(self.evm_signing, "evm_signing")?,
                    ric: self.ric,
                    spend_identity: hexd(self.spend_identity_hex, "spend_identity_hex")?,
                }))
            }
            "account" => Ok(PreparedSpend::Account(AccountPrepared {
                chain: self.chain,
                to_address: require(self.to_address, "to_address")?,
                amount_dec: require(self.amount_dec, "amount_dec")?,
                memo: require(self.memo, "memo")?,
                signing: require(self.account_signing, "account_signing")?,
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
            signing: EvmSigning {
                nonce: 7,
                gas_limit: 300_000,
                max_fee_per_gas: 50_000_000_000,
                max_priority_fee_per_gas: 1_500_000_000,
                gas_price: 5_000_000_000,
            },
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
            signing: AccountSigning::Cosmos {
                from_address: "cosmos1custody".to_string(),
                cosmos_chain_id: "cosmoshub-4".to_string(),
                account_number: 42,
                sequence: 7,
                denom: "uatom".to_string(),
                fee_amount: 5_000,
                gas_limit: 200_000,
            },
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
