//! Durable, finalized-only Bitcoin custody inventory and policy provenance.
//!
//! The journal records only canonical block-linked custody outputs and spends.
//! Rollback atomically removes orphaned facts, restores orphaned spends, and
//! increments an observation epoch that invalidates every previously issued
//! policy-input capability.
//!
//! Raw journal mutation is intentionally not part of the external API. A
//! caller outside this crate must not be able to manufacture canonical
//! inventory facts or obtain writer authority:
//!
//! ```compile_fail
//! use xindex_chain_utxo::finalized_inventory::SqliteFinalizedBitcoinInventory;
//!
//! let _bypass = SqliteFinalizedBitcoinInventory::connect;
//! ```

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::hashes::{sha256, Hash as _};
use bitcoin::{BlockHash, OutPoint, ScriptBuf, Txid};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqlitePool, SqlitePoolOptions,
    SqliteSynchronous,
};
use sqlx::{QueryBuilder, Sqlite};
use thiserror::Error;
use xindex_shared::chain_registry::ChainId;

const PROVENANCE_DOMAIN: &[u8] = b"XINDEX/BTC/FINALIZED-POLICY-INPUTS/V1";
const BLOCK_FACTS_DOMAIN: &[u8] = b"XINDEX/BTC/FINALIZED-INVENTORY-BLOCK/V1";
const SYNTHETIC_OBSERVATION_DOMAIN: &[u8] = b"XINDEX/BTC/TEST-OBSERVATION/V1";
const SOURCE_FACTS_DOMAIN: &[u8] = b"XINDEX/BTC/FINALIZED-SOURCE-FACTS/V1";
const MAX_INVENTORY_ID_BYTES: usize = 128;
const SQLITE_OUTPOINT_QUERY_CHUNK: usize = 400;

/// Non-bypassable finalized-inventory floor inherited from the protocol BTC
/// confirmation policy.
pub const MIN_FINALIZED_BITCOIN_CONFIRMATIONS: u32 = ChainId::Btc.conf_depth();

type StoredStateRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, Vec<u8>);
type StoredConfigRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>);
type StoredBlockRow = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type StoredInputRow = (
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<i64>,
    Option<Vec<u8>>,
);

#[derive(Debug)]
struct ObservationFreshnessState {
    generation: AtomicU64,
    deadline: RwLock<Option<Instant>>,
}

/// Process-local fail-closed lease proving that the approved observer set was
/// recently corroborated through the retained journal tip.
#[derive(Debug, Clone)]
pub(crate) struct ObservationFreshness {
    state: Arc<ObservationFreshnessState>,
    enforced: bool,
}

impl ObservationFreshness {
    pub(crate) fn enforced() -> Self {
        Self {
            state: Arc::new(ObservationFreshnessState {
                generation: AtomicU64::new(0),
                deadline: RwLock::new(None),
            }),
            enforced: true,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    fn test_bypass() -> Self {
        Self {
            state: Arc::new(ObservationFreshnessState {
                generation: AtomicU64::new(0),
                deadline: RwLock::new(None),
            }),
            enforced: false,
        }
    }

    pub(crate) fn invalidate(&self) -> Result<(), InventoryError> {
        if !self.enforced {
            return Ok(());
        }
        let mut deadline = self.state.deadline.write().map_err(|_| {
            InventoryError::Database("observation freshness lock is poisoned".to_string())
        })?;
        *deadline = None;
        self.state
            .generation
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |generation| {
                generation.checked_add(1)
            })
            .map_err(|_| {
                InventoryError::Database("observation freshness generation overflow".to_string())
            })?;
        Ok(())
    }

    pub(crate) fn refresh(&self, lifetime: Duration) -> Result<(), InventoryError> {
        if !self.enforced {
            return Ok(());
        }
        let deadline_value = Instant::now().checked_add(lifetime).ok_or_else(|| {
            InventoryError::Config("observation freshness lifetime is too large".to_string())
        })?;
        let mut deadline = self.state.deadline.write().map_err(|_| {
            InventoryError::Database("observation freshness lock is poisoned".to_string())
        })?;
        *deadline = Some(deadline_value);
        Ok(())
    }

    pub(crate) fn begin_check(&self) -> Result<u64, String> {
        if !self.enforced {
            return Ok(0);
        }
        let generation = self.state.generation.load(Ordering::SeqCst);
        let deadline = self
            .state
            .deadline
            .read()
            .map_err(|_| "observation freshness lock is poisoned".to_string())?;
        if deadline.is_none_or(|value| Instant::now() > value) {
            return Err("approved observer corroboration is unavailable or expired".to_string());
        }
        Ok(generation)
    }

    pub(crate) fn finish_check(&self, expected_generation: u64) -> Result<(), String> {
        if !self.enforced {
            return Ok(());
        }
        if self.state.generation.load(Ordering::SeqCst) != expected_generation {
            return Err("approved observer changed during policy validation".to_string());
        }
        let deadline = self
            .state
            .deadline
            .read()
            .map_err(|_| "observation freshness lock is poisoned".to_string())?;
        if deadline.is_none_or(|value| Instant::now() > value) {
            return Err("approved observer corroboration is unavailable or expired".to_string());
        }
        Ok(())
    }
}

/// Fail-closed errors from the finalized Bitcoin inventory.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InventoryError {
    /// Static inventory configuration is unsafe or conflicts with durable state.
    #[error("inventory configuration error: {0}")]
    Config(String),
    /// A caller-supplied block/output value is malformed.
    #[error("invalid inventory input: {0}")]
    Invalid(String),
    /// A block commit or rollback does not follow the retained canonical chain.
    #[error("invalid inventory transition: {0}")]
    Transition(String),
    /// Requested policy inputs are absent, spent, or insufficiently finalized.
    #[error("policy input unavailable: {0}")]
    Unavailable(String),
    /// A previously issued policy-input capability is no longer current.
    #[error("policy provenance stale: {0}")]
    Stale(String),
    /// Durable `SQLite` state could not be read, migrated, or updated.
    #[error("inventory database error: {0}")]
    Database(String),
}

impl InventoryError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Config(_) => "bitcoin_inventory_config",
            Self::Invalid(_) => "bitcoin_inventory_invalid",
            Self::Transition(_) => "bitcoin_inventory_transition",
            Self::Unavailable(_) => "bitcoin_inventory_unavailable",
            Self::Stale(_) => "bitcoin_inventory_stale",
            Self::Database(_) => "bitcoin_inventory_database",
        }
    }
}

impl From<sqlx::Error> for InventoryError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error.to_string())
    }
}

/// One custody output created by a finalized canonical Bitcoin block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedBitcoinOutput {
    outpoint: OutPoint,
    value_sats: u64,
    script_pubkey: ScriptBuf,
}

impl FinalizedBitcoinOutput {
    /// Construct one positive-value observed output.
    ///
    /// # Errors
    /// Returns [`InventoryError::Invalid`] for zero value or an empty script.
    pub fn new(
        outpoint: OutPoint,
        value_sats: u64,
        script_pubkey: ScriptBuf,
    ) -> Result<Self, InventoryError> {
        if value_sats == 0 {
            return Err(InventoryError::Invalid(
                "finalized custody output value must be non-zero".to_string(),
            ));
        }
        if script_pubkey.is_empty() {
            return Err(InventoryError::Invalid(
                "finalized custody output script must be non-empty".to_string(),
            ));
        }
        Ok(Self {
            outpoint,
            value_sats,
            script_pubkey,
        })
    }

    /// Exact transaction output identity.
    #[must_use]
    pub const fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    /// Exact observed output value in satoshis.
    #[must_use]
    pub const fn value_sats(&self) -> u64 {
        self.value_sats
    }

    /// Exact observed output script.
    #[must_use]
    pub const fn script_pubkey(&self) -> &ScriptBuf {
        &self.script_pubkey
    }
}

/// Canonical finalized Bitcoin block facts relevant to the custody inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedBitcoinBlock {
    height: u64,
    block_hash: BlockHash,
    parent_hash: BlockHash,
    created_outputs: Vec<FinalizedBitcoinOutput>,
    spent_outpoints: Vec<OutPoint>,
    facts_hash: [u8; 32],
    observation_evidence_hash: [u8; 32],
}

impl FinalizedBitcoinBlock {
    /// Construct one deterministic block delta.
    ///
    /// The constructor sorts output/spend facts by outpoint before computing the
    /// content hash, so producer iteration order cannot change evidence identity.
    ///
    /// # Errors
    /// Returns [`InventoryError::Invalid`] for duplicate output or spend facts.
    pub fn new(
        height: u64,
        block_hash: BlockHash,
        parent_hash: BlockHash,
        created_outputs: Vec<FinalizedBitcoinOutput>,
        spent_outpoints: Vec<OutPoint>,
    ) -> Result<Self, InventoryError> {
        Self::build(
            height,
            block_hash,
            parent_hash,
            created_outputs,
            spent_outpoints,
            None,
        )
    }

    pub(crate) fn new_observed(
        height: u64,
        block_hash: BlockHash,
        parent_hash: BlockHash,
        created_outputs: Vec<FinalizedBitcoinOutput>,
        spent_outpoints: Vec<OutPoint>,
        observation_evidence_hash: [u8; 32],
    ) -> Result<Self, InventoryError> {
        Self::build(
            height,
            block_hash,
            parent_hash,
            created_outputs,
            spent_outpoints,
            Some(observation_evidence_hash),
        )
    }

    fn build(
        height: u64,
        block_hash: BlockHash,
        parent_hash: BlockHash,
        mut created_outputs: Vec<FinalizedBitcoinOutput>,
        mut spent_outpoints: Vec<OutPoint>,
        observation_evidence_hash: Option<[u8; 32]>,
    ) -> Result<Self, InventoryError> {
        if block_hash == parent_hash {
            return Err(InventoryError::Invalid(
                "finalized block cannot name itself as parent".to_string(),
            ));
        }
        created_outputs.sort_by_key(|output| outpoint_sort_key(output.outpoint));
        spent_outpoints.sort_by_key(|outpoint| outpoint_sort_key(*outpoint));
        if created_outputs
            .windows(2)
            .any(|pair| pair[0].outpoint == pair[1].outpoint)
        {
            return Err(InventoryError::Invalid(
                "finalized block repeats a created outpoint".to_string(),
            ));
        }
        if spent_outpoints.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(InventoryError::Invalid(
                "finalized block repeats a spent outpoint".to_string(),
            ));
        }
        let facts_hash = compute_block_facts_hash(
            height,
            block_hash,
            parent_hash,
            &created_outputs,
            &spent_outpoints,
        );
        let observation_evidence_hash = observation_evidence_hash.unwrap_or_else(|| {
            let mut evidence = Vec::new();
            push_bytes(&mut evidence, SYNTHETIC_OBSERVATION_DOMAIN);
            evidence.extend_from_slice(&facts_hash);
            sha256::Hash::hash(&evidence).to_byte_array()
        });
        if observation_evidence_hash == [0; 32] {
            return Err(InventoryError::Invalid(
                "observation evidence hash must be non-zero".to_string(),
            ));
        }
        Ok(Self {
            height,
            block_hash,
            parent_hash,
            created_outputs,
            spent_outpoints,
            facts_hash,
            observation_evidence_hash,
        })
    }

    /// Canonical block height.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Canonical block hash.
    #[must_use]
    pub const fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    /// Parent block hash.
    #[must_use]
    pub const fn parent_hash(&self) -> BlockHash {
        self.parent_hash
    }

    /// Deterministic hash of all inventory-relevant block facts.
    #[must_use]
    pub const fn facts_hash(&self) -> [u8; 32] {
        self.facts_hash
    }

    /// Authenticated observer evidence bound to this canonical block delta.
    #[must_use]
    pub const fn observation_evidence_hash(&self) -> [u8; 32] {
        self.observation_evidence_hash
    }
}

/// One finalized input inside an opaque policy provenance capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedBitcoinPolicyInput {
    outpoint: OutPoint,
    value_sats: u64,
    creation_height: u64,
    creation_block_hash: BlockHash,
    source_facts_hash: [u8; 32],
}

impl FinalizedBitcoinPolicyInput {
    /// Exact canonical outpoint.
    #[must_use]
    pub const fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    /// Exact canonical value in satoshis.
    #[must_use]
    pub const fn value_sats(&self) -> u64 {
        self.value_sats
    }

    /// Canonical block height that created this output.
    #[must_use]
    pub const fn creation_height(&self) -> u64 {
        self.creation_height
    }

    /// Canonical block hash that created this output.
    #[must_use]
    pub const fn creation_block_hash(&self) -> BlockHash {
        self.creation_block_hash
    }

    /// Content hash of the complete inventory delta for the creation block.
    #[must_use]
    pub const fn source_facts_hash(&self) -> [u8; 32] {
        self.source_facts_hash
    }
}

/// Opaque, non-deserializable proof that ordered policy inputs came from one
/// current finalized Bitcoin custody inventory snapshot.
///
/// Fields and construction are private. The only public issuance path is
/// [`FinalizedBitcoinPolicySource::issue_policy_inputs`].
///
/// ```compile_fail
/// use xindex_chain_utxo::finalized_inventory::FinalizedBitcoinPolicyInputs;
///
/// fn bypass(capability: &FinalizedBitcoinPolicyInputs) {
///     let _ = &capability.inputs;
/// }
/// ```
///
/// ```compile_fail
/// use xindex_chain_utxo::finalized_inventory::FinalizedBitcoinPolicyInputs;
///
/// fn requires_deserialize<T: serde::de::DeserializeOwned>() {}
/// requires_deserialize::<FinalizedBitcoinPolicyInputs>();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedBitcoinPolicyInputs {
    inventory_id: String,
    journal_id: [u8; 32],
    chain_hash: ChainHash,
    source_set_id: [u8; 32],
    observation_epoch: u64,
    issuance_height: u64,
    issuance_block_hash: BlockHash,
    required_confirmations: u32,
    custody_script_pubkey: ScriptBuf,
    inputs: Vec<FinalizedBitcoinPolicyInput>,
    provenance_id: [u8; 32],
}

impl FinalizedBitcoinPolicyInputs {
    /// Durable inventory identity.
    #[must_use]
    pub fn inventory_id(&self) -> &str {
        &self.inventory_id
    }

    /// Exact Bitcoin genesis/chain identity.
    #[must_use]
    pub const fn chain_hash(&self) -> ChainHash {
        self.chain_hash
    }

    /// Durable identity of the exact authenticated observer endpoint set.
    #[must_use]
    pub const fn source_set_id(&self) -> [u8; 32] {
        self.source_set_id
    }

    /// Rollback generation at issuance.
    #[must_use]
    pub const fn observation_epoch(&self) -> u64 {
        self.observation_epoch
    }

    /// Canonical checkpoint height at issuance.
    #[must_use]
    pub const fn issuance_height(&self) -> u64 {
        self.issuance_height
    }

    /// Canonical checkpoint hash at issuance.
    #[must_use]
    pub const fn issuance_block_hash(&self) -> BlockHash {
        self.issuance_block_hash
    }

    /// Non-bypassable confirmation floor used by the source.
    #[must_use]
    pub const fn required_confirmations(&self) -> u32 {
        self.required_confirmations
    }

    /// Exact aggregate-key custody script observed for every input.
    #[must_use]
    pub const fn custody_script_pubkey(&self) -> &ScriptBuf {
        &self.custody_script_pubkey
    }

    /// Complete ordered finalized input set.
    #[must_use]
    pub fn inputs(&self) -> &[FinalizedBitcoinPolicyInput] {
        &self.inputs
    }

    /// Domain-separated identity of the durable journal, chain, epoch,
    /// checkpoint, finality policy, custody script, ordered inputs, and source
    /// block evidence.
    #[must_use]
    pub const fn provenance_id(&self) -> [u8; 32] {
        self.provenance_id
    }
}

/// Durable writer for canonical finalized Bitcoin custody inventory facts.
#[derive(Debug, Clone)]
pub(crate) struct SqliteFinalizedBitcoinInventory {
    pool: SqlitePool,
    freshness: ObservationFreshness,
    inventory_id: String,
    journal_id: [u8; 32],
    chain_hash: ChainHash,
    source_set_id: [u8; 32],
    custody_script_pubkey: ScriptBuf,
    required_confirmations: u32,
}

impl SqliteFinalizedBitcoinInventory {
    #[cfg(any(test, feature = "test-utils"))]
    async fn connect(
        database_url: &str,
        inventory_id: &str,
        chain_hash: ChainHash,
        custody_script_pubkey: ScriptBuf,
        required_confirmations: u32,
    ) -> Result<Self, InventoryError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        Self::initialize(
            pool,
            ObservationFreshness::test_bypass(),
            inventory_id,
            chain_hash,
            [0x74; 32],
            custody_script_pubkey,
            required_confirmations,
        )
        .await
    }

    pub(crate) async fn connect_secure(
        database_path: &Path,
        freshness: ObservationFreshness,
        inventory_id: &str,
        source_set_id: [u8; 32],
        custody_script_pubkey: ScriptBuf,
        required_confirmations: u32,
    ) -> Result<Self, InventoryError> {
        let pool = open_secure_sqlite_pool(database_path).await?;
        let inventory = Self::initialize(
            pool,
            freshness,
            inventory_id,
            ChainHash::TESTNET4,
            source_set_id,
            custody_script_pubkey,
            required_confirmations,
        )
        .await?;
        validate_secure_sqlite_file(database_path)?;
        Ok(inventory)
    }

    async fn initialize(
        pool: SqlitePool,
        freshness: ObservationFreshness,
        inventory_id: &str,
        chain_hash: ChainHash,
        source_set_id: [u8; 32],
        custody_script_pubkey: ScriptBuf,
        required_confirmations: u32,
    ) -> Result<Self, InventoryError> {
        validate_inventory_id(inventory_id)?;
        if chain_hash != ChainHash::TESTNET4 {
            return Err(InventoryError::Config(format!(
                "Bitcoin inventory requires exact Testnet4 chain hash {}, found {chain_hash}",
                ChainHash::TESTNET4
            )));
        }
        if !custody_script_pubkey.is_p2wpkh() {
            return Err(InventoryError::Config(
                "Bitcoin inventory custody script must be native P2WPKH".to_string(),
            ));
        }
        if required_confirmations < MIN_FINALIZED_BITCOIN_CONFIRMATIONS {
            return Err(InventoryError::Config(
                format!(
                    "required confirmations {required_confirmations} are below the protocol BTC floor {MIN_FINALIZED_BITCOIN_CONFIRMATIONS}"
                ),
            ));
        }
        if source_set_id == [0; 32] {
            return Err(InventoryError::Config(
                "authenticated observer source-set identity must be non-zero".to_string(),
            ));
        }
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|error| InventoryError::Database(error.to_string()))?;

        let mut transaction = pool.begin().await?;
        let existing: Option<StoredConfigRow> = sqlx::query_as(
            "SELECT chain_hash, source_set_id, custody_script_pubkey,
                    required_confirmations, journal_id
             FROM btc_finalized_inventory_state WHERE inventory_id = ?",
        )
        .bind(inventory_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let confirmations_i64 = i64::from(required_confirmations);
        let journal_id = if let Some((
            stored_chain,
            stored_source_set,
            stored_script,
            stored_confirmations,
            stored_journal_id,
        )) = existing
        {
            if stored_chain.as_slice() != chain_hash.as_bytes()
                || stored_source_set.as_slice() != source_set_id
                || stored_script.as_slice() != custody_script_pubkey.as_bytes()
                || stored_confirmations != confirmations_i64
            {
                return Err(InventoryError::Config(
                        "durable inventory configuration does not match requested chain/source-set/script/finality"
                            .to_string(),
                    ));
            }
            decode_array_32(&stored_journal_id, "journal ID")?
        } else {
            sqlx::query(
                "INSERT INTO btc_finalized_inventory_state
                    (inventory_id, chain_hash, source_set_id, custody_script_pubkey,
                     required_confirmations, observation_epoch, journal_id)
                 VALUES (?, ?, ?, ?, ?, 0, randomblob(32))",
            )
            .bind(inventory_id)
            .bind(chain_hash.to_bytes().to_vec())
            .bind(source_set_id.to_vec())
            .bind(custody_script_pubkey.as_bytes())
            .bind(confirmations_i64)
            .execute(&mut *transaction)
            .await?;
            let stored_journal_id: Vec<u8> = sqlx::query_scalar(
                "SELECT journal_id FROM btc_finalized_inventory_state WHERE inventory_id = ?",
            )
            .bind(inventory_id)
            .fetch_one(&mut *transaction)
            .await?;
            decode_array_32(&stored_journal_id, "journal ID")?
        };
        transaction.commit().await?;
        Ok(Self {
            pool,
            freshness,
            inventory_id: inventory_id.to_string(),
            journal_id,
            chain_hash,
            source_set_id,
            custody_script_pubkey,
            required_confirmations,
        })
    }

    /// Obtain the narrow read-only source used to issue and revalidate policy
    /// input capabilities. It exposes neither block mutation nor broadcast.
    #[must_use]
    pub(crate) fn policy_source(&self) -> FinalizedBitcoinPolicySource {
        FinalizedBitcoinPolicySource {
            pool: self.pool.clone(),
            freshness: self.freshness.clone(),
            inventory_id: self.inventory_id.clone(),
            journal_id: self.journal_id,
            chain_hash: self.chain_hash,
            source_set_id: self.source_set_id,
            custody_script_pubkey: self.custody_script_pubkey.clone(),
            required_confirmations: self.required_confirmations,
        }
    }

    /// Atomically append one canonical block and its complete custody delta.
    ///
    /// The first block seeds an arbitrary trusted checkpoint. Every later block
    /// must be exactly one height higher and name the retained tip as parent.
    /// Replaying the byte-identical tip is idempotent; every conflict fails.
    ///
    /// # Errors
    /// Wrong parent/height, conflicting or unknown outpoints, wrong custody
    /// script, integer overflow, or database failure.
    #[expect(
        clippy::too_many_lines,
        reason = "one SQL transaction deliberately binds checkpoint, creations, and spends atomically"
    )]
    pub(crate) async fn commit_block(
        &self,
        block: FinalizedBitcoinBlock,
    ) -> Result<(), InventoryError> {
        for output in &block.created_outputs {
            if output.script_pubkey != self.custody_script_pubkey {
                return Err(InventoryError::Invalid(format!(
                    "created output {} does not match configured custody script",
                    output.outpoint
                )));
            }
        }

        let height_i64 = to_i64(block.height, "block height")?;
        let mut transaction = self.pool.begin().await?;
        let previous: Option<StoredBlockRow> = sqlx::query_as(
            "SELECT block_height, block_hash, parent_hash, facts_hash,
                    observation_evidence_hash
             FROM btc_finalized_inventory_blocks
             WHERE inventory_id = ? ORDER BY block_height DESC LIMIT 1",
        )
        .bind(&self.inventory_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some((
            previous_height_i64,
            previous_hash,
            previous_parent,
            previous_facts,
            previous_evidence,
        )) = previous
        {
            let previous_height = from_i64(previous_height_i64, "previous block height")?;
            if block.height == previous_height {
                if previous_hash.as_slice() == block.block_hash.as_byte_array()
                    && previous_parent.as_slice() == block.parent_hash.as_byte_array()
                    && previous_facts.as_slice() == block.facts_hash
                    && previous_evidence.as_slice() == block.observation_evidence_hash
                {
                    transaction.rollback().await?;
                    return Ok(());
                }
                return Err(InventoryError::Transition(format!(
                    "block {} conflicts with retained tip",
                    block.height
                )));
            }
            if block.height != previous_height.saturating_add(1)
                || previous_hash.as_slice() != block.parent_hash.as_byte_array()
            {
                return Err(InventoryError::Transition(format!(
                    "block {} does not extend retained tip {}",
                    block.height, previous_height
                )));
            }
        }

        sqlx::query(
            "INSERT INTO btc_finalized_inventory_blocks
                (inventory_id, block_height, block_hash, parent_hash, facts_hash,
                 observation_evidence_hash)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&self.inventory_id)
        .bind(height_i64)
        .bind(block.block_hash.to_byte_array().to_vec())
        .bind(block.parent_hash.to_byte_array().to_vec())
        .bind(block.facts_hash.to_vec())
        .bind(block.observation_evidence_hash.to_vec())
        .execute(&mut *transaction)
        .await?;

        for output in &block.created_outputs {
            let result = sqlx::query(
                "INSERT OR IGNORE INTO btc_finalized_inventory_utxos
                    (inventory_id, txid, vout, value_sats, script_pubkey,
                     creation_height, creation_block_hash,
                     spent_height, spent_block_hash)
                 VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
            )
            .bind(&self.inventory_id)
            .bind(output.outpoint.txid.to_byte_array().to_vec())
            .bind(i64::from(output.outpoint.vout))
            .bind(to_i64(output.value_sats, "output value")?)
            .bind(output.script_pubkey.as_bytes())
            .bind(height_i64)
            .bind(block.block_hash.to_byte_array().to_vec())
            .execute(&mut *transaction)
            .await?;
            if result.rows_affected() != 1 {
                return Err(InventoryError::Transition(format!(
                    "created outpoint {} already exists",
                    output.outpoint
                )));
            }
        }

        for outpoint in &block.spent_outpoints {
            let result = sqlx::query(
                "UPDATE btc_finalized_inventory_utxos
                 SET spent_height = ?, spent_block_hash = ?
                 WHERE inventory_id = ? AND txid = ? AND vout = ?
                   AND spent_height IS NULL",
            )
            .bind(height_i64)
            .bind(block.block_hash.to_byte_array().to_vec())
            .bind(&self.inventory_id)
            .bind(outpoint.txid.to_byte_array().to_vec())
            .bind(i64::from(outpoint.vout))
            .execute(&mut *transaction)
            .await?;
            if result.rows_affected() != 1 {
                return Err(InventoryError::Transition(format!(
                    "spent outpoint {outpoint} is missing or already spent"
                )));
            }
        }

        transaction.commit().await?;
        Ok(())
    }

    /// Atomically roll back to an exact retained ancestor and increment the
    /// observation epoch whenever canonical facts are removed.
    ///
    /// Outputs created on removed blocks are deleted; outputs spent only on the
    /// removed branch become unspent again. A request naming the current tip is
    /// an idempotent no-op.
    ///
    /// # Errors
    /// Missing/mismatched ancestor, corrupt durable values, or database failure.
    pub(crate) async fn rollback_to(
        &self,
        ancestor_height: u64,
        ancestor_hash: BlockHash,
    ) -> Result<(), InventoryError> {
        let ancestor_i64 = to_i64(ancestor_height, "ancestor height")?;
        let mut transaction = self.pool.begin().await?;
        let latest: Option<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT block_height, block_hash
             FROM btc_finalized_inventory_blocks
             WHERE inventory_id = ? ORDER BY block_height DESC LIMIT 1",
        )
        .bind(&self.inventory_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((latest_i64, latest_hash)) = latest else {
            return Err(InventoryError::Transition(
                "cannot roll back an empty inventory".to_string(),
            ));
        };
        let latest_height = from_i64(latest_i64, "latest height")?;
        let retained: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT block_hash FROM btc_finalized_inventory_blocks
             WHERE inventory_id = ? AND block_height = ?",
        )
        .bind(&self.inventory_id)
        .bind(ancestor_i64)
        .fetch_optional(&mut *transaction)
        .await?;
        if retained.as_deref() != Some(ancestor_hash.as_byte_array()) {
            return Err(InventoryError::Transition(
                "rollback target is not an exact retained ancestor".to_string(),
            ));
        }
        if ancestor_height > latest_height {
            return Err(InventoryError::Transition(
                "rollback target is above the retained tip".to_string(),
            ));
        }
        if ancestor_height == latest_height {
            if latest_hash.as_slice() != ancestor_hash.as_byte_array() {
                return Err(InventoryError::Transition(
                    "rollback tip hash mismatch".to_string(),
                ));
            }
            transaction.rollback().await?;
            return Ok(());
        }

        sqlx::query(
            "UPDATE btc_finalized_inventory_utxos
             SET spent_height = NULL, spent_block_hash = NULL
             WHERE inventory_id = ? AND spent_height > ?",
        )
        .bind(&self.inventory_id)
        .bind(ancestor_i64)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM btc_finalized_inventory_utxos
             WHERE inventory_id = ? AND creation_height > ?",
        )
        .bind(&self.inventory_id)
        .bind(ancestor_i64)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM btc_finalized_inventory_blocks
             WHERE inventory_id = ? AND block_height > ?",
        )
        .bind(&self.inventory_id)
        .bind(ancestor_i64)
        .execute(&mut *transaction)
        .await?;
        let epoch_update = sqlx::query(
            "UPDATE btc_finalized_inventory_state
             SET observation_epoch = observation_epoch + 1
             WHERE inventory_id = ?",
        )
        .bind(&self.inventory_id)
        .execute(&mut *transaction)
        .await?;
        if epoch_update.rows_affected() != 1 {
            return Err(InventoryError::Database(
                "inventory state disappeared during rollback".to_string(),
            ));
        }
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) async fn latest_checkpoint(
        &self,
    ) -> Result<Option<(u64, BlockHash)>, InventoryError> {
        let row: Option<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT block_height, block_hash
             FROM btc_finalized_inventory_blocks
             WHERE inventory_id = ? ORDER BY block_height DESC LIMIT 1",
        )
        .bind(&self.inventory_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(height, hash)| {
            Ok((
                from_i64(height, "latest height")?,
                decode_block_hash(&hash, "latest block hash")?,
            ))
        })
        .transpose()
    }

    pub(crate) async fn first_checkpoint(
        &self,
    ) -> Result<Option<(u64, BlockHash)>, InventoryError> {
        let row: Option<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT block_height, block_hash
             FROM btc_finalized_inventory_blocks
             WHERE inventory_id = ? ORDER BY block_height ASC LIMIT 1",
        )
        .bind(&self.inventory_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(height, hash)| {
            Ok((
                from_i64(height, "first height")?,
                decode_block_hash(&hash, "first block hash")?,
            ))
        })
        .transpose()
    }

    pub(crate) async fn canonical_hash(
        &self,
        height: u64,
    ) -> Result<Option<BlockHash>, InventoryError> {
        let hash: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT block_hash FROM btc_finalized_inventory_blocks
             WHERE inventory_id = ? AND block_height = ?",
        )
        .bind(&self.inventory_id)
        .bind(to_i64(height, "canonical height")?)
        .fetch_optional(&self.pool)
        .await?;
        hash.map(|bytes| decode_block_hash(&bytes, "canonical block hash"))
            .transpose()
    }

    pub(crate) async fn retain_unspent(
        &self,
        candidates: &HashSet<OutPoint>,
    ) -> Result<HashSet<OutPoint>, InventoryError> {
        if candidates.is_empty() {
            return Ok(HashSet::new());
        }
        let mut retained = HashSet::with_capacity(candidates.len());
        let mut transaction = self.pool.begin().await?;
        let candidates = candidates.iter().copied().collect::<Vec<_>>();
        for chunk in candidates.chunks(SQLITE_OUTPOINT_QUERY_CHUNK) {
            let mut query = QueryBuilder::<Sqlite>::new(
                "SELECT txid, vout FROM btc_finalized_inventory_utxos WHERE inventory_id = ",
            );
            query.push_bind(&self.inventory_id);
            query.push(" AND spent_height IS NULL AND (");
            for (index, outpoint) in chunk.iter().enumerate() {
                if index != 0 {
                    query.push(" OR ");
                }
                query.push("(txid = ");
                query.push_bind(outpoint.txid.to_byte_array().to_vec());
                query.push(" AND vout = ");
                query.push_bind(i64::from(outpoint.vout));
                query.push(')');
            }
            query.push(')');
            let rows = query
                .build_query_as::<(Vec<u8>, i64)>()
                .fetch_all(&mut *transaction)
                .await?;
            for (txid, vout) in rows {
                retained.insert(OutPoint {
                    txid: Txid::from_slice(&txid).map_err(|error| {
                        InventoryError::Database(format!(
                            "stored candidate spend txid is invalid: {error}"
                        ))
                    })?,
                    vout: u32::try_from(vout).map_err(|error| {
                        InventoryError::Database(format!(
                            "stored candidate spend vout is invalid: {error}"
                        ))
                    })?,
                });
            }
        }
        transaction.commit().await?;
        Ok(retained)
    }
}

/// Narrow read-only finalized policy source. Construction is restricted to the
/// trusted observer composition root; this type exposes no journal mutation or
/// transaction broadcast API.
#[derive(Debug, Clone)]
pub struct FinalizedBitcoinPolicySource {
    pool: SqlitePool,
    freshness: ObservationFreshness,
    inventory_id: String,
    journal_id: [u8; 32],
    chain_hash: ChainHash,
    source_set_id: [u8; 32],
    custody_script_pubkey: ScriptBuf,
    required_confirmations: u32,
}

impl FinalizedBitcoinPolicySource {
    /// Issue an opaque capability for the exact ordered requested outpoints.
    ///
    /// Every outpoint must be present, unspent, use the configured custody
    /// script, and meet the source's non-bypassable confirmation floor in one
    /// `SQLite` read transaction.
    ///
    /// # Errors
    /// Empty/duplicate requests, unavailable inputs, corrupt state, or database
    /// failure.
    pub async fn issue_policy_inputs(
        &self,
        ordered_outpoints: &[OutPoint],
    ) -> Result<FinalizedBitcoinPolicyInputs, InventoryError> {
        validate_requested_outpoints(ordered_outpoints)?;
        let freshness_generation = self
            .freshness
            .begin_check()
            .map_err(InventoryError::Unavailable)?;
        let mut transaction = self.pool.begin().await?;
        let state = load_state(&mut transaction, &self.inventory_id).await?;
        let observation_epoch = self.validate_state(&state)?;
        let latest = load_latest_block(&mut transaction, &self.inventory_id)
            .await?
            .ok_or_else(|| {
                InventoryError::Unavailable("inventory has no finalized checkpoint".to_string())
            })?;
        let issuance_height = from_i64(latest.0, "issuance height")?;
        let issuance_block_hash = decode_block_hash(&latest.1, "issuance block hash")?;
        let mut inputs = Vec::with_capacity(ordered_outpoints.len());
        for outpoint in ordered_outpoints {
            let row = load_input(&mut transaction, &self.inventory_id, *outpoint).await?;
            let input = decode_available_input(
                row,
                *outpoint,
                &self.custody_script_pubkey,
                issuance_height,
                self.required_confirmations,
            )
            .map_err(InventoryError::Unavailable)?;
            inputs.push(input);
        }
        let provenance_id = compute_provenance_id(
            &self.inventory_id,
            self.journal_id,
            self.chain_hash,
            self.source_set_id,
            observation_epoch,
            issuance_height,
            issuance_block_hash,
            self.required_confirmations,
            &self.custody_script_pubkey,
            &inputs,
        );
        transaction.commit().await?;
        self.freshness
            .finish_check(freshness_generation)
            .map_err(InventoryError::Unavailable)?;
        Ok(FinalizedBitcoinPolicyInputs {
            inventory_id: self.inventory_id.clone(),
            journal_id: self.journal_id,
            chain_hash: self.chain_hash,
            source_set_id: self.source_set_id,
            observation_epoch,
            issuance_height,
            issuance_block_hash,
            required_confirmations: self.required_confirmations,
            custody_script_pubkey: self.custody_script_pubkey.clone(),
            inputs,
            provenance_id,
        })
    }

    /// Revalidate one issued capability against the current canonical journal in
    /// a single read transaction.
    ///
    /// Chain/config identity, rollback epoch, issuance checkpoint, ordered input
    /// values/scripts/source facts, unspent state, and finality are all checked.
    /// The tip may advance on the same canonical epoch; rollback always stales
    /// the capability even if an apparently identical branch is later replayed.
    ///
    /// # Errors
    /// Returns [`InventoryError::Stale`] for every capability mismatch or
    /// canonical-state change, and fails closed on database errors.
    pub async fn assert_current(
        &self,
        capability: &FinalizedBitcoinPolicyInputs,
    ) -> Result<(), InventoryError> {
        self.validate_capability_binding(capability)?;
        let freshness_generation = self
            .freshness
            .begin_check()
            .map_err(InventoryError::Stale)?;
        let expected_id = compute_provenance_id(
            &capability.inventory_id,
            capability.journal_id,
            capability.chain_hash,
            capability.source_set_id,
            capability.observation_epoch,
            capability.issuance_height,
            capability.issuance_block_hash,
            capability.required_confirmations,
            &capability.custody_script_pubkey,
            &capability.inputs,
        );
        if expected_id != capability.provenance_id {
            return Err(InventoryError::Stale(
                "policy provenance identity does not match its bound facts".to_string(),
            ));
        }

        let mut transaction = self.pool.begin().await?;
        let state = load_state(&mut transaction, &self.inventory_id).await?;
        let current_epoch = self.validate_state(&state)?;
        if current_epoch != capability.observation_epoch {
            return Err(InventoryError::Stale(format!(
                "observation epoch advanced from {} to {current_epoch}",
                capability.observation_epoch
            )));
        }
        let issuance_hash: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT block_hash FROM btc_finalized_inventory_blocks
             WHERE inventory_id = ? AND block_height = ?",
        )
        .bind(&self.inventory_id)
        .bind(to_i64(capability.issuance_height, "issuance height")?)
        .fetch_optional(&mut *transaction)
        .await?;
        if issuance_hash.as_deref() != Some(capability.issuance_block_hash.as_byte_array()) {
            return Err(InventoryError::Stale(
                "issuance checkpoint is no longer canonical".to_string(),
            ));
        }
        let latest = load_latest_block(&mut transaction, &self.inventory_id)
            .await?
            .ok_or_else(|| InventoryError::Stale("inventory is empty".to_string()))?;
        let latest_height = from_i64(latest.0, "latest height")?;
        if latest_height < capability.issuance_height {
            return Err(InventoryError::Stale(
                "current tip is below the issuance checkpoint".to_string(),
            ));
        }
        for expected in &capability.inputs {
            let row = load_input(&mut transaction, &self.inventory_id, expected.outpoint).await?;
            let current = decode_available_input(
                row,
                expected.outpoint,
                &self.custody_script_pubkey,
                latest_height,
                self.required_confirmations,
            )
            .map_err(InventoryError::Stale)?;
            if current != *expected {
                return Err(InventoryError::Stale(format!(
                    "canonical facts changed for {}",
                    expected.outpoint
                )));
            }
        }
        transaction.commit().await?;
        self.freshness
            .finish_check(freshness_generation)
            .map_err(InventoryError::Stale)?;
        Ok(())
    }

    fn validate_state(&self, state: &StoredStateRow) -> Result<u64, InventoryError> {
        if state.0.as_slice() != self.chain_hash.as_bytes()
            || state.1.as_slice() != self.source_set_id
            || state.2.as_slice() != self.custody_script_pubkey.as_bytes()
            || state.3 != i64::from(self.required_confirmations)
            || state.5.as_slice() != self.journal_id
        {
            return Err(InventoryError::Database(
                "durable inventory configuration changed unexpectedly".to_string(),
            ));
        }
        from_i64(state.4, "observation epoch")
    }

    fn validate_capability_binding(
        &self,
        capability: &FinalizedBitcoinPolicyInputs,
    ) -> Result<(), InventoryError> {
        if capability.inventory_id != self.inventory_id
            || capability.journal_id != self.journal_id
            || capability.chain_hash != self.chain_hash
            || capability.source_set_id != self.source_set_id
            || capability.required_confirmations != self.required_confirmations
            || capability.custody_script_pubkey != self.custody_script_pubkey
        {
            return Err(InventoryError::Stale(
                "policy provenance belongs to a different inventory configuration".to_string(),
            ));
        }
        if capability.inputs.is_empty() {
            return Err(InventoryError::Stale(
                "policy provenance contains no inputs".to_string(),
            ));
        }
        Ok(())
    }
}

async fn load_state(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    inventory_id: &str,
) -> Result<StoredStateRow, InventoryError> {
    sqlx::query_as(
        "SELECT chain_hash, source_set_id, custody_script_pubkey,
                required_confirmations, observation_epoch, journal_id
         FROM btc_finalized_inventory_state WHERE inventory_id = ?",
    )
    .bind(inventory_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| InventoryError::Database("inventory state is missing".to_string()))
}

async fn load_latest_block(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    inventory_id: &str,
) -> Result<Option<StoredBlockRow>, InventoryError> {
    Ok(sqlx::query_as(
        "SELECT block_height, block_hash, parent_hash, facts_hash,
                observation_evidence_hash
         FROM btc_finalized_inventory_blocks
         WHERE inventory_id = ? ORDER BY block_height DESC LIMIT 1",
    )
    .bind(inventory_id)
    .fetch_optional(&mut **transaction)
    .await?)
}

async fn load_input(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    inventory_id: &str,
    outpoint: OutPoint,
) -> Result<Option<StoredInputRow>, InventoryError> {
    Ok(sqlx::query_as(
        "SELECT u.value_sats, u.script_pubkey, u.creation_height,
                u.creation_block_hash, b.facts_hash,
                b.observation_evidence_hash,
                u.spent_height, u.spent_block_hash
         FROM btc_finalized_inventory_utxos u
         JOIN btc_finalized_inventory_blocks b
           ON b.inventory_id = u.inventory_id
          AND b.block_height = u.creation_height
         WHERE u.inventory_id = ? AND u.txid = ? AND u.vout = ?",
    )
    .bind(inventory_id)
    .bind(outpoint.txid.to_byte_array().to_vec())
    .bind(i64::from(outpoint.vout))
    .fetch_optional(&mut **transaction)
    .await?)
}

fn decode_available_input(
    row: Option<StoredInputRow>,
    outpoint: OutPoint,
    custody_script_pubkey: &ScriptBuf,
    tip_height: u64,
    required_confirmations: u32,
) -> Result<FinalizedBitcoinPolicyInput, String> {
    let Some((
        value_i64,
        script_bytes,
        creation_i64,
        creation_hash_bytes,
        facts_hash_bytes,
        observation_evidence_hash_bytes,
        spent_height,
        spent_hash,
    )) = row
    else {
        return Err(format!(
            "outpoint {outpoint} is not in the canonical inventory"
        ));
    };
    if spent_height.is_some() || spent_hash.is_some() {
        return Err(format!("outpoint {outpoint} is already spent"));
    }
    if script_bytes.as_slice() != custody_script_pubkey.as_bytes() {
        return Err(format!(
            "outpoint {outpoint} does not use the configured custody script"
        ));
    }
    let value_sats = u64::try_from(value_i64)
        .map_err(|error| format!("outpoint {outpoint} value is invalid: {error}"))?;
    if value_sats == 0 {
        return Err(format!("outpoint {outpoint} has zero value"));
    }
    let creation_height = u64::try_from(creation_i64)
        .map_err(|error| format!("outpoint {outpoint} creation height is invalid: {error}"))?;
    let confirmations = tip_height
        .checked_sub(creation_height)
        .and_then(|distance| distance.checked_add(1))
        .ok_or_else(|| format!("outpoint {outpoint} creation height is above the tip"))?;
    if confirmations < u64::from(required_confirmations) {
        return Err(format!(
            "outpoint {outpoint} has {confirmations} confirmations, requires {required_confirmations}"
        ));
    }
    let creation_block_hash =
        decode_block_hash_string(&creation_hash_bytes, "creation block hash")?;
    let facts_hash = decode_array_32_string(&facts_hash_bytes, "source facts hash")?;
    let observation_evidence_hash = decode_array_32_string(
        &observation_evidence_hash_bytes,
        "observation evidence hash",
    )?;
    let source_facts_hash = compute_source_facts_hash(facts_hash, observation_evidence_hash);
    Ok(FinalizedBitcoinPolicyInput {
        outpoint,
        value_sats,
        creation_height,
        creation_block_hash,
        source_facts_hash,
    })
}

fn validate_inventory_id(inventory_id: &str) -> Result<(), InventoryError> {
    if inventory_id.is_empty()
        || inventory_id.len() > MAX_INVENTORY_ID_BYTES
        || !inventory_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(InventoryError::Config(
            "inventory ID must be 1..=128 ASCII [A-Za-z0-9._:-] bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_requested_outpoints(outpoints: &[OutPoint]) -> Result<(), InventoryError> {
    if outpoints.is_empty() {
        return Err(InventoryError::Invalid(
            "ordered policy outpoint set must be non-empty".to_string(),
        ));
    }
    let mut seen = HashSet::with_capacity(outpoints.len());
    for outpoint in outpoints {
        if !seen.insert(*outpoint) {
            return Err(InventoryError::Invalid(format!(
                "ordered policy outpoint set repeats {outpoint}"
            )));
        }
    }
    Ok(())
}

fn compute_block_facts_hash(
    height: u64,
    block_hash: BlockHash,
    parent_hash: BlockHash,
    created_outputs: &[FinalizedBitcoinOutput],
    spent_outpoints: &[OutPoint],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, BLOCK_FACTS_DOMAIN);
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(block_hash.as_byte_array());
    bytes.extend_from_slice(parent_hash.as_byte_array());
    bytes.extend_from_slice(&(created_outputs.len() as u64).to_be_bytes());
    for output in created_outputs {
        push_outpoint(&mut bytes, output.outpoint);
        bytes.extend_from_slice(&output.value_sats.to_be_bytes());
        push_bytes(&mut bytes, output.script_pubkey.as_bytes());
    }
    bytes.extend_from_slice(&(spent_outpoints.len() as u64).to_be_bytes());
    for outpoint in spent_outpoints {
        push_outpoint(&mut bytes, *outpoint);
    }
    sha256::Hash::hash(&bytes).to_byte_array()
}

fn compute_source_facts_hash(
    facts_hash: [u8; 32],
    observation_evidence_hash: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, SOURCE_FACTS_DOMAIN);
    bytes.extend_from_slice(&facts_hash);
    bytes.extend_from_slice(&observation_evidence_hash);
    sha256::Hash::hash(&bytes).to_byte_array()
}

#[expect(
    clippy::too_many_arguments,
    reason = "the provenance ID intentionally commits every independent security field"
)]
fn compute_provenance_id(
    inventory_id: &str,
    journal_id: [u8; 32],
    chain_hash: ChainHash,
    source_set_id: [u8; 32],
    observation_epoch: u64,
    issuance_height: u64,
    issuance_block_hash: BlockHash,
    required_confirmations: u32,
    custody_script_pubkey: &ScriptBuf,
    inputs: &[FinalizedBitcoinPolicyInput],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, PROVENANCE_DOMAIN);
    push_bytes(&mut bytes, inventory_id.as_bytes());
    bytes.extend_from_slice(&journal_id);
    bytes.extend_from_slice(chain_hash.as_bytes());
    bytes.extend_from_slice(&source_set_id);
    bytes.extend_from_slice(&observation_epoch.to_be_bytes());
    bytes.extend_from_slice(&issuance_height.to_be_bytes());
    bytes.extend_from_slice(issuance_block_hash.as_byte_array());
    bytes.extend_from_slice(&required_confirmations.to_be_bytes());
    push_bytes(&mut bytes, custody_script_pubkey.as_bytes());
    bytes.extend_from_slice(&(inputs.len() as u64).to_be_bytes());
    for input in inputs {
        push_outpoint(&mut bytes, input.outpoint);
        bytes.extend_from_slice(&input.value_sats.to_be_bytes());
        bytes.extend_from_slice(&input.creation_height.to_be_bytes());
        bytes.extend_from_slice(input.creation_block_hash.as_byte_array());
        bytes.extend_from_slice(&input.source_facts_hash);
    }
    sha256::Hash::hash(&bytes).to_byte_array()
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn push_outpoint(target: &mut Vec<u8>, outpoint: OutPoint) {
    target.extend_from_slice(outpoint.txid.as_byte_array());
    target.extend_from_slice(&outpoint.vout.to_be_bytes());
}

fn outpoint_sort_key(outpoint: OutPoint) -> ([u8; 32], u32) {
    (outpoint.txid.to_byte_array(), outpoint.vout)
}

fn to_i64(value: u64, label: &str) -> Result<i64, InventoryError> {
    i64::try_from(value)
        .map_err(|error| InventoryError::Invalid(format!("{label} is out of range: {error}")))
}

fn from_i64(value: i64, label: &str) -> Result<u64, InventoryError> {
    u64::try_from(value)
        .map_err(|error| InventoryError::Database(format!("stored {label} is invalid: {error}")))
}

fn decode_block_hash(bytes: &[u8], label: &str) -> Result<BlockHash, InventoryError> {
    BlockHash::from_slice(bytes)
        .map_err(|error| InventoryError::Database(format!("stored {label} is invalid: {error}")))
}

fn decode_array_32(bytes: &[u8], label: &str) -> Result<[u8; 32], InventoryError> {
    <[u8; 32]>::try_from(bytes)
        .map_err(|error| InventoryError::Database(format!("stored {label} is invalid: {error}")))
}

fn decode_block_hash_string(bytes: &[u8], label: &str) -> Result<BlockHash, String> {
    BlockHash::from_slice(bytes).map_err(|error| format!("stored {label} is invalid: {error}"))
}

fn decode_array_32_string(bytes: &[u8], label: &str) -> Result<[u8; 32], String> {
    <[u8; 32]>::try_from(bytes).map_err(|error| format!("stored {label} is invalid: {error}"))
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SecureFileIdentity {
    device: u64,
    inode: u64,
    owner: u32,
}

#[cfg(unix)]
async fn open_secure_sqlite_pool(database_path: &Path) -> Result<SqlitePool, InventoryError> {
    let before = prepare_secure_sqlite_file(database_path)?;
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
    sqlx::query("PRAGMA trusted_schema = OFF")
        .execute(&pool)
        .await?;
    let after = secure_sqlite_file_identity(database_path)?;
    if before != after {
        pool.close().await;
        return Err(InventoryError::Config(
            "SQLite inventory file identity changed while opening".to_string(),
        ));
    }
    validate_sqlite_runtime_sidecars(database_path)?;
    Ok(pool)
}

#[cfg(not(unix))]
async fn open_secure_sqlite_pool(_database_path: &Path) -> Result<SqlitePool, InventoryError> {
    Err(InventoryError::Config(
        "secure finalized-inventory storage currently requires Unix file metadata".to_string(),
    ))
}

#[cfg(unix)]
pub(crate) fn prepare_secure_sqlite_file(
    database_path: &Path,
) -> Result<SecureFileIdentity, InventoryError> {
    if !database_path.is_absolute() || database_path.file_name().is_none() {
        return Err(InventoryError::Config(
            "SQLite inventory path must be an absolute file path".to_string(),
        ));
    }
    let parent = database_path.parent().ok_or_else(|| {
        InventoryError::Config("SQLite inventory path has no parent directory".to_string())
    })?;
    let canonical_parent = parent.canonicalize().map_err(|error| {
        InventoryError::Config(format!(
            "SQLite inventory parent cannot be canonicalized: {error}"
        ))
    })?;
    if canonical_parent != parent {
        return Err(InventoryError::Config(
            "SQLite inventory parent must be a canonical non-symlink path".to_string(),
        ));
    }
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(|error| {
        InventoryError::Config(format!("SQLite inventory parent is unavailable: {error}"))
    })?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.permissions().mode() & 0o077 != 0
        || parent_metadata.permissions().mode() & 0o700 != 0o700
    {
        return Err(InventoryError::Config(
            "SQLite inventory parent must be a private owner-only directory".to_string(),
        ));
    }
    match std::fs::symlink_metadata(database_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(database_path)
                .map_err(|create_error| {
                    InventoryError::Config(format!(
                        "cannot securely create SQLite inventory: {create_error}"
                    ))
                })?;
            file.sync_all().map_err(|sync_error| {
                InventoryError::Config(format!(
                    "cannot sync new SQLite inventory file: {sync_error}"
                ))
            })?;
        }
        Err(error) => {
            return Err(InventoryError::Config(format!(
                "cannot inspect SQLite inventory file: {error}"
            )));
        }
    }
    let identity = secure_sqlite_file_identity(database_path)?;
    if identity.owner != parent_metadata.uid() {
        return Err(InventoryError::Config(
            "SQLite inventory file and private parent have different owners".to_string(),
        ));
    }
    reject_preexisting_sqlite_sidecars(database_path)?;
    Ok(identity)
}

#[cfg(unix)]
fn secure_sqlite_file_identity(database_path: &Path) -> Result<SecureFileIdentity, InventoryError> {
    let metadata = std::fs::symlink_metadata(database_path).map_err(|error| {
        InventoryError::Config(format!("cannot inspect SQLite inventory file: {error}"))
    })?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.permissions().mode() & 0o600 != 0o600
    {
        return Err(InventoryError::Config(
            "SQLite inventory must be one owner-readable/writable regular file with no hard links"
                .to_string(),
        ));
    }
    Ok(SecureFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
    })
}

#[cfg(unix)]
fn reject_preexisting_sqlite_sidecars(database_path: &Path) -> Result<(), InventoryError> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = database_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        if std::fs::symlink_metadata(&sidecar).is_ok() {
            return Err(InventoryError::Config(format!(
                "unexpected SQLite {suffix} sidecar exists"
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_sqlite_runtime_sidecars(database_path: &Path) -> Result<(), InventoryError> {
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = database_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        if std::fs::symlink_metadata(&sidecar).is_ok() {
            return Err(InventoryError::Config(format!(
                "unexpected SQLite {suffix} sidecar exists"
            )));
        }
    }
    let database = secure_sqlite_file_identity(database_path)?;
    let mut journal = database_path.as_os_str().to_os_string();
    journal.push("-journal");
    match std::fs::symlink_metadata(&journal) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.nlink() == 1
                && metadata.uid() == database.owner
                && metadata.permissions().mode().trailing_zeros() >= 6 =>
        {
            Ok(())
        }
        Ok(_) => Err(InventoryError::Config(
            "SQLite rollback journal must be one owner-only regular file".to_string(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(InventoryError::Config(format!(
            "cannot inspect SQLite rollback journal: {error}"
        ))),
    }
}

#[cfg(unix)]
fn validate_secure_sqlite_file(database_path: &Path) -> Result<(), InventoryError> {
    let _identity = secure_sqlite_file_identity(database_path)?;
    validate_sqlite_runtime_sidecars(database_path)
}

#[cfg(not(unix))]
fn validate_secure_sqlite_file(_database_path: &Path) -> Result<(), InventoryError> {
    Err(InventoryError::Config(
        "secure finalized-inventory storage currently requires Unix file metadata".to_string(),
    ))
}

/// Explicitly feature-gated in-memory control surface for cross-crate tests.
/// Production builds do not expose raw journal mutation authority.
#[cfg(feature = "test-utils")]
#[derive(Debug, Clone)]
pub struct FinalizedBitcoinInventoryTestHarness {
    inventory: SqliteFinalizedBitcoinInventory,
}

#[cfg(feature = "test-utils")]
impl FinalizedBitcoinInventoryTestHarness {
    /// Open an isolated in-memory Testnet4 inventory for deterministic tests.
    ///
    /// # Errors
    /// Invalid fixture configuration or database initialization failure.
    pub async fn in_memory(
        inventory_id: &str,
        custody_script_pubkey: ScriptBuf,
        required_confirmations: u32,
    ) -> Result<Self, InventoryError> {
        Ok(Self {
            inventory: SqliteFinalizedBitcoinInventory::connect(
                "sqlite::memory:",
                inventory_id,
                ChainHash::TESTNET4,
                custody_script_pubkey,
                required_confirmations,
            )
            .await?,
        })
    }

    /// Read-only policy capability source for the test inventory.
    #[must_use]
    pub fn policy_source(&self) -> FinalizedBitcoinPolicySource {
        self.inventory.policy_source()
    }

    /// Append one synthetic deterministic block to the test inventory.
    ///
    /// # Errors
    /// Invalid or non-canonical fixture transition.
    pub async fn commit_block(&self, block: FinalizedBitcoinBlock) -> Result<(), InventoryError> {
        self.inventory.commit_block(block).await
    }

    /// Roll a test inventory back to one retained ancestor.
    ///
    /// # Errors
    /// Unknown/mismatched ancestor or database failure.
    pub async fn rollback_to(
        &self,
        ancestor_height: u64,
        ancestor_hash: BlockHash,
    ) -> Result<(), InventoryError> {
        self.inventory
            .rollback_to(ancestor_height, ancestor_hash)
            .await
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]

    use super::*;
    use bitcoin::{Txid, WPubkeyHash};
    use std::path::PathBuf;

    fn block_hash(tag: u8) -> BlockHash {
        BlockHash::from_byte_array([tag; 32])
    }

    fn outpoint(tag: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([tag; 32]),
            vout: 0,
        }
    }

    fn outpoint_at(tag: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([tag; 32]),
            vout,
        }
    }

    fn custody_script() -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0xcc; 20]))
    }

    fn sqlite_file(name: &str) -> (PathBuf, String) {
        let path = std::env::temp_dir().join(format!(
            "xindex-finalized-inventory-{name}-{}.sqlite",
            std::process::id()
        ));
        if path.exists() {
            std::fs::remove_file(&path).expect("remove stale test database");
        }
        let url = format!("sqlite://{}?mode=rwc", path.display());
        (path, url)
    }

    async fn append_empty_through(
        store: &SqliteFinalizedBitcoinInventory,
        mut height: u64,
        mut parent_hash: BlockHash,
        target_height: u64,
    ) -> BlockHash {
        while height < target_height {
            height = height.checked_add(1).expect("test height");
            let tag = u8::try_from(height)
                .expect("test height fits one byte")
                .wrapping_add(0x40);
            let next_hash = block_hash(tag);
            store
                .commit_block(
                    FinalizedBitcoinBlock::new(
                        height,
                        next_hash,
                        parent_hash,
                        Vec::new(),
                        Vec::new(),
                    )
                    .expect("empty confirmation block"),
                )
                .await
                .expect("append empty confirmation block");
            parent_hash = next_hash;
        }
        parent_hash
    }

    async fn single_capability(
        inventory_id: &str,
        script: ScriptBuf,
        required_confirmations: u32,
        funding: OutPoint,
        value_sats: u64,
        source_hash: BlockHash,
    ) -> FinalizedBitcoinPolicyInputs {
        let store = SqliteFinalizedBitcoinInventory::connect(
            "sqlite::memory:",
            inventory_id,
            ChainHash::TESTNET4,
            script.clone(),
            required_confirmations,
        )
        .await
        .expect("inventory");
        let source = store.policy_source();
        let source_block = FinalizedBitcoinBlock::new(
            100,
            source_hash,
            block_hash(0x20),
            vec![FinalizedBitcoinOutput::new(funding, value_sats, script).expect("funding output")],
            Vec::new(),
        )
        .expect("source block");
        store
            .commit_block(source_block.clone())
            .await
            .expect("source block");
        append_empty_through(
            &store,
            100,
            source_block.block_hash(),
            100 + u64::from(required_confirmations) - 1,
        )
        .await;
        source
            .issue_policy_inputs(&[funding])
            .await
            .expect("single capability")
    }

    #[test]
    fn block_cannot_name_itself_as_parent() {
        let hash = block_hash(0x44);
        let error = FinalizedBitcoinBlock::new(100, hash, hash, Vec::new(), Vec::new())
            .expect_err("a canonical block cannot name itself as parent");
        assert!(matches!(error, InventoryError::Invalid(_)));
    }

    #[tokio::test]
    async fn exact_replay_binds_authenticated_observation_evidence() {
        let script = custody_script();
        let store = SqliteFinalizedBitcoinInventory::connect(
            "sqlite::memory:",
            "observation-evidence-binding",
            ChainHash::TESTNET4,
            script,
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect("inventory");
        let first = FinalizedBitcoinBlock::new_observed(
            100,
            block_hash(100),
            block_hash(99),
            Vec::new(),
            Vec::new(),
            [0x11; 32],
        )
        .expect("first observation");
        let substituted = FinalizedBitcoinBlock::new_observed(
            100,
            block_hash(100),
            block_hash(99),
            Vec::new(),
            Vec::new(),
            [0x22; 32],
        )
        .expect("substituted observation");
        assert_eq!(first.facts_hash(), substituted.facts_hash());
        assert_ne!(
            first.observation_evidence_hash(),
            substituted.observation_evidence_hash()
        );
        store
            .commit_block(first)
            .await
            .expect("first observation commit");
        let error = store
            .commit_block(substituted)
            .await
            .expect_err("same block facts from different evidence must not replay");
        assert!(matches!(error, InventoryError::Transition(_)));
    }

    #[tokio::test]
    async fn candidate_spend_filter_batches_large_blocks_without_losing_matches() {
        let script = custody_script();
        let funding = outpoint(0x42);
        let store = SqliteFinalizedBitcoinInventory::connect(
            "sqlite::memory:",
            "batched-candidate-filter",
            ChainHash::TESTNET4,
            script.clone(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect("inventory");
        store
            .commit_block(
                FinalizedBitcoinBlock::new(
                    100,
                    block_hash(100),
                    block_hash(99),
                    vec![FinalizedBitcoinOutput::new(funding, 120_000, script)
                        .expect("funding output")],
                    Vec::new(),
                )
                .expect("funding block"),
            )
            .await
            .expect("funding commit");
        let mut candidates = (0..=SQLITE_OUTPOINT_QUERY_CHUNK)
            .map(|vout| OutPoint {
                txid: Txid::from_byte_array([u8::try_from(vout % 251).expect("bounded"); 32]),
                vout: u32::try_from(vout).expect("bounded vout"),
            })
            .collect::<HashSet<_>>();
        candidates.insert(funding);

        let retained = store
            .retain_unspent(&candidates)
            .await
            .expect("batched filter");
        assert_eq!(retained, HashSet::from([funding]));
    }

    #[tokio::test]
    async fn malformed_outputs_requests_and_database_failure_reject() {
        let script = custody_script();
        let funding = outpoint(0x11);
        let zero = FinalizedBitcoinOutput::new(funding, 0, script.clone())
            .expect_err("zero-value custody output must reject");
        assert!(matches!(zero, InventoryError::Invalid(_)));

        let output =
            FinalizedBitcoinOutput::new(funding, 120_000, script.clone()).expect("funding output");
        let duplicate_output = FinalizedBitcoinBlock::new(
            100,
            block_hash(100),
            block_hash(99),
            vec![output.clone(), output],
            Vec::new(),
        )
        .expect_err("duplicate creations must reject");
        assert!(matches!(duplicate_output, InventoryError::Invalid(_)));
        let duplicate_spend = FinalizedBitcoinBlock::new(
            100,
            block_hash(100),
            block_hash(99),
            Vec::new(),
            vec![funding, funding],
        )
        .expect_err("duplicate spends must reject");
        assert!(matches!(duplicate_spend, InventoryError::Invalid(_)));

        let store = SqliteFinalizedBitcoinInventory::connect(
            "sqlite::memory:",
            "request-validation",
            ChainHash::TESTNET4,
            script.clone(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect("inventory");
        let source = store.policy_source();
        let wrong_script_block = FinalizedBitcoinBlock::new(
            100,
            block_hash(100),
            block_hash(99),
            vec![FinalizedBitcoinOutput::new(
                funding,
                120_000,
                ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0xdd; 20])),
            )
            .expect("wrong-script output")],
            Vec::new(),
        )
        .expect("wrong-script block");
        let wrong_script = store
            .commit_block(wrong_script_block)
            .await
            .expect_err("non-custody script must reject");
        assert!(matches!(wrong_script, InventoryError::Invalid(_)));

        store
            .commit_block(
                FinalizedBitcoinBlock::new(
                    100,
                    block_hash(100),
                    block_hash(99),
                    vec![FinalizedBitcoinOutput::new(funding, 120_000, script)
                        .expect("funding output")],
                    Vec::new(),
                )
                .expect("valid block"),
            )
            .await
            .expect("wrong-script rejection must leave no partial checkpoint");
        append_empty_through(&store, 100, block_hash(100), 105).await;
        let duplicate_request = source
            .issue_policy_inputs(&[funding, funding])
            .await
            .expect_err("duplicate request must reject");
        assert!(matches!(duplicate_request, InventoryError::Invalid(_)));
        let missing = source
            .issue_policy_inputs(&[outpoint(0xee)])
            .await
            .expect_err("missing output must reject");
        assert!(matches!(missing, InventoryError::Unavailable(_)));

        source.pool.close().await;
        let closed = source
            .issue_policy_inputs(&[funding])
            .await
            .expect_err("closed database must fail closed");
        assert!(matches!(closed, InventoryError::Database(_)));
    }

    #[tokio::test]
    async fn schema_binds_creation_hash_and_protocol_finality_floor() {
        let script = custody_script();
        let funding = outpoint(0x11);
        let store = SqliteFinalizedBitcoinInventory::connect(
            "sqlite::memory:",
            "creation-hash-binding",
            ChainHash::TESTNET4,
            script.clone(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect("inventory");
        let source = store.policy_source();
        store
            .commit_block(
                FinalizedBitcoinBlock::new(
                    100,
                    block_hash(100),
                    block_hash(99),
                    vec![FinalizedBitcoinOutput::new(funding, 120_000, script)
                        .expect("funding output")],
                    Vec::new(),
                )
                .expect("block 100"),
            )
            .await
            .expect("block 100");
        append_empty_through(&store, 100, block_hash(100), 105).await;

        sqlx::query(
            "UPDATE btc_finalized_inventory_utxos
             SET creation_block_hash = ?
             WHERE inventory_id = ? AND txid = ? AND vout = ?",
        )
        .bind(block_hash(0xdd).to_byte_array().to_vec())
        .bind("creation-hash-binding")
        .bind(funding.txid.to_byte_array().to_vec())
        .bind(i64::from(funding.vout))
        .execute(&source.pool)
        .await
        .expect_err("foreign-key integrity must reject a mismatched creation block hash");
        sqlx::query(
            "UPDATE btc_finalized_inventory_state
             SET required_confirmations = ?
             WHERE inventory_id = ?",
        )
        .bind(i64::from(MIN_FINALIZED_BITCOIN_CONFIRMATIONS - 1))
        .bind("creation-hash-binding")
        .execute(&source.pool)
        .await
        .expect_err("durable state must enforce the protocol BTC confirmation floor");
        source
            .issue_policy_inputs(&[funding])
            .await
            .expect("failed corruption attempt must leave the output usable");
    }

    #[tokio::test]
    async fn independent_matching_journal_cannot_revalidate_capability() {
        let script = custody_script();
        let first = SqliteFinalizedBitcoinInventory::connect(
            "sqlite::memory:",
            "source-binding",
            ChainHash::TESTNET4,
            script.clone(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect("first inventory");
        let second = SqliteFinalizedBitcoinInventory::connect(
            "sqlite::memory:",
            "source-binding",
            ChainHash::TESTNET4,
            script.clone(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect("independent matching inventory");
        let funding = outpoint(0x11);
        let source_block = FinalizedBitcoinBlock::new(
            100,
            block_hash(100),
            block_hash(99),
            vec![FinalizedBitcoinOutput::new(funding, 120_000, script).expect("funding output")],
            Vec::new(),
        )
        .expect("source block");
        for store in [&first, &second] {
            store
                .commit_block(source_block.clone())
                .await
                .expect("source block");
            append_empty_through(store, 100, source_block.block_hash(), 105).await;
        }

        let capability = first
            .policy_source()
            .issue_policy_inputs(&[funding])
            .await
            .expect("first capability");
        let error = second
            .policy_source()
            .assert_current(&capability)
            .await
            .expect_err("an independently populated journal must not substitute for the issuer");
        assert!(matches!(error, InventoryError::Stale(_)));
    }

    #[tokio::test]
    async fn provenance_identity_commits_inventory_config_and_source_facts() {
        let baseline = single_capability(
            "identity-base",
            custody_script(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
            outpoint(0x11),
            120_000,
            block_hash(0x64),
        )
        .await;
        assert_eq!(baseline.chain_hash(), ChainHash::TESTNET4);
        assert_ne!(baseline.source_set_id(), [0; 32]);
        let variants = [
            single_capability(
                "identity-other",
                custody_script(),
                MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
                outpoint(0x11),
                120_000,
                block_hash(0x64),
            )
            .await,
            single_capability(
                "identity-base",
                ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0xdd; 20])),
                MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
                outpoint(0x11),
                120_000,
                block_hash(0x64),
            )
            .await,
            single_capability(
                "identity-base",
                custody_script(),
                MIN_FINALIZED_BITCOIN_CONFIRMATIONS + 1,
                outpoint(0x11),
                120_000,
                block_hash(0x64),
            )
            .await,
            single_capability(
                "identity-base",
                custody_script(),
                MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
                outpoint(0x22),
                120_000,
                block_hash(0x64),
            )
            .await,
            single_capability(
                "identity-base",
                custody_script(),
                MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
                outpoint(0x11),
                120_001,
                block_hash(0x64),
            )
            .await,
            single_capability(
                "identity-base",
                custody_script(),
                MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
                outpoint(0x11),
                120_000,
                block_hash(0x65),
            )
            .await,
        ];
        for variant in variants {
            assert_ne!(baseline.provenance_id(), variant.provenance_id());
        }
    }

    #[tokio::test]
    async fn connect_is_testnet4_only_and_rejects_persistent_config_drift() {
        let (path, url) = sqlite_file("config");
        let script = custody_script();
        let below_finality_floor = SqliteFinalizedBitcoinInventory::connect(
            &url,
            "below-finality-floor",
            ChainHash::TESTNET4,
            script.clone(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS - 1,
        )
        .await
        .expect_err("caller must not lower the protocol BTC confirmation floor");
        assert!(matches!(below_finality_floor, InventoryError::Config(_)));
        let store = SqliteFinalizedBitcoinInventory::connect(
            &url,
            "config-test",
            ChainHash::TESTNET4,
            script.clone(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect("initial inventory");

        for wrong_chain in [
            ChainHash::BITCOIN,
            ChainHash::TESTNET3,
            ChainHash::SIGNET,
            ChainHash::REGTEST,
        ] {
            let error = SqliteFinalizedBitcoinInventory::connect(
                &url,
                "config-test",
                wrong_chain,
                script.clone(),
                MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
            )
            .await
            .expect_err("every Testnet4 sibling chain must fail closed");
            assert!(matches!(error, InventoryError::Config(_)));
        }

        let wrong_script = SqliteFinalizedBitcoinInventory::connect(
            &url,
            "config-test",
            ChainHash::TESTNET4,
            ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0xdd; 20])),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect_err("persisted custody script must not drift");
        assert!(matches!(wrong_script, InventoryError::Config(_)));

        let wrong_finality = SqliteFinalizedBitcoinInventory::connect(
            &url,
            "config-test",
            ChainHash::TESTNET4,
            script.clone(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS + 1,
        )
        .await
        .expect_err("persisted finality floor must not drift");
        assert!(matches!(wrong_finality, InventoryError::Config(_)));

        SqliteFinalizedBitcoinInventory::connect(
            &url,
            "config-test",
            ChainHash::TESTNET4,
            script,
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect("exact persistent config must reopen");
        drop(store);
        std::fs::remove_file(path).expect("remove test database");
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one regression covers the complete canonical commit, rollback, and replacement lifecycle"
    )]
    #[tokio::test]
    async fn commit_rollback_and_replacement_preserve_canonical_utxo_state() {
        let script = custody_script();
        let store = SqliteFinalizedBitcoinInventory::connect(
            "sqlite::memory:",
            "canonical-lifecycle",
            ChainHash::TESTNET4,
            script.clone(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect("inventory");
        let source = store.policy_source();
        let first = outpoint_at(0x11, 1);
        let replacement_only = outpoint_at(0x22, 2);
        let block_100 =
            FinalizedBitcoinBlock::new(
                100,
                block_hash(100),
                block_hash(99),
                vec![FinalizedBitcoinOutput::new(first, 120_000, script.clone())
                    .expect("first output")],
                Vec::new(),
            )
            .expect("block 100");
        store
            .commit_block(block_100.clone())
            .await
            .expect("block 100");
        let immature = source
            .issue_policy_inputs(&[first])
            .await
            .expect_err("one confirmation is below the configured floor");
        assert!(matches!(immature, InventoryError::Unavailable(_)));

        let gap = store
            .commit_block(
                FinalizedBitcoinBlock::new(
                    102,
                    block_hash(102),
                    block_hash(101),
                    Vec::new(),
                    Vec::new(),
                )
                .expect("gap block"),
            )
            .await
            .expect_err("height gaps must fail closed");
        assert!(matches!(gap, InventoryError::Transition(_)));
        let wrong_parent = store
            .commit_block(
                FinalizedBitcoinBlock::new(
                    101,
                    block_hash(101),
                    block_hash(0xee),
                    Vec::new(),
                    Vec::new(),
                )
                .expect("wrong-parent block"),
            )
            .await
            .expect_err("wrong parent must fail closed");
        assert!(matches!(wrong_parent, InventoryError::Transition(_)));

        let block_101 = FinalizedBitcoinBlock::new(
            101,
            block_hash(101),
            block_100.block_hash(),
            vec![
                FinalizedBitcoinOutput::new(replacement_only, 80_000, script)
                    .expect("replacement-only output"),
            ],
            vec![first],
        )
        .expect("block 101");
        store
            .commit_block(block_101.clone())
            .await
            .expect("block 101");
        store
            .commit_block(block_101.clone())
            .await
            .expect("exact replay must be idempotent");
        let conflict = store
            .commit_block(
                FinalizedBitcoinBlock::new(
                    101,
                    block_hash(0x91),
                    block_100.block_hash(),
                    Vec::new(),
                    Vec::new(),
                )
                .expect("conflicting block"),
            )
            .await
            .expect_err("same-height conflicting facts must fail closed");
        assert!(matches!(conflict, InventoryError::Transition(_)));

        let unknown_spend = store
            .commit_block(
                FinalizedBitcoinBlock::new(
                    102,
                    block_hash(102),
                    block_101.block_hash(),
                    Vec::new(),
                    vec![outpoint_at(0xee, 9)],
                )
                .expect("unknown-spend block"),
            )
            .await
            .expect_err("unknown custody spend must abort the whole block");
        assert!(matches!(unknown_spend, InventoryError::Transition(_)));
        store
            .commit_block(
                FinalizedBitcoinBlock::new(
                    102,
                    block_hash(102),
                    block_101.block_hash(),
                    Vec::new(),
                    Vec::new(),
                )
                .expect("block 102"),
            )
            .await
            .expect("failed block transaction must leave no partial checkpoint");

        let spent = source
            .issue_policy_inputs(&[first])
            .await
            .expect_err("spent output cannot issue provenance");
        assert!(matches!(spent, InventoryError::Unavailable(_)));
        let tip_105 = append_empty_through(&store, 102, block_hash(102), 105).await;
        let below_floor = source
            .issue_policy_inputs(&[replacement_only])
            .await
            .expect_err("five confirmations remain below the protocol floor");
        assert!(matches!(below_floor, InventoryError::Unavailable(_)));
        append_empty_through(&store, 105, tip_105, 106).await;
        let replacement_capability = source
            .issue_policy_inputs(&[replacement_only])
            .await
            .expect("replacement-only output reaches the six-confirmation floor");

        store
            .rollback_to(100, block_100.block_hash())
            .await
            .expect("rollback");
        let stale = source
            .assert_current(&replacement_capability)
            .await
            .expect_err("rollback epoch must stale the old capability");
        assert!(matches!(stale, InventoryError::Stale(_)));
        let removed = source
            .issue_policy_inputs(&[replacement_only])
            .await
            .expect_err("orphan-created output must be deleted");
        assert!(matches!(removed, InventoryError::Unavailable(_)));
        let restored_but_immature = source
            .issue_policy_inputs(&[first])
            .await
            .expect_err("restored output has only one confirmation after rollback");
        assert!(matches!(
            restored_but_immature,
            InventoryError::Unavailable(_)
        ));

        store
            .commit_block(
                FinalizedBitcoinBlock::new(
                    101,
                    block_hash(0x91),
                    block_100.block_hash(),
                    Vec::new(),
                    Vec::new(),
                )
                .expect("replacement block 101"),
            )
            .await
            .expect("replacement block 101");
        append_empty_through(&store, 101, block_hash(0x91), 105).await;
        let restored = source
            .issue_policy_inputs(&[first])
            .await
            .expect("pre-ancestor spend must be restored on the replacement branch");
        assert_eq!(restored.observation_epoch(), 1);
        assert_ne!(
            restored.provenance_id(),
            replacement_capability.provenance_id()
        );
    }

    #[tokio::test]
    async fn provenance_identity_is_ordered_and_stable_across_restart() {
        let (path, url) = sqlite_file("restart");
        let script = custody_script();
        let store = SqliteFinalizedBitcoinInventory::connect(
            &url,
            "restart-test",
            ChainHash::TESTNET4,
            script.clone(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect("inventory");
        let source = store.policy_source();
        let first = outpoint_at(0x11, 1);
        let second = outpoint_at(0x22, 2);
        let block_100 = FinalizedBitcoinBlock::new(
            100,
            block_hash(100),
            block_hash(99),
            vec![
                FinalizedBitcoinOutput::new(first, 120_000, script.clone()).expect("first output"),
                FinalizedBitcoinOutput::new(second, 80_000, script.clone()).expect("second output"),
            ],
            Vec::new(),
        )
        .expect("block 100");
        store
            .commit_block(block_100.clone())
            .await
            .expect("block 100");
        store
            .commit_block(
                FinalizedBitcoinBlock::new(
                    101,
                    block_hash(101),
                    block_100.block_hash(),
                    Vec::new(),
                    Vec::new(),
                )
                .expect("block 101"),
            )
            .await
            .expect("block 101");
        append_empty_through(&store, 101, block_hash(101), 105).await;
        let before_restart = source
            .issue_policy_inputs(&[first, second])
            .await
            .expect("ordered capability");
        drop(source);
        drop(store);

        let reopened = SqliteFinalizedBitcoinInventory::connect(
            &url,
            "restart-test",
            ChainHash::TESTNET4,
            script,
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect("reopened inventory");
        let reopened_source = reopened.policy_source();
        reopened_source
            .assert_current(&before_restart)
            .await
            .expect("pre-restart capability remains current");
        let after_restart = reopened_source
            .issue_policy_inputs(&[first, second])
            .await
            .expect("same ordered capability");
        assert_eq!(
            before_restart.provenance_id(),
            after_restart.provenance_id()
        );
        let reversed = reopened_source
            .issue_policy_inputs(&[second, first])
            .await
            .expect("reversed capability");
        assert_ne!(after_restart.provenance_id(), reversed.provenance_id());
        assert_eq!(reversed.inputs()[0].outpoint(), second);
        assert_eq!(reversed.inputs()[1].outpoint(), first);

        drop(reopened_source);
        drop(reopened);
        std::fs::remove_file(path).expect("remove test database");
    }

    #[tokio::test]
    async fn capability_survives_tip_advance_but_stales_when_input_is_spent() {
        let script = custody_script();
        let store = SqliteFinalizedBitcoinInventory::connect(
            "sqlite::memory:",
            "tip-advance",
            ChainHash::TESTNET4,
            script.clone(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect("inventory");
        let source = store.policy_source();
        let funding = outpoint(0x11);
        let block_100 = FinalizedBitcoinBlock::new(
            100,
            block_hash(100),
            block_hash(99),
            vec![FinalizedBitcoinOutput::new(funding, 120_000, script).expect("funding output")],
            Vec::new(),
        )
        .expect("block 100");
        store
            .commit_block(block_100.clone())
            .await
            .expect("block 100");
        let tip_105 = append_empty_through(&store, 100, block_100.block_hash(), 105).await;
        let capability = source
            .issue_policy_inputs(&[funding])
            .await
            .expect("capability");

        let block_106 =
            FinalizedBitcoinBlock::new(106, block_hash(106), tip_105, Vec::new(), Vec::new())
                .expect("block 106");
        store
            .commit_block(block_106.clone())
            .await
            .expect("block 106");
        source
            .assert_current(&capability)
            .await
            .expect("ordinary finalized tip advance must not stale provenance");

        store
            .commit_block(
                FinalizedBitcoinBlock::new(
                    107,
                    block_hash(107),
                    block_106.block_hash(),
                    Vec::new(),
                    vec![funding],
                )
                .expect("spend block"),
            )
            .await
            .expect("spend block");
        let stale = source
            .assert_current(&capability)
            .await
            .expect_err("a subsequently spent input must stale provenance");
        assert!(matches!(stale, InventoryError::Stale(_)));
    }

    #[tokio::test]
    async fn stale_reorged_policy_is_rejected_before_reissue() {
        let store = SqliteFinalizedBitcoinInventory::connect(
            "sqlite::memory:",
            "vultisig-testnet4",
            ChainHash::TESTNET4,
            custody_script(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
        )
        .await
        .expect("inventory");
        let source = store.policy_source();
        let funding = outpoint(0x11);
        let block_100 = FinalizedBitcoinBlock::new(
            100,
            block_hash(100),
            block_hash(99),
            vec![FinalizedBitcoinOutput::new(funding, 120_000, custody_script()).expect("output")],
            Vec::new(),
        )
        .expect("block 100");
        store
            .commit_block(block_100.clone())
            .await
            .expect("block 100");
        store
            .commit_block(
                FinalizedBitcoinBlock::new(
                    101,
                    block_hash(101),
                    block_100.block_hash(),
                    Vec::new(),
                    Vec::new(),
                )
                .expect("block 101"),
            )
            .await
            .expect("block 101");
        append_empty_through(&store, 101, block_hash(101), 105).await;

        let old = source
            .issue_policy_inputs(&[funding])
            .await
            .expect("six-confirmation provenance");
        source
            .assert_current(&old)
            .await
            .expect("current provenance");
        store
            .rollback_to(100, block_100.block_hash())
            .await
            .expect("reorg rollback");
        assert!(matches!(
            source.assert_current(&old).await,
            Err(InventoryError::Stale(_))
        ));
        assert!(matches!(
            source.issue_policy_inputs(&[funding]).await,
            Err(InventoryError::Unavailable(_))
        ));

        store
            .commit_block(
                FinalizedBitcoinBlock::new(
                    101,
                    block_hash(0xb1),
                    block_100.block_hash(),
                    Vec::new(),
                    Vec::new(),
                )
                .expect("replacement block 101"),
            )
            .await
            .expect("replacement block 101");
        append_empty_through(&store, 101, block_hash(0xb1), 105).await;
        let current = source
            .issue_policy_inputs(&[funding])
            .await
            .expect("replacement provenance");
        source
            .assert_current(&current)
            .await
            .expect("replacement current");
        assert_ne!(old.provenance_id(), current.provenance_id());
        assert_eq!(old.observation_epoch(), 0);
        assert_eq!(current.observation_epoch(), 1);
    }
}
