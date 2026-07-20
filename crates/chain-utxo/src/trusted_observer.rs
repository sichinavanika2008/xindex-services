//! Trusted Bitcoin Testnet4 observation composition root for Vultisig policy.
//!
//! This module is the only production path that owns finalized-inventory writer
//! authority. It pins an exact set of HTTPS Esplora origins, authenticates every
//! origin against the Testnet4 genesis block, requires every source to return
//! equal tips and the same canonical raw blocks, validates each block's local
//! commitments and proof of work, and commits only facts derived from those
//! bytes. Policy freshness is granted only after a second equal-tip sample;
//! coinbase outputs remain excluded until 100-block maturity is modeled.
//!
//! This is authenticated multi-source observation, not an independent Bitcoin
//! consensus implementation. The configured HTTPS sources remain trusted for
//! canonical-chain selection, transaction validity, and difficulty transitions.

use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::blockdata::constants::{genesis_block, ChainHash};
use bitcoin::consensus::Params;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{sha256, Hash as _};
use bitcoin::{Block, BlockHash, Network, OutPoint, Script, ScriptBuf, Transaction, Txid, Wtxid};
use reqwest::{Client, Url};
use thiserror::Error;
use tokio::sync::Mutex;
use xindex_ops::network::{async_client, read_bounded_async, HttpClientPolicy, NetworkError};

use crate::finalized_inventory::{
    FinalizedBitcoinBlock, FinalizedBitcoinOutput, FinalizedBitcoinPolicySource, InventoryError,
    ObservationFreshness, SqliteFinalizedBitcoinInventory, MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
};

const SOURCE_SET_DOMAIN: &[u8] = b"XINDEX/BTC/TESTNET4-ESPLORA-SOURCE-SET/V1";
const OBSERVATION_DOMAIN: &[u8] = b"XINDEX/BTC/TESTNET4-CORROBORATED-BLOCK/V1";
const TRANSACTION_STATUS_SAMPLE_DOMAIN: &[u8] = b"XINDEX/BTC/TESTNET4-TRANSACTION-STATUS-SAMPLE/V1";
const CHECKPOINT_SAMPLE_DOMAIN: &[u8] = b"XINDEX/BTC/TESTNET4-CHECKPOINT-SAMPLE/V1";
const FINAL_TRANSACTION_OBSERVATION_DOMAIN: &[u8] =
    b"XINDEX/BTC/TESTNET4-FINAL-TRANSACTION-OBSERVATION/V1";
const MAX_TEXT_RESPONSE_BYTES: usize = 256;
const MAX_TRANSACTION_STATUS_BYTES: usize = 512;
const MAX_RAW_BLOCK_BYTES: usize = 4 * 1024 * 1024;
const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
const MAX_BLOCKS_PER_SYNC: u32 = 64;
const POLICY_OBSERVATION_LEASE: Duration = Duration::from_mins(2);
const MIN_CORROBORATING_SOURCES: usize = 2;
const MAX_SOURCE_ID_BYTES: usize = 64;

/// One operator-approved HTTPS Esplora source.
#[derive(Clone, PartialEq, Eq)]
pub struct Testnet4EsploraSource {
    source_id: String,
    base_url: Url,
    origin_key: String,
}

impl Testnet4EsploraSource {
    /// Pin one source by stable operator ID and exact HTTPS base URL.
    ///
    /// User information, query strings, fragments, IP-only identity, and HTTP
    /// endpoints are rejected. The URL's hostname is also used to require
    /// independent source origins.
    ///
    /// # Errors
    /// Invalid source ID or endpoint identity.
    pub fn new(
        source_id: impl Into<String>,
        base_url: impl AsRef<str>,
    ) -> Result<Self, ObserverError> {
        Self::parse(source_id.into(), base_url.as_ref(), false)
    }

    fn parse(
        source_id: String,
        base_url: &str,
        allow_loopback_http: bool,
    ) -> Result<Self, ObserverError> {
        if source_id.is_empty()
            || source_id.len() > MAX_SOURCE_ID_BYTES
            || !source_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ObserverError::Config(
                "source ID must be 1..=64 ASCII [A-Za-z0-9._-] bytes".to_string(),
            ));
        }
        let mut parsed = Url::parse(base_url)
            .map_err(|_| ObserverError::Config("source URL is invalid".to_string()))?;
        let loopback_http = allow_loopback_http
            && parsed.scheme() == "http"
            && parsed
                .host_str()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "::1"));
        if parsed.scheme() != "https" && !loopback_http {
            return Err(ObserverError::Config(
                "observer sources must use authenticated HTTPS".to_string(),
            ));
        }
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ObserverError::Config(
                "source URL must not contain credentials, query, or fragment".to_string(),
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| ObserverError::Config("source URL has no hostname".to_string()))?
            .to_ascii_lowercase();
        if !allow_loopback_http && host.parse::<std::net::IpAddr>().is_ok() {
            return Err(ObserverError::Config(
                "production observer source identity requires a DNS hostname".to_string(),
            ));
        }
        if !parsed.path().ends_with('/') {
            let path = format!("{}/", parsed.path());
            parsed.set_path(&path);
        }
        let origin_key = if allow_loopback_http {
            parsed.origin().ascii_serialization()
        } else {
            host
        };
        Ok(Self {
            source_id,
            base_url: parsed,
            origin_key,
        })
    }

    /// Stable operator-defined source identity.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }
}

impl fmt::Debug for Testnet4EsploraSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Testnet4EsploraSource")
            .field("source_id", &self.source_id)
            .field("base_url", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Immutable trusted-observer configuration for one custody inventory.
#[derive(Clone, PartialEq, Eq)]
pub struct Testnet4ObserverConfig {
    inventory_id: String,
    database_path: PathBuf,
    custody_script_pubkey: ScriptBuf,
    required_confirmations: u32,
    start_height: u32,
    sources: Vec<Testnet4EsploraSource>,
    source_set_id: [u8; 32],
}

impl Testnet4ObserverConfig {
    /// Bind one inventory to a private `SQLite` file, custody script,
    /// genesis-anchored history, finality floor, and at least two distinct
    /// authenticated source hosts.
    ///
    /// `start_height` is explicit but currently must be zero. This prevents an
    /// operator-supplied height or endpoint label from becoming an unauthenticated
    /// Testnet4 checkpoint.
    ///
    /// # Errors
    /// Unsafe finality, source count/identity, or duplicate source configuration.
    pub fn new(
        inventory_id: impl Into<String>,
        database_path: impl Into<PathBuf>,
        custody_script_pubkey: ScriptBuf,
        required_confirmations: u32,
        start_height: u32,
        sources: Vec<Testnet4EsploraSource>,
    ) -> Result<Self, ObserverError> {
        Self::build(
            inventory_id.into(),
            database_path.into(),
            custody_script_pubkey,
            required_confirmations,
            start_height,
            sources,
        )
    }

    fn build(
        inventory_id: String,
        database_path: PathBuf,
        custody_script_pubkey: ScriptBuf,
        required_confirmations: u32,
        start_height: u32,
        mut sources: Vec<Testnet4EsploraSource>,
    ) -> Result<Self, ObserverError> {
        if start_height != 0 {
            return Err(ObserverError::Config(
                "observer history must start at the authenticated Testnet4 genesis block"
                    .to_string(),
            ));
        }
        if required_confirmations < MIN_FINALIZED_BITCOIN_CONFIRMATIONS {
            return Err(ObserverError::Config(format!(
                "required confirmations {required_confirmations} are below the protocol floor {MIN_FINALIZED_BITCOIN_CONFIRMATIONS}"
            )));
        }
        if sources.len() < MIN_CORROBORATING_SOURCES {
            return Err(ObserverError::Config(format!(
                "at least {MIN_CORROBORATING_SOURCES} corroborating observer sources are required"
            )));
        }
        sources.sort_by(|left, right| left.source_id.cmp(&right.source_id));
        let mut source_ids = HashSet::with_capacity(sources.len());
        let mut origins = HashSet::with_capacity(sources.len());
        for source in &sources {
            if !source_ids.insert(source.source_id.clone()) {
                return Err(ObserverError::Config(format!(
                    "duplicate observer source ID {}",
                    source.source_id
                )));
            }
            if !origins.insert(source.origin_key.clone()) {
                return Err(ObserverError::Config(
                    "observer sources must use distinct authenticated origins".to_string(),
                ));
            }
        }
        let source_set_id = compute_source_set_id(&sources);
        Ok(Self {
            inventory_id,
            database_path,
            custody_script_pubkey,
            required_confirmations,
            start_height,
            sources,
            source_set_id,
        })
    }

    #[cfg(test)]
    fn new_for_test(
        inventory_id: impl Into<String>,
        database_path: impl Into<PathBuf>,
        custody_script_pubkey: ScriptBuf,
        required_confirmations: u32,
        start_height: u32,
        sources: Vec<(&str, &str)>,
    ) -> Result<Self, ObserverError> {
        let sources = sources
            .into_iter()
            .map(|(source_id, base_url)| {
                Testnet4EsploraSource::parse(source_id.to_string(), base_url, true)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::build(
            inventory_id.into(),
            database_path.into(),
            custody_script_pubkey,
            required_confirmations,
            start_height,
            sources,
        )
    }

    /// Domain-separated identity of the exact ordered source IDs and URLs.
    #[must_use]
    pub const fn source_set_id(&self) -> [u8; 32] {
        self.source_set_id
    }
}

impl fmt::Debug for Testnet4ObserverConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Testnet4ObserverConfig")
            .field("inventory_id", &self.inventory_id)
            .field("database_path", &"<redacted>")
            .field("custody_script_pubkey", &self.custody_script_pubkey)
            .field("required_confirmations", &self.required_confirmations)
            .field("start_height", &self.start_height)
            .field("source_count", &self.sources.len())
            .field("source_set_id", &self.source_set_id)
            .finish()
    }
}

/// One bounded synchronization result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObserverSyncReport {
    source_tip: u32,
    retained_tip: Option<u32>,
    appended_blocks: u32,
    rolled_back_blocks: u32,
}

/// Opaque, non-deserializable observation of one exact finalized Testnet4
/// transaction from the configured source set and retained inventory.
///
/// Fields and construction are private. The only public issuance path is
/// [`Testnet4FinalizedInventoryObserver::observe_finalized_transaction`].
/// The capability proves agreement among configured sources; it does not claim
/// that those sources are independent full nodes or independent operators.
///
/// ```compile_fail
/// use xindex_chain_utxo::trusted_observer::FinalizedBitcoinTransactionObservation;
///
/// fn bypass(observation: &FinalizedBitcoinTransactionObservation) {
///     let _ = observation.exact_transaction_sha256;
/// }
/// ```
///
/// ```compile_fail
/// use xindex_chain_utxo::trusted_observer::FinalizedBitcoinTransactionObservation;
///
/// fn requires_deserialize<T: serde::de::DeserializeOwned>() {}
/// requires_deserialize::<FinalizedBitcoinTransactionObservation>();
/// ```
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a finalized transaction observation must be consumed by the sealed runtime"]
pub struct FinalizedBitcoinTransactionObservation {
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

impl FinalizedBitcoinTransactionObservation {
    /// Exact Bitcoin genesis/chain identity authenticated by every source.
    #[must_use]
    pub const fn chain_hash(&self) -> ChainHash {
        self.chain_hash
    }

    /// Locally derived transaction ID of the canonical transaction bytes.
    #[must_use]
    pub const fn txid(&self) -> Txid {
        self.txid
    }

    /// Locally derived witness transaction ID of the canonical bytes.
    #[must_use]
    pub const fn wtxid(&self) -> Wtxid {
        self.wtxid
    }

    /// Single SHA-256 digest of the exact canonical serialized transaction.
    #[must_use]
    pub const fn exact_transaction_sha256(&self) -> [u8; 32] {
        self.exact_transaction_sha256
    }

    /// Corroborated canonical block containing the transaction.
    #[must_use]
    pub const fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    /// Height of the corroborated canonical block.
    #[must_use]
    pub const fn block_height(&self) -> u32 {
        self.block_height
    }

    /// Equal source-tip height sampled around the observation.
    #[must_use]
    pub const fn corroborated_tip(&self) -> u32 {
        self.corroborated_tip
    }

    /// Checked inclusive confirmation count at the corroborated tip.
    #[must_use]
    pub const fn confirmations(&self) -> u32 {
        self.confirmations
    }

    /// Non-bypassable confirmation floor configured for this inventory.
    #[must_use]
    pub const fn required_confirmations(&self) -> u32 {
        self.required_confirmations
    }

    /// Durable identity of the exact configured observer source set.
    #[must_use]
    pub const fn source_set_id(&self) -> [u8; 32] {
        self.source_set_id
    }

    /// Domain-separated commitment to the transaction, canonical location,
    /// finality calculation, inventory/source identities, and both status
    /// samples.
    #[must_use]
    pub const fn evidence_hash(&self) -> [u8; 32] {
        self.evidence_hash
    }
}

impl ObserverSyncReport {
    /// Latest tip height corroborated by every approved source.
    #[must_use]
    pub const fn source_tip(&self) -> u32 {
        self.source_tip
    }

    /// Durable inventory tip after the synchronization attempt.
    #[must_use]
    pub const fn retained_tip(&self) -> Option<u32> {
        self.retained_tip
    }

    /// Number of newly committed corroborated blocks.
    #[must_use]
    pub const fn appended_blocks(&self) -> u32 {
        self.appended_blocks
    }

    /// Number of orphaned blocks removed before appending replacements.
    #[must_use]
    pub const fn rolled_back_blocks(&self) -> u32 {
        self.rolled_back_blocks
    }
}

/// Trusted observer composition root. Raw inventory writer authority never
/// leaves this value or appears in the public API.
#[derive(Debug, Clone)]
pub struct Testnet4FinalizedInventoryObserver {
    inventory: SqliteFinalizedBitcoinInventory,
    freshness: ObservationFreshness,
    sync_lock: Arc<Mutex<()>>,
    custody_script_pubkey: ScriptBuf,
    required_confirmations: u32,
    start_height: u32,
    source_set_id: [u8; 32],
    sources: Vec<EsploraSourceClient>,
}

impl Testnet4FinalizedInventoryObserver {
    /// Authenticate every configured source against the exact Testnet4 genesis
    /// bytes, then open the source-set-pinned secure inventory file.
    ///
    /// # Errors
    /// Source authentication, secure file, durable configuration, or transport
    /// failure. No signer key, Vultisig share, transaction, or broadcast is used.
    pub async fn open(config: Testnet4ObserverConfig) -> Result<Self, ObserverError> {
        let client = async_client(HttpClientPolicy {
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(20),
            max_response_bytes: MAX_RAW_BLOCK_BYTES,
        })
        .map_err(|_| ObserverError::Transport("client_build"))?;
        let sources = config
            .sources
            .iter()
            .map(|source| EsploraSourceClient {
                source: source.clone(),
                client: client.clone(),
            })
            .collect::<Vec<_>>();
        authenticate_testnet4_sources(&sources).await?;
        let freshness = ObservationFreshness::enforced();
        let inventory = SqliteFinalizedBitcoinInventory::connect_secure(
            &config.database_path,
            freshness.clone(),
            &config.inventory_id,
            config.source_set_id,
            config.custody_script_pubkey.clone(),
            config.required_confirmations,
        )
        .await?;
        Ok(Self {
            inventory,
            freshness,
            sync_lock: Arc::new(Mutex::new(())),
            custody_script_pubkey: config.custody_script_pubkey,
            required_confirmations: config.required_confirmations,
            start_height: config.start_height,
            source_set_id: config.source_set_id,
            sources,
        })
    }

    /// Obtain the source-set-pinned, read-only policy capability issuer.
    #[must_use]
    pub fn policy_source(&self) -> FinalizedBitcoinPolicySource {
        self.inventory.policy_source()
    }

    /// Exact authenticated endpoint-set identity persisted by the inventory.
    #[must_use]
    pub const fn source_set_id(&self) -> [u8; 32] {
        self.source_set_id
    }

    /// Observe one exact transaction only after every configured source agrees
    /// on its canonical block and a current source-set-pinned inventory remains
    /// caught up through the same corroborated tip.
    ///
    /// This method accepts only a transaction ID. Block location, raw bytes,
    /// witness ID, confirmation count, source identities, and all evidence are
    /// derived locally while holding the observer synchronization lock. The
    /// source status and tip/checkpoint are sampled twice around raw-block
    /// corroboration and durable-inventory checks.
    ///
    /// # Errors
    /// Fails closed for an unconfirmed or under-confirmed transaction, source
    /// disagreement, a stale/mismatched retained inventory, malformed or
    /// oversized responses, a missing/duplicate transaction, or any change
    /// between the two samples.
    pub async fn observe_finalized_transaction(
        &self,
        txid: Txid,
    ) -> Result<FinalizedBitcoinTransactionObservation, ObserverError> {
        let _sync_guard = self.sync_lock.lock().await;
        self.freshness.invalidate()?;

        let first_status = self.corroborated_transaction_status(txid).await?;
        let TransactionStatus::Confirmed {
            block_height,
            block_hash,
        } = first_status.status
        else {
            return Err(ObserverError::TransactionUnconfirmed(txid));
        };
        let first_tip = self.corroborated_source_tip().await?;
        let confirmations = confirmation_count(first_tip, block_height, txid)?;
        if confirmations < self.required_confirmations {
            return Err(ObserverError::InsufficientConfirmations {
                txid,
                observed: confirmations,
                required: self.required_confirmations,
            });
        }

        let observed_block = self.corroborated_block(block_height).await?;
        let exact_transaction =
            derive_exact_transaction(&observed_block.block, txid, block_height, block_hash)?;

        let first_tip_checkpoint = self.corroborated_checkpoint(first_tip).await?;
        self.verify_retained_snapshot(
            block_height,
            block_hash,
            first_tip,
            first_tip_checkpoint.block_hash,
        )
        .await?;

        let second_status = self.corroborated_transaction_status(txid).await?;
        if second_status.status != first_status.status {
            return Err(ObserverError::SourceDisagreement(format!(
                "transaction {txid} status changed during finality observation"
            )));
        }
        let second_tip = self.corroborated_source_tip().await?;
        if second_tip != first_tip {
            return Err(ObserverError::SourceDisagreement(format!(
                "Testnet4 tip changed from {first_tip} to {second_tip} during finality observation"
            )));
        }
        let second_tip_checkpoint = self.corroborated_checkpoint(second_tip).await?;
        if second_tip_checkpoint.block_hash != first_tip_checkpoint.block_hash {
            return Err(ObserverError::SourceDisagreement(format!(
                "Testnet4 checkpoint at height {second_tip} changed during finality observation"
            )));
        }
        self.verify_retained_snapshot(
            block_height,
            block_hash,
            second_tip,
            second_tip_checkpoint.block_hash,
        )
        .await?;

        let evidence_hash = compute_final_transaction_observation_hash(
            self.source_set_id,
            txid,
            exact_transaction.wtxid,
            exact_transaction.sha256,
            block_height,
            block_hash,
            first_tip,
            first_tip_checkpoint.block_hash,
            confirmations,
            self.required_confirmations,
            observed_block.observation_evidence_hash,
            first_status.evidence_hash,
            second_status.evidence_hash,
            first_tip_checkpoint.evidence_hash,
            second_tip_checkpoint.evidence_hash,
        );
        self.freshness.refresh(POLICY_OBSERVATION_LEASE)?;

        Ok(FinalizedBitcoinTransactionObservation {
            chain_hash: ChainHash::TESTNET4,
            txid,
            wtxid: exact_transaction.wtxid,
            exact_transaction_sha256: exact_transaction.sha256,
            block_hash,
            block_height,
            corroborated_tip: first_tip,
            confirmations,
            required_confirmations: self.required_confirmations,
            source_set_id: self.source_set_id,
            evidence_hash,
        })
    }

    /// Corroborate and commit at most 64 blocks, handling only reorgs whose
    /// common ancestor remains inside the retained journal.
    ///
    /// Every source must report the same tip height and every committed block
    /// must match byte-for-byte across all sources. The tip is sampled again
    /// after the bounded block batch; policy freshness is granted only when the
    /// retained checkpoint reaches that second corroborated sample. A source
    /// lagging behind the retained tip causes a no-op rather than an inferred
    /// rollback.
    ///
    /// # Errors
    /// Source disagreement, malformed block data, a reorg deeper than the
    /// retained checkpoint, or durable inventory failure.
    pub async fn sync_once(&self) -> Result<ObserverSyncReport, ObserverError> {
        let _sync_guard = self.sync_lock.lock().await;
        self.freshness.invalidate()?;
        let source_tip = self.corroborated_source_tip().await?;
        let mut latest = self.inventory.latest_checkpoint().await?;
        let mut rolled_back_blocks = 0u32;

        if let Some((retained_height, retained_hash)) = latest {
            let retained_height_u32 = u32::try_from(retained_height).map_err(|_| {
                ObserverError::Inventory(InventoryError::Database(
                    "retained Bitcoin height exceeds u32".to_string(),
                ))
            })?;
            if source_tip < retained_height_u32 {
                return self
                    .complete_sync(ObserverSyncReport {
                        source_tip,
                        retained_tip: Some(retained_height_u32),
                        appended_blocks: 0,
                        rolled_back_blocks: 0,
                    })
                    .await;
            }
            let observed = self.corroborated_block(retained_height_u32).await?;
            if observed.block.block_hash() != retained_hash {
                let first = self.inventory.first_checkpoint().await?.ok_or_else(|| {
                    ObserverError::Inventory(InventoryError::Database(
                        "inventory tip exists without a first checkpoint".to_string(),
                    ))
                })?;
                let first_height = u32::try_from(first.0).map_err(|_| {
                    ObserverError::Inventory(InventoryError::Database(
                        "first Bitcoin height exceeds u32".to_string(),
                    ))
                })?;
                let mut candidate = retained_height_u32;
                let common = loop {
                    let canonical = self.inventory.canonical_hash(u64::from(candidate)).await?;
                    let observed = self.corroborated_block(candidate).await?;
                    if canonical == Some(observed.block.block_hash()) {
                        break Some((candidate, observed.block.block_hash()));
                    }
                    if candidate == first_height {
                        break None;
                    }
                    candidate = candidate.saturating_sub(1);
                };
                let Some((ancestor_height, ancestor_hash)) = common else {
                    return Err(ObserverError::ReorgBeyondCheckpoint);
                };
                self.inventory
                    .rollback_to(u64::from(ancestor_height), ancestor_hash)
                    .await?;
                rolled_back_blocks = retained_height_u32.saturating_sub(ancestor_height);
                latest = Some((u64::from(ancestor_height), ancestor_hash));
            }
        }

        let next_height = match latest {
            Some((height, _)) => u32::try_from(height)
                .map_err(|_| {
                    ObserverError::Inventory(InventoryError::Database(
                        "retained Bitcoin height exceeds u32".to_string(),
                    ))
                })?
                .checked_add(1)
                .ok_or_else(|| ObserverError::Decode("Bitcoin height overflow".to_string()))?,
            None => self.start_height,
        };
        if next_height > source_tip {
            return self
                .complete_sync(ObserverSyncReport {
                    source_tip,
                    retained_tip: latest.and_then(|(height, _)| u32::try_from(height).ok()),
                    appended_blocks: 0,
                    rolled_back_blocks,
                })
                .await;
        }
        let last_height = source_tip.min(
            next_height
                .saturating_add(MAX_BLOCKS_PER_SYNC)
                .saturating_sub(1),
        );
        let mut appended_blocks = 0u32;
        for height in next_height..=last_height {
            let observed = self.corroborated_block(height).await?;
            self.commit_observed_block(height, observed).await?;
            appended_blocks = appended_blocks.saturating_add(1);
        }
        self.complete_sync(ObserverSyncReport {
            source_tip,
            retained_tip: Some(last_height),
            appended_blocks,
            rolled_back_blocks,
        })
        .await
    }

    async fn complete_sync(
        &self,
        mut report: ObserverSyncReport,
    ) -> Result<ObserverSyncReport, ObserverError> {
        report.source_tip = self.corroborated_source_tip().await?;
        if report.retained_tip == Some(report.source_tip) {
            self.freshness.refresh(POLICY_OBSERVATION_LEASE)?;
        }
        Ok(report)
    }

    async fn corroborated_source_tip(&self) -> Result<u32, ObserverError> {
        let mut corroborated = None;
        for source in &self.sources {
            let height = source.fetch_tip_height().await?;
            if corroborated.is_some_and(|expected| expected != height) {
                return Err(ObserverError::SourceDisagreement(
                    "approved sources disagree on the current Testnet4 tip height".to_string(),
                ));
            }
            corroborated = Some(height);
        }
        corroborated
            .ok_or_else(|| ObserverError::Config("observer source set is empty".to_string()))
    }

    async fn corroborated_transaction_status(
        &self,
        txid: Txid,
    ) -> Result<CorroboratedTransactionStatus, ObserverError> {
        let mut evidence = Vec::with_capacity(self.sources.len());
        for source in &self.sources {
            evidence.push(source.fetch_transaction_status(txid).await?);
        }
        let first = evidence
            .first()
            .ok_or_else(|| ObserverError::Config("observer source set is empty".to_string()))?;
        if evidence
            .iter()
            .skip(1)
            .any(|candidate| candidate.status != first.status)
        {
            return Err(ObserverError::SourceDisagreement(format!(
                "approved sources disagree on transaction {txid} confirmation status"
            )));
        }
        Ok(CorroboratedTransactionStatus {
            status: first.status,
            evidence_hash: compute_transaction_status_sample_hash(
                self.source_set_id,
                txid,
                first.status,
                &evidence,
            ),
        })
    }

    async fn corroborated_checkpoint(
        &self,
        height: u32,
    ) -> Result<CorroboratedCheckpoint, ObserverError> {
        let mut evidence = Vec::with_capacity(self.sources.len());
        for source in &self.sources {
            let (block_hash, response_hash) = source.fetch_block_hash(height).await?;
            evidence.push(SourceCheckpointEvidence {
                source_id: source.source.source_id.clone(),
                response_hash,
                block_hash,
            });
        }
        let first = evidence
            .first()
            .ok_or_else(|| ObserverError::Config("observer source set is empty".to_string()))?;
        if evidence
            .iter()
            .skip(1)
            .any(|candidate| candidate.block_hash != first.block_hash)
        {
            return Err(ObserverError::SourceDisagreement(format!(
                "approved sources disagree on the canonical block at Testnet4 height {height}"
            )));
        }
        Ok(CorroboratedCheckpoint {
            block_hash: first.block_hash,
            evidence_hash: compute_checkpoint_sample_hash(
                self.source_set_id,
                height,
                first.block_hash,
                &evidence,
            ),
        })
    }

    async fn verify_retained_snapshot(
        &self,
        transaction_height: u32,
        transaction_block_hash: BlockHash,
        corroborated_tip: u32,
        corroborated_tip_hash: BlockHash,
    ) -> Result<(), ObserverError> {
        let canonical_transaction_hash = self
            .inventory
            .canonical_hash(u64::from(transaction_height))
            .await?;
        if canonical_transaction_hash != Some(transaction_block_hash) {
            return Err(ObserverError::Finality(format!(
                "retained inventory does not contain transaction block {transaction_block_hash} at height {transaction_height}"
            )));
        }
        let latest = self.inventory.latest_checkpoint().await?;
        if latest != Some((u64::from(corroborated_tip), corroborated_tip_hash)) {
            return Err(ObserverError::Finality(format!(
                "retained inventory is not caught up through corroborated Testnet4 tip {corroborated_tip}"
            )));
        }
        Ok(())
    }

    async fn corroborated_block(&self, height: u32) -> Result<CorroboratedBlock, ObserverError> {
        let mut evidence = Vec::with_capacity(self.sources.len());
        for source in &self.sources {
            evidence.push(source.fetch_block(height).await?);
        }
        let first = evidence
            .first()
            .ok_or_else(|| ObserverError::Config("observer source set is empty".to_string()))?;
        let canonical_bytes = serialize(&first.block);
        if evidence.iter().skip(1).any(|candidate| {
            candidate.block.block_hash() != first.block.block_hash()
                || serialize(&candidate.block) != canonical_bytes
        }) {
            return Err(ObserverError::SourceDisagreement(format!(
                "approved sources disagree at Testnet4 height {height}"
            )));
        }
        let observation_evidence_hash = compute_observation_evidence_hash(
            self.source_set_id,
            height,
            first.block.block_hash(),
            &evidence,
        );
        Ok(CorroboratedBlock {
            block: first.block.clone(),
            observation_evidence_hash,
        })
    }

    async fn commit_observed_block(
        &self,
        height: u32,
        observed: CorroboratedBlock,
    ) -> Result<(), ObserverError> {
        let (created_outputs, candidate_spends) =
            derive_observed_facts(&observed.block.txdata, &self.custody_script_pubkey)?;
        let mut spent_outpoints = self.inventory.retain_unspent(&candidate_spends).await?;
        let created_set = created_outputs
            .iter()
            .map(FinalizedBitcoinOutput::outpoint)
            .collect::<HashSet<_>>();
        spent_outpoints.extend(candidate_spends.intersection(&created_set).copied());
        let block = FinalizedBitcoinBlock::new_observed(
            u64::from(height),
            observed.block.block_hash(),
            observed.block.header.prev_blockhash,
            created_outputs,
            spent_outpoints.into_iter().collect(),
            observed.observation_evidence_hash,
        )?;
        self.inventory.commit_block(block).await?;
        Ok(())
    }
}

fn derive_observed_facts(
    transactions: &[Transaction],
    custody_script_pubkey: &Script,
) -> Result<(Vec<FinalizedBitcoinOutput>, HashSet<OutPoint>), ObserverError> {
    let mut created_outputs = Vec::new();
    let mut candidate_spends = HashSet::new();
    for transaction in transactions {
        // Xindex does not authorize mining rewards. Omitting coinbase outputs is
        // conservative and avoids issuing a six-confirmation capability for an
        // output that Bitcoin consensus keeps immature for 100 blocks.
        if transaction.is_coinbase() {
            continue;
        }
        let txid = transaction.compute_txid();
        for (vout, output) in transaction.output.iter().enumerate() {
            if output.script_pubkey.as_script() == custody_script_pubkey
                && output.value.to_sat() > 0
            {
                let vout = u32::try_from(vout).map_err(|_| {
                    ObserverError::Decode("transaction output index exceeds u32".to_string())
                })?;
                created_outputs.push(FinalizedBitcoinOutput::new(
                    OutPoint { txid, vout },
                    output.value.to_sat(),
                    output.script_pubkey.clone(),
                )?);
            }
        }
        candidate_spends.extend(
            transaction
                .input
                .iter()
                .map(|input| input.previous_output)
                .filter(|outpoint| !outpoint.is_null()),
        );
    }
    Ok((created_outputs, candidate_spends))
}

/// Fail-closed trusted-observer error.
#[derive(Debug, Error)]
pub enum ObserverError {
    /// Static trusted-observer configuration is unsafe.
    #[error("observer configuration error: {0}")]
    Config(String),
    /// Network transport failed without disclosing endpoint credentials.
    #[error("observer transport failed: {0}")]
    Transport(&'static str),
    /// One approved source returned a non-success status.
    #[error("observer source {source_id} returned HTTP {status}")]
    Http { source_id: String, status: u16 },
    /// One response exceeded the bounded parser limit.
    #[error("observer response exceeded {0} bytes")]
    ResponseTooLarge(usize),
    /// One source response or block failed exact decoding/validation.
    #[error("observer decode error: {0}")]
    Decode(String),
    /// Approved sources returned different canonical data.
    #[error("observer source disagreement: {0}")]
    SourceDisagreement(String),
    /// Every source agreed that the requested transaction is not confirmed.
    #[error("Bitcoin transaction {0} is not confirmed by the approved source set")]
    TransactionUnconfirmed(Txid),
    /// The corroborated transaction has not reached the configured floor.
    #[error("Bitcoin transaction {txid} has {observed} confirmations, requires {required}")]
    InsufficientConfirmations {
        /// Requested transaction.
        txid: Txid,
        /// Inclusive confirmations at the corroborated tip.
        observed: u32,
        /// Source-set-pinned inventory floor.
        required: u32,
    },
    /// Finality evidence could not be bound to the retained canonical snapshot.
    #[error("Bitcoin finality observation failed: {0}")]
    Finality(String),
    /// A reorg did not retain any locally journaled common ancestor.
    #[error("Bitcoin reorg extends below the trusted inventory checkpoint")]
    ReorgBeyondCheckpoint,
    /// Durable finalized-inventory failure.
    #[error(transparent)]
    Inventory(#[from] InventoryError),
}

#[derive(Debug, Clone)]
struct EsploraSourceClient {
    source: Testnet4EsploraSource,
    client: Client,
}

impl EsploraSourceClient {
    async fn fetch_tip_height(&self) -> Result<u32, ObserverError> {
        let bytes = self
            .get_bounded("blocks/tip/height", MAX_TEXT_RESPONSE_BYTES)
            .await?;
        parse_u32_text(&bytes, "tip height")
    }

    async fn fetch_block_hash(&self, height: u32) -> Result<(BlockHash, [u8; 32]), ObserverError> {
        let bytes = self
            .get_bounded(&format!("block-height/{height}"), MAX_TEXT_RESPONSE_BYTES)
            .await?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ObserverError::Decode("block hash response is not UTF-8".to_string()))?;
        let hash = BlockHash::from_str(text.trim())
            .map_err(|_| ObserverError::Decode("block hash response is invalid".to_string()))?;
        Ok((hash, sha256::Hash::hash(&bytes).to_byte_array()))
    }

    async fn fetch_block(&self, height: u32) -> Result<SourceBlockEvidence, ObserverError> {
        let (expected_hash, height_response_hash) = self.fetch_block_hash(height).await?;
        let raw_bytes = self
            .get_bounded(&format!("block/{expected_hash}/raw"), MAX_RAW_BLOCK_BYTES)
            .await?;
        let block: Block = deserialize(&raw_bytes)
            .map_err(|error| ObserverError::Decode(format!("raw block encoding: {error}")))?;
        if serialize(&block) != raw_bytes {
            return Err(ObserverError::Decode(
                "raw block is not one canonical consensus encoding".to_string(),
            ));
        }
        validate_block(height, expected_hash, &block)?;
        Ok(SourceBlockEvidence {
            source_id: self.source.source_id.clone(),
            height_response_hash,
            raw_response_hash: sha256::Hash::hash(&raw_bytes).to_byte_array(),
            block,
        })
    }

    async fn fetch_transaction_status(
        &self,
        txid: Txid,
    ) -> Result<SourceTransactionStatusEvidence, ObserverError> {
        let bytes = self
            .get_bounded(&format!("tx/{txid}/status"), MAX_TRANSACTION_STATUS_BYTES)
            .await?;
        let status = parse_transaction_status(&bytes)?;
        Ok(SourceTransactionStatusEvidence {
            source_id: self.source.source_id.clone(),
            response_hash: sha256::Hash::hash(&bytes).to_byte_array(),
            status,
        })
    }

    async fn get_bounded(
        &self,
        relative_path: &str,
        limit: usize,
    ) -> Result<Vec<u8>, ObserverError> {
        let url = self
            .source
            .base_url
            .join(relative_path)
            .map_err(|_| ObserverError::Config("source URL path is invalid".to_string()))?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| ObserverError::Transport(transport_class(&error)))?;
        let status = response.status();
        if !status.is_success() {
            return Err(ObserverError::Http {
                source_id: self.source.source_id.clone(),
                status: status.as_u16(),
            });
        }
        read_bounded_async(response, limit)
            .await
            .map_err(|error| match error {
                NetworkError::ResponseTooLarge { .. } => ObserverError::ResponseTooLarge(limit),
                _ => ObserverError::Transport("response_body"),
            })
    }
}

#[derive(Debug, Clone)]
struct SourceBlockEvidence {
    source_id: String,
    height_response_hash: [u8; 32],
    raw_response_hash: [u8; 32],
    block: Block,
}

#[derive(Debug, Clone)]
struct CorroboratedBlock {
    block: Block,
    observation_evidence_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
struct ExactObservedTransaction {
    wtxid: Wtxid,
    sha256: [u8; 32],
}

fn derive_exact_transaction(
    block: &Block,
    txid: Txid,
    block_height: u32,
    expected_block_hash: BlockHash,
) -> Result<ExactObservedTransaction, ObserverError> {
    if block.block_hash() != expected_block_hash {
        return Err(ObserverError::Finality(format!(
            "transaction {txid} status block hash does not match corroborated block at height {block_height}"
        )));
    }
    let mut matching = block
        .txdata
        .iter()
        .filter(|transaction| transaction.compute_txid() == txid);
    let transaction = matching.next().ok_or_else(|| {
        ObserverError::Finality(format!(
            "transaction {txid} is absent from its corroborated status block"
        ))
    })?;
    if matching.next().is_some() {
        return Err(ObserverError::Finality(format!(
            "transaction {txid} appears more than once in its corroborated status block"
        )));
    }
    if transaction.compute_txid() != txid {
        return Err(ObserverError::Finality(
            "locally derived transaction ID changed during observation".to_string(),
        ));
    }
    Ok(ExactObservedTransaction {
        wtxid: transaction.compute_wtxid(),
        sha256: sha256::Hash::hash(&serialize(transaction)).to_byte_array(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionStatus {
    Unconfirmed,
    Confirmed {
        block_height: u32,
        block_hash: BlockHash,
    },
}

#[derive(Debug, Clone)]
struct SourceTransactionStatusEvidence {
    source_id: String,
    response_hash: [u8; 32],
    status: TransactionStatus,
}

#[derive(Debug, Clone, Copy)]
struct CorroboratedTransactionStatus {
    status: TransactionStatus,
    evidence_hash: [u8; 32],
}

#[derive(Debug, Clone)]
struct SourceCheckpointEvidence {
    source_id: String,
    response_hash: [u8; 32],
    block_hash: BlockHash,
}

#[derive(Debug, Clone, Copy)]
struct CorroboratedCheckpoint {
    block_hash: BlockHash,
    evidence_hash: [u8; 32],
}

async fn authenticate_testnet4_sources(
    sources: &[EsploraSourceClient],
) -> Result<(), ObserverError> {
    let expected = genesis_block(Network::Testnet4);
    let expected_bytes = serialize(&expected);
    for source in sources {
        let observed = source.fetch_block(0).await?;
        if observed.block.block_hash() != expected.block_hash()
            || serialize(&observed.block) != expected_bytes
            || ChainHash::from_genesis_block_hash(observed.block.block_hash())
                != ChainHash::TESTNET4
        {
            return Err(ObserverError::Decode(format!(
                "source {} did not authenticate the exact Bitcoin Testnet4 genesis block",
                source.source.source_id
            )));
        }
    }
    Ok(())
}

fn validate_block(
    height: u32,
    expected_hash: BlockHash,
    block: &Block,
) -> Result<(), ObserverError> {
    if block.block_hash() != expected_hash {
        return Err(ObserverError::Decode(format!(
            "raw block hash does not match height {height} response"
        )));
    }
    let target = block.header.target();
    if target > Params::TESTNET4.max_attainable_target || block.header.validate_pow(target).is_err()
    {
        return Err(ObserverError::Decode(format!(
            "block {height} fails Testnet4 proof-of-work bounds"
        )));
    }
    if !block.check_merkle_root() || !block.check_witness_commitment() {
        return Err(ObserverError::Decode(format!(
            "block {height} fails transaction commitment validation"
        )));
    }
    if block.weight().to_wu() > MAX_BLOCK_WEIGHT {
        return Err(ObserverError::Decode(format!(
            "block {height} exceeds the consensus weight limit"
        )));
    }
    if height == 0 {
        if block.header.prev_blockhash != BlockHash::all_zeros() {
            return Err(ObserverError::Decode(
                "genesis block has a non-zero parent".to_string(),
            ));
        }
    } else {
        let encoded_height = block.bip34_block_height().map_err(|error| {
            ObserverError::Decode(format!("block {height} BIP34 height: {error}"))
        })?;
        if encoded_height != u64::from(height) {
            return Err(ObserverError::Decode(format!(
                "block encoded height {encoded_height} does not equal requested {height}"
            )));
        }
    }
    Ok(())
}

fn parse_u32_text(bytes: &[u8], label: &str) -> Result<u32, ObserverError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ObserverError::Decode(format!("{label} response is not UTF-8")))?;
    let trimmed = text.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ObserverError::Decode(format!(
            "{label} response is not a decimal integer"
        )));
    }
    trimmed
        .parse::<u32>()
        .map_err(|error| ObserverError::Decode(format!("{label}: {error}")))
}

fn parse_transaction_status(bytes: &[u8]) -> Result<TransactionStatus, ObserverError> {
    let mut parser = StatusJsonParser::new(bytes);
    parser.expect_byte(b'{', "transaction status must be a JSON object")?;
    let mut confirmed = None;
    let mut block_height = None;
    let mut block_height_seen = false;
    let mut block_hash = None;
    let mut block_hash_seen = false;
    let mut block_time_seen = false;

    if !parser.consume_byte(b'}') {
        loop {
            let key = parser.parse_string("transaction status field name")?;
            parser.expect_byte(b':', "transaction status field requires ':'")?;
            match key {
                "confirmed" => {
                    if confirmed.is_some() {
                        return Err(ObserverError::Decode(
                            "transaction status repeats confirmed".to_string(),
                        ));
                    }
                    confirmed = Some(parser.parse_bool("confirmed")?);
                }
                "block_height" => {
                    if block_height_seen {
                        return Err(ObserverError::Decode(
                            "transaction status repeats block_height".to_string(),
                        ));
                    }
                    block_height_seen = true;
                    block_height = parser.parse_optional_u32("block_height")?;
                }
                "block_hash" => {
                    if block_hash_seen {
                        return Err(ObserverError::Decode(
                            "transaction status repeats block_hash".to_string(),
                        ));
                    }
                    block_hash_seen = true;
                    block_hash = parser.parse_optional_block_hash()?;
                }
                "block_time" => {
                    if block_time_seen {
                        return Err(ObserverError::Decode(
                            "transaction status repeats block_time".to_string(),
                        ));
                    }
                    block_time_seen = true;
                    let _ = parser.parse_optional_u64("block_time")?;
                }
                _ => {
                    return Err(ObserverError::Decode(format!(
                        "transaction status contains unsupported field {key}"
                    )));
                }
            }
            if parser.consume_byte(b'}') {
                break;
            }
            parser.expect_byte(b',', "transaction status fields require ','")?;
        }
    }
    parser.finish()?;

    match confirmed {
        Some(true) => Ok(TransactionStatus::Confirmed {
            block_height: block_height.ok_or_else(|| {
                ObserverError::Decode("confirmed transaction status omits block_height".to_string())
            })?,
            block_hash: block_hash.ok_or_else(|| {
                ObserverError::Decode("confirmed transaction status omits block_hash".to_string())
            })?,
        }),
        Some(false) => {
            if block_height.is_some() || block_hash.is_some() {
                return Err(ObserverError::Decode(
                    "unconfirmed transaction status supplies a canonical block".to_string(),
                ));
            }
            Ok(TransactionStatus::Unconfirmed)
        }
        None => Err(ObserverError::Decode(
            "transaction status omits confirmed".to_string(),
        )),
    }
}

struct StatusJsonParser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> StatusJsonParser<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn finish(&mut self) -> Result<(), ObserverError> {
        self.skip_whitespace();
        if self.position != self.bytes.len() {
            return Err(ObserverError::Decode(
                "transaction status has trailing JSON data".to_string(),
            ));
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.position = self.position.saturating_add(1);
        }
    }

    fn consume_byte(&mut self, expected: u8) -> bool {
        self.skip_whitespace();
        if self.bytes.get(self.position) == Some(&expected) {
            self.position = self.position.saturating_add(1);
            true
        } else {
            false
        }
    }

    fn expect_byte(&mut self, expected: u8, message: &str) -> Result<(), ObserverError> {
        if self.consume_byte(expected) {
            Ok(())
        } else {
            Err(ObserverError::Decode(message.to_string()))
        }
    }

    fn parse_string(&mut self, label: &str) -> Result<&'a str, ObserverError> {
        self.skip_whitespace();
        if self.bytes.get(self.position) != Some(&b'"') {
            return Err(ObserverError::Decode(format!(
                "{label} must be a JSON string"
            )));
        }
        self.position = self.position.saturating_add(1);
        let start = self.position;
        while let Some(byte) = self.bytes.get(self.position).copied() {
            match byte {
                b'"' => {
                    let value = std::str::from_utf8(&self.bytes[start..self.position])
                        .map_err(|_| ObserverError::Decode(format!("{label} is not UTF-8")))?;
                    self.position = self.position.saturating_add(1);
                    return Ok(value);
                }
                b'\\' => {
                    return Err(ObserverError::Decode(format!(
                        "{label} must not use JSON escapes"
                    )));
                }
                0x00..=0x1f => {
                    return Err(ObserverError::Decode(format!(
                        "{label} contains a JSON control byte"
                    )));
                }
                _ => self.position = self.position.saturating_add(1),
            }
        }
        Err(ObserverError::Decode(format!("{label} is not terminated")))
    }

    fn parse_bool(&mut self, label: &str) -> Result<bool, ObserverError> {
        self.skip_whitespace();
        let remaining = &self.bytes[self.position..];
        if remaining.starts_with(b"true") {
            self.position = self.position.saturating_add(4);
            Ok(true)
        } else if remaining.starts_with(b"false") {
            self.position = self.position.saturating_add(5);
            Ok(false)
        } else {
            Err(ObserverError::Decode(format!(
                "{label} must be a JSON boolean"
            )))
        }
    }

    fn parse_optional_u32(&mut self, label: &str) -> Result<Option<u32>, ObserverError> {
        self.parse_optional_u64(label)?
            .map(|value| {
                u32::try_from(value)
                    .map_err(|_| ObserverError::Decode(format!("{label} exceeds the u32 range")))
            })
            .transpose()
    }

    fn parse_optional_u64(&mut self, label: &str) -> Result<Option<u64>, ObserverError> {
        self.skip_whitespace();
        if self.bytes[self.position..].starts_with(b"null") {
            self.position = self.position.saturating_add(4);
            return Ok(None);
        }
        let start = self.position;
        while self
            .bytes
            .get(self.position)
            .is_some_and(u8::is_ascii_digit)
        {
            self.position = self.position.saturating_add(1);
        }
        if start == self.position {
            return Err(ObserverError::Decode(format!(
                "{label} must be a non-negative JSON integer or null"
            )));
        }
        if self.position.saturating_sub(start) > 1 && self.bytes[start] == b'0' {
            return Err(ObserverError::Decode(format!(
                "{label} has a non-canonical leading zero"
            )));
        }
        let text = std::str::from_utf8(&self.bytes[start..self.position])
            .map_err(|_| ObserverError::Decode(format!("{label} is not UTF-8")))?;
        text.parse::<u64>()
            .map(Some)
            .map_err(|error| ObserverError::Decode(format!("{label}: {error}")))
    }

    fn parse_optional_block_hash(&mut self) -> Result<Option<BlockHash>, ObserverError> {
        self.skip_whitespace();
        if self.bytes[self.position..].starts_with(b"null") {
            self.position = self.position.saturating_add(4);
            return Ok(None);
        }
        let text = self.parse_string("block_hash")?;
        BlockHash::from_str(text)
            .map(Some)
            .map_err(|_| ObserverError::Decode("block_hash is invalid".to_string()))
    }
}

fn confirmation_count(tip: u32, block_height: u32, txid: Txid) -> Result<u32, ObserverError> {
    tip.checked_sub(block_height)
        .and_then(|depth| depth.checked_add(1))
        .ok_or_else(|| {
            ObserverError::Finality(format!(
                "transaction {txid} block height {block_height} is above corroborated tip {tip}"
            ))
        })
}

fn compute_source_set_id(sources: &[Testnet4EsploraSource]) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, SOURCE_SET_DOMAIN);
    bytes.extend_from_slice(ChainHash::TESTNET4.as_bytes());
    bytes.extend_from_slice(&(sources.len() as u64).to_be_bytes());
    for source in sources {
        push_bytes(&mut bytes, source.source_id.as_bytes());
        push_bytes(&mut bytes, source.base_url.as_str().as_bytes());
    }
    sha256::Hash::hash(&bytes).to_byte_array()
}

fn compute_observation_evidence_hash(
    source_set_id: [u8; 32],
    height: u32,
    block_hash: BlockHash,
    evidence: &[SourceBlockEvidence],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, OBSERVATION_DOMAIN);
    bytes.extend_from_slice(&source_set_id);
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(block_hash.as_byte_array());
    bytes.extend_from_slice(&(evidence.len() as u64).to_be_bytes());
    for source in evidence {
        push_bytes(&mut bytes, source.source_id.as_bytes());
        bytes.extend_from_slice(&source.height_response_hash);
        bytes.extend_from_slice(&source.raw_response_hash);
    }
    sha256::Hash::hash(&bytes).to_byte_array()
}

fn compute_transaction_status_sample_hash(
    source_set_id: [u8; 32],
    txid: Txid,
    status: TransactionStatus,
    evidence: &[SourceTransactionStatusEvidence],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, TRANSACTION_STATUS_SAMPLE_DOMAIN);
    bytes.extend_from_slice(ChainHash::TESTNET4.as_bytes());
    bytes.extend_from_slice(&source_set_id);
    bytes.extend_from_slice(txid.as_byte_array());
    match status {
        TransactionStatus::Unconfirmed => bytes.push(0),
        TransactionStatus::Confirmed {
            block_height,
            block_hash,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&block_height.to_be_bytes());
            bytes.extend_from_slice(block_hash.as_byte_array());
        }
    }
    bytes.extend_from_slice(&(evidence.len() as u64).to_be_bytes());
    for source in evidence {
        push_bytes(&mut bytes, source.source_id.as_bytes());
        bytes.extend_from_slice(&source.response_hash);
    }
    sha256::Hash::hash(&bytes).to_byte_array()
}

fn compute_checkpoint_sample_hash(
    source_set_id: [u8; 32],
    height: u32,
    block_hash: BlockHash,
    evidence: &[SourceCheckpointEvidence],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, CHECKPOINT_SAMPLE_DOMAIN);
    bytes.extend_from_slice(ChainHash::TESTNET4.as_bytes());
    bytes.extend_from_slice(&source_set_id);
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(block_hash.as_byte_array());
    bytes.extend_from_slice(&(evidence.len() as u64).to_be_bytes());
    for source in evidence {
        push_bytes(&mut bytes, source.source_id.as_bytes());
        bytes.extend_from_slice(&source.response_hash);
    }
    sha256::Hash::hash(&bytes).to_byte_array()
}

#[expect(
    clippy::too_many_arguments,
    reason = "the final observation commitment intentionally enumerates every authoritative field"
)]
fn compute_final_transaction_observation_hash(
    source_set_id: [u8; 32],
    txid: Txid,
    wtxid: Wtxid,
    exact_transaction_sha256: [u8; 32],
    block_height: u32,
    block_hash: BlockHash,
    corroborated_tip: u32,
    corroborated_tip_hash: BlockHash,
    confirmations: u32,
    required_confirmations: u32,
    block_evidence_hash: [u8; 32],
    first_status_evidence_hash: [u8; 32],
    second_status_evidence_hash: [u8; 32],
    first_tip_evidence_hash: [u8; 32],
    second_tip_evidence_hash: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, FINAL_TRANSACTION_OBSERVATION_DOMAIN);
    bytes.extend_from_slice(ChainHash::TESTNET4.as_bytes());
    bytes.extend_from_slice(&source_set_id);
    bytes.extend_from_slice(txid.as_byte_array());
    bytes.extend_from_slice(wtxid.as_byte_array());
    bytes.extend_from_slice(&exact_transaction_sha256);
    bytes.extend_from_slice(&block_height.to_be_bytes());
    bytes.extend_from_slice(block_hash.as_byte_array());
    bytes.extend_from_slice(&corroborated_tip.to_be_bytes());
    bytes.extend_from_slice(corroborated_tip_hash.as_byte_array());
    bytes.extend_from_slice(&confirmations.to_be_bytes());
    bytes.extend_from_slice(&required_confirmations.to_be_bytes());
    bytes.extend_from_slice(&block_evidence_hash);
    bytes.extend_from_slice(&first_status_evidence_hash);
    bytes.extend_from_slice(&second_status_evidence_hash);
    bytes.extend_from_slice(&first_tip_evidence_hash);
    bytes.extend_from_slice(&second_tip_evidence_hash);
    sha256::Hash::hash(&bytes).to_byte_array()
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
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

#[cfg(all(test, unix))]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]

    use std::os::unix::fs::{symlink, PermissionsExt};

    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash as _;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, Sequence, TxIn, TxOut, Txid, WPubkeyHash, Witness};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::finalized_inventory::prepare_secure_sqlite_file;

    fn custody_script() -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0xcc; 20]))
    }

    fn private_test_directory(name: &str) -> PathBuf {
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("canonical temporary directory")
            .join(format!(
                "xindex-testnet4-observer-{name}-{}",
                std::process::id()
            ));
        if root.exists() {
            std::fs::remove_dir_all(&root).expect("remove stale observer fixture");
        }
        std::fs::create_dir(&root).expect("create observer fixture");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private observer fixture");
        root
    }

    async fn mount_genesis(server: &MockServer, tip: u32) {
        let genesis = genesis_block(Network::Testnet4);
        let hash = genesis.block_hash().to_string();
        Mock::given(method("GET"))
            .and(path("/block-height/0"))
            .respond_with(ResponseTemplate::new(200).set_body_string(hash.clone()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/block/{hash}/raw")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(serialize(&genesis)))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/blocks/tip/height"))
            .respond_with(ResponseTemplate::new(200).set_body_string(tip.to_string()))
            .mount(server)
            .await;
    }

    async fn mount_checkpoint(server: &MockServer, height: u32, block_hash: BlockHash) {
        Mock::given(method("GET"))
            .and(path(format!("/block-height/{height}")))
            .respond_with(ResponseTemplate::new(200).set_body_string(block_hash.to_string()))
            .mount(server)
            .await;
    }

    async fn mount_status(server: &MockServer, txid: Txid, body: impl Into<Vec<u8>>) {
        Mock::given(method("GET"))
            .and(path(format!("/tx/{txid}/status")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(server)
            .await;
    }

    async fn mount_status_sequence(
        server: &MockServer,
        txid: Txid,
        first: impl Into<Vec<u8>>,
        second: impl Into<Vec<u8>>,
    ) {
        Mock::given(method("GET"))
            .and(path(format!("/tx/{txid}/status")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(first))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/tx/{txid}/status")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(second))
            .with_priority(2)
            .mount(server)
            .await;
    }

    fn confirmed_status(block_height: u32, block_hash: BlockHash) -> String {
        format!(
            "{{\"confirmed\":true,\"block_height\":{block_height},\"block_hash\":\"{block_hash}\",\"block_time\":1}}"
        )
    }

    async fn seed_inventory_through(
        observer: &Testnet4FinalizedInventoryObserver,
        tip: u32,
    ) -> BlockHash {
        let mut parent = BlockHash::all_zeros();
        for height in 0..=tip {
            let block_hash = if height == 0 {
                genesis_block(Network::Testnet4).block_hash()
            } else {
                BlockHash::from_byte_array([u8::try_from(height).expect("small test height"); 32])
            };
            let block = FinalizedBitcoinBlock::new(
                u64::from(height),
                block_hash,
                parent,
                Vec::new(),
                Vec::new(),
            )
            .expect("synthetic inventory checkpoint");
            observer
                .inventory
                .commit_block(block)
                .await
                .expect("seed retained checkpoint");
            parent = block_hash;
        }
        parent
    }

    struct FinalityFixture {
        observer: Testnet4FinalizedInventoryObserver,
        first: MockServer,
        second: MockServer,
        directory: PathBuf,
        transaction: Transaction,
    }

    impl FinalityFixture {
        fn cleanup(self) {
            let Self {
                observer,
                first,
                second,
                directory,
                transaction: _,
            } = self;
            drop(observer);
            drop(first);
            drop(second);
            std::fs::remove_dir_all(directory).expect("remove finality fixture");
        }
    }

    async fn finality_fixture(name: &str, tip: u32) -> FinalityFixture {
        let first = MockServer::start().await;
        let second = MockServer::start().await;
        mount_genesis(&first, tip).await;
        mount_genesis(&second, tip).await;
        let directory = private_test_directory(name);
        let database = directory.join("inventory.sqlite");
        let config = Testnet4ObserverConfig::new_for_test(
            name,
            &database,
            custody_script(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
            0,
            vec![("first", &first.uri()), ("second", &second.uri())],
        )
        .expect("finality test config");
        let observer = Testnet4FinalizedInventoryObserver::open(config)
            .await
            .expect("finality test observer");
        let tip_hash = seed_inventory_through(&observer, tip).await;
        if tip != 0 {
            mount_checkpoint(&first, tip, tip_hash).await;
            mount_checkpoint(&second, tip, tip_hash).await;
        }
        FinalityFixture {
            observer,
            first,
            second,
            directory,
            transaction: genesis_block(Network::Testnet4).txdata[0].clone(),
        }
    }

    #[test]
    fn production_source_configuration_requires_https_and_distinct_hosts() {
        let http = Testnet4EsploraSource::new("a", "http://observer-a.example/api");
        assert!(matches!(http, Err(ObserverError::Config(_))));

        let first =
            Testnet4EsploraSource::new("a", "https://observer.example/api").expect("first source");
        let second = Testnet4EsploraSource::new("b", "https://observer.example/other")
            .expect("second source");
        let error = Testnet4ObserverConfig::new(
            "test",
            "/tmp/inventory.sqlite",
            custody_script(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
            0,
            vec![first, second],
        )
        .expect_err("same authenticated host must not count twice");
        assert!(matches!(error, ObserverError::Config(_)));

        let first = Testnet4EsploraSource::new("a", "https://observer-a.example/api")
            .expect("first distinct source");
        let second = Testnet4EsploraSource::new("b", "https://observer-b.example/api")
            .expect("second distinct source");
        let error = Testnet4ObserverConfig::new(
            "test",
            "/tmp/inventory.sqlite",
            custody_script(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
            1,
            vec![first, second],
        )
        .expect_err("an operator height must not become a trusted chain checkpoint");
        assert!(matches!(error, ObserverError::Config(_)));
    }

    #[test]
    fn observer_derives_only_exact_custody_outputs_and_non_coinbase_spends() {
        let custody = custody_script();
        let spent = OutPoint {
            txid: Txid::from_byte_array([0x11; 32]),
            vout: 7,
        };
        let transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: spent,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(120_000),
                    script_pubkey: custody.clone(),
                },
                TxOut {
                    value: Amount::from_sat(80_000),
                    script_pubkey: ScriptBuf::new(),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: custody.clone(),
                },
            ],
        };

        let (created, candidates) =
            derive_observed_facts(std::slice::from_ref(&transaction), &custody)
                .expect("derived facts");
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].value_sats(), 120_000);
        assert_eq!(
            created[0].outpoint(),
            OutPoint {
                txid: transaction.compute_txid(),
                vout: 0,
            }
        );
        assert_eq!(candidates, HashSet::from([spent]));

        let coinbase = Transaction {
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                ..transaction.input[0].clone()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: custody.clone(),
            }],
            ..transaction
        };
        let (coinbase_created, coinbase_candidates) =
            derive_observed_facts(&[coinbase], &custody).expect("coinbase facts");
        assert!(
            coinbase_created.is_empty(),
            "six-confirmation policy must not expose 100-block-immature coinbase outputs"
        );
        assert!(coinbase_candidates.is_empty());
    }

    #[test]
    fn observation_evidence_commits_source_set_and_raw_responses() {
        let block = genesis_block(Network::Testnet4);
        let evidence = vec![
            SourceBlockEvidence {
                source_id: "first".to_string(),
                height_response_hash: [0x11; 32],
                raw_response_hash: [0x22; 32],
                block: block.clone(),
            },
            SourceBlockEvidence {
                source_id: "second".to_string(),
                height_response_hash: [0x33; 32],
                raw_response_hash: [0x44; 32],
                block: block.clone(),
            },
        ];
        let baseline =
            compute_observation_evidence_hash([0x55; 32], 0, block.block_hash(), &evidence);
        let changed_set =
            compute_observation_evidence_hash([0x56; 32], 0, block.block_hash(), &evidence);
        let mut changed_evidence = evidence;
        changed_evidence[1].raw_response_hash[0] ^= 0x01;
        let changed_raw =
            compute_observation_evidence_hash([0x55; 32], 0, block.block_hash(), &changed_evidence);
        assert_ne!(baseline, changed_set);
        assert_ne!(baseline, changed_raw);
    }

    #[test]
    fn policy_freshness_requires_refresh_and_detects_sync_generation_changes() {
        let freshness = ObservationFreshness::enforced();
        assert!(freshness.begin_check().is_err());
        freshness
            .refresh(Duration::from_secs(1))
            .expect("fresh observer lease");
        let generation = freshness.begin_check().expect("current observer lease");
        freshness
            .finish_check(generation)
            .expect("unchanged observer lease");
        freshness.invalidate().expect("invalidate observer lease");
        assert!(freshness.finish_check(generation).is_err());
        assert!(freshness.begin_check().is_err());
    }

    #[test]
    fn transaction_status_parser_is_strict_and_fail_closed() {
        let block_hash = genesis_block(Network::Testnet4).block_hash();
        assert_eq!(
            parse_transaction_status(confirmed_status(0, block_hash).as_bytes())
                .expect("valid confirmed status"),
            TransactionStatus::Confirmed {
                block_height: 0,
                block_hash,
            }
        );
        assert_eq!(
            parse_transaction_status(br#"{"confirmed":false}"#).expect("valid unconfirmed status"),
            TransactionStatus::Unconfirmed
        );
        assert!(parse_transaction_status(
            br#"{"confirmed":true,"confirmed":true,"block_height":0,"block_hash":null}"#
        )
        .is_err());
        assert!(parse_transaction_status(br#"{"confirmed":false,"unknown":1}"#).is_err());
        assert!(parse_transaction_status(br#"{"confirmed":false} trailing"#).is_err());
    }

    #[tokio::test]
    async fn finalized_transaction_observation_binds_exact_bytes_and_source_set() {
        let fixture = finality_fixture("finality-happy", 5).await;
        let txid = fixture.transaction.compute_txid();
        let status = confirmed_status(0, genesis_block(Network::Testnet4).block_hash());
        mount_status(&fixture.first, txid, status.clone()).await;
        mount_status(&fixture.second, txid, status).await;

        let observation = fixture
            .observer
            .observe_finalized_transaction(txid)
            .await
            .expect("stable six-confirmation observation");
        let exact_bytes = serialize(&fixture.transaction);
        assert_eq!(observation.chain_hash(), ChainHash::TESTNET4);
        assert_eq!(observation.txid(), txid);
        assert_eq!(observation.wtxid(), fixture.transaction.compute_wtxid());
        assert_eq!(
            observation.exact_transaction_sha256(),
            sha256::Hash::hash(&exact_bytes).to_byte_array()
        );
        assert_eq!(
            observation.block_hash(),
            genesis_block(Network::Testnet4).block_hash()
        );
        assert_eq!(observation.block_height(), 0);
        assert_eq!(observation.corroborated_tip(), 5);
        assert_eq!(observation.confirmations(), 6);
        assert_eq!(
            observation.required_confirmations(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS
        );
        assert_eq!(
            observation.source_set_id(),
            fixture.observer.source_set_id()
        );
        assert_ne!(observation.source_set_id(), [0; 32]);
        assert_ne!(observation.evidence_hash(), [0; 32]);

        fixture.cleanup();
    }

    #[tokio::test]
    async fn unconfirmed_transaction_is_rejected() {
        let fixture = finality_fixture("finality-unconfirmed", 5).await;
        let txid = fixture.transaction.compute_txid();
        mount_status(&fixture.first, txid, br#"{"confirmed":false}"#).await;
        mount_status(&fixture.second, txid, br#"{"confirmed":false}"#).await;

        let error = fixture
            .observer
            .observe_finalized_transaction(txid)
            .await
            .expect_err("unconfirmed transaction must fail closed");
        assert!(matches!(error, ObserverError::TransactionUnconfirmed(id) if id == txid));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn source_status_height_disagreement_is_rejected() {
        let fixture = finality_fixture("finality-status-disagreement", 5).await;
        let txid = fixture.transaction.compute_txid();
        let block_hash = genesis_block(Network::Testnet4).block_hash();
        mount_status(&fixture.first, txid, confirmed_status(0, block_hash)).await;
        mount_status(&fixture.second, txid, confirmed_status(1, block_hash)).await;

        let error = fixture
            .observer
            .observe_finalized_transaction(txid)
            .await
            .expect_err("source-supplied height disagreement must fail closed");
        assert!(matches!(error, ObserverError::SourceDisagreement(_)));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn status_block_hash_must_match_corroborated_raw_block() {
        let fixture = finality_fixture("finality-wrong-hash", 5).await;
        let txid = fixture.transaction.compute_txid();
        let wrong_hash = BlockHash::from_byte_array([0x99; 32]);
        let status = confirmed_status(0, wrong_hash);
        mount_status(&fixture.first, txid, status.clone()).await;
        mount_status(&fixture.second, txid, status).await;

        let error = fixture
            .observer
            .observe_finalized_transaction(txid)
            .await
            .expect_err("status block hash cannot override raw block validation");
        assert!(matches!(error, ObserverError::Finality(_)));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn status_block_must_contain_the_requested_transaction() {
        let fixture = finality_fixture("finality-missing-transaction", 5).await;
        let txid = Txid::from_byte_array([0x77; 32]);
        let status = confirmed_status(0, genesis_block(Network::Testnet4).block_hash());
        mount_status(&fixture.first, txid, status.clone()).await;
        mount_status(&fixture.second, txid, status).await;

        let error = fixture
            .observer
            .observe_finalized_transaction(txid)
            .await
            .expect_err("status cannot substitute for transaction inclusion");
        assert!(matches!(error, ObserverError::Finality(_)));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn configured_confirmation_floor_is_enforced() {
        let fixture = finality_fixture("finality-confirmations", 4).await;
        let txid = fixture.transaction.compute_txid();
        let status = confirmed_status(0, genesis_block(Network::Testnet4).block_hash());
        mount_status(&fixture.first, txid, status.clone()).await;
        mount_status(&fixture.second, txid, status).await;

        let error = fixture
            .observer
            .observe_finalized_transaction(txid)
            .await
            .expect_err("five confirmations must not satisfy the six-block floor");
        assert!(matches!(
            error,
            ObserverError::InsufficientConfirmations {
                txid: id,
                observed: 5,
                required: MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
            } if id == txid
        ));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn retained_inventory_must_be_caught_up_through_corroborated_tip() {
        let fixture = finality_fixture("finality-stale-inventory", 5).await;
        let txid = fixture.transaction.compute_txid();
        let height_four_hash = fixture
            .observer
            .inventory
            .canonical_hash(4)
            .await
            .expect("canonical height query")
            .expect("height four checkpoint");
        fixture
            .observer
            .inventory
            .rollback_to(4, height_four_hash)
            .await
            .expect("stale inventory fixture");
        let status = confirmed_status(0, genesis_block(Network::Testnet4).block_hash());
        mount_status(&fixture.first, txid, status.clone()).await;
        mount_status(&fixture.second, txid, status).await;

        let error = fixture
            .observer
            .observe_finalized_transaction(txid)
            .await
            .expect_err("inventory behind the corroborated tip must fail closed");
        assert!(matches!(error, ObserverError::Finality(_)));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn reorg_between_status_samples_is_rejected() {
        let fixture = finality_fixture("finality-status-race", 5).await;
        let txid = fixture.transaction.compute_txid();
        let first_status = confirmed_status(0, genesis_block(Network::Testnet4).block_hash());
        let changed_status = confirmed_status(0, BlockHash::from_byte_array([0x88; 32]));
        mount_status_sequence(
            &fixture.first,
            txid,
            first_status.clone(),
            changed_status.clone(),
        )
        .await;
        mount_status_sequence(&fixture.second, txid, first_status, changed_status).await;

        let error = fixture
            .observer
            .observe_finalized_transaction(txid)
            .await
            .expect_err("status reorg between samples must fail closed");
        assert!(matches!(error, ObserverError::SourceDisagreement(_)));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn oversized_transaction_status_is_rejected_before_parsing() {
        let fixture = finality_fixture("finality-status-limit", 5).await;
        let txid = fixture.transaction.compute_txid();
        mount_status(
            &fixture.first,
            txid,
            vec![b' '; MAX_TRANSACTION_STATUS_BYTES.saturating_add(1)],
        )
        .await;
        mount_status(&fixture.second, txid, br#"{"confirmed":false}"#).await;

        let error = fixture
            .observer
            .observe_finalized_transaction(txid)
            .await
            .expect_err("oversized status body must fail closed");
        assert!(matches!(
            error,
            ObserverError::ResponseTooLarge(MAX_TRANSACTION_STATUS_BYTES)
        ));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn exact_testnet4_genesis_is_authenticated_before_inventory_open() {
        let first = MockServer::start().await;
        let second = MockServer::start().await;
        mount_genesis(&first, 0).await;
        mount_genesis(&second, 0).await;
        let directory = private_test_directory("genesis");
        let database = directory.join("inventory.sqlite");
        let config = Testnet4ObserverConfig::new_for_test(
            "genesis-auth",
            &database,
            custody_script(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
            0,
            vec![("first", &first.uri()), ("second", &second.uri())],
        )
        .expect("test config");

        let observer = Testnet4FinalizedInventoryObserver::open(config)
            .await
            .expect("authenticated observer");
        let policy_source = observer.policy_source();
        let missing = OutPoint {
            txid: Txid::from_byte_array([0x44; 32]),
            vout: 0,
        };
        let error = policy_source
            .issue_policy_inputs(&[missing])
            .await
            .expect_err("policy issuance must wait for a complete source-tip sync");
        assert!(
            matches!(&error, InventoryError::Unavailable(message) if message.contains("corroboration"))
        );
        let report = observer.sync_once().await.expect("sync genesis");
        assert_eq!(report.source_tip(), 0);
        assert_eq!(report.retained_tip(), Some(0));
        assert_eq!(report.appended_blocks(), 1);
        assert_ne!(observer.source_set_id(), [0; 32]);
        let error = policy_source
            .issue_policy_inputs(&[missing])
            .await
            .expect_err("missing output must fail after freshness is established");
        assert!(
            matches!(&error, InventoryError::Unavailable(message) if message.contains("not in the canonical inventory"))
        );
        let metadata = std::fs::symlink_metadata(&database).expect("database metadata");
        assert_eq!(metadata.permissions().mode() & 0o077, 0);

        drop(observer);
        std::fs::remove_dir_all(directory).expect("remove observer fixture");
    }

    #[tokio::test]
    async fn source_tip_disagreement_fails_before_commit_or_freshness() {
        let first = MockServer::start().await;
        let second = MockServer::start().await;
        mount_genesis(&first, 0).await;
        mount_genesis(&second, 1).await;
        let directory = private_test_directory("tip-disagreement");
        let database = directory.join("inventory.sqlite");
        let config = Testnet4ObserverConfig::new_for_test(
            "tip-disagreement",
            &database,
            custody_script(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
            0,
            vec![("first", &first.uri()), ("second", &second.uri())],
        )
        .expect("test config");

        let observer = Testnet4FinalizedInventoryObserver::open(config)
            .await
            .expect("authenticated observer");
        let error = observer
            .sync_once()
            .await
            .expect_err("different approved-source tips must fail closed");
        assert!(matches!(error, ObserverError::SourceDisagreement(_)));
        assert_eq!(
            observer
                .inventory
                .latest_checkpoint()
                .await
                .expect("checkpoint query"),
            None,
            "a lagging source must not define a fresh common-prefix checkpoint"
        );
        let missing = OutPoint {
            txid: Txid::from_byte_array([0x45; 32]),
            vout: 0,
        };
        let error = observer
            .policy_source()
            .issue_policy_inputs(&[missing])
            .await
            .expect_err("tip disagreement must leave policy issuance stale");
        assert!(
            matches!(&error, InventoryError::Unavailable(message) if message.contains("corroboration"))
        );

        drop(observer);
        std::fs::remove_dir_all(directory).expect("remove observer fixture");
    }

    #[tokio::test]
    async fn source_tip_advance_during_sync_does_not_refresh_stale_checkpoint() {
        let first = MockServer::start().await;
        let second = MockServer::start().await;
        let genesis = genesis_block(Network::Testnet4);
        let hash = genesis.block_hash().to_string();
        for server in [&first, &second] {
            Mock::given(method("GET"))
                .and(path("/block-height/0"))
                .respond_with(ResponseTemplate::new(200).set_body_string(hash.clone()))
                .mount(server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/block/{hash}/raw")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(serialize(&genesis)))
                .mount(server)
                .await;
            Mock::given(method("GET"))
                .and(path("/blocks/tip/height"))
                .respond_with(ResponseTemplate::new(200).set_body_string("0"))
                .up_to_n_times(1)
                .with_priority(1)
                .mount(server)
                .await;
            Mock::given(method("GET"))
                .and(path("/blocks/tip/height"))
                .respond_with(ResponseTemplate::new(200).set_body_string("1"))
                .with_priority(2)
                .mount(server)
                .await;
        }
        let directory = private_test_directory("tip-advance");
        let database = directory.join("inventory.sqlite");
        let config = Testnet4ObserverConfig::new_for_test(
            "tip-advance",
            &database,
            custody_script(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
            0,
            vec![("first", &first.uri()), ("second", &second.uri())],
        )
        .expect("test config");

        let observer = Testnet4FinalizedInventoryObserver::open(config)
            .await
            .expect("authenticated observer");
        let report = observer.sync_once().await.expect("bounded sync");
        assert_eq!(report.source_tip(), 1);
        assert_eq!(report.retained_tip(), Some(0));
        assert_eq!(report.appended_blocks(), 1);
        let missing = OutPoint {
            txid: Txid::from_byte_array([0x46; 32]),
            vout: 0,
        };
        let error = observer
            .policy_source()
            .issue_policy_inputs(&[missing])
            .await
            .expect_err("a checkpoint behind the resampled tip must remain stale");
        assert!(
            matches!(&error, InventoryError::Unavailable(message) if message.contains("corroboration"))
        );

        drop(observer);
        std::fs::remove_dir_all(directory).expect("remove observer fixture");
    }

    #[tokio::test]
    async fn wrong_genesis_fails_before_creating_inventory() {
        let first = MockServer::start().await;
        let second = MockServer::start().await;
        mount_genesis(&first, 0).await;
        let wrong_hash = BlockHash::from_byte_array([0x44; 32]).to_string();
        Mock::given(method("GET"))
            .and(path("/block-height/0"))
            .respond_with(ResponseTemplate::new(200).set_body_string(wrong_hash.clone()))
            .mount(&second)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/block/{wrong_hash}/raw")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(serialize(&genesis_block(Network::Testnet4))),
            )
            .mount(&second)
            .await;
        let directory = private_test_directory("wrong-genesis");
        let database = directory.join("inventory.sqlite");
        let config = Testnet4ObserverConfig::new_for_test(
            "wrong-genesis",
            &database,
            custody_script(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
            0,
            vec![("first", &first.uri()), ("second", &second.uri())],
        )
        .expect("test config");

        let error = Testnet4FinalizedInventoryObserver::open(config)
            .await
            .expect_err("wrong genesis must fail closed");
        assert!(matches!(error, ObserverError::Decode(_)));
        assert!(!database.exists());
        std::fs::remove_dir_all(directory).expect("remove observer fixture");
    }

    #[tokio::test]
    async fn durable_inventory_pins_the_exact_authenticated_source_set() {
        let first = MockServer::start().await;
        let second = MockServer::start().await;
        let replacement = MockServer::start().await;
        mount_genesis(&first, 0).await;
        mount_genesis(&second, 0).await;
        mount_genesis(&replacement, 0).await;
        let directory = private_test_directory("source-pinning");
        let database = directory.join("inventory.sqlite");
        let original = Testnet4ObserverConfig::new_for_test(
            "source-pinning",
            &database,
            custody_script(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
            0,
            vec![("first", &first.uri()), ("second", &second.uri())],
        )
        .expect("original config");
        let observer = Testnet4FinalizedInventoryObserver::open(original)
            .await
            .expect("original observer");
        drop(observer);

        let changed = Testnet4ObserverConfig::new_for_test(
            "source-pinning",
            &database,
            custody_script(),
            MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
            0,
            vec![("first", &first.uri()), ("replacement", &replacement.uri())],
        )
        .expect("changed config");
        let error = Testnet4FinalizedInventoryObserver::open(changed)
            .await
            .expect_err("source-set drift must fail closed");
        assert!(matches!(
            error,
            ObserverError::Inventory(InventoryError::Config(_))
        ));
        std::fs::remove_dir_all(directory).expect("remove observer fixture");
    }

    #[test]
    fn secure_store_rejects_symlink_database_files() {
        let directory = private_test_directory("symlink");
        let target = directory.join("target.sqlite");
        std::fs::write(&target, []).expect("target file");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("target permissions");
        let link = directory.join("inventory.sqlite");
        symlink(&target, &link).expect("database symlink");
        let error = prepare_secure_sqlite_file(&link).expect_err("symlink must fail closed");
        assert!(matches!(error, InventoryError::Config(_)));
        std::fs::remove_dir_all(directory).expect("remove observer fixture");
    }

    #[test]
    fn secure_store_rejects_hard_links_and_permissive_parent_directories() {
        let directory = private_test_directory("hard-link");
        let target = directory.join("target.sqlite");
        std::fs::write(&target, []).expect("target file");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("target permissions");
        let link = directory.join("inventory.sqlite");
        std::fs::hard_link(&target, &link).expect("database hard link");
        let error = prepare_secure_sqlite_file(&link).expect_err("hard link must fail closed");
        assert!(matches!(error, InventoryError::Config(_)));
        std::fs::remove_dir_all(&directory).expect("remove hard-link fixture");

        let permissive = private_test_directory("permissive-parent");
        std::fs::set_permissions(&permissive, std::fs::Permissions::from_mode(0o750))
            .expect("permissive fixture permissions");
        let error = prepare_secure_sqlite_file(&permissive.join("inventory.sqlite"))
            .expect_err("group-accessible parent must fail closed");
        assert!(matches!(error, InventoryError::Config(_)));
        std::fs::remove_dir_all(permissive).expect("remove permissive fixture");
    }

    #[test]
    fn secure_store_rejects_preexisting_sqlite_sidecars() {
        for suffix in ["-journal", "-wal", "-shm"] {
            let directory = private_test_directory(&format!("sidecar{}", &suffix[1..]));
            let database = directory.join("inventory.sqlite");
            let mut sidecar = database.as_os_str().to_os_string();
            sidecar.push(suffix);
            std::fs::write(sidecar, []).expect("sidecar fixture");
            let error = prepare_secure_sqlite_file(&database)
                .expect_err("preexisting SQLite sidecar must fail closed");
            assert!(matches!(error, InventoryError::Config(_)));
            std::fs::remove_dir_all(directory).expect("remove sidecar fixture");
        }
    }
}
