//! Finalized-journal-driven, restart-safe terminal redemption worker.
//!
//! The process has no signing key. It mirrors one operator's canonical
//! finalized observer journal into a local transactional cursor/outbox, then
//! permissionlessly calls `IndexToken.finalizeBurn`. A successful receipt is
//! not terminal: responsibility remains queued until the finalized observer
//! journals `RedemptionIntentFinalized` (or a stuck cancellation supersedes
//! it). Metrics, journal ingestion, and posting are one supervised process.

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::providers::{Provider, ProviderBuilder, ReqwestProvider};
use alloy_primitives::{Address, Bytes};
use anyhow::{Context, Result};
use clap::Parser;
use prometheus::Registry;
use tokio::sync::Notify;
use tracing::{error, info, warn};
use xindex_chain_eth::bindings::{IndexToken, IntentQueue};
use xindex_chain_eth::finalized_observer::{
    FinalizedRedemptionEvent, SqliteFinalizedObserverStore,
};
use xindex_ops::{init_tracing, serve_metrics, Metrics};
use xindex_relayer::{FinalizationJob, SqliteRedemptionFinalizerStore};

#[derive(Parser, Debug)]
#[command(version, about = "Xindex finalized-journal terminal redemption worker")]
struct Args {
    /// Credential-free HTTP(S) execution RPC. The node owns the gas account.
    #[arg(long, env = "ETH_RPC_URL")]
    rpc_url: String,

    #[arg(long, env = "EXPECTED_CHAIN_ID")]
    expected_chain_id: u64,

    #[arg(long, env = "INTENT_QUEUE_ADDR")]
    intent_queue: String,

    /// Gas-paying address exposed by the node-managed external signer.
    #[arg(long, env = "POSTER_ADDRESS")]
    poster_address: String,

    /// Existing operator finalized-observer `SQLite` journal.
    #[arg(long, env = "OBSERVER_DATABASE_URL")]
    observer_database_url: String,

    /// Exact observer namespace used by `xindex-finalized-observer`.
    #[arg(long, env = "OBSERVER_ID")]
    observer_id: String,

    /// Dedicated durable mirror/outbox `SQLite` database.
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// First block retained by the source observer for this deployment.
    #[arg(long, env = "START_BLOCK")]
    start_block: u64,

    #[arg(long, env = "POLL_INTERVAL_MILLIS", default_value_t = 1_000)]
    poll_interval_millis: u64,

    #[arg(long, env = "RETRY_BASE_MILLIS", default_value_t = 1_000)]
    retry_base_millis: u64,

    #[arg(long, env = "RETRY_MAX_MILLIS", default_value_t = 60_000)]
    retry_max_millis: u64,

    /// Static V4 hint for each synchronous basket slot. Async slots use empty.
    #[arg(long, env = "ERC20_SWAP_HINT_HEX", default_value = "")]
    erc20_swap_hint_hex: String,

    #[arg(long, env = "METRICS_ADDR", default_value = "127.0.0.1:9092")]
    metrics_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();
    validate_args(&args)?;

    let intent_queue = parse_nonzero_address("INTENT_QUEUE_ADDR", &args.intent_queue)?;
    let poster_address = parse_nonzero_address("POSTER_ADDRESS", &args.poster_address)?;
    let erc20_hint = parse_hint(&args.erc20_swap_hint_hex)?;
    let rpc_url = args.rpc_url.parse().context("parse ETH_RPC_URL")?;
    let provider = Arc::new(ProviderBuilder::new().on_http(rpc_url));
    let chain_id = provider.get_chain_id().await.context("read chain id")?;
    if chain_id != args.expected_chain_id {
        anyhow::bail!(
            "Ethereum chain id {chain_id} differs from configured {}",
            args.expected_chain_id
        );
    }
    let source =
        SqliteFinalizedObserverStore::connect(&args.observer_database_url, &args.observer_id)
            .await
            .context("open canonical finalized observer journal")?;
    let store = SqliteRedemptionFinalizerStore::connect(&args.database_url, &args.observer_id)
        .await
        .context("open terminal redemption cursor/outbox")?;
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).context("register metrics")?;
    let notify = Arc::new(Notify::new());

    info!(
        observer = %args.observer_id,
        %intent_queue,
        start_block = args.start_block,
        "terminal redemption worker ready"
    );
    let journal = journal_worker(
        source,
        store.clone(),
        args.observer_id.clone(),
        args.start_block,
        Duration::from_millis(args.poll_interval_millis),
        Arc::clone(&notify),
        metrics.clone(),
    );
    let poster = poster_worker(
        store,
        provider,
        intent_queue,
        poster_address,
        erc20_hint,
        args.retry_base_millis,
        args.retry_max_millis,
        notify,
        metrics,
    );
    let metrics_server = serve_metrics(registry, args.metrics_addr);
    tokio::select! {
        result = journal => result.context("terminal journal worker exited"),
        result = poster => result.context("terminal poster worker exited"),
        result = metrics_server => result.context("terminal metrics server exited"),
    }
}

async fn journal_worker(
    source: SqliteFinalizedObserverStore,
    store: SqliteRedemptionFinalizerStore,
    observer_id: String,
    start_block: u64,
    poll_interval: Duration,
    notify: Arc<Notify>,
    metrics: Metrics,
) -> Result<()> {
    loop {
        reconcile_source(&source, &store, start_block).await?;
        let Some(source_head) = source.last_checkpoint().await? else {
            tokio::time::sleep(poll_interval).await;
            continue;
        };
        metrics
            .observer_finalized_head_height
            .with_label_values(&[&observer_id])
            .set(u64_to_i64(source_head.block_number));
        let next = store
            .last_checkpoint()
            .await?
            .map_or(start_block, |checkpoint| {
                checkpoint.block_number.saturating_add(1)
            });
        if next <= source_head.block_number {
            for block_number in next..=source_head.block_number {
                let block = source
                    .redemption_block(block_number)
                    .await?
                    .with_context(|| {
                        format!("source observer lacks canonical block {block_number}")
                    })?;
                let tracked = block
                    .events
                    .iter()
                    .filter(|event| matches!(event, FinalizedRedemptionEvent::Created { .. }))
                    .count();
                let resolved = block
                    .events
                    .iter()
                    .filter(|event| {
                        matches!(
                            event,
                            FinalizedRedemptionEvent::Finalized { .. }
                                | FinalizedRedemptionEvent::StuckCancelled { .. }
                        )
                    })
                    .count();
                let ready = block
                    .events
                    .iter()
                    .any(|event| matches!(event, FinalizedRedemptionEvent::LegResolved { .. }));
                store
                    .commit_source_block(block.checkpoint, &block.events, now_unix()?)
                    .await?;
                metrics
                    .redeem_relayer_tracked
                    .inc_by(u64::try_from(tracked).unwrap_or(u64::MAX));
                metrics
                    .redeem_relayer_resolved
                    .with_label_values(&["finalized_journal"])
                    .inc_by(u64::try_from(resolved).unwrap_or(u64::MAX));
                if ready {
                    notify.notify_one();
                }
            }
        }
        let now = now_unix()?;
        let stats = store.stats(now).await?;
        metrics
            .redeem_relayer_pending
            .set(u64_to_i64(stats.pending_redemptions));
        metrics
            .redeem_relayer_stuck
            .set(usize_to_i64(stats.stuck.len()));
        for stuck in stats.stuck {
            warn!(
                redemption_id = %stuck.redemption_id,
                index_token = %stuck.index_token,
                deadline = stuck.deadline,
                "SD-B stuck redemption has no finalized settlement at the strict deadline"
            );
        }
        if let Some(checkpoint) = store.last_checkpoint().await? {
            metrics
                .observer_checkpoint_height
                .with_label_values(&[&observer_id])
                .set(u64_to_i64(checkpoint.block_number));
            metrics
                .observer_last_sync_timestamp_seconds
                .with_label_values(&[&observer_id])
                .set(u64_to_i64(now));
        }
        tokio::time::sleep(poll_interval).await;
    }
}

async fn reconcile_source(
    source: &SqliteFinalizedObserverStore,
    store: &SqliteRedemptionFinalizerStore,
    start_block: u64,
) -> Result<()> {
    let Some(local) = store.last_checkpoint().await? else {
        return Ok(());
    };
    if source.checkpoint_hash(local.block_number).await? == Some(local.block_hash) {
        return Ok(());
    }
    let mut height = local.block_number;
    loop {
        let local_hash = store.checkpoint_hash(height).await?;
        let source_hash = source.checkpoint_hash(height).await?;
        if local_hash.is_some() && local_hash == source_hash {
            let hash = local_hash.context("common checkpoint hash disappeared")?;
            store.rollback_to(height, hash, now_unix()?).await?;
            error!(
                ancestor = height,
                "terminal journal mirrored source rollback"
            );
            return Ok(());
        }
        if height <= start_block {
            break;
        }
        height -= 1;
    }
    anyhow::bail!("terminal journal and source observer have no retained common ancestor")
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the isolated terminal state machine owns its outbox, contract identities, idempotence reads and retry policy"
)]
async fn poster_worker(
    store: SqliteRedemptionFinalizerStore,
    provider: Arc<ReqwestProvider>,
    intent_queue: Address,
    poster_address: Address,
    erc20_hint: Bytes,
    retry_base_millis: u64,
    retry_max_millis: u64,
    notify: Arc<Notify>,
    metrics: Metrics,
) -> Result<()> {
    store.recover_inflight(now_unix()?).await?;
    let queue = IntentQueue::new(intent_queue, Arc::clone(&provider));
    loop {
        let now = now_unix()?;
        let Some(job) = store.claim_next(now).await? else {
            tokio::select! {
                () = notify.notified() => {}
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
            continue;
        };
        let active = match queue.activeRedemption(job.index_token).call().await {
            Ok(value) => value._0,
            Err(error) => {
                warn!(redemption_id = %job.redemption_id, %error, "active-redemption read failed");
                retry_job(
                    &store,
                    &job,
                    "state_read_unavailable",
                    now,
                    retry_base_millis,
                    retry_max_millis,
                )
                .await?;
                continue;
            }
        };
        if active != job.redemption_id {
            retry_job(
                &store,
                &job,
                "awaiting_finalized_terminal_event",
                now,
                retry_base_millis,
                retry_max_millis,
            )
            .await?;
            continue;
        }
        let fully_resolved = match queue
            .isRedemptionFullyResolved(job.redemption_id)
            .call()
            .await
        {
            Ok(value) => value._0,
            Err(error) => {
                warn!(redemption_id = %job.redemption_id, %error, "resolution read failed");
                retry_job(
                    &store,
                    &job,
                    "state_read_unavailable",
                    now,
                    retry_base_millis,
                    retry_max_millis,
                )
                .await?;
                continue;
            }
        };
        if !fully_resolved {
            retry_job(
                &store,
                &job,
                "redemption_not_fully_resolved",
                now,
                retry_base_millis,
                retry_max_millis,
            )
            .await?;
            continue;
        }
        let token = IndexToken::new(job.index_token, Arc::clone(&provider));
        let async_slots = match token.isAsync().call().await {
            Ok(value) => value._0,
            Err(error) => {
                warn!(redemption_id = %job.redemption_id, %error, "basket metadata read failed");
                retry_job(
                    &store,
                    &job,
                    "basket_read_unavailable",
                    now,
                    retry_base_millis,
                    retry_max_millis,
                )
                .await?;
                continue;
            }
        };
        let hints = async_slots
            .into_iter()
            .map(|is_async| {
                if is_async {
                    Bytes::new()
                } else {
                    erc20_hint.clone()
                }
            })
            .collect();
        let sent = token
            .finalizeBurn(job.redemption_id, hints)
            .from(poster_address)
            .send()
            .await;
        let outcome = match sent {
            Ok(transaction) => match transaction.get_receipt().await {
                Ok(receipt) if receipt.status() => {
                    metrics
                        .redeem_relayer_finalize_attempts
                        .with_label_values(&["confirmed"])
                        .inc();
                    info!(
                        redemption_id = %job.redemption_id,
                        tx_hash = %receipt.transaction_hash,
                        "finalizeBurn confirmed; retaining job until finalized journal event"
                    );
                    "confirmed_awaiting_finality"
                }
                Ok(receipt) => {
                    metrics
                        .redeem_relayer_finalize_attempts
                        .with_label_values(&["revert"])
                        .inc();
                    warn!(redemption_id = %job.redemption_id, tx_hash = %receipt.transaction_hash, "finalizeBurn reverted");
                    "transaction_reverted"
                }
                Err(error) => {
                    metrics
                        .redeem_relayer_finalize_attempts
                        .with_label_values(&["send_error"])
                        .inc();
                    warn!(redemption_id = %job.redemption_id, %error, "finalizeBurn receipt unavailable");
                    "receipt_unavailable"
                }
            },
            Err(error) => {
                metrics
                    .redeem_relayer_finalize_attempts
                    .with_label_values(&["send_error"])
                    .inc();
                warn!(redemption_id = %job.redemption_id, %error, "finalizeBurn submission failed");
                "submission_failed"
            }
        };
        retry_job(
            &store,
            &job,
            outcome,
            now,
            retry_base_millis,
            retry_max_millis,
        )
        .await?;
    }
}

async fn retry_job(
    store: &SqliteRedemptionFinalizerStore,
    job: &FinalizationJob,
    error: &str,
    now: u64,
    retry_base_millis: u64,
    retry_max_millis: u64,
) -> Result<()> {
    let attempt = u32::try_from(job.attempts.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
    let delay = retry_delay(attempt.max(1), retry_base_millis, retry_max_millis);
    store
        .retry(job, now.saturating_add(delay.as_secs().max(1)), error, now)
        .await?;
    Ok(())
}

fn parse_hint(raw: &str) -> Result<Bytes> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(Bytes::new());
    }
    let bytes = alloy_primitives::hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .context("ERC20_SWAP_HINT_HEX is not valid hex")?;
    Ok(Bytes::from(bytes))
}

fn validate_args(args: &Args) -> Result<()> {
    if args.expected_chain_id == 0
        || args.start_block == 0
        || args.poll_interval_millis < 100
        || args.poll_interval_millis > 60_000
        || args.retry_base_millis == 0
        || args.retry_max_millis < args.retry_base_millis
    {
        anyhow::bail!("invalid terminal worker chain/block/retry configuration");
    }
    if !args.metrics_addr.ip().is_loopback() {
        anyhow::bail!("METRICS_ADDR must bind loopback");
    }
    validate_rpc_url(&args.rpc_url)?;
    validate_database_url(&args.observer_database_url, true)?;
    validate_database_url(&args.database_url, false)?;
    Ok(())
}

fn validate_rpc_url(raw: &str) -> Result<()> {
    let url = reqwest::Url::parse(raw).context("ETH_RPC_URL must be a URL")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.scheme(), "http" | "https")
    {
        anyhow::bail!("ETH_RPC_URL must be credential-free HTTP(S) without query/fragment");
    }
    Ok(())
}

fn validate_database_url(database_url: &str, must_exist: bool) -> Result<()> {
    let path = database_url
        .strip_prefix("sqlite://")
        .context("database URL must use sqlite:///absolute/path")?
        .split('?')
        .next()
        .context("database URL path absent")?;
    let path = Path::new(path);
    if !path.is_absolute() {
        anyhow::bail!("database URL must resolve to an absolute durable path");
    }
    let parent = path.parent().context("database path has no parent")?;
    validate_owner_only_directory(parent)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_owner_only_file(&metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !must_exist => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(error).context("required source observer database is absent")
        }
        Err(error) => return Err(error).context("inspect durable database"),
    }
    Ok(())
}

fn validate_owner_only_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute() || !metadata.file_type().is_dir() {
        anyhow::bail!("database parent must be an existing absolute non-symlink directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("database parent must be owner-only");
        }
    }
    Ok(())
}

fn validate_owner_only_file(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.file_type().is_file() {
        anyhow::bail!("database must be a non-symlink regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            anyhow::bail!("database must be owner-only and single-link");
        }
    }
    Ok(())
}

fn parse_nonzero_address(label: &str, raw: &str) -> Result<Address> {
    let address = Address::from_str(raw).with_context(|| format!("parse {label}"))?;
    if address.is_zero() {
        anyhow::bail!("{label} must be non-zero");
    }
    Ok(address)
}

fn retry_delay(attempt: u32, base_millis: u64, max_millis: u64) -> Duration {
    let factor = 1u64 << attempt.saturating_sub(1).min(6);
    Duration::from_millis(base_millis.saturating_mul(factor).min(max_millis))
}

fn now_unix() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .context("system clock predates Unix epoch")
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn usize_to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use super::*;

    #[test]
    fn hint_parser_is_strict_and_deterministic() {
        assert!(parse_hint("").expect("empty").is_empty());
        assert_eq!(parse_hint("0xabcd").expect("hex").as_ref(), &[0xab, 0xcd]);
        assert!(parse_hint("0xzz").is_err());
    }

    #[test]
    fn retry_delay_is_exponential_and_capped() {
        assert_eq!(retry_delay(1, 500, 10_000), Duration::from_millis(500));
        assert_eq!(retry_delay(2, 500, 10_000), Duration::from_secs(1));
        assert_eq!(retry_delay(9, 500, 10_000), Duration::from_secs(10));
    }
}
