//! `xindex-turnkey-approver` — the Turnkey approver-watcher (S2).
//!
//! Observes the watched `CONSENSUS_NEEDED` signing activities, runs the CTD-1
//! decision ([`xindex_custody_node::approver::process_activity`]) against the
//! prepared spend, and casts `approveActivity` / `rejectActivity` — fail-closed.
//! This is one approver voice; production runs a FLEET of M independent
//! approvers (each with its own diverse `THORChain` sources) behind a Turnkey
//! N-of-M consensus policy (DL-CTD-2). Dev default = a single approver.
//!
//! **PRODUCTION-GATED.** The approver now recomputes the signing hash from the
//! prepared fields and asserts it equals the activity payload (TK-01,
//! [`xindex_custody_node::recompute`]) and caps the declared fee (TK-02). What is
//! NOT yet validated is the Turnkey WIRE against the real dev-env — the P-256
//! stamp shape, the `NO_OP` hash function, the real `signRawPayloadIntentV2`
//! payload field the correlation key reads (R1–R4/R6 in
//! `docs/runbooks/turnkey-custody-devenv.md`). Until that reconcile passes this
//! binary refuses to start without `--dev` (mirrors DL-REHEARSAL-1).
//!
//! Activity discovery is via the watched ids passed on the CLI (the executor /
//! operator hands them off); the production push trigger is Turnkey's
//! `ACTIVITY_UPDATES` webhook (RECONCILE AT DEV-ENV).

use std::collections::HashSet;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::Address;
use anyhow::{bail, Context, Result};
use bitcoin::ScriptBuf;
use clap::Parser;

use xindex_custody_core::gates::CustodyConfig;
use xindex_custody_core::prepare::{InMemoryPrepareStore, PrepareStore, SqlitePrepareStore};
use xindex_custody_core::replay::{InMemoryReplayStore, ReplayStore, SqliteReplayStore};
use xindex_custody_node::approver::process_activity;
use xindex_shared::intent::IntentPolicy;
use xindex_turnkey_client::{TurnkeyApi, TurnkeyClient, TurnkeyStamper, TURNKEY_API_BASE};

/// Env var holding the Turnkey API P-256 private key (hex). Read from the
/// environment, never argv, so it stays out of `ps` / shell history.
const API_KEY_ENV: &str = "XINDEX_TURNKEY_API_KEY";

#[derive(Debug, Parser)]
#[command(
    name = "xindex-turnkey-approver",
    about = "Turnkey approver-watcher (S2, dev-only)"
)]
struct Args {
    /// JSON config file (chain id, oracle, Set-B policy, optional BTC spk).
    #[arg(long)]
    config: String,
    /// The Turnkey custody sub-organization id.
    #[arg(long)]
    organization_id: String,
    /// Activity ids to watch this run (repeat `--activity-id`). The production
    /// push trigger is the `ACTIVITY_UPDATES` webhook.
    #[arg(long = "activity-id")]
    activity_ids: Vec<String>,
    /// Turnkey API base URL (host only).
    #[arg(long, default_value = TURNKEY_API_BASE)]
    turnkey_base: String,
    /// Poll interval (seconds) between activity status checks.
    #[arg(long, default_value_t = 5)]
    poll_interval_secs: u64,
    /// Shared sqlite URL for the bind-prepare store (the executor `put`s the
    /// prepared spend here keyed by sighash; this approver `get`s it). Omit for
    /// a process-local in-memory store (single-process rehearsal only).
    #[arg(long)]
    db: Option<String>,
    /// REQUIRED — dev/rehearsal mode. Production is gated until the sighash ↔
    /// payload cross-check lands.
    #[arg(long)]
    dev: bool,
}

/// On-disk config (addresses as hex strings — [`IntentPolicy`] is not
/// `Deserialize`, so the policy is rebuilt from primitives).
#[derive(Debug, serde::Deserialize)]
struct FileConfig {
    chain_id: u64,
    verifying_contract: String,
    signer_whitelist: Vec<String>,
    intent_quorum: usize,
    ric_max_age_secs: u64,
    #[serde(default)]
    btc_custody_spk_hex: Option<String>,
}

/// Resolved watch configuration (built once, borrowed each poll).
struct WatchConfig {
    chain_id: u64,
    verifying_contract: Address,
    intent_policy: IntentPolicy,
    btc_custody_spk: Option<ScriptBuf>,
    activity_ids: Vec<String>,
    poll_interval: Duration,
}

/// Refuse to start in production until the Turnkey wire is reconciled at the
/// dev-env (R1–R4/R6). The TK-01 sighash↔payload recompute + TK-02 fee cap are
/// already in force via [`xindex_custody_node::recompute`].
fn assert_dev_only(dev: bool) -> Result<()> {
    if !dev {
        bail!(
            "refusing to start: the Turnkey wire (P-256 stamp shape, NO_OP hash \
             function, the real signRawPayloadIntentV2 payload field the \
             correlation key reads) is not yet reconciled against the dev-env \
             (docs/runbooks/turnkey-custody-devenv.md R1–R4/R6). The TK-01 \
             payload recompute + TK-02 fee cap are already enforced. Pass --dev \
             for rehearsal; production is gated until the wire reconcile passes."
        );
    }
    Ok(())
}

fn load_intent_policy(cfg: &FileConfig) -> Result<IntentPolicy> {
    let mut signer_whitelist = Vec::with_capacity(cfg.signer_whitelist.len());
    for a in &cfg.signer_whitelist {
        signer_whitelist
            .push(Address::from_str(a).with_context(|| format!("bad whitelist address {a}"))?);
    }
    Ok(IntentPolicy {
        signer_whitelist,
        intent_quorum: cfg.intent_quorum,
        ric_max_age_secs: cfg.ric_max_age_secs,
    })
}

fn load_btc_spk(cfg: &FileConfig) -> Result<Option<ScriptBuf>> {
    match &cfg.btc_custody_spk_hex {
        Some(h) => {
            let bytes = alloy_primitives::hex::decode(h).context("bad btc_custody_spk_hex")?;
            Ok(Some(ScriptBuf::from_bytes(bytes)))
        }
        None => Ok(None),
    }
}

fn now_unix() -> Result<i64> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    i64::try_from(secs).context("unix timestamp overflow")
}

/// Poll the watched activities until each is voted-or-terminal, voting once per
/// `CONSENSUS_NEEDED` activity. Generic over the prepare + replay stores so
/// `main` picks in-memory (rehearsal) or sqlite (shared with the executor); a
/// persistent replay store keeps the RIC one-shot rows across restarts (RS-02).
async fn watch<P: PrepareStore, R: ReplayStore>(
    client: &TurnkeyClient,
    prepare: &P,
    replay: &R,
    cfg: WatchConfig,
) -> Result<()> {
    let mut pending = cfg.activity_ids.clone();
    let mut voted: HashSet<String> = HashSet::new();

    while !pending.is_empty() {
        let mut still = Vec::new();
        for id in &pending {
            let act = match client.get_activity(id).await {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(activity = %id, error = %e, "poll failed; will retry");
                    still.push(id.clone());
                    continue;
                }
            };
            if act.status.is_terminal() {
                tracing::info!(activity = %id, status = ?act.status, "activity terminal; no longer watching");
                continue;
            }
            if !act.status.is_consensus_needed() || voted.contains(id) {
                still.push(id.clone());
                continue;
            }
            let config = CustodyConfig {
                chain_id: cfg.chain_id,
                verifying_contract: cfg.verifying_contract,
                intent_policy: &cfg.intent_policy,
            };
            match process_activity(
                client,
                prepare,
                replay,
                config,
                cfg.btc_custody_spk.as_ref(),
                &act,
                now_unix()?,
            )
            .await
            {
                Ok(decision) => {
                    tracing::info!(activity = %id, ?decision, "cast vote");
                    voted.insert(id.clone());
                    still.push(id.clone());
                }
                Err(e) => {
                    tracing::warn!(activity = %id, error = %e, "vote failed; will retry");
                    still.push(id.clone());
                }
            }
        }
        pending = still;
        if pending.is_empty() {
            break;
        }
        tokio::time::sleep(cfg.poll_interval).await;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    let args = Args::parse();
    assert_dev_only(args.dev)?;
    if args.activity_ids.is_empty() {
        bail!("no --activity-id to watch (the ACTIVITY_UPDATES webhook trigger is a follow-on)");
    }

    let api_key = std::env::var(API_KEY_ENV)
        .with_context(|| format!("{API_KEY_ENV} not set (the Turnkey API P-256 private key)"))?;
    let stamper =
        TurnkeyStamper::from_hex(&api_key).map_err(|e| anyhow::anyhow!("api key: {e}"))?;
    let client = TurnkeyClient::new(&args.turnkey_base, &args.organization_id, stamper)
        .map_err(|e| anyhow::anyhow!("turnkey client: {e}"))?;

    let cfg_bytes =
        std::fs::read_to_string(&args.config).with_context(|| format!("read {}", args.config))?;
    let file_cfg: FileConfig = serde_json::from_str(&cfg_bytes).context("parse config json")?;
    let watch_cfg = WatchConfig {
        chain_id: file_cfg.chain_id,
        verifying_contract: Address::from_str(&file_cfg.verifying_contract)
            .context("bad verifying_contract")?,
        intent_policy: load_intent_policy(&file_cfg)?,
        btc_custody_spk: load_btc_spk(&file_cfg)?,
        activity_ids: args.activity_ids.clone(),
        poll_interval: Duration::from_secs(args.poll_interval_secs),
    };

    // A shared sqlite URL backs BOTH the prepare store (executor `put`s here)
    // and the replay store (custody-core migrations 0001–0015 live in one dir),
    // so RIC one-shot rows persist across approver restarts (RS-02).
    if let Some(url) = &args.db {
        let prepare = SqlitePrepareStore::connect(url)
            .await
            .map_err(|e| anyhow::anyhow!("prepare store {url}: {e}"))?;
        let replay = SqliteReplayStore::connect(url)
            .await
            .map_err(|e| anyhow::anyhow!("replay store {url}: {e}"))?;
        tracing::info!(org = %args.organization_id, db = %url, watching = watch_cfg.activity_ids.len(),
            "xindex-turnkey-approver (dev, sqlite store) started");
        watch(&client, &prepare, &replay, watch_cfg).await
    } else {
        let prepare = InMemoryPrepareStore::new();
        let replay = InMemoryReplayStore::new();
        tracing::info!(org = %args.organization_id, watching = watch_cfg.activity_ids.len(),
            "xindex-turnkey-approver (dev, in-memory store) started");
        watch(&client, &prepare, &replay, watch_cfg).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_flag_required() {
        assert!(assert_dev_only(false).is_err());
        assert!(assert_dev_only(true).is_ok());
    }

    #[test]
    fn loads_policy_and_spk_from_config() {
        let json = serde_json::json!({
            "chain_id": 1,
            "verifying_contract": "0x4242424242424242424242424242424242424242",
            "signer_whitelist": ["0x1111111111111111111111111111111111111111"],
            "intent_quorum": 3,
            "ric_max_age_secs": 3600,
            "btc_custody_spk_hex": "0014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        })
        .to_string();
        #[expect(clippy::expect_used, reason = "test code")]
        let cfg: FileConfig = serde_json::from_str(&json).expect("parse");
        #[expect(clippy::expect_used, reason = "test code")]
        let policy = load_intent_policy(&cfg).expect("policy");
        assert_eq!(policy.intent_quorum, 3);
        assert_eq!(policy.signer_whitelist.len(), 1);
        #[expect(clippy::expect_used, reason = "test code")]
        let spk = load_btc_spk(&cfg).expect("spk");
        assert!(spk.is_some());
    }
}
