//! `xindex-custody-callback` — the Cobo TSS-Node callback server (W1).
//!
//! Verifies the TSS Node's RS256 request JWT, runs the CTD-1 decision
//! ([`xindex_custody_node::dispatch`]), and signs an APPROVE/REJECT response.
//!
//! **PRODUCTION-GATED.** W1 does not yet cross-check the message Cobo is about
//! to sign (`request_detail`, schema non-public) against the re-derived sighash
//! of the prepared spend — that is W3 dev-env reconciliation. Until then this
//! binary refuses to start without `--dev`, so it can only be used for
//! rehearsal, never against real Cobo funds. (Mirrors the `SoftwareHsm` /
//! DL-REHEARSAL-1 gating.) It also uses an in-memory prepare store: the real
//! flow needs a sqlite store SHARED with the executor process — that lands
//! with W2.

use std::str::FromStr;
use std::sync::Arc;

use alloy_primitives::Address;
use anyhow::{bail, Context, Result};
use bitcoin::ScriptBuf;
use clap::Parser;
use tokio::net::TcpListener;
use xindex_custody_core::replay::InMemoryReplayStore;
use xindex_shared::intent::IntentPolicy;

use xindex_custody_node::jwt::JwtKeys;
use xindex_custody_node::prepare::InMemoryPrepareStore;
use xindex_custody_node::server::{router, CallbackState};

#[derive(Debug, Parser)]
#[command(
    name = "xindex-custody-callback",
    about = "Cobo TSS-Node callback server (W1, dev-only)"
)]
struct Args {
    /// Bind address (`host:port`) for the callback HTTP server.
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: String,
    /// PEM file: the Cobo TSS-Node's RSA PUBLIC key (verifies requests).
    #[arg(long)]
    node_pubkey_pem: String,
    /// PEM file: OUR RSA PRIVATE key (signs responses).
    #[arg(long)]
    our_privkey_pem: String,
    /// JSON config file (chain id, oracle, Set-B policy, optional BTC spk).
    #[arg(long)]
    config: String,
    /// REQUIRED in W1 — dev/rehearsal mode. Production is gated until the W3
    /// `request_detail`↔sighash cross-check lands.
    #[arg(long)]
    dev: bool,
}

/// On-disk callback config (addresses as hex strings — [`IntentPolicy`] is not
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

/// Refuse to start in production until the W3 cross-check is wired.
fn assert_dev_only(dev: bool) -> Result<()> {
    if !dev {
        bail!(
            "refusing to start: the W1 callback does not yet cross-check the \
             Cobo-signed message against the prepared spend (dispatch.rs SECURITY \
             TODO / docs/runbooks/cobo-btc-gate.md). Pass --dev for rehearsal; \
             production is gated until W3."
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    let args = Args::parse();
    assert_dev_only(args.dev)?;

    let node_pub = std::fs::read(&args.node_pubkey_pem)
        .with_context(|| format!("read {}", args.node_pubkey_pem))?;
    let our_priv = std::fs::read(&args.our_privkey_pem)
        .with_context(|| format!("read {}", args.our_privkey_pem))?;
    let jwt =
        JwtKeys::from_pems(&node_pub, &our_priv).map_err(|e| anyhow::anyhow!("jwt keys: {e}"))?;

    let cfg_bytes =
        std::fs::read_to_string(&args.config).with_context(|| format!("read {}", args.config))?;
    let cfg: FileConfig = serde_json::from_str(&cfg_bytes).context("parse config json")?;
    let verifying_contract =
        Address::from_str(&cfg.verifying_contract).context("bad verifying_contract")?;
    let intent_policy = load_intent_policy(&cfg)?;
    let btc_custody_spk = load_btc_spk(&cfg)?;

    let state = CallbackState {
        jwt: Arc::new(jwt),
        prepare: Arc::new(InMemoryPrepareStore::new()),
        replay: Arc::new(InMemoryReplayStore::new()),
        chain_id: cfg.chain_id,
        verifying_contract,
        intent_policy,
        btc_custody_spk,
    };

    let listener = TcpListener::bind(&args.bind)
        .await
        .with_context(|| format!("bind {}", args.bind))?;
    tracing::info!(bind = %args.bind, "xindex-custody-callback (W1 dev) listening on /v1/check");
    axum::serve(listener, router(state))
        .await
        .context("serve")?;
    Ok(())
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
