//! `xindex-redeem-xrp` — Phase 4.4 XRP redeem executor binary.
//!
//! Reads the `Sequence` for our `SignerList` multisig + the current ledger
//! from a `rippled` node, drives the k-of-n `Payment` flow (via
//! [`XrpRedeemExecutor`]) to the THORChain Asgard inbound with the
//! contract-emitted swap memo, and emits the broadcast-ready multisigned
//! tx-blob.
//!
//! ## v1 scope
//!
//! Single-leg CLI skeleton (parity with `xindex-redeem-cosmos`). It builds
//! and aggregates the multisig tx and prints the tx-blob hex; `--broadcast`
//! optionally posts it via `submit`. The event-driven loop
//! (RedeemDispatched → build → broadcast → record the `xrp` dispatch row)
//! and the live `rippled` byte-match validation are C9 / signet-rehearsal
//! territory (KNOWN_FINDINGS P4.4-1).

#![expect(
    clippy::print_stdout,
    reason = "CLI binary — println is the user interface"
)]
#![expect(
    clippy::doc_markdown,
    reason = "XrpTxSignRequest / SignerList / STObject identifiers in module \
              docs — backticks add noise"
)]

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::info;
use xindex_chain_xrp::{ReqwestXrpChainClient, XrpChainClient};
use xindex_executor::xrp_redeem::{
    SignXrpFuture, XrpCosigner, XrpLockTable, XrpRedeemConfig, XrpRedeemError, XrpRedeemExecutor,
    XrpRedeemTask,
};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{XrpSignResponse, XrpTxSignRequest};
use xindex_xrp_tx::XrpMultisig;

/// CLI for a single XRP redeem leg.
#[derive(Debug, Parser)]
#[command(name = "xindex-redeem-xrp", version)]
struct Args {
    /// Destination chain (xrp).
    #[arg(long, default_value = "xrp")]
    chain: String,

    /// The funded `SignerList` multisig account (classic r-address). Used
    /// directly — the XRP account is NOT derived from the member set.
    #[arg(long)]
    multisig_address: String,

    /// All member compressed pubkeys (CSV of 0x33-byte hex). Each is given
    /// weight 1 (our k-of-n ceremony). The descriptor sorts them by
    /// AccountID internally.
    #[arg(long)]
    member_pubkeys: String,

    /// Signer quorum (k-of-n; 3 for our 3-of-5, weight-1 each).
    #[arg(long, default_value_t = 3)]
    quorum: u32,

    /// Fee in drops.
    #[arg(long)]
    fee_drops: u128,

    /// Ledgers added to the current index for `LastLedgerSequence` (the
    /// tx-expiry window). ONE deadline per leg.
    #[arg(long, default_value_t = 75)]
    last_ledger_window: u32,

    /// Current THORChain Asgard inbound (classic r-address). Operator
    /// refreshes from `/thorchain/inbound_addresses` before each run.
    #[arg(long)]
    vault: String,

    /// `rippled` JSON-RPC URL (account / ledger + submit).
    #[arg(long)]
    rpc_url: String,

    /// Signer-daemon base URLs (CSV), one per cosigner.
    #[arg(long)]
    signer_daemons: String,

    /// Each daemon's disclosed member pubkey (CSV of 0x33-byte hex, aligned
    /// with `--signer-daemons`).
    #[arg(long)]
    signer_pubkeys: String,

    /// THORChain swap memo carried in `Memos[0].MemoData`.
    #[arg(long)]
    memo: String,

    /// Native send amount in drops.
    #[arg(long)]
    amount: u128,

    /// If set, broadcast the assembled tx-blob via `submit`.
    #[arg(long, default_value_t = false)]
    broadcast: bool,
}

fn parse_pubkey33(field: &str, hex: &str) -> Result<[u8; 33]> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes =
        alloy_primitives::hex::decode(stripped).with_context(|| format!("{field}: bad hex"))?;
    bytes.as_slice().try_into().map_err(|_| {
        anyhow!(
            "{field}: expected 33-byte compressed pubkey, got {}",
            bytes.len()
        )
    })
}

fn parse_csv_pubkeys(field: &str, csv: &str) -> Result<Vec<[u8; 33]>> {
    csv.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .enumerate()
        .map(|(i, s)| parse_pubkey33(&format!("{field}[{i}]"), s))
        .collect()
}

/// Signer-daemon-backed [`XrpCosigner`]. Posts the [`XrpTxSignRequest`] to
/// `/api/v1/sign/xrp-tx`; verifies the daemon's response pubkey matches the
/// pinned member pubkey; returns the DER signature.
struct RemoteXrpCosigner {
    base_url: String,
    pubkey: [u8; 33],
    client: reqwest::Client,
}

impl XrpCosigner for RemoteXrpCosigner {
    fn member_pubkey(&self) -> [u8; 33] {
        self.pubkey
    }
    fn sign_xrp_tx<'a>(&'a self, req: &'a XrpTxSignRequest) -> SignXrpFuture<'a> {
        let url = format!("{}/api/v1/sign/xrp-tx", self.base_url);
        let client = self.client.clone();
        let pinned = self.pubkey;
        let pin_hex = format!("0x{}", alloy_primitives::hex::encode(pinned));
        let body = req.clone();
        Box::pin(async move {
            let err = |message: String| XrpRedeemError::Cosigner {
                pubkey: pin_hex.clone(),
                message,
            };
            let resp = client
                .post(&url)
                .json(&body)
                .send()
                .await
                .map_err(|e| err(format!("transport: {e}")))?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(err(format!("HTTP {status}: {text}")));
            }
            let parsed: XrpSignResponse =
                resp.json().await.map_err(|e| err(format!("decode: {e}")))?;
            let ret_hex = parsed.pubkey.strip_prefix("0x").unwrap_or(&parsed.pubkey);
            let ret = alloy_primitives::hex::decode(ret_hex)
                .map_err(|e| err(format!("bad pubkey hex: {e}")))?;
            if ret.as_slice() != pinned.as_slice() {
                return Err(err(format!("daemon returned wrong pubkey: 0x{ret_hex}")));
            }
            let sig_hex = parsed
                .signature
                .strip_prefix("0x")
                .unwrap_or(&parsed.signature);
            alloy_primitives::hex::decode(sig_hex).map_err(|e| err(format!("bad sig hex: {e}")))
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let chain: ChainId = args.chain.parse().map_err(|e| anyhow!("--chain: {e}"))?;
    let members = parse_csv_pubkeys("--member-pubkeys", &args.member_pubkeys)?;
    let multisig = XrpMultisig::new(
        args.quorum,
        members.into_iter().map(|pk| (pk, 1u16)).collect(),
    )
    .map_err(|e| anyhow!("multisig descriptor: {e}"))?;

    let signer_daemons: Vec<&str> = args.signer_daemons.split(',').map(str::trim).collect();
    let signer_pubkeys = parse_csv_pubkeys("--signer-pubkeys", &args.signer_pubkeys)?;
    if signer_daemons.len() != signer_pubkeys.len() {
        return Err(anyhow!(
            "--signer-daemons ({}) and --signer-pubkeys ({}) must align 1-to-1",
            signer_daemons.len(),
            signer_pubkeys.len()
        ));
    }

    let xrp = Arc::new(
        ReqwestXrpChainClient::new(chain, &args.rpc_url).map_err(|e| anyhow!("xrp client: {e}"))?,
    );

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("reqwest client")?;
    let cosigners: Vec<Box<dyn XrpCosigner>> = signer_daemons
        .iter()
        .zip(signer_pubkeys.iter())
        .map(|(url, pk)| -> Box<dyn XrpCosigner> {
            Box::new(RemoteXrpCosigner {
                base_url: (*url).to_string(),
                pubkey: *pk,
                client: http.clone(),
            })
        })
        .collect();

    let cfg = XrpRedeemConfig {
        chain,
        multisig,
        account_address: args.multisig_address,
        fee_drops: args.fee_drops,
        last_ledger_window: args.last_ledger_window,
        vault: args.vault,
    };
    let executor =
        XrpRedeemExecutor::new(cfg, xrp.clone(), cosigners, Arc::new(XrpLockTable::new()))
            .map_err(|e| anyhow!("executor construct: {e}"))?;

    let leg = XrpRedeemTask {
        dispatch_id: alloy_primitives::B256::ZERO,
        redemption_id: alloy_primitives::B256::ZERO,
        chain,
        memo: args.memo,
        send_amount: args.amount,
    };
    info!(?chain, "build_leg start");
    let outcome = executor
        .build_leg(&leg)
        .await
        .map_err(|e| anyhow!("build_leg: {e}"))?;

    println!("sequence: {}", outcome.sequence);
    println!("last_ledger_sequence: {}", outcome.last_ledger_sequence);
    println!("account: {}", outcome.account_address);
    println!(
        "tx_blob: 0x{}",
        alloy_primitives::hex::encode(&outcome.tx_blob)
    );

    if args.broadcast {
        let result = xrp
            .submit_tx_blob(&outcome.tx_blob)
            .await
            .map_err(|e| anyhow!("submit: {e}"))?;
        println!("engine_result: {}", result.engine_result);
        println!("txhash: {}", result.txhash);
        if !result.accepted() {
            return Err(anyhow!(
                "submit not provisionally applied: {}",
                result.engine_result
            ));
        }
        info!(txhash = %result.txhash, "submit provisionally applied (tesSUCCESS)");
    } else {
        info!("tx-blob built — broadcast deferred (--broadcast to submit; rippled byte-match gate pending)");
    }

    Ok(())
}
