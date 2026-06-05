//! `xindex-redeem-tron` — Phase 4.6 TRON redeem executor binary.
//!
//! Reads the current block (TAPOS reference) from a TRON full node, drives
//! the native account-permission k-of-n multisig flow (via
//! [`TronRedeemExecutor`]) to the THORChain Asgard inbound with the
//! contract-emitted swap memo, and emits the broadcast-ready signed
//! `Transaction` protobuf hex.
//!
//! ## v1 scope
//!
//! Single-leg CLI skeleton (parity with `xindex-redeem-xrp`). It builds and
//! aggregates the multisig tx and prints the tx hex; `--broadcast`
//! optionally posts it via `broadcasthex`. The event-driven loop
//! (RedeemDispatched → build → broadcast → record the `tron` dispatch row)
//! and the live `tronweb` / `java-tron` byte-match validation are
//! follow-on / testnet-rehearsal territory (KNOWN_FINDINGS P-TRON-1).

#![expect(
    clippy::print_stdout,
    reason = "CLI binary — println is the user interface"
)]
#![expect(
    clippy::doc_markdown,
    reason = "TronTxSignRequest / TransferContract / raw_data identifiers in module \
              docs — backticks add noise"
)]

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::info;
use xindex_chain_tron::{ReqwestTronChainClient, TronChainClient};
use xindex_executor::tron_redeem::{
    SignTronFuture, TronCosigner, TronRedeemConfig, TronRedeemError, TronRedeemExecutor,
    TronRedeemTask,
};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{TronAssetKind, TronSignResponse, TronTxSignRequest};
use xindex_tron_tx::TronMultisig;

/// CLI for a single TRON redeem leg.
#[derive(Debug, Parser)]
#[command(name = "xindex-redeem-tron", version)]
struct Args {
    /// Destination chain (tron).
    #[arg(long, default_value = "tron")]
    chain: String,

    /// The funded multisig account (base58check `T…` address). Used
    /// directly — the TRON account is NOT derived from the member set.
    #[arg(long)]
    multisig_address: String,

    /// All member compressed pubkeys (CSV of 0x33-byte hex). Each is given
    /// weight 1 (our k-of-n ceremony). The descriptor sorts them by address.
    #[arg(long)]
    member_pubkeys: String,

    /// Signer threshold (k-of-n; 3 for our 3-of-5, weight-1 each).
    #[arg(long, default_value_t = 3)]
    threshold: u64,

    /// The active `Permission.id` the multisig signs under (≥ 2).
    #[arg(long, default_value_t = 2)]
    permission_id: u32,

    /// Asset to send: `trx` (native) or `usdt` (TRC20).
    #[arg(long, default_value = "trx")]
    asset: String,

    /// `usdt` only: the TRC20 contract address (base58 `T…`).
    #[arg(long)]
    contract_address: Option<String>,

    /// `usdt` only: the `fee_limit` (energy cap) in sun.
    #[arg(long, default_value_t = 0)]
    fee_limit: u64,

    /// Milliseconds added to the block timestamp for `expiration` (the
    /// TAPOS deadline window; THORChain uses 20 min = 1_200_000).
    #[arg(long, default_value_t = 1_200_000)]
    expiration_window_ms: u64,

    /// Current THORChain Asgard inbound (base58 `T…` address). Operator
    /// refreshes from `/thorchain/inbound_addresses` before each run.
    #[arg(long)]
    vault: String,

    /// TRON full-node base URL (e.g. `https://api.trongrid.io`).
    #[arg(long)]
    rpc_url: String,

    /// Signer-daemon base URLs (CSV), one per cosigner.
    #[arg(long)]
    signer_daemons: String,

    /// Each daemon's disclosed member pubkey (CSV of 0x33-byte hex, aligned
    /// with `--signer-daemons`).
    #[arg(long)]
    signer_pubkeys: String,

    /// THORChain swap memo carried in `raw_data.data`.
    #[arg(long)]
    memo: String,

    /// Native send amount (sun for TRX, 6-decimal base units for USDT).
    #[arg(long)]
    amount: u128,

    /// If set, broadcast the assembled tx via `broadcasthex`.
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

fn parse_asset(s: &str) -> Result<TronAssetKind> {
    match s.to_ascii_lowercase().as_str() {
        "trx" => Ok(TronAssetKind::Trx),
        "usdt" => Ok(TronAssetKind::Usdt),
        other => Err(anyhow!("--asset: expected 'trx' or 'usdt', got '{other}'")),
    }
}

/// Signer-daemon-backed [`TronCosigner`]. Posts the [`TronTxSignRequest`] to
/// `/api/v1/sign/tron-tx`; verifies the daemon's response pubkey matches the
/// pinned member pubkey; returns the 65-byte recoverable signature.
struct RemoteTronCosigner {
    base_url: String,
    pubkey: [u8; 33],
    client: reqwest::Client,
}

impl TronCosigner for RemoteTronCosigner {
    fn member_pubkey(&self) -> [u8; 33] {
        self.pubkey
    }
    fn sign_tron_tx<'a>(&'a self, req: &'a TronTxSignRequest) -> SignTronFuture<'a> {
        let url = format!("{}/api/v1/sign/tron-tx", self.base_url);
        let client = self.client.clone();
        let pinned = self.pubkey;
        let pin_hex = format!("0x{}", alloy_primitives::hex::encode(pinned));
        let body = req.clone();
        Box::pin(async move {
            let err = |message: String| TronRedeemError::Cosigner {
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
            let parsed: TronSignResponse =
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
            let sig = alloy_primitives::hex::decode(sig_hex)
                .map_err(|e| err(format!("bad sig hex: {e}")))?;
            sig.as_slice()
                .try_into()
                .map_err(|_| err(format!("expected 65-byte signature, got {}", sig.len())))
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
    let asset = parse_asset(&args.asset)?;
    let members = parse_csv_pubkeys("--member-pubkeys", &args.member_pubkeys)?;
    let multisig = TronMultisig::new(
        args.threshold,
        args.permission_id,
        members.into_iter().map(|pk| (pk, 1u64)).collect(),
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

    let tron = Arc::new(
        ReqwestTronChainClient::new(chain, &args.rpc_url)
            .map_err(|e| anyhow!("tron client: {e}"))?,
    );

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("reqwest client")?;
    let cosigners: Vec<Box<dyn TronCosigner>> = signer_daemons
        .iter()
        .zip(signer_pubkeys.iter())
        .map(|(url, pk)| -> Box<dyn TronCosigner> {
            Box::new(RemoteTronCosigner {
                base_url: (*url).to_string(),
                pubkey: *pk,
                client: http.clone(),
            })
        })
        .collect();

    let cfg = TronRedeemConfig {
        chain,
        multisig,
        owner_address: args.multisig_address,
        vault: args.vault,
        asset,
        contract_address: args.contract_address,
        fee_limit: args.fee_limit,
        expiration_window_ms: args.expiration_window_ms,
    };
    let executor = TronRedeemExecutor::new(cfg, tron.clone(), cosigners)
        .map_err(|e| anyhow!("executor construct: {e}"))?;

    let leg = TronRedeemTask {
        dispatch_id: alloy_primitives::B256::ZERO,
        redemption_id: alloy_primitives::B256::ZERO,
        chain,
        memo: args.memo,
        send_amount: args.amount,
    };
    info!(?chain, ?asset, "build_leg start");
    let outcome = executor
        .build_leg(&leg)
        .await
        .map_err(|e| anyhow!("build_leg: {e}"))?;

    println!("owner: {}", outcome.owner_address);
    println!("txid: {}", outcome.txid);
    println!("tx: 0x{}", outcome.tx_hex);

    if args.broadcast {
        let result = tron
            .broadcast_hex(&outcome.tx_hex)
            .await
            .map_err(|e| anyhow!("broadcast: {e}"))?;
        println!("result: {}", result.result);
        println!("code: {}", result.code);
        println!("txid: {}", result.txid);
        if !result.accepted() {
            return Err(anyhow!("broadcast not accepted: {}", result.code));
        }
        info!(code = %result.code, "broadcast accepted");
    } else {
        info!("tx built — broadcast deferred (--broadcast to submit; tronweb byte-match gate pending)");
    }

    Ok(())
}
