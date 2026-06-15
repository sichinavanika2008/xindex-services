//! `xindex-redeem-cosmos` — Phase 3.3 Cosmos redeem executor binary.
//!
//! Reads `{account_number, sequence}` for our `LegacyAminoPubKey` multisig
//! from a Cosmos node, drives the 3-of-5 `MsgSend` flow (via
//! [`CosmosRedeemExecutor`]) to the THORChain Asgard inbound with the
//! contract-emitted swap memo, and emits the broadcast-ready `TxRaw`.
//!
//! ## v1 scope
//!
//! Single-leg CLI skeleton (parity with `xindex-redeem-evm`). It builds +
//! aggregates the multisig tx and prints the `TxRaw` hex; `--broadcast`
//! optionally posts it via `broadcast_tx_sync`. The event-driven loop
//! (RedeemDispatched → build → broadcast → record the F2 `gaia` dispatch
//! row) and the live `gaiad` byte-match validation are C9 / signet-
//! rehearsal territory.

#![expect(
    clippy::print_stdout,
    reason = "CLI binary — println is the user interface"
)]
#![expect(
    clippy::doc_markdown,
    reason = "CosmosTxSignRequest / LegacyAminoPubKey / TxRaw identifiers in \
              module docs — backticks add noise"
)]

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::info;
use xindex_chain_cosmos::{CosmosChainClient, ReqwestCosmosChainClient};
use xindex_cosmos_tx::CosmosMultisig;
use xindex_executor::cosmos_redeem::{
    CosmosCosigner, CosmosLockTable, CosmosRedeemConfig, CosmosRedeemError, CosmosRedeemExecutor,
    CosmosRedeemTask, SignCosmosFuture,
};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{CosmosSignResponse, CosmosTxSignRequest};

/// CLI for a single Cosmos redeem leg.
#[derive(Debug, Parser)]
#[command(name = "xindex-redeem-cosmos", version)]
struct Args {
    /// Destination chain (gaia).
    #[arg(long, default_value = "gaia")]
    chain: String,

    /// The multisig bech32 account address (sanity-checked against the
    /// address derived from `--member-pubkeys` + `--threshold`).
    #[arg(long)]
    multisig_address: String,

    /// All ordered member compressed pubkeys (CSV of 0x33-byte hex). Order
    /// is the frozen ceremony order — never reorder.
    #[arg(long)]
    member_pubkeys: String,

    /// Multisig threshold (k-of-n; 3 for our 3-of-5).
    #[arg(long, default_value_t = 3)]
    threshold: u32,

    /// Consensus chain-id (e.g. `cosmoshub-4`).
    #[arg(long)]
    cosmos_chain_id: String,

    /// Native micro-denom.
    #[arg(long, default_value = "uatom")]
    denom: String,

    /// Bech32 human-readable prefix for the multisig account address
    /// (`cosmos` for GAIA, `noble` for Noble).
    #[arg(long, default_value = "cosmos")]
    bech32_hrp: String,

    /// Fee amount in the micro-unit.
    #[arg(long)]
    fee_amount: u128,

    /// Gas limit.
    #[arg(long, default_value_t = 200_000)]
    gas_limit: u64,

    /// Current THORChain Asgard inbound (bech32). Operator refreshes from
    /// `/thorchain/inbound_addresses` before each run.
    #[arg(long)]
    vault: String,

    /// Tendermint RPC URL (account/sequence + broadcast).
    #[arg(long)]
    rpc_url: String,

    /// Cosmos REST URL (auth account lookup).
    #[arg(long)]
    rest_url: String,

    /// Signer-daemon base URLs (CSV), one per cosigner.
    #[arg(long)]
    signer_daemons: String,

    /// Each daemon's disclosed member pubkey (CSV of 0x33-byte hex, aligned
    /// with `--signer-daemons`).
    #[arg(long)]
    signer_pubkeys: String,

    /// THORChain swap memo carried in the tx memo.
    #[arg(long)]
    memo: String,

    /// Native send amount in the micro-unit.
    #[arg(long)]
    amount: u128,

    /// If set, broadcast the assembled TxRaw via `broadcast_tx_sync`.
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

/// Signer-daemon-backed [`CosmosCosigner`]. Posts the
/// [`CosmosTxSignRequest`] to `/api/v1/sign/cosmos-tx`; verifies the
/// daemon's response pubkey matches the pinned member pubkey.
struct RemoteCosmosCosigner {
    base_url: String,
    pubkey: [u8; 33],
    client: reqwest::Client,
}

impl CosmosCosigner for RemoteCosmosCosigner {
    fn member_pubkey(&self) -> [u8; 33] {
        self.pubkey
    }
    fn sign_cosmos_tx<'a>(&'a self, req: &'a CosmosTxSignRequest) -> SignCosmosFuture<'a> {
        let url = format!("{}/api/v1/sign/cosmos-tx", self.base_url);
        let client = self.client.clone();
        let pinned = self.pubkey;
        let pin_hex = format!("0x{}", alloy_primitives::hex::encode(pinned));
        let body = req.clone();
        Box::pin(async move {
            let err = |message: String| CosmosRedeemError::Cosigner {
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
            let parsed: CosmosSignResponse =
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
            let arr: [u8; 64] = sig
                .as_slice()
                .try_into()
                .map_err(|_| err(format!("sig not 64 bytes: got {}", sig.len())))?;
            Ok(arr)
        })
    }
}

#[tokio::main]
#[expect(
    clippy::too_many_lines,
    reason = "rustfmt 1.9.0 line-wrapping expanded this CLI driver past the 100-line \
              lint (106); logic unchanged, splitting it would not aid readability"
)]
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
    let multisig = CosmosMultisig::new(args.threshold, members, args.bech32_hrp.as_str())
        .map_err(|e| anyhow!("multisig descriptor: {e}"))?;
    let derived = multisig
        .account_address()
        .map_err(|e| anyhow!("address derivation: {e}"))?;
    if derived != args.multisig_address {
        return Err(anyhow!(
            "derived multisig address {derived} != --multisig-address {}",
            args.multisig_address
        ));
    }

    let signer_daemons: Vec<&str> = args.signer_daemons.split(',').map(str::trim).collect();
    let signer_pubkeys = parse_csv_pubkeys("--signer-pubkeys", &args.signer_pubkeys)?;
    if signer_daemons.len() != signer_pubkeys.len() {
        return Err(anyhow!(
            "--signer-daemons ({}) and --signer-pubkeys ({}) must align 1-to-1",
            signer_daemons.len(),
            signer_pubkeys.len()
        ));
    }

    let cosmos = Arc::new(
        ReqwestCosmosChainClient::new(chain, &args.cosmos_chain_id, &args.rpc_url, &args.rest_url)
            .map_err(|e| anyhow!("cosmos client: {e}"))?,
    );

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("reqwest client")?;
    let cosigners: Vec<Box<dyn CosmosCosigner>> = signer_daemons
        .iter()
        .zip(signer_pubkeys.iter())
        .map(|(url, pk)| -> Box<dyn CosmosCosigner> {
            Box::new(RemoteCosmosCosigner {
                base_url: (*url).to_string(),
                pubkey: *pk,
                client: http.clone(),
            })
        })
        .collect();

    let cfg = CosmosRedeemConfig {
        chain,
        multisig,
        account_address: derived,
        cosmos_chain_id: args.cosmos_chain_id,
        denom: args.denom,
        fee_amount: args.fee_amount,
        gas_limit: args.gas_limit,
        vault: args.vault,
    };
    let executor = CosmosRedeemExecutor::new(
        cfg,
        cosmos.clone(),
        cosigners,
        Arc::new(CosmosLockTable::new()),
    )
    .map_err(|e| anyhow!("executor construct: {e}"))?;

    let leg = CosmosRedeemTask {
        dispatch_id: alloy_primitives::B256::ZERO,
        redemption_id: alloy_primitives::B256::ZERO,
        chain,
        memo: args.memo,
        send_amount: args.amount,
        // CTD-1: certificate supplied by the observer/relay (Slice B);
        // None is refused daemon-side (fail closed).
        intent_proof: None,
    };
    info!(?chain, "build_leg start");
    let outcome = executor
        .build_leg(&leg)
        .await
        .map_err(|e| anyhow!("build_leg: {e}"))?;

    println!(
        "sign_doc_hash: 0x{}",
        alloy_primitives::hex::encode(outcome.sign_doc_hash)
    );
    println!("sequence: {}", outcome.sequence);
    println!("account: {}", outcome.account_address);
    println!(
        "tx_raw: 0x{}",
        alloy_primitives::hex::encode(&outcome.tx_raw)
    );

    if args.broadcast {
        let result = cosmos
            .broadcast_tx_sync(&outcome.tx_raw)
            .await
            .map_err(|e| anyhow!("broadcast: {e}"))?;
        println!("broadcast_code: {}", result.code);
        println!("broadcast_txhash: {}", result.txhash);
        if !result.accepted() {
            return Err(anyhow!(
                "CheckTx rejected (code {}): {}",
                result.code,
                result.log
            ));
        }
        info!(txhash = %result.txhash, "broadcast accepted to mempool");
    } else {
        info!("TxRaw built — broadcast deferred (--broadcast to submit; gaiad byte-match gate pending)");
    }

    Ok(())
}
