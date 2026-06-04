//! `xindex-redeem-solana` — Phase 4.5 Solana (Squads V4) redeem executor.
//!
//! Drives the `1 + threshold + 1` Squads choreography (propose → approve×T
//! → execute) that sends native SOL from our vault PDA to the user's own
//! Solana address, via [`SolanaRedeemExecutor`]. Unlike the single-tx XRP /
//! Cosmos binaries, the executor itself broadcasts + confirms each step, so
//! `--broadcast` is required to move funds; without it the binary prints
//! the derived PDAs (a dry-run that touches no chain state).
//!
//! ## v1 scope
//!
//! Single-leg CLI skeleton (parity with `xindex-redeem-xrp`). The
//! event-driven loop (RedeemDispatched → execute_redeem → record the `sol`
//! dispatch row) and the live Squads-JS byte-match are devnet-rehearsal
//! territory (KNOWN_FINDINGS P-SOL-1/3).

#![expect(
    clippy::print_stdout,
    reason = "CLI binary — println is the user interface"
)]
#![expect(
    clippy::doc_markdown,
    reason = "Squads / SolanaTxSignRequest identifiers in module docs — \
              backticks add noise"
)]

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::info;
use xindex_chain_solana::ReqwestSolanaChainClient;
use xindex_executor::solana_redeem::{
    SignSolanaFuture, SolanaCosigner, SolanaLockTable, SolanaMemberSig, SolanaRedeemConfig,
    SolanaRedeemError, SolanaRedeemExecutor, SolanaRedeemTask,
};
use xindex_executor::solana_redeem_store::{
    InMemorySolanaRedeemStore, SolanaRedeemStore, SqliteSolanaRedeemStore,
};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{SolanaSignResponse, SolanaTxSignRequest};
use xindex_solana_tx::{squads, Pubkey};

/// CLI for a single Solana redeem leg.
#[derive(Debug, Parser)]
#[command(name = "xindex-redeem-solana", version)]
struct Args {
    /// Destination chain (sol).
    #[arg(long, default_value = "sol")]
    chain: String,

    /// The Squads multisig PDA (base58). NOT derived from the member set —
    /// it is a function of the one-time create_key (see the key ceremony).
    #[arg(long)]
    multisig_address: String,

    /// All member ed25519 pubkeys (CSV of base58). The on-chain threshold
    /// is re-checked against `--threshold`.
    #[arg(long)]
    member_pubkeys: String,

    /// Approval threshold (k-of-n; 3 for our 3-of-5).
    #[arg(long, default_value_t = 3)]
    threshold: u16,

    /// The vault index whose PDA holds the SOL (always 0 for Xindex).
    #[arg(long, default_value_t = 0)]
    vault_index: u8,

    /// Solana JSON-RPC URL.
    #[arg(long)]
    rpc_url: String,

    /// Signer-daemon base URLs (CSV), one per cosigner.
    #[arg(long)]
    signer_daemons: String,

    /// Each daemon's disclosed member pubkey (CSV of base58, aligned with
    /// `--signer-daemons`).
    #[arg(long)]
    signer_pubkeys: String,

    /// THORChain swap memo carried in the SPL-Memo instruction.
    #[arg(long)]
    memo: String,

    /// Native send amount in lamports.
    #[arg(long)]
    amount: u128,

    /// The user's own Solana address (base58) — the transfer destination.
    #[arg(long)]
    destination: String,

    /// `DATABASE_URL` for the sqlite recovery store; in-memory if omitted.
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,

    /// If set, drive the full choreography (moves funds). Without it, the
    /// binary prints the derived PDAs and exits.
    #[arg(long, default_value_t = false)]
    broadcast: bool,
}

fn parse_pubkey(field: &str, s: &str) -> Result<Pubkey> {
    Pubkey::from_base58(s.trim()).map_err(|e| anyhow!("{field}: {e}"))
}

fn parse_csv_pubkeys(field: &str, csv: &str) -> Result<Vec<Pubkey>> {
    csv.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .enumerate()
        .map(|(i, s)| parse_pubkey(&format!("{field}[{i}]"), s))
        .collect()
}

/// Signer-daemon-backed [`SolanaCosigner`]. Posts the [`SolanaTxSignRequest`]
/// to `/api/v1/sign/solana-tx`; verifies the daemon's response pubkey
/// matches the pinned member pubkey; returns the 64-byte ed25519 signature.
struct RemoteSolanaCosigner {
    base_url: String,
    pubkey: Pubkey,
    client: reqwest::Client,
}

impl SolanaCosigner for RemoteSolanaCosigner {
    fn member_pubkey(&self) -> Pubkey {
        self.pubkey
    }
    fn sign_solana_tx<'a>(&'a self, req: &'a SolanaTxSignRequest) -> SignSolanaFuture<'a> {
        let url = format!("{}/api/v1/sign/solana-tx", self.base_url);
        let client = self.client.clone();
        let pinned = self.pubkey;
        let body = req.clone();
        Box::pin(async move {
            let err = |message: String| SolanaRedeemError::Cosigner {
                pubkey: pinned.to_base58(),
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
            let parsed: SolanaSignResponse =
                resp.json().await.map_err(|e| err(format!("decode: {e}")))?;
            let ret =
                Pubkey::from_base58(&parsed.pubkey).map_err(|e| err(format!("bad pubkey: {e}")))?;
            if ret != pinned {
                return Err(err(format!(
                    "daemon returned wrong pubkey: {}",
                    parsed.pubkey
                )));
            }
            let sig_hex = parsed
                .signature
                .strip_prefix("0x")
                .unwrap_or(&parsed.signature);
            let sig_bytes = alloy_primitives::hex::decode(sig_hex)
                .map_err(|e| err(format!("bad sig hex: {e}")))?;
            let signature: [u8; 64] = sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| err(format!("expected 64-byte sig, got {}", sig_bytes.len())))?;
            Ok(SolanaMemberSig {
                member_pubkey: pinned,
                signature,
            })
        })
    }
}

async fn run<S: SolanaRedeemStore>(
    cfg: SolanaRedeemConfig,
    sol: Arc<ReqwestSolanaChainClient>,
    cosigners: Vec<Box<dyn SolanaCosigner>>,
    store: Arc<S>,
    task: SolanaRedeemTask,
    broadcast: bool,
) -> Result<()> {
    let executor =
        SolanaRedeemExecutor::new(cfg, sol, cosigners, store, Arc::new(SolanaLockTable::new()))
            .map_err(|e| anyhow!("executor construct: {e}"))?;
    let multisig = executor.config().multisig_pda;
    let (vault, _) = squads::vault_pda(&multisig, executor.config().vault_index)
        .map_err(|e| anyhow!("vault pda: {e}"))?;
    println!("multisig_pda: {multisig}");
    println!("vault_pda: {vault}");

    if !broadcast {
        info!("dry-run — pass --broadcast to drive propose/approve/execute (moves funds)");
        return Ok(());
    }

    info!("execute_redeem start");
    let outcome = executor
        .execute_redeem(&task)
        .await
        .map_err(|e| anyhow!("execute_redeem: {e}"))?;
    println!("transaction_index: {}", outcome.transaction_index);
    println!("execute_signature: {}", outcome.execute_signature);
    info!(sig = %outcome.execute_signature, "redemption executed");
    Ok(())
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
    let multisig_pda = parse_pubkey("--multisig-address", &args.multisig_address)?;

    let signer_daemons: Vec<&str> = args.signer_daemons.split(',').map(str::trim).collect();
    let signer_pubkeys = parse_csv_pubkeys("--signer-pubkeys", &args.signer_pubkeys)?;
    if signer_daemons.len() != signer_pubkeys.len() {
        return Err(anyhow!(
            "--signer-daemons ({}) and --signer-pubkeys ({}) must align 1-to-1",
            signer_daemons.len(),
            signer_pubkeys.len()
        ));
    }

    let sol = Arc::new(
        ReqwestSolanaChainClient::new(chain, &args.rpc_url)
            .map_err(|e| anyhow!("solana client: {e}"))?,
    );
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("reqwest client")?;
    let cosigners: Vec<Box<dyn SolanaCosigner>> = signer_daemons
        .iter()
        .zip(signer_pubkeys.iter())
        .map(|(url, pk)| -> Box<dyn SolanaCosigner> {
            Box::new(RemoteSolanaCosigner {
                base_url: (*url).to_string(),
                pubkey: *pk,
                client: http.clone(),
            })
        })
        .collect();

    let cfg = SolanaRedeemConfig {
        chain,
        multisig_pda,
        vault_index: args.vault_index,
        members,
        threshold: args.threshold,
        confirm_poll: Duration::from_millis(1500),
        confirm_timeout: Duration::from_secs(90),
    };
    let task = SolanaRedeemTask {
        dispatch_id: alloy_primitives::B256::ZERO,
        redemption_id: alloy_primitives::B256::ZERO,
        chain,
        memo: args.memo,
        send_amount: args.amount,
        destination: args.destination,
    };

    if let Some(url) = args.database_url {
        let store = Arc::new(
            SqliteSolanaRedeemStore::connect(&url)
                .await
                .map_err(|e| anyhow!("sqlite store: {e}"))?,
        );
        run(cfg, sol, cosigners, store, task, args.broadcast).await
    } else {
        let store = Arc::new(InMemorySolanaRedeemStore::new());
        run(cfg, sol, cosigners, store, task, args.broadcast).await
    }
}
