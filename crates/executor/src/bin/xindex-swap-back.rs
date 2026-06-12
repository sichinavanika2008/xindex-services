//! `xindex-swap-back` — operator-attended mint-cancel BTC swap-back
//! (CTD-1 Slice C execution flow, one-shot CLI).
//!
//! When a mint intent is cancelled after its USDT→BTC swap completed,
//! the acquired BTC sits orphaned at custody. An operator runs this
//! tool ONCE per cancel:
//!   1. builds the recovery memo `=:<asset>:<recovery dest>[:<lim>]`
//!      (destination = the ops/treasury Safe per `DL-CTD-C-1`);
//!   2. collects the k-of-n Acquire-Cancel Certificate from the
//!      per-operator observers (each pins the memo destination to its
//!      OWN configured recovery address and bounds the amount);
//!   3. pays the observers' AGREED Asgard inbound from the custody
//!      multisig, driving the HSM-backed cosigner daemons (each
//!      re-verifies the ACC statelessly and one-shots per
//!      `(chain, cancel_id)`);
//!   4. broadcasts and prints the txid.
//!
//! Sizing honesty (CTD-C-R1): `--amount-sats` is the OPERATOR's number,
//! read from custody observation (the orphaned UTXO) — NEVER from
//! `AcquireCancelled.amount` (non-authoritative USDT units, A1/A5).
//!
//! Remote-only by design: this tool moves real custody funds, so there
//! is no software-key mode. Attended one-shot ⇒ no re-broadcast
//! registry; if the tx sticks, re-running is safe (the daemons treat an
//! identical certificate idempotently and the spent UTXO self-dedups).

use std::str::FromStr;

use alloy_primitives::{B256, U256};
use anyhow::{bail, Context, Result};
use bitcoin::{Address, Network, PublicKey};
use clap::Parser;
use tracing::info;
use xindex_chain_utxo::{EsploraClient, UtxoParams};
use xindex_executor::remote_cosigner::RemoteMultisigCosigner;
use xindex_executor::{InProcessExecutor, MultisigCosigner, RicCollector, SwapBackTask};
use xindex_multisig::MultisigDescriptor;
use xindex_shared::chain_registry::ChainId;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Xindex one-shot mint-cancel BTC swap-back (CTD-1 Slice C)"
)]
struct Args {
    /// The `AcquireCancelled` cancel id (0x-prefixed bytes32 hex).
    #[arg(long)]
    cancel_id: String,

    /// Sats to swap back — from custody observation of the orphaned
    /// UTXO, NEVER from the cancel event's USDT-unit amount (A1/A5).
    #[arg(long)]
    amount_sats: u64,

    /// The recovery destination (the ops/treasury Safe, DL-CTD-C-1).
    /// Must match every observer's pinned `CANCEL_RECOVERY_DEST`.
    #[arg(long, env = "CANCEL_RECOVERY_DEST")]
    recovery_dest: String,

    /// `THORChain` swap-back asset (stagenet differs from mainnet).
    #[arg(long, env = "SWAP_BACK_ASSET", default_value = "ETH.USDT")]
    swap_back_asset: String,

    /// Optional `THORChain` limit field (`LIM` / streaming spec)
    /// appended as the memo's 4th field.
    #[arg(long)]
    lim: Option<String>,

    /// Per-operator observer base URLs, comma-separated.
    #[arg(long, env = "OBSERVER_URLS")]
    observer_urls: String,

    /// k of the k-of-n ACC quorum (must match the daemons' policy).
    #[arg(long, env = "INTENT_QUORUM")]
    quorum: usize,

    /// Esplora base URL for UTXO lookup + broadcast.
    #[arg(long, env = "ESPLORA_URL")]
    esplora_url: String,

    /// Bitcoin network (`bitcoin` | `signet` | `testnet` | `regtest`).
    #[arg(long, env = "BTC_NETWORK", default_value = "signet")]
    btc_network: String,

    /// The custody multisig's N compressed pubkeys, comma-separated
    /// (ceremony-disclosed Set A).
    #[arg(long, env = "MULTISIG_PUBKEYS")]
    multisig_pubkeys: String,

    /// The custody multisig threshold K.
    #[arg(long, env = "MULTISIG_THRESHOLD")]
    multisig_threshold: usize,

    /// Cosigner daemon base URLs, comma-separated (≥ threshold).
    #[arg(long, env = "COSIGNER_DAEMON_URLS")]
    cosigner_daemon_urls: String,

    /// Each daemon's disclosed BTC pubkey, comma-separated, aligned
    /// with --cosigner-daemon-urls.
    #[arg(long, env = "COSIGNER_PUBKEYS")]
    cosigner_pubkeys: String,

    /// Flat fee budget in sats (operator checks the mempool first —
    /// attended tool, no estimator).
    #[arg(long, env = "BTC_FEE_SATS", default_value_t = 5_000)]
    fee_sats: u64,
}

fn parse_network(s: &str) -> Result<Network> {
    match s {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "signet" => Ok(Network::Signet),
        "testnet" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        other => bail!("unknown btc_network: {other}"),
    }
}

fn parse_b256(s: &str) -> Result<B256> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = alloy_primitives::hex::decode(stripped).context("cancel_id hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("cancel_id must be 32 bytes"))?;
    Ok(B256::from(arr))
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

#[expect(
    clippy::print_stdout,
    reason = "operator CLI: the broadcast txid IS the program's output contract"
)]
fn main() -> Result<()> {
    tracing_subscriber::fmt().json().init();
    let args = Args::parse();

    let cancel_id = parse_b256(&args.cancel_id)?;
    let network = parse_network(&args.btc_network)?;
    if args.amount_sats == 0 {
        bail!("--amount-sats must be > 0");
    }
    // Canonical recovery memo. The observers re-validate the grammar
    // and pin the destination; building it here just keeps the operator
    // from typo-ing the structure.
    let recovery = args.recovery_dest.to_lowercase();
    let mut memo = format!("=:{}:{recovery}", args.swap_back_asset);
    if let Some(lim) = &args.lim {
        memo.push(':');
        memo.push_str(lim);
    }

    // 1) Collect the k-of-n ACC from the per-operator observers.
    let collector = RicCollector::new(split_csv(&args.observer_urls), args.quorum)
        .context("observer collector")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let collected = collector
        .collect_acc(
            ChainId::Btc,
            cancel_id,
            &args.amount_sats.to_string(),
            &memo,
            now,
        )
        .context("collect k-of-n ACC")?;
    info!(
        asgard = %collected.asgard_address,
        signatures = collected.proof.signatures.len(),
        "ACC quorum collected"
    );

    // 2) Pay the observers' AGREED Asgard (the address whose hash the
    //    certificate binds) — never an independently-resolved one.
    let asgard = Address::from_str(&collected.asgard_address)
        .context("agreed Asgard address parse")?
        .require_network(network)
        .context("agreed Asgard network")?;

    // 3) Custody executor over HSM-backed remote cosigners.
    let pubkeys: Vec<PublicKey> = split_csv(&args.multisig_pubkeys)
        .iter()
        .map(|p| PublicKey::from_str(p).context("multisig pubkey"))
        .collect::<Result<_>>()?;
    let descriptor = MultisigDescriptor::new_p2wsh(args.multisig_threshold, &pubkeys)
        .map_err(|e| anyhow::anyhow!("descriptor: {e}"))?;
    let urls = split_csv(&args.cosigner_daemon_urls);
    let cosigner_pks: Vec<PublicKey> = split_csv(&args.cosigner_pubkeys)
        .iter()
        .map(|p| PublicKey::from_str(p).context("cosigner pubkey"))
        .collect::<Result<_>>()?;
    if urls.len() != cosigner_pks.len() {
        bail!(
            "{} cosigner URLs but {} pubkeys",
            urls.len(),
            cosigner_pks.len()
        );
    }
    let cosigners: Vec<Box<dyn MultisigCosigner>> = urls
        .into_iter()
        .zip(cosigner_pks)
        .map(|(url, pk)| {
            Box::new(RemoteMultisigCosigner::new(ChainId::Btc, url, pk))
                as Box<dyn MultisigCosigner>
        })
        .collect();
    let chain = EsploraClient::for_chain(
        UtxoParams::for_chain(ChainId::Btc),
        network,
        &args.esplora_url,
    );
    let executor =
        InProcessExecutor::with_cosigners(descriptor, cosigners, chain, network, args.fee_sats)
            .map_err(|e| anyhow::anyhow!("executor: {e}"))?;

    // 4) Execute + broadcast.
    let task = SwapBackTask {
        cancel_id,
        amount: U256::from(args.amount_sats),
        memo: memo.into_bytes(),
        proof: collected.proof,
    };
    let txid = executor
        .execute_swap_back(&task, &asgard)
        .map_err(|e| anyhow::anyhow!("swap-back execution: {e}"))?;
    println!("{txid}");
    Ok(())
}
