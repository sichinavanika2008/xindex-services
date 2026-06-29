//! `xindex-redeem-evm` — Phase 3.2 EVM redeem executor binary.
//!
//! Watches the Ethereum `IndexToken` / `ThorchainAdapter` for an EVM-
//! family `RedeemDispatched` event, drives the Safe v1.4.1
//! `execTransaction` flow on the destination chain (via [`EvmRedeemExecutor`]),
//! and submits the wrapper transaction through an `alloy` `WalletProvider`.
//!
//! ## Backends
//!
//! Two mutually-exclusive subcommands select the custody backend:
//!
//! - `safe` — the Safe v1.4.1 + 3-of-5 cosigner-fleet flow ([`EvmRedeemExecutor`]).
//! - `turnkey` — the Turnkey single-key flow (`DL-CUSTODY-TURNKEY-1`,
//!   [`TurnkeyEvmRedeemExecutor`]). The EVM custody key is a single enclave
//!   EOA; the executor builds the tx + Turnkey signs the hash (gated by the
//!   approver-watcher) + assembles the raw signed tx, and this binary submits
//!   it. The unsigned spend is staged in a [`SqlitePrepareStore`] file shared
//!   with the `xindex-turnkey-approver` process.
//!
//! ## v1 scope
//!
//! This binary is a **skeleton** — it wires the executor up, exposes the CLI,
//! and drives a single leg. The end-to-end event-driven loop (RedeemDispatched
//! → build → submit → confirm → record) is V9's anvil-forked integration test
//! territory. Operators drive single legs via this CLI in the meantime.

#![expect(
    clippy::print_stdout,
    reason = "CLI binary — println is the user interface"
)]
#![expect(
    clippy::doc_markdown,
    reason = "EvmSafeTxSignRequest / WalletProvider / IndexToken \
              identifiers in module docs — backticks add noise"
)]

use std::sync::Arc;
use std::time::Duration;

use alloy::providers::{Provider, ProviderBuilder};
use alloy_primitives::{Address, B256, U256};
use anyhow::{anyhow, Context, Result};
use clap::{Args as ClapArgs, Parser, Subcommand};
use tracing::info;
use xindex_chain_evm::{AlloyEvmChainClient, EvmChainClient, EvmTxFee};
use xindex_custody_core::prepare::SqlitePrepareStore;
use xindex_executor::evm_redeem::{
    EvmCosigner, EvmRedeemConfig, EvmRedeemExecutor, EvmRedeemTask, SafeLockTable,
};
use xindex_executor::turnkey_evm_redeem::{TurnkeyEvmRedeemConfig, TurnkeyEvmRedeemExecutor};
use xindex_shared::chain_registry::ChainId;
use xindex_turnkey_client::{TurnkeyClient, TurnkeyStamper, TURNKEY_API_BASE};

/// CLI for a single EVM redeem leg. Production wraps this in a
/// long-running daemon (V9-era follow-up).
#[derive(Debug, Parser)]
#[command(name = "xindex-redeem-evm", version)]
struct Cli {
    #[command(subcommand)]
    backend: Backend,
}

/// Custody backend for the redeem leg.
#[derive(Debug, Subcommand)]
enum Backend {
    /// Safe v1.4.1 + 3-of-5 cosigner-fleet flow.
    Safe(SafeArgs),
    /// Turnkey single-key flow (DL-CUSTODY-TURNKEY-1).
    Turnkey(TurnkeyEvmArgs),
}

/// Arguments for the Safe-backed redeem leg.
#[derive(Debug, ClapArgs)]
struct SafeArgs {
    /// Destination chain (eth / bsc / avax / base / pol).
    #[arg(long)]
    chain: String,

    /// Safe proxy contract address on `chain`.
    #[arg(long)]
    safe_address: String,

    /// Configured Safe owners (CSV of 0x-hex addresses).
    #[arg(long)]
    safe_owners: String,

    /// Safe threshold (k-of-n; 3 for our 3-of-5).
    #[arg(long, default_value_t = 3)]
    safe_threshold: u8,

    /// Current THORChain Asgard vault address on `chain`. Operator
    /// refreshes from `inbound_addresses` before each run.
    #[arg(long)]
    vault: String,

    /// HTTPS RPC URL for `chain`.
    #[arg(long)]
    rpc_url: String,

    /// Submitter EOA — the address that signs + broadcasts the
    /// wrapper transaction. Must be funded with gas on `chain`.
    #[arg(long)]
    submitter_address: String,

    /// Signer-daemon base URLs (CSV, e.g.
    /// `http://node1:9101,http://node2:9101,...`). One per
    /// configured cosigner; the executor walks them in order until
    /// threshold is met.
    #[arg(long)]
    signer_daemons: String,

    /// Disclosed signer addresses, one per daemon (CSV, aligned with
    /// `--signer-daemons`).
    #[arg(long)]
    signer_addresses: String,

    /// Gas budget (units) for the wrapper transaction.
    #[arg(long, default_value_t = 600_000)]
    gas_limit: u64,

    /// EIP-1559 `max_fee_per_gas` (wei).
    #[arg(long)]
    max_fee_per_gas: u128,

    /// EIP-1559 `max_priority_fee_per_gas` (wei).
    #[arg(long)]
    max_priority_fee_per_gas: u128,

    /// Legacy `gas_price` (wei). Used only on BSC (DL-P3.2-4).
    #[arg(long, default_value_t = 0)]
    gas_price: u128,

    /// `depositWithExpiry` expiry, seconds from now.
    #[arg(long, default_value_t = 7200)]
    expiry_offset_secs: u64,

    /// THORChain swap memo carried in `depositWithExpiry`.
    #[arg(long)]
    memo: String,

    /// Native amount in wei the Safe is redeeming.
    #[arg(long)]
    amount_wei: String,
}

/// Arguments for the Turnkey-backed EVM redeem leg. The Turnkey API P-256
/// private key is read from the `XINDEX_TURNKEY_API_KEY` environment variable
/// (hex) — never an argv flag.
#[derive(Debug, ClapArgs)]
struct TurnkeyEvmArgs {
    /// Destination EVM chain (eth / bsc / avax / base / pol).
    #[arg(long)]
    chain: String,

    /// The Turnkey custody EOA address on `chain` — the `from` of the signed
    /// tx, whose account nonce this binary fetches.
    #[arg(long)]
    custody_address: String,

    /// The Turnkey `signWith` selector (private-key id / wallet-account address)
    /// for the custody key.
    #[arg(long)]
    sign_with: String,

    /// The Turnkey custody sub-organization id.
    #[arg(long)]
    organization_id: String,

    /// Current THORChain Asgard vault address on `chain`. Operator refreshes
    /// from `inbound_addresses` before each run.
    #[arg(long)]
    vault: String,

    /// HTTPS RPC URL for `chain` (nonce fetch + raw-tx submit).
    #[arg(long)]
    rpc_url: String,

    /// Shared sqlite URL for the bind-prepare store (e.g.
    /// `sqlite:///var/lib/xindex/prepare.db`). The `xindex-turnkey-approver`
    /// process reads the same DB to gate the signature.
    #[arg(long)]
    db: String,

    /// Turnkey API host. Defaults to the production API; the dev-env is a
    /// sub-org on the same host.
    #[arg(long, default_value_t = TURNKEY_API_BASE.to_string())]
    turnkey_host: String,

    /// Gas budget (units) for the tx.
    #[arg(long, default_value_t = 300_000)]
    gas_limit: u64,

    /// EIP-1559 `max_fee_per_gas` (wei).
    #[arg(long, default_value_t = 0)]
    max_fee_per_gas: u128,

    /// EIP-1559 `max_priority_fee_per_gas` (wei).
    #[arg(long, default_value_t = 0)]
    max_priority_fee_per_gas: u128,

    /// Legacy `gas_price` (wei). Used only on BSC (DL-P3.2-4).
    #[arg(long, default_value_t = 0)]
    gas_price: u128,

    /// `depositWithExpiry` expiry, seconds from now.
    #[arg(long, default_value_t = 7200)]
    expiry_offset_secs: u64,

    /// Seconds between Turnkey activity-status polls.
    #[arg(long, default_value_t = 5)]
    poll_interval_secs: u64,

    /// Max status polls before timing out.
    #[arg(long, default_value_t = 60)]
    poll_max_attempts: u32,

    /// Originating dispatch id (32-byte hex). Defaults to zero for a manual
    /// drive; pass a distinct id per re-drive.
    #[arg(
        long,
        default_value = "0x0000000000000000000000000000000000000000000000000000000000000000"
    )]
    dispatch_id: String,

    /// Originating redemption id (32-byte hex) for attestation correlation.
    #[arg(
        long,
        default_value = "0x0000000000000000000000000000000000000000000000000000000000000000"
    )]
    redemption_id: String,

    /// THORChain swap memo carried in `depositWithExpiry`.
    #[arg(long)]
    memo: String,

    /// Native amount in wei the custody key is redeeming.
    #[arg(long)]
    amount_wei: String,
}

fn parse_addr(field: &str, hex: &str) -> Result<Address> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes =
        alloy_primitives::hex::decode(stripped).with_context(|| format!("{field}: bad hex"))?;
    let arr: [u8; 20] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{field}: expected 20-byte address"))?;
    Ok(Address::from(arr))
}

fn parse_chain(s: &str) -> Result<ChainId> {
    s.parse::<ChainId>()
        .map_err(|e| anyhow!("--chain {s}: {e}"))
}

fn parse_b256(field: &str, hex: &str) -> Result<B256> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes =
        alloy_primitives::hex::decode(stripped).with_context(|| format!("{field}: bad hex"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{field}: expected 32-byte hash"))?;
    Ok(B256::from(arr))
}

fn parse_csv_addr(field: &str, csv: &str) -> Result<Vec<Address>> {
    csv.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .enumerate()
        .map(|(i, s)| parse_addr(&format!("{field}[{i}]"), s))
        .collect()
}

/// A signer-daemon-backed `EvmCosigner`. Posts the
/// [`EvmSafeTxSignRequest`] to `/api/v1/sign/evm-safe-tx`; verifies the
/// daemon's response matches the pinned `signer_address`.
struct RemoteEvmCosigner {
    base_url: String,
    signer: Address,
    client: reqwest::Client,
}

impl EvmCosigner for RemoteEvmCosigner {
    fn signer_address(&self) -> Address {
        self.signer
    }
    fn sign_safe_tx<'a>(
        &'a self,
        chain: ChainId,
        safe_address: Address,
        tx: &'a xindex_safe_evm::digest::SafeTransaction,
        safe_tx_hash: alloy_primitives::B256,
        fee_wei: u128,
        intent_proof: Option<&'a xindex_shared::signer_wire::IntentProof>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        xindex_safe_evm::sigs::EcdsaSig,
                        xindex_executor::evm_redeem::EvmRedeemError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        let url = format!("{}/api/v1/sign/evm-safe-tx", self.base_url);
        let signer = self.signer;
        let client = self.client.clone();
        // Snapshot the SafeTransaction fields into owned strings here
        // — pinning the future doesn't capture `tx` past the await.
        let req = xindex_shared::signer_wire::EvmSafeTxSignRequest {
            chain_id: chain,
            safe_address: format!("{safe_address:#x}"),
            to: format!("{:#x}", tx.to),
            value: tx.value.to_string(),
            data: format!("0x{}", alloy_primitives::hex::encode(&tx.data)),
            operation: tx.operation as u8,
            safe_tx_gas: tx.safe_tx_gas.to_string(),
            base_gas: tx.base_gas.to_string(),
            gas_price: tx.gas_price.to_string(),
            gas_token: format!("{:#x}", tx.gas_token),
            refund_receiver: format!("{:#x}", tx.refund_receiver),
            nonce: tx.nonce.to_string(),
            safe_tx_hash: format!("0x{}", alloy_primitives::hex::encode(safe_tx_hash)),
            fee_wei: fee_wei.to_string(),
            intent_proof: intent_proof.cloned(),
        };
        Box::pin(async move {
            let resp = client.post(&url).json(&req).send().await.map_err(|e| {
                xindex_executor::evm_redeem::EvmRedeemError::Cosigner {
                    signer,
                    message: format!("transport: {e}"),
                }
            })?;
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(xindex_executor::evm_redeem::EvmRedeemError::Cosigner {
                    signer,
                    message: format!("HTTP {status}: {body}"),
                });
            }
            let parsed: xindex_shared::signer_wire::Eip712SignResponse = resp
                .json()
                .await
                .map_err(|e| xindex_executor::evm_redeem::EvmRedeemError::Cosigner {
                    signer,
                    message: format!("decode: {e}"),
                })?;
            // Verify pinned signer.
            let returned = parsed
                .signer_address
                .strip_prefix("0x")
                .unwrap_or(&parsed.signer_address);
            let returned_bytes = alloy_primitives::hex::decode(returned).map_err(|e| {
                xindex_executor::evm_redeem::EvmRedeemError::Cosigner {
                    signer,
                    message: format!("bad signer hex: {e}"),
                }
            })?;
            if returned_bytes.as_slice() != signer.as_slice() {
                return Err(xindex_executor::evm_redeem::EvmRedeemError::Cosigner {
                    signer,
                    message: format!("daemon returned wrong signer: 0x{returned}"),
                });
            }
            let sig_hex = parsed
                .signature
                .strip_prefix("0x")
                .unwrap_or(&parsed.signature);
            let sig_bytes = alloy_primitives::hex::decode(sig_hex).map_err(|e| {
                xindex_executor::evm_redeem::EvmRedeemError::Cosigner {
                    signer,
                    message: format!("bad sig hex: {e}"),
                }
            })?;
            let arr: [u8; 65] = sig_bytes.as_slice().try_into().map_err(|_| {
                xindex_executor::evm_redeem::EvmRedeemError::Cosigner {
                    signer,
                    message: format!("sig not 65 bytes: got {}", sig_bytes.len()),
                }
            })?;
            xindex_safe_evm::sigs::EcdsaSig::from_65_bytes(arr).map_err(|e| {
                xindex_executor::evm_redeem::EvmRedeemError::Cosigner {
                    signer,
                    message: format!("non-canonical sig: {e:?}"),
                }
            })
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

    match Cli::parse().backend {
        Backend::Safe(args) => run_safe(args).await,
        Backend::Turnkey(args) => run_turnkey(args).await,
    }
}

/// Drive a single Safe-backed redeem leg.
async fn run_safe(args: SafeArgs) -> Result<()> {
    let chain = parse_chain(&args.chain)?;
    let safe_address = parse_addr("--safe-address", &args.safe_address)?;
    let safe_owners = parse_csv_addr("--safe-owners", &args.safe_owners)?;
    let vault = parse_addr("--vault", &args.vault)?;
    let submitter_address = parse_addr("--submitter-address", &args.submitter_address)?;
    let signer_daemons: Vec<&str> = args.signer_daemons.split(',').map(str::trim).collect();
    let signer_addresses = parse_csv_addr("--signer-addresses", &args.signer_addresses)?;
    if signer_daemons.len() != signer_addresses.len() {
        return Err(anyhow!(
            "--signer-daemons ({}) and --signer-addresses ({}) must align 1-to-1",
            signer_daemons.len(),
            signer_addresses.len()
        ));
    }
    let amount_wei =
        U256::from_str_radix(&args.amount_wei, 10).context("--amount-wei: bad decimal")?;

    // Build alloy provider against the destination chain. `.boxed()`
    // erases the concrete `Http<Client>` transport to `BoxTransport`
    // so the `Provider` trait bound on `AlloyEvmChainClient<P>` is
    // satisfied (the default `Provider<T = BoxTransport>` signature
    // doesn't unify with the unboxed transport).
    let provider = ProviderBuilder::new()
        .on_http(args.rpc_url.parse().context("--rpc-url")?)
        .boxed();
    let evm = Arc::new(
        AlloyEvmChainClient::new(chain, Arc::new(provider))
            .map_err(|e| anyhow!("AlloyEvmChainClient::new: {e}"))?,
    );

    // Build cosigner fleet.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("reqwest client")?;
    let cosigners: Vec<Box<dyn EvmCosigner>> = signer_daemons
        .iter()
        .zip(signer_addresses.iter())
        .map(|(url, signer)| -> Box<dyn EvmCosigner> {
            Box::new(RemoteEvmCosigner {
                base_url: (*url).to_string(),
                signer: *signer,
                client: http.clone(),
            })
        })
        .collect();

    let fee = EvmTxFee {
        gas_limit: args.gas_limit,
        max_fee_per_gas: args.max_fee_per_gas,
        max_priority_fee_per_gas: args.max_priority_fee_per_gas,
        gas_price: args.gas_price,
    };

    let cfg = EvmRedeemConfig {
        chain,
        safe_address,
        safe_owners,
        safe_threshold: args.safe_threshold,
        fee,
        vault,
        expiry_offset_secs: args.expiry_offset_secs,
        submitter_address,
    };
    let lock_table = Arc::new(SafeLockTable::new());
    let executor = EvmRedeemExecutor::new(cfg, evm, cosigners, lock_table)
        .map_err(|e| anyhow!("executor construct: {e}"))?;

    // Single-leg drive (v1 scope; long-running event watcher is V9-era).
    let task = EvmRedeemTask {
        dispatch_id: alloy_primitives::B256::ZERO,
        redemption_id: alloy_primitives::B256::ZERO,
        chain,
        memo: args.memo,
        amount_wei,
        // CTD-1: certificate supplied by the observer/relay (Slice B);
        // None is refused daemon-side (fail closed).
        intent_proof: None,
    };
    info!(?chain, ?safe_address, ?amount_wei, "build_leg start");
    let outcome = executor
        .build_leg(&task)
        .await
        .map_err(|e| anyhow!("build_leg: {e}"))?;

    info!(
        nonce = outcome.nonce,
        safe_tx_hash = %outcome.safe_tx_hash,
        exec_calldata_len = outcome.exec_calldata.len(),
        "leg built — submission deferred to operator's wallet-fronted broadcaster"
    );

    // Submission requires the submitter EOA's signing key. v1 leaves
    // that to the operator's chosen path (alloy WalletProvider with
    // `--private-key`, HSM-fronted signer, Safe Transaction Service).
    // Print the calldata so the operator can construct and broadcast.
    println!("safe_tx_hash: {:#x}", outcome.safe_tx_hash);
    println!("nonce: {}", outcome.nonce);
    println!("from: {:#x}", outcome.from);
    println!("to: {:#x}", outcome.safe_address);
    println!("chain_id: {}", outcome.evm_chain_id);
    println!(
        "data: 0x{}",
        alloy_primitives::hex::encode(&outcome.exec_calldata)
    );

    Ok(())
}

/// Drive a single Turnkey-backed EVM redeem leg: stage the unsigned spend in
/// the shared prepare store, sign the tx hash via Turnkey (gated by the
/// approver-watcher), assemble the raw signed tx, and submit it.
async fn run_turnkey(args: TurnkeyEvmArgs) -> Result<()> {
    let chain = parse_chain(&args.chain)?;
    let custody_address = parse_addr("--custody-address", &args.custody_address)?;
    let vault = parse_addr("--vault", &args.vault)?;
    let dispatch_id = parse_b256("--dispatch-id", &args.dispatch_id)?;
    let redemption_id = parse_b256("--redemption-id", &args.redemption_id)?;
    let amount_wei =
        U256::from_str_radix(&args.amount_wei, 10).context("--amount-wei: bad decimal")?;

    // The Turnkey API P-256 key stays out of argv — read it from the env.
    let api_key = std::env::var("XINDEX_TURNKEY_API_KEY").context(
        "XINDEX_TURNKEY_API_KEY (hex P-256 private key) must be set for --backend turnkey",
    )?;
    let stamper = TurnkeyStamper::from_hex(&api_key).map_err(|e| anyhow!("turnkey key: {e}"))?;
    let turnkey = Arc::new(
        TurnkeyClient::new(&args.turnkey_host, &args.organization_id, stamper)
            .map_err(|e| anyhow!("turnkey client: {e}"))?,
    );

    // Shared bind-prepare store: the executor `put`s the unsigned spend here;
    // the approver process `get`s the same DB file to gate the signature.
    let prepare = Arc::new(
        SqlitePrepareStore::connect(&args.db)
            .await
            .map_err(|e| anyhow!("prepare store {}: {e}", args.db))?,
    );

    // Provider for the custody EOA nonce + raw-tx submit.
    let provider = ProviderBuilder::new()
        .on_http(args.rpc_url.parse().context("--rpc-url")?)
        .boxed();
    let evm = AlloyEvmChainClient::new(chain, Arc::new(provider))
        .map_err(|e| anyhow!("AlloyEvmChainClient::new: {e}"))?;
    let nonce = evm
        .provider()
        .get_transaction_count(custody_address)
        .await
        .context("get_transaction_count")?;

    let fee = EvmTxFee {
        gas_limit: args.gas_limit,
        max_fee_per_gas: args.max_fee_per_gas,
        max_priority_fee_per_gas: args.max_priority_fee_per_gas,
        gas_price: args.gas_price,
    };
    let config = TurnkeyEvmRedeemConfig {
        sign_with: args.sign_with,
        expiry_offset_secs: args.expiry_offset_secs,
        poll_interval: Duration::from_secs(args.poll_interval_secs),
        poll_max_attempts: args.poll_max_attempts,
    };
    let executor = TurnkeyEvmRedeemExecutor::new(config, turnkey, prepare);

    let task = EvmRedeemTask {
        dispatch_id,
        redemption_id,
        chain,
        memo: args.memo,
        amount_wei,
        // CTD-1: the RIC is supplied by the observer/relay (Slice B); None
        // fail-closes at the approver (decide_evm_deposit is RIC-only).
        intent_proof: None,
    };
    info!(
        ?chain,
        ?custody_address,
        nonce,
        ?amount_wei,
        "turnkey EVM execute_leg start"
    );
    let outcome = executor
        .execute_leg(&task, vault, nonce, fee)
        .await
        .map_err(|e| anyhow!("execute_leg: {e}"))?;

    // Submit the raw signed tx the executor assembled.
    let tx_hash = evm
        .submit_raw(outcome.raw_tx)
        .await
        .map_err(|e| anyhow!("submit_raw: {e}"))?;
    info!(activity = %outcome.activity_id, %tx_hash, "turnkey EVM redeem leg broadcast");
    println!("signing_hash: {:#x}", outcome.signing_hash);
    println!("activity_id: {}", outcome.activity_id);
    println!("tx_hash: {tx_hash:#x}");

    Ok(())
}
