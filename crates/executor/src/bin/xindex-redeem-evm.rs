//! `xindex-redeem-evm` — Phase 3.2 EVM redeem executor binary.
//!
//! Watches the Ethereum `IndexToken` / `ThorchainAdapter` for an EVM-
//! family `RedeemDispatched` event, drives the Safe v1.4.1
//! `execTransaction` flow on the destination chain (via [`EvmRedeemExecutor`]),
//! and submits the wrapper transaction through an `alloy` `WalletProvider`.
//!
//! ## v1 scope
//!
//! This binary is a **skeleton** — it wires the executor up against
//! an `AlloyEvmChainClient` + cosigner fleet, exposes the CLI, and
//! shells out to [`EvmRedeemExecutor::build_leg`]. The end-to-end
//! event-driven loop (RedeemDispatched → build → submit → confirm →
//! record) is V9's anvil-forked integration test territory. Operators
//! drive single legs via this CLI in the meantime.

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

use alloy::providers::ProviderBuilder;
use alloy_primitives::{Address, U256};
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::info;
use xindex_chain_evm::{AlloyEvmChainClient, EvmTxFee};
use xindex_executor::evm_redeem::{
    EvmCosigner, EvmRedeemConfig, EvmRedeemExecutor, EvmRedeemTask, SafeLockTable,
};
use xindex_shared::chain_registry::ChainId;

/// CLI for a single EVM redeem leg. Production wraps this in a
/// long-running daemon (V9-era follow-up).
#[derive(Debug, Parser)]
#[command(name = "xindex-redeem-evm", version)]
struct Args {
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

    let args = Args::parse();
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
    let amount_wei = U256::from_str_radix(&args.amount_wei, 10)
        .context("--amount-wei: bad decimal")?;

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
