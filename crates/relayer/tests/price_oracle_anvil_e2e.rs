//! Runnable ignored end-to-end gate for the NAV price quorum path.
//!
//! Run explicitly (requires `anvil`, `forge`, and the sibling Solidity repo):
//! `cargo test -p xindex-relayer --test price_oracle_anvil_e2e -- --ignored --nocapture`

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::network::EthereumWallet;
use alloy::node_bindings::Anvil;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::{Signer, SignerSync};
use anyhow::{Context, Result};
use xindex_chain_eth::bindings::PriceAttestationOracle;
use xindex_relayer::{IngestOutcome, PriceCollector};
use xindex_shared::eip712::{
    price_attestation, price_attestation_signing_hash, price_oracle_domain,
};
use xindex_shared::price_wire::SignedPriceMessage;

fn wire(
    signer: &PrivateKeySigner,
    oracle: Address,
    asset_id: B256,
    timestamp: u64,
) -> Result<SignedPriceMessage> {
    let price_wad = U256::from(43_210u64) * U256::from(10u64).pow(U256::from(18u8));
    let supply = U256::from(21_000_000u64) * U256::from(100_000_000u64);
    let att = price_attestation(asset_id, price_wad, supply, timestamp);
    let digest = price_attestation_signing_hash(&att, &price_oracle_domain(31_337, oracle));
    let signature = signer.sign_hash_sync(&digest)?.as_bytes();
    Ok(SignedPriceMessage {
        asset_id: format!("{asset_id:#x}"),
        price_wad: price_wad.to_string(),
        supply: supply.to_string(),
        timestamp,
        signer_address: format!("{:#x}", signer.address()),
        signature: format!("0x{}", alloy::primitives::hex::encode(signature)),
    })
}

#[tokio::test]
#[ignore = "requires local anvil + forge; explicit release/rehearsal gate"]
async fn exact_quorum_posts_real_attest_price_and_reads_pending_quote() -> Result<()> {
    let anvil = Anvil::new().chain_id(31_337).try_spawn()?;
    let owner = PrivateKeySigner::from_signing_key(anvil.keys()[0].clone().into());
    let signers: Vec<PrivateKeySigner> = anvil.keys()[1..=3]
        .iter()
        .cloned()
        .map(|key| PrivateKeySigner::from_signing_key(key.into()))
        .collect();
    let signer_array = format!(
        "[{}]",
        signers
            .iter()
            .map(|s| format!("{:#x}", s.address()))
            .collect::<Vec<_>>()
            .join(",")
    );
    let solidity_dir = std::env::var_os("XINDEX_SOLIDITY_DIR").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../..")
                .join("Xindex")
        },
        PathBuf::from,
    );
    let owner_key = format!(
        "0x{}",
        alloy::primitives::hex::encode(anvil.keys()[0].to_bytes())
    );
    let output = Command::new("forge")
        .current_dir(&solidity_dir)
        .args([
            "create",
            "--broadcast",
            "--rpc-url",
            &anvil.endpoint(),
            "--private-key",
            &owner_key,
            "src/PriceAttestationOracle.sol:PriceAttestationOracle",
            "--constructor-args",
            &format!("{:#x}", owner.address()),
            &signer_array,
            "2",
            "3600",
        ])
        .output()
        .context("run forge create")?;
    if !output.status.success() {
        anyhow::bail!(
            "forge create failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8(output.stdout).context("forge stdout utf8")?;
    let deployed = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Deployed to: "))
        .context("forge output missing deployed address")?
        .parse::<Address>()?;

    let provider = std::sync::Arc::new(
        ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(EthereumWallet::new(owner))
            .on_http(anvil.endpoint_url()),
    );
    let oracle = PriceAttestationOracle::new(deployed, provider.clone());
    let asset_id = B256::repeat_byte(0xab);
    oracle
        .setPriceBounds(asset_id, U256::from(1u8), U256::MAX)
        .send()
        .await?
        .get_receipt()
        .await?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .saturating_sub(1);
    let messages = [
        wire(&signers[0], deployed, asset_id, timestamp)?,
        wire(&signers[1], deployed, asset_id, timestamp)?,
    ];
    let mut collector = PriceCollector::new(
        price_oracle_domain(31_337, deployed),
        signers.iter().map(Signer::address),
        2,
        300,
    )?;
    let now = timestamp + 1;
    let _ = collector.ingest(&messages[0], now)?;
    let ready = match collector.ingest(&messages[1], now)? {
        IngestOutcome::Ready(ready) => ready,
        other => anyhow::bail!("expected exact quorum, got {other:?}"),
    };
    let receipt = oracle
        .attestPrice(
            ready.payload.asset_id,
            ready.payload.price_wad,
            ready.payload.supply,
            ready.payload.timestamp,
            ready.signatures.into_iter().map(Bytes::from).collect(),
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    anyhow::ensure!(receipt.status(), "attestPrice receipt reverted");

    let pending = oracle.pendingQuote(asset_id).call().await?;
    anyhow::ensure!(
        pending.priceWad == ready.payload.price_wad,
        "price mismatch"
    );
    anyhow::ensure!(pending.supply == ready.payload.supply, "supply mismatch");
    anyhow::ensure!(pending.updatedAt == timestamp, "timestamp mismatch");
    Ok(())
}
