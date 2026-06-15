//! `xindex-price-signer` — self-driven NAV price-attestation producer
//! (workstream A, `DL-INDEX-METHOD-ORACLE-1`).
//!
//! On an interval, for each configured asset: source the price from multiple
//! independent CEX venues + the circulating supply from supply feeds, median
//! each (outlier-rejected, fail-closed), sign the `PriceAttestation` with the
//! HSM (recover-verified), and emit it as a JSON line on stdout. A collector
//! gathers the k-of-n signatures and posts `attestPrice` on-chain (that posting
//! half folds into the rehearsal, like the other families' broadcast legs).
//!
//! It NEVER signs a price it was handed — it signs its own aggregated value
//! (the CTD-1 "don't trust the coordinator" property applied to the oracle).
//!
//! Usage: `xindex-price-signer <config.json>`.
#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "producer binary: signed attestations are emitted as JSON lines on \
              stdout for the k-of-n collector; operational status goes to stderr"
)]

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::{Address, B256};
use serde::Deserialize;
use xindex_shared::eip712::price_oracle_domain;
use xindex_signer_daemon::price_sign::{produce_signed_price, PricePolicy, ProducerInputs};
use xindex_signer_daemon::price_supply::{CoinGeckoSupply, SupplyFeed};
use xindex_signer_daemon::price_venue::{BinanceVenue, CoinbaseVenue, Feed, KrakenVenue};
use xindex_signer_daemon::web3signer::HttpHsmClient;

#[derive(Debug, Deserialize)]
struct Config {
    /// EIP-712 domain chainId of the `PriceAttestationOracle`.
    oracle_chain_id: u64,
    /// `PriceAttestationOracle` address (EIP-712 verifyingContract), hex.
    oracle_contract: String,
    /// This signer's EOA the HSM signs for, hex.
    signer_address: String,
    /// HSM frontend base URL (loopback inside the daemon's mTLS perimeter).
    hsm_url: String,
    /// Minimum independent price venues (fail closed below).
    min_venues: usize,
    /// Outlier band (bps) for both price and supply medians.
    max_deviation_bps: u32,
    /// Minimum independent supply sources (typically 1; see `PricePolicy`).
    supply_min_venues: usize,
    /// Seconds between observation rounds.
    interval_secs: u64,
    binance_base: String,
    coinbase_base: String,
    kraken_base: String,
    coingecko_base: String,
    assets: Vec<AssetConfig>,
}

#[derive(Debug, Deserialize)]
struct AssetConfig {
    /// Registry asset id (keccak of the `THORChain` asset string), hex.
    asset_id: String,
    /// Token decimals (scales circulating supply to raw units).
    decimals: u8,
    /// Per-venue symbols / ids for this asset.
    binance: String,
    coinbase: String,
    kraken: String,
    coingecko: String,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: xindex-price-signer <config.json>")?;
    let cfg: Config = serde_json::from_str(&std::fs::read_to_string(&path)?)?;

    let oracle_contract: Address = cfg.oracle_contract.parse()?;
    let signer_address: Address = cfg.signer_address.parse()?;
    let assets: Vec<(B256, &AssetConfig)> = cfg
        .assets
        .iter()
        .map(|a| Ok::<_, Box<dyn std::error::Error>>((a.asset_id.parse::<B256>()?, a)))
        .collect::<Result<_, _>>()?;

    let http = reqwest::Client::new();
    let binance = BinanceVenue::new(http.clone(), &cfg.binance_base);
    let coinbase = CoinbaseVenue::new(http.clone(), &cfg.coinbase_base);
    let kraken = KrakenVenue::new(http.clone(), &cfg.kraken_base);
    let coingecko = CoinGeckoSupply::new(http.clone(), &cfg.coingecko_base);
    let hsm = HttpHsmClient::new(cfg.hsm_url.clone());
    let domain = price_oracle_domain(cfg.oracle_chain_id, oracle_contract);
    let policy = PricePolicy {
        min_venues: cfg.min_venues,
        max_deviation_bps: cfg.max_deviation_bps,
        supply_min_venues: cfg.supply_min_venues,
    };

    let mut last_signed: HashMap<B256, u64> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(cfg.interval_secs));
    loop {
        tick.tick().await;
        let now = now_unix();
        for (asset_id, a) in &assets {
            let price_feeds = [
                Feed {
                    venue: &binance,
                    symbol: &a.binance,
                },
                Feed {
                    venue: &coinbase,
                    symbol: &a.coinbase,
                },
                Feed {
                    venue: &kraken,
                    symbol: &a.kraken,
                },
            ];
            let supply_feeds = [SupplyFeed {
                source: &coingecko,
                id: &a.coingecko,
            }];
            let input = ProducerInputs {
                asset_id: *asset_id,
                decimals: a.decimals,
                price_feeds: &price_feeds,
                supply_feeds: &supply_feeds,
                timestamp: now,
                last_signed_at: last_signed.get(asset_id).copied(),
            };
            match produce_signed_price(&hsm, signer_address, &domain, policy, &input).await {
                Ok(signed) => {
                    last_signed.insert(*asset_id, now);
                    println!(
                        "{}",
                        serde_json::json!({
                            "assetId": format!("{asset_id:#x}"),
                            "priceWad": signed.price_wad.to_string(),
                            "timestamp": now,
                            "signature": format!("0x{}", alloy_primitives::hex::encode(signed.signature)),
                        })
                    );
                }
                Err(e) => eprintln!("price-sign {asset_id:#x} failed (fail-closed): {e}"),
            }
        }
    }
}
