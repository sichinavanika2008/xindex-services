//! `xindex-price-signer` — self-driven NAV price-attestation producer
//! (workstream A, `DL-INDEX-METHOD-ORACLE-1`).
//!
//! On an interval, for each configured asset: source the price from multiple
//! independent CEX venues + the circulating supply from supply feeds, median
//! each (outlier-rejected, fail-closed), sign the `PriceAttestation` with the
//! HSM (recover-verified), emit the complete signed tuple as a JSON line, and
//! push it to the configured untrusted collectors. Collectors recover-verify
//! and group exact tuples before posting `attestPrice` on-chain.
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
use xindex_shared::price_twap::{TwapConfig, TwapSample};
use xindex_shared::price_wire::SignedPriceMessage;
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
    /// TWAP window (secs): the trailing span the spatial medians are
    /// time-weight-averaged over (OM-4). A transient spike must persist across
    /// this window to move the signed price. Suggested a large multiple of
    /// `interval_secs` (e.g. 30 min for a 60s interval).
    twap_window_secs: u64,
    /// Minimum samples informing the TWAP window (>= 2). Higher forces denser
    /// coverage before a price can be signed.
    twap_min_samples: usize,
    /// Maximum stale gap allowed inside the TWAP window (secs). A longer feed
    /// stall fails closed; must be in `interval_secs..=twap_window_secs`.
    twap_max_gap_secs: u64,
    /// Seconds between observation rounds.
    interval_secs: u64,
    /// Deterministic timestamp epoch shared by every independent signer. The
    /// timestamp signed in a round is `floor(now / epoch_secs) * epoch_secs`,
    /// never the host's arbitrary wall-clock second.
    epoch_secs: u64,
    /// Decimal significant digits retained in the signed WAD price. Four is the
    /// minimum accepted (<10 bps deterministic downward canonicalization).
    price_significant_digits: u8,
    /// Decimal significant digits retained in the signed raw supply.
    supply_significant_digits: u8,
    /// Path to the durable anti-equivocation state file (per-asset last-signed
    /// timestamps); persists the monotonic guard across restarts.
    state_file: String,
    /// Base URLs of redundant untrusted collectors. The signer independently
    /// creates the price; collectors receive only an already-signed tuple.
    collector_urls: Vec<String>,
    /// Per-collector publish attempts for transient transport/5xx/429 errors.
    publish_attempts: u32,
    /// Timeout for one collector HTTP attempt.
    publish_timeout_secs: u64,
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

/// Align an observation to the shared deterministic epoch. `epoch_secs == 0`
/// is rejected at boot, so this helper's zero branch is defensive only.
fn observation_epoch(now: u64, epoch_secs: u64) -> u64 {
    if epoch_secs == 0 {
        return 0;
    }
    now - now % epoch_secs
}

/// Load the persisted per-asset last-signed timestamps (the anti-equivocation
/// guard) so it SURVIVES a producer restart. A missing file is a first run
/// (empty map); a CORRUPT file fails closed — refuse to start rather than
/// silently reset the guard and risk signing two prices for one instant.
fn load_last_signed(path: &str) -> Result<HashMap<B256, u64>, Box<dyn std::error::Error>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(format!("cannot read state file {path}: {e}").into()),
    };
    let map: HashMap<String, u64> = serde_json::from_str(&raw)
        .map_err(|e| format!("corrupt anti-equivocation state {path}: {e} (refusing to start)"))?;
    let mut out = HashMap::with_capacity(map.len());
    for (k, v) in map {
        out.insert(
            k.parse::<B256>()
                .map_err(|e| format!("bad asset id '{k}' in state {path}: {e}"))?,
            v,
        );
    }
    Ok(out)
}

/// Atomically persist the guard (write a temp file, then rename) so a crash
/// mid-write cannot corrupt or truncate the state.
fn save_last_signed(path: &str, map: &HashMap<B256, u64>) -> std::io::Result<()> {
    let raw: HashMap<String, u64> = map.iter().map(|(k, v)| (format!("{k:#x}"), *v)).collect();
    let json = serde_json::to_string(&raw).map_err(std::io::Error::other)?;
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)
}

/// Fail-closed boot-time validation of the venue-consensus + TWAP policy. A
/// mis-set parameter silently weakens a manipulation guard, so refuse to start.
fn validate_config(cfg: &Config) -> Result<(), Box<dyn std::error::Error>> {
    // G/red-team RT-A-LOW: the aggregator's outlier rejection needs an ODD
    // honest anchor. At min_venues == 2 an even survivor set averages the two
    // middle quotes, so one compromised venue moves the median by (X-P)/2
    // (bounded only by max_deviation_bps). Require >= 3 price venues so a single
    // bad venue is always out-voted by an honest majority.
    if cfg.min_venues < 3 {
        return Err(format!(
            "min_venues must be >= 3 for single-venue resistance (got {}); an even \
             survivor set has no honest anchor",
            cfg.min_venues
        )
        .into());
    }
    if cfg.epoch_secs == 0 || cfg.interval_secs == 0 || cfg.epoch_secs != cfg.interval_secs {
        return Err(format!(
            "epoch_secs and interval_secs must be the same non-zero cadence (epoch={}, interval={}); \
             every signer must produce at most one tuple for the same shared epoch",
            cfg.epoch_secs, cfg.interval_secs
        )
        .into());
    }
    if !(4..=78).contains(&cfg.price_significant_digits) {
        return Err(format!(
            "price_significant_digits must be in 4..=78 (got {}); fewer than 4 can \
             move the canonical price downward by >=10 bps",
            cfg.price_significant_digits
        )
        .into());
    }
    if !(4..=78).contains(&cfg.supply_significant_digits) {
        return Err(format!(
            "supply_significant_digits must be in 4..=78 (got {})",
            cfg.supply_significant_digits
        )
        .into());
    }
    if cfg.publish_attempts == 0 || cfg.publish_timeout_secs == 0 {
        return Err("publish_attempts and publish_timeout_secs must be non-zero".into());
    }
    // TWAP (OM-4) window sanity. Ordering: interval <= max_gap <= window, and
    // >= 2 informing samples (a single sample is not a time average).
    if cfg.twap_min_samples < 2 {
        return Err(format!(
            "twap_min_samples must be >= 2 (got {}); a single sample is not a time average",
            cfg.twap_min_samples
        )
        .into());
    }
    if cfg.twap_window_secs < cfg.interval_secs {
        return Err(format!(
            "twap_window_secs ({}) must be >= interval_secs ({})",
            cfg.twap_window_secs, cfg.interval_secs
        )
        .into());
    }
    if cfg.twap_max_gap_secs < cfg.interval_secs || cfg.twap_max_gap_secs > cfg.twap_window_secs {
        return Err(format!(
            "twap_max_gap_secs must be in {}..={} (got {}); below interval every normal \
             gap trips it, above window it never trips",
            cfg.interval_secs, cfg.twap_window_secs, cfg.twap_max_gap_secs
        )
        .into());
    }
    Ok(())
}

const COLLECT_PATH: &str = "/api/v1/price-signature";

/// Publish an already-signed tuple. Retry only errors that can plausibly change
/// without changing the signed plaintext (transport, 429, 5xx). A collector's
/// deterministic 4xx rejection is logged and not retried.
async fn publish_to_collector(
    http: &reqwest::Client,
    base_url: &str,
    message: &SignedPriceMessage,
    attempts: u32,
) -> Result<(), String> {
    let url = format!("{}{COLLECT_PATH}", base_url.trim_end_matches('/'));
    for attempt in 1..=attempts {
        match http.post(&url).json(message).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response)
                if response.status().is_server_error()
                    || response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
            {
                let status = response.status();
                if attempt == attempts {
                    return Err(format!("http {status} after {attempts} attempt(s)"));
                }
            }
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(format!(
                    "collector rejected signed tuple: http {status}: {body}"
                ));
            }
            Err(e) => {
                if attempt == attempts {
                    return Err(format!("transport after {attempts} attempt(s): {e}"));
                }
            }
        }
        let shift = attempt.saturating_sub(1).min(6);
        tokio::time::sleep(Duration::from_millis(250u64.saturating_mul(1u64 << shift))).await;
    }
    Err("publish attempt loop exhausted".to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: xindex-price-signer <config.json>")?;
    let cfg: Config = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    validate_config(&cfg)?;

    let oracle_contract: Address = cfg.oracle_contract.parse()?;
    let signer_address: Address = cfg.signer_address.parse()?;
    let assets: Vec<(B256, &AssetConfig)> = cfg
        .assets
        .iter()
        .map(|a| Ok::<_, Box<dyn std::error::Error>>((a.asset_id.parse::<B256>()?, a)))
        .collect::<Result<_, _>>()?;

    let http = reqwest::Client::new();
    let publish_http = reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.publish_timeout_secs))
        .build()?;
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
        price_significant_digits: cfg.price_significant_digits,
        supply_significant_digits: cfg.supply_significant_digits,
        twap: TwapConfig {
            window_secs: cfg.twap_window_secs,
            min_samples: cfg.twap_min_samples,
            max_gap_secs: cfg.twap_max_gap_secs,
        },
    };

    // Anti-equivocation guard, loaded from durable state so it survives a
    // restart (a corrupt state file fails closed inside load_last_signed).
    let mut last_signed = load_last_signed(&cfg.state_file)?;
    // Per-asset TWAP sample buffer. In-memory only: on restart it starts empty
    // and the TWAP fails closed (no signing) until it refills across the window
    // — the safe cold-start behaviour, so it needs no durability.
    let mut twap_history: HashMap<B256, Vec<TwapSample>> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(cfg.interval_secs));
    loop {
        tick.tick().await;
        let now = observation_epoch(now_unix(), cfg.epoch_secs);
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
            let history = twap_history.entry(*asset_id).or_default();
            match produce_signed_price(&hsm, signer_address, &domain, policy, &input, history).await
            {
                Ok(signed) => {
                    last_signed.insert(*asset_id, now);
                    // Persist the guard BEFORE emitting, so a restart cannot
                    // reset it and re-sign a different price at this timestamp.
                    // The on-chain attestPrice monotonic check backstops the
                    // narrow sign-then-crash-before-persist window.
                    if let Err(e) = save_last_signed(&cfg.state_file, &last_signed) {
                        eprintln!(
                            "WARN persist anti-equivocation state to {} failed: {e} \
                             (on-chain monotonic check still backstops)",
                            cfg.state_file
                        );
                    }
                    let message = SignedPriceMessage {
                        asset_id: format!("{:#x}", signed.asset_id),
                        price_wad: signed.price_wad.to_string(),
                        supply: signed.supply.to_string(),
                        timestamp: signed.timestamp,
                        signer_address: format!("{:#x}", signed.signer_address),
                        signature: format!("0x{}", alloy_primitives::hex::encode(signed.signature)),
                    };
                    println!("{}", serde_json::to_string(&message)?);
                    for collector in &cfg.collector_urls {
                        if let Err(e) = publish_to_collector(
                            &publish_http,
                            collector,
                            &message,
                            cfg.publish_attempts,
                        )
                        .await
                        {
                            eprintln!(
                                "price-publish {asset_id:#x} epoch {now} to {collector} failed: {e}"
                            );
                        }
                    }
                }
                Err(e) => eprintln!("price-sign {asset_id:#x} failed (fail-closed): {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// G/RT-A-MED: the anti-equivocation guard must persist across restarts and
    /// fail closed on a corrupt state file (never silently reset).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn last_signed_state_round_trips_and_corrupt_fails_closed() {
        let path = std::env::temp_dir().join(format!(
            "xindex-pricesigner-state-{}.json",
            std::process::id()
        ));
        let p = path.to_str().expect("utf8 path");
        let _ = std::fs::remove_file(p);
        // Missing file → empty (first run).
        assert!(load_last_signed(p).expect("missing-ok").is_empty());
        // Round-trip a guard entry.
        let mut m = HashMap::new();
        m.insert(B256::repeat_byte(0xab), 1_700_000_000_u64);
        save_last_signed(p, &m).expect("save");
        assert_eq!(load_last_signed(p).expect("load"), m);
        // Corrupt state → fail closed (refuse to start), never silently reset.
        std::fs::write(p, "{ not json").expect("write corrupt");
        assert!(
            load_last_signed(p).is_err(),
            "corrupt state must fail closed"
        );
        let _ = std::fs::remove_file(p);
    }

    /// A sane policy: 3 venues, a 30-min TWAP window sampled every 60s with a
    /// 5-min stale-gap cap and 10 informing samples.
    fn valid_cfg() -> Config {
        Config {
            oracle_chain_id: 1,
            oracle_contract: "0x0000000000000000000000000000000000000001".into(),
            signer_address: "0x0000000000000000000000000000000000000002".into(),
            hsm_url: "http://localhost".into(),
            min_venues: 3,
            max_deviation_bps: 5000,
            supply_min_venues: 1,
            twap_window_secs: 1800,
            twap_min_samples: 10,
            twap_max_gap_secs: 300,
            interval_secs: 60,
            epoch_secs: 60,
            price_significant_digits: 4,
            supply_significant_digits: 6,
            state_file: "/tmp/xindex-price-signer-state.json".into(),
            collector_urls: vec!["http://127.0.0.1:9191".into()],
            publish_attempts: 3,
            publish_timeout_secs: 5,
            binance_base: String::new(),
            coinbase_base: String::new(),
            kraken_base: String::new(),
            coingecko_base: String::new(),
            assets: vec![],
        }
    }

    #[test]
    fn validate_config_accepts_sane_policy() {
        assert!(validate_config(&valid_cfg()).is_ok());
    }

    #[test]
    fn validate_config_rejects_two_venues() {
        let mut c = valid_cfg();
        c.min_venues = 2; // no odd honest anchor
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn observation_time_is_epoch_aligned_and_never_future() {
        assert_eq!(observation_epoch(1_700_000_059, 60), 1_700_000_040);
        assert!(observation_epoch(1_700_000_059, 60) <= 1_700_000_059);
    }

    #[test]
    fn validate_config_rejects_mismatched_epoch_cadence() {
        let mut c = valid_cfg();
        c.epoch_secs = 30;
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn validate_config_rejects_coarse_price_canonicalization() {
        let mut c = valid_cfg();
        c.price_significant_digits = 3;
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn validate_config_rejects_single_twap_sample() {
        let mut c = valid_cfg();
        c.twap_min_samples = 1; // a single sample is not a time average
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn validate_config_rejects_window_below_interval() {
        let mut c = valid_cfg();
        c.twap_window_secs = 30; // < interval 60
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn validate_config_rejects_gap_out_of_range() {
        let mut below = valid_cfg();
        below.twap_max_gap_secs = 59; // < interval → every normal gap trips it
        assert!(validate_config(&below).is_err());
        let mut above = valid_cfg();
        above.twap_max_gap_secs = above.twap_window_secs + 1; // > window → never trips
        assert!(validate_config(&above).is_err());
    }
}
