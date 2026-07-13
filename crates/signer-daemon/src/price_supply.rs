//! Circulating-supply sourcing for the self-driven price signer (workstream A,
//! `DL-INDEX-METHOD-ORACLE-1`).
//!
//! The oracle attests `(price, circulating_supply)` per asset. Price comes
//! from [`crate::price_venue`] (CEX tickers); the constituents are NATIVE
//! assets (BTC / ETH / ATOM / ...), so their circulating supply is market data
//! rather than a single `totalSupply()` call — sourced here from supply feeds.
//! Same robustness shape as price: multiple sources, fault-tolerant, fed to
//! [`aggregate_price`](xindex_shared::price_aggregate::aggregate_price) for a
//! median + outlier rejection. Whole-token supplies are well under 2^53, so the
//! feed's JSON number → decimal string → [`decimal_to_scaled`] is exact at
//! realistic magnitudes (the scale-by-decimals happens in `U256`).

use alloy_primitives::{keccak256, U256};
use async_trait::async_trait;
use serde_json::Value;

use crate::price_venue::{decimal_to_scaled, http_get, SourcedValue, VenueError};

/// One circulating-supply source for an asset.
#[async_trait]
pub trait SupplySource: Send + Sync + std::fmt::Debug {
    /// Human source name (logging / diagnostics).
    fn name(&self) -> &'static str;
    /// Fetch `id`'s circulating supply in RAW token units (scaled by
    /// `decimals`).
    async fn circulating_supply_observation(
        &self,
        id: &str,
        decimals: u8,
    ) -> Result<SourcedValue, VenueError>;
}

/// A `(source, id)` supply feed: one asset on one source (ids differ per
/// source, e.g. the `coingecko` source's `bitcoin`).
#[derive(Debug)]
pub struct SupplyFeed<'a> {
    /// The supply source client.
    pub source: &'a dyn SupplySource,
    /// The source-specific asset id.
    pub id: &'a str,
}

/// Query every supply feed for one asset (sequentially), tolerating per-source
/// failures (logged at WARN). Returns the successful raw-unit supplies; the
/// caller medians them via `aggregate_price`.
pub async fn source_supply(feeds: &[SupplyFeed<'_>], decimals: u8) -> Vec<U256> {
    source_supply_evidence(feeds, decimals)
        .await
        .into_iter()
        .map(|observation| observation.value)
        .collect()
}

/// Query supply providers and return exact successful observations for the
/// append-only evidence writer.
pub async fn source_supply_evidence(feeds: &[SupplyFeed<'_>], decimals: u8) -> Vec<SourcedValue> {
    let mut out = Vec::with_capacity(feeds.len());
    for feed in feeds {
        match feed
            .source
            .circulating_supply_observation(feed.id, decimals)
            .await
        {
            Ok(s) => out.push(s),
            Err(e) => tracing::warn!(
                source = feed.source.name(),
                id = feed.id,
                error = %e,
                "supply fetch failed; tolerating",
            ),
        }
    }
    out
}

/// `coingecko` circulating-supply source.
pub struct CoinGeckoSupply {
    client: reqwest::Client,
    base: String,
}

impl std::fmt::Debug for CoinGeckoSupply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoinGeckoSupply")
            .field("base", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl CoinGeckoSupply {
    /// Construct against the public API (override `base` for tests).
    #[must_use]
    pub fn new(client: reqwest::Client, base: impl Into<String>) -> Self {
        Self {
            client,
            base: base.into(),
        }
    }

    /// Parse `{"market_data":{"circulating_supply": 19500000.0}}` into raw
    /// units (× 10^`decimals`).
    ///
    /// # Errors
    /// [`VenueError::Parse`] if `market_data.circulating_supply` is absent /
    /// null / not a number.
    pub fn parse_supply(body: &str, decimals: u8) -> Result<U256, VenueError> {
        let v: Value = serde_json::from_str(body).map_err(|e| VenueError::Parse(e.to_string()))?;
        let n = v
            .get("market_data")
            .and_then(|m| m.get("circulating_supply"))
            .ok_or_else(|| {
                VenueError::Parse("missing market_data.circulating_supply".to_string())
            })?;
        if !n.is_number() {
            return Err(VenueError::Parse(
                "circulating_supply not a number".to_string(),
            ));
        }
        decimal_to_scaled(&n.to_string(), decimals)
    }
}

#[async_trait]
impl SupplySource for CoinGeckoSupply {
    fn name(&self) -> &'static str {
        "coingecko"
    }
    async fn circulating_supply_observation(
        &self,
        id: &str,
        decimals: u8,
    ) -> Result<SourcedValue, VenueError> {
        let url = format!(
            "{}/api/v3/coins/{id}?localization=false&tickers=false&community_data=false&developer_data=false",
            self.base
        );
        let body = http_get(&self.client, &url).await?;
        Ok(SourcedValue {
            source: self.name(),
            subject: id.to_string(),
            value: Self::parse_supply(&body, decimals)?,
            response_hash: keccak256(body.as_bytes()),
            raw_response: body,
        })
    }
}

/// `CoinCap` circulating-supply source. This is intentionally a provider
/// independent from `CoinGecko` so production can require two agreeing supply
/// observations instead of treating one API as an oracle.
pub struct CoinCapSupply {
    client: reqwest::Client,
    base: String,
}

impl std::fmt::Debug for CoinCapSupply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoinCapSupply")
            .field("base", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl CoinCapSupply {
    /// Construct against the `CoinCap` API (override `base` for tests).
    #[must_use]
    pub fn new(client: reqwest::Client, base: impl Into<String>) -> Self {
        Self {
            client,
            base: base.into(),
        }
    }

    /// Parse `{"data":{"supply":"19500000.0"}}` into raw token
    /// units (multiplied by `10^decimals`).
    ///
    /// # Errors
    /// [`VenueError::Parse`] if `data.supply` is absent or malformed.
    pub fn parse_supply(body: &str, decimals: u8) -> Result<U256, VenueError> {
        let v: Value = serde_json::from_str(body).map_err(|e| VenueError::Parse(e.to_string()))?;
        let supply = v
            .get("data")
            .and_then(|data| data.get("supply"))
            .and_then(Value::as_str)
            .ok_or_else(|| VenueError::Parse("missing string data.supply".to_string()))?;
        decimal_to_scaled(supply, decimals)
    }
}

#[async_trait]
impl SupplySource for CoinCapSupply {
    fn name(&self) -> &'static str {
        "coincap"
    }

    async fn circulating_supply_observation(
        &self,
        id: &str,
        decimals: u8,
    ) -> Result<SourcedValue, VenueError> {
        let url = format!("{}/v2/assets/{id}", self.base);
        let body = http_get(&self.client, &url).await?;
        Ok(SourcedValue {
            source: self.name(),
            subject: id.to_string(),
            value: Self::parse_supply(&body, decimals)?,
            response_hash: keccak256(body.as_bytes()),
            raw_response: body,
        })
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]
    use super::*;
    use alloy_primitives::B256;

    #[test]
    fn parses_coingecko_supply_scaled_by_decimals() {
        // 19_500_000 BTC at 8 decimals → 19_500_000 * 1e8 raw units.
        let body = r#"{"market_data":{"circulating_supply":19500000.0,"x":1}}"#;
        let got = CoinGeckoSupply::parse_supply(body, 8).expect("parse");
        assert_eq!(got, U256::from(19_500_000u64) * U256::from(100_000_000u64));
        // Missing / null / non-number → error (not panic).
        assert!(CoinGeckoSupply::parse_supply("{}", 8).is_err());
        assert!(
            CoinGeckoSupply::parse_supply(r#"{"market_data":{"circulating_supply":null}}"#, 8)
                .is_err()
        );
    }

    #[test]
    fn parses_coincap_supply_scaled_by_decimals() {
        let body = r#"{"data":{"id":"bitcoin","supply":"19500000.0"}}"#;
        let got = CoinCapSupply::parse_supply(body, 8).expect("parse");
        assert_eq!(got, U256::from(19_500_000u64) * U256::from(100_000_000u64));
        assert!(CoinCapSupply::parse_supply("{}", 8).is_err());
        assert!(CoinCapSupply::parse_supply(r#"{"data":{"supply":null}}"#, 8).is_err());
    }

    #[derive(Debug)]
    struct MockSupply {
        name: &'static str,
        result: Result<U256, ()>,
    }
    #[async_trait]
    impl SupplySource for MockSupply {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn circulating_supply_observation(
            &self,
            id: &str,
            _decimals: u8,
        ) -> Result<SourcedValue, VenueError> {
            self.result
                .map(|value| SourcedValue {
                    source: self.name,
                    subject: id.to_string(),
                    value,
                    response_hash: B256::repeat_byte(1),
                    raw_response: "mock".to_string(),
                })
                .map_err(|()| VenueError::Http("mock down".to_string()))
        }
    }

    #[tokio::test]
    async fn source_supply_tolerates_failures() {
        let ok = MockSupply {
            name: "a",
            result: Ok(U256::from(100u64)),
        };
        let down = MockSupply {
            name: "b",
            result: Err(()),
        };
        let feeds = [
            SupplyFeed {
                source: &ok,
                id: "x",
            },
            SupplyFeed {
                source: &down,
                id: "x",
            },
        ];
        assert_eq!(source_supply(&feeds, 8).await, vec![U256::from(100u64)]);
    }
}
