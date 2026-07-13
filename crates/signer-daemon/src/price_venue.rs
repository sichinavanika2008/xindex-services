//! Independent venue price sourcing for the self-driven price signer
//! (workstream A, `DL-INDEX-METHOD-ORACLE-1`).
//!
//! The signer fetches the SAME asset price from MULTIPLE independent venues
//! (CEX tickers here — Binance / Coinbase / Kraken), then feeds the quotes to
//! [`aggregate_price`](xindex_shared::price_aggregate::aggregate_price) +
//! [`sign_observed_price`](crate::price_sign::sign_observed_price). Per-venue
//! failures are tolerated (logged) — the venue floor + outlier rejection are
//! enforced by the aggregator, so one venue being down or manipulated cannot
//! move the signed price. Each client splits a PURE `parse_price` (unit-tested
//! against canned bodies) from the thin reqwest fetch.

use alloy_primitives::{keccak256, B256, U256};
use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;

/// Why a venue fetch / parse failed (per-venue, tolerated by [`source_quotes`]).
#[derive(Debug, Error)]
pub enum VenueError {
    /// Transport / HTTP-status failure.
    #[error("http: {0}")]
    Http(String),
    /// Response body did not parse into a price.
    #[error("parse: {0}")]
    Parse(String),
}

/// One successful source observation plus the exact response retained for
/// audit evidence. URLs and credentials are deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcedValue {
    /// Stable provider name.
    pub source: &'static str,
    /// Provider-specific public asset symbol/id.
    pub subject: String,
    /// Normalized integer value used by aggregation.
    pub value: U256,
    /// Hash of the exact UTF-8 response body.
    pub response_hash: B256,
    /// Exact bounded response body. The evidence writer persists this before
    /// a corresponding signature can be published.
    pub raw_response: String,
}

/// One independent price venue.
#[async_trait]
pub trait PriceVenue: Send + Sync + std::fmt::Debug {
    /// Human venue name (logging / diagnostics).
    fn name(&self) -> &'static str;
    /// Fetch the spot price for `symbol`, scaled to a WAD (1e18) `U256`.
    async fn fetch_price_observation(&self, symbol: &str) -> Result<SourcedValue, VenueError>;
}

/// A `(venue, symbol)` feed: one asset on one venue (symbols differ per venue,
/// e.g. `BTCUSDT` on Binance vs `BTC-USD` on Coinbase).
#[derive(Debug)]
pub struct Feed<'a> {
    /// The venue client.
    pub venue: &'a dyn PriceVenue,
    /// The venue-specific ticker symbol for the asset.
    pub symbol: &'a str,
}

/// Query every feed for one asset (sequentially — a handful per asset),
/// tolerating per-venue failures (logged at WARN). Returns the successful WAD
/// quotes; the caller passes them to `aggregate_price`, which enforces the
/// minimum-venue floor and rejects outliers.
pub async fn source_quotes(feeds: &[Feed<'_>]) -> Vec<U256> {
    source_quote_evidence(feeds)
        .await
        .into_iter()
        .map(|observation| observation.value)
        .collect()
}

/// Query every feed and return the exact successful observations for durable
/// evidence. Failed feeds are logged by stable provider name only.
pub async fn source_quote_evidence(feeds: &[Feed<'_>]) -> Vec<SourcedValue> {
    let mut quotes = Vec::with_capacity(feeds.len());
    for feed in feeds {
        match feed.venue.fetch_price_observation(feed.symbol).await {
            Ok(q) => quotes.push(q),
            Err(e) => tracing::warn!(
                venue = feed.venue.name(),
                symbol = feed.symbol,
                error = %e,
                "venue price fetch failed; tolerating",
            ),
        }
    }
    quotes
}

/// Parse a decimal price string (`"43000.5"`) into a WAD `U256` (scaled 1e18).
///
/// # Errors
/// [`VenueError::Parse`] on a malformed price.
pub fn decimal_to_wad(s: &str) -> Result<U256, VenueError> {
    decimal_to_scaled(s, 18)
}

/// Parse a decimal string into a `U256` scaled by `10^decimals` (e.g. a price
/// at 18, or a circulating supply at the token's own decimals). Fractions
/// longer than `decimals` are truncated (sub-unit precision dropped);
/// negatives / non-numeric / empty inputs error.
///
/// # Errors
/// [`VenueError::Parse`] on a malformed value.
pub fn decimal_to_scaled(s: &str, decimals: u8) -> Result<U256, VenueError> {
    let s = s.trim();
    if s.is_empty() || s.starts_with('-') {
        return Err(VenueError::Parse(format!("invalid value '{s}'")));
    }
    let (int_part, frac_part) = s.split_once('.').unwrap_or((s, ""));
    if int_part.is_empty() && frac_part.is_empty() {
        return Err(VenueError::Parse(format!("invalid value '{s}'")));
    }
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        return Err(VenueError::Parse(format!("non-numeric value '{s}'")));
    }
    let d = usize::from(decimals);
    let mut frac = frac_part.to_string();
    if frac.len() > d {
        frac.truncate(d);
    } else {
        while frac.len() < d {
            frac.push('0');
        }
    }
    let int_str = if int_part.is_empty() { "0" } else { int_part };
    let int_u = U256::from_str_radix(int_str, 10)
        .map_err(|e| VenueError::Parse(format!("int '{int_str}': {e}")))?;
    // Checked arithmetic (G/red-team RT-A-LOW): a compromised venue can return
    // an arbitrarily large decimal STRING (e.g. ~1e60) that parses in-range,
    // then silently WRAPS mod 2^256 on the scale multiply to an attacker-chosen
    // (possibly in-band) value — `U256` `pow`/`*`/`+` are wrapping. Fail closed
    // on any overflow instead (the value is rejected, not wrapped).
    let scale = U256::from(10u64)
        .checked_pow(U256::from(d))
        .ok_or_else(|| VenueError::Parse(format!("scale 10^{d} overflows U256")))?;
    let scaled_int = int_u
        .checked_mul(scale)
        .ok_or_else(|| VenueError::Parse(format!("value '{s}' overflows U256 when scaled")))?;
    if frac.is_empty() {
        return Ok(scaled_int);
    }
    let frac_u =
        U256::from_str_radix(&frac, 10).map_err(|e| VenueError::Parse(format!("frac: {e}")))?;
    scaled_int
        .checked_add(frac_u)
        .ok_or_else(|| VenueError::Parse(format!("value '{s}' overflows U256")))
}

/// Pull a string field from a JSON body via a dotted path, then decimal→WAD.
fn json_price(body: &str, path: &[&str]) -> Result<U256, VenueError> {
    let v: Value = serde_json::from_str(body).map_err(|e| VenueError::Parse(e.to_string()))?;
    let mut cur = &v;
    for key in path {
        cur = cur
            .get(key)
            .ok_or_else(|| VenueError::Parse(format!("missing field '{key}'")))?;
    }
    let s = cur
        .as_str()
        .ok_or_else(|| VenueError::Parse("price field not a string".to_string()))?;
    decimal_to_wad(s)
}

/// Shared reqwest GET → body text, mapping transport/status to [`VenueError`].
pub(crate) async fn http_get(client: &reqwest::Client, url: &str) -> Result<String, VenueError> {
    const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| VenueError::Http(transport_class(&e).to_string()))?;
    if !resp.status().is_success() {
        return Err(VenueError::Http(format!("status {}", resp.status())));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| VenueError::Http(transport_class(&e).to_string()))?;
    if bytes.len() > MAX_BODY_BYTES {
        return Err(VenueError::Http("response body exceeds 2 MiB".to_string()));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| VenueError::Http("response body is not UTF-8".to_string()))
}

/// Classify a reqwest failure without copying its display string. Reqwest
/// errors may include the complete credential-bearing request URL.
pub(crate) fn transport_class(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() {
        "body"
    } else if error.is_decode() {
        "decode"
    } else if error.is_request() {
        "request"
    } else {
        "unknown"
    }
}

/// `binance` spot-price venue client.
pub struct BinanceVenue {
    client: reqwest::Client,
    base: String,
}

impl std::fmt::Debug for BinanceVenue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinanceVenue")
            .field("base", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl BinanceVenue {
    /// Construct against the public API (override `base` for tests).
    #[must_use]
    pub fn new(client: reqwest::Client, base: impl Into<String>) -> Self {
        Self {
            client,
            base: base.into(),
        }
    }

    /// Parse `{"symbol":"BTCUSDT","price":"43000.00"}`.
    ///
    /// # Errors
    /// [`VenueError::Parse`] if the body lacks a string `price`.
    pub fn parse_price(body: &str) -> Result<U256, VenueError> {
        json_price(body, &["price"])
    }
}

#[async_trait]
impl PriceVenue for BinanceVenue {
    fn name(&self) -> &'static str {
        "binance"
    }
    async fn fetch_price_observation(&self, symbol: &str) -> Result<SourcedValue, VenueError> {
        let url = format!("{}/api/v3/ticker/price?symbol={symbol}", self.base);
        let body = http_get(&self.client, &url).await?;
        Ok(SourcedValue {
            source: self.name(),
            subject: symbol.to_string(),
            value: Self::parse_price(&body)?,
            response_hash: keccak256(body.as_bytes()),
            raw_response: body,
        })
    }
}

/// `coinbase` spot-price venue client.
pub struct CoinbaseVenue {
    client: reqwest::Client,
    base: String,
}

impl std::fmt::Debug for CoinbaseVenue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoinbaseVenue")
            .field("base", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl CoinbaseVenue {
    /// Construct against the public API (override `base` for tests).
    #[must_use]
    pub fn new(client: reqwest::Client, base: impl Into<String>) -> Self {
        Self {
            client,
            base: base.into(),
        }
    }

    /// Parse `{"data":{"amount":"43000.00","base":"BTC","currency":"USD"}}`.
    ///
    /// # Errors
    /// [`VenueError::Parse`] if the body lacks `data.amount`.
    pub fn parse_price(body: &str) -> Result<U256, VenueError> {
        json_price(body, &["data", "amount"])
    }
}

#[async_trait]
impl PriceVenue for CoinbaseVenue {
    fn name(&self) -> &'static str {
        "coinbase"
    }
    async fn fetch_price_observation(&self, symbol: &str) -> Result<SourcedValue, VenueError> {
        let url = format!("{}/v2/prices/{symbol}/spot", self.base);
        let body = http_get(&self.client, &url).await?;
        Ok(SourcedValue {
            source: self.name(),
            subject: symbol.to_string(),
            value: Self::parse_price(&body)?,
            response_hash: keccak256(body.as_bytes()),
            raw_response: body,
        })
    }
}

/// `kraken` spot-price venue client.
pub struct KrakenVenue {
    client: reqwest::Client,
    base: String,
}

impl std::fmt::Debug for KrakenVenue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KrakenVenue")
            .field("base", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl KrakenVenue {
    /// Construct against the public API (override `base` for tests).
    #[must_use]
    pub fn new(client: reqwest::Client, base: impl Into<String>) -> Self {
        Self {
            client,
            base: base.into(),
        }
    }

    /// Parse `{"error":[],"result":{"XXBTZUSD":{"c":["43000.0","0.1"], ...}}}`
    /// — the last-trade price `c[0]` of the single result pair.
    ///
    /// # Errors
    /// [`VenueError::Parse`] if the result pair or `c[0]` is absent.
    pub fn parse_price(body: &str) -> Result<U256, VenueError> {
        let v: Value = serde_json::from_str(body).map_err(|e| VenueError::Parse(e.to_string()))?;
        let pair = v
            .get("result")
            .and_then(Value::as_object)
            .and_then(|m| m.values().next())
            .ok_or_else(|| VenueError::Parse("missing result pair".to_string()))?;
        let last = pair
            .get("c")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .ok_or_else(|| VenueError::Parse("missing c[0]".to_string()))?;
        decimal_to_wad(last)
    }
}

#[async_trait]
impl PriceVenue for KrakenVenue {
    fn name(&self) -> &'static str {
        "kraken"
    }
    async fn fetch_price_observation(&self, symbol: &str) -> Result<SourcedValue, VenueError> {
        let url = format!("{}/0/public/Ticker?pair={symbol}", self.base);
        let body = http_get(&self.client, &url).await?;
        Ok(SourcedValue {
            source: self.name(),
            subject: symbol.to_string(),
            value: Self::parse_price(&body)?,
            response_hash: keccak256(body.as_bytes()),
            raw_response: body,
        })
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]
    use super::*;

    fn wad(int: u64, frac_e18: u64) -> U256 {
        U256::from(int) * U256::from(10u64).pow(U256::from(18u64)) + U256::from(frac_e18)
    }

    #[test]
    fn decimal_to_wad_cases() {
        assert_eq!(decimal_to_wad("1").expect("1"), wad(1, 0));
        assert_eq!(
            decimal_to_wad("0.5").expect("0.5"),
            wad(0, 500_000_000_000_000_000)
        );
        assert_eq!(
            decimal_to_wad("43000.50").expect("p"),
            wad(43_000, 500_000_000_000_000_000)
        );
        assert_eq!(
            decimal_to_wad(".25").expect(".25"),
            wad(0, 250_000_000_000_000_000)
        );
        // > 18 frac digits truncate (sub-wei dropped).
        assert_eq!(
            decimal_to_wad("1.0000000000000000009").expect("trunc"),
            wad(1, 0)
        );
        assert!(decimal_to_wad("").is_err());
        assert!(decimal_to_wad("-1").is_err());
        assert!(decimal_to_wad("1.2.3").is_err());
        assert!(decimal_to_wad("abc").is_err());
    }

    /// G/red-team RT-A-LOW: an oversized decimal string must FAIL CLOSED, not
    /// silently wrap mod 2^256 to an attacker-chosen value.
    #[test]
    fn decimal_to_scaled_overflow_fails_closed() {
        // ~1e60 integer * 1e18 scale wraps in unchecked U256 arithmetic.
        let huge = "1".to_string() + &"0".repeat(60);
        assert!(
            decimal_to_scaled(&huge, 18).is_err(),
            "oversized value must be rejected, never wrapped"
        );
        // A scale exponent that itself overflows 10^d (d > 77) fails closed.
        assert!(decimal_to_scaled("1", 78).is_err());
        // A realistic value still scales fine.
        assert_eq!(
            decimal_to_scaled("19500000", 8).expect("ok"),
            U256::from(19_500_000u64) * U256::from(100_000_000u64)
        );
    }

    #[test]
    fn parses_each_venue_body() {
        assert_eq!(
            BinanceVenue::parse_price(r#"{"symbol":"BTCUSDT","price":"43000.00"}"#).expect("b"),
            wad(43_000, 0)
        );
        assert_eq!(
            CoinbaseVenue::parse_price(
                r#"{"data":{"amount":"43000.5","base":"BTC","currency":"USD"}}"#
            )
            .expect("c"),
            wad(43_000, 500_000_000_000_000_000)
        );
        assert_eq!(
            KrakenVenue::parse_price(
                r#"{"error":[],"result":{"XXBTZUSD":{"a":["1"],"b":["1"],"c":["43000.0","0.1"]}}}"#
            )
            .expect("k"),
            wad(43_000, 0)
        );
        // Malformed bodies error (not panic).
        assert!(BinanceVenue::parse_price("{}").is_err());
        assert!(KrakenVenue::parse_price(r#"{"result":{}}"#).is_err());
    }

    #[derive(Debug)]
    struct MockVenue {
        name: &'static str,
        result: Result<U256, ()>,
    }
    #[async_trait]
    impl PriceVenue for MockVenue {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn fetch_price_observation(&self, symbol: &str) -> Result<SourcedValue, VenueError> {
            self.result
                .map(|value| SourcedValue {
                    source: self.name,
                    subject: symbol.to_string(),
                    value,
                    response_hash: B256::repeat_byte(1),
                    raw_response: "mock".to_string(),
                })
                .map_err(|()| VenueError::Http("mock down".to_string()))
        }
    }

    #[tokio::test]
    async fn source_quotes_tolerates_per_venue_failures() {
        let ok1 = MockVenue {
            name: "a",
            result: Ok(U256::from(100u64)),
        };
        let down = MockVenue {
            name: "b",
            result: Err(()),
        };
        let ok2 = MockVenue {
            name: "c",
            result: Ok(U256::from(102u64)),
        };
        let feeds = [
            Feed {
                venue: &ok1,
                symbol: "X",
            },
            Feed {
                venue: &down,
                symbol: "X",
            },
            Feed {
                venue: &ok2,
                symbol: "X",
            },
        ];
        // The down venue is dropped; the two live quotes survive.
        assert_eq!(
            source_quotes(&feeds).await,
            vec![U256::from(100u64), U256::from(102u64)]
        );
    }
}
