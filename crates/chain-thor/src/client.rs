//! HTTP client for `THORNode` REST.
//!
//! Stateless: holds only the base URL + a shared `reqwest::Client`. All
//! methods are `async`. JSON deserialization via serde; errors funnel
//! through [`ThorError`].

use std::time::Duration;

use alloy_primitives::{keccak256, B256, U256};
use futures_util::StreamExt;
use reqwest::Client;
use thiserror::Error;

use crate::types::{
    AsgardMembershipError, AsgardVault, ConsensusStatusResponse, ConsensusTip,
    HistoricalAsgardMembership, InboundAddress, Mimir, OutboundEntry, Pool, SwapQuoteRequest,
    SwapQuoteResponse, TxDetailsResponse, TxResponse, TxStatusResponse,
};

/// Maximum response body size accepted from `THORNode` (16 MiB). A
/// well-behaved `THORNode` response is well under 1 MiB; the 16 MiB cap
/// bounds memory exhaustion if a compromised or malicious upstream
/// streams a large body. Hits before deserialize, so a hostile JSON
/// stream can't OOM the daemon under cover of valid syntax.
const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Errors surfaced by `THORNode` RPC calls.
#[derive(Debug, Error)]
pub enum ThorError {
    /// Network / transport failure (DNS, TLS, connect, body read).
    #[error("transport error: {0}")]
    Transport(&'static str),
    /// `THORNode` returned a non-2xx status.
    #[error("HTTP {status}: {body}")]
    Http { status: u16, body: String },
    /// Response body exceeded [`MAX_RESPONSE_BODY_BYTES`]. Fail loud
    /// rather than silently truncate or OOM.
    #[error("response too large: > {limit} bytes")]
    ResponseTooLarge { limit: usize },
    /// Successful response that didn't deserialize.
    #[error("decode error: {0}")]
    Decode(String),
    /// A finalized transaction did not yield an exact, eligible historical
    /// Asgard membership set.
    #[error("historical Asgard membership: {0}")]
    AsgardMembership(#[from] AsgardMembershipError),
}

/// Exact upstream response retained for evidence-before-signing workflows.
/// `response_hash` is Keccak-256 over the byte-for-byte UTF-8 body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse<T> {
    pub value: T,
    pub raw_body: String,
    pub response_hash: B256,
}

/// Minimal `THORNode` REST client.
///
/// Construct with [`ThorClient::new`] (mainnet default base URL),
/// [`ThorClient::stagenet`], or [`ThorClient::with_base_url`].
#[derive(Clone)]
pub struct ThorClient {
    base_url: String,
    http: Client,
}

impl std::fmt::Debug for ThorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThorClient")
            .field("base_url", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ThorClient {
    /// Mainnet `THORNode` at `thornode.thorchain.network`.
    /// 10-second total request timeout — adjust via [`ThorClient::with_timeout`]
    /// if your operator runs poll-heavy workloads.
    ///
    /// # Errors
    /// Returns [`ThorError::Transport`] if the underlying reqwest client
    /// cannot be constructed (typically TLS configuration failures).
    pub fn new() -> Result<Self, ThorError> {
        Self::with_base_url("https://thornode.thorchain.network")
    }

    /// Stagenet `THORNode` at `stagenet-thornode.ninerealms.com`.
    ///
    /// # Errors
    /// See [`ThorClient::new`].
    pub fn stagenet() -> Result<Self, ThorError> {
        Self::with_base_url("https://stagenet-thornode.ninerealms.com")
    }

    /// Custom base URL (no trailing slash). Lets tests point at a
    /// `wiremock::MockServer` or operators point at a private node.
    ///
    /// # Errors
    /// Returns [`ThorError::Transport`] if reqwest client construction fails.
    pub fn with_base_url(base_url: impl Into<String>) -> Result<Self, ThorError> {
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ThorError::Transport(transport_class(&e)))?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    /// Override the default 10-second request timeout.
    ///
    /// # Errors
    /// Returns [`ThorError::Transport`] if the underlying reqwest client
    /// cannot be rebuilt (typically TLS configuration failures). Caller
    /// must propagate — silent fallback would leave the previous timeout
    /// in place with no signal.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, ThorError> {
        self.http = Client::builder()
            .connect_timeout(timeout.min(Duration::from_secs(3)))
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ThorError::Transport(transport_class(&e)))?;
        Ok(self)
    }

    /// `GET /thorchain/inbound_addresses` — current Asgard vault addresses
    /// per supported chain plus halt flags.
    ///
    /// # Errors
    /// [`ThorError::Transport`] on network failure, [`ThorError::Http`]
    /// on non-2xx, [`ThorError::Decode`] on schema mismatch.
    pub async fn fetch_inbound_addresses(&self) -> Result<Vec<InboundAddress>, ThorError> {
        self.get_json("/thorchain/inbound_addresses").await
    }

    /// `GET /thorchain/tx/{hash}` — observed inbound + queued outbound.
    /// Used by signers to verify the deposit landed before signing.
    ///
    /// # Errors
    /// As [`ThorClient::fetch_inbound_addresses`].
    pub async fn tx_status(&self, hash: &str) -> Result<TxResponse, ThorError> {
        let path = format!("/thorchain/tx/{hash}");
        self.get_json(&path).await
    }

    /// Exact raw observation response for evidence-before-signing workflows.
    ///
    /// # Errors
    /// As [`ThorClient::tx_status`].
    pub async fn tx_status_evidence(
        &self,
        hash: &str,
    ) -> Result<RawResponse<TxResponse>, ThorError> {
        let path = format!("/thorchain/tx/{hash}");
        self.get_evidence(&path).await
    }

    /// `GET /thorchain/tx/details/{hash}` — the richer details view whose
    /// `out_txs` carry the OBSERVED outbound on-chain hash(es). The
    /// observation view ([`ThorClient::tx_status`]) only lists PLANNED
    /// outbound actions with no hash; RUST-004 reads this view to bind the
    /// delivered USDT `Transfer.transaction_hash` to the specific
    /// `THORChain` outbound 1:1.
    ///
    /// # Errors
    /// As [`ThorClient::fetch_inbound_addresses`].
    pub async fn tx_details(&self, hash: &str) -> Result<TxDetailsResponse, ThorError> {
        let path = format!("/thorchain/tx/details/{hash}");
        self.get_json(&path).await
    }

    /// Exact raw observed-outbound response for pre-sign evidence.
    ///
    /// # Errors
    /// As [`ThorClient::tx_details`].
    pub async fn tx_details_evidence(
        &self,
        hash: &str,
    ) -> Result<RawResponse<TxDetailsResponse>, ThorError> {
        let path = format!("/thorchain/tx/details/{hash}");
        self.get_evidence(&path).await
    }

    /// `GET /thorchain/tx/status/{hash}` — the swap-lifecycle "stages"
    /// view. Distinct from [`ThorClient::tx_status`] (the observation
    /// view): this carries `swap_finalised.completed` plus the streaming
    /// `count` / `quantity`, which the coordinator's streaming-swap
    /// FINALITY gate ([`TxStatusResponse::is_swap_finalised`]) reads before
    /// settling a streamed redeem (`STREAM-B2-COORD`).
    ///
    /// # Errors
    /// As [`ThorClient::fetch_inbound_addresses`].
    pub async fn tx_status_stages(&self, hash: &str) -> Result<TxStatusResponse, ThorError> {
        let path = format!("/thorchain/tx/status/{hash}");
        self.get_json(&path).await
    }

    /// Exact raw swap-lifecycle response for pre-sign evidence.
    ///
    /// # Errors
    /// As [`ThorClient::tx_status_stages`].
    pub async fn tx_status_stages_evidence(
        &self,
        hash: &str,
    ) -> Result<RawResponse<TxStatusResponse>, ThorError> {
        let path = format!("/thorchain/tx/status/{hash}");
        self.get_evidence(&path).await
    }

    /// `GET /thorchain/queue/outbound` — outbound transactions `THORChain`
    /// has decided on but not yet broadcast on the destination chain.
    ///
    /// # Errors
    /// As [`ThorClient::fetch_inbound_addresses`].
    pub async fn outbound_queue(&self) -> Result<Vec<OutboundEntry>, ThorError> {
        self.get_json("/thorchain/queue/outbound").await
    }

    /// `GET /thorchain/pools` — current pool depths.
    ///
    /// # Errors
    /// As [`ThorClient::fetch_inbound_addresses`].
    pub async fn pools(&self) -> Result<Vec<Pool>, ThorError> {
        self.get_json("/thorchain/pools").await
    }

    /// `GET /thorchain/mimir` — current network and chain halt controls.
    ///
    /// # Errors
    /// As [`ThorClient::fetch_inbound_addresses`].
    pub async fn mimir(&self) -> Result<Mimir, ThorError> {
        self.get_json("/thorchain/mimir").await
    }

    /// Fetch inbound rows while retaining the exact raw response for an
    /// append-only signer evidence record.
    ///
    /// # Errors
    /// As [`ThorClient::fetch_inbound_addresses`].
    pub async fn inbound_evidence(&self) -> Result<RawResponse<Vec<InboundAddress>>, ThorError> {
        self.get_evidence("/thorchain/inbound_addresses").await
    }

    /// Fetch active/retiring Asgard membership at the finalized `THORChain`
    /// height bound by `status`, retaining the exact vault response body for
    /// pre-sign evidence.
    ///
    /// Historical membership is used only for settlement sender/destination
    /// identity. Callers must separately consult current inbound rows for live
    /// halt and routing policy.
    ///
    /// # Errors
    /// Fails on a missing/invalid finalized height, transport/HTTP/schema
    /// failure, or if the historical response has no eligible address for
    /// `chain`.
    pub async fn historical_asgard_membership_evidence(
        &self,
        status: &TxResponse,
        chain: &str,
    ) -> Result<RawResponse<HistoricalAsgardMembership>, ThorError> {
        let height = status.historical_asgard_height()?;
        let base = format!("{}/thorchain/vaults/asgard", self.base_url);
        let mut url = reqwest::Url::parse(&base)
            .map_err(|error| ThorError::Decode(format!("invalid Asgard endpoint: {error}")))?;
        url.query_pairs_mut()
            .append_pair("height", &height.to_string());
        let response: RawResponse<Vec<AsgardVault>> = self
            .get_evidence_url(url, "/thorchain/vaults/asgard")
            .await?;
        let membership = HistoricalAsgardMembership::from_vaults(height, chain, &response.value)?;
        Ok(RawResponse {
            value: membership,
            raw_body: response.raw_body,
            response_hash: response.response_hash,
        })
    }

    /// Historical Asgard membership without raw evidence retention.
    ///
    /// # Errors
    /// As [`Self::historical_asgard_membership_evidence`].
    pub async fn historical_asgard_membership(
        &self,
        status: &TxResponse,
        chain: &str,
    ) -> Result<HistoricalAsgardMembership, ThorError> {
        Ok(self
            .historical_asgard_membership_evidence(status, chain)
            .await?
            .value)
    }

    /// Fetch Mimir while retaining exact raw evidence.
    ///
    /// # Errors
    /// As [`ThorClient::fetch_inbound_addresses`].
    pub async fn mimir_evidence(&self) -> Result<RawResponse<Mimir>, ThorError> {
        self.get_evidence("/thorchain/mimir").await
    }

    /// Fetch pools while retaining exact raw evidence.
    ///
    /// # Errors
    /// As [`ThorClient::fetch_inbound_addresses`].
    pub async fn pools_evidence(&self) -> Result<RawResponse<Vec<Pool>>, ThorError> {
        self.get_evidence("/thorchain/pools").await
    }

    /// `GET /thorchain/quote/swap` with Xindex's complete, explicit query
    /// shape. The request type has no affiliate or legacy `tolerance_bps`
    /// field, so those unsafe options cannot be emitted accidentally.
    ///
    /// # Errors
    /// [`ThorError::Decode`] for an invalid request or response and the usual
    /// transport/HTTP errors.
    pub async fn quote_swap(
        &self,
        request: &SwapQuoteRequest,
    ) -> Result<RawResponse<SwapQuoteResponse>, ThorError> {
        validate_quote_request(request)?;
        let base = format!("{}/thorchain/quote/swap", self.base_url);
        let mut url = reqwest::Url::parse(&base)
            .map_err(|error| ThorError::Decode(format!("invalid quote endpoint: {error}")))?;
        url.query_pairs_mut()
            .append_pair("from_asset", &request.from_asset)
            .append_pair("to_asset", &request.to_asset)
            .append_pair("amount", &request.amount)
            .append_pair("destination", &request.destination)
            .append_pair("refund_address", &request.refund_address)
            .append_pair(
                "liquidity_tolerance_bps",
                &request.liquidity_tolerance_bps.to_string(),
            )
            .append_pair(
                "streaming_interval",
                &request.streaming_interval.to_string(),
            )
            .append_pair(
                "streaming_quantity",
                &request.streaming_quantity.to_string(),
            );
        self.get_evidence_url(url, "/thorchain/quote/swap").await
    }

    /// Convenience: filter `fetch_inbound_addresses` to a single chain.
    ///
    /// # Errors
    /// As [`ThorClient::fetch_inbound_addresses`].
    pub async fn vault_for_chain(&self, chain: &str) -> Result<Option<InboundAddress>, ThorError> {
        let entries = self.fetch_inbound_addresses().await?;
        Ok(entries.into_iter().find(|e| e.chain == chain))
    }

    async fn get_json<T: for<'de> serde::Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<T, ThorError> {
        let url = format!("{}{}", self.base_url, path);
        let url = reqwest::Url::parse(&url)
            .map_err(|error| ThorError::Decode(format!("invalid endpoint: {error}")))?;
        Ok(self.get_evidence_url(url, path).await?.value)
    }

    async fn get_evidence<T: for<'de> serde::Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<RawResponse<T>, ThorError> {
        let url = format!("{}{}", self.base_url, path);
        let url = reqwest::Url::parse(&url)
            .map_err(|error| ThorError::Decode(format!("invalid endpoint: {error}")))?;
        self.get_evidence_url(url, path).await
    }

    async fn get_evidence_url<T: for<'de> serde::Deserialize<'de>>(
        &self,
        url: reqwest::Url,
        path_label: &str,
    ) -> Result<RawResponse<T>, ThorError> {
        tracing::debug!(path = path_label, "thornode GET");
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| ThorError::Transport(transport_class(&e)))?;
        let status = resp.status();
        let body = read_body_capped(resp).await?;
        if !status.is_success() {
            return Err(ThorError::Http {
                status: status.as_u16(),
                body,
            });
        }
        let value = serde_json::from_str(&body).map_err(|e| ThorError::Decode(e.to_string()))?;
        let response_hash = keccak256(body.as_bytes());
        Ok(RawResponse {
            value,
            raw_body: body,
            response_hash,
        })
    }
}

/// Minimal `CometBFT` RPC client for consensus freshness. `THORNode` REST and
/// `CometBFT` RPC normally use different origins, so they are deliberately
/// configured as separate clients and separately committed in evidence.
#[derive(Clone)]
pub struct ThorConsensusClient {
    base_url: String,
    http: Client,
}

impl std::fmt::Debug for ThorConsensusClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThorConsensusClient")
            .field("base_url", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ThorConsensusClient {
    /// Construct a client for one `CometBFT` RPC origin.
    ///
    /// # Errors
    /// [`ThorError::Transport`] if the HTTP client cannot be built.
    pub fn with_base_url(base_url: impl Into<String>) -> Result<Self, ThorError> {
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| ThorError::Transport(transport_class(&error)))?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    /// Query `/status`, parse height and RFC3339 block time, and retain the
    /// exact body used to produce the policy-ready tip.
    ///
    /// # Errors
    /// Transport/HTTP/schema errors, zero/malformed height, or malformed time.
    pub async fn status(&self) -> Result<RawResponse<ConsensusTip>, ThorError> {
        let url = reqwest::Url::parse(&format!("{}/status", self.base_url))
            .map_err(|error| ThorError::Decode(format!("invalid consensus endpoint: {error}")))?;
        tracing::debug!(path = "/status", "cometbft GET");
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|error| ThorError::Transport(transport_class(&error)))?;
        let status = response.status();
        let body = read_body_capped(response).await?;
        if !status.is_success() {
            return Err(ThorError::Http {
                status: status.as_u16(),
                body,
            });
        }
        let envelope: ConsensusStatusResponse =
            serde_json::from_str(&body).map_err(|error| ThorError::Decode(error.to_string()))?;
        let height = envelope
            .result
            .sync_info
            .latest_block_height
            .parse::<u64>()
            .map_err(|error| ThorError::Decode(format!("invalid consensus height: {error}")))?;
        if height == 0 {
            return Err(ThorError::Decode(
                "consensus height must be non-zero".to_string(),
            ));
        }
        let block_time_unix = parse_cometbft_time(&envelope.result.sync_info.latest_block_time)?;
        let tip = ConsensusTip {
            node_id: envelope.result.node_info.id,
            network: envelope.result.node_info.network,
            version: envelope.result.node_info.version,
            block_hash: envelope.result.sync_info.latest_block_hash,
            height,
            block_time_unix,
            catching_up: envelope.result.sync_info.catching_up,
        };
        Ok(RawResponse {
            value: tip,
            response_hash: keccak256(body.as_bytes()),
            raw_body: body,
        })
    }
}

fn validate_quote_request(request: &SwapQuoteRequest) -> Result<(), ThorError> {
    if request.from_asset.is_empty()
        || request.to_asset.is_empty()
        || request.destination.is_empty()
        || request.refund_address.is_empty()
        || U256::from_str_radix(&request.amount, 10)
            .ok()
            .is_none_or(|amount| amount.is_zero())
    {
        return Err(ThorError::Decode(
            "quote request contains an empty field or non-positive amount".to_string(),
        ));
    }
    if !(1..10_000).contains(&request.liquidity_tolerance_bps) {
        return Err(ThorError::Decode(
            "liquidity_tolerance_bps must be in 1..10000".to_string(),
        ));
    }
    if request.streaming_quantity == 0 {
        return Err(ThorError::Decode(
            "streaming_quantity must be explicit and non-zero".to_string(),
        ));
    }
    if request.streaming_quantity == 1 && request.streaming_interval != 1 {
        return Err(ThorError::Decode(
            "forced-single quotes must use streaming_interval=1 and quantity=1".to_string(),
        ));
    }
    Ok(())
}

/// Parse the UTC RFC3339 shape emitted by `CometBFT` without adding another
/// date/time dependency to the audited service graph. Fractional seconds are
/// accepted and ignored; offsets other than `Z` fail closed because a normal
/// `CometBFT` status response is UTC.
fn parse_cometbft_time(raw: &str) -> Result<u64, ThorError> {
    let bytes = raw.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || bytes.last() != Some(&b'Z')
    {
        return Err(ThorError::Decode(
            "consensus time must be UTC RFC3339".to_string(),
        ));
    }
    let year = parse_decimal(&bytes[0..4], "year")?;
    let month = parse_decimal(&bytes[5..7], "month")?;
    let day = parse_decimal(&bytes[8..10], "day")?;
    let hour = parse_decimal(&bytes[11..13], "hour")?;
    let minute = parse_decimal(&bytes[14..16], "minute")?;
    let second = parse_decimal(&bytes[17..19], "second")?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(ThorError::Decode(
            "consensus time contains an out-of-range component".to_string(),
        ));
    }
    if bytes.len() > 20
        && (bytes[19] != b'.' || !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return Err(ThorError::Decode(
            "consensus time has an invalid fractional component".to_string(),
        ));
    }
    let days = days_since_unix_epoch(year, month, day)
        .ok_or_else(|| ThorError::Decode("consensus time is before the unix epoch".to_string()))?;
    days.checked_mul(86_400)
        .and_then(|value| value.checked_add(hour * 3_600 + minute * 60 + second))
        .ok_or_else(|| ThorError::Decode("consensus time overflows u64".to_string()))
}

fn parse_decimal(bytes: &[u8], field: &'static str) -> Result<u64, ThorError> {
    if !bytes.iter().all(u8::is_ascii_digit) {
        return Err(ThorError::Decode(format!(
            "consensus time {field} is not decimal"
        )));
    }
    bytes.iter().try_fold(0u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| ThorError::Decode(format!("consensus time {field} overflows")))
    })
}

const fn is_leap_year(year: u64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

const fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Gregorian days since 1970-01-01. Validated inputs only.
const fn days_since_unix_epoch(year: u64, month: u64, day: u64) -> Option<u64> {
    if year < 1970 {
        return None;
    }
    let mut days = 0u64;
    let mut current_year = 1970u64;
    while current_year < year {
        days += if is_leap_year(current_year) { 366 } else { 365 };
        current_year += 1;
    }
    let mut current_month = 1u64;
    while current_month < month {
        days += days_in_month(year, current_month);
        current_month += 1;
    }
    Some(days + day - 1)
}

/// Read the response body into a `String`, refusing anything larger than
/// [`MAX_RESPONSE_BODY_BYTES`]. Streams chunk-by-chunk so an oversized
/// body bails before fully buffering. Used by both the success and
/// error paths so a malicious 503 with a 1 GB body can't OOM us either.
///
/// On chunk-read failure, surfaces the underlying [`reqwest::Error`] —
/// preserves context that the prior `unwrap_or_default()` swallowed.
async fn read_body_capped(resp: reqwest::Response) -> Result<String, ThorError> {
    let mut bytes = Vec::with_capacity(8 * 1024);
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| ThorError::Transport(transport_class(&e)))?;
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BODY_BYTES {
            return Err(ThorError::ResponseTooLarge {
                limit: MAX_RESPONSE_BODY_BYTES,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|e| ThorError::Decode(format!("non-utf8 body: {e}")))
}

/// Classify a reqwest failure without copying its display string: reqwest
/// errors may embed the complete credential-bearing request URL.
fn transport_class(error: &reqwest::Error) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Sample payload pinned against `THORChain` mainnet (truncated to one
    /// chain — BTC) plus a representative ETH entry. Field names are
    /// verbatim from `~/refs/thornode/openapi/openapi.yaml::InboundAddress`.
    fn sample_inbound_addresses() -> serde_json::Value {
        serde_json::json!([
            {
                "chain": "BTC",
                "pub_key": "thorpub1addwnpepqg9...",
                "address": "bc1qexamplemultisigaddress",
                "halted": false,
                "global_trading_paused": false,
                "chain_trading_paused": false,
                "chain_lp_actions_paused": false,
                "gas_rate": "10",
                "gas_rate_units": "satsperbyte"
            },
            {
                "chain": "ETH",
                "pub_key": "thorpub1addwnpepqg9...",
                "address": "0xeAf72A36ec9F0F8D90C0E5e3b9C2A95eAfBcDef0",
                "router": "0xD37BbE5744D730a1d98d8DC97c42F0Ca46aD7146",
                "halted": false,
                "global_trading_paused": false,
                "chain_trading_paused": false,
                "chain_lp_actions_paused": false,
                "gas_rate": "20",
                "gas_rate_units": "gwei"
            }
        ])
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn fetch_inbound_addresses_decodes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/thorchain/inbound_addresses"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_inbound_addresses()))
            .mount(&server)
            .await;

        let client = ThorClient::with_base_url(server.uri()).expect("client");
        let entries = client.fetch_inbound_addresses().await.expect("fetch");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].chain, "BTC");
        assert_eq!(entries[1].chain, "ETH");
        assert_eq!(
            entries[1].router.as_deref(),
            Some("0xD37BbE5744D730a1d98d8DC97c42F0Ca46aD7146")
        );
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn vault_for_chain_filters() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/thorchain/inbound_addresses"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_inbound_addresses()))
            .mount(&server)
            .await;

        let client = ThorClient::with_base_url(server.uri()).expect("client");
        let btc = client.vault_for_chain("BTC").await.expect("query");
        assert!(btc.is_some());
        assert_eq!(
            btc.expect("btc entry").address,
            "bc1qexamplemultisigaddress"
        );
        let none = client.vault_for_chain("DOESNT_EXIST").await.expect("query");
        assert!(none.is_none());
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn historical_asgard_membership_queries_exact_finalised_height() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/thorchain/vaults/asgard"))
            .and(query_param("height", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "pub_key": "thorpub1active",
                    "type": "AsgardVault",
                    "status": "ActiveVault",
                    "status_since": 90,
                    "addresses": [{ "chain": "BTC", "address": "bc1qvault-a" }]
                },
                {
                    "pub_key": "thorpub1retiring",
                    "type": "AsgardVault",
                    "status": "RetiringVault",
                    "status_since": 95,
                    "addresses": [{ "chain": "BTC", "address": "bc1qvault-r" }]
                }
            ])))
            .mount(&server)
            .await;
        let status: TxResponse = serde_json::from_value(serde_json::json!({
            "observed_tx": {
                "tx": {
                    "id": "ABC", "chain": "BTC", "from_address": "from",
                    "to_address": "to", "coins": [], "memo": ""
                },
                "status": "done"
            },
            "actions": [],
            "finalised_height": 100
        }))
        .expect("status fixture");

        let client = ThorClient::with_base_url(server.uri()).expect("client");
        let evidence = client
            .historical_asgard_membership_evidence(&status, "BTC")
            .await
            .expect("membership");
        assert_eq!(evidence.value.height, 100);
        assert_eq!(
            evidence.value.addresses,
            vec!["bc1qvault-a".to_string(), "bc1qvault-r".to_string()]
        );
        assert_eq!(
            evidence.response_hash,
            keccak256(evidence.raw_body.as_bytes())
        );
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn tx_status_decodes_done_observation() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "observed_tx": {
                "tx": {
                    "id": "ABCDEF",
                    "chain": "ETH",
                    "from_address": "0xUser",
                    "to_address": "0xRouter",
                    "coins": [{ "asset": "ETH.USDT-0xdAC17F958D2ee523a2206206994597C13D831ec7", "amount": "100000000000" }],
                    "memo": "=:BTC.BTC:bc1quser:0"
                },
                "status": "done",
                "block_height": 12345,
                "finalise_height": 12345,
                "signers": ["thor1signer1", "thor1signer2", "thor1signer3"]
            },
            "actions": [{
                "chain": "BTC",
                "to_address": "bc1quser",
                "coin": { "asset": "BTC.BTC", "amount": "98000000" },
                "memo": "OUT:ABCDEF",
                "max_gas": [{ "asset": "BTC.BTC", "amount": "10000" }]
            }]
        });
        Mock::given(method("GET"))
            .and(path("/thorchain/tx/ABCDEF"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&server)
            .await;

        let client = ThorClient::with_base_url(server.uri()).expect("client");
        let resp = client.tx_status("ABCDEF").await.expect("tx_status");
        assert_eq!(resp.observed_tx.status, "done");
        assert_eq!(resp.actions.len(), 1);
        assert_eq!(resp.actions[0].chain, "BTC");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn http_error_surfaces_status_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/thorchain/inbound_addresses"))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
            .mount(&server)
            .await;

        let client = ThorClient::with_base_url(server.uri()).expect("client");
        let result = client.fetch_inbound_addresses().await;
        assert!(matches!(
            result,
            Err(ThorError::Http { status: 503, ref body }) if body.contains("upstream down")
        ));
    }

    /// STREAM-B2-COORD: the streaming-swap finality gate. A partial
    /// mid-stream fill (`count < quantity`) must NOT be treated as final
    /// even if `swap_finalised.completed` is set; only a fully-executed,
    /// not-pending stream settles. Fail closed on missing signals.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn streaming_finality_gate() {
        use crate::types::TxStatusResponse;
        let parse = |v: serde_json::Value| -> TxStatusResponse {
            serde_json::from_value(v).expect("decode")
        };

        // Stream fully executed (count == quantity) + finalised + not pending → final.
        assert!(parse(serde_json::json!({"stages": {
            "swap_status": {"pending": false, "streaming": {"quantity": 10, "count": 10, "interval": 1}},
            "swap_finalised": {"completed": true}
        }}))
        .is_swap_finalised());

        // Partial mid-stream (count < quantity) → NOT final, even with the flag.
        assert!(
            !parse(serde_json::json!({"stages": {
                "swap_status": {"pending": false, "streaming": {"quantity": 10, "count": 4, "interval": 1}},
                "swap_finalised": {"completed": true}
            }}))
            .is_swap_finalised(),
            "a partial fill must never settle"
        );

        // Still pending → not final.
        assert!(!parse(serde_json::json!({"stages": {
            "swap_status": {"pending": true, "streaming": {"quantity": 10, "count": 10, "interval": 1}},
            "swap_finalised": {"completed": true}
        }}))
        .is_swap_finalised());

        // swap_finalised not completed → not final.
        assert!(
            !parse(serde_json::json!({"stages": {"swap_finalised": {"completed": false}}}))
                .is_swap_finalised()
        );

        // Non-streaming swap (no streaming sub-object), finalised → final.
        assert!(parse(serde_json::json!({"stages": {
            "swap_status": {"pending": false},
            "swap_finalised": {"completed": true}
        }}))
        .is_swap_finalised());

        // Empty / missing stages → not final (fail closed).
        assert!(!parse(serde_json::json!({})).is_swap_finalised());

        // Degenerate present-but-empty streaming object (count==quantity==0)
        // must NOT read final via 0>=0 (G/red-team RT-C-INFO) — defer instead.
        assert!(
            !parse(serde_json::json!({"stages": {
                "swap_status": {"pending": false, "streaming": {"quantity": 0, "count": 0}},
                "swap_finalised": {"completed": true}
            }}))
            .is_swap_finalised(),
            "a degenerate empty stream must not settle"
        );
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn tx_status_stages_decodes_and_gates() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "stages": {
                "inbound_observed": {"completed": true},
                "swap_status": {"pending": false, "streaming": {"quantity": 5, "count": 5, "interval": 1}},
                "swap_finalised": {"completed": true}
            }
        });
        Mock::given(method("GET"))
            .and(path("/thorchain/tx/status/ABC"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&server)
            .await;
        let client = ThorClient::with_base_url(server.uri()).expect("client");
        let resp = client.tx_status_stages("ABC").await.expect("stages");
        assert!(resp.is_swap_finalised());
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn mimir_and_quote_evidence_are_exact_and_explicit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/thorchain/mimir"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"HALTTRADING":0,"HALTSIGNINGETH":1}"#),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/thorchain/quote/swap"))
            .and(query_param("from_asset", "ETH.USDT-0XDAC17F"))
            .and(query_param("to_asset", "BTC.BTC"))
            .and(query_param("amount", "100000000"))
            .and(query_param("destination", "bc1qcustody"))
            .and(query_param(
                "refund_address",
                "0x1111111111111111111111111111111111111111",
            ))
            .and(query_param("liquidity_tolerance_bps", "500"))
            .and(query_param("streaming_interval", "1"))
            .and(query_param("streaming_quantity", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "inbound_address": "0x2222222222222222222222222222222222222222",
                "inbound_confirmation_blocks": 2,
                "inbound_confirmation_seconds": 24,
                "outbound_delay_blocks": 10,
                "outbound_delay_seconds": 60,
                "fees": {
                    "asset": "BTC.BTC",
                    "affiliate": "0",
                    "outbound": "1",
                    "liquidity": "2",
                    "total": "3",
                    "slippage_bps": 10,
                    "total_bps": 20
                },
                "expiry": 1_800_000_100u64,
                "warning": "Do not cache",
                "dust_threshold": "100",
                "recommended_min_amount_in": "1000",
                "recommended_gas_rate": "20",
                "gas_rate_units": "gwei",
                "memo": "=:BTC.BTC:bc1qcustody/0x1111111111111111111111111111111111111111:900/1/1",
                "expected_amount_out": "1000",
                "max_streaming_quantity": 1,
                "streaming_swap_blocks": 0,
                "total_swap_seconds": 84
            })))
            .mount(&server)
            .await;

        let client = ThorClient::with_base_url(format!("{}/", server.uri())).expect("client");
        let mimir = client.mimir_evidence().await.expect("mimir");
        assert_eq!(mimir.value.get("HALTSIGNINGETH"), Some(&1));
        assert_eq!(mimir.response_hash, keccak256(mimir.raw_body.as_bytes()));

        let quote = client
            .quote_swap(&SwapQuoteRequest {
                from_asset: "ETH.USDT-0XDAC17F".to_string(),
                to_asset: "BTC.BTC".to_string(),
                amount: "100000000".to_string(),
                destination: "bc1qcustody".to_string(),
                refund_address: "0x1111111111111111111111111111111111111111".to_string(),
                liquidity_tolerance_bps: 500,
                streaming_interval: 1,
                streaming_quantity: 1,
            })
            .await
            .expect("quote");
        assert_eq!(quote.value.expected_amount_out, "1000");
        assert_eq!(quote.response_hash, keccak256(quote.raw_body.as_bytes()));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn consensus_status_parses_height_and_fractional_utc_time() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": -1,
                "result": {
                    "node_info": {
                        "id": "abc123",
                        "network": "thorchain-mainnet-v1",
                        "version": "0.38.17"
                    },
                    "sync_info": {
                        "latest_block_hash": "DEADBEEF",
                        "latest_block_height": "123456",
                        "latest_block_time": "2026-07-13T12:34:56.123456789Z",
                        "catching_up": false
                    }
                }
            })))
            .mount(&server)
            .await;
        let client = ThorConsensusClient::with_base_url(server.uri()).expect("client");
        let status = client.status().await.expect("status");
        assert_eq!(status.value.height, 123_456);
        assert_eq!(status.value.block_time_unix, 1_783_946_096);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn cometbft_time_parser_is_strict_and_calendar_correct() {
        assert_eq!(
            parse_cometbft_time("1970-01-01T00:00:00Z").expect("epoch"),
            0
        );
        assert_eq!(
            parse_cometbft_time("2000-02-29T00:00:00.1Z").expect("leap day"),
            951_782_400
        );
        assert!(parse_cometbft_time("2026-02-29T00:00:00Z").is_err());
        assert!(parse_cometbft_time("2026-07-13T12:00:00+04:00").is_err());
    }
}
