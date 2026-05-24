//! HTTP client for `THORNode` REST.
//!
//! Stateless: holds only the base URL + a shared `reqwest::Client`. All
//! methods are `async`. JSON deserialization via serde; errors funnel
//! through [`ThorError`].

use std::time::Duration;

use futures_util::StreamExt;
use reqwest::Client;
use thiserror::Error;

use crate::types::{InboundAddress, OutboundEntry, Pool, TxResponse};

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
    Transport(#[from] reqwest::Error),
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
}

/// Minimal `THORNode` REST client.
///
/// Construct with [`ThorClient::new`] (mainnet default base URL),
/// [`ThorClient::stagenet`], or [`ThorClient::with_base_url`].
#[derive(Debug, Clone)]
pub struct ThorClient {
    base_url: String,
    http: Client,
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
        let http = Client::builder().timeout(Duration::from_secs(10)).build()?;
        Ok(Self {
            base_url: base_url.into(),
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
        self.http = Client::builder().timeout(timeout).build()?;
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
        tracing::debug!(url = %url, "thornode GET");
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        let body = read_body_capped(resp).await?;
        if !status.is_success() {
            return Err(ThorError::Http {
                status: status.as_u16(),
                body,
            });
        }
        serde_json::from_str(&body).map_err(|e| ThorError::Decode(e.to_string()))
    }
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
        let chunk = chunk?;
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BODY_BYTES {
            return Err(ThorError::ResponseTooLarge {
                limit: MAX_RESPONSE_BODY_BYTES,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|e| ThorError::Decode(format!("non-utf8 body: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
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
}
