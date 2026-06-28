//! The Cobo v2 REST client.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::CoboSigner;
use crate::types::{ContractCallParams, CreatedTransaction, TransactionDetail};
use crate::CoboError;

/// Cobo dev-env host (free trial; the W3 reconciliation target).
pub const COBO_API_DEV: &str = "https://api.dev.cobo.com";
/// Cobo production host.
pub const COBO_API_PROD: &str = "https://api.cobo.com";

/// A minimal Cobo v2 client for the EVM redeem reroute. Every request is
/// Ed25519-signed via [`CoboSigner`].
#[derive(Debug)]
pub struct CoboClient {
    http: reqwest::Client,
    base_url: String,
    signer: CoboSigner,
}

fn now_ms() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
        .to_string()
}

impl CoboClient {
    /// Build a client for `base_url` (host only, e.g. [`COBO_API_DEV`]; paths
    /// include `/v2`).
    ///
    /// # Errors
    /// [`CoboError::Http`] if the HTTP client cannot be constructed.
    pub fn new(base_url: impl Into<String>, signer: CoboSigner) -> Result<Self, CoboError> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| CoboError::Http(e.to_string()))?;
        Ok(Self {
            http,
            base_url: base_url.into(),
            signer,
        })
    }

    /// Sign + send a request, returning the response body on 2xx.
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<String>,
    ) -> Result<String, CoboError> {
        let nonce = now_ms();
        let body_str = body.as_deref().unwrap_or("");
        // RECONCILE AT DEV-ENV: `path` here is the full request path incl. /v2,
        // and PARAMS is empty (no query on these endpoints).
        let signature = self
            .signer
            .sign(method.as_str(), path, &nonce, "", body_str);
        let url = format!("{}{}", self.base_url, path);

        let mut req = self
            .http
            .request(method, &url)
            .header("Biz-Api-Key", self.signer.api_key_hex())
            .header("Biz-Api-Nonce", &nonce)
            .header("Biz-Api-Signature", signature);
        if let Some(b) = body {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(b);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| CoboError::Http(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| CoboError::Http(e.to_string()))?;
        if status.is_success() {
            Ok(text)
        } else {
            Err(CoboError::Api {
                status: status.as_u16(),
                body: text,
            })
        }
    }

    /// `POST /v2/transactions/contract_call` — build a contract-call tx. Use
    /// `transaction_process_type = "BuildOnly"` so signing is deferred to
    /// [`Self::sign_and_broadcast`] (where the TSS Node fires our callback).
    ///
    /// # Errors
    /// [`CoboError`] on transport, a non-2xx response, or a decode failure.
    pub async fn contract_call(
        &self,
        params: &ContractCallParams,
    ) -> Result<CreatedTransaction, CoboError> {
        let body = serde_json::to_string(params).map_err(|e| CoboError::Decode(e.to_string()))?;
        let text = self
            .send(
                reqwest::Method::POST,
                "/v2/transactions/contract_call",
                Some(body),
            )
            .await?;
        serde_json::from_str(&text)
            .map_err(|e| CoboError::Decode(format!("contract_call response: {e}")))
    }

    /// `POST /v2/transactions/{id}/sign_and_broadcast` — sign + broadcast a
    /// `Built` tx. The TSS Node signs here, so our callback gates the spend.
    ///
    /// # Errors
    /// [`CoboError`] on transport, a non-2xx response, or a decode failure.
    pub async fn sign_and_broadcast(
        &self,
        transaction_id: &str,
    ) -> Result<CreatedTransaction, CoboError> {
        let path = format!("/v2/transactions/{transaction_id}/sign_and_broadcast");
        let text = self.send(reqwest::Method::POST, &path, None).await?;
        serde_json::from_str(&text)
            .map_err(|e| CoboError::Decode(format!("sign_and_broadcast response: {e}")))
    }

    /// `GET /v2/transactions/{id}` — fetch a transaction's status / hash.
    ///
    /// # Errors
    /// [`CoboError`] on transport, a non-2xx response, or a decode failure.
    pub async fn get_transaction(
        &self,
        transaction_id: &str,
    ) -> Result<TransactionDetail, CoboError> {
        let path = format!("/v2/transactions/{transaction_id}");
        let text = self.send(reqwest::Method::GET, &path, None).await?;
        serde_json::from_str(&text)
            .map_err(|e| CoboError::Decode(format!("get_transaction response: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContractCallDestination, ContractCallSource, TransactionStatus};
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_SECRET: &str = "0202020202020202020202020202020202020202020202020202020202020202";

    #[expect(clippy::expect_used, reason = "test code")]
    fn client_for(server: &MockServer) -> CoboClient {
        CoboClient::new(
            server.uri(),
            CoboSigner::from_hex(TEST_SECRET).expect("signer"),
        )
        .expect("client")
    }

    fn sample_params() -> ContractCallParams {
        ContractCallParams {
            request_id: "r-1".to_string(),
            chain_id: "ETH".to_string(),
            source: ContractCallSource {
                source_type: "Org-Controlled".to_string(),
                wallet_id: "w-1".to_string(),
                address: "0xMpc".to_string(),
            },
            destination: ContractCallDestination {
                destination_type: "EVM_Contract".to_string(),
                address: "0xRouter".to_string(),
                calldata: "0xdeadbeef".to_string(),
                value: Some("1.5".to_string()),
            },
            transaction_process_type: "BuildOnly".to_string(),
        }
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn contract_call_sends_signed_request_and_parses() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/transactions/contract_call"))
            .and(header_exists("Biz-Api-Key"))
            .and(header_exists("Biz-Api-Nonce"))
            .and(header_exists("Biz-Api-Signature"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "request_id": "r-1", "transaction_id": "tx-1", "status": "Built"
            })))
            .mount(&server)
            .await;

        let created = client_for(&server)
            .contract_call(&sample_params())
            .await
            .expect("call");
        assert_eq!(created.transaction_id, "tx-1");
        assert_eq!(created.status, TransactionStatus::Built);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sign_and_broadcast_posts_to_id_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/transactions/tx-1/sign_and_broadcast"))
            .and(header_exists("Biz-Api-Signature"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "request_id": "r-1", "transaction_id": "tx-1", "status": "Submitted"
            })))
            .mount(&server)
            .await;

        let res = client_for(&server)
            .sign_and_broadcast("tx-1")
            .await
            .expect("sab");
        assert_eq!(res.transaction_id, "tx-1");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn get_transaction_parses_status_and_hash() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/transactions/tx-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transaction_id": "tx-1", "request_id": "r-1",
                "status": "Completed", "transaction_hash": "0xhash"
            })))
            .mount(&server)
            .await;

        let detail = client_for(&server)
            .get_transaction("tx-1")
            .await
            .expect("get");
        assert!(detail.status.is_completed());
        assert_eq!(detail.transaction_hash.as_deref(), Some("0xhash"));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn non_2xx_is_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/transactions/missing"))
            .respond_with(ResponseTemplate::new(404).set_body_string("{\"error_code\":1}"))
            .mount(&server)
            .await;

        let err = client_for(&server)
            .get_transaction("missing")
            .await
            .expect_err("should 404");
        assert!(matches!(err, CoboError::Api { status: 404, .. }));
    }
}
