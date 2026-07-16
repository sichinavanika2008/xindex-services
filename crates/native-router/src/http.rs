use alloy_primitives::{keccak256, B256};
use serde::de::DeserializeOwned;
use serde::Serialize;
use xindex_ops::network::{async_client, read_bounded_async, HttpClientPolicy};

use crate::NativeRouterError;

#[derive(Clone, Debug)]
pub(crate) struct BoundedJsonClient {
    client: reqwest::Client,
    base: reqwest::Url,
    max_response_bytes: usize,
}

#[derive(Debug)]
pub(crate) struct JsonEvidence<T> {
    pub(crate) value: T,
    pub(crate) raw_body: Vec<u8>,
    pub(crate) response_hash: B256,
}

impl BoundedJsonClient {
    pub(crate) fn new(raw_base: &str, policy: HttpClientPolicy) -> Result<Self, NativeRouterError> {
        Self::with_loopback_http(raw_base, policy, false)
    }

    #[cfg(test)]
    pub(crate) fn new_loopback(
        raw_base: &str,
        policy: HttpClientPolicy,
    ) -> Result<Self, NativeRouterError> {
        Self::with_loopback_http(raw_base, policy, true)
    }

    fn with_loopback_http(
        raw_base: &str,
        policy: HttpClientPolicy,
        allow_loopback_http: bool,
    ) -> Result<Self, NativeRouterError> {
        let mut base =
            reqwest::Url::parse(raw_base).map_err(|_| NativeRouterError::InvalidEndpoint)?;
        let secure = base.scheme() == "https";
        let loopback_http = allow_loopback_http
            && base.scheme() == "http"
            && base.host_str().is_some_and(|host| {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            });
        if base.host_str().is_none() || (!secure && !loopback_http) {
            return Err(NativeRouterError::InvalidEndpoint);
        }
        base.set_query(None);
        base.set_fragment(None);
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        Ok(Self {
            client: async_client(policy)?,
            base,
            max_response_bytes: policy.max_response_bytes,
        })
    }

    fn url(&self, path: &str) -> Result<reqwest::Url, NativeRouterError> {
        if path.starts_with('/') || path.contains("..") {
            return Err(NativeRouterError::InvalidEndpointPath);
        }
        self.base
            .join(path)
            .map_err(|_| NativeRouterError::InvalidEndpointPath)
    }

    pub(crate) async fn get<T, Q>(&self, path: &str, query: &Q) -> Result<T, NativeRouterError>
    where
        T: DeserializeOwned,
        Q: Serialize + ?Sized,
    {
        let response = self
            .client
            .get(self.url(path)?)
            .query(query)
            .send()
            .await
            .map_err(|_| NativeRouterError::HttpTransport)?;
        self.decode(response).await
    }

    pub(crate) async fn post<T, B>(&self, path: &str, body: &B) -> Result<T, NativeRouterError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let response = self
            .client
            .post(self.url(path)?)
            .json(body)
            .send()
            .await
            .map_err(|_| NativeRouterError::HttpTransport)?;
        self.decode(response).await
    }

    pub(crate) async fn post_with_evidence<T, B>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<JsonEvidence<T>, NativeRouterError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let response = self
            .client
            .post(self.url(path)?)
            .json(body)
            .send()
            .await
            .map_err(|_| NativeRouterError::HttpTransport)?;
        self.decode_with_evidence(response).await
    }

    async fn decode<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, NativeRouterError> {
        Ok(self.decode_with_evidence(response).await?.value)
    }

    async fn decode_with_evidence<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<JsonEvidence<T>, NativeRouterError> {
        let status = response.status();
        let bytes = read_bounded_async(response, self.max_response_bytes).await?;
        if status != reqwest::StatusCode::OK {
            return Err(NativeRouterError::HttpStatus(status.as_u16()));
        }
        let value = serde_json::from_slice(&bytes).map_err(|_| NativeRouterError::InvalidJson)?;
        Ok(JsonEvidence {
            value,
            response_hash: keccak256(&bytes),
            raw_body: bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn policy() -> HttpClientPolicy {
        HttpClientPolicy {
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(1),
            max_response_bytes: 1024,
        }
    }

    #[test]
    fn production_client_rejects_plain_http() {
        assert!(matches!(
            BoundedJsonClient::new("http://example.com", policy()),
            Err(NativeRouterError::InvalidEndpoint)
        ));
    }

    #[test]
    fn loopback_http_is_test_only() {
        assert!(BoundedJsonClient::new_loopback("http://127.0.0.1:1234", policy()).is_ok());
        assert!(matches!(
            BoundedJsonClient::new_loopback("http://example.com", policy()),
            Err(NativeRouterError::InvalidEndpoint)
        ));
    }
}
