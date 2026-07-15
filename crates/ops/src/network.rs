//! Shared bounded HTTP clients, response readers, and blocking-work admission.

use std::io::Read;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use alloy_json_rpc::{RequestPacket, ResponsePacket};
use alloy_transport::{TransportError, TransportErrorKind, TransportFut};
use tokio::sync::Semaphore;
use tower::Service;

/// Connect/request deadlines plus the maximum decoded response envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpClientPolicy {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
}

impl Default for HttpClientPolicy {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(15),
            max_response_bytes: 16 * 1024 * 1024,
        }
    }
}

impl HttpClientPolicy {
    fn validate(self) -> Result<Self, NetworkError> {
        if self.connect_timeout.is_zero()
            || self.request_timeout.is_zero()
            || self.connect_timeout > self.request_timeout
            || self.max_response_bytes == 0
        {
            return Err(NetworkError::InvalidPolicy);
        }
        Ok(self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("invalid HTTP client policy")]
    InvalidPolicy,
    #[error("HTTP client construction failed")]
    ClientBuild,
    #[error("HTTP endpoint URL is invalid")]
    InvalidEndpoint,
    #[error("HTTP response body failed")]
    ResponseBody,
    #[error("HTTP response exceeded {limit} bytes")]
    ResponseTooLarge { limit: usize },
}

/// Start an async reqwest builder with production-safe transport defaults.
/// Callers may add identities/trust roots before `build`, but cannot omit the
/// connect and total request deadlines.
///
/// # Errors
/// Zero, inverted, or empty bounds.
pub fn async_client_builder(
    policy: HttpClientPolicy,
) -> Result<reqwest::ClientBuilder, NetworkError> {
    let policy = policy.validate()?;
    Ok(reqwest::Client::builder()
        .connect_timeout(policy.connect_timeout)
        .timeout(policy.request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(8)
        .tcp_keepalive(Duration::from_secs(30))
        .tcp_nodelay(true))
}

/// Build an async reqwest client with explicit connection/request bounds.
///
/// # Errors
/// Invalid policy or client construction failure.
pub fn async_client(policy: HttpClientPolicy) -> Result<reqwest::Client, NetworkError> {
    async_client_builder(policy)?
        .build()
        .map_err(|_| NetworkError::ClientBuild)
}

/// Alloy JSON-RPC transport that applies the shared request deadline and
/// bounded response reader before JSON deserialization.
#[derive(Clone, Debug)]
pub struct BoundedAlloyHttp {
    client: reqwest::Client,
    url: reqwest::Url,
    max_response_bytes: usize,
}

impl BoundedAlloyHttp {
    /// Build a bounded Alloy HTTP transport for one JSON-RPC endpoint.
    ///
    /// # Errors
    /// Invalid URL/policy or HTTP client construction failure.
    pub fn new(raw_url: &str, policy: HttpClientPolicy) -> Result<Self, NetworkError> {
        let url = reqwest::Url::parse(raw_url).map_err(|_| NetworkError::InvalidEndpoint)?;
        let policy = policy.validate()?;
        Ok(Self {
            client: async_client(policy)?,
            url,
            max_response_bytes: policy.max_response_bytes,
        })
    }
}

impl Service<RequestPacket> for BoundedAlloyHttp {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let transport = self.clone();
        Box::pin(async move {
            let response = transport
                .client
                .post(transport.url)
                .json(&request)
                .send()
                .await
                .map_err(TransportErrorKind::custom)?;
            let status = response.status();
            let body = read_bounded_async(response, transport.max_response_bytes)
                .await
                .map_err(TransportErrorKind::custom)?;
            if status != reqwest::StatusCode::OK {
                return Err(TransportErrorKind::http_error(
                    status.as_u16(),
                    String::from_utf8_lossy(&body).into_owned(),
                ));
            }
            serde_json::from_slice(&body)
                .map_err(|error| TransportError::deser_err(error, String::from_utf8_lossy(&body)))
        })
    }
}

/// Start a blocking reqwest builder with the same production transport
/// defaults as [`async_client_builder`].
///
/// # Errors
/// Zero, inverted, or empty bounds.
pub fn blocking_client_builder(
    policy: HttpClientPolicy,
) -> Result<reqwest::blocking::ClientBuilder, NetworkError> {
    let policy = policy.validate()?;
    Ok(reqwest::blocking::Client::builder()
        .connect_timeout(policy.connect_timeout)
        .timeout(policy.request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(8)
        .tcp_keepalive(Duration::from_secs(30))
        .tcp_nodelay(true))
}

/// Build a blocking reqwest client with explicit connection/request bounds.
///
/// # Errors
/// Invalid policy or client construction failure.
pub fn blocking_client(
    policy: HttpClientPolicy,
) -> Result<reqwest::blocking::Client, NetworkError> {
    blocking_client_builder(policy)?
        .build()
        .map_err(|_| NetworkError::ClientBuild)
}

/// Read an async response without ever buffering more than `limit` bytes.
/// Both fixed-length and chunked responses are rejected at the same boundary.
///
/// # Errors
/// Body transport failure or size overflow.
pub async fn read_bounded_async(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, NetworkError> {
    if limit == 0 {
        return Err(NetworkError::InvalidPolicy);
    }
    let limit_u64 = u64::try_from(limit).map_or(u64::MAX, |value| value);
    if response
        .content_length()
        .is_some_and(|length| length > limit_u64)
    {
        return Err(NetworkError::ResponseTooLarge { limit });
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(limit),
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| NetworkError::ResponseBody)?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(NetworkError::ResponseTooLarge { limit });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Read a blocking response without ever buffering more than `limit + 1`
/// bytes. A declared oversized body is rejected before any body read.
///
/// # Errors
/// Body transport failure or size overflow.
pub fn read_bounded_blocking(
    mut response: reqwest::blocking::Response,
    limit: usize,
) -> Result<Vec<u8>, NetworkError> {
    if limit == 0 {
        return Err(NetworkError::InvalidPolicy);
    }
    let limit_u64 = u64::try_from(limit).map_or(u64::MAX, |value| value);
    if response
        .content_length()
        .is_some_and(|length| length > limit_u64)
    {
        return Err(NetworkError::ResponseTooLarge { limit });
    }
    let mut body = Vec::new();
    response
        .by_ref()
        .take(limit_u64.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|_| NetworkError::ResponseBody)?;
    if body.len() > limit {
        return Err(NetworkError::ResponseTooLarge { limit });
    }
    Ok(body)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BlockingWorkError {
    #[error("invalid blocking-work policy")]
    InvalidPolicy,
    #[error("blocking-work capacity exhausted")]
    Saturated,
    #[error("blocking work exceeded its deadline")]
    TimedOut,
    #[error("blocking worker terminated unexpectedly")]
    Join,
}

/// Admission gate for synchronous clients invoked from async services.
///
/// A permit is moved into the blocking closure, not held only by the awaiting
/// task. Therefore timing out/cancelling the await does not admit replacement
/// work while the original OS thread is still occupied.
#[derive(Debug, Clone)]
pub struct BlockingWorkPool {
    permits: Arc<Semaphore>,
    timeout: Duration,
}

impl Default for BlockingWorkPool {
    fn default() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(4)),
            timeout: Duration::from_secs(30),
        }
    }
}

impl BlockingWorkPool {
    /// Construct a fail-fast bounded blocking-work gate.
    ///
    /// # Errors
    /// Zero concurrency or timeout.
    pub fn new(max_in_flight: usize, timeout: Duration) -> Result<Self, BlockingWorkError> {
        if max_in_flight == 0 || timeout.is_zero() {
            return Err(BlockingWorkError::InvalidPolicy);
        }
        Ok(Self {
            permits: Arc::new(Semaphore::new(max_in_flight)),
            timeout,
        })
    }

    /// Run one synchronous operation only when capacity is immediately
    /// available. The Tokio blocking queue never receives more operations than
    /// the configured permit count.
    ///
    /// # Errors
    /// Saturation, timeout, or worker termination.
    pub async fn run<F, T>(&self, work: F) -> Result<T, BlockingWorkError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let permit = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| BlockingWorkError::Saturated)?;
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        });
        match tokio::time::timeout(self.timeout, task).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(BlockingWorkError::Join),
            Err(_) => Err(BlockingWorkError::TimedOut),
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "network test fixtures")]

    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn raw_server(response: Vec<u8>, hold_after_write: Duration) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = vec![0u8; 4 * 1024];
            let _ = socket.read(&mut request).await;
            socket.write_all(&response).await.expect("write response");
            tokio::time::sleep(hold_after_write).await;
        });
        format!("http://{address}")
    }

    fn short_policy(max_response_bytes: usize) -> HttpClientPolicy {
        HttpClientPolicy {
            connect_timeout: Duration::from_millis(50),
            request_timeout: Duration::from_millis(100),
            max_response_bytes,
        }
    }

    #[tokio::test]
    async fn fixed_oversized_response_is_rejected_from_content_length() {
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n".to_vec();
        let url = raw_server(response, Duration::from_millis(300)).await;
        let policy = short_policy(64);
        let client = async_client(policy).expect("client");
        let response = client.get(url).send().await.expect("headers");
        let started = Instant::now();
        let error = read_bounded_async(response, policy.max_response_bytes)
            .await
            .expect_err("oversized response");
        assert!(matches!(error, NetworkError::ResponseTooLarge { .. }));
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "content length must reject before waiting for the body"
        );
    }

    #[tokio::test]
    async fn alloy_transport_rejects_oversized_json_before_deserialization() {
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n".to_vec();
        let url = raw_server(response, Duration::from_millis(300)).await;
        let policy = short_policy(64);
        let mut transport = BoundedAlloyHttp::new(&url, policy).expect("transport");
        let request = alloy_json_rpc::Request::new(
            "eth_chainId",
            alloy_json_rpc::Id::Number(1),
            Vec::<serde_json::Value>::new(),
        )
        .serialize()
        .expect("serialized request");
        let error = transport
            .call(RequestPacket::from(request))
            .await
            .expect_err("oversized RPC response");
        assert!(error.to_string().contains("exceeded 64 bytes"));
    }

    #[tokio::test]
    async fn chunked_oversized_response_is_rejected_while_streaming() {
        let body = "x".repeat(128);
        let response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        )
        .into_bytes();
        let url = raw_server(response, Duration::ZERO).await;
        let policy = short_policy(64);
        let client = async_client(policy).expect("client");
        let response = client.get(url).send().await.expect("headers");
        let error = read_bounded_async(response, policy.max_response_bytes)
            .await
            .expect_err("oversized chunked response");
        assert!(matches!(error, NetworkError::ResponseTooLarge { .. }));
    }

    #[tokio::test]
    async fn total_request_deadline_rejects_blackhole_upstream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let policy = short_policy(64);
        let client = async_client(policy).expect("client");
        let error = client
            .get(format!("http://{address}"))
            .send()
            .await
            .expect_err("blackhole must time out");
        assert!(error.is_timeout());
    }

    #[tokio::test]
    async fn slow_drip_body_cannot_extend_the_total_request_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = vec![0u8; 4 * 1024];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
                .await
                .expect("write headers");
            for _ in 0..100 {
                if socket.write_all(b"x").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        });
        let policy = short_policy(256);
        let client = async_client(policy).expect("client");
        let started = Instant::now();
        let response = client
            .get(format!("http://{address}"))
            .send()
            .await
            .expect("headers");
        let error = read_bounded_async(response, policy.max_response_bytes)
            .await
            .expect_err("slow drip must time out");
        assert!(matches!(error, NetworkError::ResponseBody));
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "body progress must not reset the total request deadline"
        );
    }

    #[tokio::test]
    async fn blocking_pool_rejects_saturation_and_recovers() {
        let pool = Arc::new(BlockingWorkPool::new(1, Duration::from_secs(1)).expect("pool"));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let first_pool = Arc::clone(&pool);
        let first = tokio::spawn(async move {
            first_pool
                .run(move || {
                    let _ = started_tx.send(());
                    std::thread::sleep(Duration::from_millis(120));
                    1u8
                })
                .await
        });
        started_rx.await.expect("first started");

        let saturated = pool.run(|| 2u8).await;
        assert!(matches!(saturated, Err(BlockingWorkError::Saturated)));
        assert_eq!(first.await.expect("first task").expect("first work"), 1);
        assert_eq!(pool.run(|| 3u8).await.expect("recovered work"), 3);
    }

    #[tokio::test]
    async fn timed_out_blocking_work_retains_its_permit_until_thread_exit() {
        let pool = BlockingWorkPool::new(1, Duration::from_millis(40)).expect("pool");
        let timed_out = pool
            .run(|| {
                std::thread::sleep(Duration::from_millis(140));
                1u8
            })
            .await;
        assert!(matches!(timed_out, Err(BlockingWorkError::TimedOut)));
        assert!(matches!(
            pool.run(|| 2u8).await,
            Err(BlockingWorkError::Saturated)
        ));
        tokio::time::sleep(Duration::from_millis(130)).await;
        assert_eq!(pool.run(|| 3u8).await.expect("permit released"), 3);
    }
}
