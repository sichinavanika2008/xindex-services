//! Minimal HTTP server exposing `/metrics` (Prometheus scrape) and
//! `/health` (k8s / systemd liveness probe).
//!
//! Single endpoint pair, single small dependency (`axum`), no middleware
//! — the absolute minimum infrastructure for production scraping. If a
//! richer surface is ever needed (auth, TLS, multiple registries), the
//! same pattern extends; we just don't need it for v1.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use prometheus::{Encoder, Registry, TextEncoder};
use thiserror::Error;

/// Errors surfaced by the metrics HTTP server.
#[derive(Debug, Error)]
pub enum HttpError {
    #[error("bind {addr} failed: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("server failed: {0}")]
    Serve(#[from] std::io::Error),
}

/// Spawn the metrics HTTP server. Long-lived: returns only when the
/// listener fails or the server is cancelled.
///
/// Routes:
/// - `GET /metrics` → Prometheus text exposition format
/// - `GET /health` → 200 OK with body `ok`
///
/// # Errors
/// - [`HttpError::Bind`] if `addr` can't be bound (port in use, permission denied).
/// - [`HttpError::Serve`] if the running server encounters a fatal I/O error.
pub async fn serve_metrics(registry: Registry, addr: SocketAddr) -> Result<(), HttpError> {
    let state = AppState {
        registry: Arc::new(registry),
    };

    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| HttpError::Bind { addr, source: e })?;

    tracing::info!(%addr, "metrics + health HTTP server listening");

    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Clone)]
struct AppState {
    registry: Arc<Registry>,
}

/// `GET /metrics` — gather all collectors registered on the supplied
/// `Registry`, encode as Prometheus text format, return as 200.
///
/// Failures during gathering or encoding (extremely rare — would mean
/// a Prometheus library bug) surface as 500.
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = state.registry.gather();
    let mut buffer = Vec::with_capacity(8 * 1024);
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", "text/plain; charset=utf-8")],
            format!("encode failed: {e}").into_bytes(),
        );
    }
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        buffer,
    )
}

/// `GET /health` — return 200 OK with body `ok`. The bare existence of
/// the response is the signal; the body is for log + curl debug.
async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Metrics;

    /// Smoke test: spin the server on an OS-assigned port, hit /health
    /// and /metrics, assert sensible responses. Tests the wiring
    /// (router → handler → encoder) end-to-end without external infra.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn server_serves_health_and_metrics() {
        let registry = Registry::new();
        let metrics = Metrics::new(&registry).expect("metrics");
        // Tick a counter so /metrics has something to report.
        metrics.relayer_intents_tracked.inc();
        metrics.relayer_intents_tracked.inc();

        // Port 0 → OS assigns; we read it back from the bound listener
        // to know where to send the request.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health", get(health_handler))
            .with_state(AppState {
                registry: Arc::new(registry),
            });

        // Spawn the server; abort it after the requests.
        let server_handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        // Give the runtime a tick to start serving.
        tokio::task::yield_now().await;

        // Hit /health using a fresh raw HTTP request — we don't pull
        // reqwest into ops dev-deps for this single test. `axum::http`
        // is the request type, but we construct via tokio TcpStream
        // for full end-to-end coverage.
        let health = http_get(addr, "/health").await.expect("health");
        assert!(health.starts_with("HTTP/1.1 200"), "health 200: {health}");
        assert!(health.contains("ok"));

        let m = http_get(addr, "/metrics").await.expect("metrics");
        assert!(m.starts_with("HTTP/1.1 200"), "metrics 200: {m}");
        // The Prometheus exposition for an incremented counter should
        // contain our metric name and the value 2.
        assert!(
            m.contains("xindex_relayer_intents_tracked_total"),
            "metrics response missing counter name: {m}"
        );
        assert!(
            m.contains("xindex_relayer_intents_tracked_total 2"),
            "metrics response missing counter value: {m}"
        );

        server_handle.abort();
    }

    /// Minimal raw-HTTP GET so the test doesn't pull `reqwest` into
    /// dev-deps. Sends a fixed `Host` header so axum's HTTP/1.1 parser
    /// accepts the request.
    async fn http_get(addr: SocketAddr, path: &str) -> std::io::Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await?;
        let mut buf = Vec::with_capacity(4096);
        stream.read_to_end(&mut buf).await?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }
}
