//! Multi-RPC endpoint set with fallback-on-transient-error semantics.
//!
//! Closes Rust-audit finding L-R3: prior binaries (`xindex-watch`,
//! `xindex-attest`, `xindex-cancel`, `xindex-redeem`) each accepted a
//! single `--rpc-url` argument. If that endpoint went down — Alchemy
//! rate-limit, Infura `DDoS`, self-hosted node OOM — the daemon lost
//! event reception with no automatic fallover.
//!
//! ## Scope of this module
//!
//! We provide **connection-time fallover**: at startup, try each URL
//! in priority order and use the first that responds. Combined with
//! restart-on-failure (the operator's task) this is sufficient for v1.
//!
//! **Transparent in-flight fallover for active subscriptions is NOT
//! addressed here.** Alloy's `WS` subscription holds a single
//! connection; transparently swapping that to a different WS without
//! losing in-flight subscription state requires bespoke transport-layer
//! work (a custom `Transport` impl that multiplexes across underlying
//! transports and re-subscribes on swap). That's a meaningful project
//! — bigger than the rest of M5 combined — and gated on us actually
//! seeing subscription churn in prod. v2 work.
//!
//! For now: subscription dies → daemon exits → operator restarts with
//! the next URL promoted to primary (or we rely on our existing
//! `--from-block` backfill to catch missed events on restart).
//!
//! ## Usage
//!
//! ```ignore
//! let endpoints = WsEndpointList::from_csv(&args.rpc_urls)?;
//! let (used_url, provider) = endpoints
//!     .connect_first_working(|url| async move {
//!         WsConnect::new(&url).connect().await
//!     })
//!     .await?;
//! info!(rpc_url = %used_url, "connected");
//! ```

use std::time::Duration;

use thiserror::Error;

/// An ordered list of Ethereum WS RPC endpoints. Position 0 is the
/// primary; subsequent entries are fallbacks tried only when primary
/// returns a [`is_transient_rpc_error`] failure.
#[derive(Debug, Clone)]
pub struct WsEndpointList {
    urls: Vec<String>,
}

/// Errors surfaced by [`WsEndpointList`] operations.
#[derive(Debug, Error)]
pub enum EndpointError {
    /// Caller supplied an empty list (or a CSV that parsed to empty).
    #[error("at least one RPC URL required")]
    Empty,

    /// All endpoints exhausted via transient errors. The wrapped
    /// vector pairs each URL with its surfaced error string, in the
    /// order they were tried, so the operator can see which one
    /// failed first and how.
    #[error("all {0} RPC endpoints exhausted")]
    AllExhausted(usize),
}

impl WsEndpointList {
    /// Parse a comma-separated URL list. Whitespace around URLs is
    /// trimmed; empty entries are skipped. Order is preserved (caller
    /// controls priority by ordering the input).
    ///
    /// # Errors
    /// [`EndpointError::Empty`] if no non-empty URLs are present.
    pub fn from_csv(csv: &str) -> Result<Self, EndpointError> {
        let urls: Vec<String> = csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        if urls.is_empty() {
            return Err(EndpointError::Empty);
        }
        Ok(Self { urls })
    }

    /// Construct from an already-parsed list of URLs.
    ///
    /// # Errors
    /// [`EndpointError::Empty`] if `urls` is empty.
    pub fn from_vec(urls: Vec<String>) -> Result<Self, EndpointError> {
        if urls.is_empty() {
            return Err(EndpointError::Empty);
        }
        Ok(Self { urls })
    }

    /// Number of endpoints (including primary).
    #[must_use]
    pub fn len(&self) -> usize {
        self.urls.len()
    }

    /// Always at least one (constructor enforces non-empty).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Primary URL. Use this when subscription fallover isn't
    /// implemented (i.e., for `subscribe_logs`).
    #[must_use]
    pub fn primary(&self) -> &str {
        &self.urls[0]
    }

    /// Full ordered slice of URLs.
    #[must_use]
    pub fn all(&self) -> &[String] {
        &self.urls
    }

    /// Try each URL in priority order. The first call to `connect`
    /// that returns `Ok(P)` wins; returns `(url_used, P)` so the
    /// operator can log which endpoint won. Transient errors trigger
    /// fallover; permanent errors are returned immediately.
    ///
    /// Caller controls timeout / retry budget per URL inside `connect`.
    ///
    /// # Errors
    /// - [`EndpointError::AllExhausted`] if every URL produced a
    ///   transient error.
    /// - Whatever the caller's permanent error is, propagated as soon
    ///   as a permanent error appears.
    pub async fn connect_first_working<F, Fut, P, E>(
        &self,
        connect: F,
    ) -> Result<(String, P), ConnectAttempt<E>>
    where
        F: Fn(String) -> Fut,
        Fut: std::future::Future<Output = Result<P, E>>,
        E: std::fmt::Display,
    {
        let mut last_err: Option<(String, E)> = None;
        for url in &self.urls {
            match connect(url.clone()).await {
                Ok(p) => {
                    if last_err.is_some() {
                        tracing::info!(
                            url = %url,
                            "RPC fallover succeeded after primary(s) failed"
                        );
                    }
                    return Ok((url.clone(), p));
                }
                Err(e) => {
                    if is_transient_rpc_error(&e) {
                        tracing::warn!(
                            url = %url,
                            error = %e,
                            "transient RPC error; trying next endpoint"
                        );
                        last_err = Some((url.clone(), e));
                    } else {
                        // Permanent error — propagate immediately rather
                        // than mask it behind a fallover. Bad credentials,
                        // wrong chain id, malformed URL: these need
                        // operator attention, not silent fallover.
                        return Err(ConnectAttempt::Permanent {
                            url: url.clone(),
                            source: e,
                        });
                    }
                }
            }
        }
        Err(ConnectAttempt::AllExhausted {
            count: self.urls.len(),
            last: last_err,
        })
    }
}

/// Failure surfaced by [`WsEndpointList::connect_first_working`]. Splits
/// "all endpoints failed transiently" from "one endpoint failed
/// permanently" so the operator alert / log can be specific.
#[derive(Debug)]
pub enum ConnectAttempt<E> {
    /// All endpoints exhausted via transient errors. The last `(url,
    /// error)` pair is kept for log context.
    AllExhausted {
        count: usize,
        last: Option<(String, E)>,
    },
    /// One endpoint returned a permanent error — operator attention
    /// required (bad URL, wrong network, bad credentials).
    Permanent { url: String, source: E },
}

impl<E: std::fmt::Display> std::fmt::Display for ConnectAttempt<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AllExhausted { count, last } => {
                if let Some((url, err)) = last {
                    write!(
                        f,
                        "all {count} RPC endpoints exhausted; last attempt {url}: {err}"
                    )
                } else {
                    write!(f, "all {count} RPC endpoints exhausted")
                }
            }
            Self::Permanent { url, source } => {
                write!(f, "permanent RPC error at {url}: {source}")
            }
        }
    }
}

impl<E: std::fmt::Display + std::fmt::Debug> std::error::Error for ConnectAttempt<E> {}

/// Classify an error as transient (retry on a different endpoint) or
/// permanent (operator intervention). Heuristic based on the error's
/// display string — alloy's transport error types nest through
/// `reqwest`/`tokio-tungstenite` and don't always expose a stable
/// `kind()` we can match on.
///
/// Transient classes:
/// - Connection refused / reset / timeout (TCP)
/// - DNS failures (`failed to lookup`)
/// - TLS handshake interrupted
/// - HTTP 5xx (server-side)
/// - HTTP 429 (rate limited)
/// - WS upgrade failure
/// - `service unavailable`
///
/// Permanent classes (DO NOT fall over):
/// - HTTP 401/403 (auth)
/// - HTTP 4xx other than 429 (client-side; same bad request on
///   every endpoint won't fix anything)
/// - URL parse errors
/// - Wrong-chain rejections
pub fn is_transient_rpc_error<E: std::fmt::Display>(e: &E) -> bool {
    let s = e.to_string().to_lowercase();

    // Auth + bad-request → permanent.
    if s.contains("401")
        || s.contains("403")
        || s.contains("unauthorized")
        || s.contains("forbidden")
        || s.contains("invalid url")
        || s.contains("malformed")
    {
        return false;
    }

    // Transient transport-level failures.
    if s.contains("connection refused")
        || s.contains("connection reset")
        || s.contains("connection closed")
        || s.contains("connect timed out")
        || s.contains("timeout")
        || s.contains("timed out")
        || s.contains("dns")
        || s.contains("name resolution")
        || s.contains("failed to lookup")
        || s.contains("network")
        || s.contains("tls")
        || s.contains("handshake")
        || s.contains("broken pipe")
        || s.contains("eof while reading")
    {
        return true;
    }

    // Transient server-side failures.
    if s.contains("500")
        || s.contains("502")
        || s.contains("503")
        || s.contains("504")
        || s.contains("429")
        || s.contains("rate limit")
        || s.contains("service unavailable")
        || s.contains("bad gateway")
        || s.contains("gateway timeout")
    {
        return true;
    }

    // WS-specific transients.
    if s.contains("websocket") && (s.contains("close") || s.contains("disconnect")) {
        return true;
    }

    // Default: treat unknown errors as PERMANENT. False negatives
    // (failing over when we shouldn't) corrupt invariants more
    // dangerously than false positives (giving up too soon — which
    // the operator notices via paging).
    false
}

/// Sleep helper for retry-with-backoff loops; thin wrapper so callers
/// don't need a separate `tokio` import just for this.
pub async fn backoff(attempt: u32, base: Duration) {
    let factor: u32 = 1u32 << attempt.min(6); // cap at 64×
    tokio::time::sleep(base.saturating_mul(factor)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn parse_csv_single() {
        let l = WsEndpointList::from_csv("wss://primary.example").expect("parse");
        assert_eq!(l.len(), 1);
        assert_eq!(l.primary(), "wss://primary.example");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn parse_csv_multiple_with_whitespace() {
        let l = WsEndpointList::from_csv(
            "  wss://primary.example , wss://fallback1.example , wss://fallback2.example  ",
        )
        .expect("parse");
        assert_eq!(l.len(), 3);
        assert_eq!(l.primary(), "wss://primary.example");
        assert_eq!(l.all()[1], "wss://fallback1.example");
        assert_eq!(l.all()[2], "wss://fallback2.example");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn parse_csv_skips_empty_entries() {
        let l = WsEndpointList::from_csv(",wss://a,,wss://b,").expect("parse");
        assert_eq!(l.len(), 2);
        assert_eq!(l.primary(), "wss://a");
    }

    #[test]
    fn parse_csv_rejects_empty_or_whitespace_only() {
        assert!(matches!(
            WsEndpointList::from_csv(""),
            Err(EndpointError::Empty)
        ));
        assert!(matches!(
            WsEndpointList::from_csv(",,,"),
            Err(EndpointError::Empty)
        ));
        assert!(matches!(
            WsEndpointList::from_csv("   "),
            Err(EndpointError::Empty)
        ));
    }

    /// String-error wrapper for the classifier tests — we don't need
    /// a real alloy error type, just something that implements Display.
    #[derive(Debug)]
    struct StringError(&'static str);
    impl std::fmt::Display for StringError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    #[test]
    fn classifier_transient_transport_failures() {
        for msg in [
            "connection refused",
            "connection reset by peer",
            "connection closed",
            "connect timed out",
            "request timeout",
            "DNS lookup failed",
            "failed to lookup address",
            "TLS handshake error",
            "broken pipe",
        ] {
            assert!(
                is_transient_rpc_error(&StringError(msg)),
                "should be transient: {msg}"
            );
        }
    }

    #[test]
    fn classifier_transient_server_5xx_and_rate_limit() {
        for msg in [
            "HTTP 500 Internal Server Error",
            "HTTP 502 Bad Gateway",
            "HTTP 503 Service Unavailable",
            "HTTP 504 Gateway Timeout",
            "HTTP 429 Too Many Requests",
            "rate limit exceeded",
        ] {
            assert!(
                is_transient_rpc_error(&StringError(msg)),
                "should be transient: {msg}"
            );
        }
    }

    #[test]
    fn classifier_permanent_auth_and_bad_request() {
        for msg in [
            "HTTP 401 Unauthorized",
            "HTTP 403 Forbidden",
            "invalid URL",
            "malformed request",
        ] {
            assert!(
                !is_transient_rpc_error(&StringError(msg)),
                "should NOT be transient: {msg}"
            );
        }
    }

    #[test]
    fn classifier_unknown_defaults_to_permanent() {
        // A genuinely unknown error: we conservatively treat as
        // permanent so we don't silently fall over on a bug we
        // haven't characterized.
        assert!(!is_transient_rpc_error(&StringError(
            "some weird protocol violation"
        )));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn connect_first_working_uses_primary_on_success() {
        let l = WsEndpointList::from_csv("a,b,c").expect("parse");
        let (used, val) = l
            .connect_first_working(|url| async move { Ok::<_, StringError>(url) })
            .await
            .expect("connect");
        assert_eq!(used, "a");
        assert_eq!(val, "a");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn connect_first_working_falls_through_transient() {
        let l = WsEndpointList::from_csv("primary,backup1,backup2").expect("parse");
        // primary fails transiently, backup1 succeeds.
        let result = l
            .connect_first_working(|url| async move {
                if url == "primary" {
                    Err(StringError("connection refused"))
                } else {
                    Ok(url)
                }
            })
            .await;
        let (used, val) = result.expect("connect");
        assert_eq!(used, "backup1");
        assert_eq!(val, "backup1");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn connect_first_working_propagates_permanent() {
        let l = WsEndpointList::from_csv("a,b,c").expect("parse");
        let err = l
            .connect_first_working(|url| async move {
                if url == "a" {
                    Err(StringError("HTTP 403 Forbidden"))
                } else {
                    Ok::<_, StringError>(url)
                }
            })
            .await
            .expect_err("should error");
        assert!(matches!(err, ConnectAttempt::Permanent { .. }));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn connect_first_working_exhausts_when_all_transient() {
        let l = WsEndpointList::from_csv("a,b,c").expect("parse");
        let err = l
            .connect_first_working(|_url| async move {
                Err::<String, _>(StringError("connection refused"))
            })
            .await
            .expect_err("should error");
        assert!(matches!(err, ConnectAttempt::AllExhausted { count: 3, .. }));
    }
}
