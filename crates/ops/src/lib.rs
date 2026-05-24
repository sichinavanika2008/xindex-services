//! `xindex-ops` — observability primitives shared across binaries.
//!
//! Closes Rust-audit finding I-R1: prior `crates/ops` was a single-line
//! stub. Production-running daemons need three things every operator
//! takes for granted:
//!
//! 1. **Structured logging** — JSON-formatted `tracing` output that a
//!    log shipper (Vector, Fluent Bit, Datadog agent) can ingest. The
//!    binaries inlined this; we hoist it here so the configuration
//!    lives in one place.
//! 2. **Metrics** — Prometheus counters + gauges scraped by an
//!    external Prometheus server. The data we need to alert on:
//!    intents tracked, attestations posted, broadcasts pending,
//!    rebroadcast attempts, RPC fallover events.
//! 3. **Health endpoint** — an HTTP `/health` probe k8s / systemd
//!    liveness checks can hit. 200 == process is up.
//!
//! ## Deliberate scope cuts (v1)
//!
//! - **No OpenTelemetry / OTLP exporter.** `OTel` is the right call when
//!   we have a real Grafana + Jaeger stack to point at; today JSON
//!   logs + Prometheus pull cover every alert + dashboard we need.
//!   Wire OTLP in v2 when the cost is justified by an actual consumer.
//! - **No histograms.** Counters + gauges only. Latency histograms
//!   carry meaningful cardinality + memory cost; defer until we have
//!   a specific latency SLO to enforce.
//! - **No structured-event push** (Datadog Events, `PagerDuty` Events
//!   API). Operator can correlate via timestamps; `PagerDuty` fires on
//!   metric thresholds instead.
//!
//! ## Usage
//!
//! ```ignore
//! use xindex_ops::{init_tracing, serve_metrics, Metrics};
//! use prometheus::Registry;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     init_tracing();
//!     let registry = Registry::new();
//!     let metrics = Metrics::new(&registry)?;
//!     tokio::spawn(serve_metrics(registry, "0.0.0.0:9090".parse()?));
//!
//!     // … binary-specific work, calling metrics.intents_tracked.inc() etc.
//!     Ok(())
//! }
//! ```

pub mod http;
pub mod metrics;
pub mod tracing_init;

pub use http::{serve_metrics, HttpError};
pub use metrics::{Metrics, MetricsError};
pub use tracing_init::init_tracing;
