//! Shared `tracing` subscriber initialization.
//!
//! Hoists the inline pattern used in every binary today
//! (`tracing_subscriber::fmt().json().with_env_filter(...).init()`)
//! into a single place. If we ever change the log format (CBOR,
//! protobuf, additional middleware), there's one site to update.
//!
//! ## Format
//!
//! JSON output: one event per line, each event a flat object with
//! `timestamp`, `level`, `target`, `fields`, and `span` keys. Designed
//! for log shippers — every common pipeline (Vector, Fluent Bit, Loki,
//! Datadog agent, Cloud Logging) accepts this shape natively.
//!
//! ## Filter
//!
//! Reads the standard `RUST_LOG` environment variable; falls back to
//! `info` if unset. Per-module filtering still works
//! (`RUST_LOG=xindex_relayer=debug,sqlx=warn`).

/// Install the global tracing subscriber. Idempotent at the process
/// level — calling more than once is a no-op (`try_init` returns
/// `Err`, which we swallow with a `tracing::warn!` so the second
/// caller can still log against the subscriber installed by the first).
///
/// Must be called from the binary's `main` BEFORE any `tracing::info!`
/// / `tracing::warn!` / etc. — output emitted before init is silently
/// discarded.
pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let result = tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .try_init();

    if let Err(e) = result {
        // Subscriber already installed (e.g., test harness, embedded
        // caller). Not fatal; swallow so the binary keeps going.
        tracing::warn!(error = %e, "tracing subscriber already installed; skipping init");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `init_tracing` is safe to call multiple times — second call
    /// emits a warn through the FIRST-installed subscriber instead of
    /// panicking. Ensures binaries that share startup helpers can
    /// each call it without coordination.
    #[test]
    fn init_tracing_is_idempotent() {
        init_tracing();
        // No panic on second call. The warn-emitting code path
        // exercises the "already installed" branch.
        init_tracing();
    }
}
