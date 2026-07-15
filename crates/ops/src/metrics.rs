//! Prometheus counters + gauges shared across the off-chain stack.
//!
//! Closes Rust-audit finding I-R1. The [`Metrics`] struct holds the
//! named Prometheus collectors every daemon shares. Each binary
//! constructs ONE `Metrics` instance at startup (registered into the
//! HTTP server's `Registry`), then increments / sets values inline
//! during normal operation.
//!
//! ## Naming convention
//!
//! All metric names are prefixed `xindex_` and named in
//! `xindex_<component>_<subject>_<unit>` form per the Prometheus naming
//! guide. Suffix tells you the unit (`_total` for counters, `_count`
//! for gauges that represent a cardinality, etc.).
//!
//! ## Why public fields (and not methods)
//!
//! `Metrics` exposes its collectors as public fields so callers write
//! `metrics.intents_tracked.inc()` directly. That's noisier than a
//! `metrics.intent_tracked()` method but it keeps the implementation
//! a pure data holder — adding a new metric is one field + one
//! `register` call, no method wrapper to write.
//!
//! ## Coverage
//!
//! The current set covers the three production binaries:
//! - **Relayer (`xindex-cancel`)**: tracked / resolved / cancel attempts
//! - **Signer (`xindex-attest`)**: signed / skipped / posted
//! - **Executor (`xindex-redeem`)**: received / broadcast / failed / rebroadcast / pending
//! - **Shared (RPC fallover)**: fallover attempts per chain
//!
//! Add new metrics here when a binary needs them — keep the registry
//! consolidated rather than per-crate.

use prometheus::{IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry};
use thiserror::Error;

/// Errors surfaced when registering metrics with a `Registry`. Every
/// failure mode is "you called register twice for the same metric
/// name" — fail loud at startup rather than at first increment.
#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("prometheus error: {0}")]
    Prometheus(#[from] prometheus::Error),
}

/// Shared metrics struct. One per process; cloneable so it can be
/// passed into spawned tasks. Internally all collectors are `Arc`
/// (Prometheus crate's `IntCounter` / `IntGauge` are `Arc<...>`
/// underneath).
#[derive(Clone, Debug)]
pub struct Metrics {
    // --- Relayer (xindex-cancel) ---
    /// Total `MintIntentCreated` events the relayer has observed.
    pub relayer_intents_tracked: IntCounter,
    /// Total intents marked resolved (Finalized or Cancelled).
    /// Label: `status` ∈ {`finalized`, `cancelled`}.
    pub relayer_intents_resolved: IntCounterVec,
    /// Total `cancelMint` dispatches attempted. Label: `result` ∈
    /// {`confirmed`, `revert_already_resolved`, `revert_finalizable`,
    /// `revert_other`, `send_error`}.
    pub relayer_cancel_attempts: IntCounterVec,
    /// Currently-tracked intents waiting on a deadline pass.
    pub relayer_pending_intents: IntGauge,

    // --- Redemption relayer (xindex-finalize-redeem) ---
    /// `RedemptionIntentCreated` events observed.
    pub redeem_relayer_tracked: IntCounter,
    /// Redemptions marked resolved. Label `status` ∈
    /// {`finalized`, `cancelled`}.
    pub redeem_relayer_resolved: IntCounterVec,
    /// `IndexToken.finalizeBurn` dispatches. Label `result` ∈
    /// {`confirmed`, `revert`, `send_error`}.
    pub redeem_relayer_finalize_attempts: IntCounterVec,
    /// `IndexToken.cancelBurn` dispatches. Same `result` labels.
    pub redeem_relayer_cancel_attempts: IntCounterVec,
    /// Currently-tracked unresolved redemptions.
    pub redeem_relayer_pending: IntGauge,
    /// SD-B: redemptions past deadline with NO delivery/refund
    /// attestation (`THORChain` halt / orphaned inbound). Operator-alert
    /// gauge; there is deliberately no on-chain auto-action.
    pub redeem_relayer_stuck: IntGauge,

    // --- Signer (xindex-attest) ---
    /// Total attestations successfully signed by this signer instance.
    pub signer_attestations_signed: IntCounter,
    /// Attestations skipped before signing. Label: `reason` ∈
    /// {`multi_slot`, `amount_overflow`, `crosscheck_failed`, `decode_error`}.
    pub signer_attestations_skipped: IntCounterVec,
    /// `AttestationOracle.attest` tx outcomes. Label: `result` ∈
    /// {`confirmed`, `revert`, `send_error`}.
    pub signer_attest_posted: IntCounterVec,
    /// Policy/HSM signer requests. Labels: `role` is a fixed route family and
    /// `result` ∈ {`success`, `refused`, `error`}.
    pub signer_requests: IntCounterVec,

    // --- Price signer / exact-quorum collector ---
    /// Independent price-production rounds. Label: `result` ∈
    /// {`signed`, `refused`, `hsm_error`, `evidence_error`, `state_error`,
    /// `publish_error`, `latched`}.
    pub price_signer_rounds: IntCounterVec,
    /// Last successfully signed deterministic epoch per configured asset id.
    pub price_signer_last_success_timestamp_seconds: IntGaugeVec,
    /// Consecutive fail-closed price rounds per configured asset id.
    pub price_signer_anomaly_streak: IntGaugeVec,
    /// Delivery of signed price tuples to redundant collectors. Label:
    /// `result` ∈ {`success`, `error`}.
    pub price_collector_deliveries: IntCounterVec,
    /// Exact-quorum collector ingestion. Label: `result` ∈
    /// {`accepted`, `duplicate`, `quorum`, `refused`, `error`}.
    pub price_collector_messages: IntCounterVec,
    /// Permissionless on-chain price post outcomes. Label: `result` ∈
    /// {`confirmed`, `idempotent`, `conflict`, `revert`, `error`}.
    pub price_post_attempts: IntCounterVec,

    // --- THORChain registry signer / collector ---
    /// Complete independent source-poll rounds. Label: `result` ∈
    /// {`success`, `source_error`, `policy_error`, `stale_tip`}.
    pub registry_source_polls: IntCounterVec,
    /// Registry signature attempts. Labels: `kind` ∈ {`inbound`, `quote`},
    /// `result` ∈ {`signed`, `replay`, `refused`, `hsm_error`}.
    pub registry_signatures: IntCounterVec,
    /// Delivery of signed registry messages to redundant collectors. Labels:
    /// `kind` ∈ {`inbound`, `quote`}, `result` ∈ {`success`, `error`}.
    pub registry_collector_deliveries: IntCounterVec,
    /// Registry collector ingestion. Labels: `kind` ∈ {`inbound`, `quote`},
    /// `result` ∈ {`accepted`, `duplicate`, `quorum`, `refused`, `capacity`,
    /// `oversized`, `evidence_error`}.
    pub registry_collector_messages: IntCounterVec,
    /// Evidence records that could not be durably persisted before signing.
    pub registry_evidence_failures: IntCounter,
    /// Unix timestamp of the last successful registry operation. Label:
    /// `kind` ∈ {`source_poll`, `inbound_sign`, `quote_sign`, `inbound_post`}.
    pub registry_last_success_timestamp_seconds: IntGaugeVec,
    /// Latest locally-derived `THORChain` pause bitmask.
    pub registry_pause_flags: IntGauge,

    // --- Finalized event observers ---
    /// Finalized event processing outcomes. Labels: `kind` ∈
    /// {`mint`, `delivery`, `refund`, `streamed`}, `result` ∈
    /// {`observed`, `posted`, `duplicate`, `refused`, `error`}.
    pub observer_events: IntCounterVec,
    /// Durable checkpoint rewinds after canonical-hash disagreement.
    pub observer_reorg_rollbacks: IntCounter,
    /// Last durably committed finalized block. Label: `observer` is a fixed
    /// configured role identifier, never an endpoint or user-supplied value.
    pub observer_checkpoint_height: IntGaugeVec,
    /// Consensus-finalized head observed from the pinned Ethereum RPC.
    pub observer_finalized_head_height: IntGaugeVec,
    /// Unix timestamp of the last canonical checkpoint/head convergence.
    pub observer_last_sync_timestamp_seconds: IntGaugeVec,

    // --- Executor (xindex-redeem) ---
    /// `RedeemDispatched` events the executor has received.
    pub executor_redemptions_received: IntCounter,
    /// Redemptions that reached `chain.broadcast(tx)` and got a txid.
    pub executor_redemptions_broadcast: IntCounter,
    /// Redemptions that failed before broadcast. Label: `reason` ∈
    /// {`decode_error`, `select_utxo`, `psbt_build`, `psbt_sign`,
    /// `broadcast_error`}.
    pub executor_redemptions_failed: IntCounterVec,
    /// Re-broadcast attempts by the rebroadcast watcher. Label:
    /// `result` ∈ {`success`, `already_known`, `error`}.
    pub executor_rebroadcasts: IntCounterVec,
    /// Currently-pending broadcasts in the registry.
    pub executor_pending_broadcasts: IntGauge,
    /// Current-protocol custody dispatch outcomes. Labels: `family` is one of
    /// the fixed supported chain families and `result` ∈
    /// {`reserved`, `signed`, `broadcast`, `confirmed`, `refused`, `error`}.
    pub custody_dispatches: IntCounterVec,
    /// Attempts to reuse a one-shot custody spend/dispatch identity with a
    /// different transaction payload.
    pub custody_one_shot_conflicts: IntCounter,

    // --- Cross-cutting RPC fallover ---
    /// RPC fallover attempts to non-primary endpoints. Label: `chain`
    /// ∈ {`eth`, `thor`, `btc`}, `result` ∈ {`success`, `exhausted`,
    /// `permanent_error`}.
    pub rpc_fallover: IntCounterVec,
}

impl Metrics {
    /// Construct + register every metric on the supplied `Registry`.
    /// Call once at startup; pass the `Registry` to [`crate::http::serve_metrics`].
    ///
    /// # Errors
    /// [`MetricsError::Prometheus`] if a metric name is already
    /// registered on this `Registry` (caller bug — only call once per
    /// `Registry`).
    #[expect(
        clippy::too_many_lines,
        reason = "linear list of metric definitions; splitting into helpers fights the obvious structure"
    )]
    pub fn new(registry: &Registry) -> Result<Self, MetricsError> {
        let relayer_intents_tracked = IntCounter::new(
            "xindex_relayer_intents_tracked_total",
            "MintIntentCreated events the relayer has observed",
        )?;
        let relayer_intents_resolved = IntCounterVec::new(
            Opts::new(
                "xindex_relayer_intents_resolved_total",
                "Intents marked resolved (Finalized or Cancelled)",
            ),
            &["status"],
        )?;
        let relayer_cancel_attempts = IntCounterVec::new(
            Opts::new(
                "xindex_relayer_cancel_attempts_total",
                "cancelMint dispatches attempted",
            ),
            &["result"],
        )?;
        let relayer_pending_intents = IntGauge::new(
            "xindex_relayer_pending_intents",
            "Currently-tracked intents waiting on a deadline pass",
        )?;

        let redeem_relayer_tracked = IntCounter::new(
            "xindex_redeem_relayer_tracked_total",
            "RedemptionIntentCreated events the redemption relayer has observed",
        )?;
        let redeem_relayer_resolved = IntCounterVec::new(
            Opts::new(
                "xindex_redeem_relayer_resolved_total",
                "Redemptions marked resolved (Finalized or Cancelled)",
            ),
            &["status"],
        )?;
        let redeem_relayer_finalize_attempts = IntCounterVec::new(
            Opts::new(
                "xindex_redeem_relayer_finalize_attempts_total",
                "IndexToken.finalizeBurn dispatches attempted",
            ),
            &["result"],
        )?;
        let redeem_relayer_cancel_attempts = IntCounterVec::new(
            Opts::new(
                "xindex_redeem_relayer_cancel_attempts_total",
                "IndexToken.cancelBurn dispatches attempted",
            ),
            &["result"],
        )?;
        let redeem_relayer_pending = IntGauge::new(
            "xindex_redeem_relayer_pending",
            "Currently-tracked unresolved redemptions",
        )?;
        let redeem_relayer_stuck = IntGauge::new(
            "xindex_redeem_relayer_stuck",
            "SD-B: redemptions past deadline with no delivery/refund attestation",
        )?;

        let signer_attestations_signed = IntCounter::new(
            "xindex_signer_attestations_signed_total",
            "Attestations successfully signed by this signer instance",
        )?;
        let signer_attestations_skipped = IntCounterVec::new(
            Opts::new(
                "xindex_signer_attestations_skipped_total",
                "Attestations skipped before signing",
            ),
            &["reason"],
        )?;
        let signer_attest_posted = IntCounterVec::new(
            Opts::new(
                "xindex_signer_attest_posted_total",
                "AttestationOracle.attest tx outcomes",
            ),
            &["result"],
        )?;
        let signer_requests = IntCounterVec::new(
            Opts::new(
                "xindex_signer_requests_total",
                "Policy and HSM signer request outcomes",
            ),
            &["role", "result"],
        )?;
        let price_signer_rounds = IntCounterVec::new(
            Opts::new(
                "xindex_price_signer_rounds_total",
                "Independent price-production round outcomes",
            ),
            &["result"],
        )?;
        let price_signer_last_success_timestamp_seconds = IntGaugeVec::new(
            Opts::new(
                "xindex_price_signer_last_success_timestamp_seconds",
                "Last successfully signed deterministic price epoch",
            ),
            &["asset"],
        )?;
        let price_signer_anomaly_streak = IntGaugeVec::new(
            Opts::new(
                "xindex_price_signer_anomaly_streak",
                "Consecutive fail-closed price rounds",
            ),
            &["asset"],
        )?;
        let price_collector_deliveries = IntCounterVec::new(
            Opts::new(
                "xindex_price_collector_deliveries_total",
                "Signed price tuple deliveries to redundant collectors",
            ),
            &["result"],
        )?;
        let price_collector_messages = IntCounterVec::new(
            Opts::new(
                "xindex_price_collector_messages_total",
                "Exact price quorum collector ingestion outcomes",
            ),
            &["result"],
        )?;
        let price_post_attempts = IntCounterVec::new(
            Opts::new(
                "xindex_price_post_attempts_total",
                "Permissionless PriceAttestationOracle post outcomes",
            ),
            &["result"],
        )?;

        let registry_source_polls = IntCounterVec::new(
            Opts::new(
                "xindex_registry_source_polls_total",
                "Complete independent THORChain source-poll rounds",
            ),
            &["result"],
        )?;
        let registry_signatures = IntCounterVec::new(
            Opts::new(
                "xindex_registry_signatures_total",
                "Registry inbound and quote signature attempts",
            ),
            &["kind", "result"],
        )?;
        let registry_collector_deliveries = IntCounterVec::new(
            Opts::new(
                "xindex_registry_collector_deliveries_total",
                "Signed registry-message deliveries to collectors",
            ),
            &["kind", "result"],
        )?;
        let registry_collector_messages = IntCounterVec::new(
            Opts::new(
                "xindex_registry_collector_messages_total",
                "Registry collector ingestion outcomes",
            ),
            &["kind", "result"],
        )?;
        let registry_evidence_failures = IntCounter::new(
            "xindex_registry_evidence_failures_total",
            "Registry evidence records that failed durable persistence",
        )?;
        let registry_last_success_timestamp_seconds = IntGaugeVec::new(
            Opts::new(
                "xindex_registry_last_success_timestamp_seconds",
                "Unix timestamp of the last successful registry operation",
            ),
            &["kind"],
        )?;
        let registry_pause_flags = IntGauge::new(
            "xindex_registry_pause_flags",
            "Latest locally-derived THORChain pause bitmask",
        )?;

        let observer_events = IntCounterVec::new(
            Opts::new(
                "xindex_observer_events_total",
                "Finalized protocol-event processing outcomes",
            ),
            &["kind", "result"],
        )?;
        let observer_reorg_rollbacks = IntCounter::new(
            "xindex_observer_reorg_rollbacks_total",
            "Durable observer checkpoint rewinds after a reorg",
        )?;
        let observer_checkpoint_height = IntGaugeVec::new(
            Opts::new(
                "xindex_observer_checkpoint_height",
                "Last durably committed finalized observer block",
            ),
            &["observer"],
        )?;
        let observer_finalized_head_height = IntGaugeVec::new(
            Opts::new(
                "xindex_observer_finalized_head_height",
                "Consensus-finalized Ethereum head seen by the observer",
            ),
            &["observer"],
        )?;
        let observer_last_sync_timestamp_seconds = IntGaugeVec::new(
            Opts::new(
                "xindex_observer_last_sync_timestamp_seconds",
                "Unix timestamp of the last canonical observer synchronization",
            ),
            &["observer"],
        )?;

        let executor_redemptions_received = IntCounter::new(
            "xindex_executor_redemptions_received_total",
            "RedeemDispatched events the executor has received",
        )?;
        let executor_redemptions_broadcast = IntCounter::new(
            "xindex_executor_redemptions_broadcast_total",
            "Redemptions that reached chain.broadcast(tx) and got a txid",
        )?;
        let executor_redemptions_failed = IntCounterVec::new(
            Opts::new(
                "xindex_executor_redemptions_failed_total",
                "Redemptions that failed before broadcast",
            ),
            &["reason"],
        )?;
        let executor_rebroadcasts = IntCounterVec::new(
            Opts::new(
                "xindex_executor_rebroadcasts_total",
                "Re-broadcast attempts by the rebroadcast watcher",
            ),
            &["result"],
        )?;
        let executor_pending_broadcasts = IntGauge::new(
            "xindex_executor_pending_broadcasts",
            "Currently-pending broadcasts in the registry",
        )?;
        let custody_dispatches = IntCounterVec::new(
            Opts::new(
                "xindex_custody_dispatches_total",
                "Current-protocol custody dispatch outcomes",
            ),
            &["family", "result"],
        )?;
        let custody_one_shot_conflicts = IntCounter::new(
            "xindex_custody_one_shot_conflicts_total",
            "Conflicting reuse attempts for one-shot custody spends",
        )?;

        let rpc_fallover = IntCounterVec::new(
            Opts::new(
                "xindex_rpc_fallover_total",
                "RPC fallover attempts to non-primary endpoints",
            ),
            &["chain", "result"],
        )?;

        registry.register(Box::new(relayer_intents_tracked.clone()))?;
        registry.register(Box::new(relayer_intents_resolved.clone()))?;
        registry.register(Box::new(relayer_cancel_attempts.clone()))?;
        registry.register(Box::new(relayer_pending_intents.clone()))?;
        registry.register(Box::new(redeem_relayer_tracked.clone()))?;
        registry.register(Box::new(redeem_relayer_resolved.clone()))?;
        registry.register(Box::new(redeem_relayer_finalize_attempts.clone()))?;
        registry.register(Box::new(redeem_relayer_cancel_attempts.clone()))?;
        registry.register(Box::new(redeem_relayer_pending.clone()))?;
        registry.register(Box::new(redeem_relayer_stuck.clone()))?;
        registry.register(Box::new(signer_attestations_signed.clone()))?;
        registry.register(Box::new(signer_attestations_skipped.clone()))?;
        registry.register(Box::new(signer_attest_posted.clone()))?;
        registry.register(Box::new(signer_requests.clone()))?;
        registry.register(Box::new(price_signer_rounds.clone()))?;
        registry.register(Box::new(
            price_signer_last_success_timestamp_seconds.clone(),
        ))?;
        registry.register(Box::new(price_signer_anomaly_streak.clone()))?;
        registry.register(Box::new(price_collector_deliveries.clone()))?;
        registry.register(Box::new(price_collector_messages.clone()))?;
        registry.register(Box::new(price_post_attempts.clone()))?;
        registry.register(Box::new(registry_source_polls.clone()))?;
        registry.register(Box::new(registry_signatures.clone()))?;
        registry.register(Box::new(registry_collector_deliveries.clone()))?;
        registry.register(Box::new(registry_collector_messages.clone()))?;
        registry.register(Box::new(registry_evidence_failures.clone()))?;
        registry.register(Box::new(registry_last_success_timestamp_seconds.clone()))?;
        registry.register(Box::new(registry_pause_flags.clone()))?;
        registry.register(Box::new(observer_events.clone()))?;
        registry.register(Box::new(observer_reorg_rollbacks.clone()))?;
        registry.register(Box::new(observer_checkpoint_height.clone()))?;
        registry.register(Box::new(observer_finalized_head_height.clone()))?;
        registry.register(Box::new(observer_last_sync_timestamp_seconds.clone()))?;
        registry.register(Box::new(executor_redemptions_received.clone()))?;
        registry.register(Box::new(executor_redemptions_broadcast.clone()))?;
        registry.register(Box::new(executor_redemptions_failed.clone()))?;
        registry.register(Box::new(executor_rebroadcasts.clone()))?;
        registry.register(Box::new(executor_pending_broadcasts.clone()))?;
        registry.register(Box::new(custody_dispatches.clone()))?;
        registry.register(Box::new(custody_one_shot_conflicts.clone()))?;
        registry.register(Box::new(rpc_fallover.clone()))?;

        Ok(Self {
            relayer_intents_tracked,
            relayer_intents_resolved,
            relayer_cancel_attempts,
            relayer_pending_intents,
            redeem_relayer_tracked,
            redeem_relayer_resolved,
            redeem_relayer_finalize_attempts,
            redeem_relayer_cancel_attempts,
            redeem_relayer_pending,
            redeem_relayer_stuck,
            signer_attestations_signed,
            signer_attestations_skipped,
            signer_attest_posted,
            signer_requests,
            price_signer_rounds,
            price_signer_last_success_timestamp_seconds,
            price_signer_anomaly_streak,
            price_collector_deliveries,
            price_collector_messages,
            price_post_attempts,
            registry_source_polls,
            registry_signatures,
            registry_collector_deliveries,
            registry_collector_messages,
            registry_evidence_failures,
            registry_last_success_timestamp_seconds,
            registry_pause_flags,
            observer_events,
            observer_reorg_rollbacks,
            observer_checkpoint_height,
            observer_finalized_head_height,
            observer_last_sync_timestamp_seconds,
            executor_redemptions_received,
            executor_redemptions_broadcast,
            executor_redemptions_failed,
            executor_rebroadcasts,
            executor_pending_broadcasts,
            custody_dispatches,
            custody_one_shot_conflicts,
            rpc_fallover,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construction registers every metric on a fresh registry without
    /// conflict — sanity-check for typos in metric names. Spot-checks
    /// only label-free collectors (`IntCounter`, `IntGauge`) because
    /// `IntCounterVec` doesn't emit a time series in `gather()` until
    /// a label combination is dispatched — that's a Prometheus client
    /// design choice, not a bug here.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn new_registers_all_metrics() {
        let registry = Registry::new();
        let m = Metrics::new(&registry).expect("fresh registry must accept all metrics");
        // Touch one label of the IntCounterVec metrics so gather()
        // emits a time series for each — proves the registration
        // succeeded for the labeled variants too.
        m.relayer_intents_resolved
            .with_label_values(&["finalized"])
            .inc();
        m.rpc_fallover.with_label_values(&["eth", "success"]).inc();
        m.registry_signatures
            .with_label_values(&["inbound", "signed"])
            .inc();
        m.registry_collector_messages
            .with_label_values(&["quote", "capacity"])
            .inc();
        m.signer_requests
            .with_label_values(&["psbt", "success"])
            .inc();
        m.price_signer_rounds.with_label_values(&["signed"]).inc();
        m.observer_events
            .with_label_values(&["mint", "observed"])
            .inc();
        m.custody_dispatches
            .with_label_values(&["evm", "reserved"])
            .inc();

        let families = registry.gather();
        let names: Vec<&str> = families
            .iter()
            .map(prometheus::proto::MetricFamily::get_name)
            .collect();
        assert!(names.contains(&"xindex_relayer_intents_tracked_total"));
        assert!(names.contains(&"xindex_executor_pending_broadcasts"));
        assert!(names.contains(&"xindex_relayer_intents_resolved_total"));
        assert!(names.contains(&"xindex_rpc_fallover_total"));
        assert!(names.contains(&"xindex_registry_signatures_total"));
        assert!(names.contains(&"xindex_registry_collector_messages_total"));
        assert!(names.contains(&"xindex_signer_requests_total"));
        assert!(names.contains(&"xindex_price_signer_rounds_total"));
        assert!(names.contains(&"xindex_observer_events_total"));
        assert!(names.contains(&"xindex_custody_dispatches_total"));
    }

    /// Calling `new()` twice on the same registry MUST fail loud
    /// (rather than silently double-registering, which would produce
    /// duplicate metric names in the scrape output and break dashboards).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn new_twice_on_same_registry_errors() {
        let registry = Registry::new();
        let _first = Metrics::new(&registry).expect("first new");
        let second = Metrics::new(&registry);
        assert!(
            matches!(second, Err(MetricsError::Prometheus(_))),
            "second registration should error"
        );
    }

    /// Counter increment + label dispatch round-trip. Validates that
    /// the public-fields API does what we expect — `metrics.foo.inc()`
    /// reflects in the scrape output.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn counters_round_trip() {
        let registry = Registry::new();
        let m = Metrics::new(&registry).expect("new");

        m.relayer_intents_tracked.inc();
        m.relayer_intents_tracked.inc();
        m.relayer_intents_resolved
            .with_label_values(&["finalized"])
            .inc();
        m.relayer_intents_resolved
            .with_label_values(&["cancelled"])
            .inc();
        m.relayer_intents_resolved
            .with_label_values(&["finalized"])
            .inc();

        assert_eq!(m.relayer_intents_tracked.get(), 2);
        assert_eq!(
            m.relayer_intents_resolved
                .with_label_values(&["finalized"])
                .get(),
            2
        );
        assert_eq!(
            m.relayer_intents_resolved
                .with_label_values(&["cancelled"])
                .get(),
            1
        );
    }

    /// Gauge set + get round-trip.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn gauges_round_trip() {
        let registry = Registry::new();
        let m = Metrics::new(&registry).expect("new");

        m.relayer_pending_intents.set(7);
        assert_eq!(m.relayer_pending_intents.get(), 7);
        m.relayer_pending_intents.dec();
        assert_eq!(m.relayer_pending_intents.get(), 6);
    }
}
