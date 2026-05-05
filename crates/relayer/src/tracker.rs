//! In-memory tracker of pending mint intents.
//!
//! Holds a snapshot of every intent the relayer has seen but not yet
//! resolved (finalized or cancelled). On each tick the relayer asks
//! [`IntentTracker::scan`] for the set of intents whose deadlines have
//! passed; the keeper then dispatches `cancelMint(intentId)` for each.

use std::collections::HashMap;

use alloy_primitives::B256;

/// State the relayer holds about one in-flight mint intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackedIntent {
    /// `block.timestamp` after which `cancelMint` is callable on-chain.
    pub deadline_unix_secs: u64,
    /// Index token contract that minted the intent (target of cancel).
    pub index_token: alloy_primitives::Address,
}

/// Output of [`IntentTracker::scan`] — what the keeper should do this
/// tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayDecision {
    pub expired: Vec<(B256, TrackedIntent)>,
}

/// Stateless tracker: map of intentId → tracked-state.
///
/// "Forget" is explicit (`mark_resolved`); the relayer calls it after a
/// `MintIntentFinalized` or `MintIntentCancelled` event clears the
/// intent on-chain. Until then we keep polling — re-trying a cancel is
/// idempotent on the contract side (it reverts with `WrongState`),
/// so the cost of a stale entry is one wasted RPC call.
#[derive(Debug, Default)]
pub struct IntentTracker {
    intents: HashMap<B256, TrackedIntent>,
}

impl IntentTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            intents: HashMap::new(),
        }
    }

    /// Add a freshly-observed `MintIntentCreated` event. If we already
    /// know about it (re-replayed log on reconnect), the existing entry
    /// is replaced — events from the same intent should carry identical
    /// deadlines and addresses, so the replacement is a no-op.
    pub fn observe(&mut self, id: B256, intent: TrackedIntent) {
        self.intents.insert(id, intent);
    }

    /// Drop the intent — called on `MintIntentFinalized` /
    /// `MintIntentCancelled`. Idempotent.
    pub fn mark_resolved(&mut self, id: &B256) {
        self.intents.remove(id);
    }

    /// Number of intents currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.intents.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.intents.is_empty()
    }

    /// Scan: which intents have crossed their deadline as of `now_unix`?
    /// Returns deterministically-ordered output (sorted by intent-id) so
    /// tests + replay are stable.
    #[must_use]
    pub fn scan(&self, now_unix: u64) -> RelayDecision {
        let mut expired: Vec<(B256, TrackedIntent)> = self
            .intents
            .iter()
            .filter(|(_, intent)| now_unix > intent.deadline_unix_secs)
            .map(|(id, intent)| (*id, *intent))
            .collect();
        expired.sort_by_key(|(id, _)| *id);
        RelayDecision { expired }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};

    fn ti(deadline: u64) -> TrackedIntent {
        TrackedIntent {
            deadline_unix_secs: deadline,
            index_token: address!("0000000000000000000000000000000000000001"),
        }
    }

    #[test]
    fn empty_tracker_scans_clean() {
        let t = IntentTracker::new();
        let r = t.scan(100);
        assert!(r.expired.is_empty());
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn scan_filters_by_deadline() {
        let mut t = IntentTracker::new();
        let id_a = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let id_b = b256!("0000000000000000000000000000000000000000000000000000000000000002");
        let id_c = b256!("0000000000000000000000000000000000000000000000000000000000000003");
        t.observe(id_a, ti(100));
        t.observe(id_b, ti(200));
        t.observe(id_c, ti(300));

        // now = 250 → A and B expired, C still alive.
        let decision = t.scan(250);
        assert_eq!(decision.expired.len(), 2);
        assert_eq!(decision.expired[0].0, id_a);
        assert_eq!(decision.expired[1].0, id_b);
    }

    #[test]
    fn mark_resolved_removes() {
        let mut t = IntentTracker::new();
        let id = b256!("00000000000000000000000000000000000000000000000000000000000000aa");
        t.observe(id, ti(100));
        assert_eq!(t.len(), 1);
        t.mark_resolved(&id);
        assert!(t.is_empty());
        // Idempotent: removing twice is fine.
        t.mark_resolved(&id);
        assert!(t.is_empty());
    }

    #[test]
    fn observe_replaces_existing() {
        let mut t = IntentTracker::new();
        let id = b256!("00000000000000000000000000000000000000000000000000000000000000bb");
        t.observe(id, ti(100));
        t.observe(id, ti(500));
        let decision = t.scan(200);
        // Replaced deadline pushes intent past `now=200`.
        assert!(decision.expired.is_empty());
        let decision_late = t.scan(600);
        assert_eq!(decision_late.expired.len(), 1);
        assert_eq!(decision_late.expired[0].1.deadline_unix_secs, 500);
    }
}
