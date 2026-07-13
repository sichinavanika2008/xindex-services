//! `xindex-relayer` — keeper-bot logic for the async-mint state machine.
//!
//! Responsibilities:
//! 1. Watch the on-chain `IntentQueue` for `MintIntentCreated` events.
//! 2. Track each intent's deadline; once `block.timestamp > deadline`
//!    AND the intent is still `PENDING`, dispatch a `cancelMint` call.
//! 3. (Future) Retry partner-side dispatch on detected stalls — wire
//!    deferred until M5; for now we only handle the deadline-cancel path.
//!
//! The relayer is **stateless** other than its in-memory tracker. Anyone
//! can call `cancelMint`, so a missed dispatch is recoverable: the next
//! poll catches it. We never authoritatively decide intents — only the
//! contract's `IntentState` is canonical.

pub mod hint_builder;
pub mod price_collector;
pub mod redemption_store;
pub mod registry_collector;
pub mod registry_hints;
pub mod settlement_collector;
pub mod store;
pub mod tracker;

pub use hint_builder::{
    plan_stream, slip_bps, HintParams, StreamPlan, MAX_STREAM_BLOCKS, THOR_BLOCK_SECS,
};
pub use price_collector::{
    IngestOutcome, PriceCollectError, PriceCollector, PricePayload, ReadyPrice,
};
pub use redemption_store::{
    InMemoryRedemptionTracker, RedemptionTrackerError, RedemptionTrackerStore,
    SqliteRedemptionTracker, StuckDecision, TrackedRedemption,
};
pub use settlement_collector::{
    ReadySettlement, SettlementCollectError, SettlementCollector, SettlementIngestOutcome,
    SettlementPayload,
};
pub use store::{InMemoryIntentTracker, IntentTrackerStore, SqliteIntentTracker, TrackerError};
pub use tracker::{IntentTracker, RelayDecision, TrackedIntent};
