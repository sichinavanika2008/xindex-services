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

pub mod tracker;

pub use tracker::{IntentTracker, RelayDecision, TrackedIntent};
