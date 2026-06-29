//! `xindex-turnkey-client` — a minimal Turnkey REST client for the custody
//! signing path under Turnkey enclave custody (`DL-CUSTODY-TURNKEY-1`).
//!
//! Covers exactly the four calls our custody flow needs:
//! [`TurnkeyClient::sign_raw_payload`] (sign a caller-computed sighash via
//! `SIGN_RAW_PAYLOAD` with `HASH_FUNCTION_NO_OP` — *we* build the BTC / EVM tx
//! and compute the hash, Turnkey signs it), [`TurnkeyClient::get_activity`]
//! (poll a `CONSENSUS_NEEDED` activity), and
//! [`TurnkeyClient::approve_activity`] / [`TurnkeyClient::reject_activity`]
//! (the approver-watcher's CTD-1 verdict). Requests are P-256 stamped per
//! Turnkey's `X-Stamp` scheme ([`auth`]).
//!
//! **PROVISIONAL — reconcile against the Turnkey dev-env.** The wire shapes are
//! pinned from Turnkey's public API docs + SDK and are mock-tested only. Known
//! reconcile points are marked `// RECONCILE AT DEV-ENV`: whether a pre-hashed
//! sighash uses `HASH_FUNCTION_NO_OP` vs `NOT_APPLICABLE`, the activity ↔
//! prepared-spend correlation field, and the `ACTIVITY_UPDATES` webhook payload
//! shape (the approver-watcher's push trigger).

pub mod auth;
pub mod client;
pub mod types;

pub use auth::TurnkeyStamper;
pub use client::{TurnkeyApi, TurnkeyClient, TURNKEY_API_BASE};
pub use types::{
    Activity, ActivityResult, ActivityStatus, SignRawPayloadParams, SignRawPayloadResult,
    HASH_FUNCTION_NO_OP, PAYLOAD_ENCODING_HEXADECIMAL,
};

/// A Turnkey client failure.
#[derive(Debug, thiserror::Error)]
pub enum TurnkeyError {
    /// Transport / connection failure.
    #[error("turnkey http error: {0}")]
    Http(String),
    /// Bad API key or stamping failure.
    #[error("turnkey auth error: {0}")]
    Auth(String),
    /// Non-2xx HTTP response from Turnkey.
    #[error("turnkey api error {status}: {body}")]
    Api {
        /// HTTP status code.
        status: u16,
        /// Response body (Turnkey error JSON).
        body: String,
    },
    /// Request/response (de)serialization failure.
    #[error("turnkey decode error: {0}")]
    Decode(String),
    /// The activity completed without the expected signature result.
    #[error("turnkey result error: {0}")]
    Result(String),
}
