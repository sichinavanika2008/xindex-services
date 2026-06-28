//! `xindex-cobo-client` — a minimal Cobo v2 REST client for the EVM redeem
//! reroute under Cobo MPC custody (`DL-CUSTODY-COBO-1`).
//!
//! Covers exactly the three calls the executor's EVM-Cobo path needs:
//! [`CoboClient::contract_call`] (build a `Router.depositWithExpiry` tx,
//! `BuildOnly`), [`CoboClient::sign_and_broadcast`] (the TSS Node signs HERE,
//! so our `xindex-custody-node` callback fires), and
//! [`CoboClient::get_transaction`] (poll to confirmation). Requests are
//! Ed25519-signed per Cobo's `Biz-Api-*` scheme ([`auth`]).
//!
//! **PROVISIONAL — reconcile against `api.dev.cobo.com` (W3).** The wire shapes
//! are pinned from Cobo's public docs + the Go/Python SDKs (there is no Rust
//! SDK), and are mock-tested only. Known reconcile points are marked
//! `// RECONCILE AT DEV-ENV` and summarized in `docs/runbooks/cobo-btc-gate.md`:
//! the exact sign-string PATH (incl. `/v2`), the `value` units (decimal coin,
//! not wei), and whether `BuildOnly` yields a `Built` status.

pub mod auth;
pub mod client;
pub mod types;

pub use auth::CoboSigner;
pub use client::{CoboApi, CoboClient, COBO_API_DEV, COBO_API_PROD};

/// A Cobo client failure.
#[derive(Debug, thiserror::Error)]
pub enum CoboError {
    /// Transport / connection failure.
    #[error("cobo http error: {0}")]
    Http(String),
    /// Bad API key/secret or signing failure.
    #[error("cobo auth error: {0}")]
    Auth(String),
    /// Non-2xx HTTP response from Cobo.
    #[error("cobo api error {status}: {body}")]
    Api {
        /// HTTP status code.
        status: u16,
        /// Response body (Cobo error JSON).
        body: String,
    },
    /// Request/response (de)serialization failure.
    #[error("cobo decode error: {0}")]
    Decode(String),
}
