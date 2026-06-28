//! `xindex-custody-node` — Cobo TSS-Node callback handler.
//!
//! Under the Cobo MPC-TSS custody model (`DL-CUSTODY-COBO-1`) Cobo's TSS
//! Node POSTs every pending signature to this callback server, which APPROVEs
//! or REJECTs it before the MPC share signs (mutual RS256 JWT, fail-closed).
//! Our destination-binding (CTD-1) runs HERE as custom risk-control on our own
//! node — the provider's policy engine cannot inspect a `THORChain`
//! `OP_RETURN` memo, so for the BTC raw-signing path this callback is the sole
//! semantic enforcement, fail-closed.
//!
//! **This crate today = the WIRE-INDEPENDENT core:** the bind-prepare context
//! store ([`prepare`]) and the per-family CTD-1 spend decisions ([`btc`],
//! [`evm`], [`account`]), built on the shared [`xindex_custody_core`] gates +
//! binders. The thin Cobo-wire adapter — mutual RS256 JWT, the TSS-Node
//! callback request schema (`request_detail` / `extra_info`), and the
//! sighash ↔ callback-request tie-in — is pinned against the real Cobo dev-env
//! (`api.dev.cobo.com`) and layered on top. The BTC `OP_RETURN` / raw-sighash
//! capability the BTC path depends on is the OPEN gate — see
//! `docs/runbooks/cobo-btc-gate.md`.

pub mod account;
pub mod btc;
pub mod cobo_types;
pub mod dispatch;
pub mod evm;
pub mod jwt;
pub mod prepare;
pub mod server;

#[cfg(test)]
mod test_support;

/// The callback's verdict on a pending Cobo TSS-Node signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Every check passed — Cobo MPC may produce the signature.
    Approve,
    /// Refused (fail-closed). `code` is the stable wire error code, `message`
    /// the operator-facing detail.
    Reject {
        /// Stable wire error code (`xindex_shared::signer_wire::error_codes`).
        code: &'static str,
        /// Operator-facing rejection detail.
        message: String,
    },
}
