//! `xindex-fb-cosigner` — Fireblocks API Co-Signer callback handler.
//!
//! Under the Fireblocks MPC custody model (`DL-CUSTODY-FIREBLOCKS-1`) the
//! Fireblocks API Co-Signer POSTs every pending signature to this handler,
//! which APPROVEs or REJECTs it before the MPC signs. Our destination-binding
//! (CTD-1) lives HERE — the policy engine (TAP) cannot inspect a `THORChain`
//! `OP_RETURN` memo, so for the BTC RAW-signing path this callback is the
//! sole semantic enforcement, fail-closed.
//!
//! **This crate today = the WIRE-INDEPENDENT core:** the bind-prepare context
//! store ([`prepare`]) and the CTD-1 redeem-spend decision ([`btc`]), built on
//! the shared [`xindex_custody_core`] gates + binder. The thin Fireblocks-wire
//! adapter — mutual RS256 JWT, the `tx_sign_request` serde schema, and the
//! input-sighash ↔ `rawMessage` tie-in — is pinned against the real Fireblocks
//! sandbox/SDK (Slice 0) and layered on top.

pub mod btc;
pub mod prepare;

/// The callback's verdict on a pending Fireblocks signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Every check passed — Fireblocks MPC may produce the signature.
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
