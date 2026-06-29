//! `xindex-custody-node` — the provider-neutral custody decision library.
//!
//! Under the Turnkey custody model (`DL-CUSTODY-TURNKEY-1`) every pending
//! signature is a `CONSENSUS_NEEDED` activity that our approver-watcher must
//! `approveActivity` before Turnkey's enclave signs (fail-closed by
//! construction — no approval ⇒ no signature). Our destination-binding (CTD-1)
//! runs HERE as the approval gate on our own fleet — the provider cannot
//! inspect a `THORChain` `OP_RETURN` memo, so this is the sole semantic
//! enforcement, fail-closed.
//!
//! This crate is the **wire-independent decision core:** the per-family CTD-1
//! spend decisions ([`btc`], [`evm`], [`account`]) and the [`dispatch`]
//! pipeline that runs them against the shared [`xindex_custody_core`] gates +
//! binders + prepare/replay stores. The Turnkey wire (P-256 stamp, the
//! `SIGN_RAW_PAYLOAD` activity schema, the `ACTIVITY_UPDATES` correlation) lives
//! in `xindex-turnkey-client` and the approver-watcher binary; they are pinned
//! against the real Turnkey dev-env and layered on top.

pub mod account;
pub mod approver;
pub mod btc;
pub mod dispatch;
pub mod evm;

#[cfg(test)]
mod test_support;

/// The approver's verdict on a pending custody signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Every check passed — Turnkey's enclave may produce the signature.
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
