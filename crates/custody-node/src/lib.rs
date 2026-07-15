//! `xindex-custody-node` — the provider-neutral custody decision library.
//!
//! This crate is the **wire-independent decision core:** the per-family CTD-1
//! spend decisions ([`btc`], [`evm`], [`account`]) and the [`dispatch`]
//! pipeline that runs them against the shared [`xindex_custody_core`] gates +
//! binders + prepare/replay stores. A custody-provider callback may map its
//! request into [`dispatch::decide_callback`], but no provider transport or key
//! client is part of this crate.

pub mod account;
pub mod btc;
pub mod dispatch;
pub mod evm;
pub mod recompute;

#[cfg(test)]
mod test_support;

/// The approver's verdict on a pending custody signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Every check passed — the custody provider may produce the signature.
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
