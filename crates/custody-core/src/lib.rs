//! `xindex-custody-core` — CTD-1 custody-verification primitives shared by
//! the signer-daemon (transitional), the Fireblocks co-signer callback,
//! and the Set-B attest-signer.
//!
//! Currently holds the replay / one-shot / certification-volume store
//! ([`replay`]). The RIC/ACC gates, `CertifiedSpend`, and the per-family
//! spend binders are being relocated here from the daemon as they are
//! decoupled from its HTTP (`axum`) layer.

pub mod btc_bind;
pub mod evm_bind;
pub mod gates;
pub mod prepare;
pub mod replay;
