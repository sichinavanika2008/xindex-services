//! `xindex-executor` — settlement of native-chain redemptions.
//!
//! Job:
//! 1. Watch [`ThorchainAdapter::RedeemDispatched`](xindex_chain_eth::bindings::ThorchainAdapter)
//!    on Ethereum.
//! 2. Per event, decode the user's destination address (UTF-8 bytes) and
//!    pro-rata amount, select a multisig UTXO, build an unsigned PSBT
//!    spending it.
//! 3. Coordinate with the K signer daemons (M5 — wire-protocol deferred)
//!    to collect K partial signatures, finalize the PSBT, broadcast.
//!
//! ## In-process variant
//!
//! [`InProcessExecutor`] holds K secret keys directly and signs locally.
//! Used by integration tests + dev environments. Production replaces this
//! with a `MultisigCosigner` trait carrying signer-daemon RPC calls.

pub mod broadcast_registry;
pub mod rebroadcast;
pub mod redeem;
pub mod remote_cosigner;

pub use broadcast_registry::{
    now_unix_secs, BroadcastRegistry, BroadcastStatus, InMemoryBroadcastRegistry, PendingBroadcast,
    RegistryError, SqliteBroadcastRegistry,
};
pub use rebroadcast::{run_watcher, WatcherConfig, WatcherError};
pub use redeem::{
    decode_redeem_event, ExecuteError, InProcessExecutor, MultisigCosigner, RedeemTask,
    RedeemTaskSource,
};
