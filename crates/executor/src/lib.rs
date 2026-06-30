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
pub mod cancel_swap_back;
pub mod cosmos_redeem;
pub mod evm_redeem;
pub mod rebroadcast;
pub mod redeem;
pub mod remote_cosigner;
pub mod ric_collector;
pub mod solana_redeem;
pub mod solana_redeem_store;
pub mod tron_redeem;
pub mod turnkey_btc_redeem;
pub mod turnkey_cosmos_redeem;
pub mod turnkey_evm_redeem;
pub mod turnkey_solana_redeem;
pub mod turnkey_tron_redeem;
pub mod turnkey_xrp_redeem;
pub mod xrp_redeem;

pub use broadcast_registry::{
    now_unix_secs, BroadcastRegistry, BroadcastStatus, InMemoryBroadcastRegistry, PendingBroadcast,
    RegistryError, SqliteBroadcastRegistry,
};
pub use cancel_swap_back::SwapBackTask;
pub use rebroadcast::{run_watcher, WatcherConfig, WatcherError};
pub use redeem::{
    decode_redeem_event, ExecuteError, ExpectedOutputs, InProcessExecutor, MultisigCosigner,
    RedeemTask, RedeemTaskSource, SpendCertificate,
};
pub use ric_collector::{CollectedAcc, CollectedRic, RicCollectError, RicCollector};
pub use solana_redeem::{
    SolanaCosigner, SolanaLockTable, SolanaMemberSig, SolanaRedeemConfig, SolanaRedeemError,
    SolanaRedeemExecutor, SolanaRedeemLegOutcome, SolanaRedeemTask,
};
pub use solana_redeem_store::{
    CachedBroadcast, InMemorySolanaRedeemStore, RedeemProgress, SolanaRedeemStore,
    SolanaStoreError, SqliteSolanaRedeemStore,
};
pub use tron_redeem::{
    member_evm_address, SignTronFuture, TronCosigner, TronRedeemConfig, TronRedeemError,
    TronRedeemExecutor, TronRedeemLegOutcome, TronRedeemTask,
};
