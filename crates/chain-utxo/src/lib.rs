//! `xindex-chain-utxo` — UTXO chain client + watcher for the
//! Phase 3.1 UTXO custody family (BTC + LTC + BCH + DOGE + ZEC).
//!
//! Two responsibilities for the off-chain stack:
//!
//! 1. **Inbound observation (signer cross-check)** — watch our 3-of-5
//!    multisig address (P2WSH on segwit chains, P2SH-legacy elsewhere)
//!    for confirmed arrivals. The attestation signer cross-checks
//!    this against `THORChain`'s outbound observation before signing
//!    an attestation for the on-chain oracle.
//!
//! 2. **Outbound dispatch (executor)** — broadcast UTXO transactions
//!    the multisig has signed via PSBT round-trips with the per-key
//!    `xindex-multisig` daemon.
//!
//! [`UtxoChainClient`] is the production / test surface. Per-chain
//! constants live in [`params`]; per-chain address codecs in U6.

pub mod client;
pub mod codec;
pub mod params;
pub mod types;
pub mod watcher;

pub use client::{EsploraClient, UtxoChainClient, UtxoError};
pub use codec::{
    codec_for_mainnet, BchCodec, BtcCodec, CodecError, DogeCodec, LtcCodec, UtxoAddressCodec,
    ZecCodec,
};
pub use params::{ScriptKind, UtxoParams};
pub use types::{UtxoEntry, UtxoOutputFacts, UtxoTransactionFacts, UtxoTxStatus};
pub use watcher::find_arrival;
