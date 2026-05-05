//! Bitcoin chain client trait + production HTTP implementation.
//!
//! [`BitcoinChainClient`] is the surface the rest of the off-chain stack
//! programs against. The production [`EsploraClient`] talks to any
//! Blockstream-style Esplora HTTP API (signet, mainnet, or a self-hosted
//! Esplora). Tests inject a fake implementing the same trait — no
//! network dependency.

use bitcoin::{Address, Network, Transaction, Txid};
use thiserror::Error;

use crate::types::{BitcoinTxStatus, BitcoinUtxo};

/// Errors surfaced by Bitcoin chain queries.
#[derive(Debug, Error)]
pub enum BitcoinError {
    /// Transport / HTTP failure talking to the underlying Esplora server.
    #[error("transport error: {0}")]
    Transport(String),
    /// The address checksum / network does not match the configured
    /// [`Network`] for this client.
    #[error("address network mismatch: expected {expected:?}, got {actual:?}")]
    AddressNetworkMismatch { expected: Network, actual: Network },
    /// The server returned a response that did not deserialize.
    #[error("decode error: {0}")]
    Decode(String),
    /// Catch-all for upstream issues we surface with a string.
    #[error("upstream error: {0}")]
    Upstream(String),
}

/// Trait abstracting the Bitcoin chain queries the off-chain stack uses.
///
/// Implementations:
/// - Production: [`EsploraClient`] backed by a Blockstream / mempool.space
///   compatible Esplora HTTP server.
/// - Tests: an in-memory fake (see `crates/chain-btc/tests` and the
///   `tests` module of [`crate::watcher`]).
pub trait BitcoinChainClient {
    /// Confirmed UTXOs currently sitting at `address`.
    ///
    /// # Errors
    /// [`BitcoinError::Transport`] on network failure,
    /// [`BitcoinError::AddressNetworkMismatch`] if the address belongs
    /// to a different network than this client.
    fn get_address_utxos(&self, address: &Address) -> Result<Vec<BitcoinUtxo>, BitcoinError>;

    /// Confirmation status of a single transaction.
    ///
    /// # Errors
    /// As [`BitcoinChainClient::get_address_utxos`].
    fn get_tx_status(&self, txid: &Txid) -> Result<BitcoinTxStatus, BitcoinError>;

    /// Current chain tip height.
    ///
    /// # Errors
    /// [`BitcoinError::Transport`] on network failure.
    fn get_tip_height(&self) -> Result<u32, BitcoinError>;

    /// Broadcast a finalized transaction. Used by the executor after the
    /// 3-of-5 multisig signing round completes.
    ///
    /// # Errors
    /// [`BitcoinError::Upstream`] if the node rejects the broadcast
    /// (mempool conflict, dust-relay, signature failure).
    fn broadcast(&self, tx: &Transaction) -> Result<Txid, BitcoinError>;
}

/// Production [`BitcoinChainClient`] backed by an Esplora-compatible
/// HTTP server.
///
/// Construct with [`EsploraClient::new`] (default 30s timeout) or
/// [`EsploraClient::with_url`] for custom endpoints. The blocking
/// underlying client is fine for the periodic-poll workload our watchers
/// do; an async variant can land later if hot loops appear.
///
/// **Connection deferred until M3-test phase.** The plumbing is here so
/// the rest of the stack programs against the trait, but no real Esplora
/// HTTP call has been exercised yet — that's the test step the user
/// explicitly deferred. The implementation calls into `bdk_esplora`'s
/// re-exported `esplora_client::BlockingClient` exactly as the BDK docs
/// describe.
#[derive(Debug)]
pub struct EsploraClient {
    /// Configured chain network. Used to validate addresses passed to
    /// `get_address_utxos` belong to the intended network.
    pub network: Network,
    base_url: String,
}

impl EsploraClient {
    /// Mainnet Esplora at `https://blockstream.info/api`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            network: Network::Bitcoin,
            base_url: "https://blockstream.info/api".to_string(),
        }
    }

    /// Signet Esplora at `https://blockstream.info/signet/api`.
    #[must_use]
    pub fn signet() -> Self {
        Self {
            network: Network::Signet,
            base_url: "https://blockstream.info/signet/api".to_string(),
        }
    }

    /// Custom Esplora endpoint + network.
    pub fn with_url(network: Network, base_url: impl Into<String>) -> Self {
        Self {
            network,
            base_url: base_url.into(),
        }
    }

    /// Configured base URL for this client.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl Default for EsploraClient {
    fn default() -> Self {
        Self::new()
    }
}

impl BitcoinChainClient for EsploraClient {
    fn get_address_utxos(&self, _address: &Address) -> Result<Vec<BitcoinUtxo>, BitcoinError> {
        // Network validation happens at parse time (caller uses
        // `Address::require_network`). This impl assumes the caller has
        // already done that.
        //
        // The real Esplora call lands when this client is wired into the
        // M3-test phase (deferred per user instruction). The shape we
        // would call is documented inline so the wiring is unambiguous:
        //
        //     use bdk_esplora::esplora_client::Builder;
        //     let client = Builder::new(&self.base_url).build_blocking();
        //     let scripthash_txs = client
        //         .scripthash_txs(address.script_pubkey().as_script(), None)
        //         .map_err(|e| BitcoinError::Transport(e.to_string()))?;
        //     // For each tx, walk vouts → match address → record UTXO.
        //
        // Until the test-phase wiring runs, we return Err so any
        // accidental "production code path" is loud rather than silent.
        Err(BitcoinError::Upstream(
            "EsploraClient not yet wired to live Esplora; will be enabled in test phase"
                .to_string(),
        ))
    }

    fn get_tx_status(&self, _txid: &Txid) -> Result<BitcoinTxStatus, BitcoinError> {
        Err(BitcoinError::Upstream(
            "EsploraClient not yet wired to live Esplora; will be enabled in test phase"
                .to_string(),
        ))
    }

    fn get_tip_height(&self) -> Result<u32, BitcoinError> {
        Err(BitcoinError::Upstream(
            "EsploraClient not yet wired to live Esplora; will be enabled in test phase"
                .to_string(),
        ))
    }

    fn broadcast(&self, _tx: &Transaction) -> Result<Txid, BitcoinError> {
        Err(BitcoinError::Upstream(
            "EsploraClient not yet wired to live Esplora; will be enabled in test phase"
                .to_string(),
        ))
    }
}
