//! Bitcoin chain client trait + production HTTP implementation.
//!
//! [`UtxoChainClient`] is the surface the rest of the off-chain stack
//! programs against. The production [`EsploraClient`] talks to any
//! Blockstream-style Esplora HTTP API (signet, mainnet, or a self-hosted
//! Esplora). Tests inject a fake implementing the same trait — no
//! network dependency.

use std::collections::HashMap;

use bdk_esplora::esplora_client::{self, BlockingClient};
use bitcoin::{Address, Amount, Network, Transaction, Txid};
use thiserror::Error;

use crate::types::{UtxoEntry, UtxoTxStatus};

/// Default per-request timeout (seconds). Chosen to be generous enough for
/// the slowest Esplora endpoints (Blockstream's free tier under load) but
/// short enough that a stuck call doesn't wedge the executor.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Esplora's documented `scripthash/{hash}/txs` pagination size. The API
/// returns at most this many transactions per page; a page returning
/// fewer entries signals the end of history. Hardcoded upstream as 25
/// (see github.com/Blockstream/esplora#get-scripthashhashtxs); pinning
/// here so the pagination loop's exit condition is named, not magic.
const ESPLORA_PAGE_SIZE: usize = 25;

/// Intermediate accumulator while walking an address's tx history. We
/// collect everything paying our `script_pubkey` first, then filter out
/// already-spent outputs in a second pass via `get_output_status`.
struct UtxoCandidate {
    txid: Txid,
    vout: u32,
    value: Amount,
    block_hash: Option<bitcoin::BlockHash>,
    block_height: Option<u32>,
}

/// Errors surfaced by Bitcoin chain queries.
#[derive(Debug, Error)]
pub enum UtxoError {
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
pub trait UtxoChainClient {
    /// Confirmed UTXOs currently sitting at `address`.
    ///
    /// # Errors
    /// [`UtxoError::Transport`] on network failure,
    /// [`UtxoError::AddressNetworkMismatch`] if the address belongs
    /// to a different network than this client.
    fn get_address_utxos(&self, address: &Address) -> Result<Vec<UtxoEntry>, UtxoError>;

    /// Confirmation status of a single transaction.
    ///
    /// # Errors
    /// As [`UtxoChainClient::get_address_utxos`].
    fn get_tx_status(&self, txid: &Txid) -> Result<UtxoTxStatus, UtxoError>;

    /// Current chain tip height.
    ///
    /// # Errors
    /// [`UtxoError::Transport`] on network failure.
    fn get_tip_height(&self) -> Result<u32, UtxoError>;

    /// Broadcast a finalized transaction. Used by the executor after the
    /// 3-of-5 multisig signing round completes.
    ///
    /// # Errors
    /// [`UtxoError::Upstream`] if the node rejects the broadcast
    /// (mempool conflict, dust-relay, signature failure).
    fn broadcast(&self, tx: &Transaction) -> Result<Txid, UtxoError>;

    /// Live fee rate (sat/vB) sufficient to confirm within
    /// `target_blocks`. Default impl returns [`UtxoError::Upstream`]:
    /// only the production [`EsploraClient`] queries a real fee oracle,
    /// so test fakes keep the caller's configured flat fallback with no
    /// per-fake boilerplate. Closes `KNOWN_FINDINGS` L-R5 (hardcoded
    /// `fee_sats` brittle under fee spikes) — the executor binary derives
    /// its absolute budget from this, clamped, falling back to the flat
    /// default on any error.
    ///
    /// # Errors
    /// [`UtxoError::Transport`] on network failure;
    /// [`UtxoError::Upstream`] if the backend has no fee oracle or
    /// returns no usable estimate.
    fn estimate_fee_rate_sat_vb(&self, target_blocks: u16) -> Result<f64, UtxoError> {
        let _ = target_blocks;
        Err(UtxoError::Upstream(
            "fee estimation unsupported by this client".to_string(),
        ))
    }

    /// Addresses that funded the inputs of `txid` (vin prev-out `script_pubkeys`
    /// resolved to addresses for this client's network). Used to bind a UTXO's
    /// sender to the live `THORChain` Asgard vault. Default impl errors so test
    /// fakes that don't need it stay boilerplate-free.
    ///
    /// # Errors
    /// [`UtxoError::Upstream`] from the default impl; production impls map
    /// transport/decoding failures to [`UtxoError::Transport`] /
    /// [`UtxoError::Decode`].
    fn tx_input_addresses(&self, txid: &Txid) -> Result<Vec<String>, UtxoError> {
        let _ = txid;
        Err(UtxoError::Upstream(
            "tx_input_addresses unsupported by this client".to_string(),
        ))
    }
}

/// Pick the fee rate for confirming within `target_blocks` from an
/// Esplora `/fee-estimates` map (key = confirmation target in blocks,
/// value = sat/vB; sparse: typically 1,2,3,4,5,6,10,20,144,504,1008).
///
/// Esplora semantics: `estimates[k]` is the rate needed to confirm
/// within `k` blocks (smaller `k` ⇒ higher rate). To meet a deadline of
/// `target_blocks` at the lowest sufficient fee we take the entry with
/// the GREATEST key `≤ target_blocks`. If every key is above the target
/// (target tighter than the finest bucket) we take the SMALLEST key —
/// the most aggressive (safest) rate. `None` only if the map is empty.
///
/// Pure + total: the mutation-test target for this module.
#[must_use]
pub fn pick_fee_estimate<S: std::hash::BuildHasher>(
    estimates: &HashMap<u16, f64, S>,
    target_blocks: u16,
) -> Option<f64> {
    let best_at_or_below = estimates
        .iter()
        .filter(|(k, _)| **k <= target_blocks)
        .max_by_key(|(k, _)| **k)
        .map(|(_, v)| *v);
    if let Some(v) = best_at_or_below {
        return Some(v);
    }
    // Target tighter than the finest available bucket → most aggressive.
    estimates.iter().min_by_key(|(k, _)| **k).map(|(_, v)| *v)
}

/// Production [`UtxoChainClient`] backed by an Esplora-compatible
/// HTTP server.
///
/// Construct with [`EsploraClient::new`] (mainnet, default 30s timeout),
/// [`EsploraClient::signet`], or [`EsploraClient::with_url`] for custom
/// endpoints. Calls are blocking — fine for the periodic-poll workload
/// our watchers and executor do.
///
/// UTXO discovery uses the canonical Esplora pattern: walk the address's
/// transaction history, identify the vouts paying our `script_pubkey`,
/// then query `get_output_status` to filter unspent outputs.
pub struct EsploraClient {
    /// Configured chain network. Used to validate addresses passed to
    /// `get_address_utxos` belong to the intended network.
    pub network: Network,
    base_url: String,
    inner: BlockingClient,
}

impl std::fmt::Debug for EsploraClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EsploraClient")
            .field("network", &self.network)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl EsploraClient {
    /// Mainnet Esplora at `https://blockstream.info/api`.
    #[must_use]
    pub fn new() -> Self {
        Self::build(Network::Bitcoin, "https://blockstream.info/api".to_string())
    }

    /// Signet Esplora at `https://blockstream.info/signet/api`.
    #[must_use]
    pub fn signet() -> Self {
        Self::build(
            Network::Signet,
            "https://blockstream.info/signet/api".to_string(),
        )
    }

    /// Custom Esplora endpoint + network.
    pub fn with_url(network: Network, base_url: impl Into<String>) -> Self {
        Self::build(network, base_url.into())
    }

    /// Build a client for the chain described by `params`. Today this
    /// forwards to [`Self::with_url`] — BTC is the only chain whose
    /// `network` carries meaning here (`require_network` validates
    /// addresses against it). For Phase 3.1 non-BTC chains, the
    /// per-chain address codec (U6) is the real validator; the
    /// `bitcoin::Network` field on this struct is a placeholder
    /// (`Network::Bitcoin`) and `require_network` is bypassed at the
    /// codec layer. The signature is locked here so U6 can swap the
    /// network derivation in one place.
    pub fn for_chain(
        params: &crate::params::UtxoParams,
        network: Network,
        base_url: impl Into<String>,
    ) -> Self {
        let _ = params; // params drives the codec / sighash branches, not the HTTP transport.
        Self::build(network, base_url.into())
    }

    fn build(network: Network, base_url: String) -> Self {
        let inner = esplora_client::Builder::new(&base_url)
            .timeout(DEFAULT_TIMEOUT_SECS)
            .build_blocking();
        Self {
            network,
            base_url,
            inner,
        }
    }

    /// Configured base URL for this client.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Validate the caller-supplied address belongs to the network this
    /// client is configured for. P2WSH/segwit `script_pubkey()` does NOT
    /// encode the network (the bech32 hrp does), so a mainnet-configured
    /// client receiving a signet address would happily query the wrong
    /// chain's history — fail loud instead.
    ///
    /// On mismatch, we probe the four canonical networks in order to
    /// report which network the address actually belongs to (rather
    /// than a placeholder). Used purely for the operator-facing error
    /// message — the routing decision has already failed by the time
    /// we get here.
    fn require_network(&self, address: &Address) -> Result<(), UtxoError> {
        let unchecked = address.as_unchecked();
        if unchecked.is_valid_for_network(self.network) {
            return Ok(());
        }
        let actual = [
            Network::Bitcoin,
            Network::Testnet,
            Network::Signet,
            Network::Regtest,
        ]
        .into_iter()
        .find(|n| unchecked.is_valid_for_network(*n))
        .unwrap_or(Network::Bitcoin);
        Err(UtxoError::AddressNetworkMismatch {
            expected: self.network,
            actual,
        })
    }

    /// Compute confirmations from `(tip_height, status)`. An unconfirmed
    /// (in-mempool) tx returns 0 confirmations. A 1-block-old confirmed
    /// tx returns 1. Saturating arithmetic — `(tip - h)` is bounded by
    /// `u32::MAX` so the trailing `+ 1` is safe under saturation; this
    /// is paranoia against a u32 wraparound that practically requires
    /// >2 billion years of Bitcoin block production.
    fn confirmations_from(tip: u32, block_height: Option<u32>) -> u32 {
        match block_height {
            Some(h) if tip >= h => tip.saturating_sub(h).saturating_add(1),
            _ => 0,
        }
    }
}

impl Default for EsploraClient {
    fn default() -> Self {
        Self::new()
    }
}

impl UtxoChainClient for EsploraClient {
    fn get_address_utxos(&self, address: &Address) -> Result<Vec<UtxoEntry>, UtxoError> {
        self.require_network(address)?;
        let script = address.script_pubkey();
        let tip = self.get_tip_height()?;

        // Page through the address's transaction history (Esplora returns
        // ESPLORA_PAGE_SIZE per page, sorted newest-first). Stop when a
        // page returns fewer than ESPLORA_PAGE_SIZE results.
        let mut last_seen: Option<Txid> = None;
        let mut candidates: Vec<UtxoCandidate> = Vec::new();
        loop {
            let txs = self
                .inner
                .scripthash_txs(script.as_script(), last_seen)
                .map_err(|e| UtxoError::Transport(e.to_string()))?;
            if txs.is_empty() {
                break;
            }
            let len = txs.len();
            for tx in &txs {
                for (vout_idx, vout) in tx.vout.iter().enumerate() {
                    if vout.scriptpubkey == script {
                        let vout_u32: u32 =
                            vout_idx
                                .try_into()
                                .map_err(|e: std::num::TryFromIntError| {
                                    UtxoError::Decode(format!("vout index overflow: {e}"))
                                })?;
                        candidates.push(UtxoCandidate {
                            txid: tx.txid,
                            vout: vout_u32,
                            value: Amount::from_sat(vout.value),
                            block_hash: tx.status.block_hash,
                            block_height: tx.status.block_height,
                        });
                    }
                }
            }
            if len < ESPLORA_PAGE_SIZE {
                break;
            }
            last_seen = txs.last().map(|t| t.txid);
        }

        // Filter to currently-unspent outputs by checking each candidate
        // against `/tx/<txid>/outspend/<vout>`. Esplora marks an output
        // as `spent: true` the moment a spending tx hits the mempool;
        // unconfirmed-spend ambiguity is the chain's, not ours.
        let mut utxos = Vec::with_capacity(candidates.len());
        for c in candidates {
            let status = self
                .inner
                .get_output_status(&c.txid, u64::from(c.vout))
                .map_err(|e| UtxoError::Transport(e.to_string()))?;
            let is_spent = status.is_some_and(|s| s.spent);
            if is_spent {
                continue;
            }
            utxos.push(UtxoEntry {
                txid: c.txid,
                vout: c.vout,
                value: c.value,
                confirmations: Self::confirmations_from(tip, c.block_height),
                block_hash: c.block_hash,
            });
        }
        Ok(utxos)
    }

    fn get_tx_status(&self, txid: &Txid) -> Result<UtxoTxStatus, UtxoError> {
        let status = self
            .inner
            .get_tx_status(txid)
            .map_err(|e| UtxoError::Transport(e.to_string()))?;
        let tip = self.get_tip_height()?;
        Ok(UtxoTxStatus {
            txid: *txid,
            confirmed: status.confirmed,
            block_height: status.block_height,
            block_hash: status.block_hash,
            confirmations: Self::confirmations_from(tip, status.block_height),
        })
    }

    fn get_tip_height(&self) -> Result<u32, UtxoError> {
        self.inner
            .get_height()
            .map_err(|e| UtxoError::Transport(e.to_string()))
    }

    fn broadcast(&self, tx: &Transaction) -> Result<Txid, UtxoError> {
        self.inner
            .broadcast(tx)
            .map_err(|e| UtxoError::Upstream(e.to_string()))?;
        Ok(tx.compute_txid())
    }

    fn estimate_fee_rate_sat_vb(&self, target_blocks: u16) -> Result<f64, UtxoError> {
        let estimates = self
            .inner
            .get_fee_estimates()
            .map_err(|e| UtxoError::Transport(e.to_string()))?;
        pick_fee_estimate(&estimates, target_blocks)
            .ok_or_else(|| UtxoError::Upstream("esplora returned no fee estimates".to_string()))
    }

    fn tx_input_addresses(&self, txid: &Txid) -> Result<Vec<String>, UtxoError> {
        let tx = self
            .inner
            .get_tx_info(txid)
            .map_err(|e| UtxoError::Transport(e.to_string()))?
            .ok_or_else(|| UtxoError::Decode(format!("tx {txid} not found")))?;
        let mut addresses = Vec::with_capacity(tx.vin.len());
        for vin in tx.vin {
            // Coinbase inputs carry no prevout — skip (an Asgard outbound is
            // never coinbase, so this only drops irrelevant inputs).
            let Some(prevout) = vin.prevout else {
                continue;
            };
            let address = Address::from_script(prevout.scriptpubkey.as_script(), self.network)
                .map_err(|e| UtxoError::Decode(format!("vin script not an address: {e}")))?;
            addresses.push(address.to_string());
        }
        Ok(addresses)
    }
}

#[cfg(test)]
mod fee_estimate_tests {
    use super::pick_fee_estimate;
    use std::collections::HashMap;

    /// Realistic sparse Esplora shape.
    fn sample() -> HashMap<u16, f64> {
        HashMap::from([
            (1, 87.0),
            (2, 60.0),
            (3, 45.0),
            (6, 20.0),
            (10, 8.0),
            (144, 2.0),
            (1008, 1.0),
        ])
    }

    #[test]
    fn exact_target_hits_that_bucket() {
        assert_eq!(pick_fee_estimate(&sample(), 6), Some(20.0));
        assert_eq!(pick_fee_estimate(&sample(), 3), Some(45.0));
    }

    #[test]
    fn between_buckets_takes_greatest_key_at_or_below() {
        // target 5 → no key 5; greatest key ≤ 5 is 3 (45 sat/vB), NOT 6.
        // (Confirming "within 5" is satisfied by the within-3 rate; the
        //  within-6 rate could miss the 5-block deadline.)
        assert_eq!(pick_fee_estimate(&sample(), 5), Some(45.0));
        // target 100 → greatest key ≤ 100 is 10 (8.0).
        assert_eq!(pick_fee_estimate(&sample(), 100), Some(8.0));
    }

    #[test]
    fn target_tighter_than_finest_bucket_uses_most_aggressive() {
        // No key ≤ 0 → fall back to the smallest key (1 → 87.0), the
        // safest/most-aggressive rate, never a slower one.
        assert_eq!(pick_fee_estimate(&sample(), 0), Some(87.0));
    }

    #[test]
    fn empty_map_is_none() {
        assert_eq!(pick_fee_estimate(&HashMap::new(), 3), None);
    }

    #[test]
    fn beyond_coarsest_bucket_takes_coarsest() {
        assert_eq!(pick_fee_estimate(&sample(), 5000), Some(1.0));
    }
}

#[cfg(test)]
mod fee_estimate_integration_tests {
    //! Kill the mutation-survivors for the trait DEFAULT and the
    //! `EsploraClient` IMPL of `estimate_fee_rate_sat_vb`:
    //! `Ok(0.0)`/`Ok(1.0)`/`Ok(-1.0)` stubs would only slip if no test
    //! actually exercises these methods end-to-end. The picker is pure
    //! and already covered above; these tests cover the boundary.

    use super::*;
    use bitcoin::Transaction;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Minimal `UtxoChainClient` that overrides ONLY the required
    /// methods and inherits the trait default for fee estimation. Lets
    /// us assert the default returns `Err` (kills the `Ok(*)` default-
    /// impl mutants).
    struct DefaultFeeChain;
    impl UtxoChainClient for DefaultFeeChain {
        fn get_address_utxos(&self, _address: &Address) -> Result<Vec<UtxoEntry>, UtxoError> {
            Ok(Vec::new())
        }
        fn get_tx_status(&self, _txid: &Txid) -> Result<UtxoTxStatus, UtxoError> {
            // Not used by any test in this module; returning Err avoids
            // needing a fabricated `Txid` (and avoids `expect_used`).
            Err(UtxoError::Upstream("not used".to_string()))
        }
        fn get_tip_height(&self) -> Result<u32, UtxoError> {
            Ok(0)
        }
        fn broadcast(&self, _tx: &Transaction) -> Result<Txid, UtxoError> {
            Err(UtxoError::Upstream("not used".to_string()))
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn trait_default_fee_estimate_returns_err() {
        let c = DefaultFeeChain;
        let err = c
            .estimate_fee_rate_sat_vb(3)
            .expect_err("default impl must return Err");
        // Surfaces as Upstream so callers can fall back to a flat fee
        // without confusing a transport failure with "no oracle here".
        assert!(matches!(err, UtxoError::Upstream(_)));
    }

    /// `EsploraClient` integration: mount `/fee-estimates` on a wiremock
    /// server, build a client pointed at it, and verify the returned
    /// rate is the picker's exact output for the same map. Kills the
    /// `Ok(0.0)`/`Ok(1.0)`/`Ok(-1.0)` mutations on the impl override
    /// (no real chain access — pure local HTTP).
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn esplora_estimate_fee_rate_matches_picker_output() {
        let server = MockServer::start().await;
        // Realistic shape.
        let body = json!({
            "1": 87.0,
            "2": 60.0,
            "3": 45.0,
            "6": 20.0,
            "10": 8.0,
            "144": 2.0,
            "1008": 1.0,
        });
        Mock::given(method("GET"))
            .and(path("/fee-estimates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .mount(&server)
            .await;

        // Esplora's blocking client is synchronous; run it on a spawn-
        // blocking thread so the tokio test runtime isn't blocked.
        let url = server.uri();
        let rate3 = tokio::task::spawn_blocking(move || {
            let client = EsploraClient::with_url(Network::Regtest, &url);
            client.estimate_fee_rate_sat_vb(3)
        })
        .await
        .expect("join")
        .expect("estimate");

        // Greatest key ≤ 3 = 3 → 45.0 sat/vB. Equality is exact — body
        // values are integral f64s with no rounding hazard.
        assert!(
            (rate3 - 45.0).abs() < f64::EPSILON,
            "expected 45.0 sat/vB, got {rate3}"
        );
    }
}
