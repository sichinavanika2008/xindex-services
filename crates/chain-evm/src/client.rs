//! [`EvmChainClient`] trait + production [`AlloyEvmChainClient`] impl.
//!
//! The trait is the abstraction every Phase 3.2 consumer programs
//! against (V6 cross-check policies, V7 executor). Implementations:
//!
//! - Production: [`AlloyEvmChainClient`] backed by `alloy` over WS.
//!   Multi-RPC fallover at construction is the binary's responsibility
//!   (see chain-eth's `WsEndpointList` for the same-shape pattern).
//! - Tests: in-memory fakes (one per consumer crate's test fixture).
//!
//! ## Type surface
//!
//! Public types ([`EvmLogEntry`], [`EvmLogFilter`], [`EvmConfirmedReceipt`],
//! [`EvmTransactionSummary`]) are decoupled from `alloy`'s wire types so
//! consumers can use plain bytes without dragging in the alloy provider
//! stack. The production client converts at the boundary; tests build
//! these structs directly.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{sol, SolCall};
use thiserror::Error;
use xindex_shared::chain_registry::{ChainId, EvmTxType};

/// Logs filter — chain-evm's wire-level equivalent of `alloy`'s
/// `Filter`. `from_block` / `to_block` are absolute block numbers
/// (callers compute via `tip - lookback`).
#[derive(Debug, Clone, Default)]
pub struct EvmLogFilter {
    /// Inclusive start block (`None` = earliest known).
    pub from_block: Option<u64>,
    /// Inclusive end block (`None` = latest).
    pub to_block: Option<u64>,
    /// Contract `address` we expect the event from. `None` = any.
    pub address: Option<Address>,
    /// `topic0` event-signature hash; further topics tested in `topics_1_3`.
    pub topic0: Option<B256>,
    /// Optional further-topic filters. `None` at any index = wildcard.
    pub topics_1_3: [Option<B256>; 3],
}

/// One decoded log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmLogEntry {
    /// Emitting contract.
    pub address: Address,
    /// All topics in order — `topic0` is the event-signature hash for
    /// non-anonymous events; further topics are indexed args.
    pub topics: Vec<B256>,
    /// Non-indexed args, ABI-encoded as one tightly-packed byte string.
    pub data: Bytes,
    /// Block height the log was mined into.
    pub block_number: u64,
    /// Tx-hash within that block.
    pub transaction_hash: B256,
    /// Index of this log within the block. Together with `transaction_hash`
    /// it identifies a physical log uniquely (RUST-004 consumed-inflow ledger).
    pub log_index: u64,
}

/// Confirmed-receipt subset chain-evm consumers care about. Smaller
/// than alloy's `TransactionReceipt`, which carries dozens of fields
/// the executor / cross-check never reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmConfirmedReceipt {
    /// Tx-hash of the submitted transaction.
    pub transaction_hash: B256,
    /// Block height the tx was mined into.
    pub block_number: u64,
    /// `true` = `status == 1`; `false` = revert. The executor refuses
    /// to record a successful redeem dispatch if `status == false`.
    pub success: bool,
    /// Logs emitted by the tx, in receipt order.
    pub logs: Vec<EvmLogEntry>,
}

/// Transaction summary returned by `eth_getTransactionByHash`. None of
/// the gas / fee fields are exposed — V7 builds + signs txs externally
/// and only consults this surface to verify a tx exists / read its
/// sender (= the Safe address for a delivered redeem).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmTransactionSummary {
    /// Hash.
    pub hash: B256,
    /// `from` (signer).
    pub from: Address,
    /// `to` (recipient — `None` for contract creation, never expected
    /// in the Safe-flow).
    pub to: Option<Address>,
    /// `value` in wei.
    pub value: U256,
    /// Block height (`None` = pending).
    pub block_number: Option<u64>,
}

/// Errors surfaced by every [`EvmChainClient`] method.
#[derive(Debug, Error)]
pub enum EvmChainError {
    /// Transport / JSON-RPC failure. Message is whatever the underlying
    /// stack (alloy + reqwest + tungstenite) produced — we don't try to
    /// recover a stable error code.
    #[error("RPC error: {0}")]
    Rpc(String),

    /// `eth_call` against a Safe address returned bytes we couldn't
    /// decode (wrong contract at the address, or the contract reverted
    /// and the node returned the empty string).
    #[error("decode error: {0}")]
    Decode(String),

    /// `wait_for_confirmations` exceeded the per-call timeout without
    /// reaching the required confirmation depth. Tx may still confirm
    /// later; the caller should requery before declaring it failed.
    #[error("timed out waiting for {depth} confirmations of {tx_hash} after {elapsed:?}")]
    ConfirmationTimeout {
        /// The hash that didn't confirm in time.
        tx_hash: B256,
        /// The depth that wasn't reached.
        depth: u32,
        /// How long the call waited.
        elapsed: Duration,
    },

    /// A submitted transaction reverted on-chain (`status == 0`). The
    /// caller should treat this as a permanent failure for the redeem
    /// leg — Safe txs revert when sig threshold isn't met or when the
    /// inner call reverts.
    #[error("transaction reverted: {tx_hash}")]
    TransactionReverted {
        /// The reverted tx-hash.
        tx_hash: B256,
    },
}

/// Per-(destination-chain) RPC primitives. Implementations are
/// constructed once per chain (production: one [`AlloyEvmChainClient`]
/// per chain the executor / signer is configured for).
///
/// Returns `impl Future<...> + Send` rather than `async fn` so the
/// futures are `Send`-bound at the trait level — V6 / V7 spawn them
/// onto tokio's multi-thread runtime.
pub trait EvmChainClient: Send + Sync + 'static {
    /// Which Phase 3.2 chain this client targets.
    fn chain(&self) -> ChainId;

    /// EVM `chain_id` (`1`, `56`, `43_114`, `8_453`, `137`). Pinned in
    /// the registry; the client surfaces it for tx-signing convenience
    /// (callers building EIP-155-bound signed bytes).
    fn evm_chain_id(&self) -> u64;

    /// Tx envelope to build per chain — EIP-1559 except BSC (DL-P3.2-4).
    fn tx_type(&self) -> EvmTxType;

    /// Current chain-tip block number. Used by cross-check policies
    /// (V6) to compute confirmation depth from a log's `block_number`.
    fn block_number(&self) -> impl Future<Output = Result<u64, EvmChainError>> + Send;

    /// Read the Safe contract's monotonic `nonce()` via `eth_call`.
    /// Returns the value the NEXT successful `execTransaction` will
    /// consume. Callers MUST hold a per-Safe lock (V7's
    /// `SQLite` advisory lock) around `safe_nonce → build → submit` to
    /// avoid concurrent legs colliding.
    fn safe_nonce(&self, safe: Address) -> impl Future<Output = Result<u64, EvmChainError>> + Send;

    /// Generic `eth_call`. Used by V6 cross-checks that need to query
    /// contract state beyond what `eth_get_logs` exposes.
    fn eth_call(
        &self,
        to: Address,
        data: Bytes,
    ) -> impl Future<Output = Result<Bytes, EvmChainError>> + Send;

    /// Fetch a transaction summary by hash. `None` = unknown or
    /// pre-mempool. The Safe-flow consumer never expects pending here
    /// — V6 only queries hashes the executor recorded post-confirmation.
    fn eth_get_transaction_by_hash(
        &self,
        hash: B256,
    ) -> impl Future<Output = Result<Option<EvmTransactionSummary>, EvmChainError>> + Send;

    /// `eth_getLogs` against a filter. Used by V6 to find the ERC20
    /// `Transfer` log of the THORChain-delivered native asset into the
    /// Safe address, and by V7 to scan dispatch confirmations.
    fn eth_get_logs(
        &self,
        filter: EvmLogFilter,
    ) -> impl Future<Output = Result<Vec<EvmLogEntry>, EvmChainError>> + Send;

    /// Submit a pre-signed raw transaction. Returns the tx-hash the
    /// node computed; the executor records this hash in the broadcast
    /// registry before returning.
    fn submit_raw(&self, raw: Bytes) -> impl Future<Output = Result<B256, EvmChainError>> + Send;

    /// Block until `hash` reaches `depth` confirmations. Returns
    /// [`EvmChainError::ConfirmationTimeout`] when `timeout` elapses
    /// first; returns [`EvmChainError::TransactionReverted`] if the tx
    /// is confirmed but its status is `0`. Successful return ⇒ the
    /// receipt is at least `depth` blocks deep at the latest tip.
    fn wait_for_confirmations(
        &self,
        hash: B256,
        depth: u32,
        timeout: Duration,
    ) -> impl Future<Output = Result<EvmConfirmedReceipt, EvmChainError>> + Send;
}

// ─── `Safe.nonce()` ABI ─────────────────────────────────────────────────────

sol! {
    /// Safe v1.4.1 `nonce()` view selector (`0xaffed0e0`).
    function nonce() external view returns (uint256);
}

/// Encode the calldata for `Safe.nonce()`. The 4-byte selector is
/// `0xaffed0e0`; zero args.
#[must_use]
pub fn encode_safe_nonce_call() -> Bytes {
    Bytes::from(nonceCall {}.abi_encode())
}

/// Decode the 32-byte return value of `Safe.nonce()` into a `u64`.
/// Safe's nonce starts at 0 and increments by 1 per `execTransaction`;
/// it cannot exceed `u64::MAX` in any realistic horizon (one tx per
/// second forever = 584 billion years). A return value that overflows
/// `u64` is therefore a node returning gibberish — surface as decode
/// error, don't truncate.
///
/// # Errors
/// [`EvmChainError::Decode`] if the value doesn't fit in `u64` or the
/// input length is wrong.
pub fn decode_safe_nonce_return(bytes: &[u8]) -> Result<u64, EvmChainError> {
    if bytes.len() != 32 {
        return Err(EvmChainError::Decode(format!(
            "expected 32-byte nonce return, got {}",
            bytes.len()
        )));
    }
    let value = U256::from_be_slice(bytes);
    u64::try_from(value).map_err(|_| {
        EvmChainError::Decode(format!(
            "Safe nonce {value} overflows u64 — node misreporting"
        ))
    })
}

// ─── Production alloy-backed impl ───────────────────────────────────────────

/// Production [`EvmChainClient`] backed by alloy's WS provider.
///
/// The binary callsite constructs an `alloy` provider (typically via
/// `ProviderBuilder` + WS), wraps it with [`AlloyEvmChainClient::new`],
/// and shares the result across the executor / cross-check layers.
/// Multi-RPC fallover at connect time is the binary's concern (see
/// `chain-eth::WsEndpointList` for the same-shape primitive).
pub struct AlloyEvmChainClient<P>
where
    P: alloy::providers::Provider + Send + Sync + 'static,
{
    chain: ChainId,
    evm_chain_id: u64,
    tx_type: EvmTxType,
    provider: Arc<P>,
}

impl<P> std::fmt::Debug for AlloyEvmChainClient<P>
where
    P: alloy::providers::Provider + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlloyEvmChainClient")
            .field("chain", &self.chain)
            .field("evm_chain_id", &self.evm_chain_id)
            .field("tx_type", &self.tx_type)
            .finish_non_exhaustive()
    }
}

impl<P> AlloyEvmChainClient<P>
where
    P: alloy::providers::Provider + Send + Sync + 'static,
{
    /// Wrap an already-constructed alloy provider. Binary callers
    /// build the provider via `ProviderBuilder` (with multi-RPC
    /// fallover at construction); this constructor takes ownership and
    /// pairs it with the chain identity.
    ///
    /// # Errors
    /// Returns [`EvmChainError::Decode`] if `chain` is not in the EVM
    /// custody family.
    pub fn new(chain: ChainId, provider: Arc<P>) -> Result<Self, EvmChainError> {
        let evm_chain_id = chain.evm_chain_id().ok_or_else(|| {
            EvmChainError::Decode(format!(
                "ChainId::{chain:?} is not in the EVM custody family"
            ))
        })?;
        let tx_type = chain.tx_type().ok_or_else(|| {
            EvmChainError::Decode(format!(
                "ChainId::{chain:?} has no EVM tx_type — not in the EVM family"
            ))
        })?;
        Ok(Self {
            chain,
            evm_chain_id,
            tx_type,
            provider,
        })
    }

    /// Borrow the wrapped provider — useful for tests and any callsite
    /// that needs an alloy primitive not exposed via the trait.
    #[must_use]
    pub fn provider(&self) -> &Arc<P> {
        &self.provider
    }
}

impl<P> EvmChainClient for AlloyEvmChainClient<P>
where
    P: alloy::providers::Provider + Send + Sync + 'static,
{
    fn chain(&self) -> ChainId {
        self.chain
    }

    fn evm_chain_id(&self) -> u64 {
        self.evm_chain_id
    }

    fn tx_type(&self) -> EvmTxType {
        self.tx_type
    }

    async fn block_number(&self) -> Result<u64, EvmChainError> {
        self.provider
            .get_block_number()
            .await
            .map_err(|e| EvmChainError::Rpc(format!("get_block_number: {e}")))
    }

    async fn safe_nonce(&self, safe: Address) -> Result<u64, EvmChainError> {
        let calldata = encode_safe_nonce_call();
        let bytes = self.eth_call(safe, calldata).await?;
        decode_safe_nonce_return(&bytes)
    }

    async fn eth_call(&self, to: Address, data: Bytes) -> Result<Bytes, EvmChainError> {
        use alloy::rpc::types::TransactionRequest;
        let req = TransactionRequest::default().to(to).input(data.into());
        self.provider
            .call(&req)
            .await
            .map_err(|e| EvmChainError::Rpc(format!("eth_call: {e}")))
    }

    async fn eth_get_transaction_by_hash(
        &self,
        hash: B256,
    ) -> Result<Option<EvmTransactionSummary>, EvmChainError> {
        use alloy::consensus::Transaction as _;
        let tx = self
            .provider
            .get_transaction_by_hash(hash)
            .await
            .map_err(|e| EvmChainError::Rpc(format!("get_transaction_by_hash: {e}")))?;
        Ok(tx.map(|t| EvmTransactionSummary {
            hash: *t.inner.tx_hash(),
            from: t.from,
            to: t.to(),
            value: t.value(),
            block_number: t.block_number,
        }))
    }

    async fn eth_get_logs(&self, filter: EvmLogFilter) -> Result<Vec<EvmLogEntry>, EvmChainError> {
        use alloy::rpc::types::Filter;
        let mut f = Filter::new();
        if let Some(from) = filter.from_block {
            f = f.from_block(from);
        }
        if let Some(to) = filter.to_block {
            f = f.to_block(to);
        }
        if let Some(addr) = filter.address {
            f = f.address(addr);
        }
        // Topic0 (event signature) — `Filter::event_signature` is the
        // alloy 0.8 API for filtering `topic[0]`.
        if let Some(t0) = filter.topic0 {
            f = f.event_signature(t0);
        }
        // Further topics — alloy `topic1` / `topic2` / `topic3` setters.
        if let Some(t1) = filter.topics_1_3[0] {
            f = f.topic1(t1);
        }
        if let Some(t2) = filter.topics_1_3[1] {
            f = f.topic2(t2);
        }
        if let Some(t3) = filter.topics_1_3[2] {
            f = f.topic3(t3);
        }
        let logs = self
            .provider
            .get_logs(&f)
            .await
            .map_err(|e| EvmChainError::Rpc(format!("get_logs: {e}")))?;
        Ok(logs
            .into_iter()
            .map(|l| EvmLogEntry {
                address: l.inner.address,
                topics: l.inner.topics().to_vec(),
                data: l.inner.data.data.clone(),
                block_number: l.block_number.unwrap_or(0),
                transaction_hash: l.transaction_hash.unwrap_or(B256::ZERO),
                log_index: l.log_index.unwrap_or(0),
            })
            .collect())
    }

    async fn submit_raw(&self, raw: Bytes) -> Result<B256, EvmChainError> {
        let pending = self
            .provider
            .send_raw_transaction(&raw)
            .await
            .map_err(|e| EvmChainError::Rpc(format!("send_raw_transaction: {e}")))?;
        Ok(*pending.tx_hash())
    }

    async fn wait_for_confirmations(
        &self,
        hash: B256,
        depth: u32,
        timeout: Duration,
    ) -> Result<EvmConfirmedReceipt, EvmChainError> {
        let start = std::time::Instant::now();
        loop {
            // Poll receipt; once it exists, poll the tip until we have
            // `depth` confirmations.
            let maybe = self
                .provider
                .get_transaction_receipt(hash)
                .await
                .map_err(|e| EvmChainError::Rpc(format!("get_transaction_receipt: {e}")))?;
            if let Some(receipt) = maybe {
                let receipt_block = receipt.block_number.unwrap_or(0);
                if !receipt.status() {
                    return Err(EvmChainError::TransactionReverted { tx_hash: hash });
                }
                let tip = self
                    .provider
                    .get_block_number()
                    .await
                    .map_err(|e| EvmChainError::Rpc(format!("get_block_number: {e}")))?;
                let confirmations =
                    u32::try_from(tip.saturating_sub(receipt_block).saturating_add(1))
                        .unwrap_or(u32::MAX);
                if confirmations >= depth {
                    return Ok(EvmConfirmedReceipt {
                        transaction_hash: hash,
                        block_number: receipt_block,
                        success: true,
                        logs: receipt
                            .inner
                            .logs()
                            .iter()
                            .map(|l| EvmLogEntry {
                                address: l.inner.address,
                                topics: l.inner.topics().to_vec(),
                                data: l.inner.data.data.clone(),
                                block_number: l.block_number.unwrap_or(0),
                                transaction_hash: l.transaction_hash.unwrap_or(B256::ZERO),
                                log_index: l.log_index.unwrap_or(0),
                            })
                            .collect(),
                    });
                }
            }
            if start.elapsed() >= timeout {
                return Err(EvmChainError::ConfirmationTimeout {
                    tx_hash: hash,
                    depth,
                    elapsed: start.elapsed(),
                });
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Safe.nonce()` selector is `0xaffed0e0`. Pinned against the
    /// Safe v1.4.1 ABI.
    #[test]
    fn safe_nonce_selector_pinned() {
        let calldata = encode_safe_nonce_call();
        assert_eq!(calldata.len(), 4, "nonce() takes no args");
        assert_eq!(&calldata[..], &[0xaf, 0xfe, 0xd0, 0xe0]);
    }

    /// Decodes a 32-byte big-endian return value as the Safe's nonce.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn decode_safe_nonce_returns_u64() {
        let mut buf = [0u8; 32];
        buf[31] = 42;
        let n = decode_safe_nonce_return(&buf).expect("decode 42");
        assert_eq!(n, 42);

        // Large but-still-u64 value.
        buf[24..].copy_from_slice(&u64::MAX.to_be_bytes());
        let big = decode_safe_nonce_return(&buf).expect("decode u64::MAX");
        assert_eq!(big, u64::MAX);
    }

    /// Wrong-length input is a decode error (defends against an alloy
    /// `eth_call` returning empty bytes when the Safe address doesn't
    /// hold a contract).
    #[test]
    fn decode_safe_nonce_rejects_wrong_length() {
        assert!(matches!(
            decode_safe_nonce_return(&[]),
            Err(EvmChainError::Decode(_))
        ));
        assert!(matches!(
            decode_safe_nonce_return(&[0u8; 16]),
            Err(EvmChainError::Decode(_))
        ));
        assert!(matches!(
            decode_safe_nonce_return(&[0u8; 64]),
            Err(EvmChainError::Decode(_))
        ));
    }

    /// A nonce that overflows `u64` is an error, not silent truncation.
    /// In practice unreachable — Safe's monotonic increment can't reach
    /// `u64::MAX` in human time — but a node returning gibberish would
    /// otherwise corrupt the executor's idea of the current nonce.
    #[test]
    fn decode_safe_nonce_rejects_overflow() {
        let mut buf = [0u8; 32];
        buf[0] = 1; // value = 2^248 > u64::MAX
        assert!(matches!(
            decode_safe_nonce_return(&buf),
            Err(EvmChainError::Decode(_))
        ));
    }
}
