//! Bind-prepare side-channel.
//!
//! Because the Fireblocks RAW-signing `tx_sign_request` carries only a hash
//! to sign (TAP cannot see destination/amount/memo), the executor stores the
//! unsigned PSBT + its k-of-n certificate here BEFORE submitting to Fireblocks,
//! keyed by a correlation id it echoes through as the Fireblocks `externalTxId`.
//! The callback retrieves the prepared context by that id and binds the spend;
//! a missing context is a fail-closed REJECT.
//!
//! In-memory here (dev/test); the production store mirrors the sqlite
//! [`xindex_custody_core::replay`] shape and lands with the Slice-0 wire adapter.

use std::collections::HashMap;

use alloy_primitives::B256;
use bitcoin::psbt::Psbt;
use tokio::sync::Mutex;
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{AcquireCancelProof, IntentProof};

/// The unsigned spend + its authorizing certificate, stored at prepare time.
#[derive(Debug, Clone)]
pub struct BindContext {
    /// Custody chain of the spend.
    pub chain: ChainId,
    /// The unsigned PSBT the executor will submit to Fireblocks.
    pub psbt: Psbt,
    /// The k-of-n RIC authorizing a redeem spend (XOR [`Self::acc`]).
    pub ric: Option<IntentProof>,
    /// The k-of-n ACC authorizing a mint-cancel swap-back (XOR [`Self::ric`]).
    pub acc: Option<AcquireCancelProof>,
}

/// In-memory bind-context store (dev/test). Production mirrors the sqlite
/// `ReplayStore` shape and lands with the Slice-0 wire adapter.
#[derive(Debug, Default)]
pub struct InMemoryPrepareStore {
    inner: Mutex<HashMap<B256, BindContext>>,
}

impl InMemoryPrepareStore {
    /// A fresh, empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store `ctx` under `correlation_id` (overwrites a prior prepare).
    pub async fn put(&self, correlation_id: B256, ctx: BindContext) {
        self.inner.lock().await.insert(correlation_id, ctx);
    }

    /// Retrieve the prepared context (cloned), or `None` if absent — the
    /// callback fail-closes to REJECT on `None`.
    pub async fn get(&self, correlation_id: B256) -> Option<BindContext> {
        self.inner.lock().await.get(&correlation_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute::LockTime, transaction::Version, Transaction};

    fn empty_psbt() -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        #[expect(clippy::expect_used, reason = "test code")]
        Psbt::from_unsigned_tx(tx).expect("unsigned psbt")
    }

    #[tokio::test]
    async fn put_then_get_roundtrips() {
        let store = InMemoryPrepareStore::new();
        let id = B256::repeat_byte(0x7);
        store
            .put(
                id,
                BindContext { chain: ChainId::Btc, psbt: empty_psbt(), ric: None, acc: None },
            )
            .await;
        let got = store.get(id).await;
        assert!(got.is_some());
        assert_eq!(got.map(|c| c.chain), Some(ChainId::Btc));
    }

    #[tokio::test]
    async fn missing_context_is_none() {
        let store = InMemoryPrepareStore::new();
        assert!(store.get(B256::repeat_byte(0x9)).await.is_none());
    }
}
