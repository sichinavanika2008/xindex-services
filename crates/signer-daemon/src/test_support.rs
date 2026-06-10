//! Test-only [`ReplayStore`] wrapper that simulates the audit-L10 write
//! race: the handler's pre-flight `check_*` observes `FirstTime`, signs,
//! then loses the `record_*` race to a concurrent identical request that
//! already committed the winning row. The wrapper makes the loser's
//! `record_*` return [`ReplayError::Duplicate`] and the inner store hold
//! the winner's row, so the handler's L10 recovery re-check resolves to
//! `Idempotent` and returns the cached signature (HTTP 200) — never a
//! spurious 4xx/5xx.

use std::sync::atomic::{AtomicBool, Ordering};

use alloy_primitives::{B256, U256};

use crate::replay::{
    CheckOutcome, RedemptionCheckOutcome, RedemptionKind, ReplayError, ReplayStore,
};

/// Which signing path the race is simulated on. Every OTHER method
/// delegates verbatim to the inner store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RacePath {
    /// Force the race on `(check|record)_psbt_input`.
    PsbtInput,
    /// Force the race on `(check|record)_attestation`.
    Attestation,
}

/// Wraps an [`InMemoryReplayStore`](crate::replay::InMemoryReplayStore)
/// (any [`ReplayStore`]) and forces the L10 write race on `path`.
#[derive(Debug)]
pub struct RaceReplayStore<S: ReplayStore> {
    inner: S,
    path: RacePath,
    /// `false` until the handler's pre-flight `check_*` for `path` has run
    /// once. The first call returns `FirstTime`; later calls (the L10
    /// recovery re-check) delegate to the inner store, which already holds
    /// the winner's row.
    first_check_done: AtomicBool,
}

impl<S: ReplayStore> RaceReplayStore<S> {
    /// `inner` must ALREADY hold the winning row for the tuple under test
    /// (record it via `inner` before wrapping).
    pub fn new(inner: S, path: RacePath) -> Self {
        Self {
            inner,
            path,
            first_check_done: AtomicBool::new(false),
        }
    }

    /// `true` once the first pre-flight `check_*` on `path` has returned
    /// `FirstTime` (so the handler proceeds to sign + race on `record_*`).
    fn take_first_check(&self) -> bool {
        !self.first_check_done.swap(true, Ordering::SeqCst)
    }
}

impl<S: ReplayStore> ReplayStore for RaceReplayStore<S> {
    async fn check_attestation(
        &self,
        intent_id: B256,
        slot_index: U256,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        if self.path == RacePath::Attestation && self.take_first_check() {
            return Ok(CheckOutcome::FirstTime);
        }
        self.inner
            .check_attestation(intent_id, slot_index, payload_hash)
            .await
    }

    async fn record_attestation(
        &self,
        intent_id: B256,
        slot_index: U256,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        if self.path == RacePath::Attestation {
            return Err(ReplayError::Duplicate);
        }
        self.inner
            .record_attestation(intent_id, slot_index, payload_hash, signature, now_unix)
            .await
    }

    async fn check_redemption(
        &self,
        redemption_id: B256,
        leg_index: u32,
        kind: RedemptionKind,
        payload_hash: [u8; 32],
    ) -> Result<RedemptionCheckOutcome, ReplayError> {
        self.inner
            .check_redemption(redemption_id, leg_index, kind, payload_hash)
            .await
    }

    async fn record_redemption(
        &self,
        redemption_id: B256,
        leg_index: u32,
        kind: RedemptionKind,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        self.inner
            .record_redemption(
                redemption_id,
                leg_index,
                kind,
                payload_hash,
                signature,
                now_unix,
            )
            .await
    }

    async fn check_psbt_input(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        input_txid: [u8; 32],
        input_vout: u32,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        if self.path == RacePath::PsbtInput && self.take_first_check() {
            return Ok(CheckOutcome::FirstTime);
        }
        self.inner
            .check_psbt_input(chain_id, input_txid, input_vout, payload_hash)
            .await
    }

    async fn record_psbt_input(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        input_txid: [u8; 32],
        input_vout: u32,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        if self.path == RacePath::PsbtInput {
            return Err(ReplayError::Duplicate);
        }
        self.inner
            .record_psbt_input(
                chain_id,
                input_txid,
                input_vout,
                payload_hash,
                signature,
                now_unix,
            )
            .await
    }

    async fn check_solana_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        multisig: String,
        transaction_index: u64,
        kind: &'static str,
        member: String,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        self.inner
            .check_solana_tx(
                chain_id,
                multisig,
                transaction_index,
                kind,
                member,
                payload_hash,
            )
            .await
    }

    async fn record_solana_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        multisig: String,
        transaction_index: u64,
        kind: &'static str,
        member: String,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        self.inner
            .record_solana_tx(
                chain_id,
                multisig,
                transaction_index,
                kind,
                member,
                payload_hash,
                signature,
                now_unix,
            )
            .await
    }

    async fn check_safe_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        safe_address: alloy_primitives::Address,
        nonce: u64,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        self.inner
            .check_safe_tx(chain_id, safe_address, nonce, payload_hash)
            .await
    }

    async fn record_safe_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        safe_address: alloy_primitives::Address,
        nonce: u64,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        self.inner
            .record_safe_tx(
                chain_id,
                safe_address,
                nonce,
                payload_hash,
                signature,
                now_unix,
            )
            .await
    }

    async fn check_cosmos_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        self.inner
            .check_cosmos_tx(chain_id, account_address, sequence, payload_hash)
            .await
    }

    async fn record_cosmos_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        self.inner
            .record_cosmos_tx(
                chain_id,
                account_address,
                sequence,
                payload_hash,
                signature,
                now_unix,
            )
            .await
    }

    async fn check_xrp_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        self.inner
            .check_xrp_tx(chain_id, account_address, sequence, payload_hash)
            .await
    }

    async fn record_xrp_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        account_address: String,
        sequence: u64,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        self.inner
            .record_xrp_tx(
                chain_id,
                account_address,
                sequence,
                payload_hash,
                signature,
                now_unix,
            )
            .await
    }

    async fn check_tron_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        owner_address: String,
        txid: [u8; 32],
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        self.inner
            .check_tron_tx(chain_id, owner_address, txid, payload_hash)
            .await
    }

    async fn record_tron_tx(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        owner_address: String,
        txid: [u8; 32],
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        self.inner
            .record_tron_tx(
                chain_id,
                owner_address,
                txid,
                payload_hash,
                signature,
                now_unix,
            )
            .await
    }

    async fn check_ric_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        self.inner
            .check_ric_intent(chain_id, redemption_id, leg_index, payload_hash)
            .await
    }

    async fn record_ric_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        self.inner
            .record_ric_intent(
                chain_id,
                redemption_id,
                leg_index,
                payload_hash,
                signature,
                now_unix,
            )
            .await
    }

    async fn check_ric_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        self.inner
            .check_ric_cert(chain_id, redemption_id, leg_index, payload_hash)
            .await
    }

    async fn record_ric_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        redemption_id: B256,
        leg_index: u32,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        self.inner
            .record_ric_cert(
                chain_id,
                redemption_id,
                leg_index,
                payload_hash,
                signature,
                now_unix,
            )
            .await
    }
}
