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
    CheckOutcome, RedemptionCheckOutcome, RedemptionKind, ReplayError, ReplayStore, VolumeOutcome,
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

    async fn check_ac_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        self.inner
            .check_ac_intent(chain_id, cancel_id, payload_hash)
            .await
    }

    async fn record_ac_intent(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        self.inner
            .record_ac_intent(chain_id, cancel_id, payload_hash, signature, now_unix)
            .await
    }

    async fn check_ac_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
    ) -> Result<CheckOutcome, ReplayError> {
        self.inner
            .check_ac_cert(chain_id, cancel_id, payload_hash)
            .await
    }

    async fn record_ac_cert(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        cancel_id: B256,
        payload_hash: [u8; 32],
        signature: Vec<u8>,
        now_unix: i64,
    ) -> Result<(), ReplayError> {
        self.inner
            .record_ac_cert(chain_id, cancel_id, payload_hash, signature, now_unix)
            .await
    }

    async fn consume_cert_volume(
        &self,
        chain_id: xindex_shared::chain_registry::ChainId,
        window_start: i64,
        amount: u128,
        cap: u128,
    ) -> Result<VolumeOutcome, ReplayError> {
        self.inner
            .consume_cert_volume(chain_id, window_start, amount, cap)
            .await
    }
}

/// CTD-1 (`DL-CTD-2`) test fixtures: a deterministic 3-member Set-B
/// whose addresses form every test daemon's `intent_policy` whitelist,
/// plus a builder that signs a Redemption Intent Certificate exactly
/// the way the per-operator observers will (Slice B): asset id +
/// decimals from the chain registry, target/memo hashes = keccak of
/// the raw bytes, `vault_resolved_at` = now.
pub mod ric {
    use alloy_primitives::{keccak256, Address, B256, U256};
    use k256::ecdsa::SigningKey;
    use xindex_shared::chain_registry::ChainId;
    use xindex_shared::eip712::{
        attestation_oracle_domain, redemption_intent_certificate, ric_signing_hash,
    };
    use xindex_shared::signer_wire::{AcquireCancelProof, IntentProof};

    use crate::intent::IntentPolicy;

    /// Deterministic Set-B test keys (seeds 41/42/43) → (key, EOA).
    #[expect(clippy::expect_used, reason = "test code")]
    pub fn set_b_keys() -> Vec<(SigningKey, Address)> {
        [41u8, 42, 43]
            .iter()
            .map(|seed| {
                let sk = SigningKey::from_slice(&[*seed; 32]).expect("key");
                let vk = sk.verifying_key();
                let uncompressed = vk.to_encoded_point(false);
                let hash = keccak256(&uncompressed.as_bytes()[1..]);
                let addr = Address::from_slice(&hash[12..]);
                (sk, addr)
            })
            .collect()
    }

    /// 2-of-3 test policy over [`set_b_keys`].
    pub fn policy() -> IntentPolicy {
        IntentPolicy {
            signer_whitelist: set_b_keys().into_iter().map(|(_, a)| a).collect(),
            intent_quorum: 2,
            ric_max_age_secs: 3_600,
        }
    }

    /// The certified fields of one test leg. `immediate_target` and
    /// `memo` are the RAW bytes the family hashes (BTC: scriptPubKey
    /// bytes / memo bytes; EVM: the 20-byte Asgard vault address;
    /// account families: the canonical address / memo strings as
    /// UTF-8).
    #[derive(Debug, Clone)]
    pub struct CertSpec {
        pub chain: ChainId,
        pub redemption_id: B256,
        pub leg_index: u32,
        pub amount: U256,
        pub immediate_target: Vec<u8>,
        pub memo: Vec<u8>,
    }

    /// Build + quorum-sign an [`IntentProof`] over `spec`.
    #[expect(clippy::expect_used, reason = "test code")]
    pub fn proof_for(
        eth_chain_id: u64,
        verifying_contract: Address,
        spec: &CertSpec,
    ) -> IntentProof {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let immediate_target_hash = keccak256(&spec.immediate_target);
        let memo_hash = keccak256(&spec.memo);
        let final_destination_hash = B256::repeat_byte(0x12);
        let ric = redemption_intent_certificate(
            spec.redemption_id,
            U256::from(spec.leg_index),
            spec.chain.asset_id_hash(),
            spec.amount,
            spec.chain.decimals(),
            immediate_target_hash,
            memo_hash,
            final_destination_hash,
            now,
        );
        let digest = ric_signing_hash(
            &ric,
            &attestation_oracle_domain(eth_chain_id, verifying_contract),
        );
        let signatures = set_b_keys()
            .iter()
            .take(2)
            .map(|(sk, _)| {
                let (sig, recid) = sk
                    .sign_prehash_recoverable(digest.as_slice())
                    .expect("sign");
                let mut out = [0u8; 65];
                out[..64].copy_from_slice(sig.to_bytes().as_ref());
                out[64] = 27 + recid.to_byte();
                format!("0x{}", alloy_primitives::hex::encode(out))
            })
            .collect();
        IntentProof {
            redemption_id: format!("{:#x}", spec.redemption_id),
            leg_index: spec.leg_index.to_string(),
            asset_id: format!("{:#x}", spec.chain.asset_id_hash()),
            amount: spec.amount.to_string(),
            amount_decimals: spec.chain.decimals(),
            immediate_target_hash: format!("{immediate_target_hash:#x}"),
            memo_hash: format!("{memo_hash:#x}"),
            final_destination_hash: format!("{final_destination_hash:#x}"),
            vault_resolved_at: now,
            signatures,
        }
    }

    /// CTD-1 Slice C: the certified fields of one test mint-cancel
    /// swap-back. Same raw-bytes conventions as [`CertSpec`].
    #[derive(Debug, Clone)]
    pub struct AccSpec {
        pub chain: ChainId,
        pub cancel_id: B256,
        pub intent_id: B256,
        pub slot_index: u32,
        pub amount: U256,
        pub immediate_target: Vec<u8>,
        pub memo: Vec<u8>,
    }

    /// Build + quorum-sign an [`AcquireCancelProof`] over `spec` with
    /// the SAME deterministic Set-B trio — mirrors [`proof_for`] for
    /// the Acquire-Cancel sibling certificate.
    #[expect(clippy::expect_used, reason = "test code")]
    pub fn acc_proof_for(
        eth_chain_id: u64,
        verifying_contract: Address,
        spec: &AccSpec,
    ) -> AcquireCancelProof {
        use xindex_shared::eip712::{acquire_cancel_certificate, acquire_cancel_signing_hash};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let immediate_target_hash = keccak256(&spec.immediate_target);
        let memo_hash = keccak256(&spec.memo);
        let final_destination_hash = B256::repeat_byte(0x12);
        let acc = acquire_cancel_certificate(
            spec.cancel_id,
            spec.intent_id,
            U256::from(spec.slot_index),
            spec.chain.asset_id_hash(),
            spec.amount,
            spec.chain.decimals(),
            immediate_target_hash,
            memo_hash,
            final_destination_hash,
            now,
        );
        let digest = acquire_cancel_signing_hash(
            &acc,
            &attestation_oracle_domain(eth_chain_id, verifying_contract),
        );
        let signatures = set_b_keys()
            .iter()
            .take(2)
            .map(|(sk, _)| {
                let (sig, recid) = sk
                    .sign_prehash_recoverable(digest.as_slice())
                    .expect("sign");
                let mut out = [0u8; 65];
                out[..64].copy_from_slice(sig.to_bytes().as_ref());
                out[64] = 27 + recid.to_byte();
                format!("0x{}", alloy_primitives::hex::encode(out))
            })
            .collect();
        AcquireCancelProof {
            cancel_id: format!("{:#x}", spec.cancel_id),
            intent_id: format!("{:#x}", spec.intent_id),
            slot_index: spec.slot_index.to_string(),
            asset_id: format!("{:#x}", spec.chain.asset_id_hash()),
            amount: spec.amount.to_string(),
            amount_decimals: spec.chain.decimals(),
            immediate_target_hash: format!("{immediate_target_hash:#x}"),
            memo_hash: format!("{memo_hash:#x}"),
            final_destination_hash: format!("{final_destination_hash:#x}"),
            vault_resolved_at: now,
            signatures,
        }
    }
}
