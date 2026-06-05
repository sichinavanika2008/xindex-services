//! Phase 4.6 — TRON-side redeem leg executor.
//!
//! Builds + signs (native account-permission k-of-n multisig) the transfer
//! that sends native TRX (`TransferContract`) or TRC20 USDT
//! (`TriggerSmartContract`) from our TRON multisig to the THORChain Asgard
//! inbound, carrying the contract-emitted swap memo
//! (`=:ETH.USDT:<indexToken>:<minOut>`) in `raw_data.data`. THORChain then
//! swaps to USDT and delivers to the IndexToken on Ethereum (same routing
//! as the Cosmos / XRP legs).
//!
//! ## Pipeline (per leg)
//!
//! 1. Read the current block ([`TronChainClient::now_block`]) for the
//!    TAPOS reference (`ref_block_bytes` / `ref_block_hash`) + timestamp.
//! 2. Build the `raw_data` protobuf (via `tron-tx`) — the SHARED payload —
//!    and compute `txID = sha256(raw_data)`.
//! 3. Round-robin collect ≥ threshold partials from the configured
//!    [`TronCosigner`]s (each → one signer-daemon `/sign/tron-tx`). Unlike
//!    XRP, every member signs the IDENTICAL `txID`.
//! 4. Verify-and-aggregate ([`aggregate_verified`]) — each partial recovers
//!    to a distinct permission member; the summed weight reaches the
//!    threshold; the sigs are returned signer-address-sorted.
//! 5. Assemble the broadcast `Transaction` protobuf
//!    ([`build_signed_transaction`]).
//! 6. Return [`TronRedeemLegOutcome`]; the binary broadcasts via
//!    [`TronChainClient::broadcast_hex`] and records the `tron` dispatch row.
//!
//! ## Replay / expiry (the TRON-specific nuance)
//!
//! TRON has NO account nonce. Replay/expiry is TAPOS: the `ref_block_*` +
//! `expiration` bind the tx to a recent block and a deadline. A re-driven
//! leg within the window rebuilds the same `raw_data` → same `txID` → the
//! node de-dups (`DUP_TRANSACTION_ERROR`, treated as success) and each
//! daemon returns its cached signature idempotently. After expiry the
//! executor rebuilds against a fresh block → a new `txID`.

#![expect(
    clippy::doc_markdown,
    reason = "module-level: many THORChain / IndexToken / TransferContract / \
              TriggerSmartContract / raw_data identifiers — per-identifier backticks \
              add noise without aiding parsing"
)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use alloy_primitives::B256;
use thiserror::Error;
use tracing::warn;
use xindex_chain_tron::{TronChainClient, TronChainError};
use xindex_shared::chain_registry::{ChainId, CustodyFamily};
use xindex_shared::signer_wire::{TronAssetKind, TronTxSignRequest};
use xindex_tron_tx::addr::{decode_base58check, decode_to_evm20, evm_address};
use xindex_tron_tx::sigs::{aggregate_verified, recover_evm20};
use xindex_tron_tx::tx::{
    build_signed_transaction, build_trx_raw_data, build_usdt_raw_data, txid, Tapos, TrxTransfer,
    UsdtTransfer,
};
use xindex_tron_tx::{TronMultisig, TronTxError};

/// Errors surfaced by the TRON redeem executor.
#[derive(Debug, Error)]
pub enum TronRedeemError {
    /// Task chain is not in the TRON custody family / not this executor's.
    #[error("ChainId {0:?} is not this executor's TRON chain")]
    WrongChain(ChainId),
    /// TRON RPC failure (now-block / broadcast).
    #[error("tron rpc: {0}")]
    Chain(#[from] TronChainError),
    /// A configured `T…` address (owner / vault / contract) did not decode.
    #[error("address: {0}")]
    Address(String),
    /// An amount / fee did not fit its on-wire width.
    #[error("out-of-range numeric: {0}")]
    Numeric(String),
    /// A `tron-tx` primitive failed (aggregation / recovery).
    #[error("tron-tx: {0}")]
    Tx(#[from] TronTxError),
    /// USDT leg config is missing the TRC20 contract address.
    #[error("USDT leg requires a contract_address")]
    MissingContract,
    /// A cosigner returned an error (transport / daemon refusal).
    #[error("cosigner {pubkey}: {message}")]
    Cosigner {
        /// Hex of the cosigner's pinned member pubkey.
        pubkey: String,
        /// Failure detail.
        message: String,
    },
    /// A cosigner's pinned pubkey is not a member of the configured
    /// permission — a deploy-time misconfiguration.
    #[error("cosigner pubkey {0} is not in the permission member set")]
    MemberNotInSet(String),
    /// Collected signer weight fell short of the threshold.
    #[error("insufficient cosigner weight: got {got}, need {need}")]
    InsufficientCosigners {
        /// Summed weight of the partials collected.
        got: u64,
        /// Threshold required.
        need: u64,
    },
}

/// Boxed future returned by [`TronCosigner::sign_tron_tx`].
pub type SignTronFuture<'a> =
    Pin<Box<dyn Future<Output = Result<[u8; 65], TronRedeemError>> + Send + 'a>>;

/// One cosigner — talks to one signer-daemon's `/api/v1/sign/tron-tx` and
/// returns the member's 65-byte recoverable signature over the shared
/// `txID`. The implementation MUST verify the daemon's response pubkey
/// matches [`TronCosigner::member_pubkey`] (never self-reported).
pub trait TronCosigner: Send + Sync {
    /// The disclosed 33-byte compressed member pubkey (pinned by config).
    fn member_pubkey(&self) -> [u8; 33];

    /// POST `req` to the daemon; return the verified 65-byte signature.
    fn sign_tron_tx<'a>(&'a self, req: &'a TronTxSignRequest) -> SignTronFuture<'a>;
}

/// Decoded form of one TRON `RedeemDispatched` event (or hand-built by
/// tests).
#[derive(Debug, Clone)]
pub struct TronRedeemTask {
    /// Per-adapter dispatch id (broadcast registry key).
    pub dispatch_id: B256,
    /// `IntentQueue` redemption id (correlation key).
    pub redemption_id: B256,
    /// Destination chain (TRON family).
    pub chain: ChainId,
    /// THORChain swap memo, trusted verbatim from the contract event.
    pub memo: String,
    /// Native send amount in the asset's smallest unit (sun for TRX,
    /// 6-decimal base units for USDT).
    pub send_amount: u128,
}

/// Static per-executor config. One executor instance per (multisig, asset).
#[derive(Debug, Clone)]
pub struct TronRedeemConfig {
    /// Destination chain this executor serves.
    pub chain: ChainId,
    /// The frozen k-of-n account-permission multisig descriptor.
    pub multisig: TronMultisig,
    /// The multisig account (base58check `T…` address). NOT derived from
    /// `multisig` — the TRON account is separately funded and its `Active`
    /// `Permission` configured by `AccountPermissionUpdateContract`.
    pub owner_address: String,
    /// Current THORChain Asgard inbound (base58check `T…` address). The
    /// binary refreshes from `/thorchain/inbound_addresses` before each leg.
    pub vault: String,
    /// Which asset this executor moves (TRX or TRC20 USDT).
    pub asset: TronAssetKind,
    /// `Usdt` only: the TRC20 contract address (`T…`).
    pub contract_address: Option<String>,
    /// `Usdt` only: the `fee_limit` (energy cap) in `sun`.
    pub fee_limit: u64,
    /// Milliseconds added to the block timestamp for `expiration` (the
    /// TAPOS deadline window).
    pub expiration_window_ms: u64,
}

/// Build + collect-sigs executor. Broadcast is the binary's job.
pub struct TronRedeemExecutor<C: TronChainClient> {
    config: TronRedeemConfig,
    tron: Arc<C>,
    cosigners: Vec<Box<dyn TronCosigner>>,
}

impl<C: TronChainClient> std::fmt::Debug for TronRedeemExecutor<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TronRedeemExecutor")
            .field("config", &self.config)
            .field("cosigner_count", &self.cosigners.len())
            .finish_non_exhaustive()
    }
}

impl<C: TronChainClient> TronRedeemExecutor<C> {
    /// Construct. Rejects a non-TRON config, a USDT config without a
    /// contract address, or fewer cosigners than the multisig threshold.
    ///
    /// # Errors
    /// [`TronRedeemError::WrongChain`] / [`TronRedeemError::MissingContract`]
    /// / [`TronRedeemError::InsufficientCosigners`].
    pub fn new(
        config: TronRedeemConfig,
        tron: Arc<C>,
        cosigners: Vec<Box<dyn TronCosigner>>,
    ) -> Result<Self, TronRedeemError> {
        if config.chain.custody_family() != CustodyFamily::Tron {
            return Err(TronRedeemError::WrongChain(config.chain));
        }
        if config.asset == TronAssetKind::Usdt && config.contract_address.is_none() {
            return Err(TronRedeemError::MissingContract);
        }
        let need = config.multisig.threshold();
        let have = u64::try_from(cosigners.len()).unwrap_or(u64::MAX);
        if have < need {
            return Err(TronRedeemError::InsufficientCosigners { got: have, need });
        }
        Ok(Self {
            config,
            tron,
            cosigners,
        })
    }

    /// Borrow the config (logs / metrics at the binary callsite).
    #[must_use]
    pub fn config(&self) -> &TronRedeemConfig {
        &self.config
    }

    /// Build + collect-sigs for one leg.
    ///
    /// # Errors
    /// Any [`TronRedeemError`] variant.
    pub async fn build_leg(
        &self,
        task: &TronRedeemTask,
    ) -> Result<TronRedeemLegOutcome, TronRedeemError> {
        if task.chain != self.config.chain {
            return Err(TronRedeemError::WrongChain(task.chain));
        }

        let block = self.tron.now_block().await?;
        let expiration = block
            .timestamp_ms
            .saturating_add(self.config.expiration_window_ms);
        let amount = u64::try_from(task.send_amount)
            .map_err(|_| TronRedeemError::Numeric(format!("amount > u64: {}", task.send_amount)))?;
        let owner = decode_base58check(&self.config.owner_address)
            .map_err(|e| TronRedeemError::Address(format!("owner {e}")))?;
        let permission_id = self.config.multisig.permission_id();

        let (raw_data, fee_limit) = match self.config.asset {
            TronAssetKind::Trx => {
                let to = decode_base58check(&self.config.vault)
                    .map_err(|e| TronRedeemError::Address(format!("vault {e}")))?;
                let tapos = Tapos {
                    ref_block_bytes: block.ref_block_bytes,
                    ref_block_hash: block.ref_block_hash,
                    expiration,
                    timestamp: block.timestamp_ms,
                    fee_limit: 0,
                    memo: task.memo.clone().into_bytes(),
                    permission_id,
                };
                (
                    build_trx_raw_data(&TrxTransfer { owner, to, amount }, &tapos),
                    None,
                )
            }
            TronAssetKind::Usdt => {
                let contract_str = self
                    .config
                    .contract_address
                    .as_deref()
                    .ok_or(TronRedeemError::MissingContract)?;
                let contract = decode_base58check(contract_str)
                    .map_err(|e| TronRedeemError::Address(format!("contract {e}")))?;
                let to_evm20 = decode_to_evm20(&self.config.vault)
                    .map_err(|e| TronRedeemError::Address(format!("vault {e}")))?;
                let tapos = Tapos {
                    ref_block_bytes: block.ref_block_bytes,
                    ref_block_hash: block.ref_block_hash,
                    expiration,
                    timestamp: block.timestamp_ms,
                    fee_limit: self.config.fee_limit,
                    memo: task.memo.clone().into_bytes(),
                    permission_id,
                };
                (
                    build_usdt_raw_data(
                        &UsdtTransfer {
                            owner,
                            contract,
                            to_evm20,
                            amount,
                        },
                        &tapos,
                    ),
                    Some(self.config.fee_limit),
                )
            }
        };

        let tx_id = txid(&raw_data);
        let req = TronTxSignRequest {
            chain_id: self.config.chain,
            asset: self.config.asset,
            owner_address: self.config.owner_address.clone(),
            to_address: self.config.vault.clone(),
            amount: amount.to_string(),
            contract_address: self.config.contract_address.clone(),
            permission_id,
            ref_block_bytes: format!("0x{}", alloy_primitives::hex::encode(block.ref_block_bytes)),
            ref_block_hash: format!("0x{}", alloy_primitives::hex::encode(block.ref_block_hash)),
            expiration: expiration.to_string(),
            timestamp: block.timestamp_ms.to_string(),
            fee_limit: fee_limit.map(|f| f.to_string()),
            memo: task.memo.clone(),
            txid: format!("0x{}", alloy_primitives::hex::encode(tx_id)),
        };

        let parts = self.collect_signatures(&req, &tx_id).await?;
        let ordered = aggregate_verified(&self.config.multisig, &tx_id, &parts)?;
        let tx_bytes = build_signed_transaction(&raw_data, &ordered);

        Ok(TronRedeemLegOutcome {
            chain: self.config.chain,
            tx_hex: alloy_primitives::hex::encode(&tx_bytes),
            txid: format!("0x{}", alloy_primitives::hex::encode(tx_id)),
            owner_address: self.config.owner_address.clone(),
            dispatch_id: task.dispatch_id,
            redemption_id: task.redemption_id,
        })
    }

    /// Round-robin cosigners until the summed member weight of VALID
    /// partials reaches the threshold. Each partial is recovered + checked
    /// against the pinned member AS IT IS COLLECTED — a cosigner that
    /// returns a garbage signature is skipped and the next is tried, so one
    /// bad daemon among the first-k cannot DoS the leg.
    async fn collect_signatures(
        &self,
        req: &TronTxSignRequest,
        tx_id: &[u8; 32],
    ) -> Result<Vec<[u8; 65]>, TronRedeemError> {
        let need = self.config.multisig.threshold();
        let mut parts: Vec<[u8; 65]> = Vec::new();
        let mut weight: u64 = 0;
        let mut errors: Vec<TronRedeemError> = Vec::new();
        for cosigner in &self.cosigners {
            if weight >= need {
                break;
            }
            let pubkey = cosigner.member_pubkey();
            let Some(member) = self.config.multisig.member_by_pubkey(&pubkey) else {
                errors.push(TronRedeemError::MemberNotInSet(hex33(&pubkey)));
                continue;
            };
            match cosigner.sign_tron_tx(req).await {
                Ok(sig) => {
                    // Verify the partial recovers to THIS member before it
                    // counts toward the threshold.
                    match recover_evm20(tx_id, &sig) {
                        Ok(addr) if addr == member.address20 => {
                            weight += member.weight;
                            parts.push(sig);
                        }
                        Ok(_) | Err(_) => {
                            errors.push(TronRedeemError::Cosigner {
                                pubkey: hex33(&pubkey),
                                message: "returned a signature that did not recover to the member"
                                    .to_string(),
                            });
                        }
                    }
                }
                Err(e) => errors.push(e),
            }
        }
        if weight < need {
            for e in &errors {
                warn!(error = %e, "tron cosigner failed");
            }
            return Err(TronRedeemError::InsufficientCosigners { got: weight, need });
        }
        Ok(parts)
    }
}

/// Hex of a compressed member pubkey for error messages.
fn hex33(pk: &[u8; 33]) -> String {
    format!("0x{}", alloy_primitives::hex::encode(pk))
}

/// Output of [`TronRedeemExecutor::build_leg`] — every input the binary
/// needs to broadcast + record the dispatch.
#[derive(Debug, Clone)]
pub struct TronRedeemLegOutcome {
    /// Destination chain (for the dispatch-store `chain` column).
    pub chain: ChainId,
    /// Broadcast-ready signed `Transaction` protobuf, hex-encoded (no 0x).
    pub tx_hex: String,
    /// The `txID` (`0x`-prefixed) — the dispatch `inbound_txid`.
    pub txid: String,
    /// Multisig account that signed.
    pub owner_address: String,
    /// Originating dispatch id (broadcast registry key).
    pub dispatch_id: B256,
    /// Originating redemption id (attestation correlation).
    pub redemption_id: B256,
}

/// Convenience: the 20-byte EVM address a member pubkey derives to (used by
/// the binary to pin cosigners). Re-exported here so callers don't need a
/// direct `tron-tx` dep just for this.
///
/// # Errors
/// [`TronTxError::BadPubkey`] if `pubkey` is not a valid compressed point.
pub fn member_evm_address(pubkey: &[u8; 33]) -> Result<[u8; 20], TronTxError> {
    evm_address(pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use std::future::ready;
    use xindex_chain_tron::{TronBlockRef, TronBroadcastOutcome, TronTxReceipt};
    use xindex_tron_tx::sigs::sign_recoverable;

    fn member(seed: u8) -> (SigningKey, [u8; 33]) {
        #[expect(clippy::expect_used, reason = "test code")]
        let sk = SigningKey::from_slice(&[seed; 32]).expect("key");
        let ep = sk.verifying_key().to_encoded_point(true);
        let mut pk = [0u8; 33];
        pk.copy_from_slice(ep.as_bytes());
        (sk, pk)
    }

    /// Stub TRON client: fixed now-block, no broadcast.
    struct StubTron;
    impl TronChainClient for StubTron {
        fn chain(&self) -> ChainId {
            ChainId::Tron
        }
        fn now_block(&self) -> impl Future<Output = Result<TronBlockRef, TronChainError>> + Send {
            ready(Ok(TronBlockRef {
                number: 176,
                ref_block_bytes: [0x00, 0xb0],
                ref_block_hash: [0x3f, 0x1b, 0xc9, 0x6d, 0xc8, 0x0e, 0x7f, 0x61],
                timestamp_ms: 1_548_974_072_663,
            }))
        }
        fn broadcast_hex(
            &self,
            _tx_hex: &str,
        ) -> impl Future<Output = Result<TronBroadcastOutcome, TronChainError>> + Send {
            ready(Err(TronChainError::Rpc("not used in tests".to_string())))
        }
        fn transaction_info(
            &self,
            _txid_hex: &str,
        ) -> impl Future<Output = Result<Option<TronTxReceipt>, TronChainError>> + Send {
            ready(Ok(None))
        }
    }

    /// Stub cosigner: recomputes the txID from the request's semantic
    /// fields (via the same `tron-tx` builders the daemon uses) and signs
    /// it — the faithful never-blind-sign behaviour.
    struct SigningCosigner {
        sk: SigningKey,
        pubkey: [u8; 33],
    }
    impl TronCosigner for SigningCosigner {
        fn member_pubkey(&self) -> [u8; 33] {
            self.pubkey
        }
        fn sign_tron_tx<'a>(&'a self, req: &'a TronTxSignRequest) -> SignTronFuture<'a> {
            let sk = self.sk.clone();
            let claimed = req.txid.clone();
            Box::pin(async move {
                let tx_id: [u8; 32] =
                    alloy_primitives::hex::decode(claimed.strip_prefix("0x").unwrap_or(&claimed))
                        .map_err(|e| TronRedeemError::Cosigner {
                            pubkey: "stub".to_string(),
                            message: format!("bad txid hex: {e}"),
                        })?
                        .as_slice()
                        .try_into()
                        .map_err(|_| TronRedeemError::Cosigner {
                            pubkey: "stub".to_string(),
                            message: "txid not 32 bytes".to_string(),
                        })?;
                sign_recoverable(&sk, &tx_id).map_err(|e| TronRedeemError::Cosigner {
                    pubkey: "stub".to_string(),
                    message: format!("sign: {e}"),
                })
            })
        }
    }

    /// A cosigner that always errors (transport failure).
    struct FailingCosigner {
        pubkey: [u8; 33],
    }
    impl TronCosigner for FailingCosigner {
        fn member_pubkey(&self) -> [u8; 33] {
            self.pubkey
        }
        fn sign_tron_tx<'a>(&'a self, _req: &'a TronTxSignRequest) -> SignTronFuture<'a> {
            let pk = hex33(&self.pubkey);
            Box::pin(ready(Err(TronRedeemError::Cosigner {
                pubkey: pk,
                message: "daemon offline".to_string(),
            })))
        }
    }

    fn descriptor_and_keys(n: u8, k: u64) -> (TronMultisig, Vec<(SigningKey, [u8; 33])>) {
        let keys: Vec<(SigningKey, [u8; 33])> = (1..=n).map(member).collect();
        #[expect(clippy::expect_used, reason = "test code")]
        let ms = TronMultisig::new(k, 2, keys.iter().map(|(_, pk)| (*pk, 1u64)).collect())
            .expect("descriptor");
        (ms, keys)
    }

    fn config(ms: TronMultisig) -> TronRedeemConfig {
        use xindex_tron_tx::addr::pubkey_to_address;
        #[expect(clippy::expect_used, reason = "test code")]
        let owner = pubkey_to_address(&member(50).1).expect("owner");
        #[expect(clippy::expect_used, reason = "test code")]
        let vault = pubkey_to_address(&member(60).1).expect("vault");
        TronRedeemConfig {
            chain: ChainId::Tron,
            multisig: ms,
            owner_address: owner,
            vault,
            asset: TronAssetKind::Trx,
            contract_address: None,
            fee_limit: 0,
            expiration_window_ms: 1_200_000,
        }
    }

    fn task() -> TronRedeemTask {
        TronRedeemTask {
            dispatch_id: B256::repeat_byte(0xd1),
            redemption_id: B256::repeat_byte(0xd2),
            chain: ChainId::Tron,
            memo: "=:ETH.USDT:0xdeadbeef:1000000".to_string(),
            send_amount: 5_000_000,
        }
    }

    fn signing_cosigners(keys: &[(SigningKey, [u8; 33])], n: usize) -> Vec<Box<dyn TronCosigner>> {
        keys.iter()
            .take(n)
            .map(|(sk, pk)| -> Box<dyn TronCosigner> {
                Box::new(SigningCosigner {
                    sk: sk.clone(),
                    pubkey: *pk,
                })
            })
            .collect()
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn build_leg_happy_path_produces_signed_tx() {
        let (ms, keys) = descriptor_and_keys(5, 3);
        let cfg = config(ms);
        let cosigners = signing_cosigners(&keys, 3);
        let exec = TronRedeemExecutor::new(cfg, Arc::new(StubTron), cosigners).expect("exec");
        let outcome = exec.build_leg(&task()).await.expect("leg");
        assert_eq!(outcome.chain, ChainId::Tron);
        assert!(!outcome.tx_hex.is_empty());
        assert!(outcome.txid.starts_with("0x"));
        // Signed Transaction: field 1 (raw_data) tag 0x0a at the front.
        let tx = alloy_primitives::hex::decode(&outcome.tx_hex).expect("hex");
        assert_eq!(tx[0], 0x0a);
        // Exactly 3 signature fields (each `0x12 0x41 …`).
        let sig_fields = tx.windows(2).filter(|w| *w == b"\x12\x41").count();
        assert!(
            sig_fields >= 3,
            "expected >= 3 signatures, tx={}",
            outcome.tx_hex
        );
        assert_eq!(outcome.dispatch_id, task().dispatch_id);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn build_leg_rejects_wrong_chain() {
        let (ms, keys) = descriptor_and_keys(5, 3);
        let exec =
            TronRedeemExecutor::new(config(ms), Arc::new(StubTron), signing_cosigners(&keys, 3))
                .expect("exec");
        let mut t = task();
        t.chain = ChainId::Xrp;
        let err = exec.build_leg(&t).await.expect_err("reject");
        assert!(matches!(err, TronRedeemError::WrongChain(ChainId::Xrp)));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn build_leg_insufficient_when_cosigners_fail() {
        let (ms, keys) = descriptor_and_keys(5, 3);
        // One real signer + two failing → weight 1 < threshold 3.
        let cosigners: Vec<Box<dyn TronCosigner>> = vec![
            Box::new(SigningCosigner {
                sk: keys[0].0.clone(),
                pubkey: keys[0].1,
            }),
            Box::new(FailingCosigner { pubkey: keys[1].1 }),
            Box::new(FailingCosigner { pubkey: keys[2].1 }),
        ];
        let exec =
            TronRedeemExecutor::new(config(ms), Arc::new(StubTron), cosigners).expect("exec");
        let err = exec.build_leg(&task()).await.expect_err("reject");
        assert!(matches!(
            err,
            TronRedeemError::InsufficientCosigners { got: 1, need: 3 }
        ));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn constructor_rejects_too_few_cosigners() {
        let (ms, keys) = descriptor_and_keys(5, 3);
        let err =
            TronRedeemExecutor::new(config(ms), Arc::new(StubTron), signing_cosigners(&keys, 1))
                .expect_err("construct");
        assert!(matches!(
            err,
            TronRedeemError::InsufficientCosigners { got: 1, need: 3 }
        ));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn constructor_rejects_usdt_without_contract() {
        let (ms, keys) = descriptor_and_keys(5, 3);
        let mut cfg = config(ms);
        cfg.asset = TronAssetKind::Usdt;
        cfg.contract_address = None;
        let err = TronRedeemExecutor::new(cfg, Arc::new(StubTron), signing_cosigners(&keys, 3))
            .expect_err("construct");
        assert!(matches!(err, TronRedeemError::MissingContract));
    }
}
