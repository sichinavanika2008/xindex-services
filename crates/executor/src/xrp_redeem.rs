//! C7 — XRP-side redeem leg executor (Phase 4.4).
//!
//! Builds + signs (k-of-n `SignerList` multisig) the `Payment` that sends
//! native XRP from our XRP multisig to the THORChain Asgard inbound,
//! carrying the contract-emitted swap memo
//! (`=:ETH.USDT:<indexToken>:<minOut>`) in `Memos[0].MemoData`. THORChain
//! then swaps XRP → USDT and delivers to the IndexToken on Ethereum (the
//! `xindex-attest-redeem` flow + the C6 `ThorXrp` cross-check attest it).
//!
//! ## Pipeline (per leg)
//!
//! 1. Acquire the per-account in-process lock — the account `Sequence` is
//!    monotonic; two concurrent legs collide.
//! 2. Read `Sequence` ([`XrpChainClient::account_info`]) + the current
//!    ledger ([`XrpChainClient::ledger_current`]) for `LastLedgerSequence`.
//! 3. Build the canonical `STObject` body (empty `SigningPubKey`, no
//!    `Signers`) via [`serialize_for_multisign`] — the SHARED body.
//! 4. Round-robin collect ≥ quorum partials from the configured
//!    [`XrpCosigner`]s (each → one signer-daemon `/sign/xrp-tx`). The
//!    divergence: every signer hashes a DIFFERENT message (the body with
//!    its own AccountID suffix) — the wire carries the shared body.
//! 5. Verify-and-aggregate ([`aggregate_verified`]) — each partial is
//!    re-checked against its OWN multi-signing digest, then sorted by
//!    AccountID.
//! 6. Assemble the broadcast tx-blob ([`build_signed_multisig_tx`]) with
//!    the `Signers` array.
//! 7. Return [`XrpRedeemLegOutcome`]; the binary submits via
//!    [`XrpChainClient::submit_tx_blob`] and records the `xrp` dispatch row.
//!
//! ## Deadline / replay rule (the XRP-specific nuance)
//!
//! `LastLedgerSequence` is bound into the body, so it is part of the
//! per-signer digest. A retry at the SAME `Sequence` with a different
//! deadline yields a different body → the daemon refuses it as a 409
//! Conflict. The executor therefore computes ONE deadline per leg; an
//! expired-unbroadcast leg is terminal-for-that-sequence and may only be
//! re-driven after `account_info` shows the `Sequence` advanced
//! (KNOWN_FINDINGS P4.4-2).

#![expect(
    clippy::doc_markdown,
    reason = "module-level: many THORChain / IndexToken / SignerList / STObject / \
              AccountID / Payment identifiers — per-identifier backticks add \
              noise without aiding parsing"
)]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use alloy_primitives::B256;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::warn;
use xindex_chain_xrp::{XrpChainClient, XrpChainError};
use xindex_shared::chain_registry::{ChainId, CustodyFamily};
use xindex_shared::signer_wire::XrpTxSignRequest;
use xindex_xrp_tx::addr::decode_classic_address;
use xindex_xrp_tx::sigs::{aggregate_verified, PartialSig, SigError};
use xindex_xrp_tx::tx::{build_signed_multisig_tx, serialize_for_multisign, PaymentBody, TxError};
use xindex_xrp_tx::XrpMultisig;

/// Errors surfaced by the C7 XRP redeem executor.
#[derive(Debug, Error)]
pub enum XrpRedeemError {
    /// Task chain is not in the XRP custody family / not this executor's.
    #[error("ChainId {0:?} is not this executor's XRP chain")]
    WrongChain(ChainId),
    /// XRP RPC failure (account / ledger / submit).
    #[error("xrp rpc: {0}")]
    Chain(#[from] XrpChainError),
    /// A configured r-address (account / vault) did not decode.
    #[error("address: {0}")]
    Address(String),
    /// An amount / fee / ledger value did not fit its on-wire width.
    #[error("out-of-range numeric: {0}")]
    Numeric(String),
    /// `STObject` serialization failed (e.g. memo too long).
    #[error("tx build: {0}")]
    Tx(#[from] TxError),
    /// Aggregation / partial verification failed.
    #[error("signature aggregation: {0}")]
    Aggregate(#[from] SigError),
    /// A cosigner returned an error (transport / daemon refusal).
    #[error("cosigner {pubkey}: {message}")]
    Cosigner {
        /// Hex of the cosigner's pinned member pubkey.
        pubkey: String,
        /// Failure detail.
        message: String,
    },
    /// A cosigner's pinned pubkey is not a member of the configured
    /// multisig — a deploy-time misconfiguration.
    #[error("cosigner pubkey {0} is not in the multisig member set")]
    MemberNotInSet(String),
    /// Collected signer weight fell short of the quorum.
    #[error("insufficient cosigner weight: got {got}, need {need}")]
    InsufficientCosigners {
        /// Summed weight of the partials collected.
        got: u32,
        /// Quorum required.
        need: u32,
    },
}

/// Boxed future returned by [`XrpCosigner::sign_xrp_tx`].
pub type SignXrpFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, XrpRedeemError>> + Send + 'a>>;

/// One cosigner — talks to one signer-daemon's `/api/v1/sign/xrp-tx` (C5)
/// and returns the member's DER-encoded low-S signature over its OWN
/// multi-signing digest. The implementation MUST verify the daemon's
/// response pubkey matches [`XrpCosigner::member_pubkey`] (never
/// self-reported).
pub trait XrpCosigner: Send + Sync {
    /// The disclosed 33-byte compressed member pubkey (pinned by config).
    fn member_pubkey(&self) -> [u8; 33];

    /// POST `req` to the daemon; return the verified DER signature. The
    /// daemon independently re-serializes the body from `req` and appends
    /// its own AccountID — it never trusts the coordinator's `signing_blob`
    /// blindly.
    fn sign_xrp_tx<'a>(&'a self, req: &'a XrpTxSignRequest) -> SignXrpFuture<'a>;
}

/// Per-account in-process lock table (the XRPL `Sequence` is monotonic;
/// concurrent legs against the same account must serialise).
type AccountMutexMap = HashMap<(ChainId, String), Arc<Mutex<()>>>;

#[derive(Debug, Default)]
pub struct XrpLockTable {
    locks: Mutex<AccountMutexMap>,
}

impl XrpLockTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquire the per-account lock; releases on guard drop.
    pub async fn acquire(
        &self,
        chain: ChainId,
        account: String,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        let mutex = {
            let mut table = self.locks.lock().await;
            Arc::clone(
                table
                    .entry((chain, account))
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        mutex.lock_owned().await
    }
}

/// Decoded form of one XRP `RedeemDispatched` event (or hand-built by
/// tests).
#[derive(Debug, Clone)]
pub struct XrpRedeemTask {
    /// Per-adapter dispatch id (broadcast registry key).
    pub dispatch_id: B256,
    /// `IntentQueue` redemption id (correlation key).
    pub redemption_id: B256,
    /// Destination chain (XRP family).
    pub chain: ChainId,
    /// THORChain swap memo, trusted verbatim from the contract event.
    pub memo: String,
    /// Native send amount in drops.
    pub send_amount: u128,
}

/// Static per-executor config. One executor instance per multisig account.
#[derive(Debug, Clone)]
pub struct XrpRedeemConfig {
    /// Destination chain this executor serves.
    pub chain: ChainId,
    /// The frozen k-of-n `SignerList` multisig descriptor.
    pub multisig: XrpMultisig,
    /// The multisig classic r-address. NOT derived from `multisig` (the
    /// XRP account is a separately-funded account whose `SignerList` is
    /// configured by `SignerListSet`), so it is supplied explicitly.
    pub account_address: String,
    /// Fee in drops (caller-supplied; `base_fee × (1 + signer_count)`).
    pub fee_drops: u128,
    /// Ledgers added to the current index for `LastLedgerSequence` (the
    /// tx-expiry window). Computed ONCE per leg — see the deadline rule.
    pub last_ledger_window: u32,
    /// Current THORChain Asgard inbound (classic r-address). The binary
    /// refreshes from `/thorchain/inbound_addresses` before each leg.
    pub vault: String,
}

/// Build + collect-sigs executor. Submission is the binary's job.
pub struct XrpRedeemExecutor<C: XrpChainClient> {
    config: XrpRedeemConfig,
    xrp: Arc<C>,
    cosigners: Vec<Box<dyn XrpCosigner>>,
    lock_table: Arc<XrpLockTable>,
}

impl<C: XrpChainClient> std::fmt::Debug for XrpRedeemExecutor<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XrpRedeemExecutor")
            .field("config", &self.config)
            .field("cosigner_count", &self.cosigners.len())
            .finish_non_exhaustive()
    }
}

impl<C: XrpChainClient> XrpRedeemExecutor<C> {
    /// Construct. Rejects a config that is not XRP-family or has fewer
    /// cosigners than the multisig quorum (loud startup failure).
    ///
    /// # Errors
    /// [`XrpRedeemError::WrongChain`] if `config.chain` is not XRP;
    /// [`XrpRedeemError::InsufficientCosigners`] if too few cosigners.
    pub fn new(
        config: XrpRedeemConfig,
        xrp: Arc<C>,
        cosigners: Vec<Box<dyn XrpCosigner>>,
        lock_table: Arc<XrpLockTable>,
    ) -> Result<Self, XrpRedeemError> {
        if config.chain.custody_family() != CustodyFamily::Xrp {
            return Err(XrpRedeemError::WrongChain(config.chain));
        }
        let need = config.multisig.quorum();
        if u32::try_from(cosigners.len()).unwrap_or(u32::MAX) < need {
            return Err(XrpRedeemError::InsufficientCosigners {
                got: u32::try_from(cosigners.len()).unwrap_or(u32::MAX),
                need,
            });
        }
        Ok(Self {
            config,
            xrp,
            cosigners,
            lock_table,
        })
    }

    /// Borrow the config (logs / metrics at the binary callsite).
    #[must_use]
    pub fn config(&self) -> &XrpRedeemConfig {
        &self.config
    }

    /// Build + collect-sigs for one leg. Per-account locked.
    ///
    /// # Errors
    /// Any [`XrpRedeemError`] variant.
    pub async fn build_leg(
        &self,
        task: &XrpRedeemTask,
    ) -> Result<XrpRedeemLegOutcome, XrpRedeemError> {
        if task.chain != self.config.chain {
            return Err(XrpRedeemError::WrongChain(task.chain));
        }

        let _guard = self
            .lock_table
            .acquire(self.config.chain, self.config.account_address.clone())
            .await;

        // Fresh Sequence + current ledger for the (single) deadline.
        let account = self.xrp.account_info(&self.config.account_address).await?;
        let current = self.xrp.ledger_current().await?;
        let last_ledger_sequence =
            u32::try_from(current.saturating_add(u64::from(self.config.last_ledger_window)))
                .map_err(|_| {
                    XrpRedeemError::Numeric(format!("LastLedgerSequence > u32: {current}"))
                })?;
        let amount_drops = u64::try_from(task.send_amount).map_err(|_| {
            XrpRedeemError::Numeric(format!("amount > u64 drops: {}", task.send_amount))
        })?;
        let fee_drops = u64::try_from(self.config.fee_drops).map_err(|_| {
            XrpRedeemError::Numeric(format!("fee > u64 drops: {}", self.config.fee_drops))
        })?;

        let account_addr = decode_classic_address(&self.config.account_address)
            .map_err(|e| XrpRedeemError::Address(format!("account {e}")))?;
        let destination = decode_classic_address(&self.config.vault)
            .map_err(|e| XrpRedeemError::Address(format!("vault {e}")))?;

        let body_inputs = PaymentBody {
            account: account_addr,
            destination,
            amount_drops,
            fee_drops,
            sequence: account.sequence,
            last_ledger_sequence: Some(last_ledger_sequence),
            network_id: None,
            memo: task.memo.clone().into_bytes(),
        };
        // The SHARED body: identical for every signer (each appends its own
        // AccountID before hashing).
        let body = serialize_for_multisign(&body_inputs)?;

        let req = XrpTxSignRequest {
            chain_id: self.config.chain,
            account_address: self.config.account_address.clone(),
            destination: self.config.vault.clone(),
            amount_drops: amount_drops.to_string(),
            fee_drops: fee_drops.to_string(),
            sequence: account.sequence.to_string(),
            last_ledger_sequence: last_ledger_sequence.to_string(),
            memo: task.memo.clone(),
            signing_blob: format!("0x{}", alloy_primitives::hex::encode(&body)),
        };

        let parts = self.collect_signatures(&req).await?;
        // Per-signer verify + AccountID-sorted Signers.
        let signers = aggregate_verified(&self.config.multisig, &body, &parts)?;
        let tx_blob = build_signed_multisig_tx(&body_inputs, &signers)?;

        Ok(XrpRedeemLegOutcome {
            chain: self.config.chain,
            tx_blob,
            account_address: self.config.account_address.clone(),
            sequence: account.sequence,
            last_ledger_sequence,
            dispatch_id: task.dispatch_id,
            redemption_id: task.redemption_id,
        })
    }

    /// Round-robin cosigners until the summed member weight reaches the
    /// quorum. A cosigner whose pinned pubkey is not a member is skipped
    /// (counted as a failure); [`aggregate_verified`] re-checks every
    /// partial against its own digest.
    async fn collect_signatures(
        &self,
        req: &XrpTxSignRequest,
    ) -> Result<Vec<PartialSig>, XrpRedeemError> {
        let quorum = self.config.multisig.quorum();
        let mut parts: Vec<PartialSig> = Vec::new();
        let mut weight: u32 = 0;
        let mut errors: Vec<XrpRedeemError> = Vec::new();
        for cosigner in &self.cosigners {
            if weight >= quorum {
                break;
            }
            let pubkey = cosigner.member_pubkey();
            let Some(member) = self.config.multisig.member_by_pubkey(&pubkey) else {
                errors.push(XrpRedeemError::MemberNotInSet(hex33(&pubkey)));
                continue;
            };
            match cosigner.sign_xrp_tx(req).await {
                Ok(der) => {
                    weight += u32::from(member.weight);
                    parts.push(PartialSig { pubkey, der });
                }
                Err(e) => errors.push(e),
            }
        }
        if weight < quorum {
            for e in &errors {
                warn!(error = %e, "xrp cosigner failed");
            }
            return Err(XrpRedeemError::InsufficientCosigners {
                got: weight,
                need: quorum,
            });
        }
        Ok(parts)
    }
}

/// Hex of a compressed member pubkey for error messages.
fn hex33(pk: &[u8; 33]) -> String {
    format!("0x{}", alloy_primitives::hex::encode(pk))
}

/// Output of [`XrpRedeemExecutor::build_leg`] — every input the binary
/// needs to submit + record the dispatch.
#[derive(Debug, Clone)]
pub struct XrpRedeemLegOutcome {
    /// Destination chain (for the dispatch-store `chain` column).
    pub chain: ChainId,
    /// Broadcast-ready multisigned tx-blob.
    pub tx_blob: Vec<u8>,
    /// Multisig account that signed.
    pub account_address: String,
    /// Account `Sequence` consumed by this leg.
    pub sequence: u32,
    /// The `LastLedgerSequence` deadline bound into the body (one per
    /// leg — never varied for a retry at the same sequence).
    pub last_ledger_sequence: u32,
    /// Originating dispatch id (broadcast registry key).
    pub dispatch_id: B256,
    /// Originating redemption id (attestation correlation).
    pub redemption_id: B256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature, SigningKey};
    use std::future::ready;
    use xindex_chain_xrp::{XrpAccount, XrpSubmitOutcome, XrpTransfer};
    use xindex_xrp_tx::addr::{account_id, encode_classic_address};
    use xindex_xrp_tx::signing::multisign_digest;
    use xindex_xrp_tx::sigs::der_low_s;

    fn member(seed: u8) -> (SigningKey, [u8; 33]) {
        #[expect(clippy::expect_used, reason = "test code")]
        let sk = SigningKey::from_slice(&[seed; 32]).expect("key");
        let ep = sk.verifying_key().to_encoded_point(true);
        let mut pk = [0u8; 33];
        pk.copy_from_slice(ep.as_bytes());
        (sk, pk)
    }

    /// Stub XRP client: fixed sequence + tip, no submit.
    struct StubXrp {
        sequence: u32,
        tip: u64,
    }
    impl XrpChainClient for StubXrp {
        fn chain(&self) -> ChainId {
            ChainId::Xrp
        }
        fn account_info(
            &self,
            _address: &str,
        ) -> impl Future<Output = Result<XrpAccount, XrpChainError>> + Send {
            ready(Ok(XrpAccount {
                sequence: self.sequence,
            }))
        }
        fn ledger_current(&self) -> impl Future<Output = Result<u64, XrpChainError>> + Send {
            ready(Ok(self.tip))
        }
        fn latest_validated_ledger(
            &self,
        ) -> impl Future<Output = Result<u64, XrpChainError>> + Send {
            ready(Ok(self.tip))
        }
        fn transfers_to(
            &self,
            _destination: &str,
            _min_ledger: u64,
        ) -> impl Future<Output = Result<Vec<XrpTransfer>, XrpChainError>> + Send {
            ready(Ok(Vec::new()))
        }
        fn submit_tx_blob(
            &self,
            _tx_blob: &[u8],
        ) -> impl Future<Output = Result<XrpSubmitOutcome, XrpChainError>> + Send {
            ready(Err(XrpChainError::Rpc("not used in tests".to_string())))
        }
    }

    /// Stub cosigner: recomputes ITS OWN per-signer digest from the shared
    /// body in `signing_blob` and signs it (so `aggregate_verified` accepts
    /// the partial). This is the divergence-faithful behaviour.
    struct SigningCosigner {
        sk: SigningKey,
        pubkey: [u8; 33],
    }
    impl XrpCosigner for SigningCosigner {
        fn member_pubkey(&self) -> [u8; 33] {
            self.pubkey
        }
        fn sign_xrp_tx<'a>(&'a self, req: &'a XrpTxSignRequest) -> SignXrpFuture<'a> {
            let hex = req
                .signing_blob
                .strip_prefix("0x")
                .unwrap_or(&req.signing_blob)
                .to_string();
            let sk = self.sk.clone();
            let pubkey = self.pubkey;
            Box::pin(async move {
                let body =
                    alloy_primitives::hex::decode(&hex).map_err(|e| XrpRedeemError::Cosigner {
                        pubkey: "stub".to_string(),
                        message: format!("bad body hex: {e}"),
                    })?;
                let my_id = account_id(&pubkey);
                let digest = multisign_digest(&body, &my_id);
                #[expect(clippy::expect_used, reason = "test code")]
                let sig: Signature = sk.sign_prehash(&digest).expect("sign");
                Ok(der_low_s(&sig))
            })
        }
    }

    /// A cosigner that always errors (transport failure).
    struct FailingCosigner {
        pubkey: [u8; 33],
    }
    impl XrpCosigner for FailingCosigner {
        fn member_pubkey(&self) -> [u8; 33] {
            self.pubkey
        }
        fn sign_xrp_tx<'a>(&'a self, _req: &'a XrpTxSignRequest) -> SignXrpFuture<'a> {
            let pk = hex33(&self.pubkey);
            Box::pin(ready(Err(XrpRedeemError::Cosigner {
                pubkey: pk,
                message: "daemon offline".to_string(),
            })))
        }
    }

    fn descriptor_and_keys(n: u8, k: u32) -> (XrpMultisig, Vec<(SigningKey, [u8; 33])>) {
        let keys: Vec<(SigningKey, [u8; 33])> = (1..=n).map(member).collect();
        #[expect(clippy::expect_used, reason = "test code")]
        let ms = XrpMultisig::new(k, keys.iter().map(|(_, pk)| (*pk, 1u16)).collect())
            .expect("descriptor");
        (ms, keys)
    }

    fn config(ms: XrpMultisig) -> XrpRedeemConfig {
        // The multisig account is a separately-funded r-address.
        let account_address = encode_classic_address(&[0xAB; 20]);
        XrpRedeemConfig {
            chain: ChainId::Xrp,
            multisig: ms,
            account_address,
            fee_drops: 60,
            last_ledger_window: 75,
            vault: encode_classic_address(&[0xCD; 20]),
        }
    }

    fn task() -> XrpRedeemTask {
        XrpRedeemTask {
            dispatch_id: B256::repeat_byte(0xd1),
            redemption_id: B256::repeat_byte(0xd2),
            chain: ChainId::Xrp,
            memo: "=:ETH.USDT:0xdeadbeef:1000000".to_string(),
            send_amount: 5_000_000,
        }
    }

    fn cosigners_first(keys: &[(SigningKey, [u8; 33])], n: usize) -> Vec<Box<dyn XrpCosigner>> {
        keys.iter()
            .take(n)
            .map(|(sk, pk)| -> Box<dyn XrpCosigner> {
                Box::new(SigningCosigner {
                    sk: sk.clone(),
                    pubkey: *pk,
                })
            })
            .collect()
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn build_leg_happy_path_produces_signed_tx_blob() {
        let (ms, keys) = descriptor_and_keys(5, 3);
        let cfg = config(ms);
        let cosigners = cosigners_first(&keys, 3);
        let xrp = Arc::new(StubXrp {
            sequence: 7,
            tip: 9_000_000,
        });
        let exec = XrpRedeemExecutor::new(cfg, xrp, cosigners, Arc::new(XrpLockTable::new()))
            .expect("exec");
        let outcome = exec.build_leg(&task()).await.expect("leg");
        assert_eq!(outcome.sequence, 7);
        assert_eq!(outcome.last_ledger_sequence, 9_000_075);
        assert_eq!(outcome.chain, ChainId::Xrp);
        assert!(!outcome.tx_blob.is_empty());
        // Assembled tx starts with TransactionType=Payment (12 0000).
        assert_eq!(&outcome.tx_blob[..3], &[0x12, 0x00, 0x00]);
        // The Signers array (f3) is present in the assembled blob.
        let hex = alloy_primitives::hex::encode(&outcome.tx_blob);
        assert!(hex.contains("f3e0"), "Signers array must be present");
        assert_eq!(outcome.dispatch_id, task().dispatch_id);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn build_leg_rejects_wrong_chain() {
        let (ms, keys) = descriptor_and_keys(5, 3);
        let cfg = config(ms);
        let cosigners = cosigners_first(&keys, 3);
        let xrp = Arc::new(StubXrp {
            sequence: 0,
            tip: 1,
        });
        let exec = XrpRedeemExecutor::new(cfg, xrp, cosigners, Arc::new(XrpLockTable::new()))
            .expect("exec");
        let mut t = task();
        t.chain = ChainId::Btc;
        let err = exec.build_leg(&t).await.expect_err("reject");
        assert!(matches!(err, XrpRedeemError::WrongChain(ChainId::Btc)));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn build_leg_insufficient_when_cosigners_fail() {
        let (ms, keys) = descriptor_and_keys(5, 3);
        let cfg = config(ms);
        // One real signer + two failing → weight 1 < quorum 3.
        let cosigners: Vec<Box<dyn XrpCosigner>> = vec![
            Box::new(SigningCosigner {
                sk: keys[0].0.clone(),
                pubkey: keys[0].1,
            }),
            Box::new(FailingCosigner { pubkey: keys[1].1 }),
            Box::new(FailingCosigner { pubkey: keys[2].1 }),
        ];
        let xrp = Arc::new(StubXrp {
            sequence: 0,
            tip: 1,
        });
        let exec = XrpRedeemExecutor::new(cfg, xrp, cosigners, Arc::new(XrpLockTable::new()))
            .expect("exec");
        let err = exec.build_leg(&task()).await.expect_err("reject");
        assert!(matches!(
            err,
            XrpRedeemError::InsufficientCosigners { got: 1, need: 3 }
        ));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn constructor_rejects_too_few_cosigners() {
        let (ms, keys) = descriptor_and_keys(5, 3);
        let cfg = config(ms);
        let cosigners = cosigners_first(&keys, 1);
        let xrp = Arc::new(StubXrp {
            sequence: 0,
            tip: 1,
        });
        let err = XrpRedeemExecutor::new(cfg, xrp, cosigners, Arc::new(XrpLockTable::new()))
            .expect_err("construct");
        assert!(matches!(
            err,
            XrpRedeemError::InsufficientCosigners { got: 1, need: 3 }
        ));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn lock_table_serialises_same_account() {
        let table = Arc::new(XrpLockTable::new());
        let g1 = table.acquire(ChainId::Xrp, "acct".to_string()).await;
        let t = Arc::clone(&table);
        let h = tokio::spawn(async move {
            let _g2 = t.acquire(ChainId::Xrp, "acct".to_string()).await;
            "g2"
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!h.is_finished(), "second acquire must block");
        drop(g1);
        assert_eq!(h.await.expect("join"), "g2");
    }
}
