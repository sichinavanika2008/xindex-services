//! C7 — Cosmos-side redeem leg executor (Phase 3.3).
//!
//! Builds + signs (3-of-5 `LegacyAminoPubKey` multisig) the `MsgSend` that
//! sends native ATOM from our Cosmos multisig to the THORChain Asgard
//! inbound, carrying the contract-emitted swap memo
//! (`=:ETH.USDT:<indexToken>:<minOut>`) in the tx `memo`. THORChain then
//! swaps ATOM → USDT and delivers to the IndexToken on Ethereum (the
//! `xindex-attest-redeem` flow + the C6 `ThorCosmos` cross-check attest it).
//!
//! ## Pipeline (per leg)
//!
//! 1. Acquire the per-account in-process lock — the account `sequence` is
//!    monotonic; two concurrent legs reading the same sequence collide.
//! 2. Read `{account_number, sequence}` fresh from chain
//!    ([`CosmosChainClient::account`]).
//! 3. Build the `SIGN_MODE_LEGACY_AMINO_JSON` `StdSignDoc` and its SHA-256
//!    digest ([`CosmosSendSignDoc`]).
//! 4. Round-robin collect ≥ threshold partials from the configured
//!    [`CosmosCosigner`]s (each → one signer-daemon `/sign/cosmos-tx`).
//! 5. Verify-and-aggregate ([`aggregate_verified`]) — every partial is
//!    re-checked against the descriptor's member pubkey over the digest.
//! 6. Assemble the broadcast `TxRaw` ([`build_tx_raw`]).
//! 7. Return [`CosmosRedeemLegOutcome`]; the binary broadcasts via
//!    [`CosmosChainClient::broadcast_tx_sync`] and records the F2 dispatch
//!    row (the `gaia` value C8 admits).
//!
//! Submission is the BINARY's job (parity with `evm_redeem` / `redeem`) —
//! the library stays node-free and trivially testable with stub cosigners.

#![expect(
    clippy::doc_markdown,
    reason = "module-level: many THORChain / IndexToken / ChainId / MsgSend / \
              StdSignDoc / TxRaw identifiers — per-identifier backticks add \
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
use xindex_chain_cosmos::{CosmosChainClient, CosmosChainError};
use xindex_cosmos_tx::amino::{AminoError, CosmosSendSignDoc};
use xindex_cosmos_tx::sigs::{aggregate_verified, MemberSig, SigError};
use xindex_cosmos_tx::tx::{build_tx_raw, CosmosTxParams};
use xindex_cosmos_tx::CosmosMultisig;
use xindex_shared::chain_registry::{ChainId, CustodyFamily};
use xindex_shared::signer_wire::CosmosTxSignRequest;

/// Errors surfaced by the C7 Cosmos redeem executor.
#[derive(Debug, Error)]
pub enum CosmosRedeemError {
    /// Task chain is not in the Cosmos custody family / not this executor's.
    #[error("ChainId {0:?} is not this executor's Cosmos chain")]
    WrongChain(ChainId),
    /// Cosmos RPC failure (account / broadcast).
    #[error("cosmos rpc: {0}")]
    Chain(#[from] CosmosChainError),
    /// Amino sign-doc construction failed (non-canonical numeric field).
    #[error("amino sign-bytes: {0}")]
    Amino(String),
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
    /// Fewer than `threshold` cosigners returned a valid partial.
    #[error("insufficient cosigners: got {got}, need {need}")]
    InsufficientCosigners {
        /// Partials collected.
        got: usize,
        /// Threshold required.
        need: usize,
    },
}

impl From<AminoError> for CosmosRedeemError {
    fn from(e: AminoError) -> Self {
        Self::Amino(e.to_string())
    }
}

/// Boxed future returned by [`CosmosCosigner::sign_cosmos_tx`].
pub type SignCosmosFuture<'a> =
    Pin<Box<dyn Future<Output = Result<[u8; 64], CosmosRedeemError>> + Send + 'a>>;

/// One cosigner — talks to one signer-daemon's `/api/v1/sign/cosmos-tx`
/// (C5) and returns the member's 64-byte compact low-S signature over the
/// amino sign-bytes. The implementation MUST verify the daemon's response
/// pubkey matches [`CosmosCosigner::member_pubkey`] (never self-reported).
pub trait CosmosCosigner: Send + Sync {
    /// The disclosed 33-byte compressed member pubkey (pinned by config).
    fn member_pubkey(&self) -> [u8; 33];

    /// POST `req` to the daemon; return the verified 64-byte signature.
    /// The daemon independently recomputes the sign-bytes from `req`
    /// (never trusting the coordinator's `sign_doc_hash`).
    fn sign_cosmos_tx<'a>(&'a self, req: &'a CosmosTxSignRequest) -> SignCosmosFuture<'a>;
}

/// Per-account in-process lock table (the account `sequence` is monotonic;
/// concurrent legs against the same account must serialise). One process
/// per account by operational policy (DL-P3.2-6 analogue).
type AccountMutexMap = HashMap<(ChainId, String), Arc<Mutex<()>>>;

#[derive(Debug, Default)]
pub struct CosmosLockTable {
    locks: Mutex<AccountMutexMap>,
}

impl CosmosLockTable {
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

/// Decoded form of one Cosmos `RedeemDispatched` event (or hand-built by
/// tests).
#[derive(Debug, Clone)]
pub struct CosmosRedeemTask {
    /// Per-adapter dispatch id (broadcast registry key).
    pub dispatch_id: B256,
    /// `IntentQueue` redemption id (F2 correlation key).
    pub redemption_id: B256,
    /// Destination chain (Cosmos family).
    pub chain: ChainId,
    /// THORChain swap memo, trusted verbatim from the contract event.
    pub memo: String,
    /// Native send amount in the micro-unit (uatom for GAIA).
    pub send_amount: u128,
}

/// Static per-executor config. One executor instance per multisig account.
#[derive(Debug, Clone)]
pub struct CosmosRedeemConfig {
    /// Destination chain this executor serves.
    pub chain: ChainId,
    /// The frozen 3-of-5 `LegacyAminoPubKey` multisig descriptor.
    pub multisig: CosmosMultisig,
    /// The multisig bech32 account address (= `multisig.account_address()`,
    /// cached so it is not re-derived per leg).
    pub account_address: String,
    /// Consensus chain-id bound into the sign-bytes (`"cosmoshub-4"`).
    pub cosmos_chain_id: String,
    /// Native micro-denom (`"uatom"`).
    pub denom: String,
    /// Fee amount in the micro-unit (caller-supplied per DL-P3.2-7).
    pub fee_amount: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Current THORChain Asgard inbound (bech32). The binary refreshes
    /// from `/thorchain/inbound_addresses` before each leg.
    pub vault: String,
}

/// Build + collect-sigs executor. Submission is the binary's job.
pub struct CosmosRedeemExecutor<C: CosmosChainClient> {
    config: CosmosRedeemConfig,
    cosmos: Arc<C>,
    cosigners: Vec<Box<dyn CosmosCosigner>>,
    lock_table: Arc<CosmosLockTable>,
}

impl<C: CosmosChainClient> std::fmt::Debug for CosmosRedeemExecutor<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CosmosRedeemExecutor")
            .field("config", &self.config)
            .field("cosigner_count", &self.cosigners.len())
            .finish_non_exhaustive()
    }
}

impl<C: CosmosChainClient> CosmosRedeemExecutor<C> {
    /// Construct. Rejects a config that is not Cosmos-family or has fewer
    /// cosigners than the multisig threshold (loud startup failure).
    ///
    /// # Errors
    /// [`CosmosRedeemError::WrongChain`] if `config.chain` is not Cosmos;
    /// [`CosmosRedeemError::InsufficientCosigners`] if too few cosigners.
    pub fn new(
        config: CosmosRedeemConfig,
        cosmos: Arc<C>,
        cosigners: Vec<Box<dyn CosmosCosigner>>,
        lock_table: Arc<CosmosLockTable>,
    ) -> Result<Self, CosmosRedeemError> {
        if config.chain.custody_family() != CustodyFamily::Cosmos {
            return Err(CosmosRedeemError::WrongChain(config.chain));
        }
        let need = config.multisig.threshold() as usize;
        if cosigners.len() < need {
            return Err(CosmosRedeemError::InsufficientCosigners {
                got: cosigners.len(),
                need,
            });
        }
        Ok(Self {
            config,
            cosmos,
            cosigners,
            lock_table,
        })
    }

    /// Borrow the config (logs / metrics at the binary callsite).
    #[must_use]
    pub fn config(&self) -> &CosmosRedeemConfig {
        &self.config
    }

    /// Build + collect-sigs for one leg. Per-account locked.
    ///
    /// # Errors
    /// Any [`CosmosRedeemError`] variant.
    pub async fn build_leg(
        &self,
        task: &CosmosRedeemTask,
    ) -> Result<CosmosRedeemLegOutcome, CosmosRedeemError> {
        if task.chain != self.config.chain {
            return Err(CosmosRedeemError::WrongChain(task.chain));
        }

        let _guard = self
            .lock_table
            .acquire(self.config.chain, self.config.account_address.clone())
            .await;

        // Fresh account_number + sequence.
        let account = self.cosmos.account(&self.config.account_address).await?;

        // Canonical-decimal strings shared by the amino doc, the wire
        // request, and the proto TxRaw — built once so they cannot diverge.
        let account_number = account.account_number.to_string();
        let sequence = account.sequence.to_string();
        let send_amount = task.send_amount.to_string();
        let fee_amount = self.config.fee_amount.to_string();
        let gas = self.config.gas_limit.to_string();

        let doc = CosmosSendSignDoc {
            account_number: &account_number,
            chain_id: &self.config.cosmos_chain_id,
            fee_amount: &fee_amount,
            gas: &gas,
            memo: &task.memo,
            from_address: &self.config.account_address,
            to_address: &self.config.vault,
            amount: &send_amount,
            denom: &self.config.denom,
        };
        let digest = doc.sign_bytes_sha256(&sequence)?;

        let req = CosmosTxSignRequest {
            chain_id: self.config.chain,
            account_address: self.config.account_address.clone(),
            cosmos_chain_id: self.config.cosmos_chain_id.clone(),
            account_number: account_number.clone(),
            sequence: sequence.clone(),
            to_address: self.config.vault.clone(),
            amount: send_amount.clone(),
            denom: self.config.denom.clone(),
            fee_amount: fee_amount.clone(),
            gas_limit: gas.clone(),
            memo: task.memo.clone(),
            sign_doc_hash: format!("0x{}", alloy_primitives::hex::encode(digest)),
        };

        let parts = self.collect_signatures(&req).await?;
        let agg = aggregate_verified(&self.config.multisig, &digest, &parts)?;

        let params = CosmosTxParams {
            from_address: &self.config.account_address,
            to_address: &self.config.vault,
            denom: &self.config.denom,
            send_amount: &send_amount,
            fee_amount: &fee_amount,
            gas_limit: self.config.gas_limit,
            memo: &task.memo,
            sequence: account.sequence,
        };
        let tx_raw = build_tx_raw(&self.config.multisig, &params, &agg);

        Ok(CosmosRedeemLegOutcome {
            chain: self.config.chain,
            tx_raw,
            sign_doc_hash: digest,
            account_address: self.config.account_address.clone(),
            sequence: account.sequence,
            dispatch_id: task.dispatch_id,
            redemption_id: task.redemption_id,
        })
    }

    /// Round-robin cosigners until threshold partials collected. A cosigner
    /// whose pinned pubkey is not a member is skipped (counted as a
    /// failure); the final [`aggregate_verified`] re-checks every partial.
    async fn collect_signatures(
        &self,
        req: &CosmosTxSignRequest,
    ) -> Result<Vec<MemberSig>, CosmosRedeemError> {
        let need = self.config.multisig.threshold() as usize;
        let mut parts: Vec<MemberSig> = Vec::with_capacity(need);
        let mut errors: Vec<CosmosRedeemError> = Vec::new();
        for cosigner in &self.cosigners {
            if parts.len() >= need {
                break;
            }
            let pubkey = cosigner.member_pubkey();
            let Some(member_index) = self.config.multisig.member_index(&pubkey) else {
                errors.push(CosmosRedeemError::MemberNotInSet(hex33(&pubkey)));
                continue;
            };
            match cosigner.sign_cosmos_tx(req).await {
                Ok(sig64) => parts.push(MemberSig {
                    member_index,
                    sig64,
                }),
                Err(e) => errors.push(e),
            }
        }
        if parts.len() < need {
            for e in &errors {
                warn!(error = %e, "cosmos cosigner failed");
            }
            return Err(CosmosRedeemError::InsufficientCosigners {
                got: parts.len(),
                need,
            });
        }
        Ok(parts)
    }
}

/// Hex of a compressed member pubkey for error messages.
fn hex33(pk: &[u8; 33]) -> String {
    format!("0x{}", alloy_primitives::hex::encode(pk))
}

/// Output of [`CosmosRedeemExecutor::build_leg`] — every input the binary
/// needs to broadcast + record the dispatch.
#[derive(Debug, Clone)]
pub struct CosmosRedeemLegOutcome {
    /// Destination chain (for the dispatch-store `chain` column).
    pub chain: ChainId,
    /// Broadcast-ready proto `TxRaw` bytes.
    pub tx_raw: Vec<u8>,
    /// The 32-byte amino sign-bytes digest the members signed.
    pub sign_doc_hash: [u8; 32],
    /// Multisig account that signed.
    pub account_address: String,
    /// Account sequence consumed by this leg.
    pub sequence: u64,
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
    use xindex_chain_cosmos::{CosmosAccount, CosmosBroadcastOutcome, CosmosTransfer};
    use xindex_cosmos_tx::sigs::to_cosmos_compact_low_s;

    fn member(seed: u8) -> (SigningKey, [u8; 33]) {
        #[expect(clippy::expect_used, reason = "test code")]
        let sk = SigningKey::from_slice(&[seed; 32]).expect("key");
        let ep = sk.verifying_key().to_encoded_point(true);
        let mut pk = [0u8; 33];
        pk.copy_from_slice(ep.as_bytes());
        (sk, pk)
    }

    /// Stub Cosmos client: fixed account, no broadcast.
    struct StubCosmos {
        account_number: u64,
        sequence: u64,
    }
    impl CosmosChainClient for StubCosmos {
        fn chain(&self) -> ChainId {
            ChainId::Gaia
        }
        #[expect(
            clippy::unnecessary_literal_bound,
            reason = "test stub returns a fixed consensus chain-id"
        )]
        fn cosmos_chain_id(&self) -> &str {
            "cosmoshub-4"
        }
        fn account(
            &self,
            _address: &str,
        ) -> impl Future<Output = Result<CosmosAccount, CosmosChainError>> + Send {
            ready(Ok(CosmosAccount {
                account_number: self.account_number,
                sequence: self.sequence,
            }))
        }
        fn latest_height(&self) -> impl Future<Output = Result<u64, CosmosChainError>> + Send {
            ready(Ok(1))
        }
        fn transfers_to(
            &self,
            _recipient: &str,
            _min_height: u64,
        ) -> impl Future<Output = Result<Vec<CosmosTransfer>, CosmosChainError>> + Send {
            ready(Ok(Vec::new()))
        }
        fn broadcast_tx_sync(
            &self,
            _tx_raw: &[u8],
        ) -> impl Future<Output = Result<CosmosBroadcastOutcome, CosmosChainError>> + Send {
            ready(Err(CosmosChainError::Rpc("not used in tests".to_string())))
        }
    }

    /// Stub cosigner: signs `req.sign_doc_hash` with a real member key, so
    /// `aggregate_verified` accepts the partial.
    struct SigningCosigner {
        sk: SigningKey,
        pubkey: [u8; 33],
    }
    impl CosmosCosigner for SigningCosigner {
        fn member_pubkey(&self) -> [u8; 33] {
            self.pubkey
        }
        fn sign_cosmos_tx<'a>(&'a self, req: &'a CosmosTxSignRequest) -> SignCosmosFuture<'a> {
            let hex = req
                .sign_doc_hash
                .strip_prefix("0x")
                .unwrap_or(&req.sign_doc_hash)
                .to_string();
            let sk = self.sk.clone();
            Box::pin(async move {
                let bytes = alloy_primitives::hex::decode(&hex).map_err(|e| {
                    CosmosRedeemError::Cosigner {
                        pubkey: "stub".to_string(),
                        message: format!("bad digest hex: {e}"),
                    }
                })?;
                let digest: [u8; 32] =
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| CosmosRedeemError::Cosigner {
                            pubkey: "stub".to_string(),
                            message: "digest not 32 bytes".to_string(),
                        })?;
                #[expect(clippy::expect_used, reason = "test code")]
                let sig: Signature = sk.sign_prehash(&digest).expect("sign");
                let mut sb = [0u8; 64];
                sb.copy_from_slice(sig.to_bytes().as_ref());
                let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
                r.copy_from_slice(&sb[..32]);
                s.copy_from_slice(&sb[32..]);
                #[expect(clippy::expect_used, reason = "test code")]
                let sig64 = to_cosmos_compact_low_s(&r, &s).expect("low-s");
                Ok(sig64)
            })
        }
    }

    /// A cosigner that always errors (transport failure).
    struct FailingCosigner {
        pubkey: [u8; 33],
    }
    impl CosmosCosigner for FailingCosigner {
        fn member_pubkey(&self) -> [u8; 33] {
            self.pubkey
        }
        fn sign_cosmos_tx<'a>(&'a self, _req: &'a CosmosTxSignRequest) -> SignCosmosFuture<'a> {
            let pk = hex33(&self.pubkey);
            Box::pin(ready(Err(CosmosRedeemError::Cosigner {
                pubkey: pk,
                message: "daemon offline".to_string(),
            })))
        }
    }

    fn descriptor_and_keys(n: u8, k: u32) -> (CosmosMultisig, Vec<(SigningKey, [u8; 33])>) {
        let keys: Vec<(SigningKey, [u8; 33])> = (1..=n).map(member).collect();
        #[expect(clippy::expect_used, reason = "test code")]
        let ms = CosmosMultisig::new(k, keys.iter().map(|(_, pk)| *pk).collect(), "cosmos")
            .expect("descriptor");
        (ms, keys)
    }

    fn config(ms: CosmosMultisig) -> CosmosRedeemConfig {
        #[expect(clippy::expect_used, reason = "test code")]
        let account_address = ms.account_address().expect("addr");
        CosmosRedeemConfig {
            chain: ChainId::Gaia,
            multisig: ms,
            account_address,
            cosmos_chain_id: "cosmoshub-4".to_string(),
            denom: "uatom".to_string(),
            fee_amount: 5_000,
            gas_limit: 200_000,
            vault: "cosmos1asgardvault".to_string(),
        }
    }

    fn task() -> CosmosRedeemTask {
        CosmosRedeemTask {
            dispatch_id: B256::repeat_byte(0xd1),
            redemption_id: B256::repeat_byte(0xd2),
            chain: ChainId::Gaia,
            memo: "=:ETH.USDT:0xdeadbeef:1000000".to_string(),
            send_amount: 5_000_000,
        }
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn build_leg_happy_path_produces_tx_raw() {
        let (ms, keys) = descriptor_and_keys(5, 3);
        let cfg = config(ms);
        // 3 real-key cosigners (members 0,1,2).
        let cosigners: Vec<Box<dyn CosmosCosigner>> = keys
            .iter()
            .take(3)
            .map(|(sk, pk)| -> Box<dyn CosmosCosigner> {
                Box::new(SigningCosigner {
                    sk: sk.clone(),
                    pubkey: *pk,
                })
            })
            .collect();
        let cosmos = Arc::new(StubCosmos {
            account_number: 42,
            sequence: 7,
        });
        let exec =
            CosmosRedeemExecutor::new(cfg, cosmos, cosigners, Arc::new(CosmosLockTable::new()))
                .expect("exec");
        let outcome = exec.build_leg(&task()).await.expect("leg");
        assert_eq!(outcome.sequence, 7);
        assert_eq!(outcome.chain, ChainId::Gaia);
        assert!(!outcome.tx_raw.is_empty());
        // TxRaw starts with field 1 (body) len-delim tag 0x0a.
        assert_eq!(outcome.tx_raw[0], 0x0a);
        assert_eq!(outcome.dispatch_id, task().dispatch_id);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn build_leg_rejects_wrong_chain() {
        let (ms, keys) = descriptor_and_keys(5, 3);
        let cfg = config(ms);
        let cosigners: Vec<Box<dyn CosmosCosigner>> = keys
            .iter()
            .take(3)
            .map(|(sk, pk)| -> Box<dyn CosmosCosigner> {
                Box::new(SigningCosigner {
                    sk: sk.clone(),
                    pubkey: *pk,
                })
            })
            .collect();
        let cosmos = Arc::new(StubCosmos {
            account_number: 1,
            sequence: 0,
        });
        let exec =
            CosmosRedeemExecutor::new(cfg, cosmos, cosigners, Arc::new(CosmosLockTable::new()))
                .expect("exec");
        let mut t = task();
        t.chain = ChainId::Btc;
        let err = exec.build_leg(&t).await.expect_err("reject");
        assert!(matches!(err, CosmosRedeemError::WrongChain(ChainId::Btc)));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn build_leg_insufficient_when_cosigners_fail() {
        let (ms, keys) = descriptor_and_keys(5, 3);
        let cfg = config(ms);
        // One real signer + two failing → only 1 < threshold 3.
        let cosigners: Vec<Box<dyn CosmosCosigner>> = vec![
            Box::new(SigningCosigner {
                sk: keys[0].0.clone(),
                pubkey: keys[0].1,
            }),
            Box::new(FailingCosigner { pubkey: keys[1].1 }),
            Box::new(FailingCosigner { pubkey: keys[2].1 }),
        ];
        let cosmos = Arc::new(StubCosmos {
            account_number: 1,
            sequence: 0,
        });
        let exec =
            CosmosRedeemExecutor::new(cfg, cosmos, cosigners, Arc::new(CosmosLockTable::new()))
                .expect("exec");
        let err = exec.build_leg(&task()).await.expect_err("reject");
        assert!(matches!(
            err,
            CosmosRedeemError::InsufficientCosigners { got: 1, need: 3 }
        ));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn constructor_rejects_too_few_cosigners() {
        let (ms, keys) = descriptor_and_keys(5, 3);
        let cfg = config(ms);
        let cosigners: Vec<Box<dyn CosmosCosigner>> = vec![Box::new(SigningCosigner {
            sk: keys[0].0.clone(),
            pubkey: keys[0].1,
        })];
        let cosmos = Arc::new(StubCosmos {
            account_number: 1,
            sequence: 0,
        });
        let err =
            CosmosRedeemExecutor::new(cfg, cosmos, cosigners, Arc::new(CosmosLockTable::new()))
                .expect_err("construct");
        assert!(matches!(
            err,
            CosmosRedeemError::InsufficientCosigners { got: 1, need: 3 }
        ));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn lock_table_serialises_same_account() {
        let table = Arc::new(CosmosLockTable::new());
        let g1 = table.acquire(ChainId::Gaia, "acct".to_string()).await;
        let t = Arc::clone(&table);
        let h = tokio::spawn(async move {
            let _g2 = t.acquire(ChainId::Gaia, "acct".to_string()).await;
            "g2"
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!h.is_finished(), "second acquire must block");
        drop(g1);
        assert_eq!(h.await.expect("join"), "g2");
    }
}
