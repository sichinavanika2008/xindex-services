//! S5 — Solana-side redeem leg executor (Squads V4, Phase 4.5).
//!
//! Sends native SOL from our Squads V4 vault to the user's own Solana
//! address. Unlike the single-tx XRP / Cosmos legs, a Squads redemption is
//! a `1 + threshold + 1` on-chain choreography, so this executor is a
//! DRIVER (it broadcasts + confirms), not a pure builder:
//!
//! ```text
//! tx1  vault_transaction_create + proposal_create   (proposer = cosigner[0])
//! tx2..tx(1+T)  proposal_approve                     (T distinct members)
//! final  vault_transaction_execute                   (executor = cosigner[0])
//! ```
//!
//! Each step is its own Solana message, fresh blockhash, single ed25519
//! signer, confirmed before the next. WHICH step to run is derived from
//! the on-chain proposal account (the chain is the witness), so a
//! mid-flight restart resumes correctly. The only local state is the
//! `redemption_id → transaction_index` binding (allocated once, write-ahead)
//! and the per-step 2h `signerCacheExpiry` cache — see
//! [`crate::solana_redeem_store`].
//!
//! Proposer + executor are `cosigner[0]` (must be available); approvals are
//! fault-tolerant (a failing approver is skipped, fatal only below
//! threshold). Proposer/executor fallback is a documented follow-on
//! (`KNOWN_FINDINGS` P-SOL-5).

#![expect(
    clippy::doc_markdown,
    reason = "module-level: many Squads / THORChain / Proposal / VaultTransaction \
              identifiers — per-identifier backticks add noise without aiding parsing"
)]

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::{hex, B256};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::warn;
use xindex_chain_solana::{ProposalState, SolanaChainClient, SolanaChainError};
use xindex_shared::chain_registry::{ChainId, CustodyFamily};
use xindex_shared::signer_wire::{SolanaTxKind, SolanaTxSignRequest};
use xindex_solana_tx::message::Message;
use xindex_solana_tx::{base58, message, sigs, squads, Pubkey, SolanaTxError};

use crate::solana_redeem_store::{SolanaRedeemStore, SolanaStoreError};

/// The 2h `signerCacheExpiry` window (THORChain Bifrost `const n`). Within
/// it a step is never re-signed; after it, only if an on-chain lookup
/// shows the tx did NOT land.
const SIGNER_CACHE_EXPIRY_SECS: u64 = 2 * 60 * 60;

/// Solana base fee per signature (lamports) — added to the redemption
/// amount for the pre-flight vault-balance check.
const SOL_BASE_FEE_LAMPORTS: u64 = 5_000;

/// Errors surfaced by the S5 Solana redeem executor.
#[derive(Debug, Error)]
pub enum SolanaRedeemError {
    /// Task chain is not this executor's Solana chain.
    #[error("ChainId {0:?} is not this executor's Solana chain")]
    WrongChain(ChainId),
    /// Solana RPC failure.
    #[error("solana rpc: {0}")]
    Chain(#[from] SolanaChainError),
    /// Message / PDA build failure.
    #[error("solana tx build: {0}")]
    Build(#[from] SolanaTxError),
    /// Recovery-store failure.
    #[error("store: {0}")]
    Store(#[from] SolanaStoreError),
    /// A base58 address did not decode.
    #[error("address: {0}")]
    Address(String),
    /// A numeric value did not fit its on-wire width.
    #[error("out-of-range numeric: {0}")]
    Numeric(String),
    /// A cosigner returned an error (transport / daemon refusal / bad sig).
    #[error("cosigner {pubkey}: {message}")]
    Cosigner {
        /// Base58 of the cosigner's pinned member pubkey.
        pubkey: String,
        /// Failure detail.
        message: String,
    },
    /// A cosigner's pinned member is not in the configured member set.
    #[error("cosigner pubkey {0} is not in the configured member set")]
    MemberNotInSet(String),
    /// The on-chain threshold disagrees with the configured one.
    #[error("on-chain threshold {chain} != configured {cfg}")]
    ThresholdMismatch {
        /// On-chain multisig threshold.
        chain: u16,
        /// Configured threshold.
        cfg: u16,
    },
    /// Fewer than `threshold` members could be collected to approve.
    #[error("insufficient approvers: reached {got} of {need}")]
    InsufficientApprovers {
        /// Approvals collected.
        got: u16,
        /// Threshold required.
        need: u16,
    },
    /// The vault lacks the lamports to fund the redemption + fee.
    #[error("vault balance {have} < required {need} lamports")]
    InsufficientVaultBalance {
        /// Vault balance.
        have: u64,
        /// Required (amount + base fee).
        need: u64,
    },
    /// A broadcast transaction failed on-chain.
    #[error("tx {sig} failed on-chain at step {step}")]
    TxFailed {
        /// The step.
        step: String,
        /// The base58 signature.
        sig: String,
    },
    /// A broadcast transaction did not confirm within the timeout.
    #[error("tx {sig} not confirmed within timeout at step {step}")]
    ConfirmTimeout {
        /// The step.
        step: String,
        /// The base58 signature.
        sig: String,
    },
    /// The proposal is in an unexpected state for the current step.
    #[error("proposal in unexpected state {0:?} at step {1}")]
    UnexpectedProposalState(ProposalState, String),
    /// A step was broadcast within the 2h window but is not yet observed
    /// on-chain and the RPC lookup is uncertain — never re-sign.
    #[error("signer-cache guard: step {0} broadcast within 2h, not yet observed")]
    CacheGuard(String),
    /// The system clock is before the unix epoch.
    #[error("system clock before unix epoch")]
    Clock,
}

impl SolanaRedeemError {
    /// `true` for errors that mean "this particular cosigner/attempt
    /// failed" — skippable in the approve loop, fatal as create/execute.
    fn is_skippable(&self) -> bool {
        matches!(
            self,
            Self::Cosigner { .. } | Self::TxFailed { .. } | Self::ConfirmTimeout { .. }
        )
    }
}

/// One member's ed25519 signature over one specific Solana message.
#[derive(Debug, Clone)]
pub struct SolanaMemberSig {
    /// The 32-byte ed25519 member pubkey that produced the signature.
    pub member_pubkey: Pubkey,
    /// The 64-byte ed25519 signature over the serialized message.
    pub signature: [u8; 64],
}

/// Boxed future returned by [`SolanaCosigner::sign_solana_tx`].
pub type SignSolanaFuture<'a> =
    Pin<Box<dyn Future<Output = Result<SolanaMemberSig, SolanaRedeemError>> + Send + 'a>>;

/// One cosigner — talks to one signer-daemon's `/api/v1/sign/solana-tx`
/// (S6). Invoked once PER on-chain tx that this member must sign. The
/// daemon re-derives + validates the message before ed25519-signing; the
/// impl MUST verify the response pubkey matches
/// [`SolanaCosigner::member_pubkey`] (never self-reported).
pub trait SolanaCosigner: Send + Sync {
    /// The disclosed 32-byte ed25519 member pubkey (pinned by config).
    fn member_pubkey(&self) -> Pubkey;

    /// POST `req` to the daemon; return the verified signature.
    fn sign_solana_tx<'a>(&'a self, req: &'a SolanaTxSignRequest) -> SignSolanaFuture<'a>;
}

/// Per-multisig in-process lock table (the `transaction_index` allocation
/// is racey across concurrent redemptions; serialise on the multisig).
type AccountMutexMap = HashMap<(ChainId, String), Arc<Mutex<()>>>;

/// Serialises redemptions against the same multisig.
#[derive(Debug, Default)]
pub struct SolanaLockTable {
    locks: Mutex<AccountMutexMap>,
}

impl SolanaLockTable {
    /// Construct an empty lock table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquire the per-multisig lock; releases on guard drop.
    pub async fn acquire(
        &self,
        chain: ChainId,
        multisig: String,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        let mutex = {
            let mut table = self.locks.lock().await;
            Arc::clone(
                table
                    .entry((chain, multisig))
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        mutex.lock_owned().await
    }
}

/// Decoded form of one Solana `RedeemDispatched` event.
#[derive(Debug, Clone)]
pub struct SolanaRedeemTask {
    /// Per-adapter dispatch id.
    pub dispatch_id: B256,
    /// `IntentQueue` redemption id (the idempotency / recovery key).
    pub redemption_id: B256,
    /// Destination chain (Solana family).
    pub chain: ChainId,
    /// THORChain swap memo, verbatim from the contract event.
    pub memo: String,
    /// Native send amount in lamports.
    pub send_amount: u128,
    /// The user's own Solana address (base58) — the transfer destination.
    pub destination: String,
}

/// Static per-executor config. One executor instance per multisig.
#[derive(Debug, Clone)]
pub struct SolanaRedeemConfig {
    /// Destination chain this executor serves.
    pub chain: ChainId,
    /// The Squads multisig PDA.
    pub multisig_pda: Pubkey,
    /// The vault index (always 0 for Xindex).
    pub vault_index: u8,
    /// The frozen member set.
    pub members: Vec<Pubkey>,
    /// The approval threshold (re-checked against the on-chain value).
    pub threshold: u16,
    /// Poll interval while awaiting a transaction's confirmation.
    pub confirm_poll: Duration,
    /// Maximum time to await a transaction's confirmation.
    pub confirm_timeout: Duration,
}

/// Output of [`SolanaRedeemExecutor::execute_redeem`].
#[derive(Debug, Clone)]
pub struct SolanaRedeemLegOutcome {
    /// Destination chain (for the dispatch-store `chain` column).
    pub chain: ChainId,
    /// The Squads transaction index this redemption used.
    pub transaction_index: u64,
    /// The base58 signature of the execute tx (the settlement proof).
    pub execute_signature: String,
    /// The multisig the leg ran against.
    pub multisig_pda: Pubkey,
    /// Originating dispatch id.
    pub dispatch_id: B256,
    /// Originating redemption id.
    pub redemption_id: B256,
}

/// The Squads V4 redeem driver.
pub struct SolanaRedeemExecutor<C: SolanaChainClient, S: SolanaRedeemStore> {
    config: SolanaRedeemConfig,
    sol: Arc<C>,
    cosigners: Vec<Box<dyn SolanaCosigner>>,
    store: Arc<S>,
    lock_table: Arc<SolanaLockTable>,
}

impl<C: SolanaChainClient, S: SolanaRedeemStore> std::fmt::Debug for SolanaRedeemExecutor<C, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SolanaRedeemExecutor")
            .field("config", &self.config)
            .field("cosigner_count", &self.cosigners.len())
            .finish_non_exhaustive()
    }
}

impl<C: SolanaChainClient, S: SolanaRedeemStore> SolanaRedeemExecutor<C, S> {
    /// Construct. Rejects a non-Solana config, too few cosigners, or a
    /// cosigner whose member is not in the configured set.
    ///
    /// # Errors
    /// [`SolanaRedeemError::WrongChain`], [`SolanaRedeemError::InsufficientApprovers`]
    /// (fewer cosigners than threshold), or [`SolanaRedeemError::MemberNotInSet`].
    pub fn new(
        config: SolanaRedeemConfig,
        sol: Arc<C>,
        cosigners: Vec<Box<dyn SolanaCosigner>>,
        store: Arc<S>,
        lock_table: Arc<SolanaLockTable>,
    ) -> Result<Self, SolanaRedeemError> {
        if config.chain.custody_family() != CustodyFamily::Solana {
            return Err(SolanaRedeemError::WrongChain(config.chain));
        }
        let have = u16::try_from(cosigners.len()).unwrap_or(u16::MAX);
        if have < config.threshold || cosigners.is_empty() {
            return Err(SolanaRedeemError::InsufficientApprovers {
                got: have,
                need: config.threshold,
            });
        }
        for c in &cosigners {
            let m = c.member_pubkey();
            if !config.members.contains(&m) {
                return Err(SolanaRedeemError::MemberNotInSet(m.to_base58()));
            }
        }
        Ok(Self {
            config,
            sol,
            cosigners,
            store,
            lock_table,
        })
    }

    /// Borrow the config.
    #[must_use]
    pub fn config(&self) -> &SolanaRedeemConfig {
        &self.config
    }

    /// Drive one redemption to its executed `vault_transaction`. Per-multisig
    /// locked; resumes from on-chain state.
    ///
    /// # Errors
    /// Any [`SolanaRedeemError`] variant.
    pub async fn execute_redeem(
        &self,
        task: &SolanaRedeemTask,
    ) -> Result<SolanaRedeemLegOutcome, SolanaRedeemError> {
        if task.chain != self.config.chain {
            return Err(SolanaRedeemError::WrongChain(task.chain));
        }
        let _guard = self
            .lock_table
            .acquire(self.config.chain, self.config.multisig_pda.to_base58())
            .await;

        let ms = self
            .sol
            .get_multisig_account(&self.config.multisig_pda)
            .await?;
        if ms.threshold != self.config.threshold {
            return Err(SolanaRedeemError::ThresholdMismatch {
                chain: ms.threshold,
                cfg: self.config.threshold,
            });
        }

        let transaction_index = self.allocate_index(task, ms.transaction_index).await?;

        // Fast-path: already executed (recovered).
        if let Some(progress) = self.store.load(&task.redemption_id).await? {
            if let Some(sig) = progress.execute_signature {
                return Ok(self.outcome(task, transaction_index, sig));
            }
        }

        let (vault, _) = squads::vault_pda(&self.config.multisig_pda, self.config.vault_index)?;
        let (proposal, _) = squads::proposal_pda(&self.config.multisig_pda, transaction_index)?;
        let destination = Pubkey::from_base58(&task.destination)
            .map_err(|e| SolanaRedeemError::Address(format!("destination {e}")))?;
        let lamports = u64::try_from(task.send_amount).map_err(|_| {
            SolanaRedeemError::Numeric(format!("amount > u64: {}", task.send_amount))
        })?;

        // Pre-flight: the vault must hold the amount + fee.
        let balance = self.sol.get_balance(&vault).await?;
        let need = lamports.saturating_add(SOL_BASE_FEE_LAMPORTS);
        if balance < need {
            return Err(SolanaRedeemError::InsufficientVaultBalance {
                have: balance,
                need,
            });
        }

        let memo = if task.memo.is_empty() {
            None
        } else {
            Some(task.memo.as_str())
        };
        let inner = squads::compile_redemption_inner_message(&vault, &destination, lamports, memo)?;

        // ── CREATE + PROPOSE ──
        if self.sol.get_proposal_state(&proposal).await? == ProposalState::None {
            self.run_create(task, transaction_index, &inner).await?;
        }

        // ── APPROVE until threshold ──
        let mut failed: HashSet<[u8; 32]> = HashSet::new();
        loop {
            let status = self.sol.get_proposal_state(&proposal).await?;
            match status {
                ProposalState::Approved | ProposalState::Executed | ProposalState::Executing => {
                    break
                }
                ProposalState::Active { approved } => {
                    let Some(idx) = self.pick_approver(&approved, &failed) else {
                        return Err(SolanaRedeemError::InsufficientApprovers {
                            got: u16::try_from(approved.len()).unwrap_or(u16::MAX),
                            need: self.config.threshold,
                        });
                    };
                    let member = self.cosigners[idx].member_pubkey();
                    if let Err(e) = self.run_approve(task, transaction_index, idx).await {
                        if e.is_skippable() {
                            warn!(error = %e, member = %member, "solana approver failed; skipping");
                            failed.insert(member.to_bytes());
                        } else {
                            return Err(e);
                        }
                    }
                }
                other => {
                    return Err(SolanaRedeemError::UnexpectedProposalState(
                        other,
                        "approve".to_string(),
                    ))
                }
            }
        }

        // ── EXECUTE ──
        let exec_sig = self.run_execute(task, transaction_index, &inner).await?;
        self.store
            .mark_executed(&task.redemption_id, &exec_sig)
            .await?;
        Ok(self.outcome(task, transaction_index, exec_sig))
    }

    /// Allocate (or resume) the redemption's `transaction_index`,
    /// write-ahead, before any broadcast.
    async fn allocate_index(
        &self,
        task: &SolanaRedeemTask,
        on_chain_last: u64,
    ) -> Result<u64, SolanaRedeemError> {
        if let Some(progress) = self.store.load(&task.redemption_id).await? {
            return Ok(progress.transaction_index);
        }
        let idx = on_chain_last.saturating_add(1);
        if self
            .store
            .reserve(&task.redemption_id, &self.config.multisig_pda, idx)
            .await?
        {
            return Ok(idx);
        }
        // Lost a concurrent reservation race — re-load the winner's index.
        self.store
            .load(&task.redemption_id)
            .await?
            .map(|p| p.transaction_index)
            .ok_or_else(|| {
                SolanaRedeemError::Store(SolanaStoreError::Decode(
                    "reserve lost but no row present".to_string(),
                ))
            })
    }

    /// Index of a cosigner whose member has not approved and has not failed.
    fn pick_approver(&self, approved: &[Pubkey], failed: &HashSet<[u8; 32]>) -> Option<usize> {
        self.cosigners.iter().position(|c| {
            let m = c.member_pubkey();
            !approved.contains(&m) && !failed.contains(&m.to_bytes())
        })
    }

    /// tx1: `vault_transaction_create` + `proposal_create` by `cosigner[0]`.
    async fn run_create(
        &self,
        task: &SolanaRedeemTask,
        transaction_index: u64,
        inner: &squads::InnerMessage,
    ) -> Result<(), SolanaRedeemError> {
        let proposer = self.cosigners[0].member_pubkey();
        let (transaction, _) =
            squads::transaction_pda(&self.config.multisig_pda, transaction_index)?;
        let (proposal, _) = squads::proposal_pda(&self.config.multisig_pda, transaction_index)?;
        let blockhash = self.sol.recent_blockhash().await?;
        let create_ix = squads::VaultTransactionCreate {
            multisig: self.config.multisig_pda,
            transaction,
            creator: proposer,
            rent_payer: proposer,
            vault_index: self.config.vault_index,
            ephemeral_signers: 0,
            transaction_message: &inner.bytes,
            memo: if task.memo.is_empty() {
                None
            } else {
                Some(task.memo.as_str())
            },
        }
        .instruction();
        let propose_ix = squads::ProposalCreate {
            multisig: self.config.multisig_pda,
            proposal,
            creator: proposer,
            rent_payer: proposer,
            transaction_index,
            draft: false,
        }
        .instruction();
        let msg = Message::new_legacy(&proposer, blockhash, &[create_ix, propose_ix])?;
        let req = self.build_req(
            SolanaTxKind::Create,
            proposer,
            transaction_index,
            &blockhash,
            &msg,
            task,
        )?;
        self.sign_send_confirm(task, transaction_index, "create", 0, msg, req)
            .await?;
        Ok(())
    }

    /// One `proposal_approve` by `cosigner[idx]`.
    async fn run_approve(
        &self,
        task: &SolanaRedeemTask,
        transaction_index: u64,
        idx: usize,
    ) -> Result<(), SolanaRedeemError> {
        let member = self.cosigners[idx].member_pubkey();
        let (proposal, _) = squads::proposal_pda(&self.config.multisig_pda, transaction_index)?;
        let blockhash = self.sol.recent_blockhash().await?;
        let ix = squads::proposal_approve_ix(self.config.multisig_pda, member, proposal, None);
        let msg = Message::new_legacy(&member, blockhash, &[ix])?;
        let req = self.build_req(
            SolanaTxKind::Approve,
            member,
            transaction_index,
            &blockhash,
            &msg,
            task,
        )?;
        let step = format!("approve:{}", member.to_base58());
        self.sign_send_confirm(task, transaction_index, &step, idx, msg, req)
            .await?;
        Ok(())
    }

    /// The final `vault_transaction_execute` by `cosigner[0]`.
    async fn run_execute(
        &self,
        task: &SolanaRedeemTask,
        transaction_index: u64,
        inner: &squads::InnerMessage,
    ) -> Result<String, SolanaRedeemError> {
        let executor = self.cosigners[0].member_pubkey();
        let (transaction, _) =
            squads::transaction_pda(&self.config.multisig_pda, transaction_index)?;
        let (proposal, _) = squads::proposal_pda(&self.config.multisig_pda, transaction_index)?;
        let blockhash = self.sol.recent_blockhash().await?;
        let ix = squads::vault_transaction_execute_ix(
            self.config.multisig_pda,
            proposal,
            transaction,
            executor,
            &inner.remaining_accounts,
        );
        let msg = Message::new_legacy(&executor, blockhash, &[ix])?;
        let req = self.build_req(
            SolanaTxKind::Execute,
            executor,
            transaction_index,
            &blockhash,
            &msg,
            task,
        )?;
        self.sign_send_confirm(task, transaction_index, "execute", 0, msg, req)
            .await
    }

    /// Build the daemon sign request for `kind`. Inner fields are included
    /// for Create + Execute (the daemon re-validates the transfer), omitted
    /// for Approve.
    fn build_req(
        &self,
        kind: SolanaTxKind,
        member: Pubkey,
        transaction_index: u64,
        blockhash: &[u8; 32],
        msg: &Message,
        task: &SolanaRedeemTask,
    ) -> Result<SolanaTxSignRequest, SolanaRedeemError> {
        let message_bytes = msg.serialize()?;
        let include_inner = matches!(kind, SolanaTxKind::Create | SolanaTxKind::Execute);
        Ok(SolanaTxSignRequest {
            chain_id: self.config.chain,
            tx_kind: kind,
            multisig_pda: self.config.multisig_pda.to_base58(),
            member_pubkey: member.to_base58(),
            transaction_index: transaction_index.to_string(),
            recent_blockhash: base58::encode(blockhash),
            vault_index: include_inner.then_some(self.config.vault_index),
            inner_destination: include_inner.then(|| task.destination.clone()),
            inner_amount_lamports: include_inner.then(|| task.send_amount.to_string()),
            memo: if include_inner && !task.memo.is_empty() {
                Some(task.memo.clone())
            } else {
                None
            },
            message_hex: format!("0x{}", hex::encode(&message_bytes)),
        })
    }

    /// Cache-guarded sign → assemble → broadcast → confirm of one step.
    /// Returns the base58 transaction signature.
    async fn sign_send_confirm(
        &self,
        task: &SolanaRedeemTask,
        transaction_index: u64,
        step: &str,
        cosigner_idx: usize,
        msg: Message,
        req: SolanaTxSignRequest,
    ) -> Result<String, SolanaRedeemError> {
        let message_bytes = msg.serialize()?;

        // 2h signerCacheExpiry guard (per step).
        if let Some(cached) = self
            .store
            .cache_get(&task.redemption_id, transaction_index, step)
            .await?
        {
            let now = now_secs()?;
            if now.saturating_sub(cached.broadcast_at_unix) < SIGNER_CACHE_EXPIRY_SECS {
                // Within window: NEVER re-sign. Confirm the cached broadcast.
                self.confirm(step, &cached.signature).await?;
                return Ok(cached.signature);
            }
            // Expired: re-sign ONLY if an on-chain lookup shows it did NOT land.
            match self.sol.get_signature_status(&cached.signature).await? {
                Some(s) if s.confirmed() => return Ok(cached.signature),
                None => {
                    self.store
                        .cache_clear(&task.redemption_id, transaction_index, step)
                        .await?;
                }
                _ => return Err(SolanaRedeemError::CacheGuard(step.to_string())),
            }
        }

        let pinned = self.cosigners[cosigner_idx].member_pubkey();
        let part = self.cosigners[cosigner_idx].sign_solana_tx(&req).await?;
        if part.member_pubkey != pinned {
            return Err(SolanaRedeemError::Cosigner {
                pubkey: pinned.to_base58(),
                message: "daemon returned a different member pubkey".to_string(),
            });
        }
        sigs::verify(&pinned, &message_bytes, &part.signature).map_err(|e| {
            SolanaRedeemError::Cosigner {
                pubkey: pinned.to_base58(),
                message: format!("returned an invalid signature: {e}"),
            }
        })?;
        let signature_b58 = base58::encode(&part.signature);
        let tx = message::serialize_transaction(&message_bytes, &[part.signature])?;

        // Write-ahead cache BEFORE the irreversible broadcast.
        self.store
            .cache_set(
                &task.redemption_id,
                transaction_index,
                step,
                &signature_b58,
                now_secs()?,
            )
            .await?;
        let onchain_sig = self.sol.send_transaction(&tx).await?;
        self.confirm(step, &onchain_sig).await?;
        Ok(onchain_sig)
    }

    /// Poll a signature to confirmation, or fail on on-chain error / timeout.
    async fn confirm(&self, step: &str, sig: &str) -> Result<(), SolanaRedeemError> {
        let mut waited = Duration::ZERO;
        loop {
            if let Some(status) = self.sol.get_signature_status(sig).await? {
                if status.err {
                    return Err(SolanaRedeemError::TxFailed {
                        step: step.to_string(),
                        sig: sig.to_string(),
                    });
                }
                if status.confirmed() {
                    return Ok(());
                }
            }
            if waited >= self.config.confirm_timeout {
                return Err(SolanaRedeemError::ConfirmTimeout {
                    step: step.to_string(),
                    sig: sig.to_string(),
                });
            }
            tokio::time::sleep(self.config.confirm_poll).await;
            waited = waited.saturating_add(self.config.confirm_poll);
        }
    }

    fn outcome(
        &self,
        task: &SolanaRedeemTask,
        transaction_index: u64,
        execute_signature: String,
    ) -> SolanaRedeemLegOutcome {
        SolanaRedeemLegOutcome {
            chain: self.config.chain,
            transaction_index,
            execute_signature,
            multisig_pda: self.config.multisig_pda,
            dispatch_id: task.dispatch_id,
            redemption_id: task.redemption_id,
        }
    }
}

/// Wall-clock unix seconds.
fn now_secs() -> Result<u64, SolanaRedeemError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| SolanaRedeemError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::ready;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use xindex_chain_solana::{MultisigAccount, SignatureStatus, SolanaTransfer};
    use xindex_solana_tx::sigs as solsigs;

    use crate::solana_redeem_store::InMemorySolanaRedeemStore;

    fn member(seed: u8) -> ([u8; 32], Pubkey) {
        let s = [seed; 32];
        (s, solsigs::pubkey_from_seed(&s))
    }

    /// Stateful stub chain client: the proposal advances as txs are sent,
    /// driven by the Squads discriminator found in the broadcast bytes.
    struct StubChain {
        threshold: u16,
        last_index: u64,
        state: Mutex<ProposalState>,
    }

    impl StubChain {
        fn new(threshold: u16) -> Self {
            Self {
                threshold,
                last_index: 10,
                state: Mutex::new(ProposalState::None),
            }
        }
        fn preset(threshold: u16, state: ProposalState) -> Self {
            Self {
                threshold,
                last_index: 10,
                state: Mutex::new(state),
            }
        }
    }

    /// The fee payer (approver / proposer) is account_keys[0]: after the
    /// 1-byte sig count + 64-byte sig + 3 header bytes + 1-byte shortvec
    /// account count, the first 32 bytes.
    fn fee_payer_of(tx: &[u8]) -> Pubkey {
        let off = 1 + 64 + 3 + 1;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&tx[off..off + 32]);
        Pubkey::new(arr)
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    impl SolanaChainClient for StubChain {
        fn chain(&self) -> ChainId {
            ChainId::Sol
        }
        fn recent_blockhash(
            &self,
        ) -> impl Future<Output = Result<[u8; 32], SolanaChainError>> + Send {
            ready(Ok([7u8; 32]))
        }
        fn get_multisig_account(
            &self,
            _multisig: &Pubkey,
        ) -> impl Future<Output = Result<MultisigAccount, SolanaChainError>> + Send {
            ready(Ok(MultisigAccount {
                threshold: self.threshold,
                time_lock: 0,
                transaction_index: self.last_index,
                stale_transaction_index: 0,
            }))
        }
        fn get_proposal_state(
            &self,
            _proposal: &Pubkey,
        ) -> impl Future<Output = Result<ProposalState, SolanaChainError>> + Send {
            let state = self.state.try_lock().map(|g| g.clone());
            ready(state.map_err(|_| SolanaChainError::Rpc("locked".into())))
        }
        fn send_transaction(
            &self,
            signed_tx: &[u8],
        ) -> impl Future<Output = Result<String, SolanaChainError>> + Send {
            // Advance the proposal state by the discriminator present.
            let Ok(mut g) = self.state.try_lock() else {
                return ready(Err(SolanaChainError::Rpc("locked".into())));
            };
            if contains(
                signed_tx,
                &squads::discriminator("vault_transaction_create"),
            ) {
                *g = ProposalState::Active { approved: vec![] };
            } else if contains(signed_tx, &squads::discriminator("proposal_approve")) {
                let approver = fee_payer_of(signed_tx);
                if let ProposalState::Active { approved } = &mut *g {
                    if !approved.contains(&approver) {
                        approved.push(approver);
                    }
                    if u16::try_from(approved.len()).unwrap_or(u16::MAX) >= self.threshold {
                        *g = ProposalState::Approved;
                    }
                }
            } else if contains(
                signed_tx,
                &squads::discriminator("vault_transaction_execute"),
            ) {
                *g = ProposalState::Executed;
            }
            // The signature is the base58 of the first ed25519 sig.
            ready(Ok(base58::encode(&signed_tx[1..65])))
        }
        fn get_signature_status(
            &self,
            _signature: &str,
        ) -> impl Future<Output = Result<Option<SignatureStatus>, SolanaChainError>> + Send
        {
            ready(Ok(Some(SignatureStatus {
                slot: 1,
                confirmations: None,
                confirmation_status: Some("finalized".to_string()),
                err: false,
            })))
        }
        fn get_balance(
            &self,
            _address: &Pubkey,
        ) -> impl Future<Output = Result<u64, SolanaChainError>> + Send {
            ready(Ok(1_000_000_000_000))
        }
        fn transfers_to(
            &self,
            _vault: &str,
            _min_slot: u64,
        ) -> impl Future<Output = Result<Vec<SolanaTransfer>, SolanaChainError>> + Send {
            ready(Ok(Vec::new()))
        }
    }

    /// Stub cosigner: signs `message_hex` with its ed25519 key.
    struct SigningCosigner {
        seed: [u8; 32],
        pubkey: Pubkey,
        calls: Arc<AtomicUsize>,
    }
    impl SolanaCosigner for SigningCosigner {
        fn member_pubkey(&self) -> Pubkey {
            self.pubkey
        }
        fn sign_solana_tx<'a>(&'a self, req: &'a SolanaTxSignRequest) -> SignSolanaFuture<'a> {
            let seed = self.seed;
            let pubkey = self.pubkey;
            let calls = Arc::clone(&self.calls);
            let body = req.message_hex.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                let h = body.strip_prefix("0x").unwrap_or(&body);
                let bytes = hex::decode(h).map_err(|e| SolanaRedeemError::Cosigner {
                    pubkey: "stub".to_string(),
                    message: format!("bad hex: {e}"),
                })?;
                Ok(SolanaMemberSig {
                    member_pubkey: pubkey,
                    signature: solsigs::sign(&seed, &bytes),
                })
            })
        }
    }

    /// Stub cosigner that always errors.
    struct FailingCosigner {
        pubkey: Pubkey,
    }
    impl SolanaCosigner for FailingCosigner {
        fn member_pubkey(&self) -> Pubkey {
            self.pubkey
        }
        fn sign_solana_tx<'a>(&'a self, _req: &'a SolanaTxSignRequest) -> SignSolanaFuture<'a> {
            Box::pin(ready(Err(SolanaRedeemError::Cosigner {
                pubkey: self.pubkey.to_base58(),
                message: "daemon offline".to_string(),
            })))
        }
    }

    fn config(threshold: u16, members: &[Pubkey]) -> SolanaRedeemConfig {
        SolanaRedeemConfig {
            chain: ChainId::Sol,
            multisig_pda: Pubkey::new([0x42; 32]),
            vault_index: 0,
            members: members.to_vec(),
            threshold,
            confirm_poll: Duration::from_millis(0),
            confirm_timeout: Duration::from_millis(50),
        }
    }

    fn task() -> SolanaRedeemTask {
        SolanaRedeemTask {
            dispatch_id: B256::repeat_byte(0xd1),
            redemption_id: B256::repeat_byte(0xd2),
            chain: ChainId::Sol,
            memo: "=:ETH.USDT:0xabc:1".to_string(),
            send_amount: 2_000_000_000,
            destination: Pubkey::new([0x99; 32]).to_base58(),
        }
    }

    fn signing_cosigners(
        seeds: &[u8],
    ) -> (Vec<Box<dyn SolanaCosigner>>, Vec<Pubkey>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut cosigners: Vec<Box<dyn SolanaCosigner>> = Vec::new();
        let mut pubs = Vec::new();
        for &s in seeds {
            let (seed, pk) = member(s);
            pubs.push(pk);
            cosigners.push(Box::new(SigningCosigner {
                seed,
                pubkey: pk,
                calls: Arc::clone(&calls),
            }));
        }
        (cosigners, pubs, calls)
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn happy_path_runs_create_approvals_execute() {
        let (cosigners, members, _calls) = signing_cosigners(&[1, 2, 3, 4, 5]);
        let cfg = config(3, &members);
        let chain = Arc::new(StubChain::new(3));
        let store = Arc::new(InMemorySolanaRedeemStore::new());
        let exec = SolanaRedeemExecutor::new(
            cfg,
            chain,
            cosigners,
            Arc::clone(&store),
            Arc::new(SolanaLockTable::new()),
        )
        .expect("exec");
        let outcome = exec.execute_redeem(&task()).await.expect("redeem");
        assert_eq!(outcome.chain, ChainId::Sol);
        assert_eq!(outcome.transaction_index, 11); // last 10 + 1
        assert!(!outcome.execute_signature.is_empty());
        // The store recorded the execute signature (idempotent re-run path).
        let progress = store
            .load(&task().redemption_id)
            .await
            .expect("load")
            .expect("present");
        assert_eq!(progress.execute_signature, Some(outcome.execute_signature));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rejects_wrong_chain() {
        let (cosigners, members, _) = signing_cosigners(&[1, 2, 3]);
        let exec = SolanaRedeemExecutor::new(
            config(3, &members),
            Arc::new(StubChain::new(3)),
            cosigners,
            Arc::new(InMemorySolanaRedeemStore::new()),
            Arc::new(SolanaLockTable::new()),
        )
        .expect("exec");
        let mut t = task();
        t.chain = ChainId::Btc;
        let err = exec.execute_redeem(&t).await.expect_err("reject");
        assert!(matches!(err, SolanaRedeemError::WrongChain(ChainId::Btc)));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rejects_threshold_mismatch() {
        let (cosigners, members, _) = signing_cosigners(&[1, 2, 3]);
        // Config says 3, chain says 4.
        let exec = SolanaRedeemExecutor::new(
            config(3, &members),
            Arc::new(StubChain::new(4)),
            cosigners,
            Arc::new(InMemorySolanaRedeemStore::new()),
            Arc::new(SolanaLockTable::new()),
        )
        .expect("exec");
        let err = exec.execute_redeem(&task()).await.expect_err("reject");
        assert!(matches!(
            err,
            SolanaRedeemError::ThresholdMismatch { chain: 4, cfg: 3 }
        ));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn insufficient_approvers_when_daemons_fail() {
        // 3-of-5: proposer cosigner[0] signs (create), but only 2 honest
        // approvers available → can't reach 3.
        let (s0, p0) = member(1);
        let (_s1, p1) = member(2);
        let (_s2, p2) = member(3);
        let (s3, p3) = member(4);
        let (s4, p4) = member(5);
        let members = vec![p0, p1, p2, p3, p4];
        let calls = Arc::new(AtomicUsize::new(0));
        let cosigners: Vec<Box<dyn SolanaCosigner>> = vec![
            Box::new(SigningCosigner {
                seed: s0,
                pubkey: p0,
                calls: Arc::clone(&calls),
            }),
            Box::new(FailingCosigner { pubkey: p1 }),
            Box::new(FailingCosigner { pubkey: p2 }),
            Box::new(SigningCosigner {
                seed: s3,
                pubkey: p3,
                calls: Arc::clone(&calls),
            }),
            Box::new(SigningCosigner {
                seed: s4,
                pubkey: p4,
                calls: Arc::clone(&calls),
            }),
        ];
        // p0, p3, p4 sign; that's 3 → actually succeeds. Make threshold 4
        // so only 3 honest can't reach it.
        let exec = SolanaRedeemExecutor::new(
            config(4, &members),
            Arc::new(StubChain::new(4)),
            cosigners,
            Arc::new(InMemorySolanaRedeemStore::new()),
            Arc::new(SolanaLockTable::new()),
        )
        .expect("exec");
        let err = exec.execute_redeem(&task()).await.expect_err("reject");
        assert!(matches!(
            err,
            SolanaRedeemError::InsufficientApprovers { need: 4, .. }
        ));
    }

    /// Recovery: the proposal is already Approved on-chain and the index is
    /// already reserved → the executor skips straight to execute (no
    /// create, no approvals).
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn resume_from_approved_goes_straight_to_execute() {
        let (cosigners, members, calls) = signing_cosigners(&[1, 2, 3]);
        let chain = Arc::new(StubChain::preset(3, ProposalState::Approved));
        let store = Arc::new(InMemorySolanaRedeemStore::new());
        // Pre-reserve the index (as if a prior run created+approved).
        store
            .reserve(&task().redemption_id, &Pubkey::new([0x42; 32]), 11)
            .await
            .expect("reserve");
        let exec = SolanaRedeemExecutor::new(
            config(3, &members),
            chain,
            cosigners,
            Arc::clone(&store),
            Arc::new(SolanaLockTable::new()),
        )
        .expect("exec");
        let outcome = exec.execute_redeem(&task()).await.expect("redeem");
        assert_eq!(outcome.transaction_index, 11);
        // Exactly ONE sign call — only the execute tx.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Cache guard: a step broadcast within the 2h window is NOT re-signed
    /// — the executor confirms the cached signature instead.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn cache_guard_skips_resign_within_window() {
        let (cosigners, members, calls) = signing_cosigners(&[1, 2, 3]);
        let chain = Arc::new(StubChain::preset(3, ProposalState::Approved));
        let store = Arc::new(InMemorySolanaRedeemStore::new());
        let rid = task().redemption_id;
        store
            .reserve(&rid, &Pubkey::new([0x42; 32]), 11)
            .await
            .expect("reserve");
        // Pre-cache the execute step as broadcast just now.
        let now = now_secs().expect("now");
        store
            .cache_set(&rid, 11, "execute", "CACHEDSIG", now)
            .await
            .expect("cache");
        let exec = SolanaRedeemExecutor::new(
            config(3, &members),
            chain,
            cosigners,
            Arc::clone(&store),
            Arc::new(SolanaLockTable::new()),
        )
        .expect("exec");
        let outcome = exec.execute_redeem(&task()).await.expect("redeem");
        // The cached signature is returned; no sign call happened.
        assert_eq!(outcome.execute_signature, "CACHEDSIG");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
