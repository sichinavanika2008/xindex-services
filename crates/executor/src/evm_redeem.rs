//! V7 — EVM-side redeem leg executor (Phase 3.2).
//!
//! Builds + signs (3-of-5) the Safe v1.4.1 `execTransaction` that sends
//! native_X from our Safe to the THORChain Router with the
//! contract-emitted swap memo (`=:ETH.USDT:<indexToken>:<minOut>`).
//! THORChain then swaps native_X → USDT and delivers to the IndexToken
//! on Ethereum (where the existing `xindex-attest-redeem` flow attests
//! delivery).
//!
//! ## Pipeline (per leg)
//!
//! 1. Acquire per-Safe in-process lock (concurrent legs against the
//!    same Safe race on the monotonic nonce — serialise them).
//! 2. Read `Safe.nonce()` fresh from chain via [`EvmChainClient`].
//! 3. Construct [`SafeTransaction`] targeting the Router with the
//!    `depositWithExpiry(vault, address(0), amount, memo, expiry)`
//!    ABI calldata + `value = amount_wei` so the Router forwards
//!    native value to the Asgard vault.
//! 4. Compute `safeTxHash` via [`xindex_safe_evm::digest::safe_tx_hash`].
//! 5. Round-robin collect ≥ threshold signatures from configured
//!    [`EvmCosigner`]s.
//! 6. Aggregate sigs (sort ascending by recovered signer, concat 65-byte
//!    sigs) via [`xindex_safe_evm::sigs::aggregate_signatures`].
//! 7. Build `execTransaction(...)` ABI calldata via
//!    [`xindex_safe_evm::exec::build_exec_transaction_calldata`].
//! 8. Return [`EvmRedeemLegOutcome`] — the caller (V7 binary) signs the
//!    wrapper EOA tx and submits via [`EvmChainClient::submit_raw`].
//!
//! ## Why split build vs submit
//!
//! The executor library does NOT hold the submitter EOA key. The binary
//! wires that via an alloy `WalletProvider` (or its production HSM
//! equivalent). Keeps key material out of the library; makes the
//! library trivially testable with mock cosigners.

#![expect(
    clippy::doc_markdown,
    reason = "module-level: many SafeTransaction / IndexToken / THORChain / \
              ChainId / EvmCosigner identifiers — per-identifier backticks \
              add noise without aiding parsing"
)]

use std::collections::HashMap;
use std::sync::Arc;

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{sol, SolCall};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::warn;
use xindex_chain_evm::{build_safe_exec_tx_request, EvmChainClient, EvmChainError, EvmTxFee};
use xindex_safe_evm::{
    digest::{safe_tx_hash, SafeTransaction},
    exec::build_exec_transaction_calldata,
    sigs::{aggregate_signatures, AggregateError, EcdsaSig, SignedBy},
    SafeOperation,
};
use xindex_shared::chain_registry::ChainId;

sol! {
    /// THORChain Router v6.1 `depositWithExpiry`. Same ABI on every
    /// Phase 3.2 EVM chain (Bifrost deploys the identical Router on
    /// ETH / BSC / AVAX / BASE / POL).
    function depositWithExpiry(
        address payable vault,
        address asset,
        uint256 amount,
        string memo,
        uint256 expiry
    ) external payable;
}

/// Errors surfaced by V7 executor.
#[derive(Debug, Error)]
pub enum EvmRedeemError {
    /// Task's chain is not in the EVM custody family.
    #[error("ChainId {0:?} is not in the EVM family")]
    NotEvmChain(ChainId),
    /// THORChain Router address not registered for this chain (V1
    /// registry placeholder until per-chain deployment ceremony).
    #[error("no THORChain Router address registered for chain {0:?}")]
    NoRouterAddress(ChainId),
    /// EVM RPC failure (safe_nonce / get_block_number / submit).
    #[error("chain rpc: {0}")]
    Chain(#[from] EvmChainError),
    /// Signature aggregation failed (duplicate signer, non-canonical v,
    /// or recovery mismatch).
    #[error("signature aggregation: {0}")]
    Aggregate(#[from] AggregateError),
    /// A cosigner returned an error (transport / daemon refusal).
    #[error("cosigner {signer:#x}: {message}")]
    Cosigner { signer: Address, message: String },
    /// Less than `threshold` cosigners returned a valid signature.
    #[error("insufficient cosigners: got {got}, need {need}")]
    InsufficientCosigners { got: usize, need: usize },
    /// A cosigner is configured with a `signer_address` that isn't in
    /// the Safe's owner set. This is a deploy-time misconfiguration —
    /// the Safe's `checkSignatures` would reject the sig later.
    #[error("cosigner {signer:#x} is not in the Safe owner set")]
    SignerNotInOwnerSet { signer: Address },
}

/// Decoded form of one EVM `RedeemDispatched` event (or hand-built by
/// tests). Carries every input the executor needs to build the Safe tx.
#[derive(Debug, Clone)]
pub struct EvmRedeemTask {
    /// Per-adapter unique dispatch id (broadcast registry key).
    pub dispatch_id: B256,
    /// `IntentQueue` redemption id (F2 correlation key for the
    /// attestation flow).
    pub redemption_id: B256,
    /// Destination chain (EVM family).
    pub chain: ChainId,
    /// THORChain swap memo (`=:ETH.USDT:<indexToken>:<minOut>`),
    /// trusted verbatim from the contract event.
    pub memo: String,
    /// Native amount in wei (1e18 base for the EVM family).
    pub amount_wei: U256,
}

/// Boxed future returned by [`EvmCosigner::sign_safe_tx`]. Object-safe
/// trait dispatch requires erasing the concrete async-fn future; aliased
/// here so the trait signature stays readable.
pub type SignSafeTxFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<EcdsaSig, EvmRedeemError>> + Send + 'a>,
>;

/// One cosigner — talks to one signer-daemon's
/// `/api/v1/sign/evm-safe-tx` endpoint (V5) and returns the 65-byte
/// EOA signature over the Safe digest. Static dispatch — production
/// passes `Box<dyn EvmCosigner>` for ergonomic config.
pub trait EvmCosigner: Send + Sync {
    /// Disclosed signer address (`Set A` per ceremony). Pinned by
    /// config; the implementation MUST verify the daemon's response
    /// matches this — never trust the daemon to self-report its key.
    fn signer_address(&self) -> Address;

    /// Sign the `safeTxHash` digest. The caller hands over the full
    /// SafeTransaction inputs so the daemon recomputes the digest
    /// independently (DL-M5-3 — daemon never trusts coordinator-
    /// supplied hashes).
    fn sign_safe_tx<'a>(
        &'a self,
        chain: ChainId,
        safe_address: Address,
        tx: &'a SafeTransaction,
        safe_tx_hash: B256,
        fee_wei: u128,
    ) -> SignSafeTxFuture<'a>;
}

/// Per-Safe in-process lock table. The Safe's `nonce()` is monotonic;
/// two concurrent legs that both read nonce N and build a tx will
/// collide (only one can succeed; the other reverts with `Safe::
/// InvalidNonce`). This table serialises `safe_nonce → build → submit`
/// per `(chain, safe)`.
///
/// Plan §V7 specifies a SQLite advisory lock; in-process Mutex
/// suffices for the single-process executor design (DL-P3.2-6: separate
/// binary per Safe). Cross-process concurrency is forbidden by
/// operational policy.
/// Per-Safe key → reentrant-acquire mutex (one `Arc<Mutex<()>>` slot
/// per `(chain, safe)`).
type SafeMutexMap = HashMap<(ChainId, Address), Arc<Mutex<()>>>;

#[derive(Debug, Default)]
pub struct SafeLockTable {
    locks: tokio::sync::Mutex<SafeMutexMap>,
}

impl SafeLockTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquire the per-Safe lock. Returns an owned guard that releases
    /// on drop.
    pub async fn acquire(&self, chain: ChainId, safe: Address) -> tokio::sync::OwnedMutexGuard<()> {
        let mutex = {
            let mut table = self.locks.lock().await;
            Arc::clone(
                table
                    .entry((chain, safe))
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        mutex.lock_owned().await
    }
}

/// Static per-executor configuration. One executor instance per Safe
/// per chain (DL-P3.2-6).
#[derive(Debug, Clone)]
pub struct EvmRedeemConfig {
    /// The destination chain this executor serves.
    pub chain: ChainId,
    /// Safe v1.4.1 proxy address on `chain`.
    pub safe_address: Address,
    /// Configured Safe owners (sorted ascending — Safe invariant).
    pub safe_owners: Vec<Address>,
    /// k-of-n threshold the Safe requires (3 for our 3-of-5).
    pub safe_threshold: u8,
    /// Per-tx fee parameters (caller-supplied per DL-P3.2-7).
    pub fee: EvmTxFee,
    /// THORChain Asgard vault address on this chain (rotates;
    /// the binary refreshes from the inbound-addresses registry
    /// before each leg).
    pub vault: Address,
    /// Seconds-from-now `depositWithExpiry` expiry. THORChain rejects
    /// expiries less than 60 minutes out; 2 hours is the default.
    pub expiry_offset_secs: u64,
    /// EOA address of the submitter that will sign + broadcast the
    /// wrapper transaction. Bound here so the resulting
    /// `TransactionRequest` already names `from`; the binary plugs in
    /// the signing wallet at that boundary.
    pub submitter_address: Address,
}

/// Build + collect-sigs executor. Holds chain RPC client + cosigner
/// fleet + per-Safe lock table. Submission is the BINARY's
/// responsibility (see `xindex-redeem-evm`).
pub struct EvmRedeemExecutor<E: EvmChainClient> {
    config: EvmRedeemConfig,
    evm: Arc<E>,
    cosigners: Vec<Box<dyn EvmCosigner>>,
    lock_table: Arc<SafeLockTable>,
}

impl<E: EvmChainClient> std::fmt::Debug for EvmRedeemExecutor<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvmRedeemExecutor")
            .field("config", &self.config)
            .field("cosigner_count", &self.cosigners.len())
            .finish_non_exhaustive()
    }
}

impl<E: EvmChainClient> EvmRedeemExecutor<E> {
    /// Construct.
    ///
    /// # Errors
    /// [`EvmRedeemError::InsufficientCosigners`] if fewer cosigners
    /// than `config.safe_threshold`.
    pub fn new(
        config: EvmRedeemConfig,
        evm: Arc<E>,
        cosigners: Vec<Box<dyn EvmCosigner>>,
        lock_table: Arc<SafeLockTable>,
    ) -> Result<Self, EvmRedeemError> {
        if cosigners.len() < usize::from(config.safe_threshold) {
            return Err(EvmRedeemError::InsufficientCosigners {
                got: cosigners.len(),
                need: usize::from(config.safe_threshold),
            });
        }
        Ok(Self {
            config,
            evm,
            cosigners,
            lock_table,
        })
    }

    /// Borrow the executor's configuration. Useful for the binary
    /// callsite to render logs / metrics.
    #[must_use]
    pub fn config(&self) -> &EvmRedeemConfig {
        &self.config
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn build_router_calldata(&self, amount_wei: U256, memo: &str, expiry: U256) -> Bytes {
        let call = depositWithExpiryCall {
            vault: self.config.vault,
            asset: Address::ZERO,
            amount: amount_wei,
            memo: memo.to_string(),
            expiry,
        };
        Bytes::from(call.abi_encode())
    }

    /// Execute the build + collect-sigs portion of one leg. Per-Safe
    /// locked. Caller signs the wrapper tx (using
    /// [`EvmRedeemLegOutcome::to_tx_request`]) and submits via
    /// [`EvmChainClient::submit_raw`].
    ///
    /// # Errors
    /// Any [`EvmRedeemError`] variant.
    pub async fn build_leg(
        &self,
        task: &EvmRedeemTask,
    ) -> Result<EvmRedeemLegOutcome, EvmRedeemError> {
        if task.chain != self.config.chain {
            return Err(EvmRedeemError::NotEvmChain(task.chain));
        }
        let router = task
            .chain
            .thorchain_router_address()
            .ok_or(EvmRedeemError::NoRouterAddress(task.chain))?;
        let evm_chain_id = task
            .chain
            .evm_chain_id()
            .ok_or(EvmRedeemError::NotEvmChain(task.chain))?;

        // Per-Safe serialization.
        let _guard = self
            .lock_table
            .acquire(self.config.chain, self.config.safe_address)
            .await;

        // Read fresh nonce.
        let nonce_u64 = self.evm.safe_nonce(self.config.safe_address).await?;
        let nonce = U256::from(nonce_u64);

        // Build SafeTransaction.
        let expiry = U256::from(Self::now_secs().saturating_add(self.config.expiry_offset_secs));
        let router_calldata = self.build_router_calldata(task.amount_wei, &task.memo, expiry);
        let safe_tx = SafeTransaction {
            to: router,
            value: task.amount_wei,
            data: router_calldata,
            operation: SafeOperation::Call,
            safe_tx_gas: U256::ZERO,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce,
        };
        let digest = safe_tx_hash(evm_chain_id, self.config.safe_address, &safe_tx);

        // Collect signatures.
        let parts = self.collect_signatures(&safe_tx, digest).await?;

        // Aggregate.
        let sig_blob = aggregate_signatures(digest, &parts)?;
        let exec_calldata = build_exec_transaction_calldata(&safe_tx, sig_blob);

        Ok(EvmRedeemLegOutcome {
            chain: self.config.chain,
            safe_tx,
            safe_tx_hash: digest,
            exec_calldata,
            nonce: nonce_u64,
            fee: self.config.fee,
            evm_chain_id,
            from: self.config.submitter_address,
            safe_address: self.config.safe_address,
            dispatch_id: task.dispatch_id,
            redemption_id: task.redemption_id,
        })
    }

    /// Round-robin every configured cosigner until threshold reached
    /// or all exhausted.
    async fn collect_signatures(
        &self,
        safe_tx: &SafeTransaction,
        digest: B256,
    ) -> Result<Vec<SignedBy>, EvmRedeemError> {
        let need = usize::from(self.config.safe_threshold);
        let mut parts: Vec<SignedBy> = Vec::with_capacity(need);
        let mut errors: Vec<EvmRedeemError> = Vec::new();
        let fee_wei = u128::from(self.config.fee.gas_limit) * self.config.fee.max_fee_per_gas;
        for cosigner in &self.cosigners {
            if parts.len() >= need {
                break;
            }
            let signer = cosigner.signer_address();
            if !self.config.safe_owners.contains(&signer) {
                errors.push(EvmRedeemError::SignerNotInOwnerSet { signer });
                continue;
            }
            match cosigner
                .sign_safe_tx(
                    self.config.chain,
                    self.config.safe_address,
                    safe_tx,
                    digest,
                    fee_wei,
                )
                .await
            {
                Ok(sig) => parts.push(SignedBy { signer, sig }),
                Err(e) => errors.push(e),
            }
        }
        if parts.len() < need {
            for e in &errors {
                warn!(error = %e, "cosigner failed");
            }
            return Err(EvmRedeemError::InsufficientCosigners {
                got: parts.len(),
                need,
            });
        }
        Ok(parts)
    }
}

/// The output of [`EvmRedeemExecutor::build_leg`] — every input the
/// binary needs to sign + submit the wrapper transaction.
#[derive(Debug, Clone)]
pub struct EvmRedeemLegOutcome {
    /// The destination chain (for logs + dispatch-store recording).
    pub chain: ChainId,
    /// SafeTransaction that was signed.
    pub safe_tx: SafeTransaction,
    /// The keccak-256 digest the cosigners signed.
    pub safe_tx_hash: B256,
    /// `execTransaction(...)` calldata (signatures already embedded).
    pub exec_calldata: Bytes,
    /// Safe nonce consumed by this leg.
    pub nonce: u64,
    /// Per-tx fee parameters (carried for the binary's tx assembly).
    pub fee: EvmTxFee,
    /// EVM chain_id for the EIP-155 / EIP-1559 envelope.
    pub evm_chain_id: u64,
    /// Submitter EOA (already in `TransactionRequest::from`).
    pub from: Address,
    /// Safe proxy address (= `TransactionRequest::to`).
    pub safe_address: Address,
    /// Originating dispatch id (broadcast registry key).
    pub dispatch_id: B256,
    /// Originating redemption id (attestation correlation).
    pub redemption_id: B256,
}

impl EvmRedeemLegOutcome {
    /// Build the wrapper `TransactionRequest` ready for signing +
    /// submission via [`EvmChainClient::submit_raw`]. Returns `None`
    /// if `chain` isn't an EVM family chain (impossible by construction
    /// — `build_leg` enforces — but the helper is `Option`-returning).
    #[must_use]
    pub fn to_tx_request(&self) -> Option<alloy::rpc::types::TransactionRequest> {
        build_safe_exec_tx_request(
            self.chain,
            self.from,
            self.safe_address,
            self.exec_calldata.clone(),
            self.fee,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use std::sync::Mutex as StdMutex;
    use xindex_chain_evm::{
        EvmChainError, EvmConfirmedReceipt, EvmLogEntry, EvmLogFilter, EvmTransactionSummary,
    };
    use xindex_shared::chain_registry::EvmTxType;

    /// In-memory EvmChainClient. Returns a configurable nonce on
    /// `safe_nonce`; everything else stubbed.
    #[derive(Debug)]
    struct StubEvm {
        chain: ChainId,
        nonce: StdMutex<u64>,
    }

    impl StubEvm {
        fn new(chain: ChainId, nonce: u64) -> Self {
            Self {
                chain,
                nonce: StdMutex::new(nonce),
            }
        }
    }

    impl EvmChainClient for StubEvm {
        fn chain(&self) -> ChainId {
            self.chain
        }
        fn evm_chain_id(&self) -> u64 {
            #[expect(clippy::expect_used, reason = "test code")]
            self.chain.evm_chain_id().expect("evm")
        }
        fn tx_type(&self) -> EvmTxType {
            #[expect(clippy::expect_used, reason = "test code")]
            self.chain.tx_type().expect("evm")
        }
        async fn block_number(&self) -> Result<u64, EvmChainError> {
            Ok(0)
        }
        async fn safe_nonce(&self, _safe: Address) -> Result<u64, EvmChainError> {
            #[expect(clippy::expect_used, reason = "test code")]
            Ok(*self.nonce.lock().expect("lock"))
        }
        async fn eth_call(&self, _to: Address, _data: Bytes) -> Result<Bytes, EvmChainError> {
            Ok(Bytes::new())
        }
        async fn eth_get_transaction_by_hash(
            &self,
            _hash: B256,
        ) -> Result<Option<EvmTransactionSummary>, EvmChainError> {
            Ok(None)
        }
        async fn eth_get_logs(
            &self,
            _filter: EvmLogFilter,
        ) -> Result<Vec<EvmLogEntry>, EvmChainError> {
            Ok(Vec::new())
        }
        async fn submit_raw(&self, _raw: Bytes) -> Result<B256, EvmChainError> {
            Ok(B256::ZERO)
        }
        async fn wait_for_confirmations(
            &self,
            _hash: B256,
            _depth: u32,
            _timeout: std::time::Duration,
        ) -> Result<EvmConfirmedReceipt, EvmChainError> {
            unreachable!()
        }
    }

    /// Deterministic test cosigner: produces a 65-byte signature
    /// derived from the digest. NOT a real ECDSA sig; aggregator
    /// rejects via recovery cross-check, so we wire a closure-driven
    /// cosigner that exposes the (signer, EcdsaSig) it'd return.
    struct StubCosigner {
        signer: Address,
        sig_factory: Box<dyn Fn(B256) -> Result<EcdsaSig, EvmRedeemError> + Send + Sync>,
    }

    impl StubCosigner {
        fn ok_with_sig(signer: Address, sig: EcdsaSig) -> Self {
            Self {
                signer,
                sig_factory: Box::new(move |_d| Ok(sig)),
            }
        }
        fn fail(signer: Address, message: &str) -> Self {
            let m = message.to_string();
            Self {
                signer,
                sig_factory: Box::new(move |_d| {
                    Err(EvmRedeemError::Cosigner {
                        signer,
                        message: m.clone(),
                    })
                }),
            }
        }
    }

    impl EvmCosigner for StubCosigner {
        fn signer_address(&self) -> Address {
            self.signer
        }
        fn sign_safe_tx<'a>(
            &'a self,
            _chain: ChainId,
            _safe: Address,
            _tx: &'a SafeTransaction,
            digest: B256,
            _fee_wei: u128,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<EcdsaSig, EvmRedeemError>> + Send + 'a>,
        > {
            let result = (self.sig_factory)(digest);
            Box::pin(async move { result })
        }
    }

    /// Bespoke cosigner shared by `build_leg_happy_path_meets_threshold`:
    /// signs whatever digest is given using k1, so the aggregator's
    /// recovery cross-check passes.
    struct K1Cosigner {
        key_byte: u8,
        signer: Address,
    }
    impl EvmCosigner for K1Cosigner {
        fn signer_address(&self) -> Address {
            self.signer
        }
        fn sign_safe_tx<'a>(
            &'a self,
            _chain: ChainId,
            _safe: Address,
            _tx: &'a SafeTransaction,
            digest: B256,
            _fee_wei: u128,
        ) -> SignSafeTxFuture<'a> {
            let kb = self.key_byte;
            Box::pin(async move {
                let (_addr, sig) = k1_sign(digest, kb);
                Ok(sig)
            })
        }
    }

    /// k1-derived signing helper — produces a REAL ECDSA sig for the
    /// digest using a deterministic key, so the aggregator's recovery
    /// cross-check passes. Used by tests that exercise the full
    /// aggregate path.
    fn k1_sign(digest: B256, key_byte: u8) -> (Address, EcdsaSig) {
        use k256::ecdsa::{RecoveryId, Signature, SigningKey};
        #[expect(clippy::expect_used, reason = "test code")]
        let key = SigningKey::from_bytes(&[key_byte; 32].into()).expect("k256");
        #[expect(clippy::expect_used, reason = "test code")]
        let (sig, rec_id): (Signature, RecoveryId) = key
            .sign_prehash_recoverable(digest.as_slice())
            .expect("sign");
        let r: [u8; 32] = sig.r().to_bytes().into();
        let s: [u8; 32] = sig.s().to_bytes().into();
        let v = 27 + rec_id.to_byte();
        let vk = key.verifying_key();
        let pk = vk.to_encoded_point(false);
        let hash = alloy_primitives::keccak256(&pk.as_bytes()[1..]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash.as_slice()[12..]);
        (
            Address::from(addr),
            EcdsaSig {
                r: B256::from(r),
                s: B256::from(s),
                v,
            },
        )
    }

    fn dummy_fee() -> EvmTxFee {
        EvmTxFee {
            gas_limit: 300_000,
            max_fee_per_gas: 50_000_000_000,
            max_priority_fee_per_gas: 1_500_000_000,
            gas_price: 5_000_000_000,
        }
    }

    fn cfg_with_owners(owners: Vec<Address>) -> EvmRedeemConfig {
        EvmRedeemConfig {
            chain: ChainId::Eth,
            safe_address: Address::new([0xab; 20]),
            safe_owners: owners,
            safe_threshold: 2,
            fee: dummy_fee(),
            vault: Address::new([0xde; 20]),
            expiry_offset_secs: 7200,
            submitter_address: Address::new([0xee; 20]),
        }
    }

    fn dummy_task(chain: ChainId, amount: u128) -> EvmRedeemTask {
        EvmRedeemTask {
            dispatch_id: B256::repeat_byte(0xd1),
            redemption_id: B256::repeat_byte(0xd2),
            chain,
            memo: "=:ETH.USDT:0xdeadbeef:1000000000".to_string(),
            amount_wei: U256::from(amount),
        }
    }

    /// Happy path: enough valid sigs → outcome carries the
    /// execTransaction calldata.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn build_leg_happy_path_meets_threshold() {
        let task = dummy_task(ChainId::Eth, 1_000_000_000_000_000_000);
        let cfg_chain = task.chain;
        let safe = Address::new([0xab; 20]);
        let evm = Arc::new(StubEvm::new(cfg_chain, 7));
        let router = cfg_chain.thorchain_router_address().expect("router");
        let vault = Address::new([0xde; 20]);
        let expiry = U256::from(0u64); // we'll re-derive in cfg, not in test sig
                                       // We need REAL k1 sigs that recover correctly for the executor
                                       // to aggregate. Use k1_sign over the same digest the executor
                                       // will compute.
        let amount = task.amount_wei;
        let memo = task.memo.clone();
        // Build the same SafeTransaction the executor will, with the
        // executor's nonce=7. `expiry` is now+7200; we re-derive
        // approximately via std::time::now. Since the test re-uses the
        // digest WE compute (digest fed to k1_sign), the executor's
        // recomputation must yield the same digest. Easiest: capture
        // by snapshotting now first.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("now")
            .as_secs();
        let _ = (router, vault, expiry, amount, memo, now);

        // Strategy: configure the executor with a vault we control,
        // and intercept the digest INSIDE the cosigner — we sign
        // whatever digest the executor hands us, using k1_sign keyed
        // on signer-A and signer-B. The aggregator then recovers each
        // sig to the matching address.
        let (signer_a_init, _) = k1_sign(B256::ZERO, 0xa1);
        let (signer_b_init, _) = k1_sign(B256::ZERO, 0xa2);
        let cfg = EvmRedeemConfig {
            chain: cfg_chain,
            safe_address: safe,
            safe_owners: vec![signer_a_init, signer_b_init],
            safe_threshold: 2,
            fee: dummy_fee(),
            vault,
            expiry_offset_secs: 7200,
            submitter_address: Address::new([0xee; 20]),
        };

        let cosigners: Vec<Box<dyn EvmCosigner>> = vec![
            Box::new(K1Cosigner {
                key_byte: 0xa1,
                signer: signer_a_init,
            }),
            Box::new(K1Cosigner {
                key_byte: 0xa2,
                signer: signer_b_init,
            }),
        ];
        let lock = Arc::new(SafeLockTable::new());
        let exec = EvmRedeemExecutor::new(cfg, evm, cosigners, lock).expect("exec");
        let outcome = exec.build_leg(&task).await.expect("ok");
        assert_eq!(outcome.nonce, 7);
        assert_eq!(outcome.evm_chain_id, 1);
        assert_eq!(outcome.safe_address, safe);
        assert_eq!(outcome.dispatch_id, task.dispatch_id);
        // `exec_calldata` starts with the `execTransaction` selector.
        assert_eq!(&outcome.exec_calldata[..4], &[0x6a, 0x76, 0x12, 0x02]);
        // The carried request is a valid 1559 envelope.
        let req = outcome.to_tx_request().expect("req");
        assert_eq!(req.chain_id, Some(1));
        assert!(req.max_fee_per_gas.is_some());
    }

    /// Task chain ≠ executor chain → NotEvmChain.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn build_leg_rejects_wrong_chain() {
        let evm = Arc::new(StubEvm::new(ChainId::Eth, 0));
        let cfg = cfg_with_owners(vec![Address::new([0x01; 20]), Address::new([0x02; 20])]);
        let cosigners: Vec<Box<dyn EvmCosigner>> = vec![
            Box::new(StubCosigner::ok_with_sig(
                Address::new([0x01; 20]),
                EcdsaSig {
                    r: B256::ZERO,
                    s: B256::ZERO,
                    v: 27,
                },
            )),
            Box::new(StubCosigner::ok_with_sig(
                Address::new([0x02; 20]),
                EcdsaSig {
                    r: B256::ZERO,
                    s: B256::ZERO,
                    v: 27,
                },
            )),
        ];
        let lock = Arc::new(SafeLockTable::new());
        let exec = EvmRedeemExecutor::new(cfg, evm, cosigners, lock).expect("exec");
        // BSC task to an ETH executor.
        let mut task = dummy_task(ChainId::Bsc, 1);
        task.amount_wei = U256::from(1u64);
        let err = exec.build_leg(&task).await.expect_err("should reject");
        assert!(matches!(err, EvmRedeemError::NotEvmChain(_)));
    }

    /// Cosigner with signer not in Safe owner set → that one is
    /// skipped + counted against the available pool. With only 1 valid
    /// + threshold 2 → InsufficientCosigners.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn build_leg_rejects_signer_not_in_owner_set() {
        let valid = Address::new([0x01; 20]);
        let bogus = Address::new([0xff; 20]);
        let cfg = cfg_with_owners(vec![valid, Address::new([0x02; 20])]);
        let evm = Arc::new(StubEvm::new(cfg.chain, 0));
        let cosigners: Vec<Box<dyn EvmCosigner>> = vec![
            Box::new(StubCosigner::ok_with_sig(
                valid,
                EcdsaSig {
                    r: B256::ZERO,
                    s: B256::ZERO,
                    v: 27,
                },
            )),
            Box::new(StubCosigner::ok_with_sig(
                bogus,
                EcdsaSig {
                    r: B256::ZERO,
                    s: B256::ZERO,
                    v: 27,
                },
            )),
        ];
        let lock = Arc::new(SafeLockTable::new());
        let exec = EvmRedeemExecutor::new(cfg, evm, cosigners, lock).expect("exec");
        let task = dummy_task(ChainId::Eth, 1);
        let err = exec.build_leg(&task).await.expect_err("should reject");
        assert!(matches!(
            err,
            EvmRedeemError::InsufficientCosigners { got: 1, need: 2 }
        ));
    }

    /// Cosigner returns an error → counted as failure, threshold not
    /// met → InsufficientCosigners.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn build_leg_aggregates_cosigner_failures() {
        let cfg = cfg_with_owners(vec![Address::new([0x01; 20]), Address::new([0x02; 20])]);
        let evm = Arc::new(StubEvm::new(cfg.chain, 0));
        let cosigners: Vec<Box<dyn EvmCosigner>> = vec![
            Box::new(StubCosigner::fail(Address::new([0x01; 20]), "boom")),
            Box::new(StubCosigner::fail(Address::new([0x02; 20]), "boom")),
        ];
        let lock = Arc::new(SafeLockTable::new());
        let exec = EvmRedeemExecutor::new(cfg, evm, cosigners, lock).expect("exec");
        let task = dummy_task(ChainId::Eth, 1);
        let err = exec.build_leg(&task).await.expect_err("should reject");
        assert!(matches!(
            err,
            EvmRedeemError::InsufficientCosigners { got: 0, need: 2 }
        ));
    }

    /// Cosigner count < threshold at construction time → constructor
    /// rejects (defence: we want loud config failure at startup, not
    /// silent under-collection at runtime).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn constructor_rejects_insufficient_cosigners() {
        let cfg = cfg_with_owners(vec![Address::new([0x01; 20]), Address::new([0x02; 20])]);
        let evm = Arc::new(StubEvm::new(cfg.chain, 0));
        let cosigners: Vec<Box<dyn EvmCosigner>> = vec![
            // Only one — threshold is 2.
            Box::new(StubCosigner::ok_with_sig(
                Address::new([0x01; 20]),
                EcdsaSig {
                    r: B256::ZERO,
                    s: B256::ZERO,
                    v: 27,
                },
            )),
        ];
        let lock = Arc::new(SafeLockTable::new());
        let err = EvmRedeemExecutor::new(cfg, evm, cosigners, lock).expect_err("construct");
        assert!(matches!(
            err,
            EvmRedeemError::InsufficientCosigners { got: 1, need: 2 }
        ));
    }

    /// Lock table serialises two concurrent acquires against the same
    /// `(chain, safe)`. Second `acquire` blocks until first guard drops.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn lock_table_serialises_per_safe() {
        let table = Arc::new(SafeLockTable::new());
        let g1 = table.acquire(ChainId::Eth, Address::new([0x01; 20])).await;
        // Spawn a task that tries to acquire the same key.
        let t = Arc::clone(&table);
        let h = tokio::spawn(async move {
            let _g2 = t.acquire(ChainId::Eth, Address::new([0x01; 20])).await;
            "g2"
        });
        // Give the second task time to attempt the acquire.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!h.is_finished(), "second acquire must block");
        drop(g1);
        let out = h.await.expect("join");
        assert_eq!(out, "g2");
    }

    /// Different `(chain, safe)` keys do NOT block each other.
    #[tokio::test]
    async fn lock_table_independent_per_key() {
        let table = Arc::new(SafeLockTable::new());
        let _g1 = table.acquire(ChainId::Eth, Address::new([0x01; 20])).await;
        // A different chain should be free.
        let _g2 = table.acquire(ChainId::Bsc, Address::new([0x01; 20])).await;
        // A different safe on the same chain should also be free.
        let _g3 = table.acquire(ChainId::Eth, Address::new([0x02; 20])).await;
    }
}
