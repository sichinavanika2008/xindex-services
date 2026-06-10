#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_statements,
    clippy::print_stdout,
    reason = "integration test — panics on fixture failure are appropriate; \
              inline-use keeps each test self-contained"
)]
//! V9 — End-to-end EVM redeem leg integration test (Phase 3.2).
//!
//! Spins up THREE real `xindex-signer-daemon` instances on local TCP
//! ports — each holding a distinct k1 key via a software-backed
//! `HsmDigestSigner` — and drives the V7 `EvmRedeemExecutor`
//! against them through real HTTP via the production-shape
//! `RemoteEvmCosigner`. No mocks at any layer; the produced
//! `execTransaction` calldata is the bytes a real submitter would
//! broadcast.
//!
//! ## What this test covers
//!
//! 1. **Wire roundtrip** — `EvmSafeTxSignRequest` ABI fields posted by
//!    the cosigner; the daemon decodes, recomputes `safeTxHash` from
//!    the inputs, signs via the HSM, and returns the 65-byte sig.
//! 2. **3-of-5 collection** — three daemons concurrently respond; the
//!    executor's round-robin reaches threshold and aggregates via
//!    `xindex_safe_evm::sigs::aggregate_signatures`. Sort-by-recovered-
//!    signer + recovery cross-check pass against REAL k1 sigs.
//! 3. **Idempotent replay** — the same task re-run hits the daemons'
//!    in-memory replay store + returns the cached signature byte-
//!    for-byte. HSM `invocations` counter increments only on first
//!    pass.
//! 4. **Conflict detection** — a second task with the same nonce but
//!    different memo produces a different digest → 409
//!    `conflict_already_signed_different` → executor reports
//!    `InsufficientCosigners`.
//!
//! ## On-chain submission
//!
//! Skipped at this layer. The plan's broader §V9 anvil-fork + Safe
//! deployment is gated by `FORK_RPC_ETH` env (not implemented in this
//! cut — leaves the `#[ignore]` placeholder for the next pass).
//!
//! ## File location
//!
//! Plan §V9 specifies `crates/executor/tests/evm_redeem_e2e.rs`, but
//! `xindex-executor` cannot dev-depend on `xindex-signer-daemon`
//! (`signer-daemon`'s dev-deps already pull in `executor` — cargo
//! forbids dev-dep cycles). The integration test lives in
//! `signer-daemon/tests/` where the wiring direction already works.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{Address, Bytes, B256, U256};
use xindex_chain_evm::{EvmChainClient, EvmChainError, EvmTxFee};
use xindex_executor::evm_redeem::{
    EvmCosigner, EvmRedeemConfig, EvmRedeemError, EvmRedeemExecutor, EvmRedeemTask, SafeLockTable,
    SignSafeTxFuture,
};
use xindex_safe_evm::{digest::SafeTransaction, sigs::EcdsaSig};
use xindex_shared::chain_registry::{ChainId, EvmTxType};
use xindex_shared::signer_wire::{Eip712SignResponse, EvmSafeTxSignRequest};
use xindex_signer_daemon::evm_safe::EvmSignerConfig;
use xindex_signer_daemon::replay::InMemoryReplayStore;
use xindex_signer_daemon::server::{router, DaemonConfig, DaemonState};
use xindex_signer_daemon::web3signer::{HsmDigestSigner, HsmError};

mod ric_common;

// ─── Software HSM ─────────────────────────────────────────────────────

/// Real k1-keyed HSM frontend. Wraps an `alloy::signers::local::
/// PrivateKeySigner` so the produced signatures recover via
/// `PrimitiveSignature::recover_address_from_prehash` to the expected
/// owner — exactly what the V7 executor's aggregator requires.
struct SoftHsmEvm {
    eth: PrivateKeySigner,
    invocations: Mutex<usize>,
}

impl std::fmt::Debug for SoftHsmEvm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftHsmEvm").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl HsmDigestSigner for SoftHsmEvm {
    async fn sign_digest(&self, address: Address, digest: B256) -> Result<[u8; 65], HsmError> {
        {
            let mut g = self.invocations.lock().unwrap();
            *g += 1;
        }
        assert_eq!(
            address,
            self.eth.address(),
            "HSM requested for wrong address"
        );
        use alloy::signers::SignerSync;
        let sig = self
            .eth
            .sign_hash_sync(&digest)
            .map_err(|e| HsmError::Decode(format!("eth sign: {e}")))?;
        Ok(sig.as_bytes())
    }
}

/// Boot one real daemon on a random loopback port wired with EVM
/// signing for `safe`. Returns `(base_url, signer_address, hsm)` —
/// tests pin the address and observe the HSM invocation counter.
async fn spawn_evm_daemon(key_hex: &str, safe: Address) -> (String, Address, Arc<SoftHsmEvm>) {
    let eth: PrivateKeySigner = key_hex.parse().expect("eth key");
    let signer_addr = eth.address();
    let hsm = Arc::new(SoftHsmEvm {
        eth,
        invocations: Mutex::new(0),
    });
    let cfg = DaemonConfig {
        chain_id: 1,
        verifying_contract: Address::repeat_byte(0xab),
        eth_address: signer_addr,
        intent_policy: ric_common::policy(),
    };
    let replay = Arc::new(InMemoryReplayStore::new());
    let state = DaemonState::new(cfg, replay, Arc::clone(&hsm)).with_evm(EvmSignerConfig {
        chain: ChainId::Eth,
        safe_address: safe,
        my_signer_address: signer_addr,
    });
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    // Settle the listener.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (format!("http://{addr}"), signer_addr, hsm)
}

// ─── EvmChainClient stub ─────────────────────────────────────────────

/// Minimal in-memory `EvmChainClient`. Returns a configurable Safe
/// nonce + tip; everything else stubbed. The V9 flow only exercises
/// `chain()` / `evm_chain_id()` / `tx_type()` / `safe_nonce()`.
#[derive(Debug)]
struct StubEvm {
    chain: ChainId,
    nonce: Mutex<u64>,
}

impl EvmChainClient for StubEvm {
    fn chain(&self) -> ChainId {
        self.chain
    }
    fn evm_chain_id(&self) -> u64 {
        self.chain.evm_chain_id().expect("evm")
    }
    fn tx_type(&self) -> EvmTxType {
        self.chain.tx_type().expect("evm")
    }
    async fn block_number(&self) -> Result<u64, EvmChainError> {
        Ok(100)
    }
    async fn safe_nonce(&self, _safe: Address) -> Result<u64, EvmChainError> {
        Ok(*self.nonce.lock().unwrap())
    }
    async fn eth_call(&self, _to: Address, _data: Bytes) -> Result<Bytes, EvmChainError> {
        Ok(Bytes::new())
    }
    async fn eth_get_transaction_by_hash(
        &self,
        _hash: B256,
    ) -> Result<Option<xindex_chain_evm::EvmTransactionSummary>, EvmChainError> {
        Ok(None)
    }
    async fn eth_get_logs(
        &self,
        _filter: xindex_chain_evm::EvmLogFilter,
    ) -> Result<Vec<xindex_chain_evm::EvmLogEntry>, EvmChainError> {
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
    ) -> Result<xindex_chain_evm::EvmConfirmedReceipt, EvmChainError> {
        unreachable!()
    }
}

// ─── RemoteEvmCosigner (production-shape, HTTP-backed) ──────────────

struct RemoteEvmCosigner {
    base_url: String,
    signer: Address,
    client: reqwest::Client,
}

impl EvmCosigner for RemoteEvmCosigner {
    fn signer_address(&self) -> Address {
        self.signer
    }
    fn sign_safe_tx<'a>(
        &'a self,
        chain: ChainId,
        safe_address: Address,
        tx: &'a SafeTransaction,
        safe_tx_hash: B256,
        fee_wei: u128,
        intent_proof: Option<&'a xindex_shared::signer_wire::IntentProof>,
    ) -> SignSafeTxFuture<'a> {
        let url = format!("{}/api/v1/sign/evm-safe-tx", self.base_url);
        let signer = self.signer;
        let client = self.client.clone();
        let req = EvmSafeTxSignRequest {
            chain_id: chain,
            safe_address: format!("{safe_address:#x}"),
            to: format!("{:#x}", tx.to),
            value: tx.value.to_string(),
            data: format!("0x{}", alloy_primitives::hex::encode(&tx.data)),
            operation: tx.operation as u8,
            safe_tx_gas: tx.safe_tx_gas.to_string(),
            base_gas: tx.base_gas.to_string(),
            gas_price: tx.gas_price.to_string(),
            gas_token: format!("{:#x}", tx.gas_token),
            refund_receiver: format!("{:#x}", tx.refund_receiver),
            nonce: tx.nonce.to_string(),
            safe_tx_hash: format!("0x{}", alloy_primitives::hex::encode(safe_tx_hash)),
            fee_wei: fee_wei.to_string(),
            intent_proof: intent_proof.cloned(),
        };
        Box::pin(async move {
            let resp = client.post(&url).json(&req).send().await.map_err(|e| {
                EvmRedeemError::Cosigner {
                    signer,
                    message: format!("transport: {e}"),
                }
            })?;
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(EvmRedeemError::Cosigner {
                    signer,
                    message: format!("HTTP {status}: {body}"),
                });
            }
            let parsed: Eip712SignResponse =
                resp.json().await.map_err(|e| EvmRedeemError::Cosigner {
                    signer,
                    message: format!("decode: {e}"),
                })?;
            let sig_hex = parsed
                .signature
                .strip_prefix("0x")
                .unwrap_or(&parsed.signature);
            let sig_bytes =
                alloy_primitives::hex::decode(sig_hex).map_err(|e| EvmRedeemError::Cosigner {
                    signer,
                    message: format!("bad sig hex: {e}"),
                })?;
            let arr: [u8; 65] =
                sig_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| EvmRedeemError::Cosigner {
                        signer,
                        message: format!("sig not 65 bytes: got {}", sig_bytes.len()),
                    })?;
            EcdsaSig::from_65_bytes(arr).map_err(|e| EvmRedeemError::Cosigner {
                signer,
                message: format!("non-canonical sig: {e:?}"),
            })
        })
    }
}

// ─── Fixtures ────────────────────────────────────────────────────────

/// Anvil deterministic dev keys — three distinct k1 keys whose
/// addresses we use as the Safe owners in this test.
const KEY_A: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const KEY_B: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const KEY_C: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

const SAFE_ADDR: Address = Address::new([0x42; 20]);

fn dummy_fee() -> EvmTxFee {
    EvmTxFee {
        gas_limit: 600_000,
        max_fee_per_gas: 50_000_000_000,
        max_priority_fee_per_gas: 1_500_000_000,
        gas_price: 5_000_000_000,
    }
}

async fn build_3_of_3_environment() -> (
    EvmRedeemExecutor<StubEvm>,
    Vec<Arc<SoftHsmEvm>>,
    Vec<Address>,
) {
    let (url_a, addr_a, hsm_a) = spawn_evm_daemon(KEY_A, SAFE_ADDR).await;
    let (url_b, addr_b, hsm_b) = spawn_evm_daemon(KEY_B, SAFE_ADDR).await;
    let (url_c, addr_c, hsm_c) = spawn_evm_daemon(KEY_C, SAFE_ADDR).await;
    let owners = vec![addr_a, addr_b, addr_c];

    let evm = Arc::new(StubEvm {
        chain: ChainId::Eth,
        nonce: Mutex::new(0),
    });
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("client");
    let cosigners: Vec<Box<dyn EvmCosigner>> = vec![
        Box::new(RemoteEvmCosigner {
            base_url: url_a,
            signer: addr_a,
            client: http.clone(),
        }),
        Box::new(RemoteEvmCosigner {
            base_url: url_b,
            signer: addr_b,
            client: http.clone(),
        }),
        Box::new(RemoteEvmCosigner {
            base_url: url_c,
            signer: addr_c,
            client: http,
        }),
    ];
    let cfg = EvmRedeemConfig {
        chain: ChainId::Eth,
        safe_address: SAFE_ADDR,
        safe_owners: owners.clone(),
        safe_threshold: 3,
        fee: dummy_fee(),
        vault: Address::new([0xde; 20]),
        expiry_offset_secs: 7200,
        submitter_address: Address::new([0xee; 20]),
    };
    let lock = Arc::new(SafeLockTable::new());
    let executor = EvmRedeemExecutor::new(cfg, evm, cosigners, lock).expect("executor construct");
    (executor, vec![hsm_a, hsm_b, hsm_c], owners)
}

fn task(memo: &str, amount: u128) -> EvmRedeemTask {
    EvmRedeemTask {
        dispatch_id: B256::repeat_byte(0xd1),
        redemption_id: B256::repeat_byte(0xd2),
        chain: ChainId::Eth,
        memo: memo.to_string(),
        amount_wei: U256::from(amount),
        intent_proof: Some(ric_common::proof(
            1,
            Address::repeat_byte(0xab),
            ChainId::Eth,
            0xd2,
            0,
            amount,
            Address::new([0xde; 20]).as_slice(),
            memo.as_bytes(),
        )),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

/// 3-of-3 happy path: three daemons each sign over real HTTP, the
/// aggregator's recovery cross-check passes, and the resulting
/// `execTransaction` calldata starts with the canonical selector.
#[tokio::test]
async fn evm_redeem_e2e_3_of_3_collects_sigs_via_real_daemons() {
    let (executor, hsms, _owners) = build_3_of_3_environment().await;
    let t = task(
        "=:ETH.USDT:0xdeadbeef:1000000000",
        1_000_000_000_000_000_000,
    );
    let outcome = executor.build_leg(&t).await.expect("build_leg");

    // execTransaction selector pinned.
    assert_eq!(&outcome.exec_calldata[..4], &[0x6a, 0x76, 0x12, 0x02]);
    assert_eq!(outcome.nonce, 0);
    assert_eq!(outcome.evm_chain_id, 1);
    assert_eq!(outcome.safe_address, SAFE_ADDR);

    // Each HSM was invoked exactly once.
    for (i, hsm) in hsms.iter().enumerate() {
        let n = *hsm.invocations.lock().unwrap();
        assert_eq!(n, 1, "daemon {i} HSM invocations");
    }

    // The TransactionRequest helper produces a 1559 envelope for ETH.
    let req = outcome.to_tx_request().expect("tx request");
    assert_eq!(req.chain_id, Some(1));
    assert!(req.max_fee_per_gas.is_some());
}

/// Idempotent replay: same `(chain, safe, nonce, digest)` re-runs
/// hit the daemons' in-memory replay store and the HSMs are NOT
/// invoked again.
#[tokio::test]
async fn evm_redeem_e2e_idempotent_replay_does_not_re_hit_hsm() {
    let (executor, hsms, _) = build_3_of_3_environment().await;
    let t = task("=:ETH.USDT:0xabcd:100", 1);
    let out1 = executor.build_leg(&t).await.expect("first");
    let out2 = executor.build_leg(&t).await.expect("replay");
    assert_eq!(out1.safe_tx_hash, out2.safe_tx_hash);
    assert_eq!(out1.exec_calldata, out2.exec_calldata);
    for (i, hsm) in hsms.iter().enumerate() {
        let n = *hsm.invocations.lock().unwrap();
        assert_eq!(
            n, 1,
            "daemon {i} HSM invoked exactly once across two builds"
        );
    }
}

/// Conflict path: a second task at the SAME nonce but with a
/// different memo produces a different digest. Each daemon's replay
/// store rejects with 409 → executor reports
/// `InsufficientCosigners` (every cosigner failed).
#[tokio::test]
async fn evm_redeem_e2e_same_nonce_different_memo_is_409_at_every_daemon() {
    let (executor, _hsms, _) = build_3_of_3_environment().await;
    let first = task("=:ETH.USDT:0x1:1", 1);
    executor.build_leg(&first).await.expect("first ok");
    // Same nonce (StubEvm keeps it at 0) but a different memo →
    // different SafeTransaction → different safeTxHash. The daemons
    // see the same (chain, safe, nonce) tuple with a DIFFERENT payload
    // → 409.
    let second = task("=:ETH.USDT:0x2:2", 1);
    let err = executor.build_leg(&second).await.expect_err("conflict");
    assert!(
        matches!(
            err,
            EvmRedeemError::InsufficientCosigners { got: 0, need: 3 }
        ),
        "expected InsufficientCosigners (got=0), got {err:?}"
    );
}

/// On-chain submission via an anvil-fork is OUT OF SCOPE at this
/// layer — placeholder for the next pass once the Safe deployment +
/// submitter EOA wiring is staged. Gated by `FORK_RPC_ETH` so the
/// default CI run skips it.
#[tokio::test]
#[ignore = "anvil-fork + Safe deployment: future V9 follow-up"]
async fn evm_redeem_e2e_anvil_fork_submission_placeholder() {
    // When implemented:
    // - read FORK_RPC_ETH from env
    // - spawn alloy::node_bindings::Anvil::new().fork(rpc).spawn()
    // - deploy Safe v1.4.1 via canonical proxy factory at fork block
    // - configure submitter EOA with funded balance
    // - submit `outcome.to_tx_request()` signed by the submitter
    // - assert receipt status == 1 and ERC20.Transfer / TransferOut
    //   event emitted on the Router for our Safe.
    println!("placeholder — see test docs for the implementation plan");
}
