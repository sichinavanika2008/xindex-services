#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_statements,
    clippy::print_stdout,
    reason = "integration test — panics on fixture failure are appropriate; \
              inline-use keeps each test self-contained"
)]
//! Phase 4.6 — End-to-end TRON redeem leg integration test.
//!
//! Spins up THREE real `xindex-signer-daemon` instances on local TCP
//! ports — each holding a distinct k1 key via a software-backed
//! `HsmDigestSigner` configured as one account-permission multisig member —
//! and drives the `TronRedeemExecutor` against them through real HTTP via a
//! production-shape `RemoteTronCosigner`. No mocks at the daemon layer; the
//! produced `Transaction` protobuf is the bytes a real broadcaster would
//! `broadcasthex`.
//!
//! ## What this test covers
//!
//! 1. **Wire roundtrip** — `TronTxSignRequest` posted by the cosigner; each
//!    daemon re-builds the `raw_data` protobuf, recomputes
//!    `txID = sha256(raw_data)`, signs it via the HSM, normalizes `v` to the
//!    TRON 0/1 form, verifies the recovery against the configured signer,
//!    returns the 65-byte signature.
//! 2. **Every daemon signs the IDENTICAL txID** — the convergence (the
//!    opposite of XRP's per-signer divergence): all three sigs are over the
//!    same 32 bytes, each recovering to its OWN member address, and
//!    `aggregate_verified` accepts the 3-of-3 set by summed weight.
//! 3. **Idempotent replay** — the same task re-run returns cached sigs; the
//!    assembled tx is byte-identical and each HSM is invoked once.
//!
//! ## On-chain broadcast
//!
//! Skipped at this layer. Live `broadcasthex` + the `tronweb` / `java-tron`
//! byte-match gate (`KNOWN_FINDINGS` P-TRON-1) are testnet-rehearsal
//! territory — the `#[ignore]` placeholder marks the next pass.

use std::future::ready;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{Address, B256};
use xindex_chain_tron::{
    TronBlockRef, TronBroadcastOutcome, TronChainClient, TronChainError, TronTxReceipt,
};
use xindex_executor::tron_redeem::{
    SignTronFuture, TronCosigner, TronRedeemConfig, TronRedeemError, TronRedeemExecutor,
    TronRedeemTask,
};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{TronAssetKind, TronSignResponse, TronTxSignRequest};
use xindex_signer_daemon::replay::InMemoryReplayStore;
use xindex_signer_daemon::server::{router, DaemonConfig, DaemonState};
use xindex_signer_daemon::tron_tx::TronSignerConfig;
use xindex_signer_daemon::web3signer::{HsmDigestSigner, HsmError};

mod ric_common;
use xindex_tron_tx::addr::{encode_base58check, evm_address, raw21};
use xindex_tron_tx::sigs::{aggregate_verified, recover_evm20};
use xindex_tron_tx::tx::{build_trx_raw_data, txid, Tapos, TrxTransfer};

// ─── Fixture constants ──────────────────────────────────────────────────
const BLOCK_NUMBER: u64 = 176;
const REF_BLOCK_BYTES: [u8; 2] = [0x00, 0xb0];
const REF_BLOCK_HASH: [u8; 8] = [0x3f, 0x1b, 0xc9, 0x6d, 0xc8, 0x0e, 0x7f, 0x61];
const TIMESTAMP_MS: u64 = 1_548_974_072_663;
const WINDOW_MS: u64 = 1_200_000;
const AMOUNT: u64 = 5_000_000;
const PERMISSION_ID: u32 = 2;
const MEMO: &str = "=:ETH.USDT:0xdeadbeef:1000000";

fn owner_address() -> String {
    encode_base58check(&raw21(&[0xAB; 20]))
}
fn vault_address() -> String {
    encode_base58check(&raw21(&[0xCD; 20]))
}
fn expiration() -> u64 {
    TIMESTAMP_MS + WINDOW_MS
}

// ─── Software HSM ─────────────────────────────────────────────────────

struct SoftHsm {
    eth: PrivateKeySigner,
    invocations: Mutex<usize>,
}

impl std::fmt::Debug for SoftHsm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftHsm").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl HsmDigestSigner for SoftHsm {
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

fn member_pubkey(key_hex: &str) -> [u8; 33] {
    let stripped = key_hex.strip_prefix("0x").unwrap_or(key_hex);
    let bytes = alloy_primitives::hex::decode(stripped).expect("hex");
    let sk = k256::ecdsa::SigningKey::from_slice(&bytes).expect("k256");
    let ep = sk.verifying_key().to_encoded_point(true);
    let mut pk = [0u8; 33];
    pk.copy_from_slice(ep.as_bytes());
    pk
}

/// Boot one real daemon wired with a TRON signing role for `owner` +
/// `pubkey`. Returns `(base_url, member_pubkey, hsm)`.
async fn spawn_tron_daemon(
    key_hex: &str,
    owner: &str,
    pubkey: [u8; 33],
) -> (String, [u8; 33], Arc<SoftHsm>) {
    let eth: PrivateKeySigner = key_hex.parse().expect("eth key");
    let signer_addr = eth.address();
    let hsm = Arc::new(SoftHsm {
        eth,
        invocations: Mutex::new(0),
    });
    let cfg = DaemonConfig {
        chain_id: 1,
        verifying_contract: Address::repeat_byte(0xab),
        eth_address: signer_addr,
        intent_policy: ric_common::policy(),
    };
    let state = DaemonState::new(cfg, Arc::new(InMemoryReplayStore::new()), Arc::clone(&hsm))
        .with_tron(TronSignerConfig {
            chain: ChainId::Tron,
            owner_address: owner.to_string(),
            my_signer_address: signer_addr,
            my_member_pubkey: pubkey,
        });
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (format!("http://{addr}"), pubkey, hsm)
}

// ─── TronChainClient stub ────────────────────────────────────────────

struct StubTron;
impl TronChainClient for StubTron {
    fn chain(&self) -> ChainId {
        ChainId::Tron
    }
    fn now_block(
        &self,
    ) -> impl std::future::Future<Output = Result<TronBlockRef, TronChainError>> + Send {
        ready(Ok(TronBlockRef {
            number: BLOCK_NUMBER,
            ref_block_bytes: REF_BLOCK_BYTES,
            ref_block_hash: REF_BLOCK_HASH,
            timestamp_ms: TIMESTAMP_MS,
        }))
    }
    fn broadcast_hex(
        &self,
        _tx_hex: &str,
    ) -> impl std::future::Future<Output = Result<TronBroadcastOutcome, TronChainError>> + Send
    {
        ready(Err(TronChainError::Rpc("not used in e2e".to_string())))
    }
    fn transaction_info(
        &self,
        _txid_hex: &str,
    ) -> impl std::future::Future<Output = Result<Option<TronTxReceipt>, TronChainError>> + Send
    {
        ready(Ok(None))
    }
}

// ─── RemoteTronCosigner (production-shape, HTTP-backed) ───────────────

struct RemoteTronCosigner {
    base_url: String,
    pubkey: [u8; 33],
    client: reqwest::Client,
}

impl TronCosigner for RemoteTronCosigner {
    fn member_pubkey(&self) -> [u8; 33] {
        self.pubkey
    }
    fn sign_tron_tx<'a>(&'a self, req: &'a TronTxSignRequest) -> SignTronFuture<'a> {
        let url = format!("{}/api/v1/sign/tron-tx", self.base_url);
        let client = self.client.clone();
        let pinned = self.pubkey;
        let pin_hex = format!("0x{}", alloy_primitives::hex::encode(pinned));
        let body = req.clone();
        Box::pin(async move {
            let err = |message: String| TronRedeemError::Cosigner {
                pubkey: pin_hex.clone(),
                message,
            };
            let resp = client
                .post(&url)
                .json(&body)
                .send()
                .await
                .map_err(|e| err(format!("transport: {e}")))?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(err(format!("HTTP {status}: {text}")));
            }
            let parsed: TronSignResponse =
                resp.json().await.map_err(|e| err(format!("decode: {e}")))?;
            let ret_hex = parsed.pubkey.strip_prefix("0x").unwrap_or(&parsed.pubkey);
            let ret = alloy_primitives::hex::decode(ret_hex)
                .map_err(|e| err(format!("pubkey hex: {e}")))?;
            if ret.as_slice() != pinned.as_slice() {
                return Err(err(format!("daemon returned wrong pubkey: 0x{ret_hex}")));
            }
            let sig_hex = parsed
                .signature
                .strip_prefix("0x")
                .unwrap_or(&parsed.signature);
            let sig =
                alloy_primitives::hex::decode(sig_hex).map_err(|e| err(format!("sig hex: {e}")))?;
            sig.as_slice()
                .try_into()
                .map_err(|_| err(format!("expected 65-byte sig, got {}", sig.len())))
        })
    }
}

// ─── Fixtures ────────────────────────────────────────────────────────

const KEY_A: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const KEY_B: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const KEY_C: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

fn descriptor() -> xindex_tron_tx::TronMultisig {
    xindex_tron_tx::TronMultisig::new(
        3,
        PERMISSION_ID,
        vec![
            (member_pubkey(KEY_A), 1),
            (member_pubkey(KEY_B), 1),
            (member_pubkey(KEY_C), 1),
        ],
    )
    .expect("descriptor")
}

async fn spawn_daemons() -> Vec<(String, [u8; 33], Arc<SoftHsm>)> {
    let owner = owner_address();
    vec![
        spawn_tron_daemon(KEY_A, &owner, member_pubkey(KEY_A)).await,
        spawn_tron_daemon(KEY_B, &owner, member_pubkey(KEY_B)).await,
        spawn_tron_daemon(KEY_C, &owner, member_pubkey(KEY_C)).await,
    ]
}

async fn build_3_of_3_environment() -> (TronRedeemExecutor<StubTron>, Vec<Arc<SoftHsm>>) {
    let daemons = spawn_daemons().await;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("client");
    let cosigners: Vec<Box<dyn TronCosigner>> = daemons
        .iter()
        .map(|(url, pk, _)| -> Box<dyn TronCosigner> {
            Box::new(RemoteTronCosigner {
                base_url: url.clone(),
                pubkey: *pk,
                client: http.clone(),
            })
        })
        .collect();
    let hsms: Vec<Arc<SoftHsm>> = daemons.iter().map(|(_, _, h)| Arc::clone(h)).collect();
    let cfg = TronRedeemConfig {
        chain: ChainId::Tron,
        multisig: descriptor(),
        owner_address: owner_address(),
        vault: vault_address(),
        asset: TronAssetKind::Trx,
        contract_address: None,
        fee_limit: 0,
        expiration_window_ms: WINDOW_MS,
    };
    let executor = TronRedeemExecutor::new(cfg, Arc::new(StubTron), cosigners).expect("executor");
    (executor, hsms)
}

fn task(memo: &str, amount: u128) -> TronRedeemTask {
    TronRedeemTask {
        dispatch_id: B256::repeat_byte(0xd1),
        redemption_id: B256::repeat_byte(0xd2),
        chain: ChainId::Tron,
        memo: memo.to_string(),
        send_amount: amount,
        intent_proof: Some(ric_common::proof(
            1,
            Address::repeat_byte(0xab),
            ChainId::Tron,
            0xd2,
            0,
            amount,
            vault_address().as_bytes(),
            memo.as_bytes(),
        )),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn tron_redeem_e2e_3_of_3_collects_sigs_via_real_daemons() {
    let (executor, hsms) = build_3_of_3_environment().await;
    let outcome = executor
        .build_leg(&task(MEMO, u128::from(AMOUNT)))
        .await
        .expect("build_leg");

    assert_eq!(outcome.chain, ChainId::Tron);
    assert!(!outcome.tx_hex.is_empty());
    let tx = alloy_primitives::hex::decode(&outcome.tx_hex).expect("hex");
    // raw_data field 1 (0x0a) at the front; >= 3 signature fields (0x12 0x41).
    assert_eq!(tx[0], 0x0a);
    let sig_fields = tx.windows(2).filter(|w| *w == b"\x12\x41").count();
    assert!(sig_fields >= 3, "expected >= 3 signatures");

    for (i, hsm) in hsms.iter().enumerate() {
        assert_eq!(
            *hsm.invocations.lock().unwrap(),
            1,
            "daemon {i} HSM invocations"
        );
    }
}

/// The convergence proof: post a request whose `txID` is fixed; each daemon
/// signs the IDENTICAL 32 bytes, and each sig recovers to its OWN member
/// address (never another's). `aggregate_verified` then accepts the 3-of-3.
#[tokio::test]
async fn tron_redeem_e2e_all_daemons_sign_identical_txid() {
    let daemons = spawn_daemons().await;

    // Build the exact raw_data the executor would (TRX leg) and its txID.
    let raw = build_trx_raw_data(
        &TrxTransfer {
            owner: xindex_tron_tx::addr::decode_base58check(&owner_address()).expect("o"),
            to: xindex_tron_tx::addr::decode_base58check(&vault_address()).expect("v"),
            amount: AMOUNT,
        },
        &Tapos {
            ref_block_bytes: REF_BLOCK_BYTES,
            ref_block_hash: REF_BLOCK_HASH,
            expiration: expiration(),
            timestamp: TIMESTAMP_MS,
            fee_limit: 0,
            memo: MEMO.as_bytes().to_vec(),
            permission_id: PERMISSION_ID,
        },
    );
    let tx_id = txid(&raw);

    let req = TronTxSignRequest {
        chain_id: ChainId::Tron,
        asset: TronAssetKind::Trx,
        owner_address: owner_address(),
        to_address: vault_address(),
        amount: AMOUNT.to_string(),
        contract_address: None,
        permission_id: PERMISSION_ID,
        ref_block_bytes: format!("0x{}", alloy_primitives::hex::encode(REF_BLOCK_BYTES)),
        ref_block_hash: format!("0x{}", alloy_primitives::hex::encode(REF_BLOCK_HASH)),
        expiration: expiration().to_string(),
        timestamp: TIMESTAMP_MS.to_string(),
        fee_limit: None,
        memo: MEMO.to_string(),
        txid: format!("0x{}", alloy_primitives::hex::encode(tx_id)),
        intent_proof: Some(ric_common::proof(
            1,
            Address::repeat_byte(0xab),
            ChainId::Tron,
            0xe1,
            0,
            u128::from(AMOUNT),
            vault_address().as_bytes(),
            MEMO.as_bytes(),
        )),
    };

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("client");

    let mut sigs: Vec<[u8; 65]> = Vec::new();
    for (url, pk, _) in &daemons {
        let cosigner = RemoteTronCosigner {
            base_url: url.clone(),
            pubkey: *pk,
            client: http.clone(),
        };
        let sig = cosigner.sign_tron_tx(&req).await.expect("sign");
        // Each daemon signed the IDENTICAL txID and its sig recovers to its
        // OWN member address.
        let recovered = recover_evm20(&tx_id, &sig).expect("recover");
        assert_eq!(recovered, evm_address(pk).expect("addr"));
        sigs.push(sig);
    }
    assert_eq!(sigs.len(), 3);

    // aggregate_verified accepts the convergent 3-of-3 set by summed weight.
    let ordered = aggregate_verified(&descriptor(), &tx_id, &sigs).expect("aggregate");
    assert_eq!(ordered.len(), 3);
}

#[tokio::test]
async fn tron_redeem_e2e_idempotent_replay_does_not_re_hit_hsm() {
    let (executor, hsms) = build_3_of_3_environment().await;
    let t = task("=:ETH.USDT:0xabcd:100", 1_000_000);
    let out1 = executor.build_leg(&t).await.expect("first");
    let out2 = executor.build_leg(&t).await.expect("replay");
    assert_eq!(out1.tx_hex, out2.tx_hex, "idempotent replay → identical tx");
    for (i, hsm) in hsms.iter().enumerate() {
        assert_eq!(
            *hsm.invocations.lock().unwrap(),
            1,
            "daemon {i} HSM invoked exactly once across two builds"
        );
    }
}

/// Live `broadcasthex` + `tronweb` byte-match is OUT OF SCOPE here —
/// placeholder for the testnet rehearsal pass (`KNOWN_FINDINGS` P-TRON-1).
#[tokio::test]
#[ignore = "Nile-testnet broadcast + tronweb byte-match: future follow-up"]
async fn tron_redeem_e2e_testnet_broadcast_placeholder() {
    println!("placeholder — see test docs for the testnet rehearsal plan");
}
