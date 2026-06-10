#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_statements,
    clippy::print_stdout,
    reason = "integration test — panics on fixture failure are appropriate; \
              inline-use keeps each test self-contained"
)]
//! C9 — End-to-end Cosmos redeem leg integration test (Phase 3.3).
//!
//! Spins up THREE real `xindex-signer-daemon` instances on local TCP
//! ports — each holding a distinct k1 key via a software-backed
//! `HsmDigestSigner` configured with one `LegacyAminoPubKey` multisig
//! member — and drives the C7 `CosmosRedeemExecutor` against them through
//! real HTTP via a production-shape `RemoteCosmosCosigner`. No mocks at the
//! daemon layer; the produced `TxRaw` is the bytes a real broadcaster would
//! submit.
//!
//! ## What this test covers
//!
//! 1. **Wire roundtrip** — `CosmosTxSignRequest` posted by the cosigner;
//!    each daemon recomputes the amino sign-bytes from the inputs, signs
//!    via the HSM, normalises to a 64-byte low-S sig, verifies it against
//!    the configured member pubkey, and returns it.
//! 2. **3-of-3 collection + verify-aggregate** — three daemons respond;
//!    the executor maps each pinned pubkey to its member index and
//!    `aggregate_verified` re-checks every partial against the descriptor
//!    over the digest, then `build_tx_raw` assembles the proto envelope.
//! 3. **Idempotent replay** — the same task re-run hits the daemons'
//!    in-memory replay store and returns the cached signature; the
//!    assembled `TxRaw` is byte-identical and the HSM is invoked once.
//! 4. **Conflict detection** — a second task at the same sequence but a
//!    different memo yields a different digest → 409 at every daemon →
//!    executor reports `InsufficientCosigners`.
//!
//! ## On-chain broadcast
//!
//! Skipped at this layer. Live `broadcast_tx_sync` + the `gaiad` byte-match
//! gate (DL-P3.3-8) are signet-rehearsal territory — the `#[ignore]`
//! placeholder marks the next pass.
//!
//! Lives in `signer-daemon/tests/` (not `executor/tests/`) for the same
//! dev-dep-cycle reason as the V9 EVM e2e.

use std::future::ready;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{Address, B256};
use xindex_chain_cosmos::{
    CosmosAccount, CosmosBroadcastOutcome, CosmosChainClient, CosmosChainError, CosmosTransfer,
};
use xindex_cosmos_tx::CosmosMultisig;
use xindex_executor::cosmos_redeem::{
    CosmosCosigner, CosmosLockTable, CosmosRedeemConfig, CosmosRedeemError, CosmosRedeemExecutor,
    CosmosRedeemTask, SignCosmosFuture,
};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{CosmosSignResponse, CosmosTxSignRequest};
use xindex_signer_daemon::cosmos_tx::CosmosSignerConfig;
use xindex_signer_daemon::replay::InMemoryReplayStore;
use xindex_signer_daemon::server::{router, DaemonConfig, DaemonState};
use xindex_signer_daemon::web3signer::{HsmDigestSigner, HsmError};

mod ric_common;

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

/// Compressed secp256k1 member pubkey for a raw private-key hex (the same
/// key the `PrivateKeySigner` wraps), so the daemon's `verify` accepts the
/// HSM signature against the configured member pubkey.
fn member_pubkey(key_hex: &str) -> [u8; 33] {
    let stripped = key_hex.strip_prefix("0x").unwrap_or(key_hex);
    let bytes = alloy_primitives::hex::decode(stripped).expect("hex");
    let sk = k256::ecdsa::SigningKey::from_slice(&bytes).expect("k256");
    let ep = sk.verifying_key().to_encoded_point(true);
    let mut pk = [0u8; 33];
    pk.copy_from_slice(ep.as_bytes());
    pk
}

/// Boot one real daemon wired with a Cosmos signing role for
/// `account_address` + `pubkey`. Returns `(base_url, member_pubkey, hsm)`.
async fn spawn_cosmos_daemon(
    key_hex: &str,
    account_address: &str,
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
        .with_cosmos(CosmosSignerConfig {
            chain: ChainId::Gaia,
            cosmos_chain_id: "cosmoshub-4".to_string(),
            account_address: account_address.to_string(),
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

// ─── CosmosChainClient stub ──────────────────────────────────────────

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
    ) -> impl std::future::Future<Output = Result<CosmosAccount, CosmosChainError>> + Send {
        ready(Ok(CosmosAccount {
            account_number: self.account_number,
            sequence: self.sequence,
        }))
    }
    fn latest_height(
        &self,
    ) -> impl std::future::Future<Output = Result<u64, CosmosChainError>> + Send {
        ready(Ok(1))
    }
    fn transfers_to(
        &self,
        _recipient: &str,
        _min_height: u64,
    ) -> impl std::future::Future<Output = Result<Vec<CosmosTransfer>, CosmosChainError>> + Send
    {
        ready(Ok(Vec::new()))
    }
    fn broadcast_tx_sync(
        &self,
        _tx_raw: &[u8],
    ) -> impl std::future::Future<Output = Result<CosmosBroadcastOutcome, CosmosChainError>> + Send
    {
        ready(Err(CosmosChainError::Rpc("not used in e2e".to_string())))
    }
}

// ─── RemoteCosmosCosigner (production-shape, HTTP-backed) ────────────

struct RemoteCosmosCosigner {
    base_url: String,
    pubkey: [u8; 33],
    client: reqwest::Client,
}

impl CosmosCosigner for RemoteCosmosCosigner {
    fn member_pubkey(&self) -> [u8; 33] {
        self.pubkey
    }
    fn sign_cosmos_tx<'a>(&'a self, req: &'a CosmosTxSignRequest) -> SignCosmosFuture<'a> {
        let url = format!("{}/api/v1/sign/cosmos-tx", self.base_url);
        let client = self.client.clone();
        let pinned = self.pubkey;
        let pin_hex = format!("0x{}", alloy_primitives::hex::encode(pinned));
        let body = req.clone();
        Box::pin(async move {
            let err = |message: String| CosmosRedeemError::Cosigner {
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
            let parsed: CosmosSignResponse =
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
            let arr: [u8; 64] = sig
                .as_slice()
                .try_into()
                .map_err(|_| err(format!("sig not 64 bytes: got {}", sig.len())))?;
            Ok(arr)
        })
    }
}

// ─── Fixtures ────────────────────────────────────────────────────────

const KEY_A: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const KEY_B: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const KEY_C: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

async fn build_3_of_3_environment() -> (CosmosRedeemExecutor<StubCosmos>, Vec<Arc<SoftHsm>>) {
    // Ordered member set → descriptor → account address.
    let members = vec![
        member_pubkey(KEY_A),
        member_pubkey(KEY_B),
        member_pubkey(KEY_C),
    ];
    let multisig = CosmosMultisig::new(3, members, "cosmos").expect("descriptor");
    let account = multisig.account_address().expect("address");

    let (url_a, pk_a, hsm_a) = spawn_cosmos_daemon(KEY_A, &account, member_pubkey(KEY_A)).await;
    let (url_b, pk_b, hsm_b) = spawn_cosmos_daemon(KEY_B, &account, member_pubkey(KEY_B)).await;
    let (url_c, pk_c, hsm_c) = spawn_cosmos_daemon(KEY_C, &account, member_pubkey(KEY_C)).await;

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("client");
    let cosigners: Vec<Box<dyn CosmosCosigner>> = vec![
        Box::new(RemoteCosmosCosigner {
            base_url: url_a,
            pubkey: pk_a,
            client: http.clone(),
        }),
        Box::new(RemoteCosmosCosigner {
            base_url: url_b,
            pubkey: pk_b,
            client: http.clone(),
        }),
        Box::new(RemoteCosmosCosigner {
            base_url: url_c,
            pubkey: pk_c,
            client: http,
        }),
    ];

    let cfg = CosmosRedeemConfig {
        chain: ChainId::Gaia,
        multisig,
        account_address: account,
        cosmos_chain_id: "cosmoshub-4".to_string(),
        denom: "uatom".to_string(),
        fee_amount: 5_000,
        gas_limit: 200_000,
        vault: "cosmos1asgardvault".to_string(),
    };
    let cosmos = Arc::new(StubCosmos {
        account_number: 42,
        sequence: 7,
    });
    let executor =
        CosmosRedeemExecutor::new(cfg, cosmos, cosigners, Arc::new(CosmosLockTable::new()))
            .expect("executor construct");
    (executor, vec![hsm_a, hsm_b, hsm_c])
}

fn task(memo: &str, amount: u128) -> CosmosRedeemTask {
    CosmosRedeemTask {
        dispatch_id: B256::repeat_byte(0xd1),
        redemption_id: B256::repeat_byte(0xd2),
        chain: ChainId::Gaia,
        memo: memo.to_string(),
        send_amount: amount,
        intent_proof: Some(ric_common::proof(
            1,
            Address::repeat_byte(0xab),
            ChainId::Gaia,
            0xd2,
            0,
            amount,
            b"cosmos1asgardvault",
            memo.as_bytes(),
        )),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn cosmos_redeem_e2e_3_of_3_collects_sigs_via_real_daemons() {
    let (executor, hsms) = build_3_of_3_environment().await;
    let t = task("=:ETH.USDT:0xdeadbeef:1000000", 5_000_000);
    let outcome = executor.build_leg(&t).await.expect("build_leg");

    assert_eq!(outcome.sequence, 7);
    assert_eq!(outcome.chain, ChainId::Gaia);
    assert!(!outcome.tx_raw.is_empty());
    // TxRaw field 1 (body) len-delim tag.
    assert_eq!(outcome.tx_raw[0], 0x0a);

    for (i, hsm) in hsms.iter().enumerate() {
        assert_eq!(
            *hsm.invocations.lock().unwrap(),
            1,
            "daemon {i} HSM invocations"
        );
    }
}

#[tokio::test]
async fn cosmos_redeem_e2e_idempotent_replay_does_not_re_hit_hsm() {
    let (executor, hsms) = build_3_of_3_environment().await;
    let t = task("=:ETH.USDT:0xabcd:100", 1_000_000);
    let out1 = executor.build_leg(&t).await.expect("first");
    let out2 = executor.build_leg(&t).await.expect("replay");
    assert_eq!(out1.sign_doc_hash, out2.sign_doc_hash);
    assert_eq!(
        out1.tx_raw, out2.tx_raw,
        "idempotent replay → identical TxRaw"
    );
    for (i, hsm) in hsms.iter().enumerate() {
        assert_eq!(
            *hsm.invocations.lock().unwrap(),
            1,
            "daemon {i} HSM invoked exactly once across two builds"
        );
    }
}

#[tokio::test]
async fn cosmos_redeem_e2e_same_sequence_different_memo_is_409_at_every_daemon() {
    let (executor, _hsms) = build_3_of_3_environment().await;
    executor
        .build_leg(&task("=:ETH.USDT:0x1:1", 1))
        .await
        .expect("first ok");
    // Same sequence (StubCosmos fixed at 7) + different memo → different
    // digest → 409 conflict at each daemon → InsufficientCosigners.
    let err = executor
        .build_leg(&task("=:ETH.USDT:0x2:2", 1))
        .await
        .expect_err("conflict");
    assert!(
        matches!(
            err,
            CosmosRedeemError::InsufficientCosigners { got: 0, need: 3 }
        ),
        "expected InsufficientCosigners (got=0), got {err:?}"
    );
}

/// Live broadcast + `gaiad` byte-match is OUT OF SCOPE here — placeholder
/// for the signet rehearsal pass (DL-P3.3-8).
#[tokio::test]
#[ignore = "signet broadcast + gaiad byte-match: future C9 follow-up"]
async fn cosmos_redeem_e2e_signet_broadcast_placeholder() {
    // When implemented:
    // - point StubCosmos at a real signet node (or a ReqwestCosmosChainClient)
    // - assert build_tx_raw bytes equal `gaiad tx bank send --generate-only`
    //   + `gaiad tx sign --multisig` for the same inputs (byte-for-byte)
    // - broadcast_tx_sync and assert code == 0 + inclusion
    println!("placeholder — see test docs for the signet rehearsal plan");
}
