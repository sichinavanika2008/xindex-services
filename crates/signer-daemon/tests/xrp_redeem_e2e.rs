#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_statements,
    clippy::print_stdout,
    reason = "integration test — panics on fixture failure are appropriate; \
              inline-use keeps each test self-contained"
)]
//! C9 — End-to-end XRP redeem leg integration test (Phase 4.4).
//!
//! Spins up THREE real `xindex-signer-daemon` instances on local TCP
//! ports — each holding a distinct k1 key via a software-backed
//! `HsmDigestSigner` configured with one `SignerList` multisig member —
//! and drives the C7 `XrpRedeemExecutor` against them through real HTTP via
//! a production-shape `RemoteXrpCosigner`. No mocks at the daemon layer;
//! the produced tx-blob is the bytes a real broadcaster would `submit`.
//!
//! ## What this test covers
//!
//! 1. **Wire roundtrip** — `XrpTxSignRequest` posted by the cosigner; each
//!    daemon re-serializes the `STObject` body, computes ITS OWN per-signer
//!    digest (`SMT\0 ‖ body ‖ own-AccountID`), signs via the HSM, DER-encodes
//!    low-S, verifies it against the configured member pubkey, returns it.
//! 2. **Each daemon signs a DIFFERENT blob** — the load-bearing divergence:
//!    every member's signature is bound to ITS OWN `AccountID` suffix, proven
//!    by the cross-verify test (a member's sig verifies against its own
//!    digest but NOT another member's).
//! 3. **3-of-3 collection + verify-aggregate** — `aggregate_verified`
//!    re-checks every partial against its own digest, then
//!    `build_signed_multisig_tx` assembles the AccountID-sorted `Signers`.
//! 4. **Idempotent replay** — the same task re-run returns cached sigs; the
//!    assembled tx-blob is byte-identical and each HSM is invoked once.
//! 5. **Deadline/replay conflict** — a second leg at the same `Sequence`
//!    with a different `LastLedgerSequence` → different body → 409 at every
//!    daemon → executor reports `InsufficientCosigners`.
//!
//! ## On-chain broadcast
//!
//! Skipped at this layer. Live `submit` + the `rippled` byte-match gate
//! (`KNOWN_FINDINGS` P4.4-1) are signet-rehearsal territory — the `#[ignore]`
//! placeholder marks the next pass.

use std::future::ready;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{Address, B256};
use xindex_chain_xrp::{XrpAccount, XrpChainClient, XrpChainError, XrpSubmitOutcome, XrpTransfer};
use xindex_executor::xrp_redeem::{
    SignXrpFuture, XrpCosigner, XrpLockTable, XrpRedeemConfig, XrpRedeemError, XrpRedeemExecutor,
    XrpRedeemTask,
};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{XrpSignResponse, XrpTxSignRequest};
use xindex_signer_daemon::replay::InMemoryReplayStore;
use xindex_signer_daemon::server::{router, DaemonConfig, DaemonState};
use xindex_signer_daemon::web3signer::{HsmDigestSigner, HsmError};

mod ric_common;
use xindex_signer_daemon::xrp_tx::XrpSignerConfig;
use xindex_xrp_tx::addr::{account_id, decode_classic_address, encode_classic_address};
use xindex_xrp_tx::signing::multisign_digest;
use xindex_xrp_tx::sigs::verify_der;
use xindex_xrp_tx::tx::{serialize_for_multisign, PaymentBody};

// ─── Fixture constants (shared by the executor + the divergence proof) ──
const SEQUENCE: u32 = 7;
const TIP: u64 = 9_000_000;
const WINDOW: u32 = 75;
const AMOUNT: u64 = 5_000_000;
const FEE: u64 = 60;
const MEMO: &str = "=:ETH.USDT:0xdeadbeef:1000000";

fn account_bytes() -> [u8; 20] {
    [0xAB; 20]
}
fn vault_bytes() -> [u8; 20] {
    [0xCD; 20]
}

/// The `LastLedgerSequence` the executor computes: current tip + window.
fn deadline() -> u32 {
    u32::try_from(TIP).expect("tip fits u32") + WINDOW
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

/// Boot one real daemon wired with an XRP signing role for
/// `account_address` + `pubkey`. Returns `(base_url, member_pubkey, hsm)`.
async fn spawn_xrp_daemon(
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
        .with_xrp(XrpSignerConfig {
            chain: ChainId::Xrp,
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

// ─── XrpChainClient stub ─────────────────────────────────────────────

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
    ) -> impl std::future::Future<Output = Result<XrpAccount, XrpChainError>> + Send {
        ready(Ok(XrpAccount {
            sequence: self.sequence,
        }))
    }
    fn ledger_current(
        &self,
    ) -> impl std::future::Future<Output = Result<u64, XrpChainError>> + Send {
        ready(Ok(self.tip))
    }
    fn latest_validated_ledger(
        &self,
    ) -> impl std::future::Future<Output = Result<u64, XrpChainError>> + Send {
        ready(Ok(self.tip))
    }
    fn transfers_to(
        &self,
        _destination: &str,
        _min_ledger: u64,
    ) -> impl std::future::Future<Output = Result<Vec<XrpTransfer>, XrpChainError>> + Send {
        ready(Ok(Vec::new()))
    }
    fn submit_tx_blob(
        &self,
        _tx_blob: &[u8],
    ) -> impl std::future::Future<Output = Result<XrpSubmitOutcome, XrpChainError>> + Send {
        ready(Err(XrpChainError::Rpc("not used in e2e".to_string())))
    }
}

// ─── RemoteXrpCosigner (production-shape, HTTP-backed) ───────────────

struct RemoteXrpCosigner {
    base_url: String,
    pubkey: [u8; 33],
    client: reqwest::Client,
}

impl XrpCosigner for RemoteXrpCosigner {
    fn member_pubkey(&self) -> [u8; 33] {
        self.pubkey
    }
    fn sign_xrp_tx<'a>(&'a self, req: &'a XrpTxSignRequest) -> SignXrpFuture<'a> {
        let url = format!("{}/api/v1/sign/xrp-tx", self.base_url);
        let client = self.client.clone();
        let pinned = self.pubkey;
        let pin_hex = format!("0x{}", alloy_primitives::hex::encode(pinned));
        let body = req.clone();
        Box::pin(async move {
            let err = |message: String| XrpRedeemError::Cosigner {
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
            let parsed: XrpSignResponse =
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
            alloy_primitives::hex::decode(sig_hex).map_err(|e| err(format!("sig hex: {e}")))
        })
    }
}

// ─── Fixtures ────────────────────────────────────────────────────────

const KEY_A: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const KEY_B: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const KEY_C: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

/// The shared `STObject` body the executor builds (deterministic from the
/// fixture constants). Used by the divergence proof to recompute each
/// member's per-signer digest.
fn fixture_body() -> Vec<u8> {
    let body = PaymentBody {
        account: account_bytes(),
        destination: vault_bytes(),
        amount_drops: AMOUNT,
        fee_drops: FEE,
        sequence: SEQUENCE,
        last_ledger_sequence: Some(deadline()),
        network_id: None,
        memo: MEMO.as_bytes().to_vec(),
    };
    serialize_for_multisign(&body).expect("serialize")
}

async fn spawn_daemons() -> (String, Vec<(String, [u8; 33], Arc<SoftHsm>)>) {
    let account = encode_classic_address(&account_bytes());
    let a = spawn_xrp_daemon(KEY_A, &account, member_pubkey(KEY_A)).await;
    let b = spawn_xrp_daemon(KEY_B, &account, member_pubkey(KEY_B)).await;
    let c = spawn_xrp_daemon(KEY_C, &account, member_pubkey(KEY_C)).await;
    (account, vec![a, b, c])
}

fn descriptor() -> xindex_xrp_tx::XrpMultisig {
    xindex_xrp_tx::XrpMultisig::new(
        3,
        vec![
            (member_pubkey(KEY_A), 1),
            (member_pubkey(KEY_B), 1),
            (member_pubkey(KEY_C), 1),
        ],
    )
    .expect("descriptor")
}

async fn build_3_of_3_environment() -> (XrpRedeemExecutor<StubXrp>, Vec<Arc<SoftHsm>>, String) {
    let (account, daemons) = spawn_daemons().await;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("client");
    let cosigners: Vec<Box<dyn XrpCosigner>> = daemons
        .iter()
        .map(|(url, pk, _)| -> Box<dyn XrpCosigner> {
            Box::new(RemoteXrpCosigner {
                base_url: url.clone(),
                pubkey: *pk,
                client: http.clone(),
            })
        })
        .collect();
    let hsms: Vec<Arc<SoftHsm>> = daemons.iter().map(|(_, _, h)| Arc::clone(h)).collect();
    let cfg = XrpRedeemConfig {
        chain: ChainId::Xrp,
        multisig: descriptor(),
        account_address: account.clone(),
        fee_drops: u128::from(FEE),
        last_ledger_window: WINDOW,
        vault: encode_classic_address(&vault_bytes()),
    };
    let xrp = Arc::new(StubXrp {
        sequence: SEQUENCE,
        tip: TIP,
    });
    let executor = XrpRedeemExecutor::new(cfg, xrp, cosigners, Arc::new(XrpLockTable::new()))
        .expect("executor construct");
    (executor, hsms, account)
}

fn task(memo: &str, amount: u128) -> XrpRedeemTask {
    XrpRedeemTask {
        dispatch_id: B256::repeat_byte(0xd1),
        redemption_id: B256::repeat_byte(0xd2),
        chain: ChainId::Xrp,
        memo: memo.to_string(),
        send_amount: amount,
        intent_proof: Some(ric_common::proof(
            1,
            Address::repeat_byte(0xab),
            ChainId::Xrp,
            0xd2,
            0,
            amount,
            encode_classic_address(&vault_bytes()).as_bytes(),
            memo.as_bytes(),
        )),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn xrp_redeem_e2e_3_of_3_collects_sigs_via_real_daemons() {
    let (executor, hsms, _account) = build_3_of_3_environment().await;
    let t = task(MEMO, u128::from(AMOUNT));
    let outcome = executor.build_leg(&t).await.expect("build_leg");

    assert_eq!(outcome.sequence, SEQUENCE);
    assert_eq!(outcome.last_ledger_sequence, deadline());
    assert_eq!(outcome.chain, ChainId::Xrp);
    assert!(!outcome.tx_blob.is_empty());
    // Payment TransactionType prefix + the Signers array.
    assert_eq!(&outcome.tx_blob[..3], &[0x12, 0x00, 0x00]);
    let hex = alloy_primitives::hex::encode(&outcome.tx_blob);
    assert!(hex.contains("f3e0"), "Signers array must be present");

    for (i, hsm) in hsms.iter().enumerate() {
        assert_eq!(
            *hsm.invocations.lock().unwrap(),
            1,
            "daemon {i} HSM invocations"
        );
    }
}

/// The divergence proof: post the SAME shared body to all three daemons,
/// collect their DER sigs, and show each verifies ONLY against its OWN
/// per-signer digest (`body ‖ own-AccountID`) — never another member's.
#[tokio::test]
async fn xrp_redeem_e2e_each_daemon_signs_a_distinct_blob() {
    let (account, daemons) = spawn_daemons().await;
    let body = fixture_body();
    let req = XrpTxSignRequest {
        chain_id: ChainId::Xrp,
        account_address: account,
        destination: encode_classic_address(&vault_bytes()),
        amount_drops: AMOUNT.to_string(),
        fee_drops: FEE.to_string(),
        sequence: SEQUENCE.to_string(),
        last_ledger_sequence: (deadline()).to_string(),
        memo: MEMO.to_string(),
        signing_blob: format!("0x{}", alloy_primitives::hex::encode(&body)),
        intent_proof: Some(ric_common::proof(
            1,
            Address::repeat_byte(0xab),
            ChainId::Xrp,
            0xe1,
            0,
            u128::from(AMOUNT),
            encode_classic_address(&vault_bytes()).as_bytes(),
            MEMO.as_bytes(),
        )),
    };
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("client");

    // Collect (pubkey, account_id, der) from each daemon.
    let mut sigs: Vec<([u8; 33], [u8; 20], Vec<u8>)> = Vec::new();
    for (url, pk, _) in &daemons {
        let cosigner = RemoteXrpCosigner {
            base_url: url.clone(),
            pubkey: *pk,
            client: http.clone(),
        };
        let der = cosigner.sign_xrp_tx(&req).await.expect("sign");
        sigs.push((*pk, account_id(pk), der));
    }
    assert_eq!(sigs.len(), 3);

    // Each sig verifies against its OWN digest, and FAILS against another
    // member's digest — proving the per-signer AccountID binding.
    for i in 0..sigs.len() {
        let (pk_i, id_i, der_i) = &sigs[i];
        let own = multisign_digest(&body, id_i);
        verify_der(pk_i, &own, der_i).expect("sig must verify under its own digest");
        let j = (i + 1) % sigs.len();
        let (_, id_j, _) = &sigs[j];
        let other = multisign_digest(&body, id_j);
        assert!(
            verify_der(pk_i, &other, der_i).is_err(),
            "member {i}'s sig must NOT verify under member {j}'s digest"
        );
    }
}

#[tokio::test]
async fn xrp_redeem_e2e_idempotent_replay_does_not_re_hit_hsm() {
    let (executor, hsms, _account) = build_3_of_3_environment().await;
    let t = task("=:ETH.USDT:0xabcd:100", 1_000_000);
    let out1 = executor.build_leg(&t).await.expect("first");
    let out2 = executor.build_leg(&t).await.expect("replay");
    assert_eq!(
        out1.tx_blob, out2.tx_blob,
        "idempotent replay → identical tx-blob"
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
async fn xrp_redeem_e2e_same_sequence_different_deadline_is_409_at_every_daemon() {
    // First leg fixes (account, sequence=7, deadline=TIP+WINDOW). A second
    // executor against the SAME daemons but a different deadline (higher
    // tip) produces a different body → 409 at each daemon.
    let (account, daemons) = spawn_daemons().await;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("client");
    let cosigners = || -> Vec<Box<dyn XrpCosigner>> {
        daemons
            .iter()
            .map(|(url, pk, _)| -> Box<dyn XrpCosigner> {
                Box::new(RemoteXrpCosigner {
                    base_url: url.clone(),
                    pubkey: *pk,
                    client: http.clone(),
                })
            })
            .collect()
    };
    // The config is identical for both legs; only StubXrp.tip differs (the
    // deadline = tip + window is computed by the executor).
    let make_cfg = || XrpRedeemConfig {
        chain: ChainId::Xrp,
        multisig: descriptor(),
        account_address: account.clone(),
        fee_drops: u128::from(FEE),
        last_ledger_window: WINDOW,
        vault: encode_classic_address(&vault_bytes()),
    };
    let exec1 = XrpRedeemExecutor::new(
        make_cfg(),
        Arc::new(StubXrp {
            sequence: SEQUENCE,
            tip: TIP,
        }),
        cosigners(),
        Arc::new(XrpLockTable::new()),
    )
    .expect("exec1");
    exec1
        .build_leg(&task(MEMO, u128::from(AMOUNT)))
        .await
        .expect("first ok");

    // Same sequence, LATER deadline (tip = TIP + 1000) → different body.
    let exec2 = XrpRedeemExecutor::new(
        make_cfg(),
        Arc::new(StubXrp {
            sequence: SEQUENCE,
            tip: TIP + 1000,
        }),
        cosigners(),
        Arc::new(XrpLockTable::new()),
    )
    .expect("exec2");
    let err = exec2
        .build_leg(&task(MEMO, u128::from(AMOUNT)))
        .await
        .expect_err("conflict");
    assert!(
        matches!(
            err,
            XrpRedeemError::InsufficientCosigners { got: 0, need: 3 }
        ),
        "expected InsufficientCosigners (got=0), got {err:?}"
    );
}

/// Live `submit` + `rippled` byte-match is OUT OF SCOPE here — placeholder
/// for the signet rehearsal pass (`KNOWN_FINDINGS` P4.4-1).
#[tokio::test]
#[ignore = "signet submit + rippled byte-match: future C9 follow-up"]
async fn xrp_redeem_e2e_signet_broadcast_placeholder() {
    // When implemented:
    // - point StubXrp at a real testnet node (or a ReqwestXrpChainClient)
    // - assert build_signed_multisig_tx bytes equal xrpl.js
    //   `encodeForMultisigning` + `multisign` for the same inputs
    // - submit and assert engine_result == tesSUCCESS + validation
    println!("placeholder — see test docs for the signet rehearsal plan");
    // Touch an import so the decode helper stays wired for the live pass.
    let _ = decode_classic_address("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh");
}
