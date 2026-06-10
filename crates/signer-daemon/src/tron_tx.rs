//! Phase 4.6 — `POST /api/v1/sign/tron-tx` handler.
//!
//! The TRON custody-family signing endpoint. Same per-chain dispatch shape
//! as [`crate::xrp_tx`] — `DaemonState.tron` decides which chains this
//! daemon serves; a request for an unconfigured chain returns
//! `404 endpoint_disabled`.
//!
//! ## Pipeline
//!
//! 1. Look up the per-chain [`TronSignerConfig`] by `req.chain_id`.
//! 2. Refuse if `req.owner_address` is not the daemon's configured multisig
//!    account (`wrong_tron_account`).
//! 3. RE-BUILD the `raw_data` protobuf from the semantic fields (via
//!    `tron-tx`), recompute `txID = sha256(raw_data)`, and refuse with
//!    `tron_tx_mismatch` if it does not match the caller-supplied `txid` —
//!    the daemon never blind-signs. The destination / amount / memo /
//!    `permission_id` are all bound into the `txID`.
//! 4. Replay-DB on `(chain_id, owner_address, txid)`: `FirstTime` → sign;
//!    `Idempotent` → cached.
//! 5. HSM-sign the 32-byte `txID`, normalize `v` to the TRON 0/1 form, and
//!    VERIFY the 65-byte recoverable signature recovers to the configured
//!    signer address before recording (catches an HSM key-mapping bug /
//!    wrong-key / corrupted response).

use std::sync::Arc;

use alloy_primitives::{Address, B256};
use axum::{extract::State, http::StatusCode, response::Json};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{
    error_codes, ErrorBody, TronAssetKind, TronSignResponse, TronTxSignRequest,
};
use xindex_tron_tx::addr::{decode_base58check, decode_to_evm20};
use xindex_tron_tx::sigs::recover_evm20;
use xindex_tron_tx::tx::{
    build_trx_raw_data, build_usdt_raw_data, txid, Tapos, TrxTransfer, UsdtTransfer,
};

use crate::replay::{CheckOutcome, ReplayStore};
use crate::server::DaemonState;
use crate::web3signer::{HsmDigestSigner, HsmError};

/// Per-chain TRON signing role. One entry per TRON chain this daemon is a
/// permission member of (no cross-chain key sharing — DL-P3-7).
#[derive(Debug, Clone)]
pub struct TronSignerConfig {
    /// Which TRON chain this config serves.
    pub chain: ChainId,
    /// The multisig account (base58check `T…` address) this daemon signs
    /// for. A request whose `owner_address` differs is refused.
    pub owner_address: String,
    /// EOA handle the HSM frontend keys the signing call on (the EVM-form
    /// address of the same secp256k1 key whose compressed pubkey is
    /// `my_member_pubkey`). The recovered signer must equal this.
    pub my_signer_address: Address,
    /// This daemon's 33-byte compressed member pubkey — returned to the
    /// coordinator so it can map the partial to the correct permission key.
    pub my_member_pubkey: [u8; 33],
}

fn err(
    code: &str,
    status: StatusCode,
    message: impl Into<String>,
) -> (StatusCode, Json<ErrorBody>) {
    (
        status,
        Json(ErrorBody {
            code: code.to_string(),
            message: message.into(),
        }),
    )
}

fn bad(field: &str, e: impl std::fmt::Display) -> (StatusCode, Json<ErrorBody>) {
    err(
        error_codes::BAD_REQUEST,
        StatusCode::BAD_REQUEST,
        format!("{field}: {e}"),
    )
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| {
            #[expect(
                clippy::cast_possible_wrap,
                reason = "unix secs within i64 range for centuries"
            )]
            let v = d.as_secs() as i64;
            v
        })
}

/// Parse a `0x`-prefixed (or bare) hex string into a fixed-size array.
fn parse_hex_n<const N: usize>(
    field: &str,
    s: &str,
) -> Result<[u8; N], (StatusCode, Json<ErrorBody>)> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = alloy_primitives::hex::decode(stripped).map_err(|e| bad(field, e))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| bad(field, format!("expected {N} bytes, got {}", bytes.len())))
}

/// Re-build the `raw_data` protobuf from the request's semantic fields.
fn rebuild_raw_data(req: &TronTxSignRequest) -> Result<Vec<u8>, (StatusCode, Json<ErrorBody>)> {
    let owner = decode_base58check(&req.owner_address).map_err(|e| bad("owner_address", e))?;
    let amount = req.amount.parse::<u64>().map_err(|e| bad("amount", e))?;
    let permission_id = req.permission_id;
    let ref_block_bytes = parse_hex_n::<2>("ref_block_bytes", &req.ref_block_bytes)?;
    let ref_block_hash = parse_hex_n::<8>("ref_block_hash", &req.ref_block_hash)?;
    let expiration = req
        .expiration
        .parse::<u64>()
        .map_err(|e| bad("expiration", e))?;
    let timestamp = req
        .timestamp
        .parse::<u64>()
        .map_err(|e| bad("timestamp", e))?;

    match req.asset {
        TronAssetKind::Trx => {
            let to = decode_base58check(&req.to_address).map_err(|e| bad("to_address", e))?;
            let tapos = Tapos {
                ref_block_bytes,
                ref_block_hash,
                expiration,
                timestamp,
                fee_limit: 0,
                memo: req.memo.clone().into_bytes(),
                permission_id,
            };
            Ok(build_trx_raw_data(
                &TrxTransfer { owner, to, amount },
                &tapos,
            ))
        }
        TronAssetKind::Usdt => {
            let contract_str = req
                .contract_address
                .as_deref()
                .ok_or_else(|| bad("contract_address", "required for a USDT (TRC20) transfer"))?;
            let contract =
                decode_base58check(contract_str).map_err(|e| bad("contract_address", e))?;
            let to_evm20 = decode_to_evm20(&req.to_address).map_err(|e| bad("to_address", e))?;
            let fee_limit = req
                .fee_limit
                .as_deref()
                .ok_or_else(|| bad("fee_limit", "required for a USDT (TRC20) transfer"))?
                .parse::<u64>()
                .map_err(|e| bad("fee_limit", e))?;
            let tapos = Tapos {
                ref_block_bytes,
                ref_block_hash,
                expiration,
                timestamp,
                fee_limit,
                memo: req.memo.clone().into_bytes(),
                permission_id,
            };
            Ok(build_usdt_raw_data(
                &UsdtTransfer {
                    owner,
                    contract,
                    to_evm20,
                    amount,
                },
                &tapos,
            ))
        }
    }
}

fn render(pubkey: [u8; 33], sig65: &[u8; 65]) -> TronSignResponse {
    TronSignResponse {
        pubkey: format!("0x{}", alloy_primitives::hex::encode(pubkey)),
        signature: format!("0x{}", alloy_primitives::hex::encode(sig65)),
    }
}

fn hsm_unavailable(e: &HsmError) -> (StatusCode, Json<ErrorBody>) {
    err(
        error_codes::HSM_UNAVAILABLE,
        StatusCode::SERVICE_UNAVAILABLE,
        e.to_string(),
    )
}

/// Normalize an HSM `v` byte (27/28 EVM convention, or already 0/1) into
/// the TRON recovery-id form (0/1).
fn tron_recovery_v(v: u8) -> u8 {
    if v >= 27 {
        v - 27
    } else {
        v
    }
}

/// Axum handler for `/api/v1/sign/tron-tx`.
///
/// # Errors
/// Returns `(StatusCode, Json<ErrorBody>)` with a stable code:
/// `endpoint_disabled` (404), `wrong_tron_account` (422),
/// `tron_tx_mismatch` (422), `bad_request` (400),
/// `conflict_already_signed_different` (409), `hsm_unavailable` (503),
/// `signer_recover_mismatch` (500).
#[expect(
    clippy::too_many_lines,
    reason = "single sequential validate-then-sign pipeline; splitting fragments the audit-relevant ordering of checks"
)]
pub async fn handle_tron_tx<S, H>(
    State(state): State<DaemonState<S, H>>,
    Json(req): Json<TronTxSignRequest>,
) -> Result<Json<TronSignResponse>, (StatusCode, Json<ErrorBody>)>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    // 1. Per-chain config lookup.
    let cfg: Arc<TronSignerConfig> = state.tron.get(&req.chain_id).cloned().ok_or_else(|| {
        err(
            error_codes::ENDPOINT_DISABLED,
            StatusCode::NOT_FOUND,
            format!(
                "TRON role for chain {:?} not enabled on this daemon",
                req.chain_id
            ),
        )
    })?;

    // 2. Account must match the configured multisig account.
    if req.owner_address != cfg.owner_address {
        return Err(err(
            error_codes::WRONG_TRON_ACCOUNT,
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "owner_address mismatch: configured {}, request {}",
                cfg.owner_address, req.owner_address
            ),
        ));
    }

    // 3. Re-build raw_data, recompute txID, compare to the claim.
    let raw_data = rebuild_raw_data(&req)?;
    let computed = txid(&raw_data);
    let claimed = parse_hex_n::<32>("txid", &req.txid)?;
    if computed != claimed {
        return Err(err(
            error_codes::TRON_TX_MISMATCH,
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "recomputed txID 0x{} != claimed 0x{}",
                alloy_primitives::hex::encode(computed),
                alloy_primitives::hex::encode(claimed),
            ),
        ));
    }

    // 4. Replay-DB pre-flight (payload_hash = the txID).
    let outcome = state
        .replay
        .check_tron_tx(req.chain_id, req.owner_address.clone(), computed, computed)
        .await
        .map_err(|e| {
            err(
                error_codes::BAD_REQUEST,
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("replay db: {e}"),
            )
        })?;
    match outcome {
        CheckOutcome::Idempotent(rec) => {
            let arr: [u8; 65] = rec.signature.as_slice().try_into().map_err(|_| {
                err(
                    error_codes::BAD_REQUEST,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "stored signature not 65 bytes".to_string(),
                )
            })?;
            return Ok(Json(render(cfg.my_member_pubkey, &arr)));
        }
        CheckOutcome::Conflict { .. } => {
            return Err(err(
                error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT,
                StatusCode::CONFLICT,
                "tron-tx already signed for this (chain, owner, txid) — unexpected, since \
                 the txID is the whole payload"
                    .to_string(),
            ));
        }
        CheckOutcome::FirstTime => {}
    }

    // 5. HSM-sign the txID; low-S normalize; normalize v to TRON 0/1; verify
    //    recovery.
    let sig_hsm = state
        .hsm
        .sign_digest(cfg.my_signer_address, B256::from(computed))
        .await
        .map_err(|e| hsm_unavailable(&e))?;
    // AUD-TRON-LOWS: EIP-2 low-S normalization, while `v` is still in the HSM's
    // 27/28 convention (the shared helper flips it on normalize). java-tron's
    // `checkSign` may reject high-S; the Web3Signer HSM already emits low-S, so
    // this is defense-in-depth. The recover-verify below re-checks the
    // normalized bytes, so a mis-normalization fails closed.
    let sig_low = crate::sig_norm::normalize_low_s(sig_hsm)?;
    let mut sig65 = sig_low;
    sig65[64] = tron_recovery_v(sig65[64]);
    let recovered = recover_evm20(&computed, &sig65).map_err(|e| {
        err(
            error_codes::SIGNER_RECOVER_MISMATCH,
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("HSM signature did not recover: {e}"),
        )
    })?;
    if recovered.as_slice() != cfg.my_signer_address.as_slice() {
        return Err(err(
            error_codes::SIGNER_RECOVER_MISMATCH,
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "HSM signature recovered to 0x{}, expected configured signer {:#x}",
                alloy_primitives::hex::encode(recovered),
                cfg.my_signer_address
            ),
        ));
    }

    // 5b. Record + return.
    if let Err(e) = state
        .replay
        .record_tron_tx(
            req.chain_id,
            req.owner_address.clone(),
            computed,
            computed,
            sig65.to_vec(),
            now_unix_secs(),
        )
        .await
    {
        if !matches!(e, crate::replay::ReplayError::Duplicate) {
            return Err(err(
                error_codes::BAD_REQUEST,
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("replay record: {e}"),
            ));
        }
        // L10: lost the write race; the winner already recorded. Re-read
        // and return its cached signature idempotently.
        return match state
            .replay
            .check_tron_tx(req.chain_id, req.owner_address.clone(), computed, computed)
            .await
            .map_err(|e| {
                err(
                    error_codes::BAD_REQUEST,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("replay db: {e}"),
                )
            })? {
            CheckOutcome::Idempotent(rec) => {
                let arr: [u8; 65] = rec.signature.as_slice().try_into().map_err(|_| {
                    err(
                        error_codes::BAD_REQUEST,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "stored signature not 65 bytes".to_string(),
                    )
                })?;
                Ok(Json(render(cfg.my_member_pubkey, &arr)))
            }
            CheckOutcome::Conflict { .. } => Err(err(
                error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT,
                StatusCode::CONFLICT,
                "tron-tx already signed for this (chain, owner, txid) — unexpected, since \
                 the txID is the whole payload"
                    .to_string(),
            )),
            CheckOutcome::FirstTime => Err(err(
                error_codes::BAD_REQUEST,
                StatusCode::INTERNAL_SERVER_ERROR,
                "record race left no row".to_string(),
            )),
        };
    }

    Ok(Json(render(cfg.my_member_pubkey, &sig65)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::InMemoryReplayStore;
    use crate::server::{DaemonConfig, DaemonState};
    use k256::ecdsa::SigningKey;
    use xindex_tron_tx::addr::{evm_address, pubkey_to_address};

    /// k256 test key → (EOA address, compressed member pubkey).
    #[expect(clippy::expect_used, reason = "test code")]
    fn key_identity(seed: u8) -> (SigningKey, Address, [u8; 33]) {
        let sk = SigningKey::from_slice(&[seed; 32]).expect("key");
        let vk = sk.verifying_key();
        let comp = vk.to_encoded_point(true);
        let mut pk = [0u8; 33];
        pk.copy_from_slice(comp.as_bytes());
        let a = evm_address(&pk).expect("addr");
        (sk, Address::from(a), pk)
    }

    /// HSM stub: signs the prehash with the test key, returns recoverable
    /// 65-byte `r ‖ s ‖ v` with v = 27 + recid (the EVM convention the
    /// handler normalizes to TRON's 0/1).
    #[derive(Debug)]
    struct StubHsm {
        sk: SigningKey,
    }

    #[async_trait::async_trait]
    impl HsmDigestSigner for StubHsm {
        async fn sign_digest(&self, _address: Address, digest: B256) -> Result<[u8; 65], HsmError> {
            let (sig, recid) = self
                .sk
                .sign_prehash_recoverable(digest.as_slice())
                .map_err(|e| HsmError::Decode(format!("test sign: {e}")))?;
            let mut out = [0u8; 65];
            out[..64].copy_from_slice(sig.to_bytes().as_ref());
            out[64] = 27 + recid.to_byte();
            Ok(out)
        }
    }

    fn cfg() -> DaemonConfig {
        DaemonConfig {
            chain_id: 1,
            verifying_contract: Address::ZERO,
            eth_address: Address::ZERO,
        }
    }

    /// Build a TRX request whose `txid` matches the rebuilt `raw_data`.
    fn sample_trx(owner_pubkey: [u8; 33]) -> (String, TronTxSignRequest) {
        #[expect(clippy::expect_used, reason = "test code")]
        let owner = pubkey_to_address(&owner_pubkey).expect("owner addr");
        // Destination = a THORChain Asgard inbound (any valid T-address).
        let (_d, _da, dpk) = key_identity(40);
        #[expect(clippy::expect_used, reason = "test code")]
        let dest = pubkey_to_address(&dpk).expect("dest addr");
        let mut req = TronTxSignRequest {
            chain_id: ChainId::Tron,
            asset: TronAssetKind::Trx,
            owner_address: owner.clone(),
            to_address: dest,
            amount: "5000000".to_string(),
            contract_address: None,
            permission_id: 2,
            ref_block_bytes: "0x00b0".to_string(),
            ref_block_hash: "0x3f1bc96dc80e7f61".to_string(),
            expiration: "1548974130000".to_string(),
            timestamp: "1548974072663".to_string(),
            fee_limit: None,
            memo: "=:ETH.USDT:0xabc:1".to_string(),
            txid: String::new(),
        };
        #[expect(clippy::expect_used, reason = "test code")]
        let raw = rebuild_raw_data(&req).expect("rebuild");
        req.txid = format!("0x{}", alloy_primitives::hex::encode(txid(&raw)));
        (owner, req)
    }

    fn state(
        owner: String,
        pubkey: [u8; 33],
        signer: Address,
        sk: SigningKey,
    ) -> DaemonState<InMemoryReplayStore, StubHsm> {
        DaemonState::new(
            cfg(),
            Arc::new(InMemoryReplayStore::new()),
            Arc::new(StubHsm { sk }),
        )
        .with_tron(TronSignerConfig {
            chain: ChainId::Tron,
            owner_address: owner,
            my_signer_address: signer,
            my_member_pubkey: pubkey,
        })
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn signs_and_recovers_under_signer_address() {
        let (sk, signer, pubkey) = key_identity(7);
        let (owner, req) = sample_trx(pubkey);
        let st = state(owner, pubkey, signer, sk);
        let resp = handle_tron_tx(State(st), Json(req)).await.expect("sign");
        assert_eq!(
            resp.pubkey,
            format!("0x{}", alloy_primitives::hex::encode(pubkey))
        );
        // 65-byte recoverable sig, 0x-prefixed, v normalized to 0/1.
        let sig =
            alloy_primitives::hex::decode(resp.signature.trim_start_matches("0x")).expect("hex");
        assert_eq!(sig.len(), 65);
        assert!(sig[64] <= 1, "v must be the TRON 0/1 form");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rejects_wrong_owner() {
        let (sk, signer, pubkey) = key_identity(7);
        let (owner, mut req) = sample_trx(pubkey);
        let (_o2, _a2, other) = key_identity(99);
        req.owner_address = pubkey_to_address(&other).expect("addr");
        let st = state(owner, pubkey, signer, sk);
        let (status, body) = handle_tron_tx(State(st), Json(req)).await.expect_err("err");
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.code, error_codes::WRONG_TRON_ACCOUNT);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rejects_tampered_txid() {
        let (sk, signer, pubkey) = key_identity(7);
        let (owner, mut req) = sample_trx(pubkey);
        // A txID that won't match the rebuilt raw_data.
        req.txid = format!("0x{}", "00".repeat(32));
        let st = state(owner, pubkey, signer, sk);
        let (status, body) = handle_tron_tx(State(st), Json(req)).await.expect_err("err");
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.code, error_codes::TRON_TX_MISMATCH);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn tampered_amount_changes_txid_and_is_rejected() {
        let (sk, signer, pubkey) = key_identity(7);
        let (owner, mut req) = sample_trx(pubkey);
        // Keep the (matching) txid but bump the amount — the rebuilt
        // raw_data no longer hashes to the claimed txid.
        req.amount = "9999999".to_string();
        let st = state(owner, pubkey, signer, sk);
        let (status, body) = handle_tron_tx(State(st), Json(req)).await.expect_err("err");
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.code, error_codes::TRON_TX_MISMATCH);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn unconfigured_chain_is_endpoint_disabled() {
        let (_sk, _signer, pubkey) = key_identity(7);
        let (_owner, req) = sample_trx(pubkey);
        let st: DaemonState<InMemoryReplayStore, StubHsm> = DaemonState::new(
            cfg(),
            Arc::new(InMemoryReplayStore::new()),
            Arc::new(StubHsm {
                sk: SigningKey::from_slice(&[7u8; 32]).expect("key"),
            }),
        );
        let (status, body) = handle_tron_tx(State(st), Json(req)).await.expect_err("err");
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body.code, error_codes::ENDPOINT_DISABLED);
    }

    /// HSM stub that returns a HIGH-S signature (r, n−s) with the recovery
    /// byte that is correct for that high-S form. Exercises the
    /// AUD-TRON-LOWS normalization on the handler path.
    #[derive(Debug)]
    struct HighSStubHsm {
        sk: SigningKey,
    }

    #[async_trait::async_trait]
    impl HsmDigestSigner for HighSStubHsm {
        async fn sign_digest(&self, _address: Address, digest: B256) -> Result<[u8; 65], HsmError> {
            let (sig, recid) = self
                .sk
                .sign_prehash_recoverable(digest.as_slice())
                .map_err(|e| HsmError::Decode(format!("test sign: {e}")))?;
            // Negate s → high-S; the high-S sig recovers with flipped parity.
            let neg_s = -*sig.s();
            let high = k256::ecdsa::Signature::from_scalars(sig.r().to_bytes(), neg_s.to_bytes())
                .map_err(|e| HsmError::Decode(format!("test high sig: {e}")))?;
            let mut out = [0u8; 65];
            out[..64].copy_from_slice(high.to_bytes().as_ref());
            out[64] = 27 + (recid.to_byte() ^ 1);
            Ok(out)
        }
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn high_s_hsm_signature_is_normalized() {
        let (_sk, signer, pubkey) = key_identity(7);
        let (owner, req) = sample_trx(pubkey);
        let st = DaemonState::new(
            cfg(),
            Arc::new(InMemoryReplayStore::new()),
            Arc::new(HighSStubHsm {
                sk: SigningKey::from_slice(&[7u8; 32]).expect("key"),
            }),
        )
        .with_tron(TronSignerConfig {
            chain: ChainId::Tron,
            owner_address: owner,
            my_signer_address: signer,
            my_member_pubkey: pubkey,
        });
        // The handler must normalize the high-S response (and recover-verify
        // the normalized bytes) rather than reject it.
        let resp = handle_tron_tx(State(st), Json(req)).await.expect("sign");
        let sig =
            alloy_primitives::hex::decode(resp.signature.trim_start_matches("0x")).expect("hex");
        assert_eq!(sig.len(), 65);
        assert!(sig[64] <= 1, "v must be the TRON 0/1 form");
        // The stored r||s is canonical low-S.
        assert!(
            k256::ecdsa::Signature::from_slice(&sig[..64])
                .expect("parse")
                .normalize_s()
                .is_none(),
            "output must be low-S after normalization"
        );
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn idempotent_replay_returns_cached_signature() {
        let (sk, signer, pubkey) = key_identity(7);
        let (owner, req) = sample_trx(pubkey);
        let st = state(owner, pubkey, signer, sk);
        let first = handle_tron_tx(State(st.clone()), Json(req.clone()))
            .await
            .expect("first");
        let second = handle_tron_tx(State(st), Json(req)).await.expect("second");
        assert_eq!(first.signature, second.signature);
    }
}
