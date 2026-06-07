//! C5 — `POST /api/v1/sign/xrp-tx` handler.
//!
//! The Phase 4.4 XRP custody-family signing endpoint. Same per-chain
//! dispatch shape as [`crate::cosmos_tx`] — `DaemonState.xrp` decides
//! which chains this daemon serves; a request for an unconfigured chain
//! returns `404 endpoint_disabled`.
//!
//! ## Pipeline
//!
//! 1. Look up the per-chain [`XrpSignerConfig`] by `req.chain_id`.
//! 2. Refuse if `req.account_address` is not the daemon's configured
//!    multisig account (`wrong_xrp_account`).
//! 3. RE-SERIALIZE the canonical `STObject` Payment body (empty
//!    `SigningPubKey`, no `Signers`) from the semantic fields (via
//!    `xrp-tx` C3) and refuse with `xrp_tx_mismatch` if it does not match
//!    the caller-supplied `signing_blob` — the daemon never blind-signs.
//! 4. Compute THIS daemon's per-signer multi-signing digest locally:
//!    `SHA512Half(SMT\0 ‖ body ‖ my_account_id)`. `my_account_id` is
//!    derived from the configured member pubkey — never transmitted. This
//!    is the load-bearing divergence from Cosmos: every member signs a
//!    DIFFERENT message.
//! 5. Replay-DB on `(chain_id, account_address, sequence)`: `FirstTime`
//!    → sign; `Idempotent` → cached; `Conflict` → 409.
//! 6. HSM-sign the 32-byte digest, DER-encode low-S, and VERIFY it under
//!    the configured member pubkey (XRPL signatures are non-recoverable,
//!    so this replaces the EVM recover-verify and catches an HSM
//!    key-mapping bug / wrong-key / corrupted response before recording).

use std::sync::Arc;

use alloy_primitives::B256;
use axum::{extract::State, http::StatusCode, response::Json};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{error_codes, ErrorBody, XrpSignResponse, XrpTxSignRequest};
use xindex_xrp_tx::addr::{account_id, decode_classic_address};
use xindex_xrp_tx::signing::multisign_digest;
use xindex_xrp_tx::sigs as xrp_sigs;
use xindex_xrp_tx::tx::{serialize_for_multisign, PaymentBody};

use crate::replay::{CheckOutcome, ReplayStore};
use crate::server::DaemonState;
use crate::web3signer::{HsmDigestSigner, HsmError};

/// Per-chain XRP signing role. One entry per XRP chain this daemon is a
/// `SignerList` member of (no cross-chain key sharing — DL-P3-7).
#[derive(Debug, Clone)]
pub struct XrpSignerConfig {
    /// Which XRP chain this config serves.
    pub chain: ChainId,
    /// The `SignerList` multisig account (classic r-address) this daemon
    /// signs for. A request whose `account_address` differs is refused.
    pub account_address: String,
    /// EOA handle the HSM frontend keys the signing call on (the same
    /// secp256k1 key whose compressed pubkey is `my_member_pubkey`).
    pub my_signer_address: alloy_primitives::Address,
    /// This daemon's 33-byte compressed member pubkey — used to VERIFY
    /// the HSM signature and returned to the coordinator so it can place
    /// the partial sig at the correct `Signer` entry. The daemon's own
    /// `AccountID` (the multi-signing blob suffix) is derived from this.
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

fn bad(field: &str, e: impl std::fmt::Display) -> (StatusCode, Json<ErrorBody>) {
    err(
        error_codes::BAD_REQUEST,
        StatusCode::BAD_REQUEST,
        format!("{field}: {e}"),
    )
}

/// Parse + decode the request's semantic fields into a [`PaymentBody`]
/// (mainnet: no `NetworkID`) plus the `u32` sequence.
fn build_payment_body(
    req: &XrpTxSignRequest,
) -> Result<(PaymentBody, u32), (StatusCode, Json<ErrorBody>)> {
    let account =
        decode_classic_address(&req.account_address).map_err(|e| bad("account_address", e))?;
    let destination =
        decode_classic_address(&req.destination).map_err(|e| bad("destination", e))?;
    let amount_drops = req
        .amount_drops
        .parse::<u64>()
        .map_err(|e| bad("amount_drops", e))?;
    let fee_drops = req
        .fee_drops
        .parse::<u64>()
        .map_err(|e| bad("fee_drops", e))?;
    let sequence = req
        .sequence
        .parse::<u32>()
        .map_err(|e| bad("sequence", e))?;
    let last_ledger_sequence = req
        .last_ledger_sequence
        .parse::<u32>()
        .map_err(|e| bad("last_ledger_sequence", e))?;
    Ok((
        PaymentBody {
            account,
            destination,
            amount_drops,
            fee_drops,
            sequence,
            last_ledger_sequence: Some(last_ledger_sequence),
            network_id: None,
            memo: req.memo.clone().into_bytes(),
        },
        sequence,
    ))
}

fn render(pubkey: [u8; 33], der: &[u8]) -> XrpSignResponse {
    XrpSignResponse {
        pubkey: format!("0x{}", alloy_primitives::hex::encode(pubkey)),
        // DER hex, no 0x prefix (mirrors the XRPL TxnSignature convention).
        signature: alloy_primitives::hex::encode(der),
    }
}

fn hsm_unavailable(e: &HsmError) -> (StatusCode, Json<ErrorBody>) {
    err(
        error_codes::HSM_UNAVAILABLE,
        StatusCode::SERVICE_UNAVAILABLE,
        e.to_string(),
    )
}

/// Axum handler for `/api/v1/sign/xrp-tx`.
///
/// # Errors
/// Returns `(StatusCode, Json<ErrorBody>)` with a stable error code:
/// `endpoint_disabled` (404), `wrong_xrp_account` (422),
/// `xrp_tx_mismatch` (422), `bad_request` (400),
/// `conflict_already_signed_different` (409), `hsm_unavailable` (503),
/// `signer_recover_mismatch` (500 — HSM sig fails DER/verify under the
/// configured member pubkey).
#[expect(
    clippy::too_many_lines,
    reason = "single sequential validate-then-sign pipeline; splitting fragments the audit-relevant ordering of checks"
)]
pub async fn handle_xrp_tx<S, H>(
    State(state): State<DaemonState<S, H>>,
    Json(req): Json<XrpTxSignRequest>,
) -> Result<Json<XrpSignResponse>, (StatusCode, Json<ErrorBody>)>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    // 1. Per-chain config lookup.
    let cfg: Arc<XrpSignerConfig> = state.xrp.get(&req.chain_id).cloned().ok_or_else(|| {
        err(
            error_codes::ENDPOINT_DISABLED,
            StatusCode::NOT_FOUND,
            format!(
                "XRP role for chain {:?} not enabled on this daemon",
                req.chain_id
            ),
        )
    })?;

    // 2. Account must match the configured multisig account.
    if req.account_address != cfg.account_address {
        return Err(err(
            error_codes::WRONG_XRP_ACCOUNT,
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "account_address mismatch: configured {}, request {}",
                cfg.account_address, req.account_address
            ),
        ));
    }

    // 3. Re-serialize the canonical Payment body and compare to the claim.
    let (body_inputs, sequence) = build_payment_body(&req)?;
    let body = serialize_for_multisign(&body_inputs).map_err(|e| bad("payment body", e))?;
    let claimed = {
        let s = req
            .signing_blob
            .strip_prefix("0x")
            .unwrap_or(&req.signing_blob);
        alloy_primitives::hex::decode(s).map_err(|e| bad("signing_blob", e))?
    };
    if body != claimed {
        return Err(err(
            error_codes::XRP_TX_MISMATCH,
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "recomputed body 0x{} != claimed 0x{}",
                alloy_primitives::hex::encode(&body),
                alloy_primitives::hex::encode(&claimed),
            ),
        ));
    }

    // 4. THIS daemon's per-signer digest: SMT\0 ‖ body ‖ my_account_id.
    let my_account_id = account_id(&cfg.my_member_pubkey);
    let digest = multisign_digest(&body, &my_account_id);

    // 5. Replay-DB pre-flight (payload_hash = the per-signer digest).
    let outcome = state
        .replay
        .check_xrp_tx(
            req.chain_id,
            req.account_address.clone(),
            u64::from(sequence),
            digest,
        )
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
            return Ok(Json(render(cfg.my_member_pubkey, &rec.signature)));
        }
        CheckOutcome::Conflict { .. } => {
            return Err(err(
                error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT,
                StatusCode::CONFLICT,
                "xrp-tx already signed for this (chain, account, sequence) under a \
                 different body (e.g. a different LastLedgerSequence) — pick one \
                 deadline per sequence"
                    .to_string(),
            ));
        }
        CheckOutcome::FirstTime => {}
    }

    // 6. HSM-sign the digest, DER-encode low-S, verify under member pubkey.
    let sig65 = state
        .hsm
        .sign_digest(cfg.my_signer_address, B256::from(digest))
        .await
        .map_err(|e| hsm_unavailable(&e))?;
    let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
    r.copy_from_slice(&sig65[..32]);
    s.copy_from_slice(&sig65[32..64]);
    let der = xrp_sigs::der_low_s_from_rs(&r, &s).map_err(|e| {
        err(
            error_codes::SIGNER_RECOVER_MISMATCH,
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("HSM signature did not parse: {e}"),
        )
    })?;
    xrp_sigs::verify_der(&cfg.my_member_pubkey, &digest, &der).map_err(|e| {
        err(
            error_codes::SIGNER_RECOVER_MISMATCH,
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("HSM signature does not verify under configured member pubkey: {e}"),
        )
    })?;

    // 6b. Record + return.
    if let Err(e) = state
        .replay
        .record_xrp_tx(
            req.chain_id,
            req.account_address.clone(),
            u64::from(sequence),
            digest,
            der.clone(),
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
            .check_xrp_tx(
                req.chain_id,
                req.account_address.clone(),
                u64::from(sequence),
                digest,
            )
            .await
            .map_err(|e| {
                err(
                    error_codes::BAD_REQUEST,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("replay db: {e}"),
                )
            })? {
            CheckOutcome::Idempotent(rec) => Ok(Json(render(cfg.my_member_pubkey, &rec.signature))),
            CheckOutcome::Conflict { .. } => Err(err(
                error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT,
                StatusCode::CONFLICT,
                "xrp-tx already signed for this (chain, account, sequence) under a \
                 different body (e.g. a different LastLedgerSequence) — pick one \
                 deadline per sequence"
                    .to_string(),
            )),
            CheckOutcome::FirstTime => Err(err(
                error_codes::BAD_REQUEST,
                StatusCode::INTERNAL_SERVER_ERROR,
                "record race left no row".to_string(),
            )),
        };
    }

    Ok(Json(render(cfg.my_member_pubkey, &der)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::InMemoryReplayStore;
    use crate::server::{DaemonConfig, DaemonState};
    use alloy_primitives::Address;
    use k256::ecdsa::SigningKey;
    use xindex_xrp_tx::addr;
    use xindex_xrp_tx::tx::PaymentBody as Pb;

    /// k256 test key → (EOA address, compressed member pubkey).
    #[expect(clippy::expect_used, reason = "test code")]
    fn key_identity(seed: u8) -> (SigningKey, Address, [u8; 33]) {
        let sk = SigningKey::from_slice(&[seed; 32]).expect("key");
        let vk = sk.verifying_key();
        let comp = vk.to_encoded_point(true);
        let mut pk = [0u8; 33];
        pk.copy_from_slice(comp.as_bytes());
        let unc = vk.to_encoded_point(false);
        let hash = alloy_primitives::keccak256(&unc.as_bytes()[1..]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&hash.as_slice()[12..]);
        (sk, Address::from(a), pk)
    }

    /// HSM stub: signs the prehash with the test key, returns recoverable
    /// 65-byte `r ‖ s ‖ v` (the handler drops `v`).
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

    /// Build the request body for a multisig account from `pubkey`.
    #[expect(clippy::expect_used, reason = "test code")]
    fn sample(pubkey: [u8; 33]) -> (String, XrpTxSignRequest) {
        let account = addr::encode_classic_address(&[0x11; 20]);
        let dest = addr::encode_classic_address(&[0x22; 20]);
        let body = Pb {
            account: [0x11; 20],
            destination: [0x22; 20],
            amount_drops: 1_000_000,
            fee_drops: 60,
            sequence: 7,
            last_ledger_sequence: Some(9_000_007),
            network_id: None,
            memo: b"=:ETH.USDT:0xabc:0".to_vec(),
        };
        let serialized = serialize_for_multisign(&body).expect("serialize");
        let _ = pubkey;
        (
            account.clone(),
            XrpTxSignRequest {
                chain_id: ChainId::Xrp,
                account_address: account,
                destination: dest,
                amount_drops: "1000000".to_string(),
                fee_drops: "60".to_string(),
                sequence: "7".to_string(),
                last_ledger_sequence: "9000007".to_string(),
                memo: "=:ETH.USDT:0xabc:0".to_string(),
                signing_blob: format!("0x{}", alloy_primitives::hex::encode(&serialized)),
            },
        )
    }

    fn state(
        account: String,
        pubkey: [u8; 33],
        signer: Address,
        sk: SigningKey,
    ) -> DaemonState<InMemoryReplayStore, StubHsm> {
        DaemonState::new(
            cfg(),
            Arc::new(InMemoryReplayStore::new()),
            Arc::new(StubHsm { sk }),
        )
        .with_xrp(XrpSignerConfig {
            chain: ChainId::Xrp,
            account_address: account,
            my_signer_address: signer,
            my_member_pubkey: pubkey,
        })
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn signs_and_verifies_under_member_pubkey() {
        let (sk, signer, pubkey) = key_identity(7);
        let (account, req) = sample(pubkey);
        let st = state(account, pubkey, signer, sk);
        let resp = handle_xrp_tx(State(st), Json(req)).await.expect("sign");
        assert_eq!(
            resp.pubkey,
            format!("0x{}", alloy_primitives::hex::encode(pubkey))
        );
        // DER sig is non-empty hex, no 0x prefix.
        assert!(!resp.signature.starts_with("0x"));
        assert!(resp.signature.len() >= 2 * 70);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rejects_wrong_account() {
        let (sk, signer, pubkey) = key_identity(7);
        let (account, mut req) = sample(pubkey);
        req.account_address = addr::encode_classic_address(&[0x99; 20]);
        let st = state(account, pubkey, signer, sk);
        let (status, body) = handle_xrp_tx(State(st), Json(req)).await.expect_err("err");
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.code, error_codes::WRONG_XRP_ACCOUNT);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rejects_tampered_signing_blob() {
        let (sk, signer, pubkey) = key_identity(7);
        let (account, mut req) = sample(pubkey);
        // Claim a body that won't match the recomputed one (amount differs).
        req.signing_blob = format!("0x{}", "00".repeat(60));
        let st = state(account, pubkey, signer, sk);
        let (status, body) = handle_xrp_tx(State(st), Json(req)).await.expect_err("err");
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.code, error_codes::XRP_TX_MISMATCH);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn unconfigured_chain_is_endpoint_disabled() {
        let (_sk, _signer, pubkey) = key_identity(7);
        let (_account, req) = sample(pubkey);
        let st: DaemonState<InMemoryReplayStore, StubHsm> = DaemonState::new(
            cfg(),
            Arc::new(InMemoryReplayStore::new()),
            Arc::new(StubHsm {
                sk: SigningKey::from_slice(&[7u8; 32]).expect("key"),
            }),
        );
        let (status, body) = handle_xrp_tx(State(st), Json(req)).await.expect_err("err");
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body.code, error_codes::ENDPOINT_DISABLED);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn idempotent_replay_returns_cached_signature() {
        let (sk, signer, pubkey) = key_identity(7);
        let (account, req) = sample(pubkey);
        let st = state(account, pubkey, signer, sk);
        let first = handle_xrp_tx(State(st.clone()), Json(req.clone()))
            .await
            .expect("first");
        let second = handle_xrp_tx(State(st), Json(req)).await.expect("second");
        assert_eq!(first.signature, second.signature);
    }

    /// A retry at the SAME sequence with a different `LastLedgerSequence`
    /// changes the body → different digest → 409 (the XRP deadline/replay
    /// nuance: one deadline per sequence).
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn different_deadline_same_sequence_conflicts() {
        let (sk, signer, pubkey) = key_identity(7);
        let (account, req) = sample(pubkey);
        let st = state(account, pubkey, signer, sk);
        let _first = handle_xrp_tx(State(st.clone()), Json(req.clone()))
            .await
            .expect("first");
        // Same sequence, later deadline → must rebuild the signing_blob.
        let mut req2 = req;
        req2.last_ledger_sequence = "9000999".to_string();
        let body2 = Pb {
            account: [0x11; 20],
            destination: [0x22; 20],
            amount_drops: 1_000_000,
            fee_drops: 60,
            sequence: 7,
            last_ledger_sequence: Some(9_000_999),
            network_id: None,
            memo: b"=:ETH.USDT:0xabc:0".to_vec(),
        };
        req2.signing_blob = format!(
            "0x{}",
            alloy_primitives::hex::encode(serialize_for_multisign(&body2).expect("ser"))
        );
        let (status, body) = handle_xrp_tx(State(st), Json(req2)).await.expect_err("err");
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.code, error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT);
    }
}
