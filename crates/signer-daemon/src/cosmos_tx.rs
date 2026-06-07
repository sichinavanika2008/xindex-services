//! C5 — `POST /api/v1/sign/cosmos-tx` handler.
//!
//! The Phase 3.3 Cosmos custody-family signing endpoint. Same per-chain
//! dispatch shape as [`crate::evm_safe`] — `DaemonState.cosmos` decides
//! which chains this daemon serves; a request for an unconfigured chain
//! returns `404 endpoint_disabled`.
//!
//! ## Pipeline
//!
//! 1. Look up the per-chain [`CosmosSignerConfig`] by `req.chain_id`.
//! 2. Refuse if `req.account_address` is not the daemon's configured
//!    multisig account (`wrong_cosmos_account`).
//! 3. RE-COMPUTE the amino `StdSignDoc` sign-bytes hash from the semantic
//!    fields (via `cosmos-tx` C3) and refuse with `sign_doc_mismatch` if
//!    the caller's claim disagrees — the daemon never blind-signs.
//! 4. Replay-DB on `(chain_id, account_address, sequence)`: `FirstTime`
//!    → sign; `Idempotent` → cached; `Conflict` → 409.
//! 5. HSM-sign the 32-byte digest, normalize to the 64-byte low-S compact
//!    form, and VERIFY it against the configured member pubkey (Cosmos
//!    signatures are non-recoverable, so this replaces the EVM path's
//!    recover-verify — it still catches an HSM key-mapping bug / wrong-key
//!    / corrupted response before recording).

use std::sync::Arc;

use alloy_primitives::B256;
use axum::{extract::State, http::StatusCode, response::Json};
use xindex_cosmos_tx::amino::CosmosSendSignDoc;
use xindex_cosmos_tx::sigs as cosmos_sigs;
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{error_codes, CosmosSignResponse, CosmosTxSignRequest, ErrorBody};

use crate::replay::{CheckOutcome, ReplayStore};
use crate::server::DaemonState;
use crate::web3signer::{HsmDigestSigner, HsmError};

/// Per-chain Cosmos signing role. One entry per Cosmos chain this daemon
/// is a multisig member of (no cross-chain key sharing — DL-P3-7).
#[derive(Debug, Clone)]
pub struct CosmosSignerConfig {
    /// Which Cosmos chain this config serves.
    pub chain: ChainId,
    /// The consensus chain-id this daemon will sign for (e.g.
    /// `"cosmoshub-4"`), pinned at deploy from the key ceremony. The
    /// chain-id is bound into the amino sign-bytes; a request whose
    /// `cosmos_chain_id` differs is refused, so a signature authorized for
    /// this network can never be replayed onto a different Cosmos chain the
    /// same secp256k1 key controls (mirrors the EVM handler's chain pin).
    pub cosmos_chain_id: String,
    /// The bech32 `LegacyAminoPubKey` multisig account address this daemon
    /// signs for. A request whose `account_address` differs is refused.
    pub account_address: String,
    /// EOA handle the HSM frontend keys the signing call on (the same
    /// secp256k1 key whose compressed pubkey is `my_member_pubkey`).
    pub my_signer_address: alloy_primitives::Address,
    /// This daemon's 33-byte compressed member pubkey — used to VERIFY
    /// the HSM signature and returned to the coordinator so it can place
    /// the partial sig at the correct `CompactBitArray` position.
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

fn parse_b256_hex(field: &str, hex_str: &str) -> Result<[u8; 32], (StatusCode, Json<ErrorBody>)> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = alloy_primitives::hex::decode(stripped).map_err(|e| {
        err(
            error_codes::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            format!("{field}: bad hex: {e}"),
        )
    })?;
    bytes.as_slice().try_into().map_err(|_| {
        err(
            error_codes::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            format!("{field}: expected 32-byte hash, got {} bytes", bytes.len()),
        )
    })
}

fn render(pubkey: [u8; 33], sig64: &[u8]) -> CosmosSignResponse {
    CosmosSignResponse {
        pubkey: format!("0x{}", alloy_primitives::hex::encode(pubkey)),
        signature: format!("0x{}", alloy_primitives::hex::encode(sig64)),
    }
}

fn hsm_unavailable(e: &HsmError) -> (StatusCode, Json<ErrorBody>) {
    err(
        error_codes::HSM_UNAVAILABLE,
        StatusCode::SERVICE_UNAVAILABLE,
        e.to_string(),
    )
}

/// Axum handler for `/api/v1/sign/cosmos-tx`.
///
/// # Errors
/// Returns `(StatusCode, Json<ErrorBody>)` with a stable error code:
/// `endpoint_disabled` (404), `wrong_cosmos_account` (422),
/// `wrong_cosmos_chain_id` (422),
/// `sign_doc_mismatch` (422), `bad_request` (400),
/// `conflict_already_signed_different` (409), `hsm_unavailable` (503),
/// `signer_recover_mismatch` (500 — HSM sig fails to verify under the
/// configured member pubkey).
#[expect(
    clippy::too_many_lines,
    reason = "single sequential validate-then-sign pipeline; splitting fragments the audit-relevant ordering of checks"
)]
pub async fn handle_cosmos_tx<S, H>(
    State(state): State<DaemonState<S, H>>,
    Json(req): Json<CosmosTxSignRequest>,
) -> Result<Json<CosmosSignResponse>, (StatusCode, Json<ErrorBody>)>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    // 1. Per-chain config lookup.
    let cfg: Arc<CosmosSignerConfig> =
        state.cosmos.get(&req.chain_id).cloned().ok_or_else(|| {
            err(
                error_codes::ENDPOINT_DISABLED,
                StatusCode::NOT_FOUND,
                format!(
                    "Cosmos role for chain {:?} not enabled on this daemon",
                    req.chain_id
                ),
            )
        })?;

    // 2. Account must match the configured multisig account.
    if req.account_address != cfg.account_address {
        return Err(err(
            error_codes::WRONG_COSMOS_ACCOUNT,
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "account_address mismatch: configured {}, request {}",
                cfg.account_address, req.account_address
            ),
        ));
    }

    // 2b. Consensus chain-id must match the pinned config. The chain-id is
    // bound into the sign-bytes; without this pin a signature authorized
    // for this network could be replayed onto another Cosmos chain the same
    // key controls (the sign-doc hash would still recompute consistently).
    if req.cosmos_chain_id != cfg.cosmos_chain_id {
        return Err(err(
            error_codes::WRONG_COSMOS_CHAIN_ID,
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "cosmos_chain_id mismatch: configured {}, request {}",
                cfg.cosmos_chain_id, req.cosmos_chain_id
            ),
        ));
    }

    // 3. Recompute the amino sign-bytes hash and compare to the claim.
    let doc = CosmosSendSignDoc {
        account_number: &req.account_number,
        chain_id: &req.cosmos_chain_id,
        fee_amount: &req.fee_amount,
        gas: &req.gas_limit,
        memo: &req.memo,
        from_address: &req.account_address,
        to_address: &req.to_address,
        amount: &req.amount,
        denom: &req.denom,
    };
    // A non-canonical numeric field (caught here) is malformed client
    // input, not a server fault — return BAD_REQUEST.
    let recomputed = doc.sign_bytes_sha256(&req.sequence).map_err(|e| {
        err(
            error_codes::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            format!("amino sign-bytes: {e}"),
        )
    })?;
    let claimed = parse_b256_hex("sign_doc_hash", &req.sign_doc_hash)?;
    if recomputed != claimed {
        return Err(err(
            error_codes::SIGN_DOC_MISMATCH,
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "recomputed sign_doc_hash 0x{} != claimed 0x{}",
                alloy_primitives::hex::encode(recomputed),
                alloy_primitives::hex::encode(claimed),
            ),
        ));
    }

    let sequence = req.sequence.parse::<u64>().map_err(|e| {
        err(
            error_codes::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            format!("sequence: bad u64: {e}"),
        )
    })?;

    // 4. Replay-DB pre-flight.
    let outcome = state
        .replay
        .check_cosmos_tx(
            req.chain_id,
            req.account_address.clone(),
            sequence,
            recomputed,
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
                "cosmos-tx already signed for this (chain, account, sequence) under a \
                 different payload"
                    .to_string(),
            ));
        }
        CheckOutcome::FirstTime => {}
    }

    // 5. HSM-sign the digest, normalize to 64-byte low-S, verify.
    let sig65 = state
        .hsm
        .sign_digest(cfg.my_signer_address, B256::from(recomputed))
        .await
        .map_err(|e| hsm_unavailable(&e))?;
    let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
    r.copy_from_slice(&sig65[..32]);
    s.copy_from_slice(&sig65[32..64]);
    let sig64 = cosmos_sigs::to_cosmos_compact_low_s(&r, &s).map_err(|e| {
        err(
            error_codes::SIGNER_RECOVER_MISMATCH,
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("HSM signature did not parse: {e}"),
        )
    })?;
    cosmos_sigs::verify(&cfg.my_member_pubkey, &recomputed, &sig64).map_err(|e| {
        err(
            error_codes::SIGNER_RECOVER_MISMATCH,
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("HSM signature does not verify under configured member pubkey: {e}"),
        )
    })?;

    // 5b. Record + return.
    if let Err(e) = state
        .replay
        .record_cosmos_tx(
            req.chain_id,
            req.account_address.clone(),
            sequence,
            recomputed,
            sig64.to_vec(),
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
            .check_cosmos_tx(
                req.chain_id,
                req.account_address.clone(),
                sequence,
                recomputed,
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
                "cosmos-tx already signed for this (chain, account, sequence) under a \
                 different payload"
                    .to_string(),
            )),
            CheckOutcome::FirstTime => Err(err(
                error_codes::BAD_REQUEST,
                StatusCode::INTERNAL_SERVER_ERROR,
                "record race left no row".to_string(),
            )),
        };
    }

    Ok(Json(render(cfg.my_member_pubkey, &sig64)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::InMemoryReplayStore;
    use crate::server::{DaemonConfig, DaemonState};
    use alloy_primitives::Address;
    use k256::ecdsa::SigningKey;

    /// k256 test key → (EOA address, compressed member pubkey).
    #[expect(clippy::expect_used, reason = "test code")]
    fn key_identity() -> (SigningKey, Address, [u8; 33]) {
        let sk = SigningKey::from_slice(&[7u8; 32]).expect("key");
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

    /// HSM stub that signs the prehash with the test key, returning a
    /// recoverable 65-byte `r ‖ s ‖ v` (the handler drops `v`).
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

    const ACCOUNT: &str = "cosmos1vault0multisig0account0000000000000000";

    fn sample_request(sign_doc_hash: [u8; 32]) -> CosmosTxSignRequest {
        CosmosTxSignRequest {
            chain_id: ChainId::Gaia,
            account_address: ACCOUNT.to_string(),
            cosmos_chain_id: "cosmoshub-4".to_string(),
            account_number: "12345".to_string(),
            sequence: "7".to_string(),
            to_address: "cosmos1asgard0inbound".to_string(),
            amount: "1000000".to_string(),
            denom: "uatom".to_string(),
            fee_amount: "5000".to_string(),
            gas_limit: "200000".to_string(),
            memo: "=:ETH.USDT:0xabc:0/1/0".to_string(),
            sign_doc_hash: format!("0x{}", alloy_primitives::hex::encode(sign_doc_hash)),
        }
    }

    /// Recompute the digest the handler will compute for `sample_request`.
    #[expect(clippy::expect_used, reason = "test code")]
    fn expected_digest() -> [u8; 32] {
        CosmosSendSignDoc {
            account_number: "12345",
            chain_id: "cosmoshub-4",
            fee_amount: "5000",
            gas: "200000",
            memo: "=:ETH.USDT:0xabc:0/1/0",
            from_address: ACCOUNT,
            to_address: "cosmos1asgard0inbound",
            amount: "1000000",
            denom: "uatom",
        }
        .sign_bytes_sha256("7")
        .expect("digest")
    }

    fn state(
        pubkey: [u8; 33],
        signer: Address,
        sk: SigningKey,
    ) -> DaemonState<InMemoryReplayStore, StubHsm> {
        DaemonState::new(
            cfg(),
            Arc::new(InMemoryReplayStore::new()),
            Arc::new(StubHsm { sk }),
        )
        .with_cosmos(CosmosSignerConfig {
            chain: ChainId::Gaia,
            cosmos_chain_id: "cosmoshub-4".to_string(),
            account_address: ACCOUNT.to_string(),
            my_signer_address: signer,
            my_member_pubkey: pubkey,
        })
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn signs_and_verifies_under_member_pubkey() {
        let (sk, signer, pubkey) = key_identity();
        let st = state(pubkey, signer, sk);
        let req = sample_request(expected_digest());
        let resp = handle_cosmos_tx(State(st), Json(req)).await.expect("sign");
        assert_eq!(
            resp.pubkey,
            format!("0x{}", alloy_primitives::hex::encode(pubkey))
        );
        // 64-byte (128 hex) compact signature + 0x.
        assert_eq!(resp.signature.len(), 2 + 128);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rejects_wrong_account() {
        let (sk, signer, pubkey) = key_identity();
        let st = state(pubkey, signer, sk);
        let mut req = sample_request(expected_digest());
        req.account_address = "cosmos1someoneelse".to_string();
        let (status, body) = handle_cosmos_tx(State(st), Json(req))
            .await
            .expect_err("err");
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.code, error_codes::WRONG_COSMOS_ACCOUNT);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rejects_wrong_cosmos_chain_id() {
        let (sk, signer, pubkey) = key_identity();
        let st = state(pubkey, signer, sk);
        // A request for a different Cosmos network the same key controls.
        let mut req = sample_request(expected_digest());
        req.cosmos_chain_id = "theta-testnet-001".to_string();
        let (status, body) = handle_cosmos_tx(State(st), Json(req))
            .await
            .expect_err("err");
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.code, error_codes::WRONG_COSMOS_CHAIN_ID);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rejects_sign_doc_mismatch() {
        let (sk, signer, pubkey) = key_identity();
        let st = state(pubkey, signer, sk);
        // Claim a bogus digest that won't match the recomputed one.
        let req = sample_request([0xab; 32]);
        let (status, body) = handle_cosmos_tx(State(st), Json(req))
            .await
            .expect_err("err");
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.code, error_codes::SIGN_DOC_MISMATCH);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn unconfigured_chain_is_endpoint_disabled() {
        // State with NO cosmos role configured.
        let st: DaemonState<InMemoryReplayStore, StubHsm> = DaemonState::new(
            cfg(),
            Arc::new(InMemoryReplayStore::new()),
            Arc::new(StubHsm {
                sk: SigningKey::from_slice(&[7u8; 32]).expect("key"),
            }),
        );
        let req = sample_request(expected_digest());
        let (status, body) = handle_cosmos_tx(State(st), Json(req))
            .await
            .expect_err("err");
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body.code, error_codes::ENDPOINT_DISABLED);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn idempotent_replay_returns_cached_signature() {
        let (sk, signer, pubkey) = key_identity();
        let st = state(pubkey, signer, sk);
        let req = sample_request(expected_digest());
        let first = handle_cosmos_tx(State(st.clone()), Json(req.clone()))
            .await
            .expect("first");
        let second = handle_cosmos_tx(State(st), Json(req))
            .await
            .expect("second");
        assert_eq!(first.signature, second.signature);
    }
}
