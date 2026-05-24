//! Axum HTTP server: the four signing endpoints + identity/health.
//!
//! Each handler is the same five-step pipeline (PART 5 / DL-M5-3 +
//! DL-M5-4):
//!
//! 1. Parse the wire request from JSON into the typed
//!    `xindex_shared::signer_wire` shape (type-level routing — no
//!    runtime `kind` discriminator).
//! 2. Decode hex fields into alloy primitives at the boundary.
//! 3. Compute the canonical `payload_hash` (keccak256 of the
//!    fixed-shape field bytes — not the raw JSON, so field-reordering
//!    can't smuggle a different payload past the replay DB).
//! 4. `ReplayStore.check_*`:
//!    - `FirstTime` → compute the EIP-712 digest from
//!      `xindex_shared::eip712`, call the HSM frontend, **record**,
//!      return the signature.
//!    - `Idempotent` → return the cached signature; the HSM is not
//!      invoked again.
//!    - `Conflict` / `MutexViolation` → 409, never reach the HSM.
//! 5. Render the response.

use std::sync::Arc;

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::Eip712Domain;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use xindex_shared::eip712::{
    attestation, attestation_oracle_domain, attestation_signing_hash, redemption_attestation,
    redemption_attestation_signing_hash, refund_attestation, refund_attestation_signing_hash,
};
use xindex_shared::signer_wire::{
    error_codes, AttestationSignRequest, Eip712SignResponse, ErrorBody, HealthResponse,
    KeysResponse, RedemptionDeliverySignRequest, RefundSignRequest,
};

use crate::psbt::{handle_psbt_input, BtcSignerConfig};
use crate::replay::{CheckOutcome, RedemptionCheckOutcome, RedemptionKind, ReplayStore};
use crate::web3signer::{HsmDigestSigner, HsmError};

/// Static daemon configuration. Loaded once at startup; never mutated.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// The Ethereum chain id this daemon signs attestations for (e.g.
    /// mainnet `1`, Sepolia `11155111`). The daemon refuses to sign
    /// for any other chain — defense against a cross-chain replay if
    /// the coordinator were ever pointed at the wrong network.
    pub chain_id: u64,
    /// The deployed `AttestationOracle` address. EIP-712 domain field;
    /// pinning it locally means a malicious coordinator cannot ask the
    /// daemon to sign for a different oracle contract.
    pub verifying_contract: Address,
    /// The signing key's Ethereum address (Set B per
    /// `docs/runbooks/key-ceremony.md`). Asserted to match the HSM
    /// frontend's response on every sign.
    pub eth_address: Address,
}

impl DaemonConfig {
    fn domain(&self) -> Eip712Domain {
        attestation_oracle_domain(self.chain_id, self.verifying_contract)
    }
}

/// Runtime state shared across all handler invocations. `S` + `H` are
/// generic so the test harness can wire `InMemoryReplayStore` + a stub
/// signer without giving up static dispatch.
#[derive(Debug)]
pub struct DaemonState<S: ReplayStore + 'static, H: HsmDigestSigner + 'static> {
    pub config: DaemonConfig,
    pub replay: Arc<S>,
    pub hsm: Arc<H>,
    /// `Some(_)` when this daemon has a Bitcoin signing role
    /// configured (Set A per `docs/runbooks/key-ceremony.md`). When
    /// `None`, the `/api/v1/sign/psbt-input` route is not registered
    /// and the handler short-circuits to `endpoint_disabled`.
    pub btc: Option<Arc<BtcSignerConfig>>,
}

// Manual `Clone` impl: every field is cheap to clone (`Arc<_>` +
// the small `DaemonConfig`), so the bound is just on the wrapper, not
// on `S` or `H`. Lets us avoid forcing `S: Clone` / `H: Clone` (the
// production impls hold a sqlx pool / reqwest client that are already
// `Arc`-internally cheap-clone, but the trait bounds shouldn't need
// to know).
impl<S: ReplayStore + 'static, H: HsmDigestSigner + 'static> Clone for DaemonState<S, H> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            replay: Arc::clone(&self.replay),
            hsm: Arc::clone(&self.hsm),
            btc: self.btc.as_ref().map(Arc::clone),
        }
    }
}

impl<S: ReplayStore + 'static, H: HsmDigestSigner + 'static> DaemonState<S, H> {
    #[must_use]
    pub fn new(config: DaemonConfig, replay: Arc<S>, hsm: Arc<H>) -> Self {
        Self {
            config,
            replay,
            hsm,
            btc: None,
        }
    }

    /// Builder: attach a Bitcoin signing role to an existing state.
    #[must_use]
    pub fn with_btc(mut self, btc: BtcSignerConfig) -> Self {
        self.btc = Some(Arc::new(btc));
        self
    }
}

/// Build the daemon router. Returns a `Router` ready to be served with
/// `axum::serve` (HTTP) or wrapped in a TLS acceptor (mTLS in
/// production, added in a follow-on slice).
pub fn router<S, H>(state: DaemonState<S, H>) -> Router
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    let mut r = Router::new()
        .route("/api/v1/health", get(handle_health::<S, H>))
        .route("/api/v1/keys", get(handle_keys::<S, H>))
        .route(
            "/api/v1/sign/eip712-attestation",
            post(handle_attestation::<S, H>),
        )
        .route(
            "/api/v1/sign/eip712-redemption-delivery",
            post(handle_redemption_delivery::<S, H>),
        )
        .route("/api/v1/sign/eip712-refund", post(handle_refund::<S, H>));
    if state.btc.is_some() {
        r = r.route("/api/v1/sign/psbt-input", post(handle_psbt_input::<S, H>));
    }
    r.with_state(state)
}

// ────────────────────────────────────────────────────────────────────
// Identity / health endpoints
// ────────────────────────────────────────────────────────────────────

async fn handle_health<S, H>(_state: State<DaemonState<S, H>>) -> Json<HealthResponse>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    // A real probe ought to hit the HSM frontend; for v1 code we
    // return `ok = true` as long as the daemon process is up. The
    // operator's monitoring should additionally exercise a signing
    // endpoint against a known fixture to detect a wedged HSM.
    Json(HealthResponse {
        ok: true,
        reason: String::new(),
    })
}

async fn handle_keys<S, H>(state: State<DaemonState<S, H>>) -> Json<KeysResponse>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    let btc_pubkey = state.btc.as_ref().map(|btc| {
        format!(
            "0x{}",
            alloy_primitives::hex::encode(btc.my_pubkey.to_bytes())
        )
    });
    Json(KeysResponse {
        eth_address: Some(format!("{:#x}", state.config.eth_address)),
        btc_pubkey,
    })
}

// ────────────────────────────────────────────────────────────────────
// EIP-712 signing endpoints
// ────────────────────────────────────────────────────────────────────

/// Helper: produce an `(StatusCode, Json<ErrorBody>)` for a bad request.
fn bad(code: &str, message: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            code: code.to_string(),
            message: message.into(),
        }),
    )
}

fn conflict(code: &str, message: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::CONFLICT,
        Json(ErrorBody {
            code: code.to_string(),
            message: message.into(),
        }),
    )
}

fn hsm_unavailable(e: &HsmError) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorBody {
            code: error_codes::HSM_UNAVAILABLE.to_string(),
            message: e.to_string(),
        }),
    )
}

fn parse_b256(hex_str: &str, field: &str) -> Result<B256, (StatusCode, Json<ErrorBody>)> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = alloy_primitives::hex::decode(stripped)
        .map_err(|e| bad(error_codes::BAD_REQUEST, format!("{field}: bad hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| bad(error_codes::BAD_REQUEST, format!("{field}: not 32 bytes")))?;
    Ok(B256::from(arr))
}

fn parse_u256(dec_str: &str, field: &str) -> Result<U256, (StatusCode, Json<ErrorBody>)> {
    U256::from_str_radix(dec_str, 10).map_err(|e| {
        bad(
            error_codes::BAD_REQUEST,
            format!("{field}: bad decimal: {e}"),
        )
    })
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| {
            #[expect(
                clippy::cast_possible_wrap,
                reason = "Unix seconds within i64 range for centuries; saturation acceptable"
            )]
            let v = d.as_secs() as i64;
            v
        })
}

/// Canonical payload hash = `keccak256(field1_bytes || field2_bytes ||
/// …)`, fixed encoding per request kind. The raw JSON is not used as
/// input (deliberate — JSON field-reordering or whitespace must not
/// be able to change the replay-DB key).
fn hash_attestation_payload(intent_id: B256, slot_index: U256, attested_amount: U256) -> [u8; 32] {
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(intent_id.as_slice());
    buf[32..64].copy_from_slice(&slot_index.to_be_bytes::<32>());
    buf[64..96].copy_from_slice(&attested_amount.to_be_bytes::<32>());
    alloy_primitives::keccak256(buf).into()
}

/// Phase 3.0: per-leg replay-key hash. The replay DB's mutex per
/// `(redemption_id, kind)` plus the payload hash now covers per-leg
/// distinctness — two attestations for different legs of the same
/// redemption hash differently (different `leg_index` + `asset_id`)
/// and so are not falsely flagged as a conflict.
fn hash_leg_payload(
    redemption_id: B256,
    leg_index: U256,
    asset_id: B256,
    amount: U256,
) -> [u8; 32] {
    let mut buf = [0u8; 128];
    buf[..32].copy_from_slice(redemption_id.as_slice());
    buf[32..64].copy_from_slice(&leg_index.to_be_bytes::<32>());
    buf[64..96].copy_from_slice(asset_id.as_slice());
    buf[96..128].copy_from_slice(&amount.to_be_bytes::<32>());
    alloy_primitives::keccak256(buf).into()
}

fn render_signature(state: &DaemonConfig, sig: [u8; 65]) -> Eip712SignResponse {
    Eip712SignResponse {
        signature: format!("0x{}", alloy_primitives::hex::encode(sig)),
        signer_address: format!("{:#x}", state.eth_address),
    }
}

async fn handle_attestation<S, H>(
    State(state): State<DaemonState<S, H>>,
    Json(req): Json<AttestationSignRequest>,
) -> Result<Json<Eip712SignResponse>, (StatusCode, Json<ErrorBody>)>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    let intent_id = parse_b256(&req.intent_id, "intent_id")?;
    let slot_index = parse_u256(&req.slot_index, "slot_index")?;
    let attested_amount = parse_u256(&req.attested_amount, "attested_amount")?;
    let payload_hash = hash_attestation_payload(intent_id, slot_index, attested_amount);

    let outcome = state
        .replay
        .check_attestation(intent_id, slot_index, payload_hash)
        .await
        .map_err(|e| bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?;
    match outcome {
        CheckOutcome::Idempotent(rec) => {
            let arr: [u8; 65] = rec.signature.as_slice().try_into().map_err(|_| {
                bad(
                    error_codes::BAD_REQUEST,
                    "stored signature not 65 bytes".to_string(),
                )
            })?;
            return Ok(Json(render_signature(&state.config, arr)));
        }
        CheckOutcome::Conflict { .. } => {
            return Err(conflict(
                error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT,
                "intent already attested with a different amount",
            ));
        }
        CheckOutcome::FirstTime => {}
    }
    let att = attestation(intent_id, slot_index, attested_amount);
    let digest = attestation_signing_hash(&att, &state.config.domain());
    let sig = state
        .hsm
        .sign_digest(state.config.eth_address, digest)
        .await
        .map_err(|e| hsm_unavailable(&e))?;
    state
        .replay
        .record_attestation(
            intent_id,
            slot_index,
            payload_hash,
            sig.to_vec(),
            now_unix_secs(),
        )
        .await
        .map_err(|e| bad(error_codes::BAD_REQUEST, format!("replay record: {e}")))?;
    Ok(Json(render_signature(&state.config, sig)))
}

async fn handle_redemption_delivery<S, H>(
    State(state): State<DaemonState<S, H>>,
    Json(req): Json<RedemptionDeliverySignRequest>,
) -> Result<Json<Eip712SignResponse>, (StatusCode, Json<ErrorBody>)>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    let redemption_id = parse_b256(&req.redemption_id, "redemption_id")?;
    let leg_index = parse_u256(&req.leg_index, "leg_index")?;
    let asset_id = parse_b256(&req.asset_id, "asset_id")?;
    let delivered_amount = parse_u256(&req.delivered_amount, "delivered_amount")?;
    // Replay key generalizes to (redemption_id, leg_index): a second
    // delivery attestation for the same leg with a different amount is
    // a Conflict, never re-signed.
    let payload_hash = hash_leg_payload(redemption_id, leg_index, asset_id, delivered_amount);

    handle_redemption_common(
        &state,
        redemption_id,
        RedemptionKind::Delivery,
        payload_hash,
        || {
            let m = redemption_attestation(redemption_id, leg_index, asset_id, delivered_amount);
            redemption_attestation_signing_hash(&m, &state.config.domain())
        },
    )
    .await
}

async fn handle_refund<S, H>(
    State(state): State<DaemonState<S, H>>,
    Json(req): Json<RefundSignRequest>,
) -> Result<Json<Eip712SignResponse>, (StatusCode, Json<ErrorBody>)>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    let redemption_id = parse_b256(&req.redemption_id, "redemption_id")?;
    let leg_index = parse_u256(&req.leg_index, "leg_index")?;
    let asset_id = parse_b256(&req.asset_id, "asset_id")?;
    let refunded_amount = parse_u256(&req.refunded_amount, "refunded_amount")?;
    let payload_hash = hash_leg_payload(redemption_id, leg_index, asset_id, refunded_amount);

    handle_redemption_common(
        &state,
        redemption_id,
        RedemptionKind::Refund,
        payload_hash,
        || {
            let m = refund_attestation(redemption_id, leg_index, asset_id, refunded_amount);
            refund_attestation_signing_hash(&m, &state.config.domain())
        },
    )
    .await
}

/// Shared body for the two redemption legs — same replay flow, only
/// the digest computation + the `RedemptionKind` differ.
async fn handle_redemption_common<S, H, F>(
    state: &DaemonState<S, H>,
    redemption_id: B256,
    kind: RedemptionKind,
    payload_hash: [u8; 32],
    compute_digest: F,
) -> Result<Json<Eip712SignResponse>, (StatusCode, Json<ErrorBody>)>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
    F: FnOnce() -> B256,
{
    let outcome = state
        .replay
        .check_redemption(redemption_id, kind, payload_hash)
        .await
        .map_err(|e| bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?;
    match outcome {
        RedemptionCheckOutcome::Idempotent(rec) => {
            let arr: [u8; 65] = rec.signature.as_slice().try_into().map_err(|_| {
                bad(
                    error_codes::BAD_REQUEST,
                    "stored signature not 65 bytes".to_string(),
                )
            })?;
            return Ok(Json(render_signature(&state.config, arr)));
        }
        RedemptionCheckOutcome::Conflict { .. } => {
            return Err(conflict(
                error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT,
                "redemption already signed with a different amount",
            ));
        }
        RedemptionCheckOutcome::MutexViolation { .. } => {
            return Err(conflict(
                error_codes::CONFLICT_DELIVERY_REFUND_MUTEX,
                "redemption already resolved as the opposite leg",
            ));
        }
        RedemptionCheckOutcome::FirstTime => {}
    }
    let digest = compute_digest();
    let sig = state
        .hsm
        .sign_digest(state.config.eth_address, digest)
        .await
        .map_err(|e| hsm_unavailable(&e))?;
    state
        .replay
        .record_redemption(
            redemption_id,
            kind,
            payload_hash,
            sig.to_vec(),
            now_unix_secs(),
        )
        .await
        .map_err(|e| bad(error_codes::BAD_REQUEST, format!("replay record: {e}")))?;
    Ok(Json(render_signature(&state.config, sig)))
}

/// Trait-friendly wrapper so the `axum` extractor's `IntoResponse`
/// requirement is satisfied for our error tuple shape.
impl IntoResponse for HsmError {
    fn into_response(self) -> axum::response::Response {
        hsm_unavailable(&self).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::InMemoryReplayStore;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use std::sync::Mutex;
    use tower::ServiceExt;

    /// Captures every digest the daemon asks to be signed so tests can
    /// assert the daemon hands the HSM the correct EIP-712 hash — the
    /// single most important correctness property.
    #[derive(Debug, Default)]
    struct CapturingSigner {
        seen: Mutex<Vec<(Address, B256)>>,
        // Deterministic stub: returns the digest bytes followed by
        // a fixed v byte (27), so the test signature differs per
        // digest. NOT a real ECDSA signature — never used on-chain.
    }

    #[async_trait::async_trait]
    impl HsmDigestSigner for CapturingSigner {
        async fn sign_digest(&self, address: Address, digest: B256) -> Result<[u8; 65], HsmError> {
            #[expect(clippy::unwrap_used, reason = "test code")]
            self.seen.lock().unwrap().push((address, digest));
            let mut sig = [0u8; 65];
            sig[..32].copy_from_slice(digest.as_slice());
            sig[32..64].copy_from_slice(digest.as_slice());
            sig[64] = 27;
            Ok(sig)
        }
    }

    fn cfg() -> DaemonConfig {
        DaemonConfig {
            chain_id: 31337,
            verifying_contract: Address::repeat_byte(0xab),
            eth_address: Address::repeat_byte(0xcd),
        }
    }

    fn build_state() -> (
        DaemonState<InMemoryReplayStore, CapturingSigner>,
        Arc<CapturingSigner>,
    ) {
        let replay = Arc::new(InMemoryReplayStore::new());
        let hsm = Arc::new(CapturingSigner::default());
        (DaemonState::new(cfg(), replay, hsm.clone()), hsm)
    }

    async fn post_json(
        app: &Router,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        #[expect(clippy::expect_used, reason = "test code")]
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("req"),
            )
            .await
            .expect("send");
        let status = resp.status();
        #[expect(clippy::expect_used, reason = "test code")]
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    #[tokio::test]
    async fn attestation_first_sign_records_and_returns_correct_digest() {
        let (state, hsm) = build_state();
        let app = router(state.clone());

        let intent_id = B256::repeat_byte(0x11);
        let slot_index = U256::from(0u8);
        let attested_amount = U256::from(1_000_000u32);

        let (status, body) = post_json(
            &app,
            "/api/v1/sign/eip712-attestation",
            serde_json::json!({
                "intent_id": format!("{intent_id:#x}"),
                "slot_index": slot_index.to_string(),
                "attested_amount": attested_amount.to_string(),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let sig_hex = body["signature"].as_str().unwrap_or("");
        assert!(sig_hex.starts_with("0x") && sig_hex.len() == 2 + 130);

        // The digest seen by the HSM MUST be the canonical EIP-712 hash
        // — recompute locally and compare.
        let att = attestation(intent_id, slot_index, attested_amount);
        let expected = attestation_signing_hash(&att, &state.config.domain());
        #[expect(clippy::unwrap_used, reason = "test code")]
        let seen = hsm.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, state.config.eth_address);
        assert_eq!(seen[0].1, expected);
    }

    #[tokio::test]
    async fn attestation_idempotent_retry_does_not_re_invoke_hsm() {
        let (state, hsm) = build_state();
        let app = router(state.clone());
        let body = serde_json::json!({
            "intent_id": format!("{:#x}", B256::repeat_byte(0x22)),
            "slot_index": "0",
            "attested_amount": "1",
        });
        let (s1, b1) = post_json(&app, "/api/v1/sign/eip712-attestation", body.clone()).await;
        let (s2, b2) = post_json(&app, "/api/v1/sign/eip712-attestation", body).await;
        assert_eq!(s1, StatusCode::OK);
        assert_eq!(s2, StatusCode::OK);
        // Identical signature returned both times.
        assert_eq!(b1["signature"], b2["signature"]);
        // HSM invoked exactly once.
        #[expect(clippy::unwrap_used, reason = "test code")]
        let seen = hsm.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
    }

    #[tokio::test]
    async fn attestation_same_tuple_different_amount_returns_409() {
        let (state, _hsm) = build_state();
        let app = router(state);
        let intent = format!("{:#x}", B256::repeat_byte(0x33));
        let (s1, _) = post_json(
            &app,
            "/api/v1/sign/eip712-attestation",
            serde_json::json!({
                "intent_id": intent,
                "slot_index": "0",
                "attested_amount": "100",
            }),
        )
        .await;
        assert_eq!(s1, StatusCode::OK);
        let (s2, b2) = post_json(
            &app,
            "/api/v1/sign/eip712-attestation",
            serde_json::json!({
                "intent_id": intent,
                "slot_index": "0",
                "attested_amount": "200", // ← different
            }),
        )
        .await;
        assert_eq!(s2, StatusCode::CONFLICT);
        assert_eq!(
            b2["code"].as_str().unwrap_or(""),
            error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT
        );
    }

    #[tokio::test]
    async fn redemption_delivery_then_refund_is_mutex_409() {
        let (state, _hsm) = build_state();
        let app = router(state);
        let red = format!("{:#x}", B256::repeat_byte(0x44));
        let asset = format!("{:#x}", B256::repeat_byte(0xa1));
        let (s1, _) = post_json(
            &app,
            "/api/v1/sign/eip712-redemption-delivery",
            serde_json::json!({
                "redemption_id": red,
                "leg_index": "0",
                "asset_id": asset,
                "delivered_amount": "70000000",
            }),
        )
        .await;
        assert_eq!(s1, StatusCode::OK);
        let (s2, b2) = post_json(
            &app,
            "/api/v1/sign/eip712-refund",
            serde_json::json!({
                "redemption_id": red,
                "leg_index": "0",
                "asset_id": asset,
                "refunded_amount": "99990000",
            }),
        )
        .await;
        assert_eq!(s2, StatusCode::CONFLICT);
        assert_eq!(
            b2["code"].as_str().unwrap_or(""),
            error_codes::CONFLICT_DELIVERY_REFUND_MUTEX
        );
    }

    #[tokio::test]
    async fn redemption_refund_uses_refund_digest_not_delivery_digest() {
        let (state, hsm) = build_state();
        let app = router(state.clone());
        let red = B256::repeat_byte(0x55);
        let asset = B256::repeat_byte(0xa1);
        let amt = U256::from(99_990_000u64);
        let (status, _) = post_json(
            &app,
            "/api/v1/sign/eip712-refund",
            serde_json::json!({
                "redemption_id": format!("{red:#x}"),
                "leg_index": "0",
                "asset_id": format!("{asset:#x}"),
                "refunded_amount": amt.to_string(),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let expected_refund = refund_attestation_signing_hash(
            &refund_attestation(red, U256::ZERO, asset, amt),
            &state.config.domain(),
        );
        let unexpected_delivery = redemption_attestation_signing_hash(
            &redemption_attestation(red, U256::ZERO, asset, amt),
            &state.config.domain(),
        );
        // Typehash separation: the refund digest MUST NOT equal the
        // delivery digest even with the same (id, amount) — the on-
        // chain three-way separation property mirrored here.
        assert_ne!(expected_refund, unexpected_delivery);
        #[expect(clippy::unwrap_used, reason = "test code")]
        let seen = hsm.seen.lock().unwrap();
        assert_eq!(seen[0].1, expected_refund);
    }

    #[tokio::test]
    async fn bad_hex_field_returns_400_with_bad_request_code() {
        let (state, _hsm) = build_state();
        let app = router(state);
        let (status, body) = post_json(
            &app,
            "/api/v1/sign/eip712-attestation",
            serde_json::json!({
                "intent_id": "0xZZ",
                "slot_index": "0",
                "attested_amount": "0",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["code"].as_str().unwrap_or(""),
            error_codes::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn keys_endpoint_returns_configured_eth_address() {
        let (state, _hsm) = build_state();
        let app = router(state.clone());
        #[expect(clippy::expect_used, reason = "test code")]
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/keys")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("send");
        assert_eq!(resp.status(), StatusCode::OK);
        #[expect(clippy::expect_used, reason = "test code")]
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        assert_eq!(
            v["eth_address"].as_str().unwrap_or(""),
            format!("{:#x}", state.config.eth_address)
        );
        assert!(v["btc_pubkey"].is_null());
    }
}
