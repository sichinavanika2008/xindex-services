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

use alloy_primitives::{Address, PrimitiveSignature, B256, U256};
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

use std::collections::HashMap;

use xindex_shared::chain_registry::ChainId;

use crate::cosmos_tx::{handle_cosmos_tx, CosmosSignerConfig};
use crate::evm_safe::{handle_evm_safe_tx, EvmSignerConfig};
use crate::psbt::{handle_psbt_input, UtxoSignerConfig};
use crate::replay::{CheckOutcome, RedemptionCheckOutcome, RedemptionKind, ReplayStore};
use crate::solana_tx::{handle_solana_tx, SolSignerConfig};
use crate::web3signer::{HsmDigestSigner, HsmError};
use crate::xrp_tx::{handle_xrp_tx, XrpSignerConfig};

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
    /// Per-chain UTXO signing roles. Empty map = no UTXO key
    /// configured; the `/api/v1/sign/psbt-input` route is then not
    /// registered. A request for a chain absent from this map gets a
    /// 404 `endpoint_disabled`. Distinct configs per chain because
    /// each chain has its own 3-of-5 ceremony (no cross-chain key
    /// sharing per DL-P3-7).
    pub utxo: HashMap<ChainId, Arc<UtxoSignerConfig>>,
    /// V5: per-chain EVM Safe-tx signing roles. Empty map = no EVM
    /// key configured; the `/api/v1/sign/evm-safe-tx` route is then
    /// not registered. Same dispatch shape as `utxo` — one
    /// [`EvmSignerConfig`] per chain this daemon is in the Safe
    /// owner-set of (DL-P3-7: no cross-chain key sharing).
    pub evm: HashMap<ChainId, Arc<EvmSignerConfig>>,
    /// C5: per-chain Cosmos `LegacyAminoPubKey` multisig signing roles.
    /// Empty map = no Cosmos key configured; the `/api/v1/sign/cosmos-tx`
    /// route is then not registered. One [`CosmosSignerConfig`] per Cosmos
    /// chain this daemon is a multisig member of (DL-P3-7).
    pub cosmos: HashMap<ChainId, Arc<CosmosSignerConfig>>,
    /// C5 (Phase 4.4): per-chain XRP `SignerList` multisig signing roles.
    /// Empty map = no XRP key configured; the `/api/v1/sign/xrp-tx` route
    /// is then not registered. One [`XrpSignerConfig`] per XRP chain this
    /// daemon is a `SignerList` member of (DL-P3-7).
    pub xrp: HashMap<ChainId, Arc<XrpSignerConfig>>,
    /// S6 (Phase 4.5): per-chain Solana Squads V4 ed25519 signing roles.
    /// Empty map = no Solana key configured; the `/api/v1/sign/solana-tx`
    /// route is then not registered. One [`SolSignerConfig`] per Solana
    /// chain this daemon is a Squads member of (DL-P3-7).
    pub sol: HashMap<ChainId, Arc<SolSignerConfig>>,
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
            utxo: self.utxo.clone(),
            evm: self.evm.clone(),
            cosmos: self.cosmos.clone(),
            xrp: self.xrp.clone(),
            sol: self.sol.clone(),
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
            utxo: HashMap::new(),
            evm: HashMap::new(),
            cosmos: HashMap::new(),
            xrp: HashMap::new(),
            sol: HashMap::new(),
        }
    }

    /// Builder: attach a per-chain UTXO signing role to an existing
    /// state. Call once per chain this daemon serves; the chain id is
    /// taken from `config.chain_id`.
    #[must_use]
    pub fn with_utxo(mut self, config: UtxoSignerConfig) -> Self {
        self.utxo.insert(config.chain_id, Arc::new(config));
        self
    }

    /// V5 builder: attach a per-chain EVM Safe-tx signing role.
    /// Call once per chain this daemon serves; the chain is taken from
    /// `config.chain`.
    #[must_use]
    pub fn with_evm(mut self, config: EvmSignerConfig) -> Self {
        self.evm.insert(config.chain, Arc::new(config));
        self
    }

    /// C5 builder: attach a per-chain Cosmos multisig signing role.
    #[must_use]
    pub fn with_cosmos(mut self, config: CosmosSignerConfig) -> Self {
        self.cosmos.insert(config.chain, Arc::new(config));
        self
    }

    /// C5 (Phase 4.4) builder: attach a per-chain XRP multisig signing role.
    #[must_use]
    pub fn with_xrp(mut self, config: XrpSignerConfig) -> Self {
        self.xrp.insert(config.chain, Arc::new(config));
        self
    }

    /// S6 (Phase 4.5) builder: attach a per-chain Solana Squads signing role.
    #[must_use]
    pub fn with_sol(mut self, config: SolSignerConfig) -> Self {
        self.sol.insert(config.chain, Arc::new(config));
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
    if !state.utxo.is_empty() {
        r = r.route("/api/v1/sign/psbt-input", post(handle_psbt_input::<S, H>));
    }
    if !state.evm.is_empty() {
        r = r.route("/api/v1/sign/evm-safe-tx", post(handle_evm_safe_tx::<S, H>));
    }
    if !state.cosmos.is_empty() {
        r = r.route("/api/v1/sign/cosmos-tx", post(handle_cosmos_tx::<S, H>));
    }
    if !state.xrp.is_empty() {
        r = r.route("/api/v1/sign/xrp-tx", post(handle_xrp_tx::<S, H>));
    }
    if !state.sol.is_empty() {
        r = r.route("/api/v1/sign/solana-tx", post(handle_solana_tx::<S, H>));
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
    // KeysResponse.btc_pubkey reports the ChainId::Btc role's pubkey
    // specifically (the wire field name is historical, pre-U8). Other
    // chains' pubkeys are not exposed on this endpoint; per-chain
    // discovery is a U10+ runbook concern. Coordinator pins pubkeys
    // per-(daemon, chain) at deploy time, so this field is only an
    // identity probe for the BTC role.
    let btc_pubkey = state.utxo.get(&ChainId::Btc).map(|cfg| {
        format!(
            "0x{}",
            alloy_primitives::hex::encode(cfg.my_pubkey.to_bytes())
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

fn internal(code: &str, message: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            code: code.to_string(),
            message: message.into(),
        }),
    )
}

/// Recover-verify the HSM signature against the configured signer key
/// (audit M6 — extends the 1.5/H11 evm-safe backstop to all three
/// EIP-712 paths: attestation, redemption-delivery, refund). Catches an
/// HSM key-mapping bug, a wrong-key signature, or a corrupted signing
/// response BEFORE it is recorded or returned as a valid attestation.
/// Read-only on the signature bytes (no reconstruction), so there is no
/// signature-format risk; low-S normalization (1.13) stays deferred.
fn recover_verify_signer(
    sig: &[u8; 65],
    digest: B256,
    expected: Address,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let recovered = PrimitiveSignature::try_from(&sig[..])
        .map_err(|e| {
            internal(
                error_codes::SIGNER_RECOVER_MISMATCH,
                format!("HSM signature did not parse as a 65-byte ECDSA signature: {e}"),
            )
        })?
        .recover_address_from_prehash(&digest)
        .map_err(|e| {
            internal(
                error_codes::SIGNER_RECOVER_MISMATCH,
                format!("HSM signature did not recover to an address: {e}"),
            )
        })?;
    if recovered != expected {
        return Err(internal(
            error_codes::SIGNER_RECOVER_MISMATCH,
            format!(
                "HSM signature recovered to {recovered:#x}, expected configured signer {expected:#x}"
            ),
        ));
    }
    Ok(())
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

/// Per-leg replay-key payload hash. The replay DB keys redemptions on
/// `(redemption_id, leg_index)` (audit H2) and applies a delivery-XOR-
/// refund mutex WITHIN each leg. This hash binds the `leg_index`,
/// `asset_id`, and amount, so re-signing the SAME leg with a different
/// amount is a `Conflict`, while different legs of one redemption are
/// independent slots (matching the on-chain `IntentQueue::_legForUpdate`
/// per-leg mutex).
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
    recover_verify_signer(&sig, digest, state.config.eth_address)?;
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
    let leg = u32::try_from(leg_index)
        .map_err(|_| bad(error_codes::BAD_REQUEST, "leg_index exceeds u32"))?;

    handle_redemption_common(
        &state,
        redemption_id,
        leg,
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
    let leg = u32::try_from(leg_index)
        .map_err(|_| bad(error_codes::BAD_REQUEST, "leg_index exceeds u32"))?;

    handle_redemption_common(
        &state,
        redemption_id,
        leg,
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
    leg_index: u32,
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
        .check_redemption(redemption_id, leg_index, kind, payload_hash)
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
    recover_verify_signer(&sig, digest, state.config.eth_address)?;
    state
        .replay
        .record_redemption(
            redemption_id,
            leg_index,
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

    /// Fixed test key whose address is the configured `eth_address`, so
    /// the daemon's recover-verify backstop (audit M6) accepts the HSM
    /// mock's signatures.
    #[expect(clippy::expect_used, reason = "test code")]
    fn test_key() -> alloy::signers::local::PrivateKeySigner {
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
            .parse()
            .expect("valid test key")
    }

    /// Real-signing HSM mock: signs the digest with [`test_key`] so the
    /// recover-verify accepts it, and captures every `(address, digest)`
    /// so tests can assert the daemon hands the HSM the correct EIP-712
    /// hash — the single most important correctness property.
    #[derive(Debug, Default)]
    struct CapturingSigner {
        seen: Mutex<Vec<(Address, B256)>>,
    }

    #[async_trait::async_trait]
    impl HsmDigestSigner for CapturingSigner {
        async fn sign_digest(&self, address: Address, digest: B256) -> Result<[u8; 65], HsmError> {
            use alloy::signers::SignerSync;
            #[expect(clippy::unwrap_used, reason = "test code")]
            self.seen.lock().unwrap().push((address, digest));
            let sig = test_key()
                .sign_hash_sync(&digest)
                .map_err(|e| HsmError::Decode(format!("test sign: {e}")))?;
            Ok(sig.as_bytes())
        }
    }

    fn cfg() -> DaemonConfig {
        DaemonConfig {
            chain_id: 31337,
            verifying_contract: Address::repeat_byte(0xab),
            eth_address: test_key().address(),
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

    // ────────────────────────────────────────────────────────────────
    // V5 — `/api/v1/sign/evm-safe-tx` loopback tests
    // ────────────────────────────────────────────────────────────────

    mod evm_safe_tx_tests {
        use super::*;
        use crate::evm_safe::EvmSignerConfig;
        use alloy_primitives::Bytes;
        use xindex_safe_evm::{
            digest::{safe_tx_hash, SafeTransaction},
            SafeOperation,
        };
        use xindex_shared::signer_wire::EvmSafeTxSignRequest;

        const ETH_SAFE: Address = Address::new([0x11; 20]);
        const BSC_SAFE: Address = Address::new([0x33; 20]);

        /// Fixed test key. Its address is the configured signer for both
        /// chains so the HSM's signatures recover to `my_signer_address`
        /// — required by the 1.5 recover-verify gate.
        #[expect(clippy::expect_used, reason = "test code")]
        fn evm_key() -> alloy::signers::local::PrivateKeySigner {
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
                .parse()
                .expect("valid test key")
        }

        fn evm_signer() -> Address {
            evm_key().address()
        }

        /// Real-signing HSM mock: signs the digest with [`evm_key`] and
        /// captures every `(address, digest)` for assertion. Unlike
        /// [`CapturingSigner`], it returns a recoverable ECDSA signature,
        /// so the 1.5 recover-verify (handler step 5a) accepts it.
        #[derive(Debug)]
        struct RealEvmSigner {
            seen: Mutex<Vec<(Address, B256)>>,
        }

        #[async_trait::async_trait]
        impl HsmDigestSigner for RealEvmSigner {
            async fn sign_digest(
                &self,
                address: Address,
                digest: B256,
            ) -> Result<[u8; 65], HsmError> {
                use alloy::signers::SignerSync;
                #[expect(clippy::unwrap_used, reason = "test code")]
                self.seen.lock().unwrap().push((address, digest));
                let sig = evm_key()
                    .sign_hash_sync(&digest)
                    .map_err(|e| HsmError::Decode(format!("test sign: {e}")))?;
                Ok(sig.as_bytes())
            }
        }

        fn evm_state() -> (
            DaemonState<InMemoryReplayStore, RealEvmSigner>,
            Arc<RealEvmSigner>,
        ) {
            let replay = Arc::new(InMemoryReplayStore::new());
            let hsm = Arc::new(RealEvmSigner {
                seen: Mutex::new(Vec::new()),
            });
            let signer = evm_signer();
            let state = DaemonState::new(cfg(), replay, hsm.clone())
                .with_evm(EvmSignerConfig {
                    chain: ChainId::Eth,
                    safe_address: ETH_SAFE,
                    my_signer_address: signer,
                })
                .with_evm(EvmSignerConfig {
                    chain: ChainId::Bsc,
                    safe_address: BSC_SAFE,
                    my_signer_address: signer,
                });
            (state, hsm)
        }

        /// Build a `(SafeTransaction, request_body)` pair where the
        /// `safe_tx_hash` in the request matches the digest we'd
        /// recompute server-side.
        fn build_request(
            chain: ChainId,
            safe: Address,
            nonce: u64,
            data: &[u8],
        ) -> (SafeTransaction, EvmSafeTxSignRequest) {
            let tx = SafeTransaction {
                to: Address::new([0xa1; 20]),
                value: U256::ZERO,
                data: Bytes::from(data.to_vec()),
                operation: SafeOperation::Call,
                safe_tx_gas: U256::ZERO,
                base_gas: U256::ZERO,
                gas_price: U256::ZERO,
                gas_token: Address::ZERO,
                refund_receiver: Address::ZERO,
                nonce: U256::from(nonce),
            };
            #[expect(clippy::expect_used, reason = "test code")]
            let evm_chain_id = chain.evm_chain_id().expect("evm chain");
            let h = safe_tx_hash(evm_chain_id, safe, &tx);
            let req = EvmSafeTxSignRequest {
                chain_id: chain,
                safe_address: format!("{safe:#x}"),
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
                safe_tx_hash: format!("0x{}", alloy_primitives::hex::encode(h)),
                fee_wei: "0".to_string(),
            };
            (tx, req)
        }

        /// ETH + BSC configured → both sign cleanly, daemon hands the
        /// HSM the EXACT recomputed digest for each chain.
        #[tokio::test]
        async fn signs_for_every_configured_chain() {
            let (state, hsm) = evm_state();
            let app = router(state.clone());

            for (chain, safe, signer) in [
                (ChainId::Eth, ETH_SAFE, evm_signer()),
                (ChainId::Bsc, BSC_SAFE, evm_signer()),
            ] {
                let (tx, req) = build_request(chain, safe, 0, b"hello");
                let body = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
                let (status, body) = post_json(&app, "/api/v1/sign/evm-safe-tx", body).await;
                assert_eq!(status, StatusCode::OK, "{chain:?} status: {body}");
                assert_eq!(
                    body["signer_address"].as_str().unwrap_or(""),
                    format!("{signer:#x}"),
                    "{chain:?} signer"
                );
                // The HSM received the LOCALLY-RECOMPUTED digest, not the
                // request's `safe_tx_hash` field (defence-in-depth — even
                // if a coordinator lied about the hash, the daemon would
                // have signed its own version OR rejected on mismatch).
                #[expect(clippy::expect_used, reason = "test code")]
                let evm_chain_id = chain.evm_chain_id().expect("evm chain");
                let expected_digest = safe_tx_hash(evm_chain_id, safe, &tx);
                #[expect(clippy::unwrap_used, reason = "test code")]
                let seen = hsm.seen.lock().unwrap();
                assert!(seen.iter().any(|(addr, d)| {
                    *addr == signer && *d == expected_digest
                }), "expected to see signer={signer:#x} digest={expected_digest} in HSM call history");
            }
        }

        /// 1.5 (H11): if the HSM returns a signature that recovers to an
        /// address OTHER than the configured `my_signer_address`, the
        /// daemon refuses with 500 `signer_recover_mismatch` and does NOT
        /// record it. Simulated by configuring a signer that does not
        /// match the key the (real-signing) HSM mock uses.
        #[tokio::test]
        async fn rejects_signature_recovering_to_wrong_signer() {
            let replay = Arc::new(InMemoryReplayStore::new());
            let hsm = Arc::new(RealEvmSigner {
                seen: Mutex::new(Vec::new()),
            });
            let wrong_signer = Address::repeat_byte(0x99);
            let state = DaemonState::new(cfg(), replay, hsm).with_evm(EvmSignerConfig {
                chain: ChainId::Eth,
                safe_address: ETH_SAFE,
                my_signer_address: wrong_signer,
            });
            let app = router(state);
            let (_, req) = build_request(ChainId::Eth, ETH_SAFE, 0, b"x");
            let body = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
            let (status, body) = post_json(&app, "/api/v1/sign/evm-safe-tx", body).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(
                body["code"].as_str().unwrap_or(""),
                error_codes::SIGNER_RECOVER_MISMATCH
            );
        }

        /// A chain not in `state.evm` returns 404 `endpoint_disabled`.
        /// The route IS registered (because ETH+BSC are configured),
        /// but the per-request lookup fails for AVAX.
        #[tokio::test]
        async fn avax_request_returns_endpoint_disabled() {
            let (state, _hsm) = evm_state();
            let app = router(state);
            // Use AVAX's chain_id so the serde validator passes (AVAX
            // is a valid EVM chain), but the daemon has no AVAX config.
            let (_, mut req) = build_request(ChainId::Avax, ETH_SAFE, 0, b"");
            // The hash was computed for AVAX evm_chain_id; safe_address
            // doesn't matter — endpoint_disabled wins.
            req.safe_address = format!("{:#x}", Address::new([0xfe; 20]));
            let body = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
            let (status, body) = post_json(&app, "/api/v1/sign/evm-safe-tx", body).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(
                body["code"].as_str().unwrap_or(""),
                error_codes::ENDPOINT_DISABLED
            );
        }

        /// Wrong `safe_address` (right chain, wrong Safe) → 422 `wrong_safe_address`.
        #[tokio::test]
        async fn wrong_safe_address_is_rejected() {
            let (state, _hsm) = evm_state();
            let app = router(state);
            let bogus_safe = Address::new([0xfe; 20]);
            // Build hash for the BOGUS safe so the hash matches its
            // ABI inputs — but the daemon's ETH config has ETH_SAFE,
            // not the bogus one.
            let (_, req) = build_request(ChainId::Eth, bogus_safe, 0, b"");
            let body = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
            let (status, body) = post_json(&app, "/api/v1/sign/evm-safe-tx", body).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(
                body["code"].as_str().unwrap_or(""),
                error_codes::WRONG_SAFE_ADDRESS
            );
        }

        /// Tampered `safe_tx_hash` (coordinator's claim ≠ daemon's
        /// recompute) → 422 `safe_tx_hash_mismatch`. The HSM is NEVER
        /// invoked.
        #[tokio::test]
        async fn mismatched_safe_tx_hash_is_rejected() {
            let (state, hsm) = evm_state();
            let app = router(state);
            let (_, mut req) = build_request(ChainId::Eth, ETH_SAFE, 0, b"original");
            // Substitute a hash that doesn't match the rest of the
            // request. (Use a random-looking but valid 32-byte hex.)
            req.safe_tx_hash = format!("0x{}", "de".repeat(32));
            let body = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
            let (status, body) = post_json(&app, "/api/v1/sign/evm-safe-tx", body).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(
                body["code"].as_str().unwrap_or(""),
                error_codes::SAFE_TX_HASH_MISMATCH
            );
            #[expect(clippy::unwrap_used, reason = "test code")]
            let seen = hsm.seen.lock().unwrap();
            assert!(
                seen.is_empty(),
                "HSM must not have been touched on hash mismatch"
            );
        }

        /// Identical retry returns the cached signature; HSM is hit
        /// exactly once across the two requests.
        #[tokio::test]
        async fn identical_replay_returns_cached_signature() {
            let (state, hsm) = evm_state();
            let app = router(state);
            let (_, req) = build_request(ChainId::Eth, ETH_SAFE, 42, b"once");
            let body = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
            let (s1, b1) = post_json(&app, "/api/v1/sign/evm-safe-tx", body.clone()).await;
            let (s2, b2) = post_json(&app, "/api/v1/sign/evm-safe-tx", body).await;
            assert_eq!(s1, StatusCode::OK);
            assert_eq!(s2, StatusCode::OK);
            assert_eq!(b1["signature"], b2["signature"]);
            #[expect(clippy::unwrap_used, reason = "test code")]
            let seen = hsm.seen.lock().unwrap();
            assert_eq!(seen.len(), 1, "HSM hit exactly once across two retries");
        }

        /// Same (chain, safe, nonce) with a DIFFERENT digest → 409
        /// `conflict_already_signed_different`. HSM hit only by the
        /// first request.
        #[tokio::test]
        async fn same_nonce_different_payload_is_409() {
            let (state, hsm) = evm_state();
            let app = router(state);
            let (_, req1) = build_request(ChainId::Eth, ETH_SAFE, 7, b"first");
            let (_, req2) = build_request(ChainId::Eth, ETH_SAFE, 7, b"different");
            // Both requests pass the digest-recompute check (each is
            // internally self-consistent) but their `payload_hash`
            // differs → conflict.
            let (s1, _) = post_json(
                &app,
                "/api/v1/sign/evm-safe-tx",
                serde_json::to_value(&req1).unwrap_or(serde_json::Value::Null),
            )
            .await;
            assert_eq!(s1, StatusCode::OK);
            let (s2, b2) = post_json(
                &app,
                "/api/v1/sign/evm-safe-tx",
                serde_json::to_value(&req2).unwrap_or(serde_json::Value::Null),
            )
            .await;
            assert_eq!(s2, StatusCode::CONFLICT);
            assert_eq!(
                b2["code"].as_str().unwrap_or(""),
                error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT
            );
            #[expect(clippy::unwrap_used, reason = "test code")]
            let seen = hsm.seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
        }

        /// The EVM route is NOT registered when `state.evm` is empty.
        /// Defends against accidentally serving the endpoint with no
        /// EVM role configured (e.g., a daemon misconfigured at deploy).
        #[tokio::test]
        async fn route_not_registered_when_evm_unconfigured() {
            let (state, _hsm) = build_state(); // no .with_evm()
            let app = router(state);
            let zero_addr = format!("0x{}", "00".repeat(20));
            // Body content doesn't matter — the route doesn't exist.
            let body = serde_json::json!({
                "chain_id": "eth",
                "safe_address": zero_addr,
                "to": zero_addr,
                "value": "0",
                "data": "0x",
                "operation": 0,
                "safe_tx_gas": "0",
                "base_gas": "0",
                "gas_price": "0",
                "gas_token": zero_addr,
                "refund_receiver": zero_addr,
                "nonce": "0",
                "safe_tx_hash": format!("0x{}", "00".repeat(32)),
                "fee_wei": "0",
            });
            let (status, _) = post_json(&app, "/api/v1/sign/evm-safe-tx", body).await;
            // axum returns 405 for an unrouted POST since the daemon
            // doesn't add the path. (Specifically: no route on this
            // path → 404, but axum's MethodRouter returns 405 if the
            // path exists for a different method; the daemon doesn't
            // expose this path at all → 404.)
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
    }
}
