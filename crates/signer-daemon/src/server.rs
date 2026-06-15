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
    acquire_cancel_certificate, acquire_cancel_signing_hash, attestation,
    attestation_oracle_domain, attestation_signing_hash, redemption_attestation,
    redemption_attestation_signing_hash, redemption_intent_certificate, refund_attestation,
    refund_attestation_signing_hash, ric_signing_hash, streamed_settlement,
    streamed_settlement_signing_hash,
};
use xindex_shared::signer_wire::{
    error_codes, AcquireCancelProof, AcquireCancelSignRequest, AttestationSignRequest,
    Eip712SignResponse, ErrorBody, HealthResponse, IntentProof, KeysResponse,
    RedemptionDeliverySignRequest, RefundSignRequest, RicSignRequest,
    StreamedSettlementSignRequest,
};

use crate::intent::{
    validate_acquire_cancel_proof, validate_intent_proof, IntentError, IntentPolicy,
    VerifiedCancel, VerifiedIntent,
};

use std::collections::HashMap;

use xindex_shared::chain_registry::ChainId;

use crate::cosmos_tx::{handle_cosmos_tx, CosmosSignerConfig};
use crate::evm_safe::{handle_evm_safe_tx, EvmSignerConfig};
use crate::psbt::{handle_psbt_input, UtxoSignerConfig};
use crate::replay::{
    CheckOutcome, RedemptionCheckOutcome, RedemptionKind, ReplayStore, VolumeOutcome,
};
use crate::solana_tx::{handle_solana_tx, SolSignerConfig};
use crate::tron_tx::{handle_tron_tx, TronSignerConfig};
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
    /// CTD-1 (`DL-CTD-2`): the daemon's Redemption-Intent-Certificate
    /// verification policy — static Set-B whitelist + quorum + recency
    /// window. MANDATORY: every custody-spend handler refuses to sign
    /// without a valid k-of-n RIC verified against this; there is no
    /// proof-less carve-out. Construction sites must call
    /// [`IntentPolicy::validate`] at startup (the gate also fails
    /// closed on a policy that could never verify).
    pub intent_policy: IntentPolicy,
    /// CTD-1 Slice E (`DL-CTD-E`): per-chain Set-B certification volume
    /// window policy. RIC and ACC signing consume from ONE per-chain
    /// window; an over-cap certification is refused 422
    /// (`volume_cap_exceeded`) before the HSM is touched. MANDATORY
    /// field — [`CertVolumePolicy::unmetered`] is the explicit dev/test
    /// opt-out; production MUST cap every served chain (≈10% of
    /// per-chain custody per 24h, DL-CTD-E). Construction sites call
    /// [`CertVolumePolicy::validate`] at startup.
    pub cert_volume: CertVolumePolicy,
}

impl DaemonConfig {
    fn domain(&self) -> Eip712Domain {
        attestation_oracle_domain(self.chain_id, self.verifying_contract)
    }
}

/// CTD-1 Slice E (`DL-CTD-E`): per-chain Set-B certification volume
/// caps — the containment teeth at the k-of-n floor. Caps are ABSOLUTE
/// native smallest-unit amounts per fixed `window_secs` bucket; a chain
/// absent from `caps` is UNMETERED (deploy-safe dev/test default —
/// production MUST set ≈10% of per-chain custody for every served
/// chain and re-tune as custody grows). A compromised coordinator that
/// somehow obtains k-of-n observer cooperation is still bounded to one
/// window's cap per chain, because each operator's Set-B daemon meters
/// independently and refuses beyond its cap.
#[derive(Debug, Clone)]
pub struct CertVolumePolicy {
    /// Fixed window bucket length in seconds (production: 86 400).
    pub window_secs: u64,
    /// Per-chain cap in native smallest units; absent = unmetered.
    pub caps: HashMap<ChainId, u128>,
}

impl CertVolumePolicy {
    /// No metering on any chain (dev/test default); 24h bucket length.
    #[must_use]
    pub fn unmetered() -> Self {
        Self {
            window_secs: 86_400,
            caps: HashMap::new(),
        }
    }

    /// Fail-closed startup validation — construction sites call this,
    /// mirroring [`IntentPolicy::validate`].
    ///
    /// # Errors
    /// `window_secs == 0` (the bucket arithmetic needs a positive
    /// length) or any cap of `0` (a zero cap can never authorize —
    /// remove the chain to unmeter instead).
    pub fn validate(&self) -> Result<(), String> {
        if self.window_secs == 0 {
            return Err("cert_volume.window_secs must be > 0".to_string());
        }
        if self.caps.values().any(|cap| *cap == 0) {
            return Err(
                "cert_volume cap of 0 can never authorize; remove the chain to unmeter".to_string(),
            );
        }
        Ok(())
    }

    /// Fail-closed PRODUCTION assertion (workstream F): every `served` chain
    /// MUST have a positive cap. [`Self::validate`] deliberately PASSES the
    /// legitimate dev/test UNMETERED mode (empty `caps`); this is the
    /// production-only invariant it omits — a served chain left unmetered
    /// leaves the CTD-1 containment teeth (`DL-CTD-E`) OFF, so a production
    /// daemon must refuse to boot that way.
    ///
    /// # Errors
    /// Propagates [`Self::validate`], then the first `served` chain with no
    /// positive cap.
    pub fn assert_metered_for(&self, served: &[ChainId]) -> Result<(), String> {
        self.validate()?;
        for chain in served {
            if self.caps.get(chain).is_none_or(|cap| *cap == 0) {
                return Err(format!(
                    "served chain {chain:?} has no positive cert-volume cap — production must \
                     meter every RIC-gated chain (DL-CTD-E); unmetered is dev/test only"
                ));
            }
        }
        Ok(())
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
    /// Phase 4.6: per-chain TRON account-permission multisig signing roles.
    /// Empty map = no TRON key configured; the `/api/v1/sign/tron-tx` route
    /// is then not registered. One [`TronSignerConfig`] per TRON chain this
    /// daemon is a permission member of (DL-P3-7).
    pub tron: HashMap<ChainId, Arc<TronSignerConfig>>,
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
            tron: self.tron.clone(),
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
            tron: HashMap::new(),
        }
    }

    /// Fail-closed PRODUCTION startup assertion (workstream F). A daemon
    /// bound to a real HSM MUST refuse to boot with safety features off.
    /// Composes the individual sanity checks ([`IntentPolicy::validate`] +
    /// [`CertVolumePolicy::validate`]) with the production-only invariant
    /// they miss: every RIC-gated chain this daemon signs for is metered
    /// ([`CertVolumePolicy::assert_metered_for`], `DL-CTD-E`). Solana is
    /// excluded — RIC-exempt + hard-gated (RA-2). Dev/test harnesses
    /// (stub HSM + `unmetered()`) do not call this.
    ///
    /// # Errors
    /// The first production-unsafe setting: an invalid `intent_policy`, or a
    /// served RIC-gated chain with no positive cert-volume cap.
    pub fn assert_production_safe(&self) -> Result<(), String> {
        let served: Vec<ChainId> = self
            .utxo
            .keys()
            .chain(self.evm.keys())
            .chain(self.cosmos.keys())
            .chain(self.xrp.keys())
            .chain(self.tron.keys())
            .copied()
            .collect();
        self.config.cert_volume.assert_metered_for(&served)?;
        self.config.intent_policy.validate()
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

    /// Phase 4.6 builder: attach a per-chain TRON multisig signing role.
    #[must_use]
    pub fn with_tron(mut self, config: TronSignerConfig) -> Self {
        self.tron.insert(config.chain, Arc::new(config));
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
        .route("/api/v1/sign/eip712-refund", post(handle_refund::<S, H>))
        .route(
            "/api/v1/sign/eip712-streamed-settlement",
            post(handle_streamed_settlement::<S, H>),
        )
        .route("/api/v1/sign/eip712-ric", post(handle_ric_sign::<S, H>))
        .route("/api/v1/sign/eip712-acc", post(handle_acc_sign::<S, H>));
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
    if !state.tron.is_empty() {
        r = r.route("/api/v1/sign/tron-tx", post(handle_tron_tx::<S, H>));
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

fn unprocessable(code: &str, message: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
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

/// Like [`hash_leg_payload`] but for the COMBINED streamed settlement,
/// binding BOTH the delivered-USDT and refunded-native amounts so that
/// re-signing the same leg with a different `(delivered, refunded)` pair
/// is a `Conflict`. The wider buffer (160 vs 128 bytes) also means a
/// streamed payload hash can never collide with a plain delivery/refund
/// payload hash for the same leg/amount.
fn hash_streamed_payload(
    redemption_id: B256,
    leg_index: U256,
    asset_id: B256,
    delivered_usdt: U256,
    refunded_native: U256,
) -> [u8; 32] {
    let mut buf = [0u8; 160];
    buf[..32].copy_from_slice(redemption_id.as_slice());
    buf[32..64].copy_from_slice(&leg_index.to_be_bytes::<32>());
    buf[64..96].copy_from_slice(asset_id.as_slice());
    buf[96..128].copy_from_slice(&delivered_usdt.to_be_bytes::<32>());
    buf[128..160].copy_from_slice(&refunded_native.to_be_bytes::<32>());
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
    if let Err(e) = state
        .replay
        .record_attestation(
            intent_id,
            slot_index,
            payload_hash,
            sig.to_vec(),
            now_unix_secs(),
        )
        .await
    {
        if crate::replay::must_propagate_record_error(&e) {
            return Err(bad(error_codes::BAD_REQUEST, format!("replay record: {e}")));
        }
        // L10: lost the write race; the winner already recorded. Re-read
        // and return its cached signature idempotently.
        return match state
            .replay
            .check_attestation(intent_id, slot_index, payload_hash)
            .await
            .map_err(|e| bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?
        {
            CheckOutcome::Idempotent(rec) => {
                let arr: [u8; 65] = rec.signature.as_slice().try_into().map_err(|_| {
                    bad(
                        error_codes::BAD_REQUEST,
                        "stored signature not 65 bytes".to_string(),
                    )
                })?;
                Ok(Json(render_signature(&state.config, arr)))
            }
            CheckOutcome::Conflict { .. } => Err(conflict(
                error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT,
                "intent already attested with a different amount",
            )),
            CheckOutcome::FirstTime => Err(internal(
                error_codes::BAD_REQUEST,
                "record race left no row",
            )),
        };
    }
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

/// `POST /api/v1/sign/eip712-streamed-settlement` — per-leg COMBINED
/// streamed settlement (`STREAM-B2-COORD`). Same replay flow as
/// delivery/refund (the `Streamed` kind shares the per-leg
/// delivery-XOR-refund-XOR-streamed mutex), but the digest binds BOTH
/// `delivered_usdt` and `refunded_native` (a partial-fill outcome). The
/// coordinator only posts this AFTER the streaming swap has finalised; the
/// daemon signs the structurally-distinct `AsyncLegStreamedSettlement`
/// typehash, never the delivery or refund one.
async fn handle_streamed_settlement<S, H>(
    State(state): State<DaemonState<S, H>>,
    Json(req): Json<StreamedSettlementSignRequest>,
) -> Result<Json<Eip712SignResponse>, (StatusCode, Json<ErrorBody>)>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    let redemption_id = parse_b256(&req.redemption_id, "redemption_id")?;
    let leg_index = parse_u256(&req.leg_index, "leg_index")?;
    let asset_id = parse_b256(&req.asset_id, "asset_id")?;
    let delivered_usdt = parse_u256(&req.delivered_usdt, "delivered_usdt")?;
    let refunded_native = parse_u256(&req.refunded_native, "refunded_native")?;
    // The combined settlement binds BOTH amounts: re-signing the same leg
    // with a different (delivered, refunded) pair is a Conflict.
    let payload_hash = hash_streamed_payload(
        redemption_id,
        leg_index,
        asset_id,
        delivered_usdt,
        refunded_native,
    );
    let leg = u32::try_from(leg_index)
        .map_err(|_| bad(error_codes::BAD_REQUEST, "leg_index exceeds u32"))?;

    handle_redemption_common(
        &state,
        redemption_id,
        leg,
        RedemptionKind::Streamed,
        payload_hash,
        || {
            let m = streamed_settlement(
                redemption_id,
                leg_index,
                asset_id,
                delivered_usdt,
                refunded_native,
            );
            streamed_settlement_signing_hash(&m, &state.config.domain())
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
    if let Err(e) = state
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
    {
        if crate::replay::must_propagate_record_error(&e) {
            return Err(bad(error_codes::BAD_REQUEST, format!("replay record: {e}")));
        }
        // L10: lost the write race; the winner already recorded. Re-read
        // and return its cached signature idempotently (handle all four
        // RedemptionCheckOutcome variants).
        return match state
            .replay
            .check_redemption(redemption_id, leg_index, kind, payload_hash)
            .await
            .map_err(|e| bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?
        {
            RedemptionCheckOutcome::Idempotent(rec) => {
                let arr: [u8; 65] = rec.signature.as_slice().try_into().map_err(|_| {
                    bad(
                        error_codes::BAD_REQUEST,
                        "stored signature not 65 bytes".to_string(),
                    )
                })?;
                Ok(Json(render_signature(&state.config, arr)))
            }
            RedemptionCheckOutcome::Conflict { .. } => Err(conflict(
                error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT,
                "redemption already signed with a different amount",
            )),
            RedemptionCheckOutcome::MutexViolation { .. } => Err(conflict(
                error_codes::CONFLICT_DELIVERY_REFUND_MUTEX,
                "redemption already resolved as the opposite leg",
            )),
            RedemptionCheckOutcome::FirstTime => Err(internal(
                error_codes::BAD_REQUEST,
                "record race left no row",
            )),
        };
    }
    Ok(Json(render_signature(&state.config, sig)))
}

/// CTD-1 (`DL-CTD-2`) — the shared custody-spend RIC gate. Every spend
/// handler (PSBT / EVM-Safe / Cosmos / XRP / TRON; Solana excluded,
/// RA-2) calls this BEFORE family-specific work:
///
/// 1. `None` proof → 422 `intent_proof_required` (mandatory — there is
///    no proof-less carve-out).
/// 2. Stateless k-of-n verification ([`validate_intent_proof`]) against
///    the static Set-B whitelist in [`DaemonConfig::intent_policy`].
/// 3. Family-agnostic binds: the certified asset must be THIS chain's
///    native asset (`asset_id_hash` — RIC v1 certifies native-asset
///    legs only, so a BTC certificate can never authorize an LTC spend
///    of the same numeric amount) and `amount_decimals` must equal the
///    registry decimals (RA-4, like-for-like — never rescaled).
/// 4. One-shot CONSUME (RA-1), recorded BEFORE the HSM: a same-digest
///    retry passes idempotently (the family replay arm dedups the tx
///    signature), a DIFFERENT certificate for a consumed leg is a 409
///    `intent_already_signed`, and a post-record HSM failure cannot
///    brick the leg (a retry with the SAME certificate proceeds).
///
/// The caller still binds the certified destination/amount/memo to the
/// family-specific tx shape — that part cannot be shared.
pub(crate) async fn gate_ric_intent<S: ReplayStore>(
    config: &DaemonConfig,
    replay: &S,
    chain: ChainId,
    proof: Option<&IntentProof>,
) -> Result<(VerifiedIntent, B256), (StatusCode, Json<ErrorBody>)> {
    let proof = proof.ok_or_else(|| {
        unprocessable(
            error_codes::INTENT_PROOF_REQUIRED,
            "custody-spend request carries no IntentProof (k-of-n RIC) — required",
        )
    })?;
    let now = u64::try_from(now_unix_secs()).unwrap_or(0);
    let (cert, digest) = validate_intent_proof(
        proof,
        config.chain_id,
        config.verifying_contract,
        &config.intent_policy,
        now,
    )
    .map_err(|e| unprocessable(e.error_code(), e.to_string()))?;
    if cert.asset_id != chain.asset_id_hash() {
        return Err(unprocessable(
            error_codes::INTENT_MISMATCH,
            format!(
                "certified asset id is not chain {chain:?}'s native asset — \
                 RIC v1 certifies native-asset legs only"
            ),
        ));
    }
    if cert.amount_decimals != chain.decimals() {
        return Err(unprocessable(
            error_codes::INTENT_MISMATCH,
            format!(
                "certified amount_decimals {} != chain {chain:?} native decimals {} (RA-4)",
                cert.amount_decimals,
                chain.decimals()
            ),
        ));
    }
    consume_ric_one_shot(replay, chain, &cert, digest).await?;
    Ok((cert, digest))
}

/// RA-1: consume the `(chain, redemptionId, legIndex)` one-shot. The
/// row is recorded BEFORE the HSM is consulted — the row IS the
/// authorization; the family replay table holds the actual signature
/// (the stored signature here is empty by design).
async fn consume_ric_one_shot<S: ReplayStore>(
    replay: &S,
    chain: ChainId,
    cert: &VerifiedIntent,
    digest: B256,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    const REDRIVEN: &str =
        "custody spend for this (chain, redemption, leg) was already authorized under a \
         different certificate";
    let outcome = replay
        .check_ric_intent(chain, cert.redemption_id, cert.leg_index, digest.0)
        .await
        .map_err(|e| bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?;
    match outcome {
        // Same certificate retried — the family replay arm dedups the
        // actual tx signature; nothing to consume twice.
        CheckOutcome::Idempotent(_) => return Ok(()),
        CheckOutcome::Conflict { .. } => {
            return Err(conflict(error_codes::INTENT_ALREADY_SIGNED, REDRIVEN));
        }
        CheckOutcome::FirstTime => {}
    }
    if let Err(e) = replay
        .record_ric_intent(
            chain,
            cert.redemption_id,
            cert.leg_index,
            digest.0,
            Vec::new(),
            now_unix_secs(),
        )
        .await
    {
        if crate::replay::must_propagate_record_error(&e) {
            return Err(bad(error_codes::BAD_REQUEST, format!("replay record: {e}")));
        }
        // Lost a same-leg race — proceed only if the winner consumed
        // the SAME certificate.
        return match replay
            .check_ric_intent(chain, cert.redemption_id, cert.leg_index, digest.0)
            .await
            .map_err(|e| bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?
        {
            CheckOutcome::Idempotent(_) => Ok(()),
            CheckOutcome::Conflict { .. } => {
                Err(conflict(error_codes::INTENT_ALREADY_SIGNED, REDRIVEN))
            }
            CheckOutcome::FirstTime => Err(internal(
                error_codes::BAD_REQUEST,
                "ric one-shot record race left no row",
            )),
        };
    }
    Ok(())
}

/// CTD-1 Slice C: the common custody-spend binding fields, produced by
/// EITHER certificate gate — a RIC (redeem) or an ACC (mint-cancel
/// swap-back). The PSBT handler binds the output set against these
/// without caring which certificate kind authorized the spend; the
/// kind-specific verification, asset/decimals binds, and one-shot
/// consumption all happened inside the respective gate.
#[derive(Debug, Clone)]
pub(crate) struct CertifiedSpend {
    /// Certified spend amount in the chain's native smallest units.
    pub amount: U256,
    /// Certified keccak of the immediate spend target (Asgard inbound).
    pub immediate_target_hash: B256,
    /// Certified keccak of the exact `THORChain` memo bytes.
    pub memo_hash: B256,
    /// Wire error code for an output-bind mismatch under THIS
    /// certificate kind (`intent_mismatch` / `acquire_cancel_mismatch`)
    /// so the coordinator can tell which certificate the spend violated.
    pub mismatch_code: &'static str,
}

/// Map an [`IntentError`] from the ACC validator onto the ACC-specific
/// wire codes (the validator itself is certificate-agnostic and reports
/// the RIC codes by default).
fn acc_error_code(e: &IntentError) -> &'static str {
    match e {
        IntentError::ProofInvalid(_) => error_codes::ACQUIRE_CANCEL_PROOF_INVALID,
        IntentError::VaultStale(_) => error_codes::ACQUIRE_CANCEL_VAULT_STALE,
    }
}

/// CTD-1 Slice C — the Acquire-Cancel custody-spend gate, the
/// mint-cancel sibling of [`gate_ric_intent`]:
///
/// 1. Stateless k-of-n verification ([`validate_acquire_cancel_proof`])
///    against the same static Set-B whitelist.
/// 2. Family-agnostic binds: certified asset must be THIS chain's
///    native asset and `amount_decimals` must equal the registry
///    decimals (RA-4) — an ACC for one chain can never authorize a
///    same-amount spend on another.
/// 3. One-shot CONSUME keyed `(chain, cancel_id)`, recorded BEFORE the
///    HSM: a same-digest retry passes idempotently, a DIFFERENT
///    certificate for a consumed cancel is a 409
///    `acquire_cancel_already_signed`.
pub(crate) async fn gate_acquire_cancel_intent<S: ReplayStore>(
    config: &DaemonConfig,
    replay: &S,
    chain: ChainId,
    proof: &AcquireCancelProof,
) -> Result<(VerifiedCancel, B256), (StatusCode, Json<ErrorBody>)> {
    let now = u64::try_from(now_unix_secs()).unwrap_or(0);
    let (cert, digest) = validate_acquire_cancel_proof(
        proof,
        config.chain_id,
        config.verifying_contract,
        &config.intent_policy,
        now,
    )
    .map_err(|e| unprocessable(acc_error_code(&e), e.to_string()))?;
    if cert.asset_id != chain.asset_id_hash() {
        return Err(unprocessable(
            error_codes::ACQUIRE_CANCEL_MISMATCH,
            format!(
                "certified asset id is not chain {chain:?}'s native asset — \
                 ACC v1 certifies native-asset swap-backs only"
            ),
        ));
    }
    if cert.amount_decimals != chain.decimals() {
        return Err(unprocessable(
            error_codes::ACQUIRE_CANCEL_MISMATCH,
            format!(
                "certified amount_decimals {} != chain {chain:?} native decimals {} (RA-4)",
                cert.amount_decimals,
                chain.decimals()
            ),
        ));
    }
    consume_ac_one_shot(replay, chain, &cert, digest).await?;
    Ok((cert, digest))
}

/// Slice C mirror of [`consume_ric_one_shot`] keyed `(chain, cancel_id)`:
/// the row is recorded BEFORE the HSM is consulted — the row IS the
/// authorization; the PSBT replay table holds the actual signature.
async fn consume_ac_one_shot<S: ReplayStore>(
    replay: &S,
    chain: ChainId,
    cert: &VerifiedCancel,
    digest: B256,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    const REDRIVEN: &str = "swap-back for this (chain, cancel_id) was already authorized under a \
         different certificate";
    let outcome = replay
        .check_ac_intent(chain, cert.cancel_id, digest.0)
        .await
        .map_err(|e| bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?;
    match outcome {
        CheckOutcome::Idempotent(_) => return Ok(()),
        CheckOutcome::Conflict { .. } => {
            return Err(conflict(
                error_codes::ACQUIRE_CANCEL_ALREADY_SIGNED,
                REDRIVEN,
            ));
        }
        CheckOutcome::FirstTime => {}
    }
    if let Err(e) = replay
        .record_ac_intent(chain, cert.cancel_id, digest.0, Vec::new(), now_unix_secs())
        .await
    {
        if crate::replay::must_propagate_record_error(&e) {
            return Err(bad(error_codes::BAD_REQUEST, format!("replay record: {e}")));
        }
        // Lost a same-cancel race — proceed only if the winner consumed
        // the SAME certificate.
        return match replay
            .check_ac_intent(chain, cert.cancel_id, digest.0)
            .await
            .map_err(|e| bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?
        {
            CheckOutcome::Idempotent(_) => Ok(()),
            CheckOutcome::Conflict { .. } => Err(conflict(
                error_codes::ACQUIRE_CANCEL_ALREADY_SIGNED,
                REDRIVEN,
            )),
            CheckOutcome::FirstTime => Err(internal(
                error_codes::BAD_REQUEST,
                "ac one-shot record race left no row",
            )),
        };
    }
    Ok(())
}

/// CTD-1 Slice C — the PSBT spend-certificate dispatcher: a RIC
/// (redeem) XOR an ACC (mint-cancel swap-back).
///
/// - BOTH present → 422 `intent_proof_ambiguous` (a redeem and a
///   cancel are distinct authorizations; an honest coordinator never
///   attaches both — refusing avoids any pick-the-weaker ambiguity).
/// - RIC only → [`gate_ric_intent`] (which also covers the
///   neither-present case with `intent_proof_required`).
/// - ACC only → [`gate_acquire_cancel_intent`].
///
/// Returns the kind-agnostic [`CertifiedSpend`] the PSBT output bind
/// enforces. Only the PSBT endpoint dispatches both kinds — the other
/// four custody families have no mint-cancel swap-back path.
pub(crate) async fn gate_spend_certificate<S: ReplayStore>(
    config: &DaemonConfig,
    replay: &S,
    chain: ChainId,
    ric: Option<&IntentProof>,
    acc: Option<&AcquireCancelProof>,
) -> Result<CertifiedSpend, (StatusCode, Json<ErrorBody>)> {
    match (ric, acc) {
        (Some(_), Some(_)) => Err(unprocessable(
            error_codes::INTENT_PROOF_AMBIGUOUS,
            "request carries BOTH a RIC and an Acquire-Cancel certificate — exactly one \
             certificate kind must authorize a custody spend",
        )),
        (None, Some(proof)) => {
            let (cert, _digest) = gate_acquire_cancel_intent(config, replay, chain, proof).await?;
            Ok(CertifiedSpend {
                amount: cert.amount,
                immediate_target_hash: cert.immediate_target_hash,
                memo_hash: cert.memo_hash,
                mismatch_code: error_codes::ACQUIRE_CANCEL_MISMATCH,
            })
        }
        // RIC-only AND neither: gate_ric_intent turns `None` into the
        // typed `intent_proof_required` 422.
        (ric_only, None) => {
            let (cert, _digest) = gate_ric_intent(config, replay, chain, ric_only).await?;
            Ok(CertifiedSpend {
                amount: cert.amount,
                immediate_target_hash: cert.immediate_target_hash,
                memo_hash: cert.memo_hash,
                mismatch_code: error_codes::INTENT_MISMATCH,
            })
        }
    }
}

/// CTD-1: bind an account-model send (Cosmos / XRP / TRON) to the
/// certified intent: the destination string's keccak must equal the
/// certified Asgard target, the decimal amount must equal the
/// certified amount exactly (like-for-like — the gate already pinned
/// the unit via `amount_decimals`), and the memo bytes must hash to
/// the certified memo. The family handlers' sign-bytes recompute then
/// guarantees the signed tx matches THESE fields, so
/// certificate == request fields == transaction bytes.
pub(crate) fn bind_account_send_to_cert(
    to_address: &str,
    amount_dec: &str,
    memo: &str,
    cert: &VerifiedIntent,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if alloy_primitives::keccak256(to_address.as_bytes()) != cert.immediate_target_hash {
        return Err(unprocessable(
            error_codes::INTENT_MISMATCH,
            format!("destination {to_address} does not hash to the certified Asgard target"),
        ));
    }
    let amount = U256::from_str_radix(amount_dec, 10).map_err(|e| {
        unprocessable(
            error_codes::INTENT_MISMATCH,
            format!("amount: bad decimal: {e}"),
        )
    })?;
    if amount != cert.amount {
        return Err(unprocessable(
            error_codes::INTENT_MISMATCH,
            format!("amount {amount} != certified amount {}", cert.amount),
        ));
    }
    if alloy_primitives::keccak256(memo.as_bytes()) != cert.memo_hash {
        return Err(unprocessable(
            error_codes::INTENT_MISMATCH,
            "memo does not hash to the certified memo".to_string(),
        ));
    }
    Ok(())
}

/// CTD-1 Slice A.7: how long after `vault_resolved_at` a Set-B daemon
/// is still willing to SIGN a RIC. Deliberately tighter than the
/// custody-side verification window: an honest observer requests
/// certification immediately after resolving Asgard, so anything older
/// signals a delayed or replayed certification attempt. Hardcoded —
/// not operator-tunable — so a config mistake cannot widen it.
const RIC_SIGN_MAX_AGE_SECS: u64 = 600;

/// RA-5 at the SOURCE: a Set-B daemon only certifies a FRESH Asgard
/// resolution. Future-dating beyond the shared clock-skew tolerance is
/// refused so a compromised relay cannot mint long-lived certificates.
fn check_ric_sign_recency(vault_resolved_at: u64) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    check_ric_sign_recency_at(
        vault_resolved_at,
        u64::try_from(now_unix_secs()).unwrap_or(0),
    )
}

/// Inner form taking `now` explicitly so the future-skew and max-age boundary
/// comparisons are deterministically unit-testable; the wrapper above supplies
/// the wall clock.
fn check_ric_sign_recency_at(
    vault_resolved_at: u64,
    now: u64,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if vault_resolved_at > now.saturating_add(crate::intent::RIC_FUTURE_SKEW_TOLERANCE_SECS) {
        return Err(unprocessable(
            error_codes::INTENT_VAULT_STALE,
            format!("vault_resolved_at {vault_resolved_at} is future-dated (now {now})"),
        ));
    }
    if now.saturating_sub(vault_resolved_at) > RIC_SIGN_MAX_AGE_SECS {
        return Err(unprocessable(
            error_codes::INTENT_VAULT_STALE,
            format!(
                "vault_resolved_at {vault_resolved_at} older than the \
                 {RIC_SIGN_MAX_AGE_SECS}s signing window (now {now})"
            ),
        ));
    }
    Ok(())
}

/// Floor `now` to the start of its `window`-second bucket. Extracted so the
/// bucket arithmetic is unit-testable without a live clock + `DaemonState`.
fn window_start_for(now: i64, window: i64) -> i64 {
    now - now.rem_euclid(window)
}

/// CTD-1 Slice E (`DL-CTD-E`): consume Set-B certification volume for
/// `chain_id` before the HSM is touched. Unmetered chains (no
/// configured cap) pass through. Runs strictly AFTER the equivocation
/// pre-flight returns `FirstTime`, so an idempotent retry never
/// double-consumes. Consume-before-HSM mirrors the RIC one-shot
/// posture: an HSM failure after consume burns window capacity until
/// the bucket rolls — fail-closed by design.
async fn consume_cert_volume_gate<S, H>(
    state: &DaemonState<S, H>,
    chain_id: ChainId,
    amount: U256,
) -> Result<(), (StatusCode, Json<ErrorBody>)>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    let Some(cap) = state.config.cert_volume.caps.get(&chain_id).copied() else {
        return Ok(());
    };
    let amount = u128::try_from(amount).map_err(|_| {
        unprocessable(
            error_codes::VOLUME_CAP_EXCEEDED,
            "amount exceeds u128 — cannot be metered against the volume window".to_string(),
        )
    })?;
    let now = now_unix_secs();
    // Validated > 0 at startup; an absurd >i64::MAX config falls back
    // to the 24h production bucket rather than panicking.
    let window = i64::try_from(state.config.cert_volume.window_secs).unwrap_or(86_400);
    let window_start = window_start_for(now, window);
    match state
        .replay
        .consume_cert_volume(chain_id, window_start, amount, cap)
        .await
        .map_err(|e| bad(error_codes::BAD_REQUEST, format!("volume db: {e}")))?
    {
        VolumeOutcome::Consumed { .. } => Ok(()),
        VolumeOutcome::Exceeded { attempted, cap } => Err(unprocessable(
            error_codes::VOLUME_CAP_EXCEEDED,
            format!(
                "per-window certification volume cap: attempted {attempted} > cap {cap} \
                 (window_start {window_start})"
            ),
        )),
    }
}

/// Signing-endpoint response shape (the same tuple-error type every
/// handler in this module returns).
type SignResult = Result<Json<Eip712SignResponse>, (StatusCode, Json<ErrorBody>)>;

/// Map a `ric_certs` replay outcome to a response: the cached RIC
/// signature on an identical retry, 409 on an equivocating retry,
/// `None` on first-time (caller proceeds — or treats it as impossible
/// in the post-record race re-read).
fn ric_cert_cached(config: &DaemonConfig, outcome: CheckOutcome) -> Option<SignResult> {
    match outcome {
        CheckOutcome::Idempotent(rec) => {
            let arr: Result<[u8; 65], _> = rec.signature.as_slice().try_into();
            Some(match arr {
                Ok(a) => Ok(Json(render_signature(config, a))),
                Err(_) => Err(bad(
                    error_codes::BAD_REQUEST,
                    "stored signature not 65 bytes".to_string(),
                )),
            })
        }
        CheckOutcome::Conflict { .. } => Some(Err(conflict(
            error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT,
            "leg already certified under a different intent — refusing to equivocate",
        ))),
        CheckOutcome::FirstTime => None,
    }
}

/// CTD-1 (`DL-CTD-2`) Slice A.7 — `POST /api/v1/sign/eip712-ric`.
///
/// Set-B certifies one redemption leg's custody-spend intent. The
/// daemon: refuses Solana legs (RA-2 hard gate); recomputes the RIC
/// EIP-712 digest from the plaintext fields on its locally-pinned
/// domain (never a caller-supplied digest); refuses stale/future
/// `vault_resolved_at` at the source; refuses to EQUIVOCATE — the
/// `ric_certs` replay arm (SEPARATE from the custody one-shot) makes a
/// second, different certificate for the same `(chain, redemption,
/// leg)` a 409 that never reaches the HSM; recover-verifies the HSM
/// signature (M6) before recording and returning it.
async fn handle_ric_sign<S, H>(
    State(state): State<DaemonState<S, H>>,
    Json(req): Json<RicSignRequest>,
) -> Result<Json<Eip712SignResponse>, (StatusCode, Json<ErrorBody>)>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    if req.chain_id == ChainId::Sol {
        return Err(unprocessable(
            error_codes::RIC_CHAIN_FORBIDDEN,
            "solana legs are CTD-1 hard-gated (RA-2): no on-chain destination root to certify",
        ));
    }
    let redemption_id = parse_b256(&req.redemption_id, "redemption_id")?;
    let leg_index = parse_u256(&req.leg_index, "leg_index")?;
    let leg = u32::try_from(leg_index)
        .map_err(|_| bad(error_codes::BAD_REQUEST, "leg_index exceeds u32"))?;
    let asset_id = parse_b256(&req.asset_id, "asset_id")?;
    let amount = parse_u256(&req.amount, "amount")?;
    let immediate_target_hash = parse_b256(&req.immediate_target_hash, "immediate_target_hash")?;
    let memo_hash = parse_b256(&req.memo_hash, "memo_hash")?;
    let final_destination_hash = parse_b256(&req.final_destination_hash, "final_destination_hash")?;
    check_ric_sign_recency(req.vault_resolved_at)?;

    let ric = redemption_intent_certificate(
        redemption_id,
        leg_index,
        asset_id,
        amount,
        req.amount_decimals,
        immediate_target_hash,
        memo_hash,
        final_destination_hash,
        req.vault_resolved_at,
    );
    let digest = ric_signing_hash(&ric, &state.config.domain());
    let payload_hash: [u8; 32] = digest.0;

    let outcome = state
        .replay
        .check_ric_cert(req.chain_id, redemption_id, leg, payload_hash)
        .await
        .map_err(|e| bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?;
    if let Some(resp) = ric_cert_cached(&state.config, outcome) {
        return resp;
    }
    consume_cert_volume_gate(&state, req.chain_id, amount).await?;
    let sig = state
        .hsm
        .sign_digest(state.config.eth_address, digest)
        .await
        .map_err(|e| hsm_unavailable(&e))?;
    recover_verify_signer(&sig, digest, state.config.eth_address)?;
    if let Err(e) = state
        .replay
        .record_ric_cert(
            req.chain_id,
            redemption_id,
            leg,
            payload_hash,
            sig.to_vec(),
            now_unix_secs(),
        )
        .await
    {
        if crate::replay::must_propagate_record_error(&e) {
            return Err(bad(error_codes::BAD_REQUEST, format!("replay record: {e}")));
        }
        // L10: lost the write race; return the winner's record.
        let outcome = state
            .replay
            .check_ric_cert(req.chain_id, redemption_id, leg, payload_hash)
            .await
            .map_err(|e| bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?;
        return ric_cert_cached(&state.config, outcome).unwrap_or_else(|| {
            Err(internal(
                error_codes::BAD_REQUEST,
                "record race left no row",
            ))
        });
    }
    Ok(Json(render_signature(&state.config, sig)))
}

/// CTD-1 Slice C — `POST /api/v1/sign/eip712-acc`.
///
/// Set-B certifies one MINT-CANCEL BTC swap-back's spend intent — the
/// sibling of [`handle_ric_sign`] for the `AcquireCancelled` path. Same
/// discipline: refuses Solana (RA-2); recomputes the ACC EIP-712 digest
/// from the plaintext on the daemon's pinned domain; refuses stale/future
/// `vault_resolved_at` at the source; refuses to EQUIVOCATE — a second,
/// different certificate for the same `(chain, cancel_id)` is a 409 via
/// the SEPARATE `ac_certs` arm; M6 recover-verify before record/return.
async fn handle_acc_sign<S, H>(
    State(state): State<DaemonState<S, H>>,
    Json(req): Json<AcquireCancelSignRequest>,
) -> Result<Json<Eip712SignResponse>, (StatusCode, Json<ErrorBody>)>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    if req.chain_id == ChainId::Sol {
        return Err(unprocessable(
            error_codes::RIC_CHAIN_FORBIDDEN,
            "solana legs are CTD-1 hard-gated (RA-2): no on-chain destination root to certify",
        ));
    }
    let cancel_id = parse_b256(&req.cancel_id, "cancel_id")?;
    let intent_id = parse_b256(&req.intent_id, "intent_id")?;
    // Slot index is bound into the certified digest (so a cert for slot 0
    // can't be replayed onto slot 1) but the ACC replay key is the unique
    // `cancel_id` alone — no separate slot sub-key.
    let slot_index = parse_u256(&req.slot_index, "slot_index")?;
    let asset_id = parse_b256(&req.asset_id, "asset_id")?;
    let amount = parse_u256(&req.amount, "amount")?;
    let immediate_target_hash = parse_b256(&req.immediate_target_hash, "immediate_target_hash")?;
    let memo_hash = parse_b256(&req.memo_hash, "memo_hash")?;
    let final_destination_hash = parse_b256(&req.final_destination_hash, "final_destination_hash")?;
    check_ric_sign_recency(req.vault_resolved_at)?;

    let acc = acquire_cancel_certificate(
        cancel_id,
        intent_id,
        slot_index,
        asset_id,
        amount,
        req.amount_decimals,
        immediate_target_hash,
        memo_hash,
        final_destination_hash,
        req.vault_resolved_at,
    );
    let digest = acquire_cancel_signing_hash(&acc, &state.config.domain());
    let payload_hash: [u8; 32] = digest.0;

    let outcome = state
        .replay
        .check_ac_cert(req.chain_id, cancel_id, payload_hash)
        .await
        .map_err(|e| bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?;
    if let Some(resp) = ric_cert_cached(&state.config, outcome) {
        return resp;
    }
    // Slice E: the mint-cancel swap-back consumes the SAME per-chain
    // window as redemptions — the cancel path cannot bypass the breaker.
    consume_cert_volume_gate(&state, req.chain_id, amount).await?;
    let sig = state
        .hsm
        .sign_digest(state.config.eth_address, digest)
        .await
        .map_err(|e| hsm_unavailable(&e))?;
    recover_verify_signer(&sig, digest, state.config.eth_address)?;
    if let Err(e) = state
        .replay
        .record_ac_cert(
            req.chain_id,
            cancel_id,
            payload_hash,
            sig.to_vec(),
            now_unix_secs(),
        )
        .await
    {
        if crate::replay::must_propagate_record_error(&e) {
            return Err(bad(error_codes::BAD_REQUEST, format!("replay record: {e}")));
        }
        let outcome = state
            .replay
            .check_ac_cert(req.chain_id, cancel_id, payload_hash)
            .await
            .map_err(|e| bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?;
        return ric_cert_cached(&state.config, outcome).unwrap_or_else(|| {
            Err(internal(
                error_codes::BAD_REQUEST,
                "record race left no row",
            ))
        });
    }
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
            intent_policy: crate::test_support::ric::policy(),
            cert_volume: crate::server::CertVolumePolicy::unmetered(),
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

    #[test]
    fn acc_error_code_maps_each_intent_error() {
        use crate::intent::IntentError;
        assert_eq!(
            acc_error_code(&IntentError::ProofInvalid(String::new())),
            error_codes::ACQUIRE_CANCEL_PROOF_INVALID
        );
        assert_eq!(
            acc_error_code(&IntentError::VaultStale(String::new())),
            error_codes::ACQUIRE_CANCEL_VAULT_STALE
        );
    }

    #[test]
    fn hash_leg_payload_binds_all_fields() {
        let rid = B256::repeat_byte(0x11);
        let leg = U256::from(2u64);
        let asset = B256::repeat_byte(0x33);
        let amount = U256::from(1_000_000u64);
        // Independent recomputation of the documented 128-byte layout — a
        // `-> [0; 32]` body or a layout change diverges from this.
        let mut buf = [0u8; 128];
        buf[..32].copy_from_slice(rid.as_slice());
        buf[32..64].copy_from_slice(&leg.to_be_bytes::<32>());
        buf[64..96].copy_from_slice(asset.as_slice());
        buf[96..128].copy_from_slice(&amount.to_be_bytes::<32>());
        let want: [u8; 32] = alloy_primitives::keccak256(buf).into();
        assert_eq!(hash_leg_payload(rid, leg, asset, amount), want);
        assert_ne!(want, [0u8; 32]);
        // Re-signing the same leg with a different amount is a different slot.
        assert_ne!(
            hash_leg_payload(rid, leg, asset, U256::from(999u64)),
            hash_leg_payload(rid, leg, asset, amount)
        );
    }

    #[test]
    fn ric_sign_recency_boundary() {
        let now = 1_000_000u64;
        let skew = crate::intent::RIC_FUTURE_SKEW_TOLERANCE_SECS;
        // Exactly at the future-skew limit is allowed; one second past is not.
        assert!(check_ric_sign_recency_at(now + skew, now).is_ok());
        assert!(check_ric_sign_recency_at(now + skew + 1, now).is_err());
        // Exactly at the max signing age is allowed; one second older is not.
        assert!(check_ric_sign_recency_at(now - RIC_SIGN_MAX_AGE_SECS, now).is_ok());
        assert!(check_ric_sign_recency_at(now - RIC_SIGN_MAX_AGE_SECS - 1, now).is_err());
    }

    #[test]
    fn window_start_floors_to_bucket() {
        assert_eq!(window_start_for(1_000, 600), 600);
        assert_eq!(window_start_for(600, 600), 600);
        assert_eq!(window_start_for(599, 600), 0);
        assert_eq!(window_start_for(1_200, 600), 1_200);
    }

    #[test]
    fn hsm_error_into_response_is_service_unavailable() {
        // The IntoResponse impl must map an HSM failure to 503, not a default
        // (200/empty) response that would mask the failure from the caller.
        let resp = HsmError::Decode("boom".to_string()).into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn sol_route_mounts_only_when_configured() {
        use crate::solana_tx::SolSignerConfig;
        use xindex_solana_tx::Pubkey;
        // With a Solana key configured the /sign/solana-tx route must be
        // mounted (a bad body yields 4xx, not 404). Inverting the
        // `!state.sol.is_empty()` guard would 404 a configured route.
        let (state, _hsm) = build_state();
        let state = state.with_sol(SolSignerConfig {
            chain: ChainId::Sol,
            multisig_pda: Pubkey::new([1u8; 32]),
            vault_index: 0,
            members: vec![],
            member_pubkey: Pubkey::new([2u8; 32]),
            member_seed: [3u8; 32],
        });
        let app = router(state);
        let (status, _) = post_json(&app, "/api/v1/sign/solana-tx", serde_json::json!({})).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "sol route must be mounted when a sol key is configured"
        );
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

    /// L10: the attestation handler loses the `record_attestation` write
    /// race (store returns `Duplicate`). It must re-read the winner's row
    /// and return the cached signature idempotently — HTTP 200, NOT an
    /// error.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn attestation_record_race_recovers_cached_signature() {
        use crate::replay::InMemoryReplayStore;
        use crate::test_support::{RacePath, RaceReplayStore};

        let intent_id = B256::repeat_byte(0x6c);
        let slot_index = U256::from(0u8);
        let attested_amount = U256::from(1_000_000u32);
        let payload_hash = hash_attestation_payload(intent_id, slot_index, attested_amount);

        // The winner already recorded a valid 65-byte signature.
        let winner_sig: [u8; 65] = {
            use alloy::signers::SignerSync;
            let att = attestation(intent_id, slot_index, attested_amount);
            let domain = attestation_oracle_domain(31337, Address::repeat_byte(0xab));
            let digest = attestation_signing_hash(&att, &domain);
            test_key().sign_hash_sync(&digest).expect("sign").as_bytes()
        };
        let inner = InMemoryReplayStore::new();
        inner
            .record_attestation(
                intent_id,
                slot_index,
                payload_hash,
                winner_sig.to_vec(),
                100,
            )
            .await
            .expect("seed winner");
        let replay = Arc::new(RaceReplayStore::new(inner, RacePath::Attestation));
        let hsm = Arc::new(CapturingSigner::default());
        let state = DaemonState::new(cfg(), replay, hsm);
        let app = router(state);

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
        assert_eq!(
            body["signature"].as_str().unwrap_or(""),
            format!("0x{}", alloy_primitives::hex::encode(winner_sig))
        );
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

    /// STREAM-B2-COORD: the combined streamed-settlement endpoint signs the
    /// structurally-distinct `AsyncLegStreamedSettlement` digest (NOT the
    /// delivery/refund one), binds both amounts, and is idempotent.
    #[tokio::test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    async fn streamed_settlement_signs_distinct_typehash_idempotently() {
        let (state, hsm) = build_state();
        let app = router(state.clone());
        let red = B256::repeat_byte(0x66);
        let asset = B256::repeat_byte(0xa1);
        let delivered = U256::from(40_000_000u64);
        let refunded = U256::from(12_345u64);
        let body = serde_json::json!({
            "redemption_id": format!("{red:#x}"),
            "leg_index": "0",
            "asset_id": format!("{asset:#x}"),
            "delivered_usdt": delivered.to_string(),
            "refunded_native": refunded.to_string(),
        });

        let (status, _) = post_json(
            &app,
            "/api/v1/sign/eip712-streamed-settlement",
            body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // The HSM saw the STREAMED digest — distinct from the delivery
        // digest for the same (id, leg, asset, amount): the 4-way typehash
        // separation mirrored from the on-chain oracle.
        let expected = streamed_settlement_signing_hash(
            &streamed_settlement(red, U256::ZERO, asset, delivered, refunded),
            &state.config.domain(),
        );
        let delivery_digest = redemption_attestation_signing_hash(
            &redemption_attestation(red, U256::ZERO, asset, delivered),
            &state.config.domain(),
        );
        assert_ne!(
            expected, delivery_digest,
            "streamed digest must differ from delivery"
        );
        assert_eq!(hsm.seen.lock().unwrap()[0].1, expected);

        // Idempotent re-request returns the cached signature WITHOUT
        // re-invoking the HSM.
        let (s2, _) = post_json(&app, "/api/v1/sign/eip712-streamed-settlement", body).await;
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(
            hsm.seen.lock().unwrap().len(),
            1,
            "idempotent retry must not re-sign"
        );
    }

    /// F: `validate()` passes the dev/test UNMETERED policy, but the
    /// production assertion rejects a served chain with no positive cap —
    /// the CTD-1 containment teeth (DL-CTD-E) must never be off in prod.
    #[test]
    fn cert_volume_assert_metered_for_is_production_strict() {
        use std::collections::HashMap;
        let unmetered = CertVolumePolicy::unmetered();
        assert!(
            unmetered.validate().is_ok(),
            "unmetered passes dev/test sanity"
        );
        assert!(
            unmetered.assert_metered_for(&[ChainId::Tron]).is_err(),
            "production rejects an unmetered served chain"
        );
        let mut caps = HashMap::new();
        caps.insert(ChainId::Tron, 1_000_000_u128);
        let metered = CertVolumePolicy {
            window_secs: 86_400,
            caps,
        };
        assert!(metered.assert_metered_for(&[ChainId::Tron]).is_ok());
        assert!(
            metered.assert_metered_for(&[ChainId::Btc]).is_err(),
            "a served chain absent from caps is the unmetered footgun — rejected"
        );
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
        use crate::test_support::ric as ric_fixtures;
        use alloy_primitives::Bytes;
        use alloy_sol_types::SolCall;
        use xindex_safe_evm::{
            digest::{safe_tx_hash, SafeTransaction},
            SafeOperation,
        };
        use xindex_shared::signer_wire::EvmSafeTxSignRequest;
        use xindex_shared::thorchain_router::depositWithExpiryCall;

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

        /// Build the HONEST redemption template — the only shape the
        /// CTD-1 bind accepts: `Router.depositWithExpiry(vault,
        /// address(0), amount, memo, expiry)` with `value == amount` —
        /// plus a matching k-of-n `IntentProof`. `memo` doubles as the
        /// per-test discriminator (it derives the redemption id, so
        /// different memos are different legs for the RIC one-shot).
        fn build_request(
            chain: ChainId,
            safe: Address,
            nonce: u64,
            memo: &str,
        ) -> (SafeTransaction, EvmSafeTxSignRequest) {
            let vault = Address::new([0xaa; 20]);
            let amount = U256::from(1_500_000_000_000_000_u64);
            let call = depositWithExpiryCall {
                vault,
                asset: Address::ZERO,
                amount,
                memo: memo.to_string(),
                expiry: U256::from(1_900_000_000_u64),
            };
            let router = chain.thorchain_router_address().unwrap_or(Address::ZERO);
            let tx = SafeTransaction {
                to: router,
                value: amount,
                data: Bytes::from(call.abi_encode()),
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
            let proof = ric_fixtures::proof_for(
                cfg().chain_id,
                cfg().verifying_contract,
                &ric_fixtures::CertSpec {
                    chain,
                    redemption_id: alloy_primitives::keccak256(memo.as_bytes()),
                    leg_index: 0,
                    amount,
                    immediate_target: vault.as_slice().to_vec(),
                    memo: memo.as_bytes().to_vec(),
                },
            );
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
                intent_proof: Some(proof),
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
                let (tx, req) = build_request(chain, safe, 0, "hello");
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
            let (_, req) = build_request(ChainId::Eth, ETH_SAFE, 0, "x");
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
            let (_, mut req) = build_request(ChainId::Avax, ETH_SAFE, 0, "");
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
            let (_, req) = build_request(ChainId::Eth, bogus_safe, 0, "");
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
            let (_, mut req) = build_request(ChainId::Eth, ETH_SAFE, 0, "original");
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
            let (_, req) = build_request(ChainId::Eth, ETH_SAFE, 42, "once");
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
            let (_, req1) = build_request(ChainId::Eth, ETH_SAFE, 7, "first");
            let (_, req2) = build_request(ChainId::Eth, ETH_SAFE, 7, "different");
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

        /// CTD-1: a request WITHOUT an `IntentProof` is refused before
        /// anything else — there is no proof-less carve-out.
        #[tokio::test]
        async fn missing_intent_proof_is_422_required() {
            let (state, hsm) = evm_state();
            let app = router(state);
            let (_, mut req) = build_request(ChainId::Eth, ETH_SAFE, 0, "no-proof");
            req.intent_proof = None;
            let body = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
            let (status, body) = post_json(&app, "/api/v1/sign/evm-safe-tx", body).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(
                body["code"].as_str().unwrap_or(""),
                error_codes::INTENT_PROOF_REQUIRED
            );
            #[expect(clippy::unwrap_used, reason = "test code")]
            let seen = hsm.seen.lock().unwrap();
            assert!(seen.is_empty());
        }

        /// CTD-1 core property: the certificate authorizes ONE vault;
        /// a Safe-tx paying a different vault under the same (valid)
        /// proof is refused with `intent_mismatch` before the HSM.
        #[tokio::test]
        async fn poisoned_vault_is_422_mismatch() {
            let (state, hsm) = evm_state();
            let app = router(state);
            let (_, honest) = build_request(ChainId::Eth, ETH_SAFE, 0, "poison");
            // Rebuild the Safe-tx paying an ATTACKER vault, keeping the
            // honest certificate attached.
            let attacker_vault = Address::new([0x66; 20]);
            let amount = U256::from(1_500_000_000_000_000_u64);
            let call = depositWithExpiryCall {
                vault: attacker_vault,
                asset: Address::ZERO,
                amount,
                memo: "poison".to_string(),
                expiry: U256::from(1_900_000_000_u64),
            };
            let router_addr = ChainId::Eth
                .thorchain_router_address()
                .unwrap_or(Address::ZERO);
            let tx = SafeTransaction {
                to: router_addr,
                value: amount,
                data: Bytes::from(call.abi_encode()),
                operation: SafeOperation::Call,
                safe_tx_gas: U256::ZERO,
                base_gas: U256::ZERO,
                gas_price: U256::ZERO,
                gas_token: Address::ZERO,
                refund_receiver: Address::ZERO,
                nonce: U256::ZERO,
            };
            #[expect(clippy::expect_used, reason = "test code")]
            let evm_chain_id = ChainId::Eth.evm_chain_id().expect("evm chain");
            let h = safe_tx_hash(evm_chain_id, ETH_SAFE, &tx);
            let mut req = honest;
            req.to = format!("{:#x}", tx.to);
            req.data = format!("0x{}", alloy_primitives::hex::encode(&tx.data));
            req.safe_tx_hash = format!("0x{}", alloy_primitives::hex::encode(h));
            let body = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
            let (status, body) = post_json(&app, "/api/v1/sign/evm-safe-tx", body).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
            assert_eq!(
                body["code"].as_str().unwrap_or(""),
                error_codes::INTENT_MISMATCH
            );
            #[expect(clippy::unwrap_used, reason = "test code")]
            let seen = hsm.seen.lock().unwrap();
            assert!(seen.is_empty());
        }

        /// CTD-1 / RA-1: a SECOND, different certificate for an
        /// already-consumed `(chain, redemption, leg)` is a 409
        /// `intent_already_signed` — one valid RIC can never become
        /// N payouts.
        #[tokio::test]
        async fn redriven_leg_with_different_cert_is_409() {
            let (state, hsm) = evm_state();
            let app = router(state);
            let (_, req1) = build_request(ChainId::Eth, ETH_SAFE, 0, "redrive");
            let (s1, _) = post_json(
                &app,
                "/api/v1/sign/evm-safe-tx",
                serde_json::to_value(&req1).unwrap_or(serde_json::Value::Null),
            )
            .await;
            assert_eq!(s1, StatusCode::OK);

            // Same redemption id + leg, DIFFERENT certified amount → a
            // different RIC digest at the consumed one-shot key.
            let amount2 = U256::from(2_000_000_000_000_000_u64);
            let (_, mut req2) = build_request(ChainId::Eth, ETH_SAFE, 1, "redrive");
            let proof2 = ric_fixtures::proof_for(
                cfg().chain_id,
                cfg().verifying_contract,
                &ric_fixtures::CertSpec {
                    chain: ChainId::Eth,
                    redemption_id: alloy_primitives::keccak256("redrive".as_bytes()),
                    leg_index: 0,
                    amount: amount2,
                    immediate_target: Address::new([0xaa; 20]).as_slice().to_vec(),
                    memo: "redrive".as_bytes().to_vec(),
                },
            );
            req2.intent_proof = Some(proof2);
            let (s2, b2) = post_json(
                &app,
                "/api/v1/sign/evm-safe-tx",
                serde_json::to_value(&req2).unwrap_or(serde_json::Value::Null),
            )
            .await;
            assert_eq!(s2, StatusCode::CONFLICT, "body: {b2}");
            assert_eq!(
                b2["code"].as_str().unwrap_or(""),
                error_codes::INTENT_ALREADY_SIGNED
            );
            #[expect(clippy::unwrap_used, reason = "test code")]
            let seen = hsm.seen.lock().unwrap();
            assert_eq!(seen.len(), 1, "second spend never reaches the HSM");
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

    /// CTD-1 Slice E — Set-B certification volume windows (`DL-CTD-E`).
    mod volume_tests {
        use super::*;

        fn fresh_now() -> u64 {
            u64::try_from(now_unix_secs()).unwrap_or(0)
        }

        /// State with a BTC cap (native sats per 24h window); all other
        /// chains unmetered.
        fn metered_state(
            cap: u128,
        ) -> (
            DaemonState<InMemoryReplayStore, CapturingSigner>,
            Arc<CapturingSigner>,
        ) {
            let mut config = cfg();
            config.cert_volume.caps.insert(ChainId::Btc, cap);
            let replay = Arc::new(InMemoryReplayStore::new());
            let hsm = Arc::new(CapturingSigner::default());
            (DaemonState::new(config, replay, hsm.clone()), hsm)
        }

        /// 1-BTC (1e8 sat) RIC body at `leg`.
        fn ric_body(leg: &str, vault_resolved_at: u64) -> serde_json::Value {
            serde_json::json!({
                "chain_id": "btc",
                "redemption_id": format!("0x{}", "ab".repeat(32)),
                "leg_index": leg,
                "asset_id": format!("0x{}", "a1".repeat(32)),
                "amount": "100000000",
                "amount_decimals": 8,
                "immediate_target_hash": format!("0x{}", "cd".repeat(32)),
                "memo_hash": format!("0x{}", "ef".repeat(32)),
                "final_destination_hash": format!("0x{}", "12".repeat(32)),
                "vault_resolved_at": vault_resolved_at,
            })
        }

        /// 1-BTC mint-cancel ACC body.
        fn acc_body(vault_resolved_at: u64) -> serde_json::Value {
            serde_json::json!({
                "chain_id": "btc",
                "cancel_id": format!("0x{}", "77".repeat(32)),
                "intent_id": format!("0x{}", "88".repeat(32)),
                "slot_index": "0",
                "asset_id": format!("0x{}", "a1".repeat(32)),
                "amount": "100000000",
                "amount_decimals": 8,
                "immediate_target_hash": format!("0x{}", "cd".repeat(32)),
                "memo_hash": format!("0x{}", "ef".repeat(32)),
                "final_destination_hash": format!("0x{}", "12".repeat(32)),
                "vault_resolved_at": vault_resolved_at,
            })
        }

        /// Over the per-chain window cap → 422 `volume_cap_exceeded`;
        /// the refused certification never reaches the HSM.
        #[tokio::test]
        async fn ric_over_cap_is_422() {
            let (state, hsm) = metered_state(150_000_000);
            let app = router(state);
            let now = fresh_now() - 5;
            let (s1, b1) = post_json(&app, "/api/v1/sign/eip712-ric", ric_body("1", now)).await;
            assert_eq!(s1, StatusCode::OK, "body: {b1}");
            let (s2, b2) = post_json(&app, "/api/v1/sign/eip712-ric", ric_body("2", now)).await;
            assert_eq!(s2, StatusCode::UNPROCESSABLE_ENTITY, "body: {b2}");
            assert_eq!(
                b2["code"].as_str().unwrap_or(""),
                error_codes::VOLUME_CAP_EXCEEDED
            );
            #[expect(clippy::unwrap_used, reason = "test code")]
            let calls = hsm.seen.lock().unwrap().len();
            assert_eq!(calls, 1, "refused certification must not reach the HSM");
        }

        /// An idempotent retry returns the cached signature WITHOUT
        /// consuming window capacity a second time.
        #[tokio::test]
        async fn idempotent_retry_does_not_double_consume() {
            let (state, _hsm) = metered_state(100_000_000);
            let app = router(state);
            let now = fresh_now() - 5;
            let body = ric_body("1", now);
            let (s1, _) = post_json(&app, "/api/v1/sign/eip712-ric", body.clone()).await;
            assert_eq!(s1, StatusCode::OK);
            // The window is exactly full; a double-consume would refuse
            // this identical retry.
            let (s2, b2) = post_json(&app, "/api/v1/sign/eip712-ric", body).await;
            assert_eq!(s2, StatusCode::OK, "body: {b2}");
            // …and a NEW leg is refused — the window really is full.
            let (s3, b3) = post_json(&app, "/api/v1/sign/eip712-ric", ric_body("2", now)).await;
            assert_eq!(s3, StatusCode::UNPROCESSABLE_ENTITY, "body: {b3}");
        }

        /// The mint-cancel ACC consumes the SAME per-chain window — the
        /// cancel path cannot bypass the breaker.
        #[tokio::test]
        async fn acc_consumes_same_window_as_ric() {
            let (state, _hsm) = metered_state(150_000_000);
            let app = router(state);
            let now = fresh_now() - 5;
            let (s1, b1) = post_json(&app, "/api/v1/sign/eip712-ric", ric_body("1", now)).await;
            assert_eq!(s1, StatusCode::OK, "body: {b1}");
            let (s2, b2) = post_json(&app, "/api/v1/sign/eip712-acc", acc_body(now)).await;
            assert_eq!(s2, StatusCode::UNPROCESSABLE_ENTITY, "body: {b2}");
            assert_eq!(
                b2["code"].as_str().unwrap_or(""),
                error_codes::VOLUME_CAP_EXCEEDED
            );
        }

        /// Unmetered chains pass any volume (the dev/test default).
        #[tokio::test]
        async fn unmetered_chain_passes() {
            let (state, _hsm) = build_state();
            let app = router(state);
            let now = fresh_now() - 5;
            let (s1, _) = post_json(&app, "/api/v1/sign/eip712-ric", ric_body("1", now)).await;
            let (s2, _) = post_json(&app, "/api/v1/sign/eip712-ric", ric_body("2", now)).await;
            assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK));
        }

        /// Policy validation fails closed on impossible configs.
        #[test]
        fn policy_validation_fails_closed() {
            assert!(CertVolumePolicy::unmetered().validate().is_ok());
            let mut zero_window = CertVolumePolicy::unmetered();
            zero_window.window_secs = 0;
            assert!(zero_window.validate().is_err());
            let mut zero_cap = CertVolumePolicy::unmetered();
            zero_cap.caps.insert(ChainId::Btc, 0);
            assert!(zero_cap.validate().is_err());
        }
    }

    /// CTD-1 Slice A.7 — `/api/v1/sign/eip712-ric` (Set-B certifies a
    /// redemption leg's custody-spend intent).
    mod ric_sign_tests {
        use super::*;

        fn fresh_now() -> u64 {
            u64::try_from(now_unix_secs()).unwrap_or(0)
        }

        fn ric_body(chain: &str, vault_resolved_at: u64) -> serde_json::Value {
            serde_json::json!({
                "chain_id": chain,
                "redemption_id": format!("0x{}", "ab".repeat(32)),
                "leg_index": "1",
                "asset_id": format!("0x{}", "a1".repeat(32)),
                "amount": "100000000",
                "amount_decimals": 8,
                "immediate_target_hash": format!("0x{}", "cd".repeat(32)),
                "memo_hash": format!("0x{}", "ef".repeat(32)),
                "final_destination_hash": format!("0x{}", "12".repeat(32)),
                "vault_resolved_at": vault_resolved_at,
            })
        }

        /// The single most important property: the daemon hands the HSM
        /// the RIC digest recomputed from the request's plaintext fields
        /// on ITS OWN pinned domain — independently recomputed here.
        #[tokio::test]
        async fn ric_sign_hands_hsm_the_recomputed_ric_digest() {
            let (state, hsm) = build_state();
            let app = router(state);
            let resolved_at = fresh_now() - 5;

            let (status, body) = post_json(
                &app,
                "/api/v1/sign/eip712-ric",
                ric_body("btc", resolved_at),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "body: {body}");
            let sig_hex = body["signature"].as_str().unwrap_or("");
            assert!(sig_hex.starts_with("0x") && sig_hex.len() == 2 + 130);
            assert_eq!(
                body["signer_address"].as_str().unwrap_or(""),
                format!("{:#x}", test_key().address())
            );

            let expected_ric = redemption_intent_certificate(
                B256::repeat_byte(0xab),
                U256::from(1u8),
                B256::repeat_byte(0xa1),
                U256::from(100_000_000_u64),
                8,
                B256::repeat_byte(0xcd),
                B256::repeat_byte(0xef),
                B256::repeat_byte(0x12),
                resolved_at,
            );
            let expected_digest = ric_signing_hash(
                &expected_ric,
                &attestation_oracle_domain(cfg().chain_id, cfg().verifying_contract),
            );
            #[expect(clippy::unwrap_used, reason = "test code")]
            let seen = hsm.seen.lock().unwrap().clone();
            assert_eq!(seen, vec![(test_key().address(), expected_digest)]);
        }

        /// Identical retry → cached signature, HSM invoked exactly once.
        #[tokio::test]
        async fn ric_sign_identical_retry_is_idempotent() {
            let (state, hsm) = build_state();
            let app = router(state);
            let body = ric_body("btc", fresh_now() - 5);

            let (s1, b1) = post_json(&app, "/api/v1/sign/eip712-ric", body.clone()).await;
            let (s2, b2) = post_json(&app, "/api/v1/sign/eip712-ric", body).await;
            assert_eq!(s1, StatusCode::OK);
            assert_eq!(s2, StatusCode::OK);
            assert_eq!(b1["signature"], b2["signature"]);
            #[expect(clippy::unwrap_used, reason = "test code")]
            let calls = hsm.seen.lock().unwrap().len();
            assert_eq!(calls, 1, "idempotent retry must not re-invoke the HSM");
        }

        /// A DIFFERENT certificate for the same `(chain, redemption,
        /// leg)` → 409 equivocation refusal, HSM never re-invoked.
        #[tokio::test]
        async fn ric_sign_equivocation_is_409() {
            let (state, hsm) = build_state();
            let app = router(state);
            let resolved_at = fresh_now() - 5;

            let (s1, _) = post_json(
                &app,
                "/api/v1/sign/eip712-ric",
                ric_body("btc", resolved_at),
            )
            .await;
            assert_eq!(s1, StatusCode::OK);

            let mut second = ric_body("btc", resolved_at);
            second["amount"] = serde_json::json!("200000000");
            let (s2, b2) = post_json(&app, "/api/v1/sign/eip712-ric", second).await;
            assert_eq!(s2, StatusCode::CONFLICT);
            assert_eq!(
                b2["code"].as_str().unwrap_or(""),
                error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT
            );
            #[expect(clippy::unwrap_used, reason = "test code")]
            let calls = hsm.seen.lock().unwrap().len();
            assert_eq!(calls, 1, "equivocating retry must never reach the HSM");
        }

        /// Same redemption+leg on a DIFFERENT chain is an independent
        /// replay namespace (a leg belongs to exactly one chain; the
        /// namespace split just keeps the key honest).
        #[tokio::test]
        async fn ric_sign_chain_namespaces_are_independent() {
            let (state, _hsm) = build_state();
            let app = router(state);
            let resolved_at = fresh_now() - 5;

            let (s1, _) = post_json(
                &app,
                "/api/v1/sign/eip712-ric",
                ric_body("btc", resolved_at),
            )
            .await;
            let (s2, _) = post_json(
                &app,
                "/api/v1/sign/eip712-ric",
                ric_body("ltc", resolved_at),
            )
            .await;
            assert_eq!(s1, StatusCode::OK);
            assert_eq!(s2, StatusCode::OK);
        }

        /// RA-2: the daemon refuses to certify a Solana leg.
        #[tokio::test]
        async fn ric_sign_rejects_solana() {
            let (state, hsm) = build_state();
            let app = router(state);

            let (status, body) = post_json(
                &app,
                "/api/v1/sign/eip712-ric",
                ric_body("sol", fresh_now()),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(
                body["code"].as_str().unwrap_or(""),
                error_codes::RIC_CHAIN_FORBIDDEN
            );
            #[expect(clippy::unwrap_used, reason = "test code")]
            let calls = hsm.seen.lock().unwrap().len();
            assert_eq!(calls, 0, "the RA-2 gate must fire before the HSM");
        }

        /// RA-5 at the source: stale and future-dated resolutions are
        /// refused before the HSM.
        #[tokio::test]
        async fn ric_sign_rejects_stale_and_future_resolution() {
            let (state, hsm) = build_state();
            let app = router(state);
            let now = fresh_now();

            let stale = ric_body("btc", now - RIC_SIGN_MAX_AGE_SECS - 30);
            let (s1, b1) = post_json(&app, "/api/v1/sign/eip712-ric", stale).await;
            assert_eq!(s1, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(
                b1["code"].as_str().unwrap_or(""),
                error_codes::INTENT_VAULT_STALE
            );

            let future = ric_body(
                "btc",
                now + crate::intent::RIC_FUTURE_SKEW_TOLERANCE_SECS + 30,
            );
            let (s2, b2) = post_json(&app, "/api/v1/sign/eip712-ric", future).await;
            assert_eq!(s2, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(
                b2["code"].as_str().unwrap_or(""),
                error_codes::INTENT_VAULT_STALE
            );
            #[expect(clippy::unwrap_used, reason = "test code")]
            let calls = hsm.seen.lock().unwrap().len();
            assert_eq!(calls, 0, "recency rejections must never reach the HSM");
        }

        /// Malformed fields are 400s at the parse boundary.
        #[tokio::test]
        async fn ric_sign_rejects_malformed_fields() {
            let (state, _hsm) = build_state();
            let app = router(state);
            let now = fresh_now();

            let mut bad_rid = ric_body("btc", now - 5);
            bad_rid["redemption_id"] = serde_json::json!("0x1234");
            let (s1, _) = post_json(&app, "/api/v1/sign/eip712-ric", bad_rid).await;
            assert_eq!(s1, StatusCode::BAD_REQUEST);

            let mut big_leg = ric_body("btc", now - 5);
            big_leg["leg_index"] = serde_json::json!("4294967296");
            let (s2, _) = post_json(&app, "/api/v1/sign/eip712-ric", big_leg).await;
            assert_eq!(s2, StatusCode::BAD_REQUEST);

            let mut bad_amount = ric_body("btc", now - 5);
            bad_amount["amount"] = serde_json::json!("12x");
            let (s3, _) = post_json(&app, "/api/v1/sign/eip712-ric", bad_amount).await;
            assert_eq!(s3, StatusCode::BAD_REQUEST);
        }
    }
}
