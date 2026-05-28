//! V5 — `POST /api/v1/sign/evm-safe-tx` handler.
//!
//! The Phase 3.2 EVM custody-family signing endpoint. Mirrors the
//! PSBT-input handler ([`crate::psbt`]) at the per-chain dispatch
//! shape — `DaemonState.evm: HashMap<ChainId, Arc<EvmSignerConfig>>`
//! decides which chains this daemon serves; a request for an
//! unconfigured chain returns `404 endpoint_disabled`.
//!
//! ## Five-step pipeline
//!
//! 1. Parse the wire request into [`xindex_shared::signer_wire::EvmSafeTxSignRequest`].
//! 2. Look up the per-chain [`EvmSignerConfig`] by `req.chain_id`.
//! 3. Decode the 10 `SafeTx` ABI fields into the
//!    [`xindex_safe_evm::digest::SafeTransaction`] struct.
//! 4. RE-COMPUTE `safeTxHash` via
//!    [`xindex_safe_evm::digest::safe_tx_hash`] and refuse with
//!    `safe_tx_hash_mismatch` if the caller's claim disagrees. The
//!    daemon never blind-signs a coordinator-supplied digest.
//! 5. Consult the replay DB on `(chain_id, safe_address, nonce)`:
//!    `FirstTime` → HSM-sign + record; `Idempotent` → return cached;
//!    `Conflict` → 409 (`conflict_already_signed_different`), HSM
//!    never touched.

use std::sync::Arc;

use alloy_primitives::{Address, Bytes, PrimitiveSignature, U256};
use axum::{extract::State, http::StatusCode, response::Json};
use xindex_safe_evm::{
    digest::{safe_tx_hash, SafeTransaction},
    SafeOperation,
};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{
    error_codes, Eip712SignResponse, ErrorBody, EvmSafeTxSignRequest,
};

use crate::replay::{CheckOutcome, ReplayStore};
use crate::server::DaemonState;
use crate::web3signer::{HsmDigestSigner, HsmError};

/// Per-chain EVM signing role configuration. One entry per EVM chain
/// this daemon is configured for. Each chain has its own 3-of-5 Safe
/// (no cross-chain key sharing — DL-P3-7), so each chain has its own
/// `EvmSignerConfig`.
#[derive(Debug, Clone)]
pub struct EvmSignerConfig {
    /// Which EVM chain this config serves. Matches
    /// `EvmSafeTxSignRequest::chain_id`.
    pub chain: ChainId,
    /// The Safe v1.4.1 proxy contract address this daemon signs for on
    /// `chain`. The handler refuses a request whose
    /// `req.safe_address` does not match this constant — defence
    /// against a coordinator pointing the daemon at a Safe whose
    /// owner-set the daemon is not in.
    pub safe_address: Address,
    /// This daemon's signer EOA address on `chain`. Bound to the HSM
    /// key handle and asserted as one of the configured Safe's
    /// owners at deploy time. The HSM's `sign_digest(addr, _)` call
    /// is invoked with this address.
    pub my_signer_address: Address,
}

/// Helper: build the `(StatusCode, Json<ErrorBody>)` shorthand.
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

fn parse_address(field: &str, hex_str: &str) -> Result<Address, (StatusCode, Json<ErrorBody>)> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = alloy_primitives::hex::decode(stripped).map_err(|e| {
        err(
            error_codes::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            format!("{field}: bad hex: {e}"),
        )
    })?;
    let arr: [u8; 20] = bytes.as_slice().try_into().map_err(|_| {
        err(
            error_codes::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            format!(
                "{field}: expected 20-byte address, got {} bytes",
                bytes.len()
            ),
        )
    })?;
    Ok(Address::from(arr))
}

fn parse_u256_dec(field: &str, dec_str: &str) -> Result<U256, (StatusCode, Json<ErrorBody>)> {
    U256::from_str_radix(dec_str, 10).map_err(|e| {
        err(
            error_codes::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            format!("{field}: bad decimal U256: {e}"),
        )
    })
}

fn parse_bytes_hex(field: &str, hex_str: &str) -> Result<Bytes, (StatusCode, Json<ErrorBody>)> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if stripped.is_empty() {
        return Ok(Bytes::new());
    }
    let raw = alloy_primitives::hex::decode(stripped).map_err(|e| {
        err(
            error_codes::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            format!("{field}: bad hex: {e}"),
        )
    })?;
    Ok(Bytes::from(raw))
}

fn parse_operation(op: u8) -> Result<SafeOperation, (StatusCode, Json<ErrorBody>)> {
    match op {
        0 => Ok(SafeOperation::Call),
        1 => Ok(SafeOperation::DelegateCall),
        other => Err(err(
            error_codes::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            format!("operation: expected 0 (Call) or 1 (DelegateCall), got {other}"),
        )),
    }
}

fn parse_nonce_u64(nonce_str: &str) -> Result<u64, (StatusCode, Json<ErrorBody>)> {
    let n = U256::from_str_radix(nonce_str, 10).map_err(|e| {
        err(
            error_codes::NONCE_OUT_OF_RANGE,
            StatusCode::BAD_REQUEST,
            format!("nonce: bad decimal: {e}"),
        )
    })?;
    u64::try_from(n).map_err(|_| {
        err(
            error_codes::NONCE_OUT_OF_RANGE,
            StatusCode::BAD_REQUEST,
            format!("nonce: {n} exceeds u64 range"),
        )
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

fn render_signature(signer: Address, sig: [u8; 65]) -> Eip712SignResponse {
    Eip712SignResponse {
        signature: format!("0x{}", alloy_primitives::hex::encode(sig)),
        signer_address: format!("{signer:#x}"),
    }
}

fn hsm_unavailable(e: &HsmError) -> (StatusCode, Json<ErrorBody>) {
    err(
        error_codes::HSM_UNAVAILABLE,
        StatusCode::SERVICE_UNAVAILABLE,
        e.to_string(),
    )
}

/// Axum handler for `/api/v1/sign/evm-safe-tx`.
///
/// # Errors
/// Returns an `(StatusCode, Json<ErrorBody>)` tuple with one of the
/// stable `error_codes` constants:
/// - `endpoint_disabled` (404) — no EVM role for the requested chain.
/// - `wrong_safe_address` (422) — request's safe doesn't match config.
/// - `bad_request` (400) — any input field fails to parse.
/// - `nonce_out_of_range` (400) — nonce exceeds u64.
/// - `safe_tx_hash_mismatch` (422) — recomputed digest disagrees with
///   the caller-supplied `safe_tx_hash`.
/// - `conflict_already_signed_different` (409) — same (chain, safe,
///   nonce) previously signed under a different payload.
/// - `hsm_unavailable` (503) — HSM frontend declined to sign.
#[expect(
    clippy::too_many_lines,
    reason = "single sequential validate-then-sign pipeline; splitting fragments the audit-relevant ordering of checks"
)]
pub async fn handle_evm_safe_tx<S, H>(
    State(state): State<DaemonState<S, H>>,
    Json(req): Json<EvmSafeTxSignRequest>,
) -> Result<Json<Eip712SignResponse>, (StatusCode, Json<ErrorBody>)>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    // 1. Look up per-chain config.
    let evm_cfg: Arc<EvmSignerConfig> = state.evm.get(&req.chain_id).cloned().ok_or_else(|| {
        err(
            error_codes::ENDPOINT_DISABLED,
            StatusCode::NOT_FOUND,
            format!(
                "EVM role for chain {:?} not enabled on this daemon",
                req.chain_id
            ),
        )
    })?;

    // 2. Parse the Safe-tx ABI inputs.
    let req_safe = parse_address("safe_address", &req.safe_address)?;
    if req_safe != evm_cfg.safe_address {
        return Err(err(
            error_codes::WRONG_SAFE_ADDRESS,
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "safe_address mismatch: configured {:#x}, request {:#x}",
                evm_cfg.safe_address, req_safe
            ),
        ));
    }
    let to = parse_address("to", &req.to)?;
    let value = parse_u256_dec("value", &req.value)?;
    let data = parse_bytes_hex("data", &req.data)?;
    let operation = parse_operation(req.operation)?;
    let safe_tx_gas = parse_u256_dec("safe_tx_gas", &req.safe_tx_gas)?;
    let base_gas = parse_u256_dec("base_gas", &req.base_gas)?;
    let gas_price = parse_u256_dec("gas_price", &req.gas_price)?;
    let gas_token = parse_address("gas_token", &req.gas_token)?;
    let refund_receiver = parse_address("refund_receiver", &req.refund_receiver)?;
    let nonce_u64 = parse_nonce_u64(&req.nonce)?;
    let nonce_u256 = U256::from(nonce_u64);
    let claimed_hash = parse_b256_hex("safe_tx_hash", &req.safe_tx_hash)?;

    // 3. Re-compute `safeTxHash` from the inputs.
    let evm_chain_id = req.chain_id.evm_chain_id().ok_or_else(|| {
        // Unreachable in practice: the serde validator rejected non-EVM
        // chains on the way in; if we got here with a `None`, it's a
        // bug in the registry.
        err(
            error_codes::NON_EVM_CHAIN,
            StatusCode::UNPROCESSABLE_ENTITY,
            "chain has no EVM chain_id in registry".to_string(),
        )
    })?;
    let safe_tx = SafeTransaction {
        to,
        value,
        data,
        operation,
        safe_tx_gas,
        base_gas,
        gas_price,
        gas_token,
        refund_receiver,
        nonce: nonce_u256,
    };
    let recomputed = safe_tx_hash(evm_chain_id, req_safe, &safe_tx);
    let recomputed_bytes: [u8; 32] = recomputed.into();
    if recomputed_bytes != claimed_hash {
        return Err(err(
            error_codes::SAFE_TX_HASH_MISMATCH,
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "recomputed safeTxHash 0x{} != claimed 0x{}",
                alloy_primitives::hex::encode(recomputed_bytes),
                alloy_primitives::hex::encode(claimed_hash),
            ),
        ));
    }

    // 4. Replay-DB pre-flight.
    let outcome = state
        .replay
        .check_safe_tx(req.chain_id, req_safe, nonce_u64, recomputed_bytes)
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
            return Ok(Json(render_signature(evm_cfg.my_signer_address, arr)));
        }
        CheckOutcome::Conflict { .. } => {
            return Err(err(
                error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT,
                StatusCode::CONFLICT,
                "Safe-tx already signed for this (chain, safe, nonce) under a different payload"
                    .to_string(),
            ));
        }
        CheckOutcome::FirstTime => {}
    }

    // 5. HSM-sign the digest.
    let sig = state
        .hsm
        .sign_digest(evm_cfg.my_signer_address, recomputed)
        .await
        .map_err(|e| hsm_unavailable(&e))?;

    // 5a. Recover-verify (1.5 / H11). The signature the HSM returned MUST
    // recover to this daemon's configured signer over the recomputed
    // digest; otherwise an HSM key-mapping bug, a wrong-key signature, or
    // a corrupted signing response would be recorded and returned as a
    // valid owner signature. We only READ the signature here (no byte
    // reconstruction), so there is no signature-format risk; low-S
    // normalization (1.13) is deferred — see KNOWN_FINDINGS.
    let recovered = PrimitiveSignature::try_from(sig.as_slice())
        .map_err(|e| {
            err(
                error_codes::SIGNER_RECOVER_MISMATCH,
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("HSM signature did not parse as a 65-byte ECDSA signature: {e}"),
            )
        })?
        .recover_address_from_prehash(&recomputed)
        .map_err(|e| {
            err(
                error_codes::SIGNER_RECOVER_MISMATCH,
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("HSM signature did not recover to an address: {e}"),
            )
        })?;
    if recovered != evm_cfg.my_signer_address {
        return Err(err(
            error_codes::SIGNER_RECOVER_MISMATCH,
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "HSM signature recovered to {recovered:#x}, expected configured signer {:#x}",
                evm_cfg.my_signer_address
            ),
        ));
    }

    // 5b. Record + return.
    state
        .replay
        .record_safe_tx(
            req.chain_id,
            req_safe,
            nonce_u64,
            recomputed_bytes,
            sig.to_vec(),
            now_unix_secs(),
        )
        .await
        .map_err(|e| {
            err(
                error_codes::BAD_REQUEST,
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("replay record: {e}"),
            )
        })?;

    Ok(Json(render_signature(evm_cfg.my_signer_address, sig)))
}
