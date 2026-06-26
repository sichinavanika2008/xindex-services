//! CTD-1 custody-spend gates — HTTP-agnostic.
//!
//! The RIC/ACC verification + one-shot consumption that every custody
//! spend passes through before a signature is produced, decoupled from
//! any transport. The (transitional) signer-daemon maps [`GateRejection`]
//! onto its `axum` error body; the Fireblocks co-signer callback maps it
//! onto an APPROVE/REJECT decision. The kind-specific verification lives in
//! [`xindex_shared::intent`]; the one-shot replay arm in [`crate::replay`].

use alloy_primitives::{keccak256, Address, B256, U256};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::intent::{
    validate_acquire_cancel_proof, validate_intent_proof, IntentError, IntentPolicy,
    VerifiedCancel, VerifiedIntent,
};
use xindex_shared::signer_wire::{error_codes, AcquireCancelProof, IntentProof};

use crate::replay::{must_propagate_record_error, CheckOutcome, ReplayStore};

/// Transport-agnostic HTTP-status class of a gate rejection. Consumers map
/// it to their own response (daemon → `StatusCode`; callback → REJECT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionClass {
    /// Malformed/unparseable input (daemon HTTP 400).
    BadRequest,
    /// One-shot already consumed under a different cert/spend (HTTP 409).
    Conflict,
    /// Verified-but-rejected: bad proof, stale vault, bind mismatch (422).
    Unprocessable,
    /// Internal invariant violation (HTTP 500).
    Internal,
}

/// A custody-gate rejection: a stable wire `code`, an operator-facing
/// `message`, and the [`RejectionClass`] a transport maps to its response.
#[derive(Debug, Clone)]
pub struct GateRejection {
    /// Stable wire error code (`xindex_shared::signer_wire::error_codes`).
    pub code: &'static str,
    /// Human-readable detail for logs / the rejecting response.
    pub message: String,
    /// Transport-agnostic status class.
    pub class: RejectionClass,
}

impl GateRejection {
    pub(crate) fn bad(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), class: RejectionClass::BadRequest }
    }
    pub(crate) fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), class: RejectionClass::Conflict }
    }
    pub(crate) fn unprocessable(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), class: RejectionClass::Unprocessable }
    }
    pub(crate) fn internal(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), class: RejectionClass::Internal }
    }
}

/// The subset of daemon/callback config the gates need: the EIP-712 domain
/// inputs + the static Set-B verification policy. Borrows the policy so the
/// caller's owned config is not cloned per request.
#[derive(Debug, Clone, Copy)]
pub struct CustodyConfig<'a> {
    /// Ethereum chain id pinning the RIC/ACC EIP-712 domain.
    pub chain_id: u64,
    /// The `AttestationOracle` address pinning the EIP-712 domain.
    pub verifying_contract: Address,
    /// Static Set-B whitelist + quorum + recency window.
    pub intent_policy: &'a IntentPolicy,
}

/// The common custody-spend binding fields produced by EITHER certificate
/// gate (a RIC redeem or an ACC mint-cancel swap-back). The BTC output bind
/// enforces these without caring which certificate kind authorized it.
#[derive(Debug, Clone)]
pub struct CertifiedSpend {
    /// Certified spend amount in the chain's native smallest units.
    pub amount: U256,
    /// Certified keccak of the immediate spend target (Asgard inbound).
    pub immediate_target_hash: B256,
    /// Certified keccak of the exact `THORChain` memo bytes.
    pub memo_hash: B256,
    /// Wire error code for an output-bind mismatch under THIS certificate
    /// kind (`intent_mismatch` / `acquire_cancel_mismatch`).
    pub mismatch_code: &'static str,
}

/// Map an ACC validator [`IntentError`] onto the ACC-specific wire codes
/// (the validator reports the RIC codes by default).
fn acc_error_code(e: &IntentError) -> &'static str {
    match e {
        IntentError::ProofInvalid(_) => error_codes::ACQUIRE_CANCEL_PROOF_INVALID,
        IntentError::VaultStale(_) => error_codes::ACQUIRE_CANCEL_VAULT_STALE,
    }
}

/// CTD-1 (`DL-CTD-2`): the RIC custody-spend gate. Stateless k-of-n RIC
/// verification on the pinned domain, family-agnostic asset/decimals binds
/// (RA-4), then a one-shot CONSUME keyed `(chain, redemptionId, legIndex)`
/// recorded BEFORE any signature — the row IS the authorization. The caller
/// binds the certified destination/amount/memo to the family tx shape and
/// passes `spend_identity` (the family value bound into the signed tx) so a
/// single RIC cannot be re-driven into N spends.
///
/// # Errors
/// [`GateRejection`] on a missing/invalid proof, asset/decimals mismatch, or
/// a one-shot conflict.
pub async fn gate_ric_intent<S: ReplayStore>(
    config: CustodyConfig<'_>,
    replay: &S,
    chain: ChainId,
    proof: Option<&IntentProof>,
    spend_identity: &[u8],
    now_unix: i64,
) -> Result<(VerifiedIntent, B256), GateRejection> {
    let proof = proof.ok_or_else(|| {
        GateRejection::unprocessable(
            error_codes::INTENT_PROOF_REQUIRED,
            "custody-spend request carries no IntentProof (k-of-n RIC) — required",
        )
    })?;
    let now = u64::try_from(now_unix).unwrap_or(0);
    let (cert, digest) = validate_intent_proof(
        proof,
        config.chain_id,
        config.verifying_contract,
        config.intent_policy,
        now,
    )
    .map_err(|e| GateRejection::unprocessable(e.error_code(), e.to_string()))?;
    if cert.asset_id != chain.asset_id_hash() {
        return Err(GateRejection::unprocessable(
            error_codes::INTENT_MISMATCH,
            format!(
                "certified asset id is not chain {chain:?}'s native asset — \
                 RIC v1 certifies native-asset legs only"
            ),
        ));
    }
    if cert.amount_decimals != chain.decimals() {
        return Err(GateRejection::unprocessable(
            error_codes::INTENT_MISMATCH,
            format!(
                "certified amount_decimals {} != chain {chain:?} native decimals {} (RA-4)",
                cert.amount_decimals,
                chain.decimals()
            ),
        ));
    }
    consume_ric_one_shot(replay, chain, &cert, digest, spend_identity, now_unix).await?;
    Ok((cert, digest))
}

/// RA-1 / RUST-003: consume the `(chain, redemptionId, legIndex)` one-shot,
/// recorded BEFORE any signature. The one-shot's `signature` BLOB stores the
/// FIRST-consumed `spend_identity`; a same-cert retry must re-present the
/// same identity (an HSM-failure retry / another input of the same BTC tx),
/// while a re-drive into a different spend is a 409.
async fn consume_ric_one_shot<S: ReplayStore>(
    replay: &S,
    chain: ChainId,
    cert: &VerifiedIntent,
    digest: B256,
    spend_identity: &[u8],
    now_unix: i64,
) -> Result<(), GateRejection> {
    const REDRIVEN_CERT: &str =
        "custody spend for this (chain, redemption, leg) was already authorized under a \
         different certificate";
    const REDRIVEN_SPEND: &str =
        "this certificate already authorized a DIFFERENT custody spend for the leg \
         (same RIC, advanced sequence/nonce or a different tx) — refusing the re-drive";
    let outcome = replay
        .check_ric_intent(chain, cert.redemption_id, cert.leg_index, digest.0)
        .await
        .map_err(|e| GateRejection::bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?;
    match outcome {
        CheckOutcome::Idempotent(rec) => {
            return if rec.signature.as_slice() == spend_identity {
                Ok(())
            } else {
                Err(GateRejection::conflict(error_codes::INTENT_ALREADY_SIGNED, REDRIVEN_SPEND))
            };
        }
        CheckOutcome::Conflict { .. } => {
            return Err(GateRejection::conflict(error_codes::INTENT_ALREADY_SIGNED, REDRIVEN_CERT));
        }
        CheckOutcome::FirstTime => {}
    }
    if let Err(e) = replay
        .record_ric_intent(
            chain,
            cert.redemption_id,
            cert.leg_index,
            digest.0,
            spend_identity.to_vec(),
            now_unix,
        )
        .await
    {
        if must_propagate_record_error(&e) {
            return Err(GateRejection::bad(error_codes::BAD_REQUEST, format!("replay record: {e}")));
        }
        return match replay
            .check_ric_intent(chain, cert.redemption_id, cert.leg_index, digest.0)
            .await
            .map_err(|e| GateRejection::bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?
        {
            CheckOutcome::Idempotent(rec) if rec.signature.as_slice() == spend_identity => Ok(()),
            CheckOutcome::Idempotent(_) => {
                Err(GateRejection::conflict(error_codes::INTENT_ALREADY_SIGNED, REDRIVEN_SPEND))
            }
            CheckOutcome::Conflict { .. } => {
                Err(GateRejection::conflict(error_codes::INTENT_ALREADY_SIGNED, REDRIVEN_CERT))
            }
            CheckOutcome::FirstTime => Err(GateRejection::internal(
                error_codes::BAD_REQUEST,
                "ric one-shot record race left no row",
            )),
        };
    }
    Ok(())
}

/// CTD-1 Slice C — the Acquire-Cancel custody-spend gate (mint-cancel
/// sibling of [`gate_ric_intent`]): stateless k-of-n ACC verification, the
/// same asset/decimals binds, and a one-shot CONSUME keyed `(chain,
/// cancel_id)` recorded before any signature.
///
/// # Errors
/// [`GateRejection`] on an invalid proof, asset/decimals mismatch, or a
/// one-shot conflict.
pub async fn gate_acquire_cancel_intent<S: ReplayStore>(
    config: CustodyConfig<'_>,
    replay: &S,
    chain: ChainId,
    proof: &AcquireCancelProof,
    spend_identity: &[u8],
    now_unix: i64,
) -> Result<(VerifiedCancel, B256), GateRejection> {
    let now = u64::try_from(now_unix).unwrap_or(0);
    let (cert, digest) = validate_acquire_cancel_proof(
        proof,
        config.chain_id,
        config.verifying_contract,
        config.intent_policy,
        now,
    )
    .map_err(|e| GateRejection::unprocessable(acc_error_code(&e), e.to_string()))?;
    if cert.asset_id != chain.asset_id_hash() {
        return Err(GateRejection::unprocessable(
            error_codes::ACQUIRE_CANCEL_MISMATCH,
            format!(
                "certified asset id is not chain {chain:?}'s native asset — \
                 ACC v1 certifies native-asset swap-backs only"
            ),
        ));
    }
    if cert.amount_decimals != chain.decimals() {
        return Err(GateRejection::unprocessable(
            error_codes::ACQUIRE_CANCEL_MISMATCH,
            format!(
                "certified amount_decimals {} != chain {chain:?} native decimals {} (RA-4)",
                cert.amount_decimals,
                chain.decimals()
            ),
        ));
    }
    consume_ac_one_shot(replay, chain, &cert, digest, spend_identity, now_unix).await?;
    Ok((cert, digest))
}

/// Slice C mirror of [`consume_ric_one_shot`] keyed `(chain, cancel_id)`.
async fn consume_ac_one_shot<S: ReplayStore>(
    replay: &S,
    chain: ChainId,
    cert: &VerifiedCancel,
    digest: B256,
    spend_identity: &[u8],
    now_unix: i64,
) -> Result<(), GateRejection> {
    const REDRIVEN_CERT: &str =
        "swap-back for this (chain, cancel_id) was already authorized under a \
         different certificate";
    const REDRIVEN_SPEND: &str =
        "this acquire-cancel certificate already authorized a DIFFERENT swap-back spend \
         (same ACC, different tx) — refusing the re-drive";
    let outcome = replay
        .check_ac_intent(chain, cert.cancel_id, digest.0)
        .await
        .map_err(|e| GateRejection::bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?;
    match outcome {
        CheckOutcome::Idempotent(rec) => {
            return if rec.signature.as_slice() == spend_identity {
                Ok(())
            } else {
                Err(GateRejection::conflict(error_codes::ACQUIRE_CANCEL_ALREADY_SIGNED, REDRIVEN_SPEND))
            };
        }
        CheckOutcome::Conflict { .. } => {
            return Err(GateRejection::conflict(
                error_codes::ACQUIRE_CANCEL_ALREADY_SIGNED,
                REDRIVEN_CERT,
            ));
        }
        CheckOutcome::FirstTime => {}
    }
    if let Err(e) = replay
        .record_ac_intent(chain, cert.cancel_id, digest.0, spend_identity.to_vec(), now_unix)
        .await
    {
        if must_propagate_record_error(&e) {
            return Err(GateRejection::bad(error_codes::BAD_REQUEST, format!("replay record: {e}")));
        }
        return match replay
            .check_ac_intent(chain, cert.cancel_id, digest.0)
            .await
            .map_err(|e| GateRejection::bad(error_codes::BAD_REQUEST, format!("replay db: {e}")))?
        {
            CheckOutcome::Idempotent(rec) if rec.signature.as_slice() == spend_identity => Ok(()),
            CheckOutcome::Idempotent(_) => Err(GateRejection::conflict(
                error_codes::ACQUIRE_CANCEL_ALREADY_SIGNED,
                REDRIVEN_SPEND,
            )),
            CheckOutcome::Conflict { .. } => Err(GateRejection::conflict(
                error_codes::ACQUIRE_CANCEL_ALREADY_SIGNED,
                REDRIVEN_CERT,
            )),
            CheckOutcome::FirstTime => Err(GateRejection::internal(
                error_codes::BAD_REQUEST,
                "ac one-shot record race left no row",
            )),
        };
    }
    Ok(())
}

/// CTD-1 Slice C — the PSBT spend-certificate dispatcher: a RIC (redeem)
/// XOR an ACC (mint-cancel swap-back). BOTH present → 422 ambiguous; RIC-only
/// (or neither) → [`gate_ric_intent`]; ACC-only → [`gate_acquire_cancel_intent`].
/// Returns the kind-agnostic [`CertifiedSpend`] the BTC output bind enforces.
///
/// # Errors
/// [`GateRejection`] from the dispatched gate, or `intent_proof_ambiguous`.
pub async fn gate_spend_certificate<S: ReplayStore>(
    config: CustodyConfig<'_>,
    replay: &S,
    chain: ChainId,
    ric: Option<&IntentProof>,
    acc: Option<&AcquireCancelProof>,
    spend_identity: &[u8],
    now_unix: i64,
) -> Result<CertifiedSpend, GateRejection> {
    match (ric, acc) {
        (Some(_), Some(_)) => Err(GateRejection::unprocessable(
            error_codes::INTENT_PROOF_AMBIGUOUS,
            "request carries BOTH a RIC and an Acquire-Cancel certificate — exactly one \
             certificate kind must authorize a custody spend",
        )),
        (None, Some(proof)) => {
            let (cert, _digest) =
                gate_acquire_cancel_intent(config, replay, chain, proof, spend_identity, now_unix)
                    .await?;
            Ok(CertifiedSpend {
                amount: cert.amount,
                immediate_target_hash: cert.immediate_target_hash,
                memo_hash: cert.memo_hash,
                mismatch_code: error_codes::ACQUIRE_CANCEL_MISMATCH,
            })
        }
        (ric_only, None) => {
            let (cert, _digest) =
                gate_ric_intent(config, replay, chain, ric_only, spend_identity, now_unix).await?;
            Ok(CertifiedSpend {
                amount: cert.amount,
                immediate_target_hash: cert.immediate_target_hash,
                memo_hash: cert.memo_hash,
                mismatch_code: error_codes::INTENT_MISMATCH,
            })
        }
    }
}

/// CTD-1: bind an account-model send (Cosmos / XRP / TRON) to the certified
/// intent — destination keccak == certified Asgard target, decimal amount ==
/// certified amount exactly, memo bytes hash to the certified memo.
///
/// # Errors
/// [`GateRejection`] on any destination/amount/memo mismatch.
pub fn bind_account_send_to_cert(
    to_address: &str,
    amount_dec: &str,
    memo: &str,
    cert: &VerifiedIntent,
) -> Result<(), GateRejection> {
    if keccak256(to_address.as_bytes()) != cert.immediate_target_hash {
        return Err(GateRejection::unprocessable(
            error_codes::INTENT_MISMATCH,
            format!("destination {to_address} does not hash to the certified Asgard target"),
        ));
    }
    let amount = U256::from_str_radix(amount_dec, 10).map_err(|e| {
        GateRejection::unprocessable(error_codes::INTENT_MISMATCH, format!("amount: bad decimal: {e}"))
    })?;
    if amount != cert.amount {
        return Err(GateRejection::unprocessable(
            error_codes::INTENT_MISMATCH,
            format!("amount {amount} != certified amount {}", cert.amount),
        ));
    }
    if keccak256(memo.as_bytes()) != cert.memo_hash {
        return Err(GateRejection::unprocessable(
            error_codes::INTENT_MISMATCH,
            "memo does not hash to the certified memo".to_string(),
        ));
    }
    Ok(())
}
