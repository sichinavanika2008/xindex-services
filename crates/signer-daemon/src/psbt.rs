//! PSBT-input signing endpoint (PART 5 / DL-M5-3).
//!
//! Decodes a base64 PSBT, locates the requested input, validates the
//! input's witness script matches the daemon's configured multisig
//! descriptor (refuses signing for any other script — `wrong_descriptor`),
//! validates `vin[0]` is itself a multisig UTXO (the Part-3
//! refund-address invariant — `vin0_not_multisig`), computes the
//! BIP-143 P2WSH sighash, consults the replay/slashing DB on the
//! `(input_txid, input_vout)` tuple, asks the HSM frontend to sign
//! the 32-byte sighash raw, and returns a Bitcoin-encoded partial
//! signature (DER + `SIGHASH_ALL` byte) + the signer pubkey.
//!
//! The replay-DB `payload_hash` is `keccak256(input_txid ‖
//! input_vout_le_u32 ‖ sighash)` so distinct *consuming* transactions
//! (different sighashes) sharing the same outpoint correctly register
//! as different payloads and the second is a 409 `Conflict`.

use std::sync::Arc;

use alloy_primitives::Address;
use axum::{extract::State, http::StatusCode, response::Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bitcoin::hashes::Hash;
use bitcoin::{
    ecdsa::Signature as BtcEcdsaSig,
    psbt::Psbt,
    secp256k1::{self, Message},
    sighash::{EcdsaSighashType, SighashCache},
    Network,
};
use xindex_multisig::MultisigDescriptor;
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::{error_codes, ErrorBody, PsbtInputSignRequest, PsbtSignResponse};

use crate::replay::{CheckOutcome, ReplayStore};
use crate::server::{gate_spend_certificate, CertifiedSpend, DaemonState};
use crate::web3signer::HsmDigestSigner;

/// Per-chain UTXO signing role configuration. One entry per UTXO chain
/// this daemon is configured for. The daemon refuses any PSBT input
/// whose witness script doesn't match `descriptor`'s derived
/// `witness_script`, and refuses any PSBT whose `vin[0]` is not itself
/// spending a multisig UTXO under the same descriptor (Part-3 refund
/// invariant).
#[derive(Debug)]
pub struct UtxoSignerConfig {
    /// Which UTXO chain this config serves. Matches the
    /// `PsbtInputSignRequest::chain_id` field — the daemon's
    /// `DaemonState.utxo: HashMap<ChainId, Arc<UtxoSignerConfig>>`
    /// dispatches per request.
    pub chain_id: ChainId,
    /// Bitcoin-crate network used only for the configured address
    /// (mainnet / signet / testnet / regtest for BTC; placeholder for
    /// non-BTC chains until the per-chain codec layer wires through).
    pub network: Network,
    /// The 3-of-5 multisig descriptor this daemon's key sits in for
    /// this chain. Distinct per chain because each chain has its own
    /// 3-of-5 ceremony (no cross-chain key sharing per DL-P3-7).
    pub descriptor: MultisigDescriptor,
    /// This daemon's compressed secp256k1 pubkey for this chain (Set
    /// A per `docs/runbooks/key-ceremony.md`). Must appear in
    /// `descriptor`.
    pub my_pubkey: bitcoin::PublicKey,
    /// Address used to identify this chain's key inside the HSM
    /// frontend (same secp256k1 curve as Ethereum; HSM frontends
    /// commonly address keys by ETH-style 20-byte hash regardless of
    /// usage).
    pub hsm_address: Address,
}

/// Helper: produce `(StatusCode, Json<ErrorBody>)` shorthands.
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

/// Daemon-side dependency: the BTC config + the HSM frontend +
/// the replay store. Passed via `DaemonState`'s additional bitcoin
/// role payload. Kept generic to preserve static dispatch.
#[derive(Debug)]
pub struct UtxoSignerState<S: ReplayStore + 'static, H: HsmDigestSigner + 'static> {
    pub config: Arc<UtxoSignerConfig>,
    pub replay: Arc<S>,
    pub hsm: Arc<H>,
}

impl<S: ReplayStore + 'static, H: HsmDigestSigner + 'static> Clone for UtxoSignerState<S, H> {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            replay: Arc::clone(&self.replay),
            hsm: Arc::clone(&self.hsm),
        }
    }
}

/// Axum handler. Looks up the per-chain UTXO role from `DaemonState`
/// by `req.chain_id`; returns 404 `endpoint_disabled` if this daemon
/// has no config for the requested chain (the route is always
/// registered when at least one UTXO chain is configured — per-chain
/// dispatch happens inside the handler).
///
/// # Errors
/// Returns an `(StatusCode, Json<ErrorBody>)` tuple with one of the
/// stable `error_codes` constants from [`xindex_shared::signer_wire`]:
/// `invalid_psbt` (400), `wrong_descriptor` / `vin0_not_multisig`
/// (422), `conflict_already_signed_different` (409), `hsm_unavailable`
/// (503), `endpoint_disabled` (404).
#[expect(
    clippy::too_many_lines,
    reason = "single sequential validate-then-sign pipeline; splitting fragments the audit-relevant ordering of checks"
)]
pub async fn handle_psbt_input<S, H>(
    State(state): State<DaemonState<S, H>>,
    Json(req): Json<PsbtInputSignRequest>,
) -> Result<Json<PsbtSignResponse>, (StatusCode, Json<ErrorBody>)>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    let btc = state.utxo.get(&req.chain_id).cloned().ok_or_else(|| {
        err(
            error_codes::ENDPOINT_DISABLED,
            StatusCode::NOT_FOUND,
            format!(
                "UTXO role for chain {:?} not enabled on this daemon",
                req.chain_id
            ),
        )
    })?;

    // 0. Decode the PSBT up front: its unsigned-tx txid is the RUST-003
    //    one-shot spend identity passed to the certificate gate below. A
    //    re-drive of the same certificate into a SECOND, distinct tx has a
    //    different txid → a 409; a multi-input redemption that signs further
    //    inputs of the SAME tx shares the txid and proceeds (the output-set
    //    bind + per-input replay key handle those).
    let raw = B64.decode(req.psbt_base64.as_bytes()).map_err(|e| {
        err(
            error_codes::INVALID_PSBT,
            StatusCode::BAD_REQUEST,
            format!("base64: {e}"),
        )
    })?;
    let psbt = Psbt::deserialize(&raw).map_err(|e| {
        err(
            error_codes::INVALID_PSBT,
            StatusCode::BAD_REQUEST,
            format!("psbt deserialize: {e}"),
        )
    })?;
    let unsigned_txid = psbt.unsigned_tx.compute_txid().to_byte_array();

    // 1. CTD-1 (`DL-CTD-2`): mandatory k-of-n certificate gate — a RIC
    //    (redeem) XOR an ACC (mint-cancel swap-back, Slice C). Both →
    //    422 ambiguous; neither → 422 required. Either path verifies
    //    statelessly, binds asset/decimals to this chain, and consumes
    //    its one-shot (RIC: (chain, redemption, leg); ACC: (chain,
    //    cancel_id)) BEFORE the HSM can ever be reached. The output-set
    //    bind happens at step 4c.
    let spend = gate_spend_certificate(
        &state.config,
        state.replay.as_ref(),
        req.chain_id,
        req.intent_proof.as_ref(),
        req.acquire_cancel_proof.as_ref(),
        &unsigned_txid,
    )
    .await?;

    let idx = req.input_index as usize;
    if idx >= psbt.inputs.len() {
        return Err(err(
            error_codes::INVALID_PSBT,
            StatusCode::BAD_REQUEST,
            format!("input_index {idx} ≥ inputs.len {}", psbt.inputs.len()),
        ));
    }

    // 2. Validate this input's witness_script matches our descriptor.
    let expected_ws = derive_witness_script(&btc.descriptor).map_err(|e| {
        err(
            error_codes::WRONG_DESCRIPTOR,
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("descriptor witness_script: {e}"),
        )
    })?;
    let input = &psbt.inputs[idx];
    let input_ws = input.witness_script.as_ref().ok_or_else(|| {
        err(
            error_codes::INVALID_PSBT,
            StatusCode::BAD_REQUEST,
            "input missing witness_script",
        )
    })?;
    if input_ws.as_bytes() != expected_ws.as_bytes() {
        return Err(err(
            error_codes::WRONG_DESCRIPTOR,
            StatusCode::UNPROCESSABLE_ENTITY,
            "input witness_script does not match daemon descriptor",
        ));
    }

    // 3. Validate vin[0] is itself a multisig UTXO (Part-3 invariant —
    //    THORChain resolves refund-sender to vin[0].prevout's address).
    let vin0 = &psbt.inputs[0];
    let vin0_ws = vin0.witness_script.as_ref().ok_or_else(|| {
        err(
            error_codes::VIN0_NOT_MULTISIG,
            StatusCode::UNPROCESSABLE_ENTITY,
            "vin[0] missing witness_script",
        )
    })?;
    if vin0_ws.as_bytes() != expected_ws.as_bytes() {
        return Err(err(
            error_codes::VIN0_NOT_MULTISIG,
            StatusCode::UNPROCESSABLE_ENTITY,
            "vin[0] not spending a multisig UTXO",
        ));
    }

    // 4. witness_utxo must be present for SegWit sighash.
    let witness_utxo = input.witness_utxo.as_ref().ok_or_else(|| {
        err(
            error_codes::INVALID_PSBT,
            StatusCode::BAD_REQUEST,
            "input missing witness_utxo",
        )
    })?;

    // 4b. (audit I3) Bind the prevout scriptPubKey to the descriptor.
    //     BIP-143 commits witness_utxo.value into the sighash but NOT
    //     that the prevout scriptPubKey is our descriptor's P2WSH program.
    //     A forged witness_utxo.script_pubkey would otherwise pass the
    //     witness_script check yet attest a UTXO we don't actually own.
    let expected_spk = bitcoin::ScriptBuf::new_p2wsh(&expected_ws.wscript_hash());
    if witness_utxo.script_pubkey != expected_spk {
        return Err(err(
            error_codes::WRONG_DESCRIPTOR,
            StatusCode::UNPROCESSABLE_ENTITY,
            "input witness_utxo.script_pubkey is not the descriptor P2WSH program",
        ));
    }

    // 4c. CTD-1: bind the PSBT's ENTIRE output set to the certified
    //     spend (exact-set OP_RETURN discipline, RA-3) — whichever
    //     certificate kind the gate verified.
    bind_outputs_to_cert(&psbt, &expected_spk, &spend)?;

    // 5. Compute the BIP-143 P2WSH sighash.
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = cache
        .p2wsh_signature_hash(idx, input_ws, witness_utxo.value, EcdsaSighashType::All)
        .map_err(|e| {
            err(
                error_codes::INVALID_PSBT,
                StatusCode::BAD_REQUEST,
                format!("sighash: {e}"),
            )
        })?;
    let sighash_bytes: [u8; 32] = sighash.to_byte_array();

    // 6. Replay-DB key = the outpoint this input is spending.
    let txin = psbt.unsigned_tx.input.get(idx).ok_or_else(|| {
        err(
            error_codes::INVALID_PSBT,
            StatusCode::BAD_REQUEST,
            "missing tx input",
        )
    })?;
    let prev_txid: [u8; 32] = *txin.previous_output.txid.as_ref();
    let prev_vout: u32 = txin.previous_output.vout;
    let payload_hash = hash_psbt_payload(&prev_txid, prev_vout, &sighash_bytes);

    // 7. Replay check (keyed by chain — AUD-PSBT-REPLAY-CHAINID).
    let outcome = state
        .replay
        .check_psbt_input(req.chain_id, prev_txid, prev_vout, payload_hash)
        .await
        .map_err(|e| {
            err(
                error_codes::BAD_REQUEST,
                StatusCode::BAD_REQUEST,
                format!("replay db: {e}"),
            )
        })?;
    match outcome {
        CheckOutcome::Idempotent(rec) => {
            return Ok(Json(decode_stored_response(
                rec.signature.as_slice(),
                &btc.my_pubkey,
            )));
        }
        CheckOutcome::Conflict { .. } => {
            return Err(err(
                error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT,
                StatusCode::CONFLICT,
                "outpoint already signed for a different sighash (different consuming tx)",
            ));
        }
        CheckOutcome::FirstTime => {}
    }

    // 7b. (audit M2) Output veto: when the caller pins expected outputs,
    //     refuse unless the PSBT pays them. Enforce-if-present, before
    //     the HSM is ever touched.
    veto_outputs(&psbt, &req)?;

    // 7c. (audit M2b, partial floor) Two daemon-LOCAL output constraints
    //     that need no trusted intent beyond our own descriptor + the
    //     per-chain fee ceiling: change can only return to self, and the
    //     implied miner fee is bounded. Closes the change-redirection and
    //     fee-burning legs of M2b. Does NOT close the coordinator-supplied
    //     payout destination/amount/memo (the fleet-wide destination-trust
    //     gap — see KNOWN_FINDINGS), which is the Branch-B follow-on.
    enforce_change_and_fee(&psbt, &req, &expected_spk)?;

    // 8. Sign the 32-byte sighash via the HSM frontend (raw secp256k1
    //    over the digest, no further hashing).
    let raw_sig = state
        .hsm
        .sign_digest(btc.hsm_address, sighash_bytes.into())
        .await
        .map_err(|e| {
            err(
                error_codes::HSM_UNAVAILABLE,
                StatusCode::SERVICE_UNAVAILABLE,
                e.to_string(),
            )
        })?;
    // r ‖ s ‖ v → take r ‖ s as compact (64 bytes); discard v (Bitcoin
    // ECDSA uses no recovery byte).
    let mut compact = [0u8; 64];
    compact.copy_from_slice(&raw_sig[..64]);
    let secp_sig = secp256k1::ecdsa::Signature::from_compact(&compact).map_err(|e| {
        err(
            error_codes::HSM_UNAVAILABLE,
            StatusCode::SERVICE_UNAVAILABLE,
            format!("HSM returned non-ECDSA: {e}"),
        )
    })?;
    // Belt-and-suspenders: verify HSM signature against our pubkey + sighash.
    let msg = Message::from_digest(sighash_bytes);
    let secp = btc.descriptor.secp();
    if secp
        .verify_ecdsa(&msg, &secp_sig, &btc.my_pubkey.inner)
        .is_err()
    {
        return Err(err(
            error_codes::HSM_UNAVAILABLE,
            StatusCode::SERVICE_UNAVAILABLE,
            "HSM signature did not verify against configured pubkey",
        ));
    }
    let btc_sig = BtcEcdsaSig {
        signature: secp_sig,
        sighash_type: EcdsaSighashType::All,
    };
    let sig_bytes = btc_sig.to_vec(); // DER + sighash-flag byte
    let response = PsbtSignResponse {
        pubkey: format!(
            "0x{}",
            alloy_primitives::hex::encode(btc.my_pubkey.to_bytes())
        ),
        signature: alloy_primitives::hex::encode(&sig_bytes),
    };
    // 9. Record (sig_bytes is what we hand back; storing it makes
    //    idempotent re-queries observable).
    if let Err(e) = state
        .replay
        .record_psbt_input(
            req.chain_id,
            prev_txid,
            prev_vout,
            payload_hash,
            sig_bytes,
            now_unix_secs(),
        )
        .await
    {
        if crate::replay::must_propagate_record_error(&e) {
            return Err(err(
                error_codes::BAD_REQUEST,
                StatusCode::BAD_REQUEST,
                format!("replay record: {e}"),
            ));
        }
        // L10: lost the write race; the winner already recorded. Re-read
        // and return its cached signature idempotently (deterministic
        // ECDSA → identical bytes anyway).
        return match state
            .replay
            .check_psbt_input(req.chain_id, prev_txid, prev_vout, payload_hash)
            .await
            .map_err(|e| {
                err(
                    error_codes::BAD_REQUEST,
                    StatusCode::BAD_REQUEST,
                    format!("replay db: {e}"),
                )
            })? {
            CheckOutcome::Idempotent(rec) => Ok(Json(decode_stored_response(
                rec.signature.as_slice(),
                &btc.my_pubkey,
            ))),
            CheckOutcome::Conflict { .. } => Err(err(
                error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT,
                StatusCode::CONFLICT,
                "outpoint already signed for a different sighash (different consuming tx)",
            )),
            CheckOutcome::FirstTime => Err(err(
                error_codes::BAD_REQUEST,
                StatusCode::INTERNAL_SERVER_ERROR,
                "record race left no row",
            )),
        };
    }
    Ok(Json(response))
}

/// Derive the descriptor's `witness_script` (the script all our P2WSH
/// inputs spend from). Pure — depends only on the configured pubkeys
/// + threshold, no derivation index.
fn derive_witness_script(descriptor: &MultisigDescriptor) -> Result<bitcoin::ScriptBuf, String> {
    descriptor
        .descriptor
        .at_derivation_index(0)
        .map_err(|e| e.to_string())?
        .explicit_script()
        .map_err(|e| e.to_string())
}

/// CTD-1 (`DL-CTD-2` / RA-3): bind the PSBT's ordered output set to the
/// certified spend — produced by EITHER certificate gate (RIC redeem /
/// ACC mint-cancel swap-back; the binding discipline is identical).
/// Exact-set and exact-order:
///
/// - VOUT0 is the one payout output, identified by
///   `keccak256(scriptPubKey) == spend.immediate_target_hash` (the
///   Asgard inbound the operators independently resolved), paying
///   exactly `spend.amount` sats;
/// - optional VOUT1 is one non-zero change output back to the descriptor
///   P2WSH (the VIN0 custody script);
/// - the final output is exactly one zero-value `OP_RETURN`, whose full payload
///   hashes to `spend.memo_hash` — `THORChain` concatenates ALL
///   `OP_RETURN`s into the memo, so a second one is memo injection
///   (RA-3) regardless of content.
///
/// Mismatches report `spend.mismatch_code` (`intent_mismatch` /
/// `acquire_cancel_mismatch`) so the coordinator can tell which
/// certificate kind the spend violated.
fn bind_outputs_to_cert(
    psbt: &Psbt,
    descriptor_spk: &bitcoin::ScriptBuf,
    spend: &CertifiedSpend,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let shared_spend = xindex_custody_core::gates::CertifiedSpend {
        amount: spend.amount,
        immediate_target_hash: spend.immediate_target_hash,
        memo_hash: spend.memo_hash,
        mismatch_code: spend.mismatch_code,
    };
    xindex_custody_core::btc_bind::bind_outputs_to_cert(psbt, descriptor_spk, &shared_spend)
        .map_err(|rejection| {
            err(
                rejection.code,
                StatusCode::UNPROCESSABLE_ENTITY,
                rejection.message,
            )
        })
}

/// (audit M2) Enforce the optional output constraints carried in the
/// request. Each `expected_*` field is enforce-if-present: a `None`
/// imposes no constraint, a `Some` must be satisfied by some output of
/// `psbt.unsigned_tx` or the daemon refuses with `PSBT_OUTPUTS_MISMATCH`.
///
/// - `expected_destination_spk`: at least one output whose
///   `script_pubkey` equals the hex-decoded value, and (if
///   `expected_amount_sats` is `Some`) that output's `value` in sats
///   equals it.
/// - `expected_memo`: at least one `OP_RETURN` output that pushes data
///   byte-equal to the hex-decoded value.
fn veto_outputs(
    psbt: &Psbt,
    req: &PsbtInputSignRequest,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if let Some(spk_hex) = req.expected_destination_spk.as_deref() {
        let want_spk = decode_hex_field("expected_destination_spk", spk_hex)?;
        let matched = psbt.unsigned_tx.output.iter().any(|o| {
            o.script_pubkey.as_bytes() == want_spk.as_slice()
                && req
                    .expected_amount_sats
                    .is_none_or(|sats| o.value.to_sat() == sats)
        });
        if !matched {
            return Err(err(
                error_codes::PSBT_OUTPUTS_MISMATCH,
                StatusCode::UNPROCESSABLE_ENTITY,
                "no output matches expected destination scriptPubKey (and amount)",
            ));
        }
    }
    if let Some(memo_hex) = req.expected_memo.as_deref() {
        let want_memo = decode_hex_field("expected_memo", memo_hex)?;
        let matched = psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| op_return_data_eq(&o.script_pubkey, &want_memo));
        if !matched {
            return Err(err(
                error_codes::PSBT_OUTPUTS_MISMATCH,
                StatusCode::UNPROCESSABLE_ENTITY,
                "no OP_RETURN output matches expected memo",
            ));
        }
    }
    Ok(())
}

/// (audit M2b, partial floor) Enforce two output constraints the daemon
/// can decide entirely from its OWN descriptor + per-chain config, with no
/// trust in the coordinator beyond what it already supplies:
///
/// 1. **Change-to-self** (only when the payout is pinned via
///    `expected_destination_spk`): every output must be one of
///    {the pinned payout `scriptPubKey`, a **zero-value** `OP_RETURN`
///    (the memo), the daemon's own descriptor P2WSH program}. A malicious
///    coordinator therefore cannot route the residue to an attacker
///    address, nor burn value through a funded `OP_RETURN` (whose value
///    the fee check below would not see as fee).
/// 2. **Fee cap**: the implied miner fee `Σ inputs − Σ outputs` must be
///    ≤ [`ChainId::max_redeem_fee_base_units`]. Stops the "omit change → residue
///    burned as fee" grief. Every input must carry a `witness_utxo` or the
///    fee cannot be bounded (the single-input redeem path always does).
///
/// This is NOT a never-blind-sign guarantee: the pinned payout
/// destination/amount/memo remain coordinator-supplied, and the
/// change-to-self check is skipped when the payout is absent. The
/// fleet-wide destination-trust gap (each daemon must derive the canonical
/// intent from the on-chain `RedeemDispatched` event) is tracked
/// separately and is the Branch-B fix.
fn enforce_change_and_fee(
    psbt: &Psbt,
    req: &PsbtInputSignRequest,
    descriptor_spk: &bitcoin::ScriptBuf,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if let Some(spk_hex) = req.expected_destination_spk.as_deref() {
        let payout_spk = decode_hex_field("expected_destination_spk", spk_hex)?;
        for o in &psbt.unsigned_tx.output {
            let is_payout = o.script_pubkey.as_bytes() == payout_spk.as_slice();
            let is_memo = o.script_pubkey.is_op_return() && o.value.to_sat() == 0;
            let is_change_to_self = o.script_pubkey.as_bytes() == descriptor_spk.as_bytes();
            if !(is_payout || is_memo || is_change_to_self) {
                return Err(err(
                    error_codes::PSBT_UNEXPECTED_OUTPUT,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "output is neither the pinned payout, a zero-value OP_RETURN memo, nor change-to-self",
                ));
            }
        }
    }

    let mut total_in: u64 = 0;
    for input in &psbt.inputs {
        let wu = input.witness_utxo.as_ref().ok_or_else(|| {
            err(
                error_codes::PSBT_FEE_EXCEEDS_CAP,
                StatusCode::UNPROCESSABLE_ENTITY,
                "input missing witness_utxo; cannot bound fee",
            )
        })?;
        // AUD-PSBT-FEECAP-MULTIINPUT: every input must spend our OWN descriptor
        // P2WSH. Step 4b binds only the SIGNED input's prevout; without this a
        // coordinator-forged `witness_utxo.value` on a NON-signed input would
        // inflate the apparent input sum and weaken the `Σin − Σout ≤ cap`
        // bound. The redeem coin-selection only ever draws our own multisig
        // UTXOs, so requiring it is exact — and it strengthens the Part-3
        // vin-is-multisig invariant from vin[0] to ALL inputs.
        if wu.script_pubkey != *descriptor_spk {
            return Err(err(
                error_codes::WRONG_DESCRIPTOR,
                StatusCode::UNPROCESSABLE_ENTITY,
                "a tx input does not spend the daemon descriptor P2WSH program",
            ));
        }
        total_in = total_in.saturating_add(wu.value.to_sat());
    }
    let total_out = psbt
        .unsigned_tx
        .output
        .iter()
        .fold(0u64, |acc, o| acc.saturating_add(o.value.to_sat()));
    let fee = total_in.checked_sub(total_out).ok_or_else(|| {
        err(
            error_codes::PSBT_FEE_EXCEEDS_CAP,
            StatusCode::UNPROCESSABLE_ENTITY,
            "outputs exceed inputs (negative fee)",
        )
    })?;
    if fee > req.chain_id.max_redeem_fee_base_units() {
        return Err(err(
            error_codes::PSBT_FEE_EXCEEDS_CAP,
            StatusCode::UNPROCESSABLE_ENTITY,
            "implied miner fee exceeds per-chain cap",
        ));
    }
    Ok(())
}

/// Decode a hex field (no `0x` prefix expected — the wire carries raw
/// hex for these), mapping a bad value to `PSBT_OUTPUTS_MISMATCH`.
fn decode_hex_field(field: &str, hex_str: &str) -> Result<Vec<u8>, (StatusCode, Json<ErrorBody>)> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    alloy_primitives::hex::decode(stripped).map_err(|e| {
        err(
            error_codes::PSBT_OUTPUTS_MISMATCH,
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{field}: bad hex: {e}"),
        )
    })
}

/// Does `script` push exactly `data` after an `OP_RETURN`? Returns false
/// for non-`OP_RETURN` scripts, scripts whose pushed data differs, or
/// scripts that fail to parse.
fn op_return_data_eq(script: &bitcoin::Script, data: &[u8]) -> bool {
    if !script.is_op_return() {
        return false;
    }
    script.instructions().any(|instr| {
        instr
            .ok()
            .and_then(|i| i.push_bytes().map(|b| b.as_bytes() == data))
            .unwrap_or(false)
    })
}

/// `payload_hash = keccak256(prev_txid ‖ prev_vout_le_u32 ‖ sighash)`.
/// Including the sighash means a *different* consuming tx of the same
/// outpoint is detected as a payload conflict, not silently
/// double-signed.
fn hash_psbt_payload(prev_txid: &[u8; 32], prev_vout: u32, sighash: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 68];
    buf[..32].copy_from_slice(prev_txid);
    buf[32..36].copy_from_slice(&prev_vout.to_le_bytes());
    buf[36..68].copy_from_slice(sighash);
    alloy_primitives::keccak256(buf).into()
}

/// Rebuild the wire response from a stored DER+sighash signature.
fn decode_stored_response(stored: &[u8], pubkey: &bitcoin::PublicKey) -> PsbtSignResponse {
    PsbtSignResponse {
        pubkey: format!("0x{}", alloy_primitives::hex::encode(pubkey.to_bytes())),
        signature: alloy_primitives::hex::encode(stored),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::InMemoryReplayStore;
    use crate::server::{DaemonConfig, DaemonState};
    use crate::web3signer::{HsmDigestSigner, HsmError};
    use alloy_primitives::B256;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use bitcoin::{
        secp256k1::{All, Secp256k1, SecretKey},
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use std::sync::Mutex;
    use tower::ServiceExt;

    /// Software-keyed `HsmDigestSigner` for tests — produces a real
    /// secp256k1 signature so the daemon's r||s||v → compact → DER
    /// conversion + verify-against-pubkey path actually runs.
    struct SoftHsm {
        secp: Secp256k1<All>,
        secret: SecretKey,
        public: bitcoin::PublicKey,
        seen: Mutex<u32>,
    }

    impl std::fmt::Debug for SoftHsm {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SoftHsm").finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl HsmDigestSigner for SoftHsm {
        async fn sign_digest(&self, _addr: Address, digest: B256) -> Result<[u8; 65], HsmError> {
            #[expect(clippy::unwrap_used, reason = "test code")]
            {
                *self.seen.lock().unwrap() += 1;
            }
            let msg = Message::from_digest(digest.0);
            let sig = self.secp.sign_ecdsa(&msg, &self.secret);
            let compact = sig.serialize_compact();
            let mut out = [0u8; 65];
            out[..64].copy_from_slice(&compact);
            out[64] = 27; // arbitrary v (Bitcoin discards)
            let _ = self.public; // silence lint
            Ok(out)
        }
    }

    fn make_descriptor(
        secp: &Secp256k1<All>,
        n: usize,
        k: usize,
    ) -> (MultisigDescriptor, Vec<SecretKey>) {
        let sks: Vec<SecretKey> = (1u8..=u8::try_from(n).unwrap_or(5))
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[31] = i;
                #[expect(clippy::expect_used, reason = "test code")]
                SecretKey::from_slice(&bytes).expect("valid")
            })
            .collect();
        let pks: Vec<bitcoin::PublicKey> = sks
            .iter()
            .map(|sk| bitcoin::PublicKey::new(sk.public_key(secp)))
            .collect();
        #[expect(clippy::expect_used, reason = "test code")]
        let desc = MultisigDescriptor::new_p2wsh(k, &pks).expect("descriptor");
        (desc, sks)
    }

    /// Default test memo for [`build_test_psbt`]-shaped transactions.
    const TEST_MEMO: &[u8] = b"=:ETH.USDT:0xribbon:1";

    /// CTD-1: a quorum-signed proof certifying (recipient, payout,
    /// memo) for the BTC chain on the test daemon's domain.
    fn ric_proof(
        recipient: &ScriptBuf,
        payout_sats: u64,
        memo: &[u8],
        rid: u8,
    ) -> xindex_shared::signer_wire::IntentProof {
        crate::test_support::ric::proof_for(
            31337,
            Address::repeat_byte(0xab),
            &crate::test_support::ric::CertSpec {
                chain: ChainId::Btc,
                redemption_id: B256::repeat_byte(rid),
                leg_index: 0,
                amount: alloy_primitives::U256::from(payout_sats),
                immediate_target: recipient.as_bytes().to_vec(),
                memo: memo.to_vec(),
            },
        )
    }

    /// Build a minimal valid spending PSBT in the HONEST redemption
    /// shape the CTD-1 bind accepts: one input spending a P2WSH funded
    /// with our descriptor; a payout output to `recipient_script` plus
    /// a zero-value `OP_RETURN(TEST_MEMO)`.
    #[expect(clippy::expect_used, reason = "test code")]
    fn build_test_psbt(
        descriptor: &MultisigDescriptor,
        prev_txid: bitcoin::Txid,
        prev_vout: u32,
        value: Amount,
        recipient_script: ScriptBuf,
    ) -> Psbt {
        let witness_script = derive_witness_script(descriptor).expect("ws");
        let address = descriptor.address(Network::Bitcoin).expect("addr");
        let prev_spk = address.script_pubkey();
        let push = bitcoin::script::PushBytesBuf::try_from(TEST_MEMO.to_vec()).expect("push");

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: prev_vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: value - Amount::from_sat(1_000),
                    script_pubkey: recipient_script,
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::new_op_return(push),
                },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value,
            script_pubkey: prev_spk,
        });
        psbt.inputs[0].witness_script = Some(witness_script);
        psbt
    }

    /// Two-input variant of [`build_test_psbt`]: ONE tx that spends two of
    /// the daemon's own multisig UTXOs to a single payout. Each input is
    /// independently signable via its `input_index`. Used to prove the
    /// RUST-003 one-shot binds the unsigned-tx txid (constant across the
    /// inputs of ONE tx), so a legitimate multi-input redemption signs
    /// every input under a single RIC — a per-input outpoint identity
    /// would have 409'd the second input.
    #[expect(clippy::expect_used, reason = "test code")]
    fn build_test_psbt_2in(
        descriptor: &MultisigDescriptor,
        prev0: bitcoin::Txid,
        prev1: bitcoin::Txid,
        value_each: Amount,
        recipient_script: ScriptBuf,
    ) -> Psbt {
        let witness_script = derive_witness_script(descriptor).expect("ws");
        let address = descriptor.address(Network::Bitcoin).expect("addr");
        let prev_spk = address.script_pubkey();
        let push = bitcoin::script::PushBytesBuf::try_from(TEST_MEMO.to_vec()).expect("push");
        let mk_in = |txid| TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![mk_in(prev0), mk_in(prev1)],
            output: vec![
                TxOut {
                    value: value_each - Amount::from_sat(1_000),
                    script_pubkey: recipient_script,
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::new_op_return(push),
                },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");
        for input in &mut psbt.inputs {
            input.witness_utxo = Some(TxOut {
                value: value_each,
                script_pubkey: prev_spk.clone(),
            });
            input.witness_script = Some(witness_script.clone());
        }
        psbt
    }

    /// As [`build_test_psbt`] but with TWO outputs — a payout to
    /// `recipient_script` plus an `OP_RETURN(memo)` — so the M2 output
    /// veto (destination + amount + memo) can be exercised together.
    #[expect(clippy::expect_used, reason = "test code")]
    fn build_test_psbt_with_memo(
        descriptor: &MultisigDescriptor,
        prev_txid: bitcoin::Txid,
        value: Amount,
        recipient_script: ScriptBuf,
        payout: Amount,
        memo: &[u8],
    ) -> Psbt {
        let witness_script = derive_witness_script(descriptor).expect("ws");
        let prev_spk = descriptor
            .address(Network::Bitcoin)
            .expect("addr")
            .script_pubkey();
        let push = bitcoin::script::PushBytesBuf::try_from(memo.to_vec()).expect("push");
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: payout,
                    script_pubkey: recipient_script,
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::new_op_return(push),
                },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value,
            script_pubkey: prev_spk,
        });
        psbt.inputs[0].witness_script = Some(witness_script);
        psbt
    }

    fn build_state_with_btc(
        descriptor: MultisigDescriptor,
        my_pubkey: bitcoin::PublicKey,
        hsm: Arc<SoftHsm>,
    ) -> (DaemonState<InMemoryReplayStore, SoftHsm>, Router) {
        let replay = Arc::new(InMemoryReplayStore::new());
        let cfg = UtxoSignerConfig {
            chain_id: ChainId::Btc,
            network: Network::Bitcoin,
            descriptor,
            my_pubkey,
            hsm_address: Address::repeat_byte(0xcd),
        };
        let mut utxo = std::collections::HashMap::new();
        utxo.insert(ChainId::Btc, Arc::new(cfg));
        let state = DaemonState {
            config: DaemonConfig {
                chain_id: 31337,
                verifying_contract: Address::repeat_byte(0xab),
                eth_address: Address::repeat_byte(0xcd),
                intent_policy: crate::test_support::ric::policy(),
                cert_volume: crate::server::CertVolumePolicy::unmetered(),
            },
            replay,
            hsm,
            utxo,
            evm: std::collections::HashMap::new(),
            cosmos: std::collections::HashMap::new(),
            xrp: std::collections::HashMap::new(),
            sol: std::collections::HashMap::new(),
            tron: std::collections::HashMap::new(),
        };
        let app = Router::new()
            .route(
                "/api/v1/sign/psbt-input",
                post(handle_psbt_input::<InMemoryReplayStore, SoftHsm>),
            )
            .with_state(state.clone());
        (state, app)
    }

    async fn post_psbt(
        app: &Router,
        b64: String,
        idx: u32,
        proof: &xindex_shared::signer_wire::IntentProof,
    ) -> (StatusCode, serde_json::Value) {
        post_psbt_body(
            app,
            serde_json::json!({
                "chain_id": "btc",
                "psbt_base64": b64,
                "input_index": idx,
                "intent_proof": serde_json::to_value(proof).unwrap_or(serde_json::Value::Null),
            }),
        )
        .await
    }

    /// POST an arbitrary request body — lets the M2 veto tests attach the
    /// optional `expected_*` fields.
    async fn post_psbt_body(
        app: &Router,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        #[expect(clippy::expect_used, reason = "test code")]
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/sign/psbt-input")
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
    #[expect(clippy::expect_used, reason = "test code")]
    async fn first_sign_records_and_returns_valid_partial_sig() {
        let secp = Secp256k1::new();
        let (desc, sks) = make_descriptor(&secp, 3, 2);
        let my_pubkey = bitcoin::PublicKey::new(sks[0].public_key(&secp));
        let hsm = Arc::new(SoftHsm {
            secp: secp.clone(),
            secret: sks[0],
            public: my_pubkey,
            seen: Mutex::new(0),
        });
        let (_state, app) = build_state_with_btc(desc.clone(), my_pubkey, Arc::clone(&hsm));

        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x11u8; 32]));
        let (spk, _) = dest_spk();
        let psbt = build_test_psbt(&desc, prev_txid, 0, Amount::from_sat(100_000), spk.clone());
        let b64 = B64.encode(psbt.serialize());
        let proof = ric_proof(&spk, 99_000, TEST_MEMO, 0x51);

        let (status, body) = post_psbt(&app, b64.clone(), 0, &proof).await;
        assert_eq!(status, StatusCode::OK);
        let sig_hex = body["signature"].as_str().expect("signature");
        // DER signatures are 70-72 bytes + 1 sighash byte → 71-73 bytes.
        let sig_bytes = alloy_primitives::hex::decode(sig_hex).expect("sig hex");
        assert!(
            sig_bytes.len() >= 70 && sig_bytes.len() <= 73,
            "sig len {}",
            sig_bytes.len()
        );
        assert_eq!(
            *sig_bytes.last().expect("last"),
            EcdsaSighashType::All as u8
        );
        let pk_hex = body["pubkey"].as_str().expect("pubkey");
        assert_eq!(
            pk_hex,
            format!("0x{}", alloy_primitives::hex::encode(my_pubkey.to_bytes()))
        );

        // Idempotent: re-post returns the same signature without
        // re-invoking the HSM.
        #[expect(clippy::unwrap_used, reason = "test code")]
        let before = *hsm.seen.lock().unwrap();
        let (status2, body2) = post_psbt(&app, b64, 0, &proof).await;
        assert_eq!(status2, StatusCode::OK);
        assert_eq!(body2["signature"], body["signature"]);
        #[expect(clippy::unwrap_used, reason = "test code")]
        let after = *hsm.seen.lock().unwrap();
        assert_eq!(before, after, "HSM must not be invoked on idempotent retry");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn different_consuming_tx_same_outpoint_is_409() {
        let secp = Secp256k1::new();
        let (desc, sks) = make_descriptor(&secp, 3, 2);
        let my_pubkey = bitcoin::PublicKey::new(sks[0].public_key(&secp));
        let hsm = Arc::new(SoftHsm {
            secp: secp.clone(),
            secret: sks[0],
            public: my_pubkey,
            seen: Mutex::new(0),
        });
        let (_state, app) = build_state_with_btc(desc.clone(), my_pubkey, hsm);
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x22u8; 32]));
        let (spk_a, _) = dest_spk();
        let spk_b = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x43; 20]));
        let psbt_a = build_test_psbt(
            &desc,
            prev_txid,
            0,
            Amount::from_sat(100_000),
            spk_a.clone(),
        );
        // different output → different sighash
        let psbt_b = build_test_psbt(
            &desc,
            prev_txid,
            0,
            Amount::from_sat(100_000),
            spk_b.clone(),
        );
        // Distinct legs (rids), so the RIC one-shot passes for both and
        // the OUTPOINT replay is what fires.
        let proof_a = ric_proof(&spk_a, 99_000, TEST_MEMO, 0x52);
        let proof_b = ric_proof(&spk_b, 99_000, TEST_MEMO, 0x53);
        let (s1, _) = post_psbt(&app, B64.encode(psbt_a.serialize()), 0, &proof_a).await;
        assert_eq!(s1, StatusCode::OK);
        let (s2, body2) = post_psbt(&app, B64.encode(psbt_b.serialize()), 0, &proof_b).await;
        assert_eq!(s2, StatusCode::CONFLICT);
        assert_eq!(
            body2["code"].as_str().expect("code"),
            error_codes::CONFLICT_ALREADY_SIGNED_DIFFERENT
        );
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn mismatched_witness_script_is_422_wrong_descriptor() {
        let secp = Secp256k1::new();
        let (desc, sks) = make_descriptor(&secp, 3, 2);
        let my_pubkey = bitcoin::PublicKey::new(sks[0].public_key(&secp));
        let hsm = Arc::new(SoftHsm {
            secp: secp.clone(),
            secret: sks[0],
            public: my_pubkey,
            seen: Mutex::new(0),
        });
        let (_state, app) = build_state_with_btc(desc.clone(), my_pubkey, hsm);
        // Build a PSBT but tamper the witness_script to something
        // unrelated → daemon refuses.
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x33u8; 32]));
        let (spk, _) = dest_spk();
        let mut psbt = build_test_psbt(&desc, prev_txid, 0, Amount::from_sat(100_000), spk.clone());
        psbt.inputs[0].witness_script = Some(ScriptBuf::from_bytes(vec![0x00, 0x01, 0x02]));
        let proof = ric_proof(&spk, 99_000, TEST_MEMO, 0x54);
        let (status, body) = post_psbt(&app, B64.encode(psbt.serialize()), 0, &proof).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["code"].as_str().expect("code"),
            error_codes::WRONG_DESCRIPTOR
        );
    }

    /// Test fixture: 2-of-3 descriptor + the daemon + a real `SoftHsm`.
    fn veto_fixture() -> (MultisigDescriptor, Router) {
        let secp = Secp256k1::new();
        let (desc, sks) = make_descriptor(&secp, 3, 2);
        let my_pubkey = bitcoin::PublicKey::new(sks[0].public_key(&secp));
        let hsm = Arc::new(SoftHsm {
            secp: secp.clone(),
            secret: sks[0],
            public: my_pubkey,
            seen: Mutex::new(0),
        });
        let (_state, app) = build_state_with_btc(desc.clone(), my_pubkey, hsm);
        (desc, app)
    }

    /// An arbitrary P2WPKH destination scriptPubKey + its hex.
    fn dest_spk() -> (ScriptBuf, String) {
        let spk = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x42; 20]));
        let hex = alloy_primitives::hex::encode(spk.as_bytes());
        (spk, hex)
    }

    fn veto_body(
        b64: &str,
        dest_hex: &str,
        amount: u64,
        memo_hex: &str,
        proof: &xindex_shared::signer_wire::IntentProof,
    ) -> serde_json::Value {
        serde_json::json!({
            "chain_id": "btc",
            "psbt_base64": b64,
            "input_index": 0,
            "expected_destination_spk": dest_hex,
            "expected_amount_sats": amount,
            "expected_memo": memo_hex,
            "intent_proof": serde_json::to_value(proof).unwrap_or(serde_json::Value::Null),
        })
    }

    /// M2 PASS: destination spk + amount + memo all match the PSBT → 200.
    #[tokio::test]
    async fn output_veto_passes_when_expected_match() {
        let (desc, app) = veto_fixture();
        let (spk, spk_hex) = dest_spk();
        let memo = b"=:ETH.USDT:0xabc:0";
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xa1u8; 32]));
        let psbt = build_test_psbt_with_memo(
            &desc,
            prev_txid,
            Amount::from_sat(100_000),
            spk.clone(),
            Amount::from_sat(70_000),
            memo,
        );
        let proof = ric_proof(&spk, 70_000, memo, 0x61);
        let body = veto_body(
            &B64.encode(psbt.serialize()),
            &spk_hex,
            70_000,
            &alloy_primitives::hex::encode(memo),
            &proof,
        );
        let (status, _) = post_psbt_body(&app, body).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// M2 REJECT: a destination scriptPubKey not present in any output.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn output_veto_rejects_wrong_destination() {
        let (desc, app) = veto_fixture();
        let (spk, _spk_hex) = dest_spk();
        let memo = b"=:ETH.USDT:0xabc:0";
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xa2u8; 32]));
        let psbt = build_test_psbt_with_memo(
            &desc,
            prev_txid,
            Amount::from_sat(100_000),
            spk.clone(),
            Amount::from_sat(70_000),
            memo,
        );
        // Pin a DIFFERENT destination spk than the PSBT pays. The
        // CERTIFICATE matches the PSBT, so the CTD-1 bind passes and the
        // M2 expected-field veto is what fires.
        let wrong = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x99; 20]));
        let proof = ric_proof(&spk, 70_000, memo, 0x62);
        let body = veto_body(
            &B64.encode(psbt.serialize()),
            &alloy_primitives::hex::encode(wrong.as_bytes()),
            70_000,
            &alloy_primitives::hex::encode(memo),
            &proof,
        );
        let (status, body) = post_psbt_body(&app, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["code"].as_str().expect("code"),
            error_codes::PSBT_OUTPUTS_MISMATCH
        );
    }

    /// M2 REJECT: right destination, wrong pinned amount.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn output_veto_rejects_wrong_amount() {
        let (desc, app) = veto_fixture();
        let (spk, spk_hex) = dest_spk();
        let memo = b"=:ETH.USDT:0xabc:0";
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xa3u8; 32]));
        let psbt = build_test_psbt_with_memo(
            &desc,
            prev_txid,
            Amount::from_sat(100_000),
            spk.clone(),
            Amount::from_sat(70_000),
            memo,
        );
        let proof = ric_proof(&spk, 70_000, memo, 0x63);
        let body = veto_body(
            &B64.encode(psbt.serialize()),
            &spk_hex,
            69_999, // ← off by one
            &alloy_primitives::hex::encode(memo),
            &proof,
        );
        let (status, body) = post_psbt_body(&app, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["code"].as_str().expect("code"),
            error_codes::PSBT_OUTPUTS_MISMATCH
        );
    }

    /// M2 REJECT: right destination + amount, but the pinned memo does
    /// not match any `OP_RETURN` output (wrong/missing memo).
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn output_veto_rejects_wrong_memo() {
        let (desc, app) = veto_fixture();
        let (spk, spk_hex) = dest_spk();
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xa4u8; 32]));
        let psbt = build_test_psbt_with_memo(
            &desc,
            prev_txid,
            Amount::from_sat(100_000),
            spk.clone(),
            Amount::from_sat(70_000),
            b"=:ETH.USDT:0xabc:0",
        );
        let proof = ric_proof(&spk, 70_000, b"=:ETH.USDT:0xabc:0", 0x64);
        let body = veto_body(
            &B64.encode(psbt.serialize()),
            &spk_hex,
            70_000,
            &alloy_primitives::hex::encode(b"=:ETH.USDT:0xDIFFERENT:0"),
            &proof,
        );
        let (status, body) = post_psbt_body(&app, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["code"].as_str().expect("code"),
            error_codes::PSBT_OUTPUTS_MISMATCH
        );
    }

    /// Build a single-input PSBT with an explicit output set, so the M2b
    /// change-to-self + fee-cap tests can attach arbitrary (attacker /
    /// funded-OP_RETURN / change) outputs.
    #[expect(clippy::expect_used, reason = "test code")]
    fn build_psbt_outputs(
        descriptor: &MultisigDescriptor,
        prev_txid: bitcoin::Txid,
        input_value: Amount,
        outputs: Vec<TxOut>,
    ) -> Psbt {
        let witness_script = derive_witness_script(descriptor).expect("ws");
        let prev_spk = descriptor
            .address(Network::Bitcoin)
            .expect("addr")
            .script_pubkey();
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: outputs,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: input_value,
            script_pubkey: prev_spk,
        });
        psbt.inputs[0].witness_script = Some(witness_script);
        psbt
    }

    /// An `OP_RETURN(memo)` output carrying `value` sats.
    #[expect(clippy::expect_used, reason = "test code")]
    fn op_return_out(memo: &[u8], value: Amount) -> TxOut {
        let push = bitcoin::script::PushBytesBuf::try_from(memo.to_vec()).expect("push");
        TxOut {
            value,
            script_pubkey: ScriptBuf::new_op_return(push),
        }
    }

    const M2B_MEMO: &[u8] = b"=:ETH.USDT:0xabc:0";

    /// M2b ACCEPT: payout + change back to the descriptor's own P2WSH +
    /// zero-value memo → all three are ordered and whitelisted, fee is bounded.
    #[tokio::test]
    async fn m2b_change_to_self_is_accepted() {
        let (desc, app) = veto_fixture();
        let (spk, spk_hex) = dest_spk();
        let change_spk = desc
            .address(Network::Bitcoin)
            .map(|a| a.script_pubkey())
            .unwrap_or_default();
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xb1u8; 32]));
        let psbt = build_psbt_outputs(
            &desc,
            prev_txid,
            Amount::from_sat(100_000),
            vec![
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: spk.clone(),
                },
                TxOut {
                    value: Amount::from_sat(25_000),
                    script_pubkey: change_spk,
                },
                op_return_out(M2B_MEMO, Amount::ZERO),
            ],
        );
        let proof = ric_proof(&spk, 70_000, M2B_MEMO, 0x65);
        let body = veto_body(
            &B64.encode(psbt.serialize()),
            &spk_hex,
            70_000,
            &alloy_primitives::hex::encode(M2B_MEMO),
            &proof,
        );
        let (status, _) = post_psbt_body(&app, body).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// M2b REJECT: change routed to an attacker address (not the
    /// descriptor P2WSH) → `PSBT_UNEXPECTED_OUTPUT`. This is the core
    /// theft leg of M2b.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn m2b_change_to_attacker_is_rejected() {
        let (desc, app) = veto_fixture();
        let (spk, spk_hex) = dest_spk();
        let attacker = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0xee; 20]));
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xb2u8; 32]));
        let psbt = build_psbt_outputs(
            &desc,
            prev_txid,
            Amount::from_sat(100_000),
            vec![
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: spk.clone(),
                },
                TxOut {
                    value: Amount::from_sat(25_000),
                    script_pubkey: attacker,
                },
                op_return_out(M2B_MEMO, Amount::ZERO),
            ],
        );
        let proof = ric_proof(&spk, 70_000, M2B_MEMO, 0x66);
        let body = veto_body(
            &B64.encode(psbt.serialize()),
            &spk_hex,
            70_000,
            &alloy_primitives::hex::encode(M2B_MEMO),
            &proof,
        );
        let (status, body) = post_psbt_body(&app, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["code"].as_str().expect("code"),
            error_codes::PSBT_UNEXPECTED_OUTPUT
        );
    }

    /// M2b REJECT: change omitted, residue dumped into the miner fee
    /// (input ≫ payout) → `PSBT_FEE_EXCEEDS_CAP`. The fee-burning leg.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn m2b_excessive_fee_is_rejected() {
        let (desc, app) = veto_fixture();
        let (spk, spk_hex) = dest_spk();
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xb3u8; 32]));
        // 5 BTC in, 0.0007 BTC out → ~4.999 BTC implied fee, far over the
        // 0.01 BTC (1_000_000 sat) BTC cap.
        let psbt = build_psbt_outputs(
            &desc,
            prev_txid,
            Amount::from_sat(500_000_000),
            vec![
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: spk.clone(),
                },
                op_return_out(M2B_MEMO, Amount::ZERO),
            ],
        );
        let proof = ric_proof(&spk, 70_000, M2B_MEMO, 0x67);
        let body = veto_body(
            &B64.encode(psbt.serialize()),
            &spk_hex,
            70_000,
            &alloy_primitives::hex::encode(M2B_MEMO),
            &proof,
        );
        let (status, body) = post_psbt_body(&app, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["code"].as_str().expect("code"),
            error_codes::PSBT_FEE_EXCEEDS_CAP
        );
    }

    /// Boundary: an implied fee EXACTLY at the per-chain cap is ALLOWED — the
    /// guard is a strict `>`, so a fee equal to the BTC cap passes while
    /// `m2b_excessive_fee_is_rejected` covers anything over. The PSBT nets an
    /// implied fee equal to the cap (`payout + cap` in, `payout` out).
    #[tokio::test]
    async fn fee_exactly_at_cap_is_accepted() {
        let (desc, app) = veto_fixture();
        let (spk, spk_hex) = dest_spk();
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xc1u8; 32]));
        let psbt = build_psbt_outputs(
            &desc,
            prev_txid,
            Amount::from_sat(1_070_000),
            vec![
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: spk.clone(),
                },
                op_return_out(M2B_MEMO, Amount::ZERO),
            ],
        );
        let proof = ric_proof(&spk, 70_000, M2B_MEMO, 0x71);
        let body = veto_body(
            &B64.encode(psbt.serialize()),
            &spk_hex,
            70_000,
            &alloy_primitives::hex::encode(M2B_MEMO),
            &proof,
        );
        let (status, body) = post_psbt_body(&app, body).await;
        assert_eq!(status, StatusCode::OK, "fee == cap must pass: {body}");
    }

    /// M2b REJECT: a FUNDED `OP_RETURN` (value > 0) would burn that value
    /// while passing the presence-only memo veto and escaping the fee
    /// check (it is an output, not fee). The zero-value rule catches it →
    /// `INTENT_MISMATCH`.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn m2b_funded_op_return_is_rejected() {
        let (desc, app) = veto_fixture();
        let (spk, spk_hex) = dest_spk();
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xb4u8; 32]));
        let psbt = build_psbt_outputs(
            &desc,
            prev_txid,
            Amount::from_sat(100_000),
            vec![
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: spk.clone(),
                },
                // memo bytes present (passes veto) but carries 25_000 sats
                op_return_out(M2B_MEMO, Amount::from_sat(25_000)),
            ],
        );
        let proof = ric_proof(&spk, 70_000, M2B_MEMO, 0x68);
        let body = veto_body(
            &B64.encode(psbt.serialize()),
            &spk_hex,
            70_000,
            &alloy_primitives::hex::encode(M2B_MEMO),
            &proof,
        );
        let (status, body) = post_psbt_body(&app, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        // The CTD-1 output bind fires first: a funded OP_RETURN is memo
        // value-burn regardless of the M2b whitelisting.
        assert_eq!(
            body["code"].as_str().expect("code"),
            error_codes::INTENT_MISMATCH
        );
    }

    /// AUD-PSBT-FEECAP-MULTIINPUT: a SECOND input that does not spend the
    /// daemon descriptor P2WSH (a coordinator-injected foreign input whose
    /// forged `witness_utxo.value` would otherwise inflate the fee-cap input
    /// sum) is rejected — `WRONG_DESCRIPTOR`. The signed input (idx 0) is a
    /// genuine descriptor UTXO, so steps 2-4b pass and the multi-input fee
    /// loop is the gate that fires.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn foreign_second_input_is_rejected() {
        let (desc, app) = veto_fixture();
        let (spk, spk_hex) = dest_spk();
        let witness_script = derive_witness_script(&desc).expect("ws");
        let descriptor_spk = desc
            .address(Network::Bitcoin)
            .expect("addr")
            .script_pubkey();
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xc1u8; 32]));
        let foreign_spk = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0xab; 20]));
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: prev_txid,
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: prev_txid,
                        vout: 1,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
            ],
            output: vec![
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: spk.clone(),
                },
                op_return_out(M2B_MEMO, Amount::ZERO),
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");
        // Input 0: genuine descriptor UTXO (signed input).
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: descriptor_spk,
        });
        psbt.inputs[0].witness_script = Some(witness_script);
        // Input 1: foreign prevout with a huge forged value.
        psbt.inputs[1].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10_000_000_000),
            script_pubkey: foreign_spk,
        });
        let proof = ric_proof(&spk, 70_000, M2B_MEMO, 0x69);
        let body = veto_body(
            &B64.encode(psbt.serialize()),
            &spk_hex,
            70_000,
            &alloy_primitives::hex::encode(M2B_MEMO),
            &proof,
        );
        let (status, body) = post_psbt_body(&app, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["code"].as_str().expect("code"),
            error_codes::WRONG_DESCRIPTOR
        );
    }

    /// I3: a forged `witness_utxo.script_pubkey` (not the descriptor
    /// P2WSH program) is refused even though `witness_script` matches.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn forged_witness_utxo_spk_is_rejected() {
        let (desc, app) = veto_fixture();
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xa5u8; 32]));
        let (spk, _) = dest_spk();
        let mut psbt = build_test_psbt(&desc, prev_txid, 0, Amount::from_sat(100_000), spk.clone());
        // Keep the (correct) witness_script but forge the prevout spk.
        let forged = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x77; 20]));
        let value = psbt.inputs[0].witness_utxo.as_ref().expect("wu").value;
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value,
            script_pubkey: forged,
        });
        let proof = ric_proof(&spk, 99_000, TEST_MEMO, 0x55);
        let (status, body) = post_psbt(&app, B64.encode(psbt.serialize()), 0, &proof).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["code"].as_str().expect("code"),
            error_codes::WRONG_DESCRIPTOR
        );
    }

    /// Recompute the daemon's replay key for a single-input PSBT (mirrors
    /// handler steps 5-6) so the L10 test can pre-seed the winner's row.
    #[expect(clippy::expect_used, reason = "test code")]
    fn replay_key_for(psbt: &Psbt) -> ([u8; 32], u32, [u8; 32]) {
        let input = &psbt.inputs[0];
        let ws = input.witness_script.as_ref().expect("ws");
        let wu = input.witness_utxo.as_ref().expect("wu");
        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let sighash = cache
            .p2wsh_signature_hash(0, ws, wu.value, EcdsaSighashType::All)
            .expect("sighash");
        let sighash_bytes: [u8; 32] = sighash.to_byte_array();
        let txin = &psbt.unsigned_tx.input[0];
        let prev_txid: [u8; 32] = *txin.previous_output.txid.as_ref();
        let prev_vout = txin.previous_output.vout;
        let payload_hash = hash_psbt_payload(&prev_txid, prev_vout, &sighash_bytes);
        (prev_txid, prev_vout, payload_hash)
    }

    /// L10: the handler loses the `record_psbt_input` write race (the
    /// store returns `Duplicate`). It must re-read the winner's row and
    /// return the cached signature idempotently — HTTP 200, NOT an error.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn psbt_record_race_recovers_cached_signature() {
        let secp = Secp256k1::new();
        let (desc, sks) = make_descriptor(&secp, 3, 2);
        let my_pubkey = bitcoin::PublicKey::new(sks[0].public_key(&secp));
        let hsm = Arc::new(SoftHsm {
            secp: secp.clone(),
            secret: sks[0],
            public: my_pubkey,
            seen: Mutex::new(0),
        });

        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xb1u8; 32]));
        let (spk, _) = dest_spk();
        let psbt = build_test_psbt(&desc, prev_txid, 0, Amount::from_sat(100_000), spk.clone());
        let (txid, vout, payload_hash) = replay_key_for(&psbt);

        // Winner already recorded a (distinct, recognizable) signature.
        let winner_sig = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let inner = InMemoryReplayStore::new();
        inner
            .record_psbt_input(
                ChainId::Btc,
                txid,
                vout,
                payload_hash,
                winner_sig.clone(),
                100,
            )
            .await
            .expect("seed winner");
        let replay = Arc::new(crate::test_support::RaceReplayStore::new(
            inner,
            crate::test_support::RacePath::PsbtInput,
        ));

        let cfg = UtxoSignerConfig {
            chain_id: ChainId::Btc,
            network: Network::Bitcoin,
            descriptor: desc,
            my_pubkey,
            hsm_address: Address::repeat_byte(0xcd),
        };
        let mut utxo = std::collections::HashMap::new();
        utxo.insert(ChainId::Btc, Arc::new(cfg));
        let state = DaemonState {
            config: DaemonConfig {
                chain_id: 31337,
                verifying_contract: Address::repeat_byte(0xab),
                eth_address: Address::repeat_byte(0xcd),
                intent_policy: crate::test_support::ric::policy(),
                cert_volume: crate::server::CertVolumePolicy::unmetered(),
            },
            replay,
            hsm,
            utxo,
            evm: std::collections::HashMap::new(),
            cosmos: std::collections::HashMap::new(),
            xrp: std::collections::HashMap::new(),
            sol: std::collections::HashMap::new(),
            tron: std::collections::HashMap::new(),
        };
        let app = Router::new()
            .route(
                "/api/v1/sign/psbt-input",
                post(
                    handle_psbt_input::<
                        crate::test_support::RaceReplayStore<InMemoryReplayStore>,
                        SoftHsm,
                    >,
                ),
            )
            .with_state(state);

        let proof = ric_proof(&spk, 99_000, TEST_MEMO, 0x56);
        let (status, body) = post_psbt(&app, B64.encode(psbt.serialize()), 0, &proof).await;
        assert_eq!(status, StatusCode::OK);
        // The cached winner's signature is returned, not the loser's.
        assert_eq!(
            body["signature"].as_str().expect("signature"),
            alloy_primitives::hex::encode(&winner_sig)
        );
    }

    /// CTD-1: a request WITHOUT an `IntentProof` is refused before
    /// anything else — there is no proof-less carve-out on the BTC
    /// custody path.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn psbt_missing_intent_proof_is_422_required() {
        let (desc, app) = veto_fixture();
        let (spk, _) = dest_spk();
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xd1u8; 32]));
        let psbt = build_test_psbt(&desc, prev_txid, 0, Amount::from_sat(100_000), spk);
        let body = serde_json::json!({
            "chain_id": "btc",
            "psbt_base64": B64.encode(psbt.serialize()),
            "input_index": 0,
        });
        let (status, body) = post_psbt_body(&app, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["code"].as_str().expect("code"),
            error_codes::INTENT_PROOF_REQUIRED
        );
    }

    /// CTD-1 / RA-3 exact-set: a SECOND `OP_RETURN` — even zero-value,
    /// even alongside a fully-certified payout+memo — is memo
    /// injection (`THORChain` concatenates ALL `OP_RETURN`s) and is
    /// refused as an unexpected VOUT1 under the canonical ordered shape.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn psbt_second_op_return_is_rejected() {
        let (desc, app) = veto_fixture();
        let (spk, _) = dest_spk();
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xd2u8; 32]));
        let psbt = build_psbt_outputs(
            &desc,
            prev_txid,
            Amount::from_sat(100_000),
            vec![
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: spk.clone(),
                },
                op_return_out(M2B_MEMO, Amount::ZERO),
                // The injected memo fragment.
                op_return_out(b"+:ETH.ETH:attacker", Amount::ZERO),
            ],
        );
        let proof = ric_proof(&spk, 70_000, M2B_MEMO, 0x71);
        let body = serde_json::json!({
            "chain_id": "btc",
            "psbt_base64": B64.encode(psbt.serialize()),
            "input_index": 0,
            "intent_proof": serde_json::to_value(&proof).unwrap_or(serde_json::Value::Null),
        });
        let (status, body) = post_psbt_body(&app, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert_eq!(
            body["code"].as_str().expect("code"),
            error_codes::PSBT_UNEXPECTED_OUTPUT
        );
    }

    /// CTD-1 core property: the PSBT pays a destination the operators
    /// did NOT certify → refused before the HSM, even though the
    /// attached proof itself is a perfectly valid k-of-n certificate.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn psbt_uncertified_payout_is_rejected() {
        let (desc, app) = veto_fixture();
        let (spk, _) = dest_spk();
        let attacker = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x66; 20]));
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xd3u8; 32]));
        // PSBT pays the ATTACKER; the certificate authorizes `spk`.
        let psbt = build_test_psbt(&desc, prev_txid, 0, Amount::from_sat(100_000), attacker);
        let proof = ric_proof(&spk, 99_000, TEST_MEMO, 0x72);
        let (status, body) = post_psbt(&app, B64.encode(psbt.serialize()), 0, &proof).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert_eq!(
            body["code"].as_str().expect("code"),
            error_codes::INTENT_MISMATCH
        );
    }

    /* ---- CTD-1 Slice C: Acquire-Cancel certificate (RIC-XOR-ACC) ---- */

    /// Quorum-signed ACC certifying (recipient, payout, memo) for one
    /// mint-cancel swap-back on the test daemon's domain.
    fn acc_proof(
        recipient: &ScriptBuf,
        payout_sats: u64,
        memo: &[u8],
        cid: u8,
    ) -> xindex_shared::signer_wire::AcquireCancelProof {
        crate::test_support::ric::acc_proof_for(
            31337,
            Address::repeat_byte(0xab),
            &crate::test_support::ric::AccSpec {
                chain: ChainId::Btc,
                cancel_id: B256::repeat_byte(cid),
                intent_id: B256::repeat_byte(0xaa),
                slot_index: 0,
                amount: alloy_primitives::U256::from(payout_sats),
                immediate_target: recipient.as_bytes().to_vec(),
                memo: memo.to_vec(),
            },
        )
    }

    /// Slice C happy path: a k-of-n ACC (NO RIC) authorizes the
    /// mint-cancel swap-back spend — the path the unconditional RIC
    /// gate previously bricked.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn acc_authorizes_mint_cancel_swap_back() {
        let (desc, app) = veto_fixture();
        let (spk, _) = dest_spk();
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xe1u8; 32]));
        let psbt = build_test_psbt(&desc, prev_txid, 0, Amount::from_sat(100_000), spk.clone());
        let proof = acc_proof(&spk, 99_000, TEST_MEMO, 0x81);
        let body = serde_json::json!({
            "chain_id": "btc",
            "psbt_base64": B64.encode(psbt.serialize()),
            "input_index": 0,
            "acquire_cancel_proof": serde_json::to_value(&proof)
                .unwrap_or(serde_json::Value::Null),
        });
        let (status, body) = post_psbt_body(&app, body).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let sig_hex = body["signature"].as_str().expect("signature");
        let sig_bytes = alloy_primitives::hex::decode(sig_hex).expect("sig hex");
        assert!(
            sig_bytes.len() >= 70 && sig_bytes.len() <= 73,
            "sig len {}",
            sig_bytes.len()
        );
    }

    /// Strict XOR: attaching BOTH a RIC and an ACC is a 422
    /// `intent_proof_ambiguous` — never a pick-one.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn both_certificates_is_422_ambiguous() {
        let (desc, app) = veto_fixture();
        let (spk, _) = dest_spk();
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xe2u8; 32]));
        let psbt = build_test_psbt(&desc, prev_txid, 0, Amount::from_sat(100_000), spk.clone());
        let ric = ric_proof(&spk, 99_000, TEST_MEMO, 0x82);
        let acc = acc_proof(&spk, 99_000, TEST_MEMO, 0x82);
        let body = serde_json::json!({
            "chain_id": "btc",
            "psbt_base64": B64.encode(psbt.serialize()),
            "input_index": 0,
            "intent_proof": serde_json::to_value(&ric).unwrap_or(serde_json::Value::Null),
            "acquire_cancel_proof": serde_json::to_value(&acc)
                .unwrap_or(serde_json::Value::Null),
        });
        let (status, body) = post_psbt_body(&app, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert_eq!(
            body["code"].as_str().expect("code"),
            error_codes::INTENT_PROOF_AMBIGUOUS
        );
    }

    /// The output bind under an ACC reports the ACC-specific mismatch
    /// code: PSBT pays the certified target a DIFFERENT amount.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn acc_amount_mismatch_is_acquire_cancel_mismatch() {
        let (desc, app) = veto_fixture();
        let (spk, _) = dest_spk();
        let prev_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xe3u8; 32]));
        // PSBT pays 99_000 to the certified target; the ACC authorizes
        // only 50_000.
        let psbt = build_test_psbt(&desc, prev_txid, 0, Amount::from_sat(100_000), spk.clone());
        let proof = acc_proof(&spk, 50_000, TEST_MEMO, 0x83);
        let body = serde_json::json!({
            "chain_id": "btc",
            "psbt_base64": B64.encode(psbt.serialize()),
            "input_index": 0,
            "acquire_cancel_proof": serde_json::to_value(&proof)
                .unwrap_or(serde_json::Value::Null),
        });
        let (status, body) = post_psbt_body(&app, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert_eq!(
            body["code"].as_str().expect("code"),
            error_codes::ACQUIRE_CANCEL_MISMATCH
        );
    }

    /// RA-1 on the cancel path: after one swap-back is authorized for a
    /// `cancel_id`, a DIFFERENT certificate for the SAME `cancel_id` is a
    /// 409 — one valid ACC ≠ N swap-backs.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn acc_redrive_different_certificate_is_409() {
        let (desc, app) = veto_fixture();
        let (spk, _) = dest_spk();
        let prev_a =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xe4u8; 32]));
        let psbt_a = build_test_psbt(&desc, prev_a, 0, Amount::from_sat(100_000), spk.clone());
        let proof_a = acc_proof(&spk, 99_000, TEST_MEMO, 0x84);
        let body_a = serde_json::json!({
            "chain_id": "btc",
            "psbt_base64": B64.encode(psbt_a.serialize()),
            "input_index": 0,
            "acquire_cancel_proof": serde_json::to_value(&proof_a)
                .unwrap_or(serde_json::Value::Null),
        });
        let (status_a, body_a_resp) = post_psbt_body(&app, body_a).await;
        assert_eq!(status_a, StatusCode::OK, "body: {body_a_resp}");

        // Re-drive: SAME cancel_id (0x84), different certified amount →
        // a different ACC digest at a consumed one-shot.
        let prev_b =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xe5u8; 32]));
        let psbt_b = build_test_psbt(&desc, prev_b, 0, Amount::from_sat(60_000), spk.clone());
        let proof_b = acc_proof(&spk, 59_000, TEST_MEMO, 0x84);
        let body_b = serde_json::json!({
            "chain_id": "btc",
            "psbt_base64": B64.encode(psbt_b.serialize()),
            "input_index": 0,
            "acquire_cancel_proof": serde_json::to_value(&proof_b)
                .unwrap_or(serde_json::Value::Null),
        });
        let (status_b, body_b_resp) = post_psbt_body(&app, body_b).await;
        assert_eq!(status_b, StatusCode::CONFLICT, "body: {body_b_resp}");
        assert_eq!(
            body_b_resp["code"].as_str().expect("code"),
            error_codes::ACQUIRE_CANCEL_ALREADY_SIGNED
        );
    }

    /// An ACC consumed on the cancel path does NOT consume the RIC
    /// one-shot namespace: a redemption whose `redemption_id` happens to
    /// equal a consumed `cancel_id` still signs (independent arms).
    #[tokio::test]
    async fn acc_one_shot_is_independent_of_ric_one_shot() {
        let (desc, app) = veto_fixture();
        let (spk, _) = dest_spk();
        let prev_a =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xe6u8; 32]));
        let psbt_a = build_test_psbt(&desc, prev_a, 0, Amount::from_sat(100_000), spk.clone());
        let acc = acc_proof(&spk, 99_000, TEST_MEMO, 0x85);
        let body_a = serde_json::json!({
            "chain_id": "btc",
            "psbt_base64": B64.encode(psbt_a.serialize()),
            "input_index": 0,
            "acquire_cancel_proof": serde_json::to_value(&acc)
                .unwrap_or(serde_json::Value::Null),
        });
        let (status_a, resp_a) = post_psbt_body(&app, body_a).await;
        assert_eq!(status_a, StatusCode::OK, "body: {resp_a}");

        // A RIC for redemption_id == the consumed cancel_id (0x85): the
        // arms are separate namespaces, so this still signs.
        let prev_b =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xe7u8; 32]));
        let psbt_b = build_test_psbt(&desc, prev_b, 0, Amount::from_sat(100_000), spk.clone());
        let ric = ric_proof(&spk, 99_000, TEST_MEMO, 0x85);
        let (status_b, resp_b) = post_psbt(&app, B64.encode(psbt_b.serialize()), 0, &ric).await;
        assert_eq!(status_b, StatusCode::OK, "body: {resp_b}");
    }

    /// RUST-003 (BTC) — the one-shot binds the unsigned-tx TXID, not a
    /// per-input outpoint, so a legitimate MULTI-INPUT redemption (ONE tx
    /// spending two of our UTXOs) signs every input under a single RIC.
    /// Input 0 records the txid; input 1 of the SAME tx re-presents the
    /// matching identity and signs. A per-input outpoint identity would
    /// have 409'd input 1.
    #[tokio::test]
    async fn multi_input_one_tx_signs_every_input_under_one_ric() {
        let (desc, app) = veto_fixture();
        let (spk, _) = dest_spk();
        let prev0 =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xf0u8; 32]));
        let prev1 =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xf1u8; 32]));
        let psbt = build_test_psbt_2in(&desc, prev0, prev1, Amount::from_sat(100_000), spk.clone());
        let psbt_b64 = B64.encode(psbt.serialize());
        let ric = ric_proof(&spk, 99_000, TEST_MEMO, 0x90);
        let (s0, b0) = post_psbt(&app, psbt_b64.clone(), 0, &ric).await;
        assert_eq!(s0, StatusCode::OK, "input 0: {b0}");
        let (s1, b1) = post_psbt(&app, psbt_b64, 1, &ric).await;
        assert_eq!(s1, StatusCode::OK, "input 1 of the SAME tx must sign: {b1}");
    }

    /// RUST-003 (BTC / CTD-E-R1) — a re-drive of the SAME RIC into a
    /// DIFFERENT tx (a second payout spending a different UTXO → different
    /// unsigned-tx txid) is a 409 `intent_already_signed`. Contrast the
    /// multi-input case above (same txid → signs) and
    /// `acc_redrive_different_certificate_is_409` (different certificate).
    #[tokio::test]
    async fn redrive_same_ric_different_tx_is_409() {
        let (desc, app) = veto_fixture();
        let (spk, _) = dest_spk();
        let prev_a =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xf2u8; 32]));
        let psbt_a = build_test_psbt(&desc, prev_a, 0, Amount::from_sat(100_000), spk.clone());
        let ric = ric_proof(&spk, 99_000, TEST_MEMO, 0x91);
        let (sa, ba) = post_psbt(&app, B64.encode(psbt_a.serialize()), 0, &ric).await;
        assert_eq!(sa, StatusCode::OK, "first tx: {ba}");

        // SAME RIC (0x91 — same amount/memo/dest → same digest), a DIFFERENT
        // tx spending a different UTXO → a different unsigned-tx txid → 409.
        let prev_b =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xf3u8; 32]));
        let psbt_b = build_test_psbt(&desc, prev_b, 0, Amount::from_sat(100_000), spk.clone());
        let (sb, bb) = post_psbt(&app, B64.encode(psbt_b.serialize()), 0, &ric).await;
        assert_eq!(
            sb,
            StatusCode::CONFLICT,
            "re-drive into a different tx: {bb}"
        );
        assert_eq!(
            bb["code"].as_str().unwrap_or(""),
            error_codes::INTENT_ALREADY_SIGNED
        );
    }
}
