//! CTD-1 (`DL-CTD-2` / RA-3): BTC output-set binding, transport-agnostic.
//!
//! Binds a PSBT's ENTIRE output set to a [`CertifiedSpend`] — exactly one
//! certified payout, exactly one zero-value `OP_RETURN` memo (`THORChain`
//! concatenates ALL `OP_RETURN`s, so a second one is memo injection), every
//! other output change back to our own custody `scriptPubKey`. Shared by the
//! transitional signer-daemon PSBT handler and the Fireblocks BTC binder
//! (the descriptor `scriptPubKey` is the daemon's P2WSH program / the
//! Fireblocks MPC custody program respectively).

use alloy_primitives::keccak256;
use bitcoin::psbt::Psbt;

use crate::gates::{CertifiedSpend, GateRejection};
use xindex_shared::signer_wire::error_codes;

/// Bind the PSBT's output set to `spend`. Exact-set: every output must be
/// the certified payout, the certified memo `OP_RETURN`, or change-to-self.
///
/// # Errors
/// [`GateRejection`] (`spend.mismatch_code` / `psbt_unexpected_output`) on a
/// wrong payout amount, a non-matching/missing/duplicate memo, an unexpected
/// output, or a missing/duplicate payout.
pub fn bind_outputs_to_cert(
    psbt: &Psbt,
    descriptor_spk: &bitcoin::ScriptBuf,
    spend: &CertifiedSpend,
) -> Result<(), GateRejection> {
    let want_sats = u64::try_from(spend.amount).map_err(|_| {
        GateRejection::unprocessable(spend.mismatch_code, "certified amount does not fit u64 sats")
    })?;
    let mut payouts = 0usize;
    let mut op_returns = 0usize;
    for o in &psbt.unsigned_tx.output {
        if o.script_pubkey.is_op_return() {
            op_returns += 1;
            if o.value.to_sat() != 0 {
                return Err(GateRejection::unprocessable(
                    spend.mismatch_code,
                    "OP_RETURN output carries value (memo outputs must be zero-value)",
                ));
            }
            let payload = op_return_payload(&o.script_pubkey).ok_or_else(|| {
                GateRejection::unprocessable(spend.mismatch_code, "OP_RETURN output pushes no data")
            })?;
            if keccak256(&payload) != spend.memo_hash {
                return Err(GateRejection::unprocessable(
                    spend.mismatch_code,
                    "OP_RETURN payload does not hash to the certified memo",
                ));
            }
        } else if keccak256(o.script_pubkey.as_bytes()) == spend.immediate_target_hash {
            payouts += 1;
            if o.value.to_sat() != want_sats {
                return Err(GateRejection::unprocessable(
                    spend.mismatch_code,
                    format!(
                        "payout output pays {} sats, certificate authorizes {want_sats}",
                        o.value.to_sat()
                    ),
                ));
            }
        } else if o.script_pubkey.as_bytes() != descriptor_spk.as_bytes() {
            return Err(GateRejection::unprocessable(
                error_codes::PSBT_UNEXPECTED_OUTPUT,
                "output is neither the certified payout, the memo OP_RETURN, nor change-to-self",
            ));
        }
    }
    if payouts != 1 {
        return Err(GateRejection::unprocessable(
            spend.mismatch_code,
            format!("expected exactly one certified payout output, found {payouts}"),
        ));
    }
    if op_returns != 1 {
        return Err(GateRejection::unprocessable(
            spend.mismatch_code,
            format!("expected exactly one OP_RETURN memo output, found {op_returns} (RA-3)"),
        ));
    }
    Ok(())
}

/// Concatenated pushed payload of an `OP_RETURN` script, or `None` if the
/// script is not `OP_RETURN`, fails to parse, or pushes nothing.
fn op_return_payload(script: &bitcoin::Script) -> Option<Vec<u8>> {
    if !script.is_op_return() {
        return None;
    }
    let mut out = Vec::new();
    for instr in script.instructions() {
        match instr {
            Ok(i) => {
                if let Some(b) = i.push_bytes() {
                    out.extend_from_slice(b.as_bytes());
                }
            }
            Err(_) => return None,
        }
    }
    (!out.is_empty()).then_some(out)
}
