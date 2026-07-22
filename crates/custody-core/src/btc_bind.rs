//! CTD-1 (`DL-CTD-2` / RA-3): BTC output-set binding, transport-agnostic.
//!
//! Binds a PSBT's ENTIRE ordered output set to a [`CertifiedSpend`]. For the
//! Xindex <=80-byte memo profile the only accepted shapes are
//! `[Asgard payout, OP_RETURN]` (no change) and
//! `[Asgard payout, VIN0 change, OP_RETURN]`. `THORChain` requires the Asgard
//! vault at VOUT0, change back to VIN0 at VOUT1 when present, and the memo in
//! the following output; it also concatenates all `OP_RETURN`s, so a second
//! one is memo injection. Shared by every provider-specific custody adapter.

use std::borrow::Cow;

use alloy_primitives::keccak256;
use bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_PUSHNUM_16, OP_PUSHNUM_NEG1, OP_RETURN};
use bitcoin::psbt::Psbt;
use bitcoin::script::{Builder, Instruction, PushBytesBuf};
use bitcoin::{Script, ScriptBuf};
use thiserror::Error;

use crate::gates::{CertifiedSpend, GateRejection};
use xindex_shared::signer_wire::error_codes;

/// Borrowed value/script view shared by Bitcoin PSBT and transparent Zcash
/// output binders.
#[derive(Debug, Clone, Copy)]
pub struct UtxoOutputRef<'a> {
    value: u64,
    script_pubkey: &'a Script,
}

impl<'a> UtxoOutputRef<'a> {
    /// Construct an exact transparent-output view.
    #[must_use]
    pub const fn new(value: u64, script_pubkey: &'a Script) -> Self {
        Self {
            value,
            script_pubkey,
        }
    }
}

/// Why an `OP_RETURN` script is not one canonical, non-empty data push.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CanonicalOpReturnError {
    /// The first and only prefix instruction is not `OP_RETURN`.
    #[error("script does not start with OP_RETURN")]
    NotOpReturn,
    /// No payload follows `OP_RETURN`, or the only push is empty.
    #[error("OP_RETURN payload must be non-empty")]
    EmptyPayload,
    /// The payload instruction is malformed or uses a wider-than-needed push.
    #[error("OP_RETURN payload push is malformed or non-minimal")]
    NonMinimalPush,
    /// The instruction after `OP_RETURN` is not a data-push instruction.
    #[error("OP_RETURN must be followed by exactly one data push")]
    NotDataPush,
    /// A third instruction or byte sequence follows the single payload push.
    #[error("OP_RETURN payload push must consume the entire script")]
    TrailingInstruction,
    /// The payload cannot be represented by Bitcoin's push-data container.
    #[error("OP_RETURN payload is too large to encode")]
    PayloadTooLarge,
}

/// Parse exactly `OP_RETURN <minimal non-empty push>` and return its data.
///
/// Minimality includes the shortest PUSHDATA width and the dedicated
/// `OP_PUSHNUM_NEG1` / `OP_PUSHNUM_1..16` encodings for those one-byte values.
/// No split pushes, intervening opcodes, malformed lengths, or trailing bytes
/// are accepted.
///
/// # Errors
/// Returns [`CanonicalOpReturnError`] unless the script has the exact canonical
/// two-instruction shape.
pub fn parse_canonical_op_return_payload(
    script: &Script,
) -> Result<Cow<'_, [u8]>, CanonicalOpReturnError> {
    let mut instructions = script.instructions_minimal();
    match instructions.next() {
        Some(Ok(Instruction::Op(op))) if op == OP_RETURN => {}
        Some(Err(_)) => return Err(CanonicalOpReturnError::NonMinimalPush),
        _ => return Err(CanonicalOpReturnError::NotOpReturn),
    }

    let payload = match instructions.next() {
        Some(Ok(Instruction::PushBytes(bytes))) if bytes.is_empty() => {
            return Err(CanonicalOpReturnError::EmptyPayload);
        }
        Some(Ok(Instruction::PushBytes(bytes))) => Cow::Borrowed(bytes.as_bytes()),
        Some(Ok(Instruction::Op(op))) if op == OP_PUSHNUM_NEG1 => Cow::Owned(vec![0x81]),
        Some(Ok(Instruction::Op(op)))
            if (OP_PUSHNUM_1.to_u8()..=OP_PUSHNUM_16.to_u8()).contains(&op.to_u8()) =>
        {
            Cow::Owned(vec![op.to_u8() - OP_PUSHNUM_1.to_u8() + 1])
        }
        Some(Ok(Instruction::Op(_))) => return Err(CanonicalOpReturnError::NotDataPush),
        Some(Err(_)) => return Err(CanonicalOpReturnError::NonMinimalPush),
        None => return Err(CanonicalOpReturnError::EmptyPayload),
    };

    match instructions.next() {
        None => Ok(payload),
        Some(_) => Err(CanonicalOpReturnError::TrailingInstruction),
    }
}

/// Build the unique minimally encoded script accepted by
/// [`parse_canonical_op_return_payload`].
///
/// # Errors
/// Returns [`CanonicalOpReturnError::EmptyPayload`] for empty data or
/// [`CanonicalOpReturnError::PayloadTooLarge`] when Bitcoin cannot represent
/// the payload as one push.
pub fn canonical_op_return_script(payload: &[u8]) -> Result<ScriptBuf, CanonicalOpReturnError> {
    if payload.is_empty() {
        return Err(CanonicalOpReturnError::EmptyPayload);
    }

    let builder = Builder::new().push_opcode(OP_RETURN);
    match payload {
        [0x01..=0x10] => Ok(builder.push_int(i64::from(payload[0])).into_script()),
        [0x81] => Ok(builder.push_int(-1).into_script()),
        _ => {
            let push = PushBytesBuf::try_from(payload.to_vec())
                .map_err(|_| CanonicalOpReturnError::PayloadTooLarge)?;
            Ok(builder.push_slice(push).into_script())
        }
    }
}

/// Bind the PSBT's ordered output set to `spend`. Exact-set and exact-order:
/// VOUT0 is the certified payout; optional VOUT1 is one non-zero change output
/// to `descriptor_spk`; the final output is the certified zero-value memo.
///
/// # Errors
/// [`GateRejection`] (`spend.mismatch_code` / `psbt_unexpected_output`) on a
/// wrong payout, memo, change, output count, or ordering.
pub fn bind_outputs_to_cert(
    psbt: &Psbt,
    descriptor_spk: &bitcoin::ScriptBuf,
    spend: &CertifiedSpend,
) -> Result<(), GateRejection> {
    let outputs = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|output| UtxoOutputRef::new(output.value.to_sat(), &output.script_pubkey))
        .collect::<Vec<_>>();
    bind_transparent_outputs_to_cert(&outputs, descriptor_spk, spend)
}

/// Bind an ordered transparent output set to a certified payout, optional
/// custody change, and one canonical memo output.
///
/// # Errors
/// [`GateRejection`] on a wrong payout, memo, change, output count, or order.
pub fn bind_transparent_outputs_to_cert(
    outputs: &[UtxoOutputRef<'_>],
    descriptor_spk: &bitcoin::ScriptBuf,
    spend: &CertifiedSpend,
) -> Result<(), GateRejection> {
    let want_sats = u64::try_from(spend.amount).map_err(|_| {
        GateRejection::unprocessable(
            spend.mismatch_code,
            "certified amount does not fit u64 sats",
        )
    })?;
    if !(2..=3).contains(&outputs.len()) {
        return Err(GateRejection::unprocessable(
            spend.mismatch_code,
            format!(
                "THORChain UTXO spend must have exactly 2 outputs (no change) or 3 outputs (with change), found {}",
                outputs.len()
            ),
        ));
    }

    let payout = &outputs[0];
    if payout.script_pubkey.is_op_return()
        || keccak256(payout.script_pubkey.as_bytes()) != spend.immediate_target_hash
    {
        return Err(GateRejection::unprocessable(
            spend.mismatch_code,
            "VOUT0 is not the certified Asgard payout",
        ));
    }
    if payout.value != want_sats {
        return Err(GateRejection::unprocessable(
            spend.mismatch_code,
            format!(
                "VOUT0 pays {} sats, certificate authorizes {want_sats}",
                payout.value
            ),
        ));
    }

    if outputs.len() == 3 {
        let change = &outputs[1];
        if change.script_pubkey.is_op_return()
            || change.script_pubkey.as_bytes() != descriptor_spk.as_bytes()
            || change.value == 0
        {
            return Err(GateRejection::unprocessable(
                error_codes::PSBT_UNEXPECTED_OUTPUT,
                "VOUT1 must be one non-zero change output back to the VIN0 custody scriptPubKey",
            ));
        }
    }

    let memo_index = outputs.len() - 1;
    let memo = &outputs[memo_index];
    if !memo.script_pubkey.is_op_return() {
        return Err(GateRejection::unprocessable(
            spend.mismatch_code,
            format!("VOUT{memo_index} is not the THORChain OP_RETURN memo"),
        ));
    }
    if memo.value != 0 {
        return Err(GateRejection::unprocessable(
            spend.mismatch_code,
            "OP_RETURN output carries value (memo outputs must be zero-value)",
        ));
    }
    let payload = parse_canonical_op_return_payload(memo.script_pubkey).map_err(|error| {
        GateRejection::unprocessable(
            spend.mismatch_code,
            format!("non-canonical OP_RETURN memo: {error}"),
        )
    })?;
    if keccak256(payload.as_ref()) != spend.memo_hash {
        return Err(GateRejection::unprocessable(
            spend.mismatch_code,
            "OP_RETURN payload does not hash to the certified memo",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, U256};
    use bitcoin::psbt::Psbt;
    use bitcoin::script::PushBytesBuf;
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, ScriptBuf, Transaction, TxOut,
    };

    const MEMO: &[u8] = b"=:ETH.USDT:0xrecipient:990000";

    fn spk(tag: u8) -> ScriptBuf {
        let mut bytes = vec![0x00, 0x14];
        bytes.extend_from_slice(&[tag; 20]);
        ScriptBuf::from_bytes(bytes)
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn memo_output() -> TxOut {
        let push = PushBytesBuf::try_from(MEMO.to_vec()).expect("push bytes");
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(push),
        }
    }

    fn memo_output_with_script(bytes: Vec<u8>) -> TxOut {
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(bytes),
        }
    }

    fn output(value: u64, script_pubkey: ScriptBuf) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        }
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn psbt(outputs: Vec<TxOut>) -> Psbt {
        Psbt::from_unsigned_tx(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: outputs,
        })
        .expect("unsigned psbt")
    }

    fn spend(payout: &ScriptBuf) -> CertifiedSpend {
        CertifiedSpend {
            amount: U256::from(100_000u64),
            immediate_target_hash: keccak256(payout.as_bytes()),
            memo_hash: keccak256(MEMO),
            mismatch_code: "intent_mismatch",
        }
    }

    #[test]
    fn canonical_payout_change_memo_order_passes() {
        let payout = spk(0xaa);
        let change = spk(0xcc);
        let candidate = psbt(vec![
            output(100_000, payout.clone()),
            output(50_000, change.clone()),
            memo_output(),
        ]);
        assert!(bind_outputs_to_cert(&candidate, &change, &spend(&payout)).is_ok());
    }

    #[test]
    fn no_change_payout_memo_order_passes() {
        let payout = spk(0xaa);
        let change = spk(0xcc);
        let candidate = psbt(vec![output(100_000, payout.clone()), memo_output()]);
        assert!(bind_outputs_to_cert(&candidate, &change, &spend(&payout)).is_ok());
    }

    #[test]
    fn memo_before_change_is_rejected() {
        let payout = spk(0xaa);
        let change = spk(0xcc);
        let candidate = psbt(vec![
            output(100_000, payout.clone()),
            memo_output(),
            output(50_000, change.clone()),
        ]);
        assert!(bind_outputs_to_cert(&candidate, &change, &spend(&payout)).is_err());
    }

    #[test]
    fn payout_not_at_vout0_is_rejected() {
        let payout = spk(0xaa);
        let change = spk(0xcc);
        let candidate = psbt(vec![memo_output(), output(100_000, payout.clone())]);
        assert!(bind_outputs_to_cert(&candidate, &change, &spend(&payout)).is_err());
    }

    #[test]
    fn second_change_output_is_rejected() {
        let payout = spk(0xaa);
        let change = spk(0xcc);
        let candidate = psbt(vec![
            output(100_000, payout.clone()),
            output(25_000, change.clone()),
            output(25_000, change.clone()),
            memo_output(),
        ]);
        assert!(bind_outputs_to_cert(&candidate, &change, &spend(&payout)).is_err());
    }

    #[test]
    fn zero_value_change_output_is_rejected() {
        let payout = spk(0xaa);
        let change = spk(0xcc);
        let candidate = psbt(vec![
            output(100_000, payout.clone()),
            output(0, change.clone()),
            memo_output(),
        ]);
        assert!(bind_outputs_to_cert(&candidate, &change, &spend(&payout)).is_err());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn duplicate_memo_is_rejected() {
        let payout = spk(0xaa);
        let change = spk(0xcc);
        let candidate = psbt(vec![
            output(100_000, payout.clone()),
            memo_output(),
            memo_output(),
        ]);
        let error = bind_outputs_to_cert(&candidate, &change, &spend(&payout))
            .expect_err("duplicate memo must fail");
        assert_eq!(error.code, "psbt_unexpected_output");
    }

    #[test]
    fn wrong_memo_hash_is_rejected() {
        let payout = spk(0xaa);
        let change = spk(0xcc);
        let mut certified = spend(&payout);
        certified.memo_hash = B256::repeat_byte(0xee);
        let candidate = psbt(vec![output(100_000, payout), memo_output()]);
        assert!(bind_outputs_to_cert(&candidate, &change, &certified).is_err());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn noncanonical_memo_scripts_are_rejected() {
        let memo_len = u8::try_from(MEMO.len()).expect("memo fits one-byte length");
        let mut inserted_opcode = vec![0x6a, 0x61, memo_len];
        inserted_opcode.extend_from_slice(MEMO);

        let mut split_push = vec![0x6a, 0x01, MEMO[0], memo_len - 1];
        split_push.extend_from_slice(&MEMO[1..]);

        let mut trailing_opcode = vec![0x6a, memo_len];
        trailing_opcode.extend_from_slice(MEMO);
        trailing_opcode.push(0x61);

        let mut pushdata1 = vec![0x6a, 0x4c, memo_len];
        pushdata1.extend_from_slice(MEMO);

        let mut pushdata2 = vec![0x6a, 0x4d, memo_len, 0x00];
        pushdata2.extend_from_slice(MEMO);

        let mut pushdata4 = vec![0x6a, 0x4e, memo_len, 0x00, 0x00, 0x00];
        pushdata4.extend_from_slice(MEMO);

        let payout = spk(0xaa);
        let change = spk(0xcc);
        let certified = spend(&payout);
        for script in [
            inserted_opcode,
            split_push,
            trailing_opcode,
            pushdata1,
            pushdata2,
            pushdata4,
        ] {
            let candidate = psbt(vec![
                output(100_000, payout.clone()),
                memo_output_with_script(script),
            ]);
            assert!(
                bind_outputs_to_cert(&candidate, &change, &certified).is_err(),
                "noncanonical OP_RETURN script was accepted"
            );
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn canonical_push_boundaries_use_the_unique_minimal_opcode() {
        let cases = [
            (1usize, vec![0x6a, 0x01]),
            (75, vec![0x6a, 0x4b]),
            (76, vec![0x6a, 0x4c, 0x4c]),
            (255, vec![0x6a, 0x4c, 0xff]),
            (256, vec![0x6a, 0x4d, 0x00, 0x01]),
            (65_535, vec![0x6a, 0x4d, 0xff, 0xff]),
            (65_536, vec![0x6a, 0x4e, 0x00, 0x00, 0x01, 0x00]),
        ];

        for (length, prefix) in cases {
            let payload = vec![0x20; length];
            let script = canonical_op_return_script(&payload).expect("canonical script");
            assert!(script.as_bytes().starts_with(&prefix));
            assert_eq!(
                parse_canonical_op_return_payload(&script)
                    .expect("canonical payload")
                    .as_ref(),
                payload
            );
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn small_script_numbers_use_their_dedicated_push_opcodes() {
        for (payload, opcode) in [([0x01], 0x51), ([0x10], 0x60), ([0x81], 0x4f)] {
            let script = canonical_op_return_script(&payload).expect("canonical script");
            assert_eq!(script.as_bytes(), [0x6a, opcode]);
            assert_eq!(
                parse_canonical_op_return_payload(&script)
                    .expect("canonical payload")
                    .as_ref(),
                payload
            );

            let direct_push = ScriptBuf::from_bytes(vec![0x6a, 0x01, payload[0]]);
            assert_eq!(
                parse_canonical_op_return_payload(&direct_push),
                Err(CanonicalOpReturnError::NonMinimalPush)
            );
        }
    }

    #[test]
    fn malformed_empty_split_and_trailing_scripts_are_rejected() {
        let cases = [
            vec![],
            vec![0x51],
            vec![0x6a],
            vec![0x6a, 0x00],
            vec![0x6a, 0x61],
            vec![0x6a, 0x01],
            vec![0x6a, 0x01, 0x20, 0x61],
            vec![0x6a, 0x01, 0x20, 0x01, 0x21],
        ];

        for bytes in cases {
            assert!(parse_canonical_op_return_payload(&ScriptBuf::from_bytes(bytes)).is_err());
        }
    }

    #[test]
    fn every_wider_than_needed_pushdata_form_is_rejected() {
        fn script_with_pushdata(opcode: u8, encoded_length: &[u8], length: usize) -> ScriptBuf {
            let mut bytes = vec![0x6a, opcode];
            bytes.extend_from_slice(encoded_length);
            bytes.extend(std::iter::repeat_n(0x20, length));
            ScriptBuf::from_bytes(bytes)
        }

        for (opcode, encoded_length, length) in [
            (0x4c, vec![0x01], 1usize),
            (0x4c, vec![0x4b], 75),
            (0x4d, vec![0x01, 0x00], 1),
            (0x4d, vec![0x4c, 0x00], 76),
            (0x4d, vec![0xff, 0x00], 255),
            (0x4e, vec![0x01, 0x00, 0x00, 0x00], 1),
            (0x4e, vec![0x4c, 0x00, 0x00, 0x00], 76),
            (0x4e, vec![0x00, 0x01, 0x00, 0x00], 256),
            (0x4e, vec![0xff, 0xff, 0x00, 0x00], 65_535),
        ] {
            assert_eq!(
                parse_canonical_op_return_payload(&script_with_pushdata(
                    opcode,
                    &encoded_length,
                    length,
                )),
                Err(CanonicalOpReturnError::NonMinimalPush)
            );
        }
    }
}
