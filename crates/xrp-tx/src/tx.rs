//! High-level XRPL transaction builders: `Payment` (the custody redeem
//! leg) and `SignerListSet` (the one-time `SignerList` ceremony, used by
//! ceremony tooling only — never the redeem path).
//!
//! The redeem flow:
//!   1. [`serialize_for_multisign`] → the shared body (empty
//!      `SigningPubKey`, no `Signers`) that goes on the wire as
//!      `signing_blob`; each signer hashes `SMT\0 ‖ body ‖ own-AccountID`
//!      (see [`crate::signing`]).
//!   2. [`crate::sigs::aggregate_verified`] verifies the partials and
//!      returns AccountID-sorted signers.
//!   3. [`build_signed_multisig_tx`] inserts the `Signers` array (in
//!      canonical position) and serializes the submittable tx-blob.

use crate::st::{
    account_payload, amount_payload, array_element, array_payload, serialize_fields, u16_payload,
    u32_payload, vl_payload, Field, F_ACCOUNT, F_AMOUNT, F_DESTINATION, F_FEE,
    F_LAST_LEDGER_SEQUENCE, F_MEMO, F_MEMOS, F_MEMO_DATA, F_NETWORK_ID, F_SEQUENCE, F_SIGNER,
    F_SIGNERS, F_SIGNER_ENTRIES, F_SIGNER_ENTRY, F_SIGNER_QUORUM, F_SIGNER_WEIGHT,
    F_SIGNING_PUBKEY, F_TRANSACTION_TYPE, F_TXN_SIGNATURE, TX_PAYMENT, TX_SIGNER_LIST_SET,
    T_ACCOUNT, T_AMOUNT, T_ARRAY, T_BLOB, T_OBJECT, T_UINT16, T_UINT32,
};
use crate::VerifiedSigner;

/// Errors building a transaction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxError {
    /// A variable-length field (memo / signature) exceeded the XRPL VL
    /// maximum (918,744 bytes). Indicates a malformed input.
    #[error("variable-length field too long")]
    FieldTooLong,
    /// An `Amount` / `Fee` exceeded the XRP supply cap (1e17 drops) and
    /// would corrupt the `Amount` type-flag bits. Rejected, not encoded.
    #[error("amount out of range: {0} drops > 1e17")]
    AmountOutOfRange(u64),
}

/// The semantic inputs to a custody `Payment`. Amounts are in drops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentBody {
    /// Sending account (our `SignerList` multisig) `AccountID`.
    pub account: [u8; 20],
    /// Recipient (`THORChain` Asgard inbound) `AccountID`.
    pub destination: [u8; 20],
    /// `Amount` in drops.
    pub amount_drops: u64,
    /// `Fee` in drops (`base_fee × (1 + signer_count)` for multisign).
    pub fee_drops: u64,
    /// `Sequence` (account nonce).
    pub sequence: u32,
    /// `LastLedgerSequence` (tx expiry); `None` omits the field.
    pub last_ledger_sequence: Option<u32>,
    /// `NetworkID`; `None` for mainnet/testnet (only networks with id >
    /// 1024 carry it). Present in the §9.3 mocknet test vector.
    pub network_id: Option<u32>,
    /// Raw `THORChain` memo bytes (placed in `Memos[0].MemoData`).
    pub memo: Vec<u8>,
}

/// Build the canonical `Memos` array field with a single
/// `MemoData`-only memo (matching `THORChain`'s XRP client).
fn memos_field(memo: &[u8]) -> Result<Field, TxError> {
    let data = vl_payload(memo).ok_or(TxError::FieldTooLong)?;
    let memo_data = Field::new(T_BLOB, F_MEMO_DATA, data);
    let element = array_element(T_OBJECT, F_MEMO, vec![memo_data]);
    Ok(Field::new(T_ARRAY, F_MEMOS, array_payload(&[element])))
}

/// Build the `Signers` array field from AccountID-sorted verified
/// signers. Defensively re-sorts so the wire invariant holds even if a
/// caller passes them unsorted.
fn signers_field(signers: &[VerifiedSigner]) -> Result<Field, TxError> {
    let mut sorted: Vec<&VerifiedSigner> = signers.iter().collect();
    sorted.sort_by_key(|v| v.account_id);
    let mut elements: Vec<Vec<u8>> = Vec::with_capacity(sorted.len());
    for s in sorted {
        let pubkey = vl_payload(&s.pubkey).ok_or(TxError::FieldTooLong)?;
        let sig = vl_payload(&s.der).ok_or(TxError::FieldTooLong)?;
        let inner = vec![
            Field::new(T_BLOB, F_SIGNING_PUBKEY, pubkey),
            Field::new(T_BLOB, F_TXN_SIGNATURE, sig),
            Field::new(T_ACCOUNT, F_ACCOUNT, account_payload(&s.account_id)),
        ];
        elements.push(array_element(T_OBJECT, F_SIGNER, inner));
    }
    Ok(Field::new(T_ARRAY, F_SIGNERS, array_payload(&elements)))
}

/// Assemble the `Payment` field set. `signing_pubkey` is empty for the
/// multisign body and the final multisigned tx; populated only for the
/// single-sign reference path. `signers` is `Some` only for the final
/// assembled tx (omitted from the signing body — `Signers` is
/// `kNotSigning`).
fn payment_fields(
    body: &PaymentBody,
    signing_pubkey: &[u8],
    signers: Option<&[VerifiedSigner]>,
) -> Result<Vec<Field>, TxError> {
    let pubkey = vl_payload(signing_pubkey).ok_or(TxError::FieldTooLong)?;
    let amount =
        amount_payload(body.amount_drops).ok_or(TxError::AmountOutOfRange(body.amount_drops))?;
    let fee = amount_payload(body.fee_drops).ok_or(TxError::AmountOutOfRange(body.fee_drops))?;
    let mut fields = vec![
        Field::new(T_UINT16, F_TRANSACTION_TYPE, u16_payload(TX_PAYMENT)),
        Field::new(T_UINT32, F_SEQUENCE, u32_payload(body.sequence)),
        Field::new(T_AMOUNT, F_AMOUNT, amount),
        Field::new(T_AMOUNT, F_FEE, fee),
        Field::new(T_BLOB, F_SIGNING_PUBKEY, pubkey),
        Field::new(T_ACCOUNT, F_ACCOUNT, account_payload(&body.account)),
        Field::new(T_ACCOUNT, F_DESTINATION, account_payload(&body.destination)),
    ];
    // Omit the `Memos` field entirely when the memo is empty (rippled /
    // thornode emit no Memos array, not an empty one).
    if !body.memo.is_empty() {
        fields.push(memos_field(&body.memo)?);
    }
    if let Some(nid) = body.network_id {
        fields.push(Field::new(T_UINT32, F_NETWORK_ID, u32_payload(nid)));
    }
    if let Some(lls) = body.last_ledger_sequence {
        fields.push(Field::new(
            T_UINT32,
            F_LAST_LEDGER_SEQUENCE,
            u32_payload(lls),
        ));
    }
    if let Some(sigs) = signers {
        fields.push(signers_field(sigs)?);
    }
    Ok(fields)
}

/// Serialize the SHARED multisign body: the `Payment` with an EMPTY
/// `SigningPubKey`, no `TxnSignature`, no `Signers`. This is what goes on
/// the wire as `signing_blob` and what every signer hashes (with its own
/// `AccountID` suffix).
///
/// # Errors
///
/// Returns [`TxError::FieldTooLong`] if the memo exceeds the XRPL
/// variable-length maximum, or [`TxError::AmountOutOfRange`] if the
/// amount / fee exceeds the XRP supply cap.
pub fn serialize_for_multisign(body: &PaymentBody) -> Result<Vec<u8>, TxError> {
    Ok(serialize_fields(payment_fields(body, &[], None)?))
}

/// Assemble the final submittable multisigned tx-blob: the `Payment`
/// (empty top-level `SigningPubKey`) plus the `AccountID`-sorted `Signers`
/// array, no top-level `TxnSignature`.
///
/// # Errors
///
/// Returns [`TxError::FieldTooLong`] if the memo or any signer's pubkey /
/// signature exceeds the XRPL variable-length maximum, or
/// [`TxError::AmountOutOfRange`] if the amount / fee exceeds the supply cap.
pub fn build_signed_multisig_tx(
    body: &PaymentBody,
    signers: &[VerifiedSigner],
) -> Result<Vec<u8>, TxError> {
    Ok(serialize_fields(payment_fields(body, &[], Some(signers))?))
}

/// Serialize a single-sign `Payment` body (populated `SigningPubKey`, no
/// `TxnSignature`). Used by the single-sign reference path + the §9.3
/// sourced test vector; the custody path is multisign-only.
///
/// # Errors
///
/// Returns [`TxError::FieldTooLong`] if the memo exceeds the XRPL
/// variable-length maximum, or [`TxError::AmountOutOfRange`] if the
/// amount / fee exceeds the XRP supply cap.
pub fn serialize_single_sign(
    body: &PaymentBody,
    signing_pubkey: &[u8; 33],
) -> Result<Vec<u8>, TxError> {
    Ok(serialize_fields(payment_fields(
        body,
        signing_pubkey,
        None,
    )?))
}

/// Assemble the final submittable SINGLE-sign tx-blob for a single
/// secp256k1 custody key (the Turnkey enclave key — `DL-CUSTODY-TURNKEY-1`):
/// the `Payment` with the custody `SigningPubKey` populated and a top-level
/// `TxnSignature` (the DER low-S signature over [`crate::signing::single_sign_digest`]
/// of [`serialize_single_sign`]), and NO `Signers` array. `txn_signature_der`
/// is the [`crate::sigs::der_low_s_from_rs`] form of the custody key's
/// `(r, s)`. `serialize_fields` sorts by `(type, field)`, so `TxnSignature`
/// `(7,4)` lands immediately after `SigningPubKey` `(7,3)` in canonical order.
///
/// # Errors
///
/// Returns [`TxError::FieldTooLong`] if the memo or signature exceeds the XRPL
/// variable-length maximum, or [`TxError::AmountOutOfRange`] if the amount /
/// fee exceeds the XRP supply cap.
pub fn build_signed_single_sig_tx(
    body: &PaymentBody,
    signing_pubkey: &[u8; 33],
    txn_signature_der: &[u8],
) -> Result<Vec<u8>, TxError> {
    let mut fields = payment_fields(body, signing_pubkey, None)?;
    let sig = vl_payload(txn_signature_der).ok_or(TxError::FieldTooLong)?;
    fields.push(Field::new(T_BLOB, F_TXN_SIGNATURE, sig));
    Ok(serialize_fields(fields))
}

/// One entry of a `SignerListSet` (a future signer + its weight).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerEntry {
    /// The signer's 20-byte `AccountID`.
    pub account_id: [u8; 20],
    /// The signer's weight (≥ 1).
    pub weight: u16,
}

/// Serialize a `SignerListSet` body (single-sign, populated
/// `SigningPubKey`). Ceremony tooling only — establishes the
/// `SignerList` on a freshly-funded account before `asfDisableMaster`.
/// Entries are emitted `AccountID`-sorted (gate on rippled byte-match —
/// `KNOWN_FINDINGS` P4.4-1).
///
/// # Errors
///
/// Returns [`TxError::FieldTooLong`] if the signing pubkey exceeds the
/// XRPL variable-length maximum, or [`TxError::AmountOutOfRange`] if the
/// fee exceeds the XRP supply cap.
#[expect(
    clippy::too_many_arguments,
    reason = "ceremony-only serializer; the 8 params are the distinct XRPL SignerListSet \
              transaction fields and the call signature is pinned by its test vector"
)]
pub fn serialize_signer_list_set(
    account: &[u8; 20],
    sequence: u32,
    fee_drops: u64,
    quorum: u32,
    entries: &[SignerEntry],
    signing_pubkey: &[u8; 33],
    network_id: Option<u32>,
    last_ledger_sequence: Option<u32>,
) -> Result<Vec<u8>, TxError> {
    let pubkey = vl_payload(signing_pubkey).ok_or(TxError::FieldTooLong)?;
    let mut sorted: Vec<&SignerEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| e.account_id);
    let elements: Vec<Vec<u8>> = sorted
        .iter()
        .map(|e| {
            let inner = vec![
                Field::new(T_UINT16, F_SIGNER_WEIGHT, u16_payload(e.weight)),
                Field::new(T_ACCOUNT, F_ACCOUNT, account_payload(&e.account_id)),
            ];
            array_element(T_OBJECT, F_SIGNER_ENTRY, inner)
        })
        .collect();
    let fee = amount_payload(fee_drops).ok_or(TxError::AmountOutOfRange(fee_drops))?;
    let mut fields = vec![
        Field::new(
            T_UINT16,
            F_TRANSACTION_TYPE,
            u16_payload(TX_SIGNER_LIST_SET),
        ),
        Field::new(T_UINT32, F_SEQUENCE, u32_payload(sequence)),
        Field::new(T_UINT32, F_SIGNER_QUORUM, u32_payload(quorum)),
        Field::new(T_AMOUNT, F_FEE, fee),
        Field::new(T_BLOB, F_SIGNING_PUBKEY, pubkey),
        Field::new(T_ACCOUNT, F_ACCOUNT, account_payload(account)),
        Field::new(T_ARRAY, F_SIGNER_ENTRIES, array_payload(&elements)),
    ];
    if let Some(nid) = network_id {
        fields.push(Field::new(T_UINT32, F_NETWORK_ID, u32_payload(nid)));
    }
    if let Some(lls) = last_ledger_sequence {
        fields.push(Field::new(
            T_UINT32,
            F_LAST_LEDGER_SEQUENCE,
            u32_payload(lls),
        ));
    }
    Ok(serialize_fields(fields))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::single_sign_digest;

    #[expect(clippy::expect_used, reason = "test code")]
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }
    fn unhex_n<const N: usize>(s: &str) -> [u8; N] {
        let v = unhex(s);
        let mut out = [0u8; N];
        out.copy_from_slice(&v);
        out
    }
    fn hexs(b: &[u8]) -> String {
        use std::fmt::Write as _;
        b.iter()
            .fold(String::with_capacity(b.len() * 2), |mut acc, x| {
                let _ = write!(acc, "{x:02x}");
                acc
            })
    }

    /// §9.3 SOURCED vector from `THORChain` `client_test.go` — the single
    /// most valuable cross-check. Reconstruct the exact mocknet Payment
    /// and assert (a) our serialization reproduces the sourced signing
    /// body byte-for-byte, and (b) the sourced REAL DER signature
    /// verifies against our `SHA512Half` digest. This pins field ordering,
    /// field-id encoding, Amount, VL, `AccountID`, and Memos all at once.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn single_sign_body_matches_thornode_sourced_vector() {
        let pubkey: [u8; 33] =
            unhex_n("030cef2112503d3a56d2d48b3a0f0f6503e4353400f450f9dbf344d182e7c7069c");
        let body = PaymentBody {
            account: unhex_n("d4b66bcf790babd0032c5dbfdc14ff1c643a4f48"),
            destination: unhex_n("fdffd00f2f2d215ecdad483b99be1dad2259b9c3"),
            amount_drops: 24_528_352,
            fee_drops: 750_000,
            sequence: 1,
            last_ledger_sequence: None,
            network_id: Some(1234),
            memo: b"memo".to_vec(),
        };
        let serialized = serialize_single_sign(&body, &pubkey).expect("serialize");
        let expected = "12000021000004d224000000016140000000017645e06840000000000b71b07321030cef2112503d3a56d2d48b3a0f0f6503e4353400f450f9dbf344d182e7c7069c8114d4b66bcf790babd0032c5dbfdc14ff1c643a4f488314fdffd00f2f2d215ecdad483b99be1dad2259b9c3f9ea7d046d656d6fe1f1";
        assert_eq!(
            hexs(&serialized),
            expected,
            "serialization must match thornode signBytes body"
        );

        // The full signBytes = STX prefix ‖ body. Verify the SOURCED DER
        // signature against our digest — proves the whole pipeline.
        let der = unhex("30440221008e9bc0a8d7927f1874d318bc2a57691b5321d618dd57857d64402be0e0bc0007021f4ab281ef93b0c448a9e75d6c07e9cf05ee705a3c51aafa61992510b65a03ae");
        let digest = single_sign_digest(&serialized);
        crate::sigs::verify_der(&pubkey, &digest, &der)
            .expect("sourced thornode signature must verify against our digest");
    }

    /// The multisign body omits `Signers` and carries an EMPTY
    /// `SigningPubKey` (`7300`), while the assembled tx inserts the
    /// `Signers` array in canonical position (before `Memos`).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn multisign_body_has_empty_pubkey_and_no_signers() {
        let body = PaymentBody {
            account: [0x11; 20],
            destination: [0x22; 20],
            amount_drops: 1_000_000,
            fee_drops: 30,
            sequence: 5,
            last_ledger_sequence: Some(9_000_005),
            network_id: None,
            memo: b"=:ETH.USDT:0xabc:0".to_vec(),
        };
        let serialized = serialize_for_multisign(&body).expect("serialize");
        let hex = hexs(&serialized);
        // Empty SigningPubKey present as 7300.
        assert!(hex.contains("7300"), "empty SigningPubKey must be 7300");
        // No Signers (F3) in the signing body.
        assert!(
            !hex.contains("f3"),
            "Signers must be absent from signing body"
        );
        // LastLedgerSequence present (201b).
        assert!(hex.contains("201b"), "LastLedgerSequence field id");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn assembled_tx_inserts_signers_before_memos() {
        let body = PaymentBody {
            account: [0x11; 20],
            destination: [0x22; 20],
            amount_drops: 1_000_000,
            fee_drops: 60,
            sequence: 5,
            last_ledger_sequence: None,
            network_id: None,
            memo: b"m".to_vec(),
        };
        // Two fake-but-well-formed signers (sorted by account id).
        let mut s1 = VerifiedSigner {
            account_id: [0x01; 20],
            pubkey: [0x02; 33],
            der: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        };
        let mut s2 = s1.clone();
        s2.account_id = [0x09; 20];
        // pubkey must be valid for serialization (no validation here); the
        // VL just wraps bytes, so any 33-byte slice is fine for layout.
        s1.pubkey[0] = 0x02;
        s2.pubkey[0] = 0x03;
        let tx = build_signed_multisig_tx(&body, &[s2.clone(), s1.clone()]).expect("assemble");
        let hex = hexs(&tx);
        // Signers array (f3) appears, and before Memos (f9).
        let f3 = hex.find("f3e0").expect("Signers array start");
        let f9 = hex.find("f9ea").expect("Memos array start");
        assert!(
            f3 < f9,
            "Signers (f3) must precede Memos (f9) by canonical order"
        );
        // Top-level SigningPubKey empty.
        assert!(hex.contains("7300"));
    }

    /// Single-sig assembly: the custody `SigningPubKey` is populated, a
    /// top-level `TxnSignature` follows it (canonical `(7,4)` after `(7,3)`),
    /// and there is NO `Signers` array. Uses the §9.3 sourced body + pubkey +
    /// REAL DER signature (which verifies against the single-sign digest).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn single_sig_assembly_populates_pubkey_and_txn_signature() {
        let pubkey: [u8; 33] =
            unhex_n("030cef2112503d3a56d2d48b3a0f0f6503e4353400f450f9dbf344d182e7c7069c");
        let body = PaymentBody {
            account: unhex_n("d4b66bcf790babd0032c5dbfdc14ff1c643a4f48"),
            destination: unhex_n("fdffd00f2f2d215ecdad483b99be1dad2259b9c3"),
            amount_drops: 24_528_352,
            fee_drops: 750_000,
            sequence: 1,
            last_ledger_sequence: None,
            network_id: Some(1234),
            memo: b"memo".to_vec(),
        };
        let der = unhex("30440221008e9bc0a8d7927f1874d318bc2a57691b5321d618dd57857d64402be0e0bc0007021f4ab281ef93b0c448a9e75d6c07e9cf05ee705a3c51aafa61992510b65a03ae");
        let tx = build_signed_single_sig_tx(&body, &pubkey, &der).expect("assemble");
        let hex = hexs(&tx);
        // Payment.
        assert!(hex.starts_with("120000"));
        // SigningPubKey (0x73) populated with the 33-byte (0x21) custody key.
        let pk_hex = hexs(&pubkey);
        let pk_field = format!("7321{pk_hex}");
        let pk_at = hex.find(&pk_field).expect("populated SigningPubKey");
        // TxnSignature (0x74) immediately follows SigningPubKey in canonical
        // order, carrying the DER signature.
        let sig_field = format!("74{:02x}{}", der.len(), hexs(&der));
        let sig_at = hex.find(&sig_field).expect("TxnSignature field");
        assert_eq!(
            sig_at,
            pk_at + pk_field.len(),
            "TxnSignature (7,4) must immediately follow SigningPubKey (7,3)"
        );
        // No Signers array (single-sig).
        assert!(!hex.contains("f3e0"), "single-sig tx has no Signers array");
    }

    /// P4.4-1 byte-match CLOSED (encoding): our three multisign encoders
    /// pinned byte-for-byte against xrpl.js's `ripple-binary-codec`
    /// 2.8.0 + `ripple-address-codec` 5.0.1 — the reference codec
    /// rippled validators accept from. Reference hexes generated by
    /// `tools/byte-match/xrp.mjs` over the EXACT fixtures of the two
    /// tests above: `encode(tx, SigningPubKey:"")` ↔
    /// `serialize_for_multisign`, `encodeForMultisigning(tx, signer)` ↔
    /// `multisign_blob`, `encode(tx+Signers)` ↔
    /// `build_signed_multisig_tx`. A live testnet broadcast remains
    /// rehearsal territory (P4.4-15-class), but the encoding can no
    /// longer drift silently.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn multisign_encoding_matches_xrpljs_reference() {
        // Fixture A: the multisign body.
        let body = PaymentBody {
            account: [0x11; 20],
            destination: [0x22; 20],
            amount_drops: 1_000_000,
            fee_drops: 30,
            sequence: 5,
            last_ledger_sequence: Some(9_000_005),
            network_id: None,
            memo: b"=:ETH.USDT:0xabc:0".to_vec(),
        };
        let serialized = serialize_for_multisign(&body).expect("serialize");
        assert_eq!(
            hexs(&serialized),
            "1200002400000005201b008954456140000000000f424068400000000000001e73008114111111111111111111111111111111111111111183142222222222222222222222222222222222222222f9ea7d123d3a4554482e555344543a30786162633a30e1f1",
            "multisign body must match xrpl.js encode()"
        );

        // Fixture B: the per-signer blob for signer account 0x01*20.
        let blob = crate::signing::multisign_blob(&serialized, &[0x01; 20]);
        assert_eq!(
            hexs(&blob),
            "534d54001200002400000005201b008954456140000000000f424068400000000000001e73008114111111111111111111111111111111111111111183142222222222222222222222222222222222222222f9ea7d123d3a4554482e555344543a30786162633a30e1f10101010101010101010101010101010101010101",
            "per-signer blob must match xrpl.js encodeForMultisigning()"
        );

        // Fixture C: the assembled multisigned tx (fee 60, no LLS, memo
        // "m", two sorted signers — the `assembled_tx_…` fixture).
        let assembled_body = PaymentBody {
            fee_drops: 60,
            last_ledger_sequence: None,
            memo: b"m".to_vec(),
            ..body
        };
        let mut s1 = VerifiedSigner {
            account_id: [0x01; 20],
            pubkey: [0x02; 33],
            der: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        };
        let mut s2 = s1.clone();
        s2.account_id = [0x09; 20];
        s1.pubkey[0] = 0x02;
        s2.pubkey[0] = 0x03;
        let tx = build_signed_multisig_tx(&assembled_body, &[s2, s1]).expect("assemble");
        assert_eq!(
            hexs(&tx),
            "12000024000000056140000000000f424068400000000000003c73008114111111111111111111111111111111111111111183142222222222222222222222222222222222222222f3e01073210202020202020202020202020202020202020202020202020202020202020202027408300602010102010181140101010101010101010101010101010101010101e1e01073210302020202020202020202020202020202020202020202020202020202020202027408300602010102010181140909090909090909090909090909090909090909e1f1f9ea7d016de1f1",
            "assembled multisigned tx must match xrpl.js encode() with Signers"
        );
    }

    /// C10 red-team (LOW-2): an empty memo OMITS the `Memos` field
    /// entirely (no `0xf9` field-id) — rippled / thornode emit no array,
    /// not an empty one. A non-empty memo includes it. Pins the byte-match
    /// gate (P4.4-1) against a future regression.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn empty_memo_omits_memos_field() {
        let mut body = PaymentBody {
            account: [0x11; 20],
            destination: [0x22; 20],
            amount_drops: 1_000_000,
            fee_drops: 60,
            sequence: 5,
            last_ledger_sequence: None,
            network_id: None,
            memo: Vec::new(),
        };
        let empty = hexs(&serialize_for_multisign(&body).expect("empty memo"));
        assert!(
            !empty.contains("f9"),
            "empty memo must omit the Memos field"
        );
        body.memo = b"m".to_vec();
        let present = hexs(&serialize_for_multisign(&body).expect("with memo"));
        assert!(
            present.contains("f9ea"),
            "non-empty memo must include Memos"
        );
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn signer_list_set_serializes() {
        let pubkey: [u8; 33] =
            unhex_n("030cef2112503d3a56d2d48b3a0f0f6503e4353400f450f9dbf344d182e7c7069c");
        let entries = vec![
            SignerEntry {
                account_id: [0x03; 20],
                weight: 1,
            },
            SignerEntry {
                account_id: [0x01; 20],
                weight: 1,
            },
        ];
        let out = serialize_signer_list_set(&[0xAB; 20], 3, 500, 2, &entries, &pubkey, None, None)
            .expect("serialize");
        let hex = hexs(&out);
        // TransactionType SignerListSet = 12 000c.
        assert!(hex.starts_with("12000c"));
        // SignerQuorum field id 2023, SignerEntries f4, SignerEntry eb.
        assert!(hex.contains("2023"));
        assert!(hex.contains("f4eb"));
        // Entries AccountID-sorted: 0x01.. entry before 0x03.. entry.
        let first = hex.find("8114010101").expect("entry 01");
        let second = hex.find("8114030303").expect("entry 03");
        assert!(first < second, "SignerEntries must be AccountID-sorted");
    }
}
