//! XRPL canonical `STObject` binary serialization — the byte-exact
//! surface (the XRP analogue of Cosmos amino-JSON).
//!
//! Narrow subset: only the fields a `Payment` or `SignerListSet`
//! transaction uses. Every constant is pinned from rippled `develop` +
//! `ripple-binary-codec`, cross-checked against `THORChain`'s production
//! XRP keymanager (see the §9.3 sourced single-sign vector in
//! `tx::tests`). A single wrong byte makes a signature silently invalid;
//! the multisign path additionally has **no thornode reference** and is
//! gated on a rippled byte-match before mainnet (`KNOWN_FINDINGS` P4.4-1).
//!
//! ## The named footguns (mirrors Cosmos DL-P3.3-3)
//!
//! - Fields sort by the numeric `(type_code, field_code)` PAIR, **not**
//!   by a byte-wise compare of the multi-byte Field-ID header.
//! - The top-level transaction object emits NO end marker; nested
//!   objects inside an array emit [`OBJECT_END`], arrays emit
//!   [`ARRAY_END`].
//! - Native XRP `Amount` is `drops | POSITIVE` in a fixed 8-byte field;
//!   drops occupy the low 61 bits (bit `0x20…` is the MPT flag, must be
//!   0 for XRP).

// ─── Type codes (`SerializedType`) ─────────────────────────────────────
pub(crate) const T_UINT16: u8 = 1;
pub(crate) const T_UINT32: u8 = 2;
pub(crate) const T_AMOUNT: u8 = 6;
pub(crate) const T_BLOB: u8 = 7;
pub(crate) const T_ACCOUNT: u8 = 8;
pub(crate) const T_OBJECT: u8 = 14;
pub(crate) const T_ARRAY: u8 = 15;

// ─── Field codes (`nth`) for the Payment + SignerListSet subset ─────────
pub(crate) const F_TRANSACTION_TYPE: u8 = 2; // UInt16
pub(crate) const F_SEQUENCE: u8 = 4; // UInt32
pub(crate) const F_LAST_LEDGER_SEQUENCE: u8 = 27; // UInt32
pub(crate) const F_NETWORK_ID: u8 = 1; // UInt32 (only when network id > 1024)
pub(crate) const F_SIGNER_QUORUM: u8 = 35; // UInt32
pub(crate) const F_AMOUNT: u8 = 1; // Amount
pub(crate) const F_FEE: u8 = 8; // Amount
pub(crate) const F_SIGNING_PUBKEY: u8 = 3; // Blob
pub(crate) const F_TXN_SIGNATURE: u8 = 4; // Blob (single-sign only)
pub(crate) const F_MEMO_DATA: u8 = 13; // Blob
pub(crate) const F_SIGNER_WEIGHT: u8 = 3; // UInt16
pub(crate) const F_ACCOUNT: u8 = 1; // AccountID
pub(crate) const F_DESTINATION: u8 = 3; // AccountID
pub(crate) const F_SIGNERS: u8 = 3; // STArray
pub(crate) const F_SIGNER: u8 = 16; // STObject
pub(crate) const F_SIGNER_ENTRIES: u8 = 4; // STArray
pub(crate) const F_SIGNER_ENTRY: u8 = 11; // STObject
pub(crate) const F_MEMOS: u8 = 9; // STArray
pub(crate) const F_MEMO: u8 = 10; // STObject

/// `STObject` end marker = field id of `(14, 1)`.
pub(crate) const OBJECT_END: u8 = 0xE1;
/// `STArray` end marker = field id of `(15, 1)`.
pub(crate) const ARRAY_END: u8 = 0xF1;

/// `TransactionType` enum value for `Payment`.
pub(crate) const TX_PAYMENT: u16 = 0;
/// `TransactionType` enum value for `SignerListSet`.
pub(crate) const TX_SIGNER_LIST_SET: u16 = 12;

/// Native-XRP `Amount` "is positive" flag (bit `0x40…`). Bit `0x80…`
/// (issued currency) and bit `0x20…` (MPT) stay 0 for XRP.
pub(crate) const AMOUNT_POSITIVE: u64 = 0x4000_0000_0000_0000;

/// Total XRP supply in drops (1e17). No valid native-XRP amount exceeds
/// this; a larger value (≥ 2^57) is well below the type-flag bits
/// (61/62/63), so this bound conservatively guarantees the drops never
/// collide with the `AMOUNT_POSITIVE` / issued-currency / MPT flags.
pub(crate) const MAX_XRP_DROPS: u64 = 100_000_000_000_000_000;

/// One serialized field: its sort key `(type_code, field_code)` and the
/// already-encoded payload (NOT including the field-id header).
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_field_names,
    reason = "XRPL terminology: a serialized field is identified by a type_code and a field_code"
)]
pub(crate) struct Field {
    type_code: u8,
    field_code: u8,
    payload: Vec<u8>,
}

impl Field {
    pub(crate) fn new(type_code: u8, field_code: u8, payload: Vec<u8>) -> Self {
        Self {
            type_code,
            field_code,
            payload,
        }
    }
}

/// Encode a field-id header from `(type_code, field_code)` per the
/// rippled `addFieldID` rule. The subset only ever hits the two
/// `type < 16` branches (type codes are ≤ 15); the `type ≥ 16` branches
/// are included for completeness and exercised by a unit test.
pub(crate) fn field_id(type_code: u8, field_code: u8) -> Vec<u8> {
    if type_code < 16 && field_code < 16 {
        vec![(type_code << 4) | field_code]
    } else if type_code < 16 {
        vec![type_code << 4, field_code]
    } else if field_code < 16 {
        vec![field_code, type_code]
    } else {
        vec![0x00, type_code, field_code]
    }
}

/// XRPL variable-length (`Blob` / `AccountID`) length prefix. Three
/// ranges; `len > 918_744` is invalid (returns `None`).
#[expect(
    clippy::cast_possible_truncation,
    reason = "every byte is range-guarded < 256: len<=192; (l>>8)+193<=240 and l&0xFF<=255; \
              (l>>16)+241<=254 and the masked &0xFF bytes <=255"
)]
pub(crate) fn vl_prefix(len: usize) -> Option<Vec<u8>> {
    if len <= 192 {
        Some(vec![len as u8])
    } else if len <= 12_480 {
        let l = len - 193;
        Some(vec![((l >> 8) + 193) as u8, (l & 0xFF) as u8])
    } else if len <= 918_744 {
        let l = len - 12_481;
        Some(vec![
            ((l >> 16) + 241) as u8,
            ((l >> 8) & 0xFF) as u8,
            (l & 0xFF) as u8,
        ])
    } else {
        None
    }
}

/// A `UInt16` payload (big-endian, 2 bytes).
pub(crate) fn u16_payload(v: u16) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

/// A `UInt32` payload (big-endian, 4 bytes).
pub(crate) fn u32_payload(v: u32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

/// A native-XRP `Amount` payload: `(drops | POSITIVE)` big-endian, fixed
/// 8 bytes, no VL prefix. Returns `None` if `drops` exceeds
/// [`MAX_XRP_DROPS`] — a value that high would corrupt the type-flag bits
/// (silently encoding an issued-currency / MPT amount).
pub(crate) fn amount_payload(drops: u64) -> Option<Vec<u8>> {
    if drops > MAX_XRP_DROPS {
        return None;
    }
    Some((drops | AMOUNT_POSITIVE).to_be_bytes().to_vec())
}

/// A `Blob` (VL) payload: length prefix ‖ data. A 33-byte pubkey or a
/// DER signature always fits the single-byte range; a `THORChain` memo
/// (≤ a few hundred bytes) may use the 2-byte range.
pub(crate) fn vl_payload(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = vl_prefix(data.len())?;
    out.extend_from_slice(data);
    Some(out)
}

/// An `AccountID` payload: the fixed `0x14` (=20) VL prefix ‖ the 20-byte
/// `AccountID`. Cannot fail (length is constant), so no `Option`.
pub(crate) fn account_payload(account_id: &[u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(21);
    out.push(0x14);
    out.extend_from_slice(account_id);
    out
}

/// Serialize a flat object: sort its fields by `(type_code, field_code)`
/// ascending and concatenate `field_id ‖ payload`. Emits **no** end
/// marker — the caller adds [`OBJECT_END`] for nested objects.
pub(crate) fn serialize_fields(mut fields: Vec<Field>) -> Vec<u8> {
    fields.sort_by_key(|f| (u16::from(f.type_code) << 8) | u16::from(f.field_code));
    let mut out = Vec::new();
    for f in fields {
        out.extend_from_slice(&field_id(f.type_code, f.field_code));
        out.extend_from_slice(&f.payload);
    }
    out
}

/// One element of an `STArray`: `field_id(elem) ‖ serialize_fields(inner)
/// ‖ OBJECT_END`.
pub(crate) fn array_element(elem_type: u8, elem_field: u8, inner: Vec<Field>) -> Vec<u8> {
    let mut out = field_id(elem_type, elem_field);
    out.extend_from_slice(&serialize_fields(inner));
    out.push(OBJECT_END);
    out
}

/// An `STArray` field payload: the concatenated [`array_element`]s
/// followed by [`ARRAY_END`].
pub(crate) fn array_payload(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut out: Vec<u8> = elements.concat();
    out.push(ARRAY_END);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_id_one_byte_both_small() {
        // Amount (6,1) → 0x61; Fee (6,8) → 0x68; STObject end (14,1) → 0xE1.
        assert_eq!(field_id(T_AMOUNT, F_AMOUNT), vec![0x61]);
        assert_eq!(field_id(T_AMOUNT, F_FEE), vec![0x68]);
        assert_eq!(field_id(T_OBJECT, 1), vec![OBJECT_END]);
        assert_eq!(field_id(T_ARRAY, 1), vec![ARRAY_END]);
    }

    #[test]
    fn field_id_two_byte_large_field() {
        // LastLedgerSequence (2,27) → 20 1B; SignerQuorum (2,35) → 20 23;
        // Signer (14,16) → E0 10.
        assert_eq!(field_id(T_UINT32, F_LAST_LEDGER_SEQUENCE), vec![0x20, 0x1B]);
        assert_eq!(field_id(T_UINT32, F_SIGNER_QUORUM), vec![0x20, 0x23]);
        assert_eq!(field_id(T_OBJECT, F_SIGNER), vec![0xE0, 0x10]);
    }

    #[test]
    fn field_id_high_type_branches() {
        // Completeness: type ≥ 16 branches (not used by the subset).
        assert_eq!(field_id(18, 3), vec![0x03, 18]);
        assert_eq!(field_id(18, 20), vec![0x00, 18, 20]);
    }

    #[test]
    fn amount_encodes_positive_flag() {
        // 1,000,000 drops → 0x40000000000F4240 (spec §3 worked example).
        assert_eq!(
            amount_payload(1_000_000),
            Some(vec![0x40, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x42, 0x40])
        );
        // 24,528,352 drops → 0x4000000001 7645E0.
        assert_eq!(
            amount_payload(24_528_352),
            Some(vec![0x40, 0x00, 0x00, 0x00, 0x01, 0x76, 0x45, 0xE0])
        );
        // The supply cap encodes; one drop above it is rejected.
        assert!(amount_payload(MAX_XRP_DROPS).is_some());
        assert_eq!(amount_payload(MAX_XRP_DROPS + 1), None);
    }

    #[test]
    fn vl_prefix_three_ranges() {
        assert_eq!(vl_prefix(0), Some(vec![0]));
        assert_eq!(vl_prefix(33), Some(vec![33]));
        assert_eq!(vl_prefix(192), Some(vec![192]));
        // 193 → first 2-byte value: ((193-193)>>8)+193=193, (0)&0xFF=0.
        assert_eq!(vl_prefix(193), Some(vec![193, 0]));
        assert_eq!(vl_prefix(12_480), Some(vec![240, 255]));
        // 12_481 → first 3-byte value.
        assert_eq!(vl_prefix(12_481), Some(vec![241, 0, 0]));
        // 918_744 (the max): l = 906_263 → [254, 212, 23].
        assert_eq!(vl_prefix(918_744), Some(vec![254, 212, 23]));
        assert_eq!(vl_prefix(918_745), None);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn serialize_fields_sorts_by_type_then_field() {
        // Out-of-order insert; expect (1,2) < (2,4) < (6,1) by (type,field).
        let out = serialize_fields(vec![
            Field::new(T_AMOUNT, F_AMOUNT, amount_payload(1).expect("in range")),
            Field::new(T_UINT16, F_TRANSACTION_TYPE, u16_payload(0)),
            Field::new(T_UINT32, F_SEQUENCE, u32_payload(7)),
        ]);
        // 12 0000 | 24 00000007 | 61 4000000000000001
        assert_eq!(
            out,
            vec![
                0x12, 0x00, 0x00, // TransactionType=0
                0x24, 0x00, 0x00, 0x00, 0x07, // Sequence=7
                0x61, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Amount=1
            ]
        );
    }
}
