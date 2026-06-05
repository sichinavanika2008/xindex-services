//! Minimal hand-rolled protobuf-3 wire encoder.
//!
//! TRON's `txID = sha256(proto.Marshal(raw_data))`, so the serialized
//! `raw_data` bytes MUST match what `java-tron` / `tronweb` produce
//! byte-for-byte or the signed hash is wrong and the funds are stuck. We
//! hand-roll the exact subset of the proto-3 wire format the TRON tx
//! messages use — the same rationale as `cosmos-tx` (amino) and `xrp-tx`
//! (STObject): a narrow, audited, dependency-free byte surface validated
//! against a sourced vector (see [`crate::tx`] tests against `THORChain`'s
//! `createtransaction.json`).
//!
//! Only two wire types appear in our messages:
//! - **varint** (wire type 0) — `int64` / enum fields (`amount`,
//!   `expiration`, `timestamp`, `fee_limit`, `Permission_id`, the
//!   `ContractType`).
//! - **length-delimited** (wire type 2) — `bytes` / `string` / nested
//!   message fields (`ref_block_bytes`, `contract`, the `Any` wrapper, …).
//!
//! Canonical proto-3 rules we rely on (matching `gogo/protobuf` +
//! `protobuf-java`): fields are emitted in ascending field-number order,
//! and scalar fields equal to their default (zero / empty) are OMITTED.
//! The callers in [`crate::tx`] enforce both.

/// Protobuf wire type 0 (varint).
const WIRE_VARINT: u32 = 0;
/// Protobuf wire type 2 (length-delimited).
const WIRE_LEN: u32 = 2;

/// Append a base-128 varint (LEB128, unsigned).
pub fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

/// Append the field tag `(field_number << 3) | wire_type` as a varint.
fn tag(out: &mut Vec<u8>, field: u32, wire: u32) {
    write_varint(out, (u64::from(field) << 3) | u64::from(wire));
}

/// Append a length-delimited field (`bytes` / `string` / nested message):
/// tag, then the byte length as a varint, then the bytes.
pub fn field_bytes(out: &mut Vec<u8>, field: u32, data: &[u8]) {
    tag(out, field, WIRE_LEN);
    write_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

/// Append a varint field (`int64` / `int32` / enum).
pub fn field_varint(out: &mut Vec<u8>, field: u32, value: u64) {
    tag(out, field, WIRE_VARINT);
    write_varint(out, value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_matches_known_vectors() {
        let mut out = Vec::new();
        write_varint(&mut out, 0);
        assert_eq!(out, vec![0x00]);

        out.clear();
        write_varint(&mut out, 1);
        assert_eq!(out, vec![0x01]);

        out.clear();
        write_varint(&mut out, 127);
        assert_eq!(out, vec![0x7f]);

        // 1000 = 0x3e8 → e8 07 (the TransferContract amount in the
        // sourced THORChain vector).
        out.clear();
        write_varint(&mut out, 1000);
        assert_eq!(out, vec![0xe8, 0x07]);

        // 300 = 0x12c → ac 02.
        out.clear();
        write_varint(&mut out, 300);
        assert_eq!(out, vec![0xac, 0x02]);
    }

    #[test]
    fn field_tags_match_wire_format() {
        // ref_block_bytes (field 1, len-delimited) → tag 0x0a, len, data.
        let mut out = Vec::new();
        field_bytes(&mut out, 1, &[0x00, 0xb0]);
        assert_eq!(out, vec![0x0a, 0x02, 0x00, 0xb0]);

        // expiration (field 8, varint).
        out.clear();
        field_varint(&mut out, 8, 5);
        assert_eq!(out, vec![0x40, 0x05]);

        // contract (field 11, len-delimited) → tag 0x5a.
        out.clear();
        field_bytes(&mut out, 11, &[0xaa]);
        assert_eq!(out, vec![0x5a, 0x01, 0xaa]);

        // timestamp (field 14, varint) → tag 0x70.
        out.clear();
        field_varint(&mut out, 14, 1);
        assert_eq!(out, vec![0x70, 0x01]);

        // fee_limit (field 18, varint) → two-byte tag 0x90 0x01.
        out.clear();
        field_varint(&mut out, 18, 1);
        assert_eq!(out, vec![0x90, 0x01, 0x01]);
    }
}
