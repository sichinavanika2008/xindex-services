//! Minimal protobuf wire encoding — just the messages the Cosmos
//! multisig pubkey and aggregate signature need. No `prost` dependency.
//!
//! Only proto3 wire types 0 (varint) and 2 (length-delimited) are used.
//! proto3 semantics: a scalar field equal to its zero value is OMITTED
//! from the encoding, so callers guard zero-valued scalars (e.g. only
//! emit `extra_bits_stored` when non-zero) to match a canonical
//! `prost` / `gogoproto` marshal byte-for-byte.

/// Append a base-128 LEB varint.
pub(crate) fn put_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Emit a field tag = `(field_number << 3) | wire_type`.
fn put_tag(field: u32, wire: u8, out: &mut Vec<u8>) {
    put_varint((u64::from(field) << 3) | u64::from(wire), out);
}

/// Emit a length-delimited field (wire type 2): a `bytes`, `string`, or
/// embedded-message field.
pub(crate) fn put_len_delim(field: u32, bytes: &[u8], out: &mut Vec<u8>) {
    put_tag(field, 2, out);
    put_varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

/// Emit a varint scalar field (wire type 0). proto3 omits zero values, so
/// the caller only calls this for a non-zero scalar (or one whose
/// canonical encoding requires it present).
pub(crate) fn put_varint_field(field: u32, value: u64, out: &mut Vec<u8>) {
    put_tag(field, 0, out);
    put_varint(value, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_single_byte() {
        let mut out = Vec::new();
        put_varint(0, &mut out);
        assert_eq!(out, vec![0x00]);
        out.clear();
        put_varint(127, &mut out);
        assert_eq!(out, vec![0x7f]);
    }

    #[test]
    fn varint_multi_byte() {
        // 300 = 0b1_0010_1100 → 0xAC 0x02 (canonical protobuf example).
        let mut out = Vec::new();
        put_varint(300, &mut out);
        assert_eq!(out, vec![0xac, 0x02]);
    }

    #[test]
    fn len_delim_field_one_string() {
        // field 1, wire 2 → tag 0x0a; len 3; "abc".
        let mut out = Vec::new();
        put_len_delim(1, b"abc", &mut out);
        assert_eq!(out, vec![0x0a, 0x03, b'a', b'b', b'c']);
    }

    #[test]
    fn varint_field_one_value_seven() {
        // field 1, wire 0 → tag 0x08; value 7.
        let mut out = Vec::new();
        put_varint_field(1, 7, &mut out);
        assert_eq!(out, vec![0x08, 0x07]);
    }
}
