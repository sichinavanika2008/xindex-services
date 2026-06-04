//! Solana compact-u16 ("shortvec") length encoding — the length prefix on
//! every array in a serialized message/transaction (account keys,
//! instructions, instruction accounts, instruction data, signatures).
//!
//! It is LEB128 restricted to 16 bits: 1–3 bytes, 7 value bits per byte
//! with the high bit (`0x80`) marking continuation. The third byte
//! therefore carries only the top 2 bits of a `u16`.

use crate::SolanaTxError;

/// Append `len` as a compact-u16 to `out`.
///
/// # Errors
/// Returns [`SolanaTxError::ShortVecOverflow`] if `len` exceeds `u16::MAX`.
pub fn encode_len(len: usize, out: &mut Vec<u8>) -> Result<(), SolanaTxError> {
    if len > usize::from(u16::MAX) {
        return Err(SolanaTxError::ShortVecOverflow(len));
    }
    let mut v = len;
    loop {
        let mut byte = u8::try_from(v & 0x7f).unwrap_or(0);
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return Ok(());
        }
        byte |= 0x80;
        out.push(byte);
    }
}

/// Decode a compact-u16 from `bytes` starting at `*pos`, advancing `*pos`
/// past the consumed bytes.
///
/// # Errors
/// [`SolanaTxError::BadLength`] if the buffer ends mid-value;
/// [`SolanaTxError::ShortVecOverflow`] if more than 3 bytes are consumed
/// (a malformed prefix that cannot represent a `u16`).
pub fn decode_len(bytes: &[u8], pos: &mut usize) -> Result<usize, SolanaTxError> {
    let mut val: u32 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte = *bytes.get(*pos).ok_or(SolanaTxError::BadLength {
            expected: *pos + 1,
            got: bytes.len(),
        })?;
        *pos += 1;
        val |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(val as usize);
        }
        shift += 7;
        if shift > 14 {
            return Err(SolanaTxError::ShortVecOverflow(val as usize));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[expect(clippy::expect_used, reason = "test code")]
    fn enc(len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        encode_len(len, &mut out).expect("len in range");
        out
    }

    #[test]
    fn known_vectors() {
        // Canonical Solana shortvec vectors.
        assert_eq!(enc(0), vec![0x00]);
        assert_eq!(enc(1), vec![0x01]);
        assert_eq!(enc(127), vec![0x7f]);
        assert_eq!(enc(128), vec![0x80, 0x01]);
        assert_eq!(enc(16_383), vec![0xff, 0x7f]);
        assert_eq!(enc(16_384), vec![0x80, 0x80, 0x01]);
        assert_eq!(enc(65_535), vec![0xff, 0xff, 0x03]);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn round_trip_all_boundaries() {
        for len in [0usize, 1, 127, 128, 255, 16_383, 16_384, 65_535] {
            let bytes = enc(len);
            let mut pos = 0;
            assert_eq!(decode_len(&bytes, &mut pos).expect("decode"), len);
            assert_eq!(pos, bytes.len(), "consumed exactly the prefix");
        }
    }

    #[test]
    fn over_u16_rejected() {
        let mut out = Vec::new();
        assert!(matches!(
            encode_len(65_536, &mut out),
            Err(SolanaTxError::ShortVecOverflow(65_536))
        ));
    }

    #[test]
    fn truncated_prefix_rejected() {
        let mut pos = 0;
        // 0x80 = continuation bit set but no following byte.
        assert!(matches!(
            decode_len(&[0x80], &mut pos),
            Err(SolanaTxError::BadLength { .. })
        ));
    }
}
