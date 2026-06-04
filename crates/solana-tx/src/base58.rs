//! Base58 (Bitcoin alphabet) helpers over the `bs58` crate. Solana
//! encodes every 32-byte (pubkey / blockhash) and 64-byte (signature)
//! quantity in base58 at the JSON-RPC wire.

use crate::SolanaTxError;

/// Encode bytes to a base58 string.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

/// Decode a base58 string to bytes.
///
/// # Errors
/// Returns [`SolanaTxError::Base58`] on an invalid base58 string.
pub fn decode_vec(s: &str) -> Result<Vec<u8>, SolanaTxError> {
    bs58::decode(s)
        .into_vec()
        .map_err(|e| SolanaTxError::Base58(e.to_string()))
}

/// Decode a base58 string to exactly 32 bytes.
///
/// # Errors
/// [`SolanaTxError::Base58`] on invalid base58; [`SolanaTxError::BadLength`]
/// if the decoded length is not 32.
pub fn decode_32(s: &str) -> Result<[u8; 32], SolanaTxError> {
    let v = decode_vec(s)?;
    let got = v.len();
    v.try_into()
        .map_err(|_| SolanaTxError::BadLength { expected: 32, got })
}

/// Decode a base58 string to exactly 64 bytes.
///
/// # Errors
/// [`SolanaTxError::Base58`] on invalid base58; [`SolanaTxError::BadLength`]
/// if the decoded length is not 64.
pub fn decode_64(s: &str) -> Result<[u8; 64], SolanaTxError> {
    let v = decode_vec(s)?;
    let got = v.len();
    v.try_into()
        .map_err(|_| SolanaTxError::BadLength { expected: 64, got })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn round_trip_32() {
        let bytes = [7u8; 32];
        let s = encode(&bytes);
        assert_eq!(decode_32(&s).expect("decode"), bytes);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn round_trip_64() {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("idx < 64");
        }
        let s = encode(&bytes);
        assert_eq!(decode_64(&s).expect("decode"), bytes);
    }

    #[test]
    fn system_program_is_all_ones_base58() {
        // The System Program (32 zero bytes) encodes to 32 '1' characters.
        assert_eq!(encode(&[0u8; 32]), "1".repeat(32));
    }

    #[test]
    fn wrong_length_rejected() {
        let s = encode(&[1u8; 31]);
        assert!(matches!(
            decode_32(&s),
            Err(SolanaTxError::BadLength {
                expected: 32,
                got: 31
            })
        ));
    }

    #[test]
    fn invalid_base58_rejected() {
        // '0' (zero) is not in the Bitcoin base58 alphabet.
        assert!(matches!(decode_vec("0OIl"), Err(SolanaTxError::Base58(_))));
    }
}
