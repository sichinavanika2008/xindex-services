//! `SIGN_MODE_LEGACY_AMINO_JSON` `StdSignDoc` canonical sign-bytes.
//!
//! For a `LegacyAminoPubKey` k-of-n multisig, every member signs the
//! SHA-256 of the canonical amino JSON `StdSignDoc`. The canonical form
//! (cosmos-sdk `x/auth/migrations/legacytx`):
//!
//! - keys sorted alphabetically at every level,
//! - no whitespace,
//! - all numbers encoded as JSON strings,
//! - each message wrapped as `{"type":"<amino name>","value":{…}}`.
//!
//! We obtain sorted keys for free by declaring the serde structs with
//! their fields in alphabetical order — `serde_json` emits struct fields
//! in declaration order with no whitespace. The one ordering the structs
//! encode (top-level: `account_number`, `chain_id`, `fee`, `memo`,
//! `msgs`, `sequence`; fee: `amount`, `gas`; coin: `amount`, `denom`;
//! msg-value: `amount`, `from_address`, `to_address`) is the canonical
//! sorted order, verified byte-for-byte by [`tests`].
//!
//! ## Escaping caveat (DL-P3.3-3)
//!
//! Go's `encoding/json` HTML-escapes `<`, `>`, `&` (→ `<` …);
//! `serde_json` does not. `THORChain` memos and bech32 addresses contain
//! none of those characters, so the encodings coincide for our messages —
//! but a memo containing `<`/`>`/`&` would diverge. The executor restricts
//! the memo to the `THORChain` grammar (ASCII `=:/.-` + alphanumerics),
//! and the gaiad byte-match gate (DL-P3.3-8) is the backstop.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Amino type name for a bank send. NOT present in any proto descriptor —
/// it must be hard-coded (cosmos-sdk #13407 / #17975). A wrong name
/// silently produces wrong sign-bytes.
pub const MSG_SEND_AMINO_TYPE: &str = "cosmos-sdk/MsgSend";

/// `{amount, denom}` — alphabetical key order.
#[derive(Serialize)]
struct Coin<'a> {
    amount: &'a str,
    denom: &'a str,
}

/// `{amount:[Coin], gas}` — alphabetical key order.
#[derive(Serialize)]
struct Fee<'a> {
    amount: [Coin<'a>; 1],
    gas: &'a str,
}

/// `MsgSend.value`: `{amount:[Coin], from_address, to_address}`.
#[derive(Serialize)]
struct MsgSendValue<'a> {
    amount: [Coin<'a>; 1],
    from_address: &'a str,
    to_address: &'a str,
}

/// `{type, value}` — alphabetical key order.
#[derive(Serialize)]
struct Msg<'a> {
    #[serde(rename = "type")]
    type_field: &'a str,
    value: MsgSendValue<'a>,
}

/// The full `StdSignDoc` for a single-coin `MsgSend`, fields in canonical
/// sorted order.
#[derive(Serialize)]
struct StdSignDoc<'a> {
    account_number: &'a str,
    chain_id: &'a str,
    fee: Fee<'a>,
    memo: &'a str,
    msgs: [Msg<'a>; 1],
    sequence: &'a str,
}

/// Semantic inputs for a single `THORChain`-rail `MsgSend` sign-doc. All
/// numeric fields are pre-stringified by the caller (decimal, no leading
/// zeros) since amino encodes them as JSON strings.
#[derive(Debug, Clone)]
pub struct CosmosSendSignDoc<'a> {
    /// `account_number` of the multisig account (decimal string).
    pub account_number: &'a str,
    /// Cosmos consensus chain-id (e.g. `"cosmoshub-4"`).
    pub chain_id: &'a str,
    /// Fee coin amount in the micro-unit (decimal string).
    pub fee_amount: &'a str,
    /// Gas limit (decimal string).
    pub gas: &'a str,
    /// Tx memo (the `THORChain` memo).
    pub memo: &'a str,
    /// `MsgSend.from_address` (the multisig account, bech32).
    pub from_address: &'a str,
    /// `MsgSend.to_address` (bech32 recipient).
    pub to_address: &'a str,
    /// Send coin amount in the micro-unit (decimal string).
    pub amount: &'a str,
    /// Coin denom (`"uatom"` for GAIA) — used for both the send and fee
    /// coins (the gas asset on the `THORChain` Cosmos rail).
    pub denom: &'a str,
}

impl CosmosSendSignDoc<'_> {
    fn to_doc(&self) -> StdSignDoc<'_> {
        StdSignDoc {
            account_number: self.account_number,
            chain_id: self.chain_id,
            fee: Fee {
                amount: [Coin {
                    amount: self.fee_amount,
                    denom: self.denom,
                }],
                gas: self.gas,
            },
            memo: self.memo,
            msgs: [Msg {
                type_field: MSG_SEND_AMINO_TYPE,
                value: MsgSendValue {
                    amount: [Coin {
                        amount: self.amount,
                        denom: self.denom,
                    }],
                    from_address: self.from_address,
                    to_address: self.to_address,
                },
            }],
            sequence: "",
        }
    }

    /// Canonical amino `StdSignDoc` JSON bytes.
    ///
    /// Validates that every numeric field is canonical decimal first: the
    /// daemon recomputes the digest over the SAME strings it received, so a
    /// non-canonical value (e.g. `"07"`, `"01000000"`) would pass the
    /// daemon's self-check yet produce sign-bytes that diverge from what a
    /// validator reconstructs from the canonical decimal — a released
    /// signature that is invalid on-chain (stuck funds). Rejecting here
    /// makes non-canonical input impossible to sign from any caller.
    ///
    /// # Errors
    /// - [`AminoError::NonCanonicalDecimal`] if `account_number`,
    ///   `fee_amount`, `gas`, `amount`, or `sequence` is not canonical
    ///   decimal (non-empty, ASCII digits, no leading zero unless `"0"`).
    /// - [`AminoError::Json`] if serialization fails (cannot happen for the
    ///   all-`&str` shape, but the `serde_json` API is fallible).
    pub fn canonical_json(&self, sequence: &str) -> Result<Vec<u8>, AminoError> {
        check_canonical_decimal("account_number", self.account_number)?;
        check_canonical_decimal("fee_amount", self.fee_amount)?;
        check_canonical_decimal("gas", self.gas)?;
        check_canonical_decimal("amount", self.amount)?;
        check_canonical_decimal("sequence", sequence)?;
        let mut doc = self.to_doc();
        doc.sequence = sequence;
        serde_json::to_vec(&doc).map_err(|e| AminoError::Json(e.to_string()))
    }

    /// SHA-256 of the canonical JSON — the 32-byte digest each multisig
    /// member signs (Cosmos secp256k1 signs `sha256(signBytes)`).
    ///
    /// # Errors
    /// [`AminoError::Json`] if canonicalization fails.
    pub fn sign_bytes_sha256(&self, sequence: &str) -> Result<[u8; 32], AminoError> {
        let json = self.canonical_json(sequence)?;
        Ok(Sha256::digest(&json).into())
    }
}

/// `true` iff `s` is a canonical Cosmos decimal string: non-empty, only
/// ASCII digits, and no leading zero unless the value is exactly `"0"`.
/// Cosmos amino encodes `sdk.Int`/`uint64` as this canonical decimal; a
/// validator reconstructs the sign-bytes from it.
fn is_canonical_decimal(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s.len() == 1 || s.as_bytes()[0] != b'0')
}

fn check_canonical_decimal(field: &'static str, value: &str) -> Result<(), AminoError> {
    if is_canonical_decimal(value) {
        Ok(())
    } else {
        Err(AminoError::NonCanonicalDecimal {
            field,
            value: value.to_string(),
        })
    }
}

/// Errors from amino sign-doc construction.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AminoError {
    /// A numeric field was not canonical decimal (would yield sign-bytes
    /// the network rejects).
    #[error("non-canonical decimal in field {field}: {value:?}")]
    NonCanonicalDecimal {
        /// Which sign-doc field was malformed.
        field: &'static str,
        /// The offending value.
        value: String,
    },
    /// `serde_json` serialization failed.
    #[error("amino json serialization failed: {0}")]
    Json(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample<'a>() -> CosmosSendSignDoc<'a> {
        CosmosSendSignDoc {
            account_number: "12345",
            chain_id: "cosmoshub-4",
            fee_amount: "5000",
            gas: "200000",
            memo: "=:ETH.USDT:0xabc:0/1/0",
            from_address: "cosmos1from",
            to_address: "cosmos1to",
            amount: "1000000",
            denom: "uatom",
        }
    }

    /// The canonical JSON is byte-exact: sorted keys at every level, no
    /// whitespace, numbers-as-strings, the `MsgSend` wrapped with its amino
    /// type name. Pinning this string is the canonicalization contract —
    /// a single divergent byte makes every member signature invalid.
    ///
    /// P3.3-3 byte-match CLOSED (amino sign-bytes): the pinned `expected`
    /// below is byte-identical to `@cosmjs/amino`'s
    /// `serializeSignDoc(makeSignDoc(...))` over the same inputs — the
    /// reference implementation of the cosmos-sdk
    /// `SIGN_MODE_LEGACY_AMINO_JSON` canonicalization. Regenerate via
    /// `tools/byte-match/cosmos.mjs`. This closes the security-critical
    /// half of the gaiad gate (the bytes members actually sign); a live
    /// `gaiad`/cosmjs `TxRaw` broadcast stays testnet-rehearsal territory.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn canonical_json_is_byte_exact() {
        let json = sample().canonical_json("7").expect("json");
        let expected = concat!(
            r#"{"account_number":"12345","#,
            r#""chain_id":"cosmoshub-4","#,
            r#""fee":{"amount":[{"amount":"5000","denom":"uatom"}],"gas":"200000"},"#,
            r#""memo":"=:ETH.USDT:0xabc:0/1/0","#,
            r#""msgs":[{"type":"cosmos-sdk/MsgSend","value":{"amount":[{"amount":"1000000","denom":"uatom"}],"from_address":"cosmos1from","to_address":"cosmos1to"}}],"#,
            r#""sequence":"7"}"#,
        );
        assert_eq!(String::from_utf8(json).expect("utf8"), expected);
    }

    /// `forward slash` is NOT escaped (matches Go's `MustSortJSON`, which
    /// does not escape `/`). Guards against a `serde_json` config change.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn forward_slash_in_memo_is_not_escaped() {
        let json = sample().canonical_json("0").expect("json");
        let s = String::from_utf8(json).expect("utf8");
        assert!(s.contains("0xabc:0/1/0"), "slash must be literal: {s}");
        assert!(!s.contains("\\/"), "slash must not be escaped: {s}");
    }

    /// A non-canonical sequence (leading zero) is rejected — it would
    /// hash differently from the canonical `"7"` a validator reconstructs.
    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn rejects_non_canonical_sequence() {
        let err = sample().canonical_json("07").unwrap_err();
        assert_eq!(
            err,
            AminoError::NonCanonicalDecimal {
                field: "sequence",
                value: "07".to_string(),
            }
        );
    }

    /// A non-canonical amount (leading zero) is rejected at the numeric
    /// field, before any signature can be produced over it.
    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn rejects_non_canonical_amount() {
        let mut doc = sample();
        doc.amount = "01000000";
        let err = doc.canonical_json("7").unwrap_err();
        assert_eq!(
            err,
            AminoError::NonCanonicalDecimal {
                field: "amount",
                value: "01000000".to_string(),
            }
        );
    }

    /// `"0"` is canonical (a zero `account_number` / sequence is valid).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn zero_is_canonical() {
        let mut doc = sample();
        doc.account_number = "0";
        doc.canonical_json("0").expect("zero is canonical");
    }

    /// The sign-bytes digest is SHA-256 of the canonical JSON, and is
    /// sensitive to the sequence (replay coordinate).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn sign_bytes_depend_on_sequence() {
        let d7 = sample().sign_bytes_sha256("7").expect("d7");
        let d8 = sample().sign_bytes_sha256("8").expect("d8");
        assert_ne!(d7, d8);
        // Pin the digest of the byte-exact document above.
        let json = sample().canonical_json("7").expect("json");
        let expected: [u8; 32] = Sha256::digest(&json).into();
        assert_eq!(d7, expected);
    }
}
