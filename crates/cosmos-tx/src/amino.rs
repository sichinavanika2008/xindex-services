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
    /// # Errors
    /// [`AminoError::Json`] if serialization fails (cannot happen for the
    /// all-`&str` shape, but the `serde_json` API is fallible).
    pub fn canonical_json(&self, sequence: &str) -> Result<Vec<u8>, AminoError> {
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

/// Errors from amino sign-doc construction.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AminoError {
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
