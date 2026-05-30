//! Broadcast-ready proto `TxRaw` assembly for a `LegacyAminoPubKey`
//! multisig `MsgSend`.
//!
//! [`amino`](crate::amino) produces the `SIGN_MODE_LEGACY_AMINO_JSON`
//! sign-bytes the members sign; [`sigs::aggregate_verified`] produces the
//! `CompactBitArray` + `MultiSignature`. This module wraps those into the
//! protobuf `cosmos.tx.v1beta1.TxRaw` that `broadcast_tx_sync` consumes:
//!
//! ```text
//! TxRaw { body_bytes, auth_info_bytes, signatures = [MultiSignature] }
//!   body_bytes      = TxBody  { messages = [Any(MsgSend)], memo }
//!   auth_info_bytes = AuthInfo{ signer_infos = [SignerInfo], fee = Fee }
//!     SignerInfo    { public_key = Any(LegacyAminoPubKey),
//!                     mode_info  = Multi{ bitarray, [Single(AMINO_JSON)] },
//!                     sequence }
//! ```
//!
//! Even though the members sign in `LEGACY_AMINO_JSON` mode, the broadcast
//! envelope is the proto `Tx` — the `ModeInfo` records the amino mode and
//! the signature is the amino-signed aggregate. The amino sign-doc and
//! this proto envelope MUST agree on every shared value (from/to/amount/
//! denom/memo/fee/gas/sequence); [`build_tx_raw`] takes one parameter set
//! to make divergence impossible.
//!
//! ## Byte-exactness is a pre-mainnet gate (DL-P3.3-8)
//!
//! The encoding is deterministic and unit-tested, but byte-level
//! equivalence against `gaiad`/`cosmrs` for the target Gaia SDK version is
//! a MANDATORY pre-mainnet gate — a single divergent byte yields a tx the
//! network rejects (stuck funds) or, worse, one that spends differently
//! than the members signed. See `xindex-services/KNOWN_FINDINGS.md`.

use crate::addr::{encode_any, encode_legacy_amino_pubkey};
use crate::proto::{put_len_delim, put_varint_field};
use crate::sigs::AggregatedMultisig;
use crate::CosmosMultisig;

/// proto `type_url` for a bank `MsgSend`.
const MSG_SEND_TYPE_URL: &str = "/cosmos.bank.v1beta1.MsgSend";
/// proto `type_url` for a threshold multisig pubkey.
const LEGACY_AMINO_PUBKEY_TYPE_URL: &str = "/cosmos.crypto.multisig.LegacyAminoPubKey";
/// `cosmos.tx.signing.v1beta1.SignMode.SIGN_MODE_LEGACY_AMINO_JSON`.
const SIGN_MODE_LEGACY_AMINO_JSON: u64 = 127;

/// Inputs for one `MsgSend` `TxRaw`. The numeric strings (`send_amount`,
/// `fee_amount`) are the canonical-decimal forms shared with the amino
/// sign-doc; `gas_limit` is the same value the amino doc stringifies.
#[derive(Debug, Clone)]
pub struct CosmosTxParams<'a> {
    /// `MsgSend.from_address` — the multisig account (bech32).
    pub from_address: &'a str,
    /// `MsgSend.to_address` — the `THORChain` Asgard inbound (bech32).
    pub to_address: &'a str,
    /// Coin denom (`"uatom"` for GAIA), used for both send and fee coins.
    pub denom: &'a str,
    /// Send amount in the micro-unit (canonical decimal string).
    pub send_amount: &'a str,
    /// Fee amount in the micro-unit (canonical decimal string).
    pub fee_amount: &'a str,
    /// Gas limit (proto `uint64`; the amino doc signs `gas_limit.to_string()`).
    pub gas_limit: u64,
    /// Tx memo (the `THORChain` swap memo).
    pub memo: &'a str,
    /// Account sequence the members signed at (proto `uint64`).
    pub sequence: u64,
}

/// proto-encode `cosmos.base.v1beta1.Coin { denom = 1, amount = 2 }`.
fn encode_coin(denom: &str, amount: &str) -> Vec<u8> {
    let mut out = Vec::new();
    put_len_delim(1, denom.as_bytes(), &mut out);
    put_len_delim(2, amount.as_bytes(), &mut out);
    out
}

/// proto-encode `cosmos.bank.v1beta1.MsgSend
/// { from_address = 1, to_address = 2, amount = repeated Coin 3 }`.
fn encode_msg_send(from: &str, to: &str, denom: &str, amount: &str) -> Vec<u8> {
    let mut out = Vec::new();
    put_len_delim(1, from.as_bytes(), &mut out);
    put_len_delim(2, to.as_bytes(), &mut out);
    put_len_delim(3, &encode_coin(denom, amount), &mut out);
    out
}

/// proto-encode `cosmos.tx.v1beta1.TxBody
/// { messages = repeated Any 1, memo = 2, timeout_height = 3 }`.
/// `timeout_height` is omitted (0) — proto3 drops zero scalars, matching
/// the amino doc which has no timeout.
fn encode_tx_body(msg_send: &[u8], memo: &str) -> Vec<u8> {
    let any = encode_any(MSG_SEND_TYPE_URL, msg_send);
    let mut out = Vec::new();
    put_len_delim(1, &any, &mut out);
    if !memo.is_empty() {
        put_len_delim(2, memo.as_bytes(), &mut out);
    }
    out
}

/// proto-encode `cosmos.tx.v1beta1.Fee
/// { amount = repeated Coin 1, gas_limit = 2 }`.
fn encode_fee(denom: &str, fee_amount: &str, gas_limit: u64) -> Vec<u8> {
    let mut out = Vec::new();
    put_len_delim(1, &encode_coin(denom, fee_amount), &mut out);
    if gas_limit != 0 {
        put_varint_field(2, gas_limit, &mut out);
    }
    out
}

/// proto-encode `cosmos.tx.v1beta1.ModeInfo.Single { mode = 1 }`, wrapped
/// as a `ModeInfo { single = 1 }`.
fn encode_mode_info_single() -> Vec<u8> {
    let mut single = Vec::new();
    put_varint_field(1, SIGN_MODE_LEGACY_AMINO_JSON, &mut single);
    let mut mode_info = Vec::new();
    put_len_delim(1, &single, &mut mode_info);
    mode_info
}

/// proto-encode `ModeInfo { multi = 2 }` where
/// `Multi { bitarray = CompactBitArray 1, mode_infos = repeated ModeInfo 2 }`.
/// One `Single(AMINO_JSON)` sub-`ModeInfo` per signing member, in member
/// order (the cosmos-sdk multisig invariant).
fn encode_mode_info_multi(compact_bitarray: &[u8], signed_count: usize) -> Vec<u8> {
    let mut multi = Vec::new();
    put_len_delim(1, compact_bitarray, &mut multi);
    let single = encode_mode_info_single();
    for _ in 0..signed_count {
        put_len_delim(2, &single, &mut multi);
    }
    let mut mode_info = Vec::new();
    put_len_delim(2, &multi, &mut mode_info);
    mode_info
}

/// proto-encode `cosmos.tx.v1beta1.SignerInfo
/// { public_key = Any 1, mode_info = 2, sequence = 3 }`.
fn encode_signer_info(pubkey_any: &[u8], mode_info: &[u8], sequence: u64) -> Vec<u8> {
    let mut out = Vec::new();
    put_len_delim(1, pubkey_any, &mut out);
    put_len_delim(2, mode_info, &mut out);
    if sequence != 0 {
        put_varint_field(3, sequence, &mut out);
    }
    out
}

/// proto-encode `cosmos.tx.v1beta1.AuthInfo
/// { signer_infos = repeated SignerInfo 1, fee = 2 }`.
fn encode_auth_info(signer_info: &[u8], fee: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_len_delim(1, signer_info, &mut out);
    put_len_delim(2, fee, &mut out);
    out
}

/// proto-encode `cosmos.tx.v1beta1.TxRaw
/// { body_bytes = 1, auth_info_bytes = 2, signatures = repeated bytes 3 }`.
fn encode_tx_raw(body: &[u8], auth_info: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_len_delim(1, body, &mut out);
    put_len_delim(2, auth_info, &mut out);
    put_len_delim(3, signature, &mut out);
    out
}

/// Assemble the broadcast-ready `TxRaw` bytes for a multisig `MsgSend`.
///
/// `descriptor` provides the frozen member set + threshold for the
/// `LegacyAminoPubKey` `public_key`; `agg` is the verified aggregate from
/// [`crate::sigs::aggregate_verified`] over the SAME sign-bytes the amino
/// doc produced for `params`.
///
/// # Errors
/// This function performs only encoding and cannot fail; it returns
/// `Vec<u8>` directly. (Kept signature-symmetric with the amino API by
/// returning the bytes, not a `Result`.)
#[must_use]
pub fn build_tx_raw(
    descriptor: &CosmosMultisig,
    params: &CosmosTxParams<'_>,
    agg: &AggregatedMultisig,
) -> Vec<u8> {
    let msg = encode_msg_send(
        params.from_address,
        params.to_address,
        params.denom,
        params.send_amount,
    );
    let body = encode_tx_body(&msg, params.memo);

    let pubkey_proto =
        encode_legacy_amino_pubkey(descriptor.threshold(), descriptor.member_pubkeys());
    let pubkey_any = encode_any(LEGACY_AMINO_PUBKEY_TYPE_URL, &pubkey_proto);
    let mode_info = encode_mode_info_multi(&agg.compact_bitarray, agg.signed_count);
    let signer_info = encode_signer_info(&pubkey_any, &mode_info, params.sequence);
    let fee = encode_fee(params.denom, params.fee_amount, params.gas_limit);
    let auth_info = encode_auth_info(&signer_info, &fee);

    encode_tx_raw(&body, &auth_info, &agg.multi_signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::put_varint;

    /// Read one proto field header at `pos`: returns `(field_number,
    /// wire_type, next_pos)`. Test-only helper to assert the on-wire
    /// layout without pulling in a proto decoder.
    fn read_tag(buf: &[u8], pos: usize) -> (u64, u8, usize) {
        let (tag, next) = read_varint(buf, pos);
        ((tag >> 3), (tag & 0x7) as u8, next)
    }

    fn read_varint(buf: &[u8], mut pos: usize) -> (u64, usize) {
        let mut shift = 0u32;
        let mut val = 0u64;
        loop {
            let b = buf[pos];
            pos += 1;
            val |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        (val, pos)
    }

    /// Read a length-delimited field's body at `pos` (after the tag).
    fn read_len_delim(buf: &[u8], pos: usize) -> (&[u8], usize) {
        let (len, p) = read_varint(buf, pos);
        let end = p + usize::try_from(len).unwrap_or(0);
        (&buf[p..end], end)
    }

    fn coin_bytes(denom: &str, amount: &str) -> Vec<u8> {
        encode_coin(denom, amount)
    }

    #[test]
    fn coin_layout_is_denom_then_amount() {
        let c = coin_bytes("uatom", "1000000");
        // field 1 (denom) len-delim: 0x0a 0x05 "uatom"
        assert_eq!(&c[..2], &[0x0a, 0x05]);
        assert_eq!(&c[2..7], b"uatom");
        // field 2 (amount) len-delim: 0x12 0x07 "1000000"
        assert_eq!(&c[7..9], &[0x12, 0x07]);
        assert_eq!(&c[9..], b"1000000");
    }

    #[test]
    fn msg_send_has_three_fields_in_order() {
        let m = encode_msg_send("cosmos1from", "cosmos1to", "uatom", "5");
        // field 1 from_address.
        let (f1, w1, p) = read_tag(&m, 0);
        assert_eq!((f1, w1), (1, 2));
        let (from, p) = read_len_delim(&m, p);
        assert_eq!(from, b"cosmos1from");
        // field 2 to_address.
        let (f2, w2, p) = read_tag(&m, p);
        assert_eq!((f2, w2), (2, 2));
        let (to, p) = read_len_delim(&m, p);
        assert_eq!(to, b"cosmos1to");
        // field 3 amount (Coin).
        let (f3, w3, p) = read_tag(&m, p);
        assert_eq!((f3, w3), (3, 2));
        let (coin, end) = read_len_delim(&m, p);
        assert_eq!(coin, coin_bytes("uatom", "5").as_slice());
        assert_eq!(end, m.len());
    }

    #[test]
    fn tx_body_omits_empty_memo_and_timeout() {
        let msg = encode_msg_send("a", "b", "uatom", "1");
        let body = encode_tx_body(&msg, "");
        // Only field 1 (messages) present — no memo (2), no timeout (3).
        let (f1, w1, p) = read_tag(&body, 0);
        assert_eq!((f1, w1), (1, 2));
        let (_any, end) = read_len_delim(&body, p);
        assert_eq!(end, body.len(), "no trailing fields when memo empty");
    }

    #[test]
    fn tx_body_includes_memo_when_present() {
        let msg = encode_msg_send("a", "b", "uatom", "1");
        let body = encode_tx_body(&msg, "=:ETH.USDT:0xabc:1");
        let (_f1, _w1, p) = read_tag(&body, 0);
        let (_any, p) = read_len_delim(&body, p);
        let (f2, w2, p) = read_tag(&body, p);
        assert_eq!((f2, w2), (2, 2), "memo is field 2");
        let (memo, _end) = read_len_delim(&body, p);
        assert_eq!(memo, b"=:ETH.USDT:0xabc:1");
    }

    #[test]
    fn mode_info_multi_has_one_single_per_signer() {
        // bitarray bytes are opaque here; signed_count = 3.
        let mi = encode_mode_info_multi(&[0x08, 0x05, 0x12, 0x01, 0xA8], 3);
        // Outer ModeInfo: field 2 (multi).
        let (f, w, p) = read_tag(&mi, 0);
        assert_eq!((f, w), (2, 2));
        let (multi, _end) = read_len_delim(&mi, p);
        // Inside Multi: field 1 bitarray, then 3× field 2 mode_infos.
        let (bf, bw, bp) = read_tag(multi, 0);
        assert_eq!((bf, bw), (1, 2));
        let (_ba, mut q) = read_len_delim(multi, bp);
        let mut singles = 0;
        while q < multi.len() {
            let (mf, mw, mp) = read_tag(multi, q);
            assert_eq!((mf, mw), (2, 2), "mode_infos field 2");
            let (sub, nq) = read_len_delim(multi, mp);
            // Each sub ModeInfo is a Single{mode=127}.
            assert_eq!(sub, encode_mode_info_single().as_slice());
            q = nq;
            singles += 1;
        }
        assert_eq!(singles, 3);
    }

    #[test]
    fn single_mode_is_amino_json_127() {
        let s = encode_mode_info_single();
        // ModeInfo{ single = field 1 }.
        let (f, w, p) = read_tag(&s, 0);
        assert_eq!((f, w), (1, 2));
        let (single, _end) = read_len_delim(&s, p);
        // Single{ mode = field 1 varint }.
        let (mf, mw, mp) = read_tag(single, 0);
        assert_eq!((mf, mw), (1, 0));
        let (mode, _e) = read_varint(single, mp);
        assert_eq!(mode, 127);
    }

    #[test]
    fn fee_omits_zero_gas() {
        let f0 = encode_fee("uatom", "200", 0);
        // Only the amount Coin (field 1) — gas_limit (2) dropped when 0.
        let (f, w, p) = read_tag(&f0, 0);
        assert_eq!((f, w), (1, 2));
        let (_coin, end) = read_len_delim(&f0, p);
        assert_eq!(end, f0.len());
        // Non-zero gas appears as field 2 varint.
        let f1 = encode_fee("uatom", "200", 200_000);
        let (_f, _w, p) = read_tag(&f1, 0);
        let (_coin, p) = read_len_delim(&f1, p);
        let (gf, gw, gp) = read_tag(&f1, p);
        assert_eq!((gf, gw), (2, 0));
        let (gas, _e) = read_varint(&f1, gp);
        assert_eq!(gas, 200_000);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn tx_raw_three_fields_carry_body_authinfo_signature() {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        use k256::ecdsa::{Signature, SigningKey};
        use crate::sigs::{aggregate_verified, to_cosmos_compact_low_s, MemberSig};

        // Real 2-of-3 over a digest.
        let keys: Vec<(SigningKey, [u8; 33])> = (1u8..=3)
            .map(|seed| {
                let sk = SigningKey::from_slice(&[seed; 32]).expect("key");
                let ep = sk.verifying_key().to_encoded_point(true);
                let mut pk = [0u8; 33];
                pk.copy_from_slice(ep.as_bytes());
                (sk, pk)
            })
            .collect();
        let descriptor =
            CosmosMultisig::new(2, keys.iter().map(|(_, pk)| *pk).collect(), "cosmos")
                .expect("descriptor");
        let digest = [0x42u8; 32];
        let part = |i: usize| {
            let sig: Signature = keys[i].0.sign_prehash(&digest).expect("sign");
            let mut sb = [0u8; 64];
            sb.copy_from_slice(sig.to_bytes().as_ref());
            let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
            r.copy_from_slice(&sb[..32]);
            s.copy_from_slice(&sb[32..]);
            MemberSig {
                member_index: i,
                sig64: to_cosmos_compact_low_s(&r, &s).expect("low-s"),
            }
        };
        let agg = aggregate_verified(&descriptor, &digest, &[part(0), part(2)]).expect("agg");

        let params = CosmosTxParams {
            from_address: "cosmos1from",
            to_address: "cosmos1asgard",
            denom: "uatom",
            send_amount: "5000000",
            fee_amount: "5000",
            gas_limit: 200_000,
            memo: "=:ETH.USDT:0xabc:1",
            sequence: 7,
        };
        let raw = build_tx_raw(&descriptor, &params, &agg);

        // TxRaw: field 1 body, field 2 auth_info, field 3 signature.
        let (f1, w1, p) = read_tag(&raw, 0);
        assert_eq!((f1, w1), (1, 2));
        let (body, p) = read_len_delim(&raw, p);
        let (f2, w2, p) = read_tag(&raw, p);
        assert_eq!((f2, w2), (2, 2));
        let (auth, p) = read_len_delim(&raw, p);
        let (f3, w3, p) = read_tag(&raw, p);
        assert_eq!((f3, w3), (3, 2));
        let (sig, end) = read_len_delim(&raw, p);
        assert_eq!(end, raw.len(), "no trailing fields after signatures[0]");

        // body carries the memo; signature == the aggregate's MultiSignature.
        assert!(body.windows(5).any(|w| w == b"=:ETH"), "memo embedded in body");
        assert_eq!(sig, agg.multi_signature.as_slice());
        // auth_info embeds the sequence varint (field 3 of the SignerInfo).
        let mut found_seq = false;
        // SignerInfo is field 1 of AuthInfo.
        let (af, _aw, ap) = read_tag(auth, 0);
        assert_eq!(af, 1);
        let (signer_info, _ae) = read_len_delim(auth, ap);
        // Walk SignerInfo fields for the sequence (field 3 varint = 7).
        let mut q = 0;
        while q < signer_info.len() {
            let (sf, sw, sp) = read_tag(signer_info, q);
            if sf == 3 && sw == 0 {
                let (seq, _e) = read_varint(signer_info, sp);
                assert_eq!(seq, 7);
                found_seq = true;
                break;
            }
            // skip this field's len-delim body
            let (_b, nq) = read_len_delim(signer_info, sp);
            q = nq;
        }
        assert!(found_seq, "sequence varint present in SignerInfo");

        // varint sanity (the test helper agrees with the encoder).
        let mut v = Vec::new();
        put_varint(127, &mut v);
        assert_eq!(v, vec![0x7f]);
    }
}
