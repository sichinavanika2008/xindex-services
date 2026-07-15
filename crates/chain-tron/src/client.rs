//! [`TronChainClient`] trait + production [`ReqwestTronChainClient`] impl,
//! plus the pure JSON parsers the impl delegates to.
//!
//! The trait is what the executor (the redeem leg) programs against,
//! mirroring `XrpChainClient`. The production impl talks the TRON full-node
//! HTTP API over `reqwest` POST. Parsing is split into pure functions so it
//! is unit-testable without a live node.

use std::future::Future;
use std::time::Duration;

use serde_json::{json, Value};
use thiserror::Error;
use xindex_shared::chain_registry::{ChainId, CustodyFamily};

/// Per-request timeout — a stalled RPC must not wedge the executor.
const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Connection-establishment timeout (shorter than the request budget).
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

/// A recent-block reference, decoded from `getnowblock`. The executor
/// derives the TAPOS fields (`ref_block_bytes`, `ref_block_hash`) and the
/// `timestamp` / `expiration` envelope from this — TRON's replay/expiry
/// mechanism (there is NO account nonce).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TronBlockRef {
    /// Block height (`block_header.raw_data.number`).
    pub number: u64,
    /// `ref_block_bytes` = the low 2 bytes of `number`, big-endian.
    pub ref_block_bytes: [u8; 2],
    /// `ref_block_hash` = bytes [8:16] of the 32-byte `blockID`.
    pub ref_block_hash: [u8; 8],
    /// Block timestamp in unix milliseconds.
    pub timestamp_ms: u64,
}

/// Outcome of a `broadcasthex` / `broadcasttransaction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TronBroadcastOutcome {
    /// The node's `result` flag.
    pub result: bool,
    /// The node's `code` (e.g. `"SUCCESS"`, `"DUP_TRANSACTION_ERROR"`,
    /// `"TRANSACTION_EXPIRATION_ERROR"`). Empty when absent.
    pub code: String,
    /// The transaction id the node echoed (hex), if any.
    pub txid: String,
}

impl TronBroadcastOutcome {
    /// `true` iff the node accepted the tx. A `DUP_TRANSACTION_ERROR` means
    /// the tx is already in the mempool / a block — idempotent success
    /// (`THORChain`'s TRON client treats it the same way).
    #[must_use]
    pub fn accepted(&self) -> bool {
        self.result || self.code == "SUCCESS" || self.code == "DUP_TRANSACTION_ERROR"
    }
}

/// A confirmed transaction receipt from `gettransactioninfobyid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TronTxReceipt {
    /// The block height the tx was included in.
    pub block_number: u64,
    /// `true` if the tx executed successfully (no top-level `result:
    /// FAILED`; contract `receipt.result`, when present, is `SUCCESS`).
    pub success: bool,
}

/// Errors surfaced by every [`TronChainClient`] method.
#[derive(Debug, Error)]
pub enum TronChainError {
    /// Transport / HTTP failure.
    #[error("RPC error: {0}")]
    Rpc(String),
    /// Response body did not match the expected JSON shape.
    #[error("decode error: {0}")]
    Decode(String),
    /// The configured chain is not in the TRON custody family.
    #[error("chain {0:?} is not in the TRON custody family")]
    NotTronChain(ChainId),
}

/// Per-TRON-chain RPC primitives. Returns `impl Future + Send` (not
/// `async fn`) so the futures are `Send`-bound at the trait level, like
/// `XrpChainClient`.
pub trait TronChainClient: Send + Sync + 'static {
    /// Which TRON chain this client targets.
    fn chain(&self) -> ChainId;

    /// Read the current block (`getnowblock`) for the TAPOS reference.
    fn now_block(&self) -> impl Future<Output = Result<TronBlockRef, TronChainError>> + Send;

    /// Broadcast an already-assembled, multi-signed `Transaction` protobuf
    /// (hex) via `broadcasthex`.
    fn broadcast_hex(
        &self,
        tx_hex: &str,
    ) -> impl Future<Output = Result<TronBroadcastOutcome, TronChainError>> + Send;

    /// Look up a transaction receipt by `txid` (hex) via
    /// `gettransactioninfobyid`. Returns `None` if the tx is not yet in a
    /// block (the node returns an empty object).
    fn transaction_info(
        &self,
        txid_hex: &str,
    ) -> impl Future<Output = Result<Option<TronTxReceipt>, TronChainError>> + Send;
}

// ─── pure parsers (unit-tested without a node) ──────────────────────────────

/// Decode a hex string into a byte vec.
fn unhex(s: &str) -> Result<Vec<u8>, TronChainError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return Err(TronChainError::Decode("odd-length hex".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| TronChainError::Decode(format!("bad hex: {e}")))
        })
        .collect()
}

/// Parse a `getnowblock` response into a [`TronBlockRef`].
///
/// # Errors
/// [`TronChainError::Decode`] on a missing `blockID` / `number` /
/// `timestamp`, or a `blockID` shorter than 16 bytes.
pub fn parse_now_block(body: &str) -> Result<TronBlockRef, TronChainError> {
    let v: Value = serde_json::from_str(body).map_err(|e| TronChainError::Decode(e.to_string()))?;
    let block_id_hex = v
        .get("blockID")
        .and_then(Value::as_str)
        .ok_or_else(|| TronChainError::Decode("missing blockID".into()))?;
    let raw = v
        .get("block_header")
        .and_then(|h| h.get("raw_data"))
        .ok_or_else(|| TronChainError::Decode("missing block_header.raw_data".into()))?;
    let number = raw
        .get("number")
        .and_then(Value::as_u64)
        .ok_or_else(|| TronChainError::Decode("missing block number".into()))?;
    let timestamp_ms = raw
        .get("timestamp")
        .and_then(Value::as_u64)
        .ok_or_else(|| TronChainError::Decode("missing block timestamp".into()))?;
    let block_id = unhex(block_id_hex)?;
    if block_id.len() < 16 {
        return Err(TronChainError::Decode(format!(
            "blockID too short: {} bytes",
            block_id.len()
        )));
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "ref_block_bytes is the low 2 bytes of the height by definition"
    )]
    let ref_block_bytes = [(number >> 8) as u8, number as u8];
    let mut ref_block_hash = [0u8; 8];
    ref_block_hash.copy_from_slice(&block_id[8..16]);
    Ok(TronBlockRef {
        number,
        ref_block_bytes,
        ref_block_hash,
        timestamp_ms,
    })
}

/// Parse a `broadcasthex` / `broadcasttransaction` response.
///
/// # Errors
/// [`TronChainError::Decode`] if the body is not valid JSON.
pub fn parse_broadcast(body: &str) -> Result<TronBroadcastOutcome, TronChainError> {
    let v: Value = serde_json::from_str(body).map_err(|e| TronChainError::Decode(e.to_string()))?;
    Ok(TronBroadcastOutcome {
        result: v.get("result").and_then(Value::as_bool).unwrap_or(false),
        code: v
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        txid: v
            .get("txid")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

/// Parse a `gettransactioninfobyid` response. An empty object (the node's
/// "not yet in a block" sentinel) yields `None`.
///
/// # Errors
/// [`TronChainError::Decode`] if the body is not valid JSON.
pub fn parse_transaction_info(body: &str) -> Result<Option<TronTxReceipt>, TronChainError> {
    let v: Value = serde_json::from_str(body).map_err(|e| TronChainError::Decode(e.to_string()))?;
    // Not yet confirmed: the node returns `{}` (no `id` / `blockNumber`).
    let Some(block_number) = v.get("blockNumber").and_then(Value::as_u64) else {
        return Ok(None);
    };
    // Top-level `result` is "FAILED" on a reverted tx; absent on success.
    let top_failed = v.get("result").and_then(Value::as_str) == Some("FAILED");
    // Contract calls carry `receipt.result`; a plain TRX transfer omits it.
    let receipt_ok = match v.get("receipt").and_then(|r| r.get("result")) {
        None => true,
        Some(r) => r.as_str() == Some("SUCCESS"),
    };
    Ok(Some(TronTxReceipt {
        block_number,
        success: !top_failed && receipt_ok,
    }))
}

// ─── production reqwest impl ────────────────────────────────────────────────

/// Production [`TronChainClient`] over the TRON full-node HTTP API.
#[derive(Debug, Clone)]
pub struct ReqwestTronChainClient {
    chain: ChainId,
    base_url: String,
    http: reqwest::Client,
}

impl ReqwestTronChainClient {
    /// Build a client for `chain` against a TRON full-node base URL (e.g.
    /// `https://api.trongrid.io`). The `wallet/*` path is appended per call.
    ///
    /// # Errors
    /// - [`TronChainError::NotTronChain`] if `chain` is not TRON.
    /// - [`TronChainError::Rpc`] if the HTTP client cannot be built.
    pub fn new(chain: ChainId, base_url: impl Into<String>) -> Result<Self, TronChainError> {
        if chain.custody_family() != CustodyFamily::Tron {
            return Err(TronChainError::NotTronChain(chain));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
            .build()
            .map_err(|e| TronChainError::Rpc(e.to_string()))?;
        let base = base_url.into();
        Ok(Self {
            chain,
            base_url: base.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// POST a `wallet/{method}` JSON body and return the raw response text.
    async fn post(&self, method: &str, body: Value) -> Result<String, TronChainError> {
        let url = format!("{}/wallet/{method}", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| TronChainError::Rpc(e.to_string()))?;
        resp.text()
            .await
            .map_err(|e| TronChainError::Rpc(e.to_string()))
    }
}

impl TronChainClient for ReqwestTronChainClient {
    fn chain(&self) -> ChainId {
        self.chain
    }

    async fn now_block(&self) -> Result<TronBlockRef, TronChainError> {
        let body = self.post("getnowblock", json!({})).await?;
        parse_now_block(&body)
    }

    async fn broadcast_hex(&self, tx_hex: &str) -> Result<TronBroadcastOutcome, TronChainError> {
        let hex = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
        let body = self
            .post("broadcasthex", json!({ "transaction": hex }))
            .await?;
        parse_broadcast(&body)
    }

    async fn transaction_info(
        &self,
        txid_hex: &str,
    ) -> Result<Option<TronTxReceipt>, TronChainError> {
        let hex = txid_hex.strip_prefix("0x").unwrap_or(txid_hex);
        let body = self
            .post("gettransactioninfobyid", json!({ "value": hex }))
            .await?;
        parse_transaction_info(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SOURCED-style `getnowblock`: a `blockID` whose bytes [8:16] are the
    /// `ref_block_hash` and whose `number` low-2-bytes are the
    /// `ref_block_bytes` (matching the `THORChain` `createtransaction.json`
    /// envelope `00b0` / `3f1bc96dc80e7f61`).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn now_block_derives_tapos_fields() {
        // number 0xb0 in the low 2 bytes; blockID[8..16] = 3f1bc96dc80e7f61.
        let body = r#"{
            "blockID": "00000000000000b03f1bc96dc80e7f6100000000000000000000000000000000",
            "block_header": { "raw_data": { "number": 176, "timestamp": 1548974072663 } }
        }"#;
        let r = parse_now_block(body).expect("now block");
        assert_eq!(r.number, 176);
        assert_eq!(r.ref_block_bytes, [0x00, 0xb0]);
        assert_eq!(
            r.ref_block_hash,
            [0x3f, 0x1b, 0xc9, 0x6d, 0xc8, 0x0e, 0x7f, 0x61]
        );
        assert_eq!(r.timestamp_ms, 1_548_974_072_663);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn broadcast_accepts_success_and_dup() {
        let ok = parse_broadcast(r#"{"result":true,"txid":"deadbeef"}"#).expect("ok");
        assert!(ok.accepted());
        assert_eq!(ok.txid, "deadbeef");

        let dup = parse_broadcast(r#"{"result":false,"code":"DUP_TRANSACTION_ERROR"}"#).expect("d");
        assert!(dup.accepted(), "duplicate is idempotent success");

        let fail = parse_broadcast(r#"{"result":false,"code":"TRANSACTION_EXPIRATION_ERROR"}"#)
            .expect("f");
        assert!(!fail.accepted());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn transaction_info_pending_confirmed_and_failed() {
        // Empty object → not yet in a block.
        assert_eq!(parse_transaction_info("{}").expect("pending"), None);

        // Plain TRX transfer (no receipt.result) → success.
        let trx = parse_transaction_info(r#"{"id":"aa","blockNumber":1234}"#).expect("trx");
        assert_eq!(
            trx,
            Some(TronTxReceipt {
                block_number: 1234,
                success: true
            })
        );

        // TRC20 contract call success.
        let usdt =
            parse_transaction_info(r#"{"id":"bb","blockNumber":5,"receipt":{"result":"SUCCESS"}}"#)
                .expect("usdt");
        assert!(usdt.expect("some").success);

        // Reverted contract call (receipt OUT_OF_ENERGY) → not success.
        let bad = parse_transaction_info(
            r#"{"id":"cc","blockNumber":6,"result":"FAILED","receipt":{"result":"OUT_OF_ENERGY"}}"#,
        )
        .expect("bad");
        assert!(!bad.expect("some").success);
    }

    #[test]
    fn new_rejects_non_tron_chain() {
        assert!(matches!(
            ReqwestTronChainClient::new(ChainId::Xrp, "http://x"),
            Err(TronChainError::NotTronChain(ChainId::Xrp))
        ));
    }
}
