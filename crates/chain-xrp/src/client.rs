//! [`XrpChainClient`] trait + production [`ReqwestXrpChainClient`] impl,
//! plus the pure JSON parsers the impl delegates to.
//!
//! The trait is what C6 (cross-check) and C7 (executor) program against,
//! mirroring `CosmosChainClient`. The production impl talks `rippled`
//! JSON-RPC over `reqwest` HTTP POST. Parsing is split into pure
//! functions so it is unit-testable without a live node.

use std::future::Future;
use std::time::Duration;

use serde_json::{json, Value};
use thiserror::Error;
use xindex_shared::chain_registry::{ChainId, CustodyFamily};

/// Per-request timeout — a stalled RPC must not wedge the inline
/// cross-check / executor (matches the `chain-cosmos` posture).
const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Connection-establishment timeout (shorter than the request budget).
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Account state from `account_info` — the `Sequence` (nonce) the
/// executor binds into the `Payment` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XrpAccount {
    /// Monotonic per-account transaction sequence (the XRPL nonce).
    pub sequence: u32,
}

/// A delivered `Payment` to a destination, decoded from `account_tx`.
/// Used by the cross-check to verify a `THORChain` delivery / refund
/// actually landed at our multisig account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrpTransfer {
    /// Validated ledger index the payment was included in.
    pub ledger_index: u64,
    /// Transaction hash (uppercase hex, XRPL convention).
    pub txhash: String,
    /// `tx.Account` — the sender. The cross-check binds a delivery/refund
    /// to its expected origin (the `THORChain` Asgard vault); a
    /// destination+amount match alone is forgeable by anyone who pays our
    /// public address.
    pub sender: String,
    /// `tx.Destination` — the recipient (our multisig r-address).
    pub destination: String,
    /// **`meta.delivered_amount`** in drops — the actually-delivered
    /// amount, NOT `tx.Amount` (which `tfPartialPayment` can exceed).
    pub delivered_drops: u128,
}

/// Outcome of a `submit` (node-provisional application, not validation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrpSubmitOutcome {
    /// `engine_result` (e.g. `"tesSUCCESS"`, `"terQUEUED"`,
    /// `"tefPAST_SEQ"`).
    pub engine_result: String,
    /// Transaction hash the node computed.
    pub txhash: String,
}

impl XrpSubmitOutcome {
    /// `true` iff the node provisionally applied the tx (`tesSUCCESS`).
    /// Final inclusion is confirmed separately via `account_tx` +
    /// `validated` — never inferred from this provisional result.
    #[must_use]
    pub fn accepted(&self) -> bool {
        self.engine_result == "tesSUCCESS"
    }
}

/// Errors surfaced by every [`XrpChainClient`] method.
#[derive(Debug, Error)]
pub enum XrpChainError {
    /// Transport / HTTP failure.
    #[error("RPC error: {0}")]
    Rpc(String),
    /// Response body did not match the expected JSON shape, or `rippled`
    /// returned an error status.
    #[error("decode error: {0}")]
    Decode(String),
    /// The configured chain is not in the XRP custody family.
    #[error("chain {0:?} is not in the XRP custody family")]
    NotXrpChain(ChainId),
}

/// Per-XRP-chain RPC primitives. Returns `impl Future + Send` (not
/// `async fn`) so the futures are `Send`-bound at the trait level, like
/// `CosmosChainClient`.
pub trait XrpChainClient: Send + Sync + 'static {
    /// Which XRP chain this client targets.
    fn chain(&self) -> ChainId;

    /// Query the `Sequence` for `address` (`account_info`, validated
    /// ledger). The executor reads this to build the `Payment`.
    fn account_info(
        &self,
        address: &str,
    ) -> impl Future<Output = Result<XrpAccount, XrpChainError>> + Send;

    /// Current (in-progress) ledger index (`ledger_current`). The
    /// executor sets `LastLedgerSequence = current + buffer`.
    fn ledger_current(&self) -> impl Future<Output = Result<u64, XrpChainError>> + Send;

    /// Latest **validated** ledger index (`ledger` / validated). The
    /// cross-check uses it to gauge inclusion depth (`conf_depth`).
    fn latest_validated_ledger(&self) -> impl Future<Output = Result<u64, XrpChainError>> + Send;

    /// Find validated, successful `Payment`s delivered to `destination`
    /// at or above `min_ledger` (`account_tx`). Amounts come from
    /// `meta.delivered_amount` (never `tx.Amount`).
    fn transfers_to(
        &self,
        destination: &str,
        min_ledger: u64,
    ) -> impl Future<Output = Result<Vec<XrpTransfer>, XrpChainError>> + Send;

    /// Submit an already-assembled, multisigned tx-blob (`submit`).
    fn submit_tx_blob(
        &self,
        tx_blob: &[u8],
    ) -> impl Future<Output = Result<XrpSubmitOutcome, XrpChainError>> + Send;
}

// ─── pure parsers (unit-tested without a node) ──────────────────────────────

/// The `result` object of a `rippled` JSON-RPC response, after checking
/// `status == "success"`.
///
/// # Errors
/// [`XrpChainError::Decode`] if `result` is missing or its `status` is
/// not `"success"` (surfacing the `rippled` `error` field).
fn result_object(body: &str) -> Result<Value, XrpChainError> {
    let v: Value = serde_json::from_str(body).map_err(|e| XrpChainError::Decode(e.to_string()))?;
    let result = v
        .get("result")
        .ok_or_else(|| XrpChainError::Decode("missing result".into()))?;
    if result.get("status").and_then(Value::as_str) == Some("success") {
        Ok(result.clone())
    } else {
        let err = result
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        Err(XrpChainError::Decode(format!("rippled error: {err}")))
    }
}

/// Parse the `Sequence` from an `account_info` response.
///
/// # Errors
/// [`XrpChainError::Decode`] on a non-success status or a missing /
/// out-of-range `Sequence`.
pub fn parse_account_info(body: &str) -> Result<XrpAccount, XrpChainError> {
    let result = result_object(body)?;
    let seq = result
        .get("account_data")
        .and_then(|a| a.get("Sequence"))
        .and_then(Value::as_u64)
        .ok_or_else(|| XrpChainError::Decode("missing account_data.Sequence".into()))?;
    let sequence =
        u32::try_from(seq).map_err(|_| XrpChainError::Decode(format!("Sequence {seq} > u32")))?;
    Ok(XrpAccount { sequence })
}

/// Parse `ledger_current_index` from a `ledger_current` response.
///
/// # Errors
/// [`XrpChainError::Decode`] on a non-success status or a missing index.
pub fn parse_ledger_current(body: &str) -> Result<u64, XrpChainError> {
    let result = result_object(body)?;
    result
        .get("ledger_current_index")
        .and_then(Value::as_u64)
        .ok_or_else(|| XrpChainError::Decode("missing ledger_current_index".into()))
}

/// Parse the validated `ledger_index` from a `ledger` (validated)
/// response.
///
/// # Errors
/// [`XrpChainError::Decode`] on a non-success status or a missing index.
pub fn parse_validated_ledger(body: &str) -> Result<u64, XrpChainError> {
    let result = result_object(body)?;
    result
        .get("ledger_index")
        .and_then(Value::as_u64)
        .or_else(|| {
            result
                .get("ledger")
                .and_then(|l| l.get("ledger_index"))
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<u64>().ok())
        })
        .ok_or_else(|| XrpChainError::Decode("missing ledger_index".into()))
}

/// Extract the delivered drops from a transaction's `meta`, reading
/// **`delivered_amount`** only (never `Amount`).
///
/// Returns `None` (unverifiable, drop the transfer) when
/// `delivered_amount` is absent, the sentinel `"unavailable"`, or a
/// non-XRP issued-currency object. NEVER falls back to `Amount`.
#[must_use]
pub fn parse_delivered_drops(meta: &Value) -> Option<u128> {
    let d = meta
        .get("delivered_amount")
        .or_else(|| meta.get("DeliveredAmount"))?;
    match d {
        Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse::<u128>().ok()
        }
        _ => None,
    }
}

/// Parse validated, successful `Payment`s to `want_dest` (≥ `min_ledger`)
/// from an `account_tx` response. Handles both API-v1 (`tx` / `meta`) and
/// API-v2 (`tx_json` / `meta`) shapes.
///
/// # Errors
/// [`XrpChainError::Decode`] on a non-success status or a missing
/// `transactions` array.
pub fn parse_account_tx(
    body: &str,
    want_dest: &str,
    min_ledger: u64,
) -> Result<Vec<XrpTransfer>, XrpChainError> {
    let result = result_object(body)?;
    let txs = result
        .get("transactions")
        .and_then(Value::as_array)
        .ok_or_else(|| XrpChainError::Decode("missing transactions".into()))?;
    let mut out = Vec::new();
    for entry in txs {
        if entry.get("validated").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let Some(meta) = entry.get("meta").or_else(|| entry.get("metaData")) else {
            continue;
        };
        if meta.get("TransactionResult").and_then(Value::as_str) != Some("tesSUCCESS") {
            continue;
        }
        let Some(tx) = entry.get("tx").or_else(|| entry.get("tx_json")) else {
            continue;
        };
        if tx.get("TransactionType").and_then(Value::as_str) != Some("Payment") {
            continue;
        }
        if tx.get("Destination").and_then(Value::as_str) != Some(want_dest) {
            continue;
        }
        let ledger_index = tx
            .get("ledger_index")
            .and_then(Value::as_u64)
            .or_else(|| entry.get("ledger_index").and_then(Value::as_u64))
            .unwrap_or(0);
        if ledger_index < min_ledger {
            continue;
        }
        let Some(delivered_drops) = parse_delivered_drops(meta) else {
            continue;
        };
        out.push(XrpTransfer {
            ledger_index,
            txhash: tx
                .get("hash")
                .and_then(Value::as_str)
                .or_else(|| entry.get("hash").and_then(Value::as_str))
                .unwrap_or_default()
                .to_string(),
            sender: tx
                .get("Account")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            destination: want_dest.to_string(),
            delivered_drops,
        });
    }
    Ok(out)
}

/// Parse a `submit` response.
///
/// # Errors
/// [`XrpChainError::Decode`] on a non-success status or a missing
/// `engine_result`.
pub fn parse_submit(body: &str) -> Result<XrpSubmitOutcome, XrpChainError> {
    let result = result_object(body)?;
    let engine_result = result
        .get("engine_result")
        .and_then(Value::as_str)
        .ok_or_else(|| XrpChainError::Decode("missing engine_result".into()))?
        .to_string();
    let txhash = result
        .get("tx_json")
        .and_then(|t| t.get("hash"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(XrpSubmitOutcome {
        engine_result,
        txhash,
    })
}

// ─── production reqwest impl ────────────────────────────────────────────────

/// Production [`XrpChainClient`] over `rippled` JSON-RPC (HTTP POST).
#[derive(Debug, Clone)]
pub struct ReqwestXrpChainClient {
    chain: ChainId,
    rpc_url: String,
    http: reqwest::Client,
}

impl ReqwestXrpChainClient {
    /// Build a client for `chain` against a `rippled` JSON-RPC URL.
    ///
    /// # Errors
    /// - [`XrpChainError::NotXrpChain`] if `chain` is not XRP.
    /// - [`XrpChainError::Rpc`] if the HTTP client cannot be built.
    pub fn new(chain: ChainId, rpc_url: impl Into<String>) -> Result<Self, XrpChainError> {
        if chain.custody_family() != CustodyFamily::Xrp {
            return Err(XrpChainError::NotXrpChain(chain));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
            .build()
            .map_err(|e| XrpChainError::Rpc(e.to_string()))?;
        Ok(Self {
            chain,
            rpc_url: rpc_url.into(),
            http,
        })
    }

    /// POST a `rippled` JSON-RPC `{method, params:[param]}` and return the
    /// raw response body.
    async fn rpc(&self, method: &str, param: Value) -> Result<String, XrpChainError> {
        let body = json!({ "method": method, "params": [param] });
        let resp = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| XrpChainError::Rpc(e.to_string()))?;
        resp.text()
            .await
            .map_err(|e| XrpChainError::Rpc(e.to_string()))
    }
}

/// Lower-case hex of `bytes` (for the `submit` `tx_blob` param).
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(HEX[(b >> 4) as usize]));
        s.push(char::from(HEX[(b & 0x0f) as usize]));
    }
    s
}

impl XrpChainClient for ReqwestXrpChainClient {
    fn chain(&self) -> ChainId {
        self.chain
    }

    async fn account_info(&self, address: &str) -> Result<XrpAccount, XrpChainError> {
        let body = self
            .rpc(
                "account_info",
                json!({ "account": address, "ledger_index": "validated" }),
            )
            .await?;
        parse_account_info(&body)
    }

    async fn ledger_current(&self) -> Result<u64, XrpChainError> {
        let body = self.rpc("ledger_current", json!({})).await?;
        parse_ledger_current(&body)
    }

    async fn latest_validated_ledger(&self) -> Result<u64, XrpChainError> {
        let body = self
            .rpc("ledger", json!({ "ledger_index": "validated" }))
            .await?;
        parse_validated_ledger(&body)
    }

    async fn transfers_to(
        &self,
        destination: &str,
        min_ledger: u64,
    ) -> Result<Vec<XrpTransfer>, XrpChainError> {
        let min = i64::try_from(min_ledger).unwrap_or(-1);
        let body = self
            .rpc(
                "account_tx",
                json!({
                    "account": destination,
                    "ledger_index_min": min,
                    "ledger_index_max": -1,
                    "forward": true,
                    "limit": 100,
                }),
            )
            .await?;
        parse_account_tx(&body, destination, min_ledger)
    }

    async fn submit_tx_blob(&self, tx_blob: &[u8]) -> Result<XrpSubmitOutcome, XrpChainError> {
        let body = self
            .rpc("submit", json!({ "tx_blob": to_hex(tx_blob) }))
            .await?;
        parse_submit(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn account_info_parses_sequence() {
        let body = r#"{"result":{"status":"success","account_data":{"Account":"rVault","Sequence":42,"Balance":"100000000"}}}"#;
        assert_eq!(parse_account_info(body).expect("acct").sequence, 42);
        // Error status surfaces.
        assert!(
            parse_account_info(r#"{"result":{"status":"error","error":"actNotFound"}}"#).is_err()
        );
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn ledger_indices_parse() {
        let cur = r#"{"result":{"status":"success","ledger_current_index":9000123}}"#;
        assert_eq!(parse_ledger_current(cur).expect("cur"), 9_000_123);
        let val = r#"{"result":{"status":"success","ledger_index":9000100,"validated":true}}"#;
        assert_eq!(parse_validated_ledger(val).expect("val"), 9_000_100);
    }

    /// The SECURITY-CRITICAL test: a `tfPartialPayment` whose `Amount`
    /// (10 XRP) vastly exceeds `delivered_amount` (1 drop) must be
    /// counted at the DELIVERED 1 drop, never the 10,000,000-drop Amount.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn partial_payment_counts_delivered_not_amount() {
        let body = r#"{"result":{"status":"success","transactions":[
            {"validated":true,
             "meta":{"TransactionResult":"tesSUCCESS","delivered_amount":"1"},
             "tx":{"TransactionType":"Payment","Account":"rThorVault","Destination":"rVault",
                   "Amount":"10000000","hash":"AAAA","ledger_index":9000100}}
        ]}}"#;
        let got = parse_account_tx(body, "rVault", 1).expect("parse");
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].delivered_drops, 1,
            "must use delivered_amount, NOT Amount"
        );
        assert_eq!(got[0].sender, "rThorVault");
        assert_eq!(got[0].ledger_index, 9_000_100);
    }

    /// A payment with no `delivered_amount` (or `"unavailable"`) is
    /// UNVERIFIABLE — dropped, never up-counted to `Amount`.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn missing_delivered_amount_is_dropped() {
        let body = r#"{"result":{"status":"success","transactions":[
            {"validated":true,
             "meta":{"TransactionResult":"tesSUCCESS"},
             "tx":{"TransactionType":"Payment","Account":"rT","Destination":"rVault",
                   "Amount":"10000000","hash":"AAAA","ledger_index":9000100}},
            {"validated":true,
             "meta":{"TransactionResult":"tesSUCCESS","delivered_amount":"unavailable"},
             "tx":{"TransactionType":"Payment","Account":"rT","Destination":"rVault",
                   "Amount":"5000000","hash":"BBBB","ledger_index":9000101}}
        ]}}"#;
        assert!(parse_account_tx(body, "rVault", 1)
            .expect("parse")
            .is_empty());
    }

    /// Filters: wrong destination, unvalidated, failed result, and
    /// below-min-ledger are all excluded.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn account_tx_filters() {
        let body = r#"{"result":{"status":"success","transactions":[
            {"validated":true,"meta":{"TransactionResult":"tesSUCCESS","delivered_amount":"100"},
             "tx":{"TransactionType":"Payment","Account":"rT","Destination":"rOther","Amount":"100","hash":"A","ledger_index":9000100}},
            {"validated":false,"meta":{"TransactionResult":"tesSUCCESS","delivered_amount":"100"},
             "tx":{"TransactionType":"Payment","Account":"rT","Destination":"rVault","Amount":"100","hash":"B","ledger_index":9000100}},
            {"validated":true,"meta":{"TransactionResult":"tecUNFUNDED_PAYMENT","delivered_amount":"0"},
             "tx":{"TransactionType":"Payment","Account":"rT","Destination":"rVault","Amount":"100","hash":"C","ledger_index":9000100}},
            {"validated":true,"meta":{"TransactionResult":"tesSUCCESS","delivered_amount":"200"},
             "tx":{"TransactionType":"Payment","Account":"rT","Destination":"rVault","Amount":"200","hash":"D","ledger_index":9000050}}
        ]}}"#;
        // Only the rVault hits qualify; height filter drops the 9000050 one.
        assert!(parse_account_tx(body, "rVault", 9_000_100)
            .expect("p")
            .is_empty());
        // Lower min-ledger lets the validated/tesSUCCESS one through (hash D).
        let got = parse_account_tx(body, "rVault", 9_000_000).expect("p");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].txhash, "D");
        assert_eq!(got[0].delivered_drops, 200);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn submit_parses_engine_result() {
        let ok = r#"{"result":{"status":"success","engine_result":"tesSUCCESS","tx_json":{"hash":"DEAD"}}}"#;
        let o = parse_submit(ok).expect("ok");
        assert!(o.accepted());
        assert_eq!(o.txhash, "DEAD");
        let bad = r#"{"result":{"status":"success","engine_result":"tefPAST_SEQ","tx_json":{"hash":"BEEF"}}}"#;
        let b = parse_submit(bad).expect("bad");
        assert!(!b.accepted());
        assert_eq!(b.engine_result, "tefPAST_SEQ");
    }

    #[test]
    fn to_hex_round() {
        assert_eq!(to_hex(&[0x00, 0x0a, 0xff]), "000aff");
    }

    #[test]
    fn new_rejects_non_xrp_chain() {
        assert!(matches!(
            ReqwestXrpChainClient::new(ChainId::Gaia, "http://x"),
            Err(XrpChainError::NotXrpChain(ChainId::Gaia))
        ));
    }
}
