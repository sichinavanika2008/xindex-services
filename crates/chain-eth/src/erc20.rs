//! Concrete [`Erc20ArrivalClient`] for the redemption-delivery
//! cross-check: confirm the USDT `THORChain` swapped actually landed at
//! the `IndexToken` contract (R1) before a signer attests delivery.
//!
//! The trait lives in `xindex-signer` (not here) because `chain-eth`
//! depends on `signer`; this concrete impl satisfies it and is injected
//! by the `xindex-attest-redeem` binary — exactly the mint pattern
//! where `UtxoChainClient` lives in `chain-btc` and `EsploraClient`
//! is the concrete client wired by the binary.
//!
//! `transfers_to` is SYNC (mirrors `chain-btc`'s `UtxoChainClient` /
//! `find_arrival`, which the async `ThorUtxoPolicy` already calls into).
//! Same accepted trade-off: a blocking JSON-RPC call inside the
//! low-frequency signer path. Uses `reqwest::blocking` rather than
//! pulling a full async provider through the sync boundary.

use std::str::FromStr;
use std::{collections::HashMap, io::Read};

use alloy_primitives::{Address, B256, U256};
use serde::Serialize;
use serde_json::json;
use xindex_signer::crosscheck::{Erc20Arrival, Erc20ArrivalClient, Erc20Error};

/// `keccak256("Transfer(address,address,uint256)")` — the ERC20
/// Transfer event topic0. Pinned (USDT predates events-by-name tooling
/// and never changes).
const TRANSFER_TOPIC0: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const MAX_RPC_BODY_BYTES: u64 = 16 * 1024 * 1024;

/// Blocking JSON-RPC `Erc20ArrivalClient`. Scans the last
/// `lookback_blocks` for `Transfer(_, to, value)` logs of `token`.
#[derive(Debug, Clone)]
pub struct RpcErc20LogClient {
    http_rpc_url: String,
    /// How far back to scan. A redemption's USDT arrives shortly after
    /// the BTC→Asgard deposit confirms; a day-ish window is ample and
    /// bounds the `eth_getLogs` range so a public RPC won't reject it.
    lookback_blocks: u64,
    client: reqwest::blocking::Client,
}

impl RpcErc20LogClient {
    /// `http_rpc_url` must be an HTTP(S) endpoint (not WS) — this is a
    /// one-shot blocking request path.
    #[must_use]
    pub fn new(http_rpc_url: impl Into<String>, lookback_blocks: u64) -> Self {
        Self {
            http_rpc_url: http_rpc_url.into(),
            lookback_blocks,
            client: reqwest::blocking::Client::new(),
        }
    }

    fn rpc(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, Erc20Error> {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let resp = self
            .client
            .post(&self.http_rpc_url)
            .json(&body)
            .send()
            .map_err(|e| Erc20Error::Rpc(format!("{method} send: {e}")))?;
        let v: serde_json::Value = resp
            .json()
            .map_err(|e| Erc20Error::Rpc(format!("{method} decode: {e}")))?;
        if let Some(err) = v.get("error") {
            return Err(Erc20Error::Rpc(format!("{method}: {err}")));
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| Erc20Error::Rpc(format!("{method}: no result")))
    }

    fn block_number(&self) -> Result<u64, Erc20Error> {
        let r = self.rpc("eth_blockNumber", &json!([]))?;
        parse_hex_u64(
            r.as_str()
                .ok_or_else(|| Erc20Error::Rpc("blockNumber not str".into()))?,
        )
    }
}

/// `0x`-hex (left-padded 32-byte) of an address, as topics are encoded.
fn addr_topic(a: Address) -> String {
    format!("0x{:0>64}", alloy_primitives::hex::encode(a.as_slice()))
}

fn parse_hex_u64(s: &str) -> Result<u64, Erc20Error> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|e| Erc20Error::Rpc(format!("bad hex u64 '{s}': {e}")))
}

/// Decode one `eth_getLogs` entry into an [`Erc20Arrival`] given the
/// current tip. `value` is the 32-byte data word; confirmations =
/// `tip − logBlock + 1` (0 if the log is somehow ahead of tip).
fn decode_transfer_log(
    log: &serde_json::Value,
    tip: u64,
    token: Address,
    expected_to: Address,
) -> Result<Erc20Arrival, Erc20Error> {
    // Client-side emitter re-assert (audit I5): the node-side `address` filter
    // already binds the emitting contract to `token`, but a non-compliant RPC
    // could return a Transfer log emitted by a different contract — never
    // count it as a credit of `token`.
    let log_addr = log
        .get("address")
        .and_then(|a| a.as_str())
        .ok_or_else(|| Erc20Error::Rpc("log missing address".into()))?;
    if !log_addr.eq_ignore_ascii_case(&format!("{token:#x}")) {
        return Err(Erc20Error::Rpc(format!(
            "log address {log_addr} != expected token {token:#x}"
        )));
    }
    // Client-side recipient re-assert (RUST-006, mirrors the L6 redeem-side
    // re-assert): the node-side topic filter already binds the `to` topic, but
    // a non-compliant RPC could return a Transfer to a different recipient —
    // never count it as a credit to `expected_to`.
    let to_topic = log
        .get("topics")
        .and_then(|t| t.get(2))
        .and_then(|t| t.as_str())
        .ok_or_else(|| Erc20Error::Rpc("log missing to topic".into()))?;
    if !to_topic.eq_ignore_ascii_case(&addr_topic(expected_to)) {
        return Err(Erc20Error::Rpc(format!(
            "log to topic {to_topic} != expected {expected_to:#x}"
        )));
    }
    let data = log
        .get("data")
        .and_then(|d| d.as_str())
        .ok_or_else(|| Erc20Error::Rpc("log missing data".into()))?;
    let value = U256::from_str_radix(data.strip_prefix("0x").unwrap_or(data), 16)
        .map_err(|e| Erc20Error::Rpc(format!("bad transfer value: {e}")))?;
    let value: u128 = value
        .try_into()
        .map_err(|_| Erc20Error::Rpc("transfer value > u128".into()))?;
    let block = log
        .get("blockNumber")
        .and_then(|b| b.as_str())
        .ok_or_else(|| Erc20Error::Rpc("log missing blockNumber".into()))?;
    let block = parse_hex_u64(block)?;
    let confirmations =
        u32::try_from(tip.saturating_sub(block).saturating_add(1)).unwrap_or(u32::MAX);
    // RUST-004: carry the physical inflow identity (transaction_hash,
    // log_index) so the cross-check can bind it 1:1 to the THORChain outbound
    // and consume it exactly once.
    let tx_hash_str = log
        .get("transactionHash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| Erc20Error::Rpc("log missing transactionHash".into()))?;
    let transaction_hash = B256::from_str(tx_hash_str)
        .map_err(|e| Erc20Error::Rpc(format!("bad transactionHash '{tx_hash_str}': {e}")))?;
    let log_index_str = log
        .get("logIndex")
        .and_then(|i| i.as_str())
        .ok_or_else(|| Erc20Error::Rpc("log missing logIndex".into()))?;
    let log_index = parse_hex_u64(log_index_str)?;
    Ok(Erc20Arrival {
        value,
        confirmations,
        transaction_hash,
        log_index,
    })
}

impl Erc20ArrivalClient for RpcErc20LogClient {
    fn transfers_to(&self, token: Address, to: Address) -> Result<Vec<Erc20Arrival>, Erc20Error> {
        let tip = self.block_number()?;
        let from = tip.saturating_sub(self.lookback_blocks);
        let filter = json!([{
            "address": format!("{token:#x}"),
            "fromBlock": format!("0x{from:x}"),
            "toBlock": "latest",
            // topics: [Transfer, anyFrom, to]
            "topics": [TRANSFER_TOPIC0, serde_json::Value::Null, addr_topic(to)],
        }]);
        let logs = self.rpc("eth_getLogs", &filter)?;
        let arr = logs
            .as_array()
            .ok_or_else(|| Erc20Error::Rpc("getLogs result not array".into()))?;
        let mut out = Vec::with_capacity(arr.len());
        for log in arr {
            out.push(decode_transfer_log(log, tip, token, to)?);
        }
        Ok(out)
    }
}

/// Finalized-only variant used by production settlement observers. It pins
/// `eth_getLogs.toBlock` to the RPC's explicit `finalized` head and rechecks
/// every returned log's block hash against `eth_getBlockByNumber` before the
/// transfer can be credited.
#[derive(Debug, Clone)]
pub struct FinalizedRpcErc20LogClient {
    http_rpc_url: String,
    lookback_blocks: u64,
    client: reqwest::blocking::Client,
}

/// One exact successful JSON-RPC request/response pair used to derive a
/// finalized ERC-20 observation. Endpoint URLs and credentials are excluded;
/// the public method/params and byte-for-byte UTF-8 response body are retained.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizedRpcCallEvidence {
    pub method: String,
    pub params: serde_json::Value,
    pub response_body: String,
}

/// Finalized transfer snapshot plus every exact RPC response used to prove its
/// head, log set, and canonical block hashes.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizedErc20Observation {
    pub finalized_head_number: u64,
    pub finalized_head_hash: B256,
    pub arrivals: Vec<Erc20Arrival>,
    pub rpc_calls: Vec<FinalizedRpcCallEvidence>,
}

struct RpcCall {
    result: serde_json::Value,
    evidence: FinalizedRpcCallEvidence,
}

impl FinalizedRpcErc20LogClient {
    /// Construct a finalized-only transfer observer.
    #[must_use]
    pub fn new(http_rpc_url: impl Into<String>, lookback_blocks: u64) -> Self {
        Self {
            http_rpc_url: http_rpc_url.into(),
            lookback_blocks,
            client: reqwest::blocking::Client::new(),
        }
    }

    fn rpc_evidence(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<RpcCall, Erc20Error> {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let mut response = self
            .client
            .post(&self.http_rpc_url)
            .json(&body)
            .send()
            .map_err(|error| Erc20Error::Rpc(format!("{method} transport: {error}")))?;
        if !response.status().is_success() {
            return Err(Erc20Error::Rpc(format!(
                "{method} HTTP {}",
                response.status().as_u16()
            )));
        }
        let mut bytes = Vec::new();
        response
            .by_ref()
            .take(MAX_RPC_BODY_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| Erc20Error::Rpc(format!("{method} body: {error}")))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RPC_BODY_BYTES {
            return Err(Erc20Error::Rpc(format!("{method} response too large")));
        }
        let response_body = String::from_utf8(bytes)
            .map_err(|error| Erc20Error::Rpc(format!("{method} response is not UTF-8: {error}")))?;
        let value: serde_json::Value = serde_json::from_str(&response_body)
            .map_err(|error| Erc20Error::Rpc(format!("{method} decode: {error}")))?;
        if value.get("jsonrpc").and_then(serde_json::Value::as_str) != Some("2.0")
            || value.get("id").and_then(serde_json::Value::as_u64) != Some(1)
        {
            return Err(Erc20Error::Rpc(format!(
                "{method} JSON-RPC version/id mismatch"
            )));
        }
        if value.get("error").is_some() {
            return Err(Erc20Error::Rpc(format!("{method} returned error")));
        }
        let result = value
            .get("result")
            .cloned()
            .ok_or_else(|| Erc20Error::Rpc(format!("{method}: no result")))?;
        Ok(RpcCall {
            result,
            evidence: FinalizedRpcCallEvidence {
                method: method.to_string(),
                params: params.clone(),
                response_body,
            },
        })
    }

    fn finalized_head(
        &self,
        calls: &mut Vec<FinalizedRpcCallEvidence>,
    ) -> Result<(u64, B256), Erc20Error> {
        let call = self.rpc_evidence("eth_getBlockByNumber", &json!(["finalized", false]))?;
        calls.push(call.evidence);
        let result = call.result;
        let number_raw = result
            .get("number")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Erc20Error::Rpc("finalized block missing number".to_string()))?;
        let hash_raw = result
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Erc20Error::Rpc("finalized block missing hash".to_string()))?;
        let number = parse_hex_u64(number_raw)?;
        let hash = B256::from_str(hash_raw)
            .map_err(|error| Erc20Error::Rpc(format!("finalized block hash: {error}")))?;
        if hash == B256::ZERO {
            return Err(Erc20Error::Rpc("finalized block hash is zero".to_string()));
        }
        Ok((number, hash))
    }

    fn block_hash(
        &self,
        number: u64,
        calls: &mut Vec<FinalizedRpcCallEvidence>,
    ) -> Result<B256, Erc20Error> {
        let call = self.rpc_evidence(
            "eth_getBlockByNumber",
            &json!([format!("0x{number:x}"), false]),
        )?;
        calls.push(call.evidence);
        let result = call.result;
        let returned_number = result
            .get("number")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Erc20Error::Rpc("canonical block missing number".to_string()))?;
        if parse_hex_u64(returned_number)? != number {
            return Err(Erc20Error::Rpc(
                "canonical block number mismatch".to_string(),
            ));
        }
        let hash_raw = result
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Erc20Error::Rpc("canonical block missing hash".to_string()))?;
        B256::from_str(hash_raw)
            .map_err(|error| Erc20Error::Rpc(format!("canonical block hash: {error}")))
    }

    /// Capture a finalized transfer snapshot together with exact successful
    /// JSON-RPC response bodies. The decoded snapshot and the evidence share
    /// one request sequence; no second query is needed before signing.
    ///
    /// # Errors
    /// Transport/schema/canonicality failures are surfaced as [`Erc20Error`].
    pub fn transfers_to_evidence(
        &self,
        token: Address,
        to: Address,
    ) -> Result<FinalizedErc20Observation, Erc20Error> {
        let mut rpc_calls = Vec::new();
        let (tip, finalized_head_hash) = self.finalized_head(&mut rpc_calls)?;
        let from = tip.saturating_sub(self.lookback_blocks);
        let call = self.rpc_evidence(
            "eth_getLogs",
            &json!([{
                "address": format!("{token:#x}"),
                "fromBlock": format!("0x{from:x}"),
                "toBlock": format!("0x{tip:x}"),
                "topics": [TRANSFER_TOPIC0, serde_json::Value::Null, addr_topic(to)],
            }]),
        )?;
        rpc_calls.push(call.evidence);
        let logs = call
            .result
            .as_array()
            .ok_or_else(|| Erc20Error::Rpc("getLogs result not array".to_string()))?;
        let mut canonical_hashes = HashMap::new();
        let mut arrivals = Vec::with_capacity(logs.len());
        for log in logs {
            if log
                .get("removed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                return Err(Erc20Error::Rpc(
                    "finalized query returned removed log".to_string(),
                ));
            }
            let number_raw = log
                .get("blockNumber")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Erc20Error::Rpc("log missing blockNumber".to_string()))?;
            let number = parse_hex_u64(number_raw)?;
            if number > tip {
                return Err(Erc20Error::Rpc(
                    "log is ahead of finalized head".to_string(),
                ));
            }
            let log_hash_raw = log
                .get("blockHash")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Erc20Error::Rpc("log missing blockHash".to_string()))?;
            let log_hash = B256::from_str(log_hash_raw)
                .map_err(|error| Erc20Error::Rpc(format!("log blockHash: {error}")))?;
            let canonical = if let Some(hash) = canonical_hashes.get(&number) {
                *hash
            } else {
                let hash = self.block_hash(number, &mut rpc_calls)?;
                canonical_hashes.insert(number, hash);
                hash
            };
            if canonical != log_hash {
                return Err(Erc20Error::Rpc(
                    "log block hash is not canonical".to_string(),
                ));
            }
            arrivals.push(decode_transfer_log(log, tip, token, to)?);
        }
        Ok(FinalizedErc20Observation {
            finalized_head_number: tip,
            finalized_head_hash,
            arrivals,
            rpc_calls,
        })
    }
}

impl Erc20ArrivalClient for FinalizedRpcErc20LogClient {
    fn transfers_to(&self, token: Address, to: Address) -> Result<Vec<Erc20Arrival>, Erc20Error> {
        Ok(self.transfers_to_evidence(token, to)?.arrivals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_topic0_is_canonical() {
        // keccak256("Transfer(address,address,uint256)")
        assert_eq!(
            TRANSFER_TOPIC0,
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
    }

    #[test]
    fn addr_topic_is_left_padded_32_bytes() {
        let a = Address::from([0x11u8; 20]);
        let t = addr_topic(a);
        assert_eq!(t.len(), 66); // 0x + 64
        assert!(t.starts_with("0x000000000000000000000000"));
        assert!(t.ends_with(&"11".repeat(20)));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn decode_transfer_log_value_and_confirmations() {
        // 70 USDT (1e6) = 70_000_000 = 0x42c1d80, block 100, tip 105 ⇒ 6 confs.
        let token = Address::from([0x11u8; 20]);
        let to = Address::from([0x33u8; 20]);
        let log = json!({
            "address": format!("{token:#x}"),
            "topics": [TRANSFER_TOPIC0, serde_json::Value::Null, addr_topic(to)],
            "data": "0x00000000000000000000000000000000000000000000000000000000042c1d80",
            "blockNumber": "0x64",
            "transactionHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "logIndex": "0x5"
        });
        let a = decode_transfer_log(&log, 105, token, to).expect("decode");
        assert_eq!(a.value, 70_000_000);
        assert_eq!(a.confirmations, 6);
        assert_eq!(a.transaction_hash, B256::repeat_byte(0x11));
        assert_eq!(a.log_index, 5);
    }

    /// I5: a Transfer log whose emitting contract is NOT the expected token
    /// (a non-compliant RPC ignoring the `address` filter) is rejected, never
    /// counted as a credit of `token`.
    #[test]
    fn decode_transfer_log_rejects_foreign_token_address() {
        let token = Address::from([0x11u8; 20]);
        let to = Address::from([0x33u8; 20]);
        let foreign = Address::from([0x22u8; 20]);
        let log = json!({
            "address": format!("{foreign:#x}"),
            "topics": [TRANSFER_TOPIC0, serde_json::Value::Null, addr_topic(to)],
            "data": "0x00000000000000000000000000000000000000000000000000000000042c1d80",
            "blockNumber": "0x64"
        });
        assert!(decode_transfer_log(&log, 105, token, to).is_err());
    }

    /// RUST-006: a Transfer log to a DIFFERENT recipient (a non-compliant RPC
    /// ignoring the `to` topic filter) is rejected — mirrors the L6 redeem-side
    /// re-assert. The emitter address is correct here, so only the `to` pin
    /// catches it.
    #[test]
    fn decode_transfer_log_rejects_foreign_recipient() {
        let token = Address::from([0x11u8; 20]);
        let to = Address::from([0x33u8; 20]);
        let other = Address::from([0x44u8; 20]);
        let log = json!({
            "address": format!("{token:#x}"),
            "topics": [TRANSFER_TOPIC0, serde_json::Value::Null, addr_topic(other)],
            "data": "0x00000000000000000000000000000000000000000000000000000000042c1d80",
            "blockNumber": "0x64"
        });
        assert!(decode_transfer_log(&log, 105, token, to).is_err());
    }

    #[test]
    fn parse_hex_u64_handles_prefix() {
        assert_eq!(parse_hex_u64("0x10").ok(), Some(16));
        assert_eq!(parse_hex_u64("ff").ok(), Some(255));
        assert!(parse_hex_u64("zz").is_err());
    }
}
