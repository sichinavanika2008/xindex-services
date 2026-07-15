//! Bounded, evidence-preserving Ethereum JSON-RPC reads for finalized event
//! observers.
//!
//! Production observers deliberately poll the execution client's `finalized`
//! tag, then walk every intervening block by hash. Logs are requested with the
//! EIP-234 `blockHash` filter, so a response cannot silently mix a replacement
//! block at the same height into an already selected checkpoint.

use std::time::Duration;

use alloy_primitives::{keccak256, Address, Bytes, B256};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use xindex_ops::network::{async_client, read_bounded_async, HttpClientPolicy, NetworkError};

const MAX_RPC_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FinalizedRpcError {
    #[error("transport: {0}")]
    Transport(&'static str),
    #[error("HTTP {0}")]
    Http(u16),
    #[error("response exceeded {MAX_RPC_RESPONSE_BYTES} bytes")]
    ResponseTooLarge,
    #[error("JSON-RPC: {0}")]
    Rpc(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("finalized block is unavailable")]
    FinalizedUnavailable,
}

/// Exact JSON-RPC response retained before a decoded value is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRpcResponse<T> {
    pub value: T,
    pub raw_body: String,
    pub response_hash: B256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedBlock {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
    pub block_number: u64,
    pub block_hash: B256,
    pub transaction_hash: B256,
    pub transaction_index: u64,
    pub log_index: u64,
}

#[derive(Clone)]
pub struct FinalizedRpcClient {
    endpoint: String,
    client: Client,
}

impl FinalizedRpcClient {
    /// Build a bounded JSON-RPC client. Endpoint credentials are retained but
    /// never exposed by `Debug` or error messages.
    ///
    /// # Errors
    /// Invalid URL or TLS/client construction failure.
    pub fn new(endpoint: impl Into<String>) -> Result<Self, FinalizedRpcError> {
        let endpoint = endpoint.into();
        let url = reqwest::Url::parse(&endpoint)
            .map_err(|error| FinalizedRpcError::Decode(format!("invalid RPC URL: {error}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(FinalizedRpcError::Decode(
                "RPC URL must use http or https".to_string(),
            ));
        }
        let client = async_client(HttpClientPolicy {
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(15),
            max_response_bytes: MAX_RPC_RESPONSE_BYTES,
        })
        .map_err(|_| FinalizedRpcError::Transport("client_build"))?;
        Ok(Self { endpoint, client })
    }

    /// Require HTTPS for a production profile. Loopback HTTP remains useful
    /// for a local execution client, but must be an explicit caller decision.
    ///
    /// # Errors
    /// Non-HTTPS endpoint.
    pub fn require_https(&self) -> Result<(), FinalizedRpcError> {
        let url = reqwest::Url::parse(&self.endpoint)
            .map_err(|error| FinalizedRpcError::Decode(format!("invalid RPC URL: {error}")))?;
        if url.scheme() != "https" {
            return Err(FinalizedRpcError::Decode(
                "production RPC URL must use https".to_string(),
            ));
        }
        Ok(())
    }

    /// Read `eth_chainId` while retaining the exact provider response.
    ///
    /// # Errors
    /// Transport, schema, or hex failure.
    pub async fn chain_id(&self) -> Result<RawRpcResponse<u64>, FinalizedRpcError> {
        let raw: RawRpcResponse<String> = self.call("eth_chainId", serde_json::json!([])).await?;
        map_raw(raw, |value| parse_quantity(&value, "chain id"))
    }

    /// Read the execution client's consensus-finalized head.
    ///
    /// # Errors
    /// Transport/schema failure or a client that does not expose `finalized`.
    pub async fn finalized_head(
        &self,
    ) -> Result<RawRpcResponse<FinalizedBlock>, FinalizedRpcError> {
        let raw: RawRpcResponse<Option<RpcBlock>> = self
            .call(
                "eth_getBlockByNumber",
                serde_json::json!(["finalized", false]),
            )
            .await?;
        let Some(block) = raw.value else {
            return Err(FinalizedRpcError::FinalizedUnavailable);
        };
        map_raw_value(raw.raw_body, raw.response_hash, decode_block(&block))
    }

    /// Read one exact height. The caller compares its hash/parent with the
    /// durable journal before accepting it.
    ///
    /// # Errors
    /// Transport/schema failure or missing block.
    pub async fn block_by_number(
        &self,
        number: u64,
    ) -> Result<RawRpcResponse<FinalizedBlock>, FinalizedRpcError> {
        let raw: RawRpcResponse<Option<RpcBlock>> = self
            .call(
                "eth_getBlockByNumber",
                serde_json::json!([format!("0x{number:x}"), false]),
            )
            .await?;
        let block = raw
            .value
            .ok_or_else(|| FinalizedRpcError::Rpc(format!("block {number} is unavailable")))?;
        map_raw_value(raw.raw_body, raw.response_hash, decode_block(&block))
    }

    /// Fetch logs from one already selected block hash. `topic0` is an exact
    /// allowlist of event signatures; an empty list is rejected.
    ///
    /// # Errors
    /// Transport/schema failure, malformed log, or a log whose block hash does
    /// not equal the requested hash.
    pub async fn logs_by_block_hash(
        &self,
        block_hash: B256,
        addresses: &[Address],
        topic0: &[B256],
    ) -> Result<RawRpcResponse<Vec<FinalizedLog>>, FinalizedRpcError> {
        if block_hash == B256::ZERO || addresses.is_empty() || topic0.is_empty() {
            return Err(FinalizedRpcError::Decode(
                "block hash, addresses and topic allowlist must be non-empty".to_string(),
            ));
        }
        let raw: RawRpcResponse<Vec<RpcLog>> = self
            .call(
                "eth_getLogs",
                serde_json::json!([{
                    "blockHash": format!("{block_hash:#x}"),
                    "address": addresses.iter().map(|address| format!("{address:#x}")).collect::<Vec<_>>(),
                    "topics": [topic0.iter().map(|topic| format!("{topic:#x}")).collect::<Vec<_>>()]
                }]),
            )
            .await?;
        let logs = raw
            .value
            .into_iter()
            .map(decode_log)
            .collect::<Result<Vec<_>, _>>()?;
        if logs.iter().any(|log| log.block_hash != block_hash) {
            return Err(FinalizedRpcError::Rpc(
                "eth_getLogs returned a different block hash".to_string(),
            ));
        }
        map_raw_value(raw.raw_body, raw.response_hash, Ok(logs))
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<RawRpcResponse<T>, FinalizedRpcError> {
        let request = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        };
        let response = self
            .client
            .post(&self.endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|error| FinalizedRpcError::Transport(transport_class(&error)))?;
        let status = response.status();
        if !status.is_success() {
            return Err(FinalizedRpcError::Http(status.as_u16()));
        }
        let bytes = bounded_body(response).await?;
        let raw_body = String::from_utf8(bytes).map_err(|error| {
            FinalizedRpcError::Decode(format!("response is not UTF-8: {error}"))
        })?;
        let envelope: RpcEnvelope<T> = serde_json::from_str(&raw_body)
            .map_err(|error| FinalizedRpcError::Decode(error.to_string()))?;
        if envelope.jsonrpc != "2.0" || envelope.id != 1 {
            return Err(FinalizedRpcError::Rpc(
                "JSON-RPC version/id mismatch".to_string(),
            ));
        }
        if let Some(error) = envelope.error {
            return Err(FinalizedRpcError::Rpc(format!(
                "code {}: {}",
                error.code, error.message
            )));
        }
        let value = envelope
            .result
            .ok_or_else(|| FinalizedRpcError::Rpc("missing result".to_string()))?;
        let response_hash = keccak256(raw_body.as_bytes());
        Ok(RawRpcResponse {
            value,
            raw_body,
            response_hash,
        })
    }
}

impl std::fmt::Debug for FinalizedRpcClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FinalizedRpcClient")
            .field("endpoint", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Deserialize)]
struct RpcEnvelope<T> {
    jsonrpc: String,
    id: u64,
    result: Option<T>,
    error: Option<RpcErrorBody>,
}

#[derive(Deserialize)]
struct RpcErrorBody {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcBlock {
    number: String,
    hash: B256,
    parent_hash: B256,
    timestamp: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcLog {
    address: Address,
    topics: Vec<B256>,
    data: String,
    block_number: String,
    block_hash: B256,
    transaction_hash: B256,
    transaction_index: String,
    log_index: String,
    #[serde(default)]
    removed: bool,
}

fn decode_block(block: &RpcBlock) -> Result<FinalizedBlock, FinalizedRpcError> {
    let decoded = FinalizedBlock {
        number: parse_quantity(&block.number, "block number")?,
        hash: block.hash,
        parent_hash: block.parent_hash,
        timestamp: parse_quantity(&block.timestamp, "block timestamp")?,
    };
    if decoded.hash == B256::ZERO || decoded.parent_hash == B256::ZERO {
        return Err(FinalizedRpcError::Decode(
            "block contains a zero hash".to_string(),
        ));
    }
    Ok(decoded)
}

fn decode_log(log: RpcLog) -> Result<FinalizedLog, FinalizedRpcError> {
    if log.removed {
        return Err(FinalizedRpcError::Rpc(
            "finalized log is marked removed".to_string(),
        ));
    }
    if log.topics.is_empty() || log.transaction_hash == B256::ZERO {
        return Err(FinalizedRpcError::Decode(
            "log lacks topic0 or transaction hash".to_string(),
        ));
    }
    let data = alloy_primitives::hex::decode(log.data.strip_prefix("0x").unwrap_or(&log.data))
        .map_err(|error| FinalizedRpcError::Decode(format!("log data: {error}")))?;
    Ok(FinalizedLog {
        address: log.address,
        topics: log.topics,
        data: Bytes::from(data),
        block_number: parse_quantity(&log.block_number, "log block number")?,
        block_hash: log.block_hash,
        transaction_hash: log.transaction_hash,
        transaction_index: parse_quantity(&log.transaction_index, "transaction index")?,
        log_index: parse_quantity(&log.log_index, "log index")?,
    })
}

async fn bounded_body(response: reqwest::Response) -> Result<Vec<u8>, FinalizedRpcError> {
    read_bounded_async(response, MAX_RPC_RESPONSE_BYTES)
        .await
        .map_err(|error| match error {
            NetworkError::ResponseTooLarge { .. } => FinalizedRpcError::ResponseTooLarge,
            _ => FinalizedRpcError::Transport("body"),
        })
}

fn parse_quantity(value: &str, label: &str) -> Result<u64, FinalizedRpcError> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| FinalizedRpcError::Decode(format!("{label} is not a hex quantity")))?;
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return Err(FinalizedRpcError::Decode(format!(
            "{label} is not a canonical hex quantity"
        )));
    }
    u64::from_str_radix(digits, 16)
        .map_err(|error| FinalizedRpcError::Decode(format!("{label}: {error}")))
}

fn map_raw<T, U>(
    raw: RawRpcResponse<T>,
    map: impl FnOnce(T) -> Result<U, FinalizedRpcError>,
) -> Result<RawRpcResponse<U>, FinalizedRpcError> {
    map_raw_value(raw.raw_body, raw.response_hash, map(raw.value))
}

fn map_raw_value<T>(
    raw_body: String,
    response_hash: B256,
    value: Result<T, FinalizedRpcError>,
) -> Result<RawRpcResponse<T>, FinalizedRpcError> {
    Ok(RawRpcResponse {
        value: value?,
        raw_body,
        response_hash,
    })
}

fn transport_class(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() {
        "body"
    } else if error.is_request() {
        "request"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_quantity_rejects_leading_zeroes() {
        assert_eq!(parse_quantity("0x0", "n").ok(), Some(0));
        assert_eq!(parse_quantity("0xff", "n").ok(), Some(255));
        assert!(parse_quantity("0x00", "n").is_err());
        assert!(parse_quantity("12", "n").is_err());
    }

    #[test]
    fn finalized_block_decodes_exact_fields() {
        let block: RpcBlock = serde_json::from_value(serde_json::json!({
            "number": "0xa",
            "hash": format!("{:#x}", B256::repeat_byte(1)),
            "parentHash": format!("{:#x}", B256::repeat_byte(2)),
            "timestamp": "0x64"
        }))
        .unwrap_or_else(|error| unreachable!("fixture: {error}"));
        let decoded = decode_block(&block).unwrap_or_else(|error| unreachable!("decode: {error}"));
        assert_eq!(decoded.number, 10);
        assert_eq!(decoded.timestamp, 100);
    }

    #[test]
    fn removed_finalized_log_is_rejected() {
        let log: RpcLog = serde_json::from_value(serde_json::json!({
            "address": format!("{:#x}", Address::repeat_byte(3)),
            "topics": [format!("{:#x}", B256::repeat_byte(4))],
            "data": "0x",
            "blockNumber": "0xa",
            "blockHash": format!("{:#x}", B256::repeat_byte(5)),
            "transactionHash": format!("{:#x}", B256::repeat_byte(6)),
            "transactionIndex": "0x0",
            "logIndex": "0x0",
            "removed": true
        }))
        .unwrap_or_else(|error| unreachable!("fixture: {error}"));
        assert!(decode_log(log).is_err());
    }
}
