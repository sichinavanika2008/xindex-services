//! Concrete [`Erc20ArrivalClient`] for the redemption-delivery
//! cross-check: confirm the USDT `THORChain` swapped actually landed at
//! the `IndexToken` contract (R1) before a signer attests delivery.
//!
//! The trait lives in `xindex-signer` (not here) because `chain-eth`
//! depends on `signer`; this concrete impl satisfies it and is injected
//! by the `xindex-attest-redeem` binary — exactly the mint pattern
//! where `BitcoinChainClient` lives in `chain-btc` and `EsploraClient`
//! is the concrete client wired by the binary.
//!
//! `transfers_to` is SYNC (mirrors `chain-btc`'s `BitcoinChainClient` /
//! `find_arrival`, which the async `ThorBtcPolicy` already calls into).
//! Same accepted trade-off: a blocking JSON-RPC call inside the
//! low-frequency signer path. Uses `reqwest::blocking` rather than
//! pulling a full async provider through the sync boundary.

use alloy_primitives::{Address, U256};
use serde_json::json;
use xindex_signer::crosscheck::{Erc20Arrival, Erc20ArrivalClient, Erc20Error};

/// `keccak256("Transfer(address,address,uint256)")` — the ERC20
/// Transfer event topic0. Pinned (USDT predates events-by-name tooling
/// and never changes).
const TRANSFER_TOPIC0: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

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
fn decode_transfer_log(log: &serde_json::Value, tip: u64) -> Result<Erc20Arrival, Erc20Error> {
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
    let confirmations = u32::try_from(tip.saturating_sub(block) + 1).unwrap_or(u32::MAX);
    Ok(Erc20Arrival {
        value,
        confirmations,
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
            out.push(decode_transfer_log(log, tip)?);
        }
        Ok(out)
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
        let log = json!({
            "data": "0x00000000000000000000000000000000000000000000000000000000042c1d80",
            "blockNumber": "0x64"
        });
        let a = decode_transfer_log(&log, 105).expect("decode");
        assert_eq!(a.value, 70_000_000);
        assert_eq!(a.confirmations, 6);
    }

    #[test]
    fn parse_hex_u64_handles_prefix() {
        assert_eq!(parse_hex_u64("0x10").ok(), Some(16));
        assert_eq!(parse_hex_u64("ff").ok(), Some(255));
        assert!(parse_hex_u64("zz").is_err());
    }
}
