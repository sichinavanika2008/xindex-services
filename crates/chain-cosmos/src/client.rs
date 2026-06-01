//! [`CosmosChainClient`] trait + production [`ReqwestCosmosChainClient`]
//! impl, plus the pure JSON parsers the impl delegates to.
//!
//! The trait is what C6 (cross-check) and C7 (executor) program against,
//! mirroring `EvmChainClient`. The production impl talks Tendermint
//! JSON-RPC + Cosmos REST over `reqwest`. The parsing is split into pure
//! functions ([`parse_account`], [`parse_latest_height`],
//! [`parse_transfers`], [`parse_broadcast`]) so it is unit-testable
//! without a live node — wiremock binds localhost TCP, which is exactly
//! the integration surface deferred to rehearsal (DL-P3.3-8).

use std::future::Future;
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;
use xindex_shared::chain_registry::{ChainId, CustodyFamily};

/// Per-request timeout. A stalled or black-holed RPC must not wedge the
/// signer cross-check / executor (which await these calls inline) — matches
/// the `chain-utxo` Esplora client posture.
const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Connection-establishment timeout (shorter than the per-request budget).
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Account number + sequence for a Cosmos account. Both are bound into
/// the amino sign-bytes; `sequence` is the monotonic replay coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CosmosAccount {
    /// Fixed-per-account number (assigned at first funding).
    pub account_number: u64,
    /// Monotonic per-tx sequence.
    pub sequence: u64,
}

/// A single coin transfer to a recipient, decoded from a Tendermint
/// `transfer` event. Used by the cross-check to verify a `THORChain`
/// delivery / refund actually landed at our multisig account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosmosTransfer {
    /// Block height the tx was included in.
    pub height: u64,
    /// Tx hash (uppercase hex, Tendermint convention).
    pub txhash: String,
    /// bech32 sender (the `transfer` event's `sender` attribute). The
    /// cross-check binds a delivery/refund to its expected origin (e.g.
    /// the `THORChain` Asgard vault) — a recipient+amount match alone is
    /// forgeable by anyone who pays our public multisig address.
    pub sender: String,
    /// bech32 recipient.
    pub recipient: String,
    /// Amount in the coin's micro-unit.
    pub amount: u128,
    /// Coin denom (e.g. `"uatom"`).
    pub denom: String,
}

/// Outcome of a `broadcast_tx_sync` (mempool admission, not inclusion).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosmosBroadcastOutcome {
    /// Tendermint result code. `0` = admitted to the mempool; non-zero =
    /// `CheckTx` rejected (e.g. sequence mismatch, insufficient fee).
    pub code: u32,
    /// Tx hash the node computed.
    pub txhash: String,
    /// `CheckTx` log (error detail when `code != 0`).
    pub log: String,
}

impl CosmosBroadcastOutcome {
    /// `true` iff the tx was admitted to the mempool (`code == 0`).
    #[must_use]
    pub fn accepted(&self) -> bool {
        self.code == 0
    }
}

/// Errors surfaced by every [`CosmosChainClient`] method.
#[derive(Debug, Error)]
pub enum CosmosChainError {
    /// Transport / HTTP failure.
    #[error("RPC error: {0}")]
    Rpc(String),
    /// Response body did not match the expected JSON shape.
    #[error("decode error: {0}")]
    Decode(String),
    /// The configured chain is not in the Cosmos custody family.
    #[error("chain {0:?} is not in the Cosmos custody family")]
    NotCosmosChain(ChainId),
}

/// Per-(Cosmos-chain) RPC primitives. Returns `impl Future + Send` (not
/// `async fn`) so the futures are `Send`-bound at the trait level, like
/// [`xindex_chain_evm`]'s `EvmChainClient`.
pub trait CosmosChainClient: Send + Sync + 'static {
    /// Which Cosmos chain this client targets.
    fn chain(&self) -> ChainId;

    /// Cosmos consensus chain-id (e.g. `"cosmoshub-4"`), bound into the
    /// amino sign-bytes.
    fn cosmos_chain_id(&self) -> &str;

    /// Query the account number + sequence for `address` (Cosmos REST
    /// `auth` endpoint). The executor reads this to build the sign-doc.
    fn account(
        &self,
        address: &str,
    ) -> impl Future<Output = Result<CosmosAccount, CosmosChainError>> + Send;

    /// Current chain-tip block height (Tendermint `/status`). The
    /// cross-check uses it to gauge inclusion depth (GAIA has instant
    /// finality, so any included tx is final — `conf_depth` 1).
    fn latest_height(&self) -> impl Future<Output = Result<u64, CosmosChainError>> + Send;

    /// Find coin transfers to `recipient` at or above `min_height`
    /// (Tendermint `/tx_search` on `transfer.recipient`). The cross-check
    /// matches the expected delivery/refund amount + denom against these.
    fn transfers_to(
        &self,
        recipient: &str,
        min_height: u64,
    ) -> impl Future<Output = Result<Vec<CosmosTransfer>, CosmosChainError>> + Send;

    /// Broadcast already-signed `TxRaw` bytes via `broadcast_tx_sync`
    /// (returns once `CheckTx` runs — mempool admission, not inclusion).
    fn broadcast_tx_sync(
        &self,
        tx_raw: &[u8],
    ) -> impl Future<Output = Result<CosmosBroadcastOutcome, CosmosChainError>> + Send;
}

// ─── pure parsers (unit-tested without a node) ──────────────────────────────

/// Parse `(amount, denom)` from a Cosmos coin string like `"1000000uatom"`
/// (leading ASCII digits = amount, remainder = denom).
///
/// # Errors
/// [`CosmosChainError::Decode`] if there is no leading numeric amount or
/// it overflows `u128`.
pub fn parse_coin_amount(s: &str) -> Result<(u128, String), CosmosChainError> {
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, denom) = s.split_at(split);
    if num.is_empty() || denom.is_empty() {
        return Err(CosmosChainError::Decode(format!("malformed coin: {s:?}")));
    }
    let amount = num
        .parse::<u128>()
        .map_err(|e| CosmosChainError::Decode(format!("coin amount {num:?}: {e}")))?;
    Ok((amount, denom.to_string()))
}

/// Parse the latest block height from a Tendermint `/status` response.
///
/// # Errors
/// [`CosmosChainError::Decode`] if the field is missing or not a number.
pub fn parse_latest_height(body: &str) -> Result<u64, CosmosChainError> {
    let v: Value =
        serde_json::from_str(body).map_err(|e| CosmosChainError::Decode(e.to_string()))?;
    v.get("result")
        .and_then(|r| r.get("sync_info"))
        .and_then(|s| s.get("latest_block_height"))
        .and_then(Value::as_str)
        .ok_or_else(|| CosmosChainError::Decode("missing sync_info.latest_block_height".into()))?
        .parse::<u64>()
        .map_err(|e| CosmosChainError::Decode(format!("latest_block_height: {e}")))
}

/// Parse `account_number` + `sequence` from a Cosmos REST
/// `/cosmos/auth/v1beta1/accounts/{addr}` response (a `BaseAccount`).
///
/// # Errors
/// [`CosmosChainError::Decode`] if the account fields are missing or not
/// numeric strings.
pub fn parse_account(body: &str) -> Result<CosmosAccount, CosmosChainError> {
    let v: Value =
        serde_json::from_str(body).map_err(|e| CosmosChainError::Decode(e.to_string()))?;
    let acct = v
        .get("account")
        .ok_or_else(|| CosmosChainError::Decode("missing account".into()))?;
    let num = |field: &str| -> Result<u64, CosmosChainError> {
        acct.get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| CosmosChainError::Decode(format!("missing account.{field}")))?
            .parse::<u64>()
            .map_err(|e| CosmosChainError::Decode(format!("account.{field}: {e}")))
    };
    Ok(CosmosAccount {
        account_number: num("account_number")?,
        sequence: num("sequence")?,
    })
}

/// Parse coin transfers to `want_recipient` from a Tendermint
/// `/tx_search` response. Assumes plain-string event attributes
/// (`CometBFT` ≥ 0.35). Multi-coin amounts (`"a,b"`) yield one transfer per
/// coin. Only `min_height`-and-above results are returned.
///
/// # Errors
/// [`CosmosChainError::Decode`] if the response is not the expected shape.
/// A single malformed coin segment is skipped, not propagated, so one bad
/// transfer cannot discard every valid transfer in the response.
pub fn parse_transfers(
    body: &str,
    want_recipient: &str,
    min_height: u64,
) -> Result<Vec<CosmosTransfer>, CosmosChainError> {
    let v: Value =
        serde_json::from_str(body).map_err(|e| CosmosChainError::Decode(e.to_string()))?;
    let txs = v
        .get("result")
        .and_then(|r| r.get("txs"))
        .and_then(Value::as_array)
        .ok_or_else(|| CosmosChainError::Decode("missing result.txs".into()))?;
    let mut out = Vec::new();
    for tx in txs {
        let height = tx
            .get("height")
            .and_then(Value::as_str)
            .and_then(|h| h.parse::<u64>().ok())
            .unwrap_or(0);
        if height < min_height {
            continue;
        }
        let txhash = tx
            .get("hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let Some(events) = tx
            .get("tx_result")
            .and_then(|r| r.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for ev in events {
            if ev.get("type").and_then(Value::as_str) != Some("transfer") {
                continue;
            }
            let Some(attrs) = ev.get("attributes").and_then(Value::as_array) else {
                continue;
            };
            let (mut recipient, mut amount, mut sender) = (None, None, None);
            for at in attrs {
                match at.get("key").and_then(Value::as_str) {
                    Some("recipient") => recipient = at.get("value").and_then(Value::as_str),
                    Some("amount") => amount = at.get("value").and_then(Value::as_str),
                    Some("sender") => sender = at.get("value").and_then(Value::as_str),
                    _ => {}
                }
            }
            if recipient != Some(want_recipient) {
                continue;
            }
            let Some(amount) = amount else { continue };
            let sender = sender.unwrap_or_default().to_string();
            for coin in amount.split(',') {
                let Ok((value, denom)) = parse_coin_amount(coin) else {
                    continue;
                };
                out.push(CosmosTransfer {
                    height,
                    txhash: txhash.clone(),
                    sender: sender.clone(),
                    recipient: want_recipient.to_string(),
                    amount: value,
                    denom,
                });
            }
        }
    }
    Ok(out)
}

/// Parse a Tendermint `/broadcast_tx_sync` response.
///
/// # Errors
/// [`CosmosChainError::Decode`] if the `result` object is missing.
pub fn parse_broadcast(body: &str) -> Result<CosmosBroadcastOutcome, CosmosChainError> {
    let v: Value =
        serde_json::from_str(body).map_err(|e| CosmosChainError::Decode(e.to_string()))?;
    let r = v
        .get("result")
        .ok_or_else(|| CosmosChainError::Decode("missing result".into()))?;
    let code = r
        .get("code")
        .and_then(Value::as_u64)
        .ok_or_else(|| CosmosChainError::Decode("missing or non-numeric result.code".into()))
        .and_then(|c| {
            u32::try_from(c)
                .map_err(|_| CosmosChainError::Decode("result.code out of u32 range".into()))
        })?;
    Ok(CosmosBroadcastOutcome {
        code,
        txhash: r
            .get("hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        log: r
            .get("log")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

// ─── production reqwest impl ────────────────────────────────────────────────

/// Production [`CosmosChainClient`] over Tendermint JSON-RPC + Cosmos REST.
#[derive(Debug, Clone)]
pub struct ReqwestCosmosChainClient {
    chain: ChainId,
    cosmos_chain_id: String,
    rpc_url: String,
    rest_url: String,
    http: reqwest::Client,
}

impl ReqwestCosmosChainClient {
    /// Build a client for `chain` against a Tendermint RPC base URL +
    /// Cosmos REST base URL (no trailing slash).
    ///
    /// # Errors
    /// - [`CosmosChainError::NotCosmosChain`] if `chain` is not Cosmos.
    /// - [`CosmosChainError::Rpc`] if the HTTP client cannot be built.
    pub fn new(
        chain: ChainId,
        cosmos_chain_id: impl Into<String>,
        rpc_url: impl Into<String>,
        rest_url: impl Into<String>,
    ) -> Result<Self, CosmosChainError> {
        if chain.custody_family() != CustodyFamily::Cosmos {
            return Err(CosmosChainError::NotCosmosChain(chain));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
            .build()
            .map_err(|e| CosmosChainError::Rpc(e.to_string()))?;
        Ok(Self {
            chain,
            cosmos_chain_id: cosmos_chain_id.into(),
            rpc_url: rpc_url.into(),
            rest_url: rest_url.into(),
            http,
        })
    }

    async fn get(&self, url: String) -> Result<String, CosmosChainError> {
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| CosmosChainError::Rpc(e.to_string()))?;
        resp.text()
            .await
            .map_err(|e| CosmosChainError::Rpc(e.to_string()))
    }
}

impl CosmosChainClient for ReqwestCosmosChainClient {
    fn chain(&self) -> ChainId {
        self.chain
    }

    fn cosmos_chain_id(&self) -> &str {
        &self.cosmos_chain_id
    }

    async fn account(&self, address: &str) -> Result<CosmosAccount, CosmosChainError> {
        let url = format!(
            "{}/cosmos/auth/v1beta1/accounts/{address}",
            self.rest_url.trim_end_matches('/')
        );
        parse_account(&self.get(url).await?)
    }

    async fn latest_height(&self) -> Result<u64, CosmosChainError> {
        let url = format!("{}/status", self.rpc_url.trim_end_matches('/'));
        parse_latest_height(&self.get(url).await?)
    }

    async fn transfers_to(
        &self,
        recipient: &str,
        min_height: u64,
    ) -> Result<Vec<CosmosTransfer>, CosmosChainError> {
        // Tendermint expects the query value single-quoted + URL-encoded.
        let query = format!("transfer.recipient='{recipient}'");
        let encoded = url_encode(&query);
        let url = format!(
            "{}/tx_search?query=%22{encoded}%22&per_page=100&order_by=%22asc%22",
            self.rpc_url.trim_end_matches('/')
        );
        parse_transfers(&self.get(url).await?, recipient, min_height)
    }

    async fn broadcast_tx_sync(
        &self,
        tx_raw: &[u8],
    ) -> Result<CosmosBroadcastOutcome, CosmosChainError> {
        let hex = to_hex(tx_raw);
        let url = format!(
            "{}/broadcast_tx_sync?tx=0x{hex}",
            self.rpc_url.trim_end_matches('/')
        );
        parse_broadcast(&self.get(url).await?)
    }
}

/// Minimal percent-encoding for a Tendermint query value (single quotes
/// and the few reserved chars that appear in a bech32 + dotted-key query).
fn url_encode(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[(b >> 4) as usize]));
            out.push(char::from(HEX[(b & 0x0f) as usize]));
        }
    }
    out
}

/// Lower-case hex of `bytes` (for the `broadcast_tx_sync?tx=0x…` param).
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(HEX[(b >> 4) as usize]));
        s.push(char::from(HEX[(b & 0x0f) as usize]));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn coin_amount_splits_number_and_denom() {
        assert_eq!(
            parse_coin_amount("1000000uatom").expect("ok"),
            (1_000_000u128, "uatom".to_string())
        );
        assert!(parse_coin_amount("uatom").is_err());
        assert!(parse_coin_amount("1000000").is_err());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn latest_height_parses() {
        let body = r#"{"jsonrpc":"2.0","id":-1,"result":{"sync_info":{"latest_block_height":"19876543","catching_up":false}}}"#;
        assert_eq!(parse_latest_height(body).expect("h"), 19_876_543);
        assert!(parse_latest_height(r#"{"result":{}}"#).is_err());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn account_parses_base_account() {
        let body = r#"{"account":{"@type":"/cosmos.auth.v1beta1.BaseAccount","address":"cosmos1abc","pub_key":null,"account_number":"12345","sequence":"7"}}"#;
        let a = parse_account(body).expect("acct");
        assert_eq!(a.account_number, 12345);
        assert_eq!(a.sequence, 7);
        assert!(parse_account(r#"{"account":{"address":"x"}}"#).is_err());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn broadcast_parses_code_and_hash() {
        let ok = r#"{"jsonrpc":"2.0","id":-1,"result":{"code":0,"data":"","log":"","codespace":"","hash":"A1B2"}}"#;
        let o = parse_broadcast(ok).expect("ok");
        assert!(o.accepted());
        assert_eq!(o.txhash, "A1B2");
        let bad = r#"{"result":{"code":32,"hash":"DEAD","log":"account sequence mismatch"}}"#;
        let b = parse_broadcast(bad).expect("bad");
        assert!(!b.accepted());
        assert_eq!(b.code, 32);
        assert!(b.log.contains("sequence mismatch"));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn transfers_match_recipient_and_height() {
        // Two txs: one to our recipient at height 100, one to someone else.
        let body = r#"{"result":{"total_count":"2","txs":[
            {"hash":"AAAA","height":"100","tx_result":{"events":[
                {"type":"coin_spent","attributes":[{"key":"spender","value":"cosmos1thor"}]},
                {"type":"transfer","attributes":[
                    {"key":"recipient","value":"cosmos1vault"},
                    {"key":"sender","value":"cosmos1thor"},
                    {"key":"amount","value":"5000000uatom"}]}]}},
            {"hash":"BBBB","height":"90","tx_result":{"events":[
                {"type":"transfer","attributes":[
                    {"key":"recipient","value":"cosmos1other"},
                    {"key":"amount","value":"1uatom"}]}]}}
        ]}}"#;
        let got = parse_transfers(body, "cosmos1vault", 1).expect("t");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].height, 100);
        assert_eq!(got[0].txhash, "AAAA");
        assert_eq!(got[0].sender, "cosmos1thor");
        assert_eq!(got[0].amount, 5_000_000);
        assert_eq!(got[0].denom, "uatom");
        // min_height filters out the height-100 hit.
        assert!(parse_transfers(body, "cosmos1vault", 101)
            .expect("t2")
            .is_empty());
    }

    #[test]
    fn url_encode_quotes_and_specials() {
        assert_eq!(
            url_encode("transfer.recipient='cosmos1abc'"),
            "transfer.recipient%3D%27cosmos1abc%27"
        );
    }

    #[test]
    fn to_hex_round() {
        assert_eq!(to_hex(&[0x00, 0x0a, 0xff]), "000aff");
    }
}
