//! [`SolanaChainClient`] trait + production [`ReqwestSolanaChainClient`]
//! impl, plus the pure JSON / account-data parsers it delegates to.
//!
//! The production impl talks the Solana JSON-RPC over `reqwest` HTTP POST.
//! On-chain Squads `Multisig` / `Proposal` accounts are returned base64
//! and decoded against the program's Borsh layout (pinned offsets). All
//! reads use commitment `finalized` (the SOL `conf_depth` is 1 finalized
//! observation — see `chain_registry`).

use std::future::Future;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use thiserror::Error;
use xindex_shared::chain_registry::{ChainId, CustodyFamily};
use xindex_solana_tx::{base58, Pubkey};

/// Per-request timeout — a stalled RPC must not wedge the executor.
const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Connection-establishment timeout (shorter than the request budget).
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

// ─── Borsh account-layout offsets (after the 8-byte Anchor discriminator) ──
//
// Multisig: create_key(32) | config_authority(32) | threshold(u16) |
//           time_lock(u32) | transaction_index(u64) | stale_index(u64) | …
const MS_THRESHOLD_OFF: usize = 8 + 32 + 32;
const MS_TIME_LOCK_OFF: usize = MS_THRESHOLD_OFF + 2;
const MS_TX_INDEX_OFF: usize = MS_TIME_LOCK_OFF + 4;
const MS_STALE_INDEX_OFF: usize = MS_TX_INDEX_OFF + 8;
// Proposal: multisig(32) | transaction_index(u64) | status(enum) | …
const PROP_STATUS_OFF: usize = 8 + 32 + 8;

/// Squads `Multisig` account state the executor reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultisigAccount {
    /// The approval threshold (re-checked against the configured value).
    pub threshold: u16,
    /// On-chain time lock (Xindex expects 0).
    pub time_lock: u32,
    /// The last-used transaction index; the next proposal is `+ 1`.
    pub transaction_index: u64,
    /// The stale-transaction index (config-change boundary).
    pub stale_transaction_index: u64,
}

/// Squads `Proposal` lifecycle state. `None` means the account does not
/// exist yet (the proposal has not been created).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalState {
    /// The proposal account does not exist.
    None,
    /// `Draft`.
    Draft,
    /// `Active`, carrying the members that have approved so far (the
    /// executor picks an un-approved member for the next approval, which
    /// is restart-safe — a member never double-approves).
    Active {
        /// The distinct members that have approved.
        approved: Vec<Pubkey>,
    },
    /// `Rejected`.
    Rejected,
    /// `Approved` (threshold reached) — ready to execute.
    Approved,
    /// `Executing` (deprecated transient state).
    Executing,
    /// `Executed` — the vault transfer has run.
    Executed,
    /// `Cancelled`.
    Cancelled,
}

impl ProposalState {
    /// `true` iff the proposal has reached threshold and can be executed.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved)
    }

    /// `true` iff the vault transfer has already executed.
    #[must_use]
    pub fn is_executed(&self) -> bool {
        matches!(self, Self::Executed)
    }
}

/// A confirmed-or-not signature status from `getSignatureStatuses`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureStatus {
    /// The slot the transaction landed in.
    pub slot: u64,
    /// Confirmation count (`None` once rooted/finalized).
    pub confirmations: Option<u64>,
    /// `processed` / `confirmed` / `finalized`.
    pub confirmation_status: Option<String>,
    /// Whether the transaction failed on-chain.
    pub err: bool,
}

impl SignatureStatus {
    /// `true` iff the transaction landed successfully at commitment
    /// `confirmed` or `finalized`.
    #[must_use]
    pub fn confirmed(&self) -> bool {
        !self.err
            && matches!(
                self.confirmation_status.as_deref(),
                Some("confirmed" | "finalized")
            )
    }

    /// `true` iff the transaction is finalized (irreversible).
    #[must_use]
    pub fn finalized(&self) -> bool {
        !self.err && self.confirmation_status.as_deref() == Some("finalized")
    }
}

/// A signature reference from `getSignaturesForAddress`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureRef {
    /// The base58 transaction signature.
    pub signature: String,
    /// The slot the transaction landed in.
    pub slot: u64,
}

/// A native-SOL transfer delivered to a watched address (inbound observer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolanaTransfer {
    /// The slot the transfer landed in.
    pub slot: u64,
    /// The base58 transaction signature.
    pub signature: String,
    /// The System-transfer source — bound to the expected `THORChain`
    /// vault by the cross-check (destination+amount alone is forgeable).
    pub source: String,
    /// The transfer destination (our watched vault).
    pub destination: String,
    /// Delivered lamports.
    pub lamports: u128,
    /// The SPL-Memo program string carried alongside the transfer.
    pub memo: String,
}

/// Errors surfaced by every [`SolanaChainClient`] method.
#[derive(Debug, Error)]
pub enum SolanaChainError {
    /// Transport / HTTP failure.
    #[error("RPC error: {0}")]
    Rpc(String),
    /// Response body did not match the expected JSON / account shape.
    #[error("decode error: {0}")]
    Decode(String),
    /// The configured chain is not in the Solana custody family.
    #[error("chain {0:?} is not in the Solana custody family")]
    NotSolanaChain(ChainId),
}

/// Per-Solana-chain RPC primitives. Returns `impl Future + Send` (not
/// `async fn`) so the futures are `Send`-bound at the trait level, like
/// `XrpChainClient` / `CosmosChainClient`.
pub trait SolanaChainClient: Send + Sync + 'static {
    /// Which Solana chain this client targets.
    fn chain(&self) -> ChainId;

    /// Latest blockhash (`getLatestBlockhash`, commitment `confirmed`),
    /// bound into each step's message (~60s validity).
    fn recent_blockhash(&self) -> impl Future<Output = Result<[u8; 32], SolanaChainError>> + Send;

    /// Read the Squads `Multisig` account (`getAccountInfo`, base64).
    fn get_multisig_account(
        &self,
        multisig: &Pubkey,
    ) -> impl Future<Output = Result<MultisigAccount, SolanaChainError>> + Send;

    /// Read the Squads `Proposal` lifecycle state (`getAccountInfo`).
    /// Returns [`ProposalState::None`] if the account does not exist.
    fn get_proposal_state(
        &self,
        proposal: &Pubkey,
    ) -> impl Future<Output = Result<ProposalState, SolanaChainError>> + Send;

    /// Broadcast a fully-signed base64 transaction (`sendTransaction`);
    /// returns the base58 signature.
    fn send_transaction(
        &self,
        signed_tx: &[u8],
    ) -> impl Future<Output = Result<String, SolanaChainError>> + Send;

    /// Look up a signature's status (`getSignatureStatuses`,
    /// `searchTransactionHistory`). `None` = not found on-chain.
    fn get_signature_status(
        &self,
        signature: &str,
    ) -> impl Future<Output = Result<Option<SignatureStatus>, SolanaChainError>> + Send;

    /// The lamport balance of `address` (`getBalance`, finalized).
    fn get_balance(
        &self,
        address: &Pubkey,
    ) -> impl Future<Output = Result<u64, SolanaChainError>> + Send;

    /// Find native-SOL transfers delivered to `vault` at or above
    /// `min_slot` (inbound observer): `getSignaturesForAddress` then a
    /// per-signature `getTransaction` (jsonParsed). Only finalized,
    /// successful, single System-transfers are returned.
    fn transfers_to(
        &self,
        vault: &str,
        min_slot: u64,
    ) -> impl Future<Output = Result<Vec<SolanaTransfer>, SolanaChainError>> + Send;
}

// ─── pure parsers (unit-tested without a node) ──────────────────────────────

/// Unwrap a Solana JSON-RPC envelope: surface `error.message`, else return
/// the `result` value.
fn rpc_result(body: &str) -> Result<Value, SolanaChainError> {
    let v: Value =
        serde_json::from_str(body).map_err(|e| SolanaChainError::Decode(e.to_string()))?;
    if let Some(err) = v.get("error") {
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return Err(SolanaChainError::Rpc(format!("solana rpc error: {msg}")));
    }
    v.get("result")
        .cloned()
        .ok_or_else(|| SolanaChainError::Decode("missing result".into()))
}

/// Read a little-endian fixed integer from `data` at `off`.
fn read_u16_le(data: &[u8], off: usize) -> Result<u16, SolanaChainError> {
    let slice = data
        .get(off..off + 2)
        .ok_or_else(|| SolanaChainError::Decode("account data too short".into()))?;
    let arr: [u8; 2] = slice
        .try_into()
        .map_err(|_| SolanaChainError::Decode("slice".into()))?;
    Ok(u16::from_le_bytes(arr))
}

fn read_u32_le(data: &[u8], off: usize) -> Result<u32, SolanaChainError> {
    let slice = data
        .get(off..off + 4)
        .ok_or_else(|| SolanaChainError::Decode("account data too short".into()))?;
    let arr: [u8; 4] = slice
        .try_into()
        .map_err(|_| SolanaChainError::Decode("slice".into()))?;
    Ok(u32::from_le_bytes(arr))
}

fn read_u64_le(data: &[u8], off: usize) -> Result<u64, SolanaChainError> {
    let slice = data
        .get(off..off + 8)
        .ok_or_else(|| SolanaChainError::Decode("account data too short".into()))?;
    let arr: [u8; 8] = slice
        .try_into()
        .map_err(|_| SolanaChainError::Decode("slice".into()))?;
    Ok(u64::from_le_bytes(arr))
}

/// Decode base64 account data from a `getAccountInfo` result. Returns
/// `None` if the account does not exist (`value` is null).
fn account_data(result: &Value) -> Result<Option<Vec<u8>>, SolanaChainError> {
    match result.get("value") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let data = value
                .get("data")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
                .ok_or_else(|| SolanaChainError::Decode("missing account data".into()))?;
            let bytes = STANDARD
                .decode(data)
                .map_err(|e| SolanaChainError::Decode(e.to_string()))?;
            Ok(Some(bytes))
        }
    }
}

/// Parse the recent blockhash (base58) from `getLatestBlockhash`.
///
/// # Errors
/// [`SolanaChainError::Decode`] on a missing / malformed blockhash.
pub fn parse_blockhash(body: &str) -> Result<[u8; 32], SolanaChainError> {
    let result = rpc_result(body)?;
    let bh = result
        .get("value")
        .and_then(|v| v.get("blockhash"))
        .and_then(Value::as_str)
        .ok_or_else(|| SolanaChainError::Decode("missing blockhash".into()))?;
    base58::decode_32(bh).map_err(|e| SolanaChainError::Decode(e.to_string()))
}

/// Parse the lamport balance from `getBalance`.
///
/// # Errors
/// [`SolanaChainError::Decode`] on a missing value.
pub fn parse_balance(body: &str) -> Result<u64, SolanaChainError> {
    let result = rpc_result(body)?;
    result
        .get("value")
        .and_then(Value::as_u64)
        .ok_or_else(|| SolanaChainError::Decode("missing balance value".into()))
}

/// Parse the base58 signature from `sendTransaction`.
///
/// # Errors
/// [`SolanaChainError::Decode`] if the result is not a string.
pub fn parse_send_transaction(body: &str) -> Result<String, SolanaChainError> {
    let result = rpc_result(body)?;
    result
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| SolanaChainError::Decode("sendTransaction result not a signature".into()))
}

/// Decode a Squads `Multisig` account from raw bytes.
fn decode_multisig_account(data: &[u8]) -> Result<MultisigAccount, SolanaChainError> {
    Ok(MultisigAccount {
        threshold: read_u16_le(data, MS_THRESHOLD_OFF)?,
        time_lock: read_u32_le(data, MS_TIME_LOCK_OFF)?,
        transaction_index: read_u64_le(data, MS_TX_INDEX_OFF)?,
        stale_transaction_index: read_u64_le(data, MS_STALE_INDEX_OFF)?,
    })
}

/// Parse a Squads `Multisig` account from a `getAccountInfo` response.
///
/// # Errors
/// [`SolanaChainError::Decode`] if the account is absent or too short.
pub fn parse_multisig_account(body: &str) -> Result<MultisigAccount, SolanaChainError> {
    let result = rpc_result(body)?;
    let data = account_data(&result)?
        .ok_or_else(|| SolanaChainError::Decode("multisig account not found".into()))?;
    decode_multisig_account(&data)
}

/// Decode a Squads `Proposal` lifecycle state from raw bytes.
fn decode_proposal_state(data: &[u8]) -> Result<ProposalState, SolanaChainError> {
    let variant = *data
        .get(PROP_STATUS_OFF)
        .ok_or_else(|| SolanaChainError::Decode("proposal account too short".into()))?;
    // ProposalStatus variants carry an i64 timestamp except `Executing` (4).
    let payload = if variant == 4 { 0 } else { 8 };
    match variant {
        0 => Ok(ProposalState::Draft),
        1 => {
            // The approved Vec follows the status enum (+1 variant byte
            // +payload timestamp) and the bump (+1): a 4-byte LE length
            // then that many 32-byte member pubkeys.
            let approved_off = PROP_STATUS_OFF + 1 + payload + 1;
            let count = usize::try_from(read_u32_le(data, approved_off)?).unwrap_or(0);
            let mut approved = Vec::with_capacity(count.min(64));
            let mut off = approved_off + 4;
            for _ in 0..count {
                let slice = data.get(off..off + 32).ok_or_else(|| {
                    SolanaChainError::Decode("approved pubkey out of range".into())
                })?;
                let arr: [u8; 32] = slice
                    .try_into()
                    .map_err(|_| SolanaChainError::Decode("approved slice".into()))?;
                approved.push(Pubkey::new(arr));
                off += 32;
            }
            Ok(ProposalState::Active { approved })
        }
        2 => Ok(ProposalState::Rejected),
        3 => Ok(ProposalState::Approved),
        4 => Ok(ProposalState::Executing),
        5 => Ok(ProposalState::Executed),
        6 => Ok(ProposalState::Cancelled),
        other => Err(SolanaChainError::Decode(format!(
            "unknown proposal status variant {other}"
        ))),
    }
}

/// Parse a Squads `Proposal` state from a `getAccountInfo` response.
/// Returns [`ProposalState::None`] if the account does not exist.
///
/// # Errors
/// [`SolanaChainError::Decode`] on a malformed account.
pub fn parse_proposal_state(body: &str) -> Result<ProposalState, SolanaChainError> {
    let result = rpc_result(body)?;
    match account_data(&result)? {
        None => Ok(ProposalState::None),
        Some(data) => decode_proposal_state(&data),
    }
}

/// Parse a `getSignatureStatuses` response (the first / only status).
///
/// # Errors
/// [`SolanaChainError::Decode`] on a missing `value` array.
pub fn parse_signature_status(body: &str) -> Result<Option<SignatureStatus>, SolanaChainError> {
    let result = rpc_result(body)?;
    let arr = result
        .get("value")
        .and_then(Value::as_array)
        .ok_or_else(|| SolanaChainError::Decode("missing value array".into()))?;
    match arr.first() {
        None | Some(Value::Null) => Ok(None),
        Some(s) => Ok(Some(SignatureStatus {
            slot: s.get("slot").and_then(Value::as_u64).unwrap_or(0),
            confirmations: s.get("confirmations").and_then(Value::as_u64),
            confirmation_status: s
                .get("confirmationStatus")
                .and_then(Value::as_str)
                .map(str::to_string),
            err: !s.get("err").is_none_or(Value::is_null),
        })),
    }
}

/// Parse a `getSignaturesForAddress` response, skipping failed
/// transactions.
///
/// # Errors
/// [`SolanaChainError::Decode`] if the result is not an array.
pub fn parse_signatures_for_address(body: &str) -> Result<Vec<SignatureRef>, SolanaChainError> {
    let result = rpc_result(body)?;
    let arr = result
        .as_array()
        .ok_or_else(|| SolanaChainError::Decode("expected signatures array".into()))?;
    let mut out = Vec::new();
    for entry in arr {
        if !entry.get("err").is_none_or(Value::is_null) {
            continue;
        }
        let sig = entry.get("signature").and_then(Value::as_str);
        let slot = entry.get("slot").and_then(Value::as_u64);
        if let (Some(signature), Some(slot)) = (sig, slot) {
            out.push(SignatureRef {
                signature: signature.to_string(),
                slot,
            });
        }
    }
    Ok(out)
}

/// Parse a jsonParsed `getTransaction` response into a [`SolanaTransfer`]
/// to `want_dest`, if it carries exactly a System transfer there (plus an
/// optional SPL-Memo). Returns `None` for a not-found / failed / unrelated
/// transaction.
///
/// # Errors
/// [`SolanaChainError::Decode`] on an RPC-level error envelope.
pub fn parse_get_transaction(
    body: &str,
    want_dest: &str,
) -> Result<Option<SolanaTransfer>, SolanaChainError> {
    let result = rpc_result(body)?;
    if result.is_null() {
        return Ok(None); // not found yet
    }
    if !result
        .get("meta")
        .and_then(|m| m.get("err"))
        .is_none_or(Value::is_null)
    {
        return Ok(None); // failed tx
    }
    let slot = result.get("slot").and_then(Value::as_u64).unwrap_or(0);
    let signature = result
        .get("transaction")
        .and_then(|t| t.get("signatures"))
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let Some(instructions) = result
        .get("transaction")
        .and_then(|t| t.get("message"))
        .and_then(|m| m.get("instructions"))
        .and_then(Value::as_array)
    else {
        return Ok(None);
    };

    let mut transfer: Option<(String, u128)> = None;
    let mut memo: Option<String> = None;
    for ix in instructions {
        match ix.get("program").and_then(Value::as_str) {
            Some("system") => {
                let parsed = ix.get("parsed");
                if parsed.and_then(|p| p.get("type")).and_then(Value::as_str) == Some("transfer") {
                    let info = parsed.and_then(|p| p.get("info"));
                    if info
                        .and_then(|i| i.get("destination"))
                        .and_then(Value::as_str)
                        == Some(want_dest)
                    {
                        if let Some(lamports) =
                            info.and_then(|i| i.get("lamports")).and_then(Value::as_u64)
                        {
                            let source = info
                                .and_then(|i| i.get("source"))
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string();
                            transfer = Some((source, u128::from(lamports)));
                        }
                    }
                }
            }
            Some("spl-memo") => {
                memo = ix.get("parsed").and_then(Value::as_str).map(str::to_string);
            }
            _ => {}
        }
    }

    Ok(transfer.map(|(source, lamports)| SolanaTransfer {
        slot,
        signature,
        source,
        destination: want_dest.to_string(),
        lamports,
        memo: memo.unwrap_or_default(),
    }))
}

// ─── production reqwest impl ────────────────────────────────────────────────

/// Production [`SolanaChainClient`] over the Solana JSON-RPC (HTTP POST).
#[derive(Debug, Clone)]
pub struct ReqwestSolanaChainClient {
    chain: ChainId,
    rpc_url: String,
    http: reqwest::Client,
}

impl ReqwestSolanaChainClient {
    /// Build a client for `chain` against a Solana JSON-RPC URL.
    ///
    /// # Errors
    /// - [`SolanaChainError::NotSolanaChain`] if `chain` is not Solana.
    /// - [`SolanaChainError::Rpc`] if the HTTP client cannot be built.
    pub fn new(chain: ChainId, rpc_url: impl Into<String>) -> Result<Self, SolanaChainError> {
        if chain.custody_family() != CustodyFamily::Solana {
            return Err(SolanaChainError::NotSolanaChain(chain));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
            .build()
            .map_err(|e| SolanaChainError::Rpc(e.to_string()))?;
        Ok(Self {
            chain,
            rpc_url: rpc_url.into(),
            http,
        })
    }

    /// POST a JSON-RPC `{jsonrpc, id, method, params}` and return the raw
    /// response body.
    async fn rpc(&self, method: &str, params: Value) -> Result<String, SolanaChainError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| SolanaChainError::Rpc(e.to_string()))?;
        resp.text()
            .await
            .map_err(|e| SolanaChainError::Rpc(e.to_string()))
    }

    /// Read raw base64 account info for `address` at commitment `finalized`.
    async fn get_account_info(&self, address: &Pubkey) -> Result<String, SolanaChainError> {
        self.rpc(
            "getAccountInfo",
            json!([
                address.to_base58(),
                { "encoding": "base64", "commitment": "finalized" }
            ]),
        )
        .await
    }
}

impl SolanaChainClient for ReqwestSolanaChainClient {
    fn chain(&self) -> ChainId {
        self.chain
    }

    async fn recent_blockhash(&self) -> Result<[u8; 32], SolanaChainError> {
        let body = self
            .rpc("getLatestBlockhash", json!([{ "commitment": "confirmed" }]))
            .await?;
        parse_blockhash(&body)
    }

    async fn get_multisig_account(
        &self,
        multisig: &Pubkey,
    ) -> Result<MultisigAccount, SolanaChainError> {
        let body = self.get_account_info(multisig).await?;
        parse_multisig_account(&body)
    }

    async fn get_proposal_state(
        &self,
        proposal: &Pubkey,
    ) -> Result<ProposalState, SolanaChainError> {
        let body = self.get_account_info(proposal).await?;
        parse_proposal_state(&body)
    }

    async fn send_transaction(&self, signed_tx: &[u8]) -> Result<String, SolanaChainError> {
        let body = self
            .rpc(
                "sendTransaction",
                json!([
                    STANDARD.encode(signed_tx),
                    { "encoding": "base64", "skipPreflight": false, "preflightCommitment": "confirmed" }
                ]),
            )
            .await?;
        parse_send_transaction(&body)
    }

    async fn get_signature_status(
        &self,
        signature: &str,
    ) -> Result<Option<SignatureStatus>, SolanaChainError> {
        let body = self
            .rpc(
                "getSignatureStatuses",
                json!([[signature], { "searchTransactionHistory": true }]),
            )
            .await?;
        parse_signature_status(&body)
    }

    async fn get_balance(&self, address: &Pubkey) -> Result<u64, SolanaChainError> {
        let body = self
            .rpc(
                "getBalance",
                json!([address.to_base58(), { "commitment": "finalized" }]),
            )
            .await?;
        parse_balance(&body)
    }

    async fn transfers_to(
        &self,
        vault: &str,
        min_slot: u64,
    ) -> Result<Vec<SolanaTransfer>, SolanaChainError> {
        let body = self
            .rpc(
                "getSignaturesForAddress",
                json!([vault, { "limit": 100, "commitment": "finalized" }]),
            )
            .await?;
        let mut out = Vec::new();
        for sig in parse_signatures_for_address(&body)? {
            if sig.slot < min_slot {
                continue;
            }
            let tx_body = self
                .rpc(
                    "getTransaction",
                    json!([
                        sig.signature,
                        {
                            "encoding": "jsonParsed",
                            "maxSupportedTransactionVersion": 0,
                            "commitment": "finalized"
                        }
                    ]),
                )
                .await?;
            if let Some(transfer) = parse_get_transaction(&tx_body, vault)? {
                out.push(transfer);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic `getAccountInfo` envelope wrapping base64 `data`.
    fn account_info_envelope(data: &[u8]) -> String {
        let b64 = STANDARD.encode(data);
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{"data":["{b64}","base64"],"owner":"x","lamports":1,"executable":false,"rentEpoch":0}}}}}}"#
        )
    }

    #[test]
    fn rpc_error_envelope_surfaces_message() {
        let body =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"blockhash not found"}}"#;
        assert!(matches!(
            rpc_result(body),
            Err(SolanaChainError::Rpc(m)) if m.contains("blockhash not found")
        ));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn blockhash_and_balance_parse() {
        let bh = base58::encode(&[7u8; 32]);
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{"blockhash":"{bh}","lastValidBlockHeight":100}}}}}}"#
        );
        assert_eq!(parse_blockhash(&body).expect("blockhash"), [7u8; 32]);
        let bal = r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":123456789}}"#;
        assert_eq!(parse_balance(bal).expect("balance"), 123_456_789);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn multisig_account_decodes_fixed_offsets() {
        // 8 disc + 32 create_key + 32 config_authority, then threshold=3,
        // time_lock=0, transaction_index=42, stale=40.
        let mut data = vec![0u8; 8 + 32 + 32];
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&42u64.to_le_bytes());
        data.extend_from_slice(&40u64.to_le_bytes());
        data.extend_from_slice(&[0u8; 40]); // rent_collector + bump + members tail
        let acct = parse_multisig_account(&account_info_envelope(&data)).expect("multisig");
        assert_eq!(acct.threshold, 3);
        assert_eq!(acct.time_lock, 0);
        assert_eq!(acct.transaction_index, 42);
        assert_eq!(acct.stale_transaction_index, 40);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn proposal_missing_account_is_none() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":null}}"#;
        assert_eq!(
            parse_proposal_state(body).expect("none"),
            ProposalState::None
        );
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn proposal_active_reports_approved_members() {
        // 8 disc + 32 multisig + 8 tx_index, then status Active(1) + ts(8),
        // bump(1), approved Vec len = 2 + two 32-byte pubkeys.
        let mut data = vec![0u8; 8 + 32 + 8];
        data.push(1); // Active variant
        data.extend_from_slice(&1_700_000_000i64.to_le_bytes()); // timestamp
        data.push(254); // bump
        data.extend_from_slice(&2u32.to_le_bytes()); // approved len
        data.extend_from_slice(&[0xA1; 32]);
        data.extend_from_slice(&[0xA2; 32]);
        let st = parse_proposal_state(&account_info_envelope(&data)).expect("active");
        assert_eq!(
            st,
            ProposalState::Active {
                approved: vec![Pubkey::new([0xA1; 32]), Pubkey::new([0xA2; 32])]
            }
        );
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn proposal_approved_and_executed_variants() {
        for (variant, expected) in [
            (3u8, ProposalState::Approved),
            (5u8, ProposalState::Executed),
        ] {
            let mut data = vec![0u8; 8 + 32 + 8];
            data.push(variant);
            data.extend_from_slice(&0i64.to_le_bytes());
            data.push(255);
            data.extend_from_slice(&0u32.to_le_bytes());
            assert_eq!(
                parse_proposal_state(&account_info_envelope(&data)).expect("variant"),
                expected
            );
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn signature_status_confirmed_and_missing() {
        let found = r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":[{"slot":100,"confirmations":null,"err":null,"confirmationStatus":"finalized"}]}}"#;
        let st = parse_signature_status(found)
            .expect("status")
            .expect("some");
        assert!(st.confirmed() && st.finalized());
        assert_eq!(st.slot, 100);
        let missing = r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":[null]}}"#;
        assert_eq!(parse_signature_status(missing).expect("missing"), None);
        // A failed tx is not "confirmed".
        let failed = r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":[{"slot":1,"confirmations":1,"err":{"InstructionError":[0,"Custom"]},"confirmationStatus":"confirmed"}]}}"#;
        assert!(!parse_signature_status(failed)
            .expect("failed")
            .expect("some")
            .confirmed());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn get_transaction_parses_system_transfer_and_memo() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{
            "slot":1234,
            "meta":{"err":null},
            "transaction":{"signatures":["SiG"],"message":{"instructions":[
                {"program":"spl-memo","programId":"Memo","parsed":"=:SOL.SOL:abc"},
                {"program":"system","programId":"111","parsed":{"type":"transfer","info":{"source":"ThorVault","destination":"OurVault","lamports":2000000000}}}
            ]}}}}"#;
        let t = parse_get_transaction(body, "OurVault")
            .expect("parse")
            .expect("some transfer");
        assert_eq!(t.source, "ThorVault");
        assert_eq!(t.destination, "OurVault");
        assert_eq!(t.lamports, 2_000_000_000);
        assert_eq!(t.memo, "=:SOL.SOL:abc");
        assert_eq!(t.slot, 1234);
        // Wrong destination → no transfer.
        assert!(parse_get_transaction(body, "Someone")
            .expect("parse")
            .is_none());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn failed_transaction_is_dropped() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"slot":1,"meta":{"err":{"x":1}},"transaction":{"signatures":["S"],"message":{"instructions":[]}}}}"#;
        assert_eq!(
            parse_get_transaction(body, "OurVault").expect("parse"),
            None
        );
    }

    #[test]
    fn new_rejects_non_solana_chain() {
        assert!(matches!(
            ReqwestSolanaChainClient::new(ChainId::Xrp, "http://x"),
            Err(SolanaChainError::NotSolanaChain(ChainId::Xrp))
        ));
    }
}
