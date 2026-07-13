//! Fail-closed Cobo development-environment qualification gate.
//!
//! This binary is deliberately separate from the active Turnkey custody wire.
//! It can inspect the pinned Cobo `OpenAPI` surface and locally validate captured
//! evidence without credentials. A complete PASS additionally requires an
//! authenticated call to the hard-coded Cobo development API plus live Cobo
//! transaction records for the BTC, EVM, and negative-test artifacts.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::consensus::{Transaction as AlloyTransaction, TxEnvelope};
use alloy::eips::eip2718::Decodable2718;
use alloy_primitives::{Address, TxKind, U256};
use anyhow::{Context, Result};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::psbt::Psbt;
use bitcoin::script::Instruction;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{ScriptBuf, Transaction as BitcoinTransaction};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use xindex_shared::chain_registry::ChainId;

const API_BASE: &str = "https://api.dev.cobo.com/v2";
const OPENAPI_RELEASE: &str = "1.39";
const OPENAPI_COMMIT: &str = "e14ea77ae07daa15e4f77b5e978b0a0a00f2b2bd";
const OPENAPI_SHA256: &str = "25e9d81a68eabd1754e036b2997ea8d9616261d50d4374ba19817f616952cd5f";
const DEFAULT_OPENAPI: &str = "/tmp/cobo-waas2-go-sdk/api/openapi.yaml";
const SEPOLIA_CHAIN_ID: u64 = 11_155_111;
const REQUIRED_NEGATIVE_CASES: [&str; 5] = [
    "tampered_destination",
    "tampered_amount_or_calldata",
    "tampered_callback_hash",
    "replay",
    "fee_above_cap",
];

#[derive(Debug, Parser)]
#[command(
    name = "xindex-cobo-dev-gate",
    about = "Fail-closed, evidence-producing Cobo development gate"
)]
struct Args {
    /// Official Cobo SDK `OpenAPI` YAML snapshot (release 1.39).
    #[arg(long, default_value = DEFAULT_OPENAPI)]
    openapi: PathBuf,
    /// Captured dev-environment evidence JSON. Omit for schema-only offline mode.
    #[arg(long)]
    evidence: Option<PathBuf>,
    /// Authenticate against api.dev.cobo.com and corroborate Cobo records.
    #[arg(long)]
    live: bool,
    /// Environment variable holding the 32-byte hex Cobo API secret.
    #[arg(long, default_value = "COBO_API_SECRET")]
    api_secret_env: String,
    /// Also write the machine-readable report to this path.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum GateStatus {
    Pass,
    Fail,
    Blocked,
}

#[derive(Debug, Serialize)]
struct Check {
    id: String,
    required: bool,
    status: GateStatus,
    detail: String,
}

impl Check {
    fn new(
        id: impl Into<String>,
        required: bool,
        status: GateStatus,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            required,
            status,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Serialize)]
struct AssetResult {
    asset: &'static str,
    expected_cobo_chain_ids: Vec<&'static str>,
    status: GateStatus,
    matched_cobo_chain_id: Option<String>,
    detail: String,
}

#[derive(Debug, Serialize)]
struct OpenApiSource {
    sdk_release: &'static str,
    sdk_commit: &'static str,
    path: String,
    sha256: Option<String>,
}

#[derive(Debug, Serialize)]
struct GateReport {
    schema_version: u32,
    provider: &'static str,
    environment: &'static str,
    api_base_url: &'static str,
    mode: &'static str,
    generated_at_unix: u64,
    overall: GateStatus,
    openapi: OpenApiSource,
    checks: Vec<Check>,
    assets: Vec<AssetResult>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GateEvidence {
    schema_version: u32,
    wallet: WalletEvidence,
    #[serde(default)]
    btc: Option<BtcEvidence>,
    #[serde(default)]
    evm: Option<EvmEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletEvidence {
    wallet_id: String,
    vault_id: String,
    key_share_holder_group_id: String,
    wallet_subtype: String,
    threshold: u32,
    participants: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BtcEvidence {
    path: String,
    cobo_transaction_id: String,
    cobo_request_id: String,
    reconstruction_psbt_hex: String,
    signed_transaction_hex: String,
    onchain_txid: String,
    confirmation_block_hash: String,
    confirmations: u64,
    expected_payout_script_pubkey_hex: String,
    expected_payout_sats: u64,
    expected_change_script_pubkey_hex: String,
    expected_op_return_hex: String,
    callback: CallbackEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvmEvidence {
    cobo_transaction_id: String,
    cobo_request_id: String,
    transaction_process_type: String,
    status_before_sign: String,
    status_after_sign: String,
    signed_transaction_hex: String,
    transaction_hash: String,
    confirmation_block_hash: String,
    confirmations: u64,
    receipt_status: u64,
    expected_source_address: String,
    expected_to: String,
    expected_value_wei: String,
    expected_calldata_hex: String,
    callback: CallbackEvidence,
    negative_tests: Vec<NegativeEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallbackEvidence {
    request_id: String,
    request_type: u8,
    request_detail: Value,
    extra_info: Value,
    transport_signature_verified: bool,
    response_signature_verified: bool,
    request_jwt_sha256: String,
    response_action: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "evidence shape mirrors four independent captured yes/no facts"
)]
struct NegativeEvidence {
    case: String,
    cobo_transaction_id: String,
    callback_action: String,
    rejection_code: String,
    transport_signature_verified: bool,
    response_signature_verified: bool,
    signature_produced: bool,
    broadcast: bool,
}

struct PortalSigner {
    signing_key: SigningKey,
}

impl std::fmt::Debug for PortalSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalSigner").finish_non_exhaustive()
    }
}

impl PortalSigner {
    fn from_hex(secret: &str) -> std::result::Result<Self, String> {
        let raw = alloy_primitives::hex::decode(secret.trim())
            .map_err(|_| "Cobo API secret is not valid hex".to_string())?;
        let seed: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| "Cobo API secret must be exactly 32 bytes".to_string())?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    fn api_key(&self) -> String {
        alloy_primitives::hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    fn api_key_fingerprint(&self) -> String {
        let digest = Sha256::digest(self.signing_key.verifying_key().to_bytes());
        alloy_primitives::hex::encode(&digest[..8])
    }

    fn sign(&self, method: &str, path: &str, nonce: &str, query: &str, body: &str) -> String {
        let content = format!("{method}|{path}|{nonce}|{query}|{body}");
        let first = Sha256::digest(content.as_bytes());
        let second = Sha256::digest(first);
        alloy_primitives::hex::encode(self.signing_key.sign(&second).to_bytes())
    }
}

#[derive(Debug)]
enum LiveCallError {
    Unavailable(String),
    Rejected(u16),
    InvalidResponse(String),
}

struct CoboDevClient {
    http: reqwest::Client,
    signer: PortalSigner,
}

impl std::fmt::Debug for CoboDevClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoboDevClient")
            .field("api_base", &API_BASE)
            .field("api_key_fingerprint", &self.signer.api_key_fingerprint())
            .finish_non_exhaustive()
    }
}

impl CoboDevClient {
    fn new(signer: PortalSigner) -> std::result::Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| format!("HTTP client: {e}"))?;
        Ok(Self { http, signer })
    }

    async fn get_json(
        &self,
        relative_path: &str,
        query: &str,
    ) -> std::result::Result<Value, LiveCallError> {
        if !relative_path.starts_with('/') || relative_path.contains("..") {
            return Err(LiveCallError::InvalidResponse(
                "unsafe relative API path".to_string(),
            ));
        }
        let request_path = format!("/v2{relative_path}");
        let nonce = now_millis().to_string();
        let signature = self.signer.sign("GET", &request_path, &nonce, query, "");
        let mut url = format!("{API_BASE}{relative_path}");
        if !query.is_empty() {
            url.push('?');
            url.push_str(query);
        }
        let response = self
            .http
            .get(url)
            .header("Accept", "application/json")
            .header("Biz-Api-Key", self.signer.api_key())
            .header("Biz-Api-Nonce", nonce)
            .header("Biz-Api-Signature", signature)
            .send()
            .await
            .map_err(|e| LiveCallError::Unavailable(sanitize_transport_error(&e)))?;
        let status = response.status();
        if !status.is_success() {
            return Err(LiveCallError::Rejected(status.as_u16()));
        }
        response
            .json::<Value>()
            .await
            .map_err(|_| LiveCallError::InvalidResponse("response was not JSON".to_string()))
    }
}

fn sanitize_transport_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "Cobo dev API timed out".to_string()
    } else if error.is_connect() {
        "Cobo dev API was unreachable".to_string()
    } else {
        "Cobo dev API transport error".to_string()
    }
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn sha256_hex(bytes: &[u8]) -> String {
    alloy_primitives::hex::encode(Sha256::digest(bytes))
}

fn schema_block<'a>(yaml: &'a str, schema: &str) -> Option<&'a str> {
    let needle = format!("    {schema}:");
    let start = yaml.find(&needle)?;
    let after_start = start.saturating_add(needle.len());
    let rest = &yaml[after_start..];
    let mut end = rest.len();
    let mut offset = 0usize;
    for line in rest.split_inclusive('\n') {
        let bare = line.trim_end_matches(['\r', '\n']);
        if offset > 0
            && bare.starts_with("    ")
            && !bare.starts_with("     ")
            && bare.trim_end().ends_with(':')
        {
            end = offset;
            break;
        }
        offset = offset.saturating_add(line.len());
    }
    Some(&rest[..end])
}

fn schema_property_names(block: &str) -> BTreeSet<String> {
    let mut in_properties = false;
    let mut names = BTreeSet::new();
    for line in block.lines() {
        if line == "      properties:" {
            in_properties = true;
            continue;
        }
        if !in_properties {
            continue;
        }
        let indent = line.len().saturating_sub(line.trim_start().len());
        if indent <= 6 && !line.trim().is_empty() {
            break;
        }
        if indent == 8 {
            let trimmed = line.trim();
            if let Some(name) = trimmed.strip_suffix(':') {
                names.insert(name.to_string());
            }
        }
    }
    names
}

#[expect(
    clippy::too_many_lines,
    reason = "linear fail-closed inspection report keeps evidence checks auditable"
)]
fn inspect_openapi(path: &Path) -> (OpenApiSource, Vec<Check>, bool) {
    let mut source = OpenApiSource {
        sdk_release: OPENAPI_RELEASE,
        sdk_commit: OPENAPI_COMMIT,
        path: path.display().to_string(),
        sha256: None,
    };
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                source,
                vec![Check::new(
                    "OPENAPI-01",
                    true,
                    GateStatus::Blocked,
                    format!("official OpenAPI snapshot unavailable: {error}"),
                )],
                false,
            );
        }
    };
    let actual_sha256 = sha256_hex(&bytes);
    let source_matches = actual_sha256 == OPENAPI_SHA256;
    source.sha256 = Some(actual_sha256.clone());
    let Ok(yaml) = std::str::from_utf8(&bytes) else {
        return (
            source,
            vec![Check::new(
                "OPENAPI-01",
                true,
                GateStatus::Fail,
                "OpenAPI snapshot is not UTF-8",
            )],
            false,
        );
    };

    let mut checks = vec![Check::new(
        "OPENAPI-01",
        true,
        if source_matches {
            GateStatus::Pass
        } else {
            GateStatus::Fail
        },
        if source_matches {
            format!(
                "official SDK release {OPENAPI_RELEASE} snapshot verified; sha256={actual_sha256}"
            )
        } else {
            format!(
                "OpenAPI snapshot hash mismatch: expected {OPENAPI_SHA256}, got {actual_sha256}"
            )
        },
    )];
    let expected = BTreeSet::from(["address".to_string(), "amount".to_string()]);
    let transfer = schema_block(
        yaml,
        "TransactionTransferToAddressDestination_utxo_outputs_inner",
    )
    .map(schema_property_names);
    let address = schema_block(yaml, "AddressTransferDestination_utxo_outputs_inner")
        .map(schema_property_names);
    let utxo_shape_ok = transfer.as_ref() == Some(&expected) && address.as_ref() == Some(&expected);
    checks.push(Check::new(
        "OPENAPI-02",
        true,
        if utxo_shape_ok {
            GateStatus::Pass
        } else {
            GateStatus::Fail
        },
        if utxo_shape_ok {
            "both UTXO output schemas contain only address+amount; no script/data/OP_RETURN field"
                .to_string()
        } else {
            format!("unexpected UTXO schemas: transaction={transfer:?}, address={address:?}")
        },
    ));

    let raw_block = schema_block(yaml, "RawMessageSignDestination");
    let normalized = raw_block.map_or_else(String::new, |block| {
        block
            .replace("\\\n", "")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    });
    let raw_forbidden = normalized.contains("deprecated: true")
        && normalized.contains("is no longer allowed and must not be used");
    checks.push(Check::new(
        "OPENAPI-03",
        true,
        if raw_forbidden {
            GateStatus::Pass
        } else {
            GateStatus::Fail
        },
        if raw_forbidden {
            "Raw_Message_Signature is deprecated and explicitly no longer allowed"
        } else {
            "could not prove the Raw_Message_Signature prohibition from the supplied snapshot"
        },
    ));
    (
        source,
        checks,
        source_matches && utxo_shape_ok && raw_forbidden,
    )
}

fn load_evidence(path: Option<&Path>) -> (Option<GateEvidence>, Check) {
    let Some(path) = path else {
        return (
            None,
            Check::new(
                "EVIDENCE-01",
                true,
                GateStatus::Blocked,
                "no dev-environment evidence file supplied",
            ),
        );
    };
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                None,
                Check::new(
                    "EVIDENCE-01",
                    true,
                    GateStatus::Fail,
                    format!("cannot read evidence file: {error}"),
                ),
            );
        }
    };
    match serde_json::from_slice::<GateEvidence>(&bytes) {
        Ok(evidence) if evidence.schema_version == 1 => (
            Some(evidence),
            Check::new(
                "EVIDENCE-01",
                true,
                GateStatus::Pass,
                format!("evidence schema 1 parsed; sha256={}", sha256_hex(&bytes)),
            ),
        ),
        Ok(evidence) => (
            None,
            Check::new(
                "EVIDENCE-01",
                true,
                GateStatus::Fail,
                format!("unsupported evidence schema {}", evidence.schema_version),
            ),
        ),
        Err(error) => (
            None,
            Check::new(
                "EVIDENCE-01",
                true,
                GateStatus::Fail,
                format!("invalid evidence JSON: {error}"),
            ),
        ),
    }
}

fn chain_ids_from_response(value: &Value) -> std::result::Result<BTreeSet<String>, String> {
    let data = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| "enabled-chains response has no data array".to_string())?;
    let mut ids = BTreeSet::new();
    for entry in data {
        let id = entry
            .get("chain_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "enabled-chains entry has no chain_id".to_string())?;
        ids.insert(id.to_ascii_uppercase());
    }
    if ids.is_empty() {
        return Err("enabled-chains response was empty".to_string());
    }
    Ok(ids)
}

async fn start_live(args: &Args) -> (Option<CoboDevClient>, Option<BTreeSet<String>>, Check) {
    if !args.live {
        return (
            None,
            None,
            Check::new(
                "LIVE-DEV-01",
                true,
                GateStatus::Blocked,
                "offline mode: no live credential or api.dev.cobo.com assertion was made",
            ),
        );
    }
    let secret = match env::var(&args.api_secret_env) {
        Ok(secret) if !secret.trim().is_empty() => secret,
        _ => {
            return (
                None,
                None,
                Check::new(
                    "LIVE-DEV-01",
                    true,
                    GateStatus::Blocked,
                    format!("{} is not set", args.api_secret_env),
                ),
            );
        }
    };
    let signer = match PortalSigner::from_hex(&secret) {
        Ok(signer) => signer,
        Err(detail) => {
            return (
                None,
                None,
                Check::new("LIVE-DEV-01", true, GateStatus::Fail, detail),
            );
        }
    };
    let fingerprint = signer.api_key_fingerprint();
    let client = match CoboDevClient::new(signer) {
        Ok(client) => client,
        Err(detail) => {
            return (
                None,
                None,
                Check::new("LIVE-DEV-01", true, GateStatus::Blocked, detail),
            );
        }
    };
    let response = client
        .get_json(
            "/wallets/enabled_chains",
            "limit=500&wallet_subtype=Org-Controlled&wallet_type=MPC",
        )
        .await;
    match response {
        Ok(value) => match chain_ids_from_response(&value) {
            Ok(ids) => (
                Some(client),
                Some(ids),
                Check::new(
                    "LIVE-DEV-01",
                    true,
                    GateStatus::Pass,
                    format!("authenticated Cobo dev API; api-key fingerprint={fingerprint}"),
                ),
            ),
            Err(detail) => (
                None,
                None,
                Check::new("LIVE-DEV-01", true, GateStatus::Fail, detail),
            ),
        },
        Err(LiveCallError::Unavailable(detail)) => (
            None,
            None,
            Check::new("LIVE-DEV-01", true, GateStatus::Blocked, detail),
        ),
        Err(LiveCallError::Rejected(status)) => (
            None,
            None,
            Check::new(
                "LIVE-DEV-01",
                true,
                GateStatus::Fail,
                format!("Cobo dev API rejected the authenticated probe (HTTP {status})"),
            ),
        ),
        Err(LiveCallError::InvalidResponse(detail)) => (
            None,
            None,
            Check::new("LIVE-DEV-01", true, GateStatus::Fail, detail),
        ),
    }
}

fn asset_specs() -> [(&'static str, &'static [&'static str]); 15] {
    [
        ("BTC.BTC", &["BTC", "BTC_SIGNET"]),
        ("LTC.LTC", &["LTC"]),
        ("BCH.BCH", &["BCH"]),
        ("DOGE.DOGE", &["DOGE"]),
        ("ZEC.ZEC", &["ZEC"]),
        ("ETH.ETH", &["ETH", "ETH_SEPOLIA"]),
        ("BSC.BNB", &["BSC", "BNB"]),
        ("AVAX.AVAX", &["AVAX", "AVAXC"]),
        ("BASE.ETH", &["BASE"]),
        ("POL.MATIC", &["POL", "MATIC", "POLYGON"]),
        ("GAIA.ATOM", &["GAIA", "ATOM", "COSMOS"]),
        ("NOBLE.USDC", &["NOBLE"]),
        ("XRP.XRP", &["XRP"]),
        ("SOL.SOL", &["SOL"]),
        ("TRON.TRX", &["TRON", "TRX"]),
    ]
}

fn evaluate_assets(live_chain_ids: Option<&BTreeSet<String>>) -> Vec<AssetResult> {
    asset_specs()
        .into_iter()
        .map(|(asset, aliases)| {
            let Some(ids) = live_chain_ids else {
                return AssetResult {
                    asset,
                    expected_cobo_chain_ids: aliases.to_vec(),
                    status: GateStatus::Blocked,
                    matched_cobo_chain_id: None,
                    detail: "requires authenticated Org-Controlled enabled-chains response"
                        .to_string(),
                };
            };
            let matched = aliases
                .iter()
                .find(|alias| ids.contains(&alias.to_ascii_uppercase()))
                .map(|alias| (*alias).to_string());
            AssetResult {
                asset,
                expected_cobo_chain_ids: aliases.to_vec(),
                status: if matched.is_some() {
                    GateStatus::Pass
                } else {
                    GateStatus::Fail
                },
                matched_cobo_chain_id: matched,
                detail: if aliases.iter().any(|alias| ids.contains(*alias)) {
                    "present in authenticated Org-Controlled enabled-chains response".to_string()
                } else {
                    "not present in authenticated Org-Controlled enabled-chains response"
                        .to_string()
                },
            }
        })
        .collect()
}

fn objectish(value: &Value) -> std::result::Result<Value, String> {
    match value {
        Value::Object(_) => Ok(value.clone()),
        Value::String(inner) => {
            serde_json::from_str(inner).map_err(|error| format!("embedded callback JSON: {error}"))
        }
        _ => Err("callback field is neither an object nor a JSON string".to_string()),
    }
}

fn normalize_hash(value: &str) -> String {
    value.trim().trim_start_matches("0x").to_ascii_lowercase()
}

fn value_contains_string(value: &Value, wanted: &str) -> bool {
    match value {
        Value::String(value) => value == wanted,
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_string(value, wanted)),
        Value::Object(values) => values
            .values()
            .any(|value| value_contains_string(value, wanted)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn validate_callback(
    callback: &CallbackEvidence,
    cobo_transaction_id: &str,
    expected_hashes: &[String],
) -> std::result::Result<(), String> {
    if callback.request_type != 2 {
        return Err("callback request_type is not KeySign (2)".to_string());
    }
    if callback.request_id.trim().is_empty() {
        return Err("callback request_id is empty".to_string());
    }
    if !callback.transport_signature_verified {
        return Err("callback transport signature was not verified".to_string());
    }
    if !callback.response_signature_verified {
        return Err("callback response signature was not verified".to_string());
    }
    let jwt_hash = normalize_hash(&callback.request_jwt_sha256);
    if jwt_hash.len() != 64 || alloy_primitives::hex::decode(&jwt_hash).is_err() {
        return Err("callback JWT sha256 is missing or malformed".to_string());
    }
    if callback.response_action != "APPROVE" {
        return Err("honest callback did not return APPROVE".to_string());
    }
    let detail = objectish(&callback.request_detail)?;
    let biz_task_id = detail
        .get("biz_task_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "callback request_detail has no biz_task_id".to_string())?;
    if biz_task_id != cobo_transaction_id {
        return Err("callback biz_task_id does not match Cobo transaction id".to_string());
    }
    let actual = detail
        .get("msg_hash_list")
        .and_then(Value::as_array)
        .ok_or_else(|| "callback request_detail has no msg_hash_list".to_string())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(normalize_hash)
                .ok_or_else(|| "callback msg_hash_list contains a non-string".to_string())
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let expected = expected_hashes
        .iter()
        .map(|value| normalize_hash(value))
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(
            "callback msg_hash_list does not equal the independently recomputed payloads"
                .to_string(),
        );
    }
    let extra = objectish(&callback.extra_info)?;
    if !value_contains_string(&extra, cobo_transaction_id) {
        return Err("callback extra_info is not bound to the Cobo transaction id".to_string());
    }
    Ok(())
}

fn op_return_payload(script: &ScriptBuf) -> std::result::Result<Option<Vec<u8>>, String> {
    let mut instructions = script.instructions();
    let first = match instructions.next() {
        None => return Ok(None),
        Some(Ok(instruction)) => instruction,
        Some(Err(error)) => return Err(format!("invalid output script: {error}")),
    };
    if first != Instruction::Op(OP_RETURN) {
        return Ok(None);
    }
    let payload = match instructions.next() {
        Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes().to_vec(),
        Some(Ok(Instruction::Op(_))) => {
            return Err("OP_RETURN payload is not a data push".to_string())
        }
        Some(Err(error)) => return Err(format!("invalid OP_RETURN: {error}")),
        None => Vec::new(),
    };
    if instructions.next().is_some() {
        return Err("OP_RETURN has more than one instruction after the payload".to_string());
    }
    Ok(Some(payload))
}

fn stripped_unsigned(tx: &BitcoinTransaction) -> BitcoinTransaction {
    let mut unsigned = tx.clone();
    for input in &mut unsigned.input {
        input.script_sig = ScriptBuf::new();
        input.witness.clear();
    }
    unsigned
}

fn validate_btc_artifact(evidence: &BtcEvidence) -> std::result::Result<Vec<String>, String> {
    if evidence.path != "native_op_return" {
        return Err("BTC evidence path must be native_op_return".to_string());
    }
    if evidence.cobo_request_id.trim().is_empty() {
        return Err("Cobo BTC request id is empty".to_string());
    }
    if evidence.confirmations == 0 || evidence.confirmation_block_hash.trim().is_empty() {
        return Err("BTC transaction is not recorded as confirmed".to_string());
    }
    let psbt_bytes = alloy_primitives::hex::decode(evidence.reconstruction_psbt_hex.trim())
        .map_err(|error| format!("BTC PSBT hex: {error}"))?;
    let psbt = Psbt::deserialize(&psbt_bytes).map_err(|error| format!("BTC PSBT: {error}"))?;
    let signed_bytes = alloy_primitives::hex::decode(
        evidence
            .signed_transaction_hex
            .trim()
            .trim_start_matches("0x"),
    )
    .map_err(|error| format!("BTC transaction hex: {error}"))?;
    let signed: BitcoinTransaction =
        deserialize(&signed_bytes).map_err(|error| format!("BTC transaction: {error}"))?;
    if signed.compute_txid().to_string() != evidence.onchain_txid.to_ascii_lowercase() {
        return Err("BTC txid does not match signed transaction bytes".to_string());
    }
    if stripped_unsigned(&signed) != psbt.unsigned_tx {
        return Err(
            "BTC PSBT unsigned transaction does not match the confirmed transaction".to_string(),
        );
    }
    if signed
        .input
        .iter()
        .any(|input| input.witness.is_empty() && input.script_sig.is_empty())
    {
        return Err("BTC transaction contains an unsigned input".to_string());
    }
    let payout_spk = ScriptBuf::from_bytes(
        alloy_primitives::hex::decode(&evidence.expected_payout_script_pubkey_hex)
            .map_err(|error| format!("payout script hex: {error}"))?,
    );
    let change_spk = ScriptBuf::from_bytes(
        alloy_primitives::hex::decode(&evidence.expected_change_script_pubkey_hex)
            .map_err(|error| format!("change script hex: {error}"))?,
    );
    let expected_memo = alloy_primitives::hex::decode(&evidence.expected_op_return_hex)
        .map_err(|error| format!("OP_RETURN payload hex: {error}"))?;
    if expected_memo.is_empty() {
        return Err("expected OP_RETURN payload is empty".to_string());
    }
    let mut payout_count = 0usize;
    let mut memo_count = 0usize;
    for output in &signed.output {
        if output.script_pubkey == payout_spk
            && output.value.to_sat() == evidence.expected_payout_sats
        {
            payout_count = payout_count.saturating_add(1);
            continue;
        }
        if let Some(payload) = op_return_payload(&output.script_pubkey)? {
            if output.value.to_sat() != 0 || payload != expected_memo {
                return Err("BTC OP_RETURN value or payload mismatch".to_string());
            }
            memo_count = memo_count.saturating_add(1);
            continue;
        }
        if output.script_pubkey != change_spk {
            return Err("BTC transaction has an unexpected non-change output".to_string());
        }
    }
    if payout_count != 1 || memo_count != 1 {
        return Err(format!(
            "BTC exact output set failed: payouts={payout_count}, op_returns={memo_count}"
        ));
    }

    let mut hashes = Vec::with_capacity(psbt.inputs.len());
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    for (index, input) in psbt.inputs.iter().enumerate() {
        let witness_utxo = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| format!("BTC PSBT input {index} lacks witness_utxo"))?;
        let sighash = cache
            .p2wpkh_signature_hash(
                index,
                &witness_utxo.script_pubkey,
                witness_utxo.value,
                EcdsaSighashType::All,
            )
            .map_err(|error| format!("BTC input {index} sighash: {error}"))?;
        hashes.push(alloy_primitives::hex::encode(sighash.to_byte_array()));
    }
    validate_callback(&evidence.callback, &evidence.cobo_transaction_id, &hashes)?;
    Ok(hashes)
}

fn validate_evm_artifact(evidence: &EvmEvidence) -> std::result::Result<String, String> {
    if evidence.transaction_process_type != "BuildOnly"
        || evidence.status_before_sign != "Built"
        || evidence.status_after_sign != "Completed"
    {
        return Err("EVM evidence does not prove BuildOnly -> Built -> Completed".to_string());
    }
    if evidence.cobo_request_id.trim().is_empty() {
        return Err("Cobo EVM request id is empty".to_string());
    }
    if evidence.confirmations == 0
        || evidence.receipt_status != 1
        || evidence.confirmation_block_hash.trim().is_empty()
    {
        return Err("Sepolia transaction is not recorded as successful and confirmed".to_string());
    }
    let raw = alloy_primitives::hex::decode(
        evidence
            .signed_transaction_hex
            .trim()
            .trim_start_matches("0x"),
    )
    .map_err(|error| format!("EVM transaction hex: {error}"))?;
    let envelope = TxEnvelope::decode_2718(&mut raw.as_slice())
        .map_err(|error| format!("EVM transaction: {error}"))?;
    if !envelope.is_eip1559() || envelope.chain_id() != Some(SEPOLIA_CHAIN_ID) {
        return Err("EVM transaction is not EIP-1559 on Sepolia".to_string());
    }
    if normalize_hash(&envelope.tx_hash().to_string()) != normalize_hash(&evidence.transaction_hash)
    {
        return Err("EVM transaction hash does not match signed bytes".to_string());
    }
    let expected_source = Address::from_str(&evidence.expected_source_address)
        .map_err(|error| format!("expected EVM source: {error}"))?;
    let recovered = envelope
        .recover_signer()
        .map_err(|error| format!("recover EVM signer: {error}"))?;
    if recovered != expected_source {
        return Err("EVM signer is not the expected Cobo MPC address".to_string());
    }
    let expected_to = Address::from_str(&evidence.expected_to)
        .map_err(|error| format!("expected EVM destination: {error}"))?;
    if envelope.kind() != TxKind::Call(expected_to) {
        return Err("EVM destination does not match the expected contract".to_string());
    }
    let expected_value = U256::from_str(&evidence.expected_value_wei)
        .map_err(|error| format!("expected EVM value: {error}"))?;
    if envelope.value() != expected_value {
        return Err("EVM value does not match the expected call".to_string());
    }
    let expected_calldata = alloy_primitives::hex::decode(
        evidence
            .expected_calldata_hex
            .trim()
            .trim_start_matches("0x"),
    )
    .map_err(|error| format!("expected calldata: {error}"))?;
    if expected_calldata.is_empty() || envelope.input().as_ref() != expected_calldata {
        return Err("EVM calldata is empty or does not match the expected call".to_string());
    }
    let max_fee = u128::from(envelope.gas_limit()).saturating_mul(envelope.max_fee_per_gas());
    let fee_cap = u128::from(ChainId::Eth.max_redeem_fee_base_units());
    if max_fee > fee_cap {
        return Err(format!(
            "EVM max fee {max_fee} exceeds Xindex cap {fee_cap}"
        ));
    }
    let signing_hash = alloy_primitives::hex::encode(envelope.signature_hash());
    validate_callback(
        &evidence.callback,
        &evidence.cobo_transaction_id,
        std::slice::from_ref(&signing_hash),
    )?;
    Ok(signing_hash)
}

fn transaction_status(value: &Value) -> Option<&str> {
    value.get("status").and_then(Value::as_str)
}

fn transaction_hash(value: &Value) -> Option<&str> {
    value.get("transaction_hash").and_then(Value::as_str)
}

async fn live_transaction_check(
    client: Option<&CoboDevClient>,
    transaction_id: &str,
    expected_statuses: &[&str],
    expected_hash: Option<&str>,
) -> std::result::Result<(), (GateStatus, String)> {
    let Some(client) = client else {
        return Err((
            GateStatus::Blocked,
            "requires live Cobo dev API transaction corroboration".to_string(),
        ));
    };
    if transaction_id.trim().is_empty() {
        return Err((GateStatus::Fail, "Cobo transaction id is empty".to_string()));
    }
    let path = format!("/transactions/{transaction_id}");
    match client.get_json(&path, "").await {
        Ok(value) => {
            let status = transaction_status(&value).ok_or_else(|| {
                (
                    GateStatus::Fail,
                    "Cobo transaction response has no status".to_string(),
                )
            })?;
            if !expected_statuses.contains(&status) {
                return Err((
                    GateStatus::Fail,
                    format!("Cobo transaction status {status} is not accepted"),
                ));
            }
            if let Some(expected_hash) = expected_hash {
                let actual = transaction_hash(&value).ok_or_else(|| {
                    (
                        GateStatus::Fail,
                        "Cobo completed transaction has no transaction_hash".to_string(),
                    )
                })?;
                if normalize_hash(actual) != normalize_hash(expected_hash) {
                    return Err((
                        GateStatus::Fail,
                        "Cobo transaction hash does not match the evidence".to_string(),
                    ));
                }
            } else if transaction_hash(&value).is_some() {
                return Err((
                    GateStatus::Fail,
                    "rejected negative test unexpectedly has a transaction hash".to_string(),
                ));
            }
            Ok(())
        }
        Err(LiveCallError::Unavailable(detail)) => Err((GateStatus::Blocked, detail)),
        Err(LiveCallError::Rejected(status)) => Err((
            GateStatus::Fail,
            format!("Cobo transaction lookup failed (HTTP {status})"),
        )),
        Err(LiveCallError::InvalidResponse(detail)) => Err((GateStatus::Fail, detail)),
    }
}

async fn evaluate_wallet(evidence: Option<&GateEvidence>, client: Option<&CoboDevClient>) -> Check {
    let Some(evidence) = evidence else {
        return Check::new(
            "MPC-01",
            true,
            GateStatus::Blocked,
            "requires Org-Controlled wallet and key-share-group evidence",
        );
    };
    let wallet = &evidence.wallet;
    if wallet.wallet_id.trim().is_empty()
        || wallet.vault_id.trim().is_empty()
        || wallet.key_share_holder_group_id.trim().is_empty()
        || wallet.wallet_subtype != "Org-Controlled"
        || wallet.threshold != 2
        || wallet.participants != 2
    {
        return Check::new(
            "MPC-01",
            true,
            GateStatus::Fail,
            "wallet evidence is not a complete Org-Controlled 2-of-2 group",
        );
    }
    let Some(client) = client else {
        return Check::new(
            "MPC-01",
            true,
            GateStatus::Blocked,
            "2-of-2 evidence parsed but requires live wallet/group corroboration",
        );
    };
    let wallet_path = format!("/wallets/{}", wallet.wallet_id);
    let live_wallet = match client.get_json(&wallet_path, "").await {
        Ok(value) => value,
        Err(error) => return live_error_check("MPC-01", error),
    };
    if !value_contains_string(&live_wallet, "Org-Controlled") {
        return Check::new(
            "MPC-01",
            true,
            GateStatus::Fail,
            "live wallet record is not Org-Controlled",
        );
    }
    let group_path = format!(
        "/wallets/mpc/vaults/{}/key_share_holder_groups/{}",
        wallet.vault_id, wallet.key_share_holder_group_id
    );
    let group = match client.get_json(&group_path, "").await {
        Ok(value) => value,
        Err(error) => return live_error_check("MPC-01", error),
    };
    let threshold = group.get("threshold").and_then(Value::as_u64);
    let participants = group.get("participants").and_then(Value::as_u64);
    if threshold == Some(2) && participants == Some(2) {
        Check::new(
            "MPC-01",
            true,
            GateStatus::Pass,
            "live Cobo records prove an Org-Controlled 2-of-2 key-share group",
        )
    } else {
        Check::new(
            "MPC-01",
            true,
            GateStatus::Fail,
            format!(
                "live group is not 2-of-2 (threshold={threshold:?}, participants={participants:?})"
            ),
        )
    }
}

fn live_error_check(id: &str, error: LiveCallError) -> Check {
    match error {
        LiveCallError::Unavailable(detail) => Check::new(id, true, GateStatus::Blocked, detail),
        LiveCallError::Rejected(status) => Check::new(
            id,
            true,
            GateStatus::Fail,
            format!("Cobo dev API rejected the lookup (HTTP {status})"),
        ),
        LiveCallError::InvalidResponse(detail) => Check::new(id, true, GateStatus::Fail, detail),
    }
}

async fn evaluate_btc(
    evidence: Option<&GateEvidence>,
    client: Option<&CoboDevClient>,
    openapi_ok: bool,
) -> Vec<Check> {
    let raw_status = if openapi_ok {
        GateStatus::Fail
    } else {
        GateStatus::Blocked
    };
    let raw = Check::new(
        "BTC-RAW-01",
        false,
        raw_status,
        if openapi_ok {
            "OpenAPI 1.39 forbids Raw_Message_Signature; no documented PSBT/raw-sighash fallback"
        } else {
            "OpenAPI prohibition could not be verified"
        },
    );
    let Some(btc) = evidence.and_then(|evidence| evidence.btc.as_ref()) else {
        return vec![
            raw,
            Check::new(
                "BTC-NATIVE-01",
                false,
                GateStatus::Blocked,
                "public UTXO output schema cannot encode OP_RETURN; live native-path evidence absent",
            ),
            Check::new(
                "BTC-CALLBACK-01",
                true,
                GateStatus::Blocked,
                "BTC KeySign callback evidence absent",
            ),
            Check::new(
                "BTC-PATH-01",
                true,
                GateStatus::Blocked,
                "neither native OP_RETURN nor a permitted raw-sighash path is proven",
            ),
        ];
    };

    let local = validate_btc_artifact(btc);
    let callback = match &local {
        Ok(hashes) => Check::new(
            "BTC-CALLBACK-01",
            true,
            GateStatus::Pass,
            format!(
                "callback biz_task_id + {} msg_hash(es) bind to the independently reconstructed signet transaction",
                hashes.len()
            ),
        ),
        Err(detail) => Check::new(
            "BTC-CALLBACK-01",
            true,
            GateStatus::Fail,
            detail.clone(),
        ),
    };
    let native = match local {
        Err(detail) => Check::new("BTC-NATIVE-01", false, GateStatus::Fail, detail),
        Ok(_) => match live_transaction_check(
            client,
            &btc.cobo_transaction_id,
            &["Completed"],
            Some(&btc.onchain_txid),
        )
        .await
        {
            Ok(()) => Check::new(
                "BTC-NATIVE-01",
                false,
                GateStatus::Pass,
                "live Cobo record and confirmed signet bytes prove payout + exact zero-value OP_RETURN + custody change",
            ),
            Err((status, detail)) => Check::new("BTC-NATIVE-01", false, status, detail),
        },
    };
    let path_status = native.status;
    let path_detail = match path_status {
        GateStatus::Pass => "native Cobo OP_RETURN path passed; raw fallback is unnecessary",
        GateStatus::Blocked => {
            "native OP_RETURN path still needs live corroboration; raw fallback is forbidden"
        }
        GateStatus::Fail => "native OP_RETURN evidence failed and raw fallback is forbidden",
    };
    vec![
        raw,
        native,
        callback,
        Check::new("BTC-PATH-01", true, path_status, path_detail),
    ]
}

#[expect(
    clippy::too_many_lines,
    reason = "linear evidence checklist is clearer than split stateful helpers"
)]
async fn evaluate_evm(
    evidence: Option<&GateEvidence>,
    client: Option<&CoboDevClient>,
) -> Vec<Check> {
    let Some(evm) = evidence.and_then(|evidence| evidence.evm.as_ref()) else {
        let mut checks = vec![
            Check::new(
                "EVM-SEPOLIA-01",
                true,
                GateStatus::Blocked,
                "Sepolia BuildOnly/sign/call evidence absent",
            ),
            Check::new(
                "EVM-CALLBACK-01",
                true,
                GateStatus::Blocked,
                "EVM KeySign callback evidence absent",
            ),
        ];
        for case in REQUIRED_NEGATIVE_CASES {
            checks.push(Check::new(
                format!("EVM-NEG-{case}"),
                true,
                GateStatus::Blocked,
                "negative-test evidence absent",
            ));
        }
        return checks;
    };

    let local = validate_evm_artifact(evm);
    let callback = match &local {
        Ok(hash) => Check::new(
            "EVM-CALLBACK-01",
            true,
            GateStatus::Pass,
            format!("callback msg_hash_list binds the Sepolia signing hash {hash}"),
        ),
        Err(detail) => Check::new("EVM-CALLBACK-01", true, GateStatus::Fail, detail.clone()),
    };
    let live = match local {
        Err(detail) => Check::new("EVM-SEPOLIA-01", true, GateStatus::Fail, detail),
        Ok(_) => match live_transaction_check(
            client,
            &evm.cobo_transaction_id,
            &["Completed"],
            Some(&evm.transaction_hash),
        )
        .await
        {
            Ok(()) => Check::new(
                "EVM-SEPOLIA-01",
                true,
                GateStatus::Pass,
                "live Cobo record plus raw EIP-1559 bytes prove BuildOnly -> sign -> successful Sepolia contract call",
            ),
            Err((status, detail)) => Check::new("EVM-SEPOLIA-01", true, status, detail),
        },
    };
    let mut checks = vec![live, callback];
    for required_case in REQUIRED_NEGATIVE_CASES {
        let matches = evm
            .negative_tests
            .iter()
            .filter(|negative| negative.case == required_case)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            checks.push(Check::new(
                format!("EVM-NEG-{required_case}"),
                true,
                GateStatus::Fail,
                format!(
                    "expected exactly one {required_case} artifact, got {}",
                    matches.len()
                ),
            ));
            continue;
        }
        let negative = matches[0];
        if negative.callback_action != "REJECT"
            || negative.rejection_code.trim().is_empty()
            || !negative.transport_signature_verified
            || !negative.response_signature_verified
            || negative.signature_produced
            || negative.broadcast
        {
            checks.push(Check::new(
                format!("EVM-NEG-{required_case}"),
                true,
                GateStatus::Fail,
                "negative artifact does not prove signed-callback REJECT with no signature/broadcast",
            ));
            continue;
        }
        match live_transaction_check(
            client,
            &negative.cobo_transaction_id,
            &["Rejected", "Failed"],
            None,
        )
        .await
        {
            Ok(()) => checks.push(Check::new(
                format!("EVM-NEG-{required_case}"),
                true,
                GateStatus::Pass,
                format!(
                    "live Cobo record confirms REJECT/no broadcast ({})",
                    negative.rejection_code
                ),
            )),
            Err((status, detail)) => checks.push(Check::new(
                format!("EVM-NEG-{required_case}"),
                true,
                status,
                detail,
            )),
        }
    }
    checks
}

fn overall_status(checks: &[Check], assets: &[AssetResult]) -> GateStatus {
    if checks
        .iter()
        .any(|check| check.required && check.status == GateStatus::Fail)
        || assets.iter().any(|asset| asset.status == GateStatus::Fail)
    {
        GateStatus::Fail
    } else if checks
        .iter()
        .any(|check| check.required && check.status == GateStatus::Blocked)
        || assets
            .iter()
            .any(|asset| asset.status == GateStatus::Blocked)
    {
        GateStatus::Blocked
    } else {
        GateStatus::Pass
    }
}

fn write_report(report: &GateReport, output: Option<&Path>) -> Result<()> {
    let json = serde_json::to_vec_pretty(report).context("serialize report")?;
    if let Some(path) = output {
        fs::write(path, &json).with_context(|| format!("write {}", path.display()))?;
    }
    let mut stdout = io::stdout().lock();
    stdout.write_all(&json).context("write report to stdout")?;
    stdout.write_all(b"\n").context("write newline")?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    let args = Args::parse();
    let (openapi, mut checks, openapi_ok) = inspect_openapi(&args.openapi);
    let (evidence, evidence_check) = load_evidence(args.evidence.as_deref());
    checks.push(evidence_check);
    let (client, live_chain_ids, live_check) = start_live(&args).await;
    checks.push(live_check);
    checks.push(evaluate_wallet(evidence.as_ref(), client.as_ref()).await);
    checks.extend(evaluate_btc(evidence.as_ref(), client.as_ref(), openapi_ok).await);
    checks.extend(evaluate_evm(evidence.as_ref(), client.as_ref()).await);
    let assets = evaluate_assets(live_chain_ids.as_ref());
    let overall = overall_status(&checks, &assets);
    let report = GateReport {
        schema_version: 1,
        provider: "Cobo",
        environment: "development",
        api_base_url: API_BASE,
        mode: if args.live { "live" } else { "offline" },
        generated_at_unix: now_seconds(),
        overall,
        openapi,
        checks,
        assets,
    };
    write_report(&report, args.output.as_deref())?;
    Ok(if overall == GateStatus::Pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]

    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::script::{Builder, PushBytesBuf};
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Txid, Witness};

    fn valid_callback() -> CallbackEvidence {
        CallbackEvidence {
            request_id: "tss-1".to_string(),
            request_type: 2,
            request_detail: serde_json::json!({
                "biz_task_id": "tx-1",
                "msg_hash_list": ["aabb"]
            }),
            extra_info: serde_json::json!({"transaction": {"transaction_id": "tx-1"}}),
            transport_signature_verified: true,
            response_signature_verified: true,
            request_jwt_sha256: "11".repeat(32),
            response_action: "APPROVE".to_string(),
        }
    }

    fn valid_wallet() -> WalletEvidence {
        WalletEvidence {
            wallet_id: "wallet-1".to_string(),
            vault_id: "vault-1".to_string(),
            key_share_holder_group_id: "group-1".to_string(),
            wallet_subtype: "Org-Controlled".to_string(),
            threshold: 2,
            participants: 2,
        }
    }

    #[test]
    fn extracts_only_utxo_property_names() {
        let yaml = "    Example:\n      properties:\n        address:\n          type: string\n        amount:\n          type: string\n      type: object\n    Next:\n      type: object\n";
        let block = schema_block(yaml, "Example").expect("schema");
        assert_eq!(
            schema_property_names(block),
            BTreeSet::from(["address".to_string(), "amount".to_string()])
        );
    }

    #[test]
    fn callback_requires_exact_hash_order_and_transaction_binding() {
        let mut callback = valid_callback();
        callback.request_detail = serde_json::json!({
            "biz_task_id": "tx-1",
            "msg_hash_list": ["AABB", "ccdd"]
        });
        assert!(validate_callback(
            &callback,
            "tx-1",
            &["0xaabb".to_string(), "0xccdd".to_string()]
        )
        .is_ok());
        assert!(validate_callback(
            &callback,
            "tx-1",
            &["0xccdd".to_string(), "0xaabb".to_string()]
        )
        .is_err());
    }

    #[test]
    fn op_return_parser_refuses_multiple_pushes() {
        let first = PushBytesBuf::try_from(b"=:ETH.USDT:dummy:0".to_vec()).expect("first push");
        let second = PushBytesBuf::try_from(b"unexpected".to_vec()).expect("second push");
        let invalid = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(&first)
            .push_slice(&second)
            .into_script();
        assert!(op_return_payload(&invalid)
            .expect_err("multiple pushes must fail")
            .contains("more than one instruction"));
    }

    #[test]
    fn op_return_parser_accepts_exact_single_push() {
        let payload = PushBytesBuf::try_from(b"=:ETH.USDT:dummy:0".to_vec()).expect("push");
        let valid = ScriptBuf::new_op_return(&payload);
        assert_eq!(
            op_return_payload(&valid).expect("parse"),
            Some(b"=:ETH.USDT:dummy:0".to_vec())
        );
    }

    #[test]
    fn portal_signer_rejects_bad_secrets_and_binds_request_fields() {
        assert!(PortalSigner::from_hex("not-hex").is_err());
        assert!(PortalSigner::from_hex(&"11".repeat(31)).is_err());

        let signer = PortalSigner::from_hex(&"11".repeat(32)).expect("valid seed");
        let signature = signer.sign("GET", "/v2/wallets", "123", "limit=1", "");
        assert_eq!(signature.len(), 128, "Ed25519 signature hex length");
        assert_eq!(
            signature,
            signer.sign("GET", "/v2/wallets", "123", "limit=1", ""),
            "same canonical request must sign deterministically"
        );
        assert_ne!(
            signature,
            signer.sign("GET", "/v2/wallets", "123", "limit=2", ""),
            "query mutation must change the signature"
        );
    }

    #[test]
    fn enabled_chain_response_is_strict_and_normalizes_case() {
        let ids = chain_ids_from_response(&serde_json::json!({
            "data": [{"chain_id": "btc"}, {"chain_id": "Eth_Sepolia"}]
        }))
        .expect("valid chain response");
        assert!(ids.contains("BTC"));
        assert!(ids.contains("ETH_SEPOLIA"));
        assert!(chain_ids_from_response(&serde_json::json!({"data": []})).is_err());
        assert!(chain_ids_from_response(&serde_json::json!({"data": [{}]})).is_err());
        assert!(chain_ids_from_response(&serde_json::json!({"data": "not-an-array"})).is_err());
    }

    #[test]
    fn asset_matrix_requires_all_fifteen_assets() {
        let mut ids = asset_specs()
            .into_iter()
            .map(|(_, aliases)| aliases[0].to_string())
            .collect::<BTreeSet<_>>();
        let complete = evaluate_assets(Some(&ids));
        assert_eq!(complete.len(), 15);
        assert!(complete
            .iter()
            .all(|asset| asset.status == GateStatus::Pass));

        assert!(ids.remove("NOBLE"));
        let missing = evaluate_assets(Some(&ids));
        let noble = missing
            .iter()
            .find(|asset| asset.asset == "NOBLE.USDC")
            .expect("Noble result");
        assert_eq!(noble.status, GateStatus::Fail);
        assert!(missing
            .iter()
            .filter(|asset| asset.asset != "NOBLE.USDC")
            .all(|asset| asset.status == GateStatus::Pass));
    }

    #[test]
    fn callback_security_fields_fail_closed() {
        let expected = vec!["0xaabb".to_string()];
        assert!(validate_callback(&valid_callback(), "tx-1", &expected).is_ok());

        let mut callback = valid_callback();
        callback.request_type = 1;
        assert!(validate_callback(&callback, "tx-1", &expected).is_err());

        let mut callback = valid_callback();
        callback.request_id.clear();
        assert!(validate_callback(&callback, "tx-1", &expected).is_err());

        let mut callback = valid_callback();
        callback.transport_signature_verified = false;
        assert!(validate_callback(&callback, "tx-1", &expected).is_err());

        let mut callback = valid_callback();
        callback.response_signature_verified = false;
        assert!(validate_callback(&callback, "tx-1", &expected).is_err());

        let mut callback = valid_callback();
        callback.request_jwt_sha256 = "xyz".to_string();
        assert!(validate_callback(&callback, "tx-1", &expected).is_err());

        let mut callback = valid_callback();
        callback.response_action = "REJECT".to_string();
        assert!(validate_callback(&callback, "tx-1", &expected).is_err());

        let mut callback = valid_callback();
        callback.request_detail["biz_task_id"] = serde_json::json!("tx-other");
        assert!(validate_callback(&callback, "tx-1", &expected).is_err());

        let mut callback = valid_callback();
        callback.extra_info = serde_json::json!({"transaction": {"transaction_id": "tx-other"}});
        assert!(validate_callback(&callback, "tx-1", &expected).is_err());
    }

    #[test]
    fn callback_object_fields_accept_objects_or_encoded_json_only() {
        let object = serde_json::json!({"a": 1});
        assert_eq!(objectish(&object).expect("object"), object);
        assert_eq!(
            objectish(&Value::String("{\"a\":1}".to_string())).expect("encoded object"),
            object
        );
        assert!(objectish(&Value::Bool(true)).is_err());
        assert!(objectish(&Value::String("not-json".to_string())).is_err());
    }

    #[test]
    fn evidence_loader_accepts_minimal_schema_and_denies_unknown_fields() {
        let base = serde_json::json!({
            "schema_version": 1,
            "wallet": {
                "wallet_id": "wallet-1",
                "vault_id": "vault-1",
                "key_share_holder_group_id": "group-1",
                "wallet_subtype": "Org-Controlled",
                "threshold": 2,
                "participants": 2
            }
        });
        let path = std::env::temp_dir().join(format!(
            "xindex-cobo-evidence-{}-{}.json",
            std::process::id(),
            now_millis()
        ));
        fs::write(&path, serde_json::to_vec(&base).expect("serialize"))
            .expect("write valid evidence");
        let (evidence, check) = load_evidence(Some(path.as_path()));
        assert!(evidence.is_some());
        assert_eq!(check.status, GateStatus::Pass);

        let mut invalid = base;
        invalid["unexpected"] = Value::Bool(true);
        fs::write(&path, serde_json::to_vec(&invalid).expect("serialize"))
            .expect("write invalid evidence");
        let (evidence, check) = load_evidence(Some(path.as_path()));
        assert!(evidence.is_none());
        assert_eq!(check.status, GateStatus::Fail);
        fs::remove_file(path).expect("remove evidence fixture");
    }

    #[tokio::test]
    async fn offline_mode_and_missing_artifacts_remain_blocked() {
        let args = Args {
            openapi: PathBuf::from("unused-offline-test"),
            evidence: None,
            live: false,
            api_secret_env: "UNUSED_COBO_SECRET".to_string(),
            output: None,
        };
        let (client, chain_ids, live) = start_live(&args).await;
        assert!(client.is_none());
        assert!(chain_ids.is_none());
        assert_eq!(live.status, GateStatus::Blocked);

        let btc = evaluate_btc(None, None, true).await;
        assert_eq!(
            btc.iter()
                .find(|check| check.id == "BTC-RAW-01")
                .expect("raw-path result")
                .status,
            GateStatus::Fail
        );
        assert_eq!(
            btc.iter()
                .find(|check| check.id == "BTC-PATH-01")
                .expect("BTC path result")
                .status,
            GateStatus::Blocked
        );

        let evm = evaluate_evm(None, None).await;
        assert_eq!(evm.len(), 2 + REQUIRED_NEGATIVE_CASES.len());
        assert!(evm.iter().all(|check| check.status == GateStatus::Blocked));
    }

    #[tokio::test]
    async fn wallet_evidence_requires_exact_two_of_two_and_live_corroboration() {
        let evidence = GateEvidence {
            schema_version: 1,
            wallet: valid_wallet(),
            btc: None,
            evm: None,
        };
        assert_eq!(
            evaluate_wallet(Some(&evidence), None).await.status,
            GateStatus::Blocked,
            "valid local evidence still needs a live lookup"
        );

        let mut invalid = GateEvidence {
            schema_version: 1,
            wallet: valid_wallet(),
            btc: None,
            evm: None,
        };
        invalid.wallet.threshold = 1;
        assert_eq!(
            evaluate_wallet(Some(&invalid), None).await.status,
            GateStatus::Fail
        );
    }

    #[test]
    fn overall_failure_dominates_blocked_results() {
        let checks = vec![
            Check::new("blocked", true, GateStatus::Blocked, "missing"),
            Check::new("failed", true, GateStatus::Fail, "contradiction"),
        ];
        assert_eq!(overall_status(&checks, &[]), GateStatus::Fail);
    }

    #[test]
    fn stripped_transaction_matches_unsigned_shape() {
        let tx = BitcoinTransaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::from_bytes(vec![1]),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![2]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let stripped = stripped_unsigned(&tx);
        assert!(stripped.input[0].script_sig.is_empty());
        assert!(stripped.input[0].witness.is_empty());
        assert_eq!(stripped.output, tx.output);
    }

    #[test]
    fn overall_is_blocked_until_all_required_evidence_passes() {
        let checks = vec![
            Check::new("a", true, GateStatus::Pass, "ok"),
            Check::new("b", true, GateStatus::Blocked, "missing"),
            Check::new("informational", false, GateStatus::Fail, "known limitation"),
        ];
        assert_eq!(overall_status(&checks, &[]), GateStatus::Blocked);
    }
}
