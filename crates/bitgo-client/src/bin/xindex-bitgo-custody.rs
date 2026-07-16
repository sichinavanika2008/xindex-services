//! Disabled-by-default `BitGo` Testnet4 custody workflow runtime.
//!
//! This binary never accepts a private key or performs user signing. It keeps
//! mainnet disabled, requires owner-only files, and makes final-sign/broadcast
//! an explicit capability plus sequence acknowledgement.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::Address as EvmAddress;
use anyhow::{bail, Context, Result};
use bitcoin::consensus::deserialize;
use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};
use clap::{Parser, Subcommand};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use xindex_bitgo_adapter::{
    parse_compressed_public_key, spend_policy_commitment, BitGoCoin, InputPolicy, SpendPolicy,
    WalletPolicy, P2WSH_EXTERNAL_CHAIN_CODE,
};
use xindex_bitgo_client::{
    BitGoAuthVersion, BitGoClient, BitGoCoordinator, BitGoEnvironment, BitGoWorkflowStore,
    SubmitOutcome, WorkflowPhase, WorkflowRecord,
};
use xindex_custody_core::gates::CustodyConfig;
use xindex_custody_core::replay::SqliteReplayStore;
use xindex_ops::network::HttpClientPolicy;
use xindex_shared::intent::IntentPolicy;
use xindex_shared::signer_wire::IntentProof;

const CONFIG_SCHEMA_VERSION: u32 = 1;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_TOKEN_BYTES: u64 = 4 * 1024;
const MAX_INTENT_PROOF_BYTES: u64 = 256 * 1024;
const MAX_TRANSACTION_HEX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "xindex-bitgo-custody")]
#[command(about = "Fail-closed BitGo Testnet4 custody workflow")]
struct Args {
    /// Absolute owner-only JSON configuration path.
    #[arg(long)]
    config: PathBuf,

    /// Absolute durable workflow `SQLite` path.
    #[arg(long)]
    workflow_db: PathBuf,

    /// Absolute owner-only `BitGo` token file. Required except for `status`.
    #[arg(long)]
    access_token_file: Option<PathBuf>,

    /// Must match the owner-only record for every state-changing command.
    #[arg(long)]
    authorization_id: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Read one durable workflow without provider I/O.
    Status,
    /// Corroborate the wallet and build/validate one unsigned PSBT.
    Build,
    /// Verify one RIC and consume the durable redemption-leg one-shot.
    Authorize {
        /// Absolute durable custody replay `SQLite` path, distinct from workflow DB.
        #[arg(long)]
        replay_db: PathBuf,
        /// Absolute owner-only JSON `IntentProof` path.
        #[arg(long)]
        intent_proof: PathBuf,
    },
    /// Validate and retain a user-signed raw Bitcoin transaction; never signs.
    RecordUserSigned {
        /// Absolute owner-only file containing consensus transaction hex.
        #[arg(long)]
        transaction_hex: PathBuf,
    },
    /// Cross the `BitGo` final-sign-and-broadcast boundary, or reconcile a prior reservation.
    Submit {
        /// Must exactly equal the configured sequence ID.
        #[arg(long)]
        confirm_final_sign_and_broadcast: String,
    },
    /// Emit the canonical content-addressed workflow manifest.
    Manifest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeConfig {
    schema_version: u32,
    environment: EnvironmentConfig,
    auth_version: u8,
    wallet: WalletConfig,
    spend: SpendConfig,
    intent_verification: IntentVerificationConfig,
    authorization: AuthorizationConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum EnvironmentConfig {
    Test,
    Production,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletConfig {
    wallet_id: String,
    address_chain_code: u32,
    user_public_key: String,
    backup_public_key: String,
    bitgo_public_key: String,
    witness_script_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpendConfig {
    input_txid: String,
    input_vout: u32,
    input_value_sats: u64,
    payout_script_pubkey_hex: String,
    payout_sats: u64,
    memo_hex: String,
    max_fee_sats: u64,
    sequence_id: String,
    require_change: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentVerificationConfig {
    ethereum_chain_id: u64,
    attestation_oracle: String,
    signer_whitelist: Vec<String>,
    signer_quorum: usize,
    ric_max_age_secs: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationConfig {
    authorization_id: String,
    not_before_unix: u64,
    expires_at_unix: u64,
    max_loss_sats: u64,
    capabilities: Vec<Capability>,
}

struct ValidatedConfig {
    environment: BitGoEnvironment,
    auth_version: BitGoAuthVersion,
    policy: SpendPolicy,
    intent_policy: IntentPolicy,
    verifying_contract: EvmAddress,
    ethereum_chain_id: u64,
    authorization: AuthorizationConfig,
}

#[derive(Serialize)]
struct StatusOutput<'a> {
    result: &'static str,
    authorization_id: &'a str,
    sequence_id: &'a str,
    phase: &'static str,
    policy_commitment: String,
    authorization_valid_until_unix: Option<u64>,
    pending_approval_id: Option<&'a str>,
    transfer_id: Option<&'a str>,
    txid: Option<String>,
}

#[derive(Serialize)]
struct SubmitOutput<'a> {
    result: &'static str,
    sequence_id: &'a str,
    outcome: &'static str,
    provider_id: &'a str,
    txid: Option<String>,
    newly_recorded: Option<bool>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config: RuntimeConfig = read_owner_only_json(&args.config, MAX_CONFIG_BYTES, "config")?;
    let config = validate_config(config)?;
    preflight_command_authorization(&args, &config)?;
    validate_database_path(&args.workflow_db, matches!(&args.command, Command::Build))?;
    let workflow_url = sqlite_url(&args.workflow_db)?;
    let store = BitGoWorkflowStore::connect(&workflow_url)
        .await
        .context("open BitGo workflow database")?;
    validate_owner_only_file(&args.workflow_db, "workflow database")?;

    match &args.command {
        Command::Status => {
            let record = load_exact_policy(&store, &config.policy).await?;
            write_json(&status_output(&config, &record))?;
        }
        Command::Build => {
            let coordinator = coordinator(&args, &config, store)?;
            let record = coordinator.build(&config.policy).await?;
            write_json(&status_output(&config, &record))?;
        }
        Command::Authorize {
            replay_db,
            intent_proof,
        } => {
            validate_database_path(replay_db, true)?;
            if same_file(&args.workflow_db, replay_db)? {
                bail!("workflow and custody replay databases must be distinct");
            }
            let replay_url = sqlite_url(replay_db)?;
            let replay = SqliteReplayStore::connect(&replay_url)
                .await
                .context("open custody replay database")?;
            validate_owner_only_file(replay_db, "custody replay database")?;
            let proof: IntentProof =
                read_owner_only_json(intent_proof, MAX_INTENT_PROOF_BYTES, "intent proof")?;
            let coordinator = coordinator(&args, &config, store)?;
            let now = now_unix_i64()?;
            let custody = CustodyConfig {
                chain_id: config.ethereum_chain_id,
                verifying_contract: config.verifying_contract,
                intent_policy: &config.intent_policy,
            };
            let record = coordinator
                .authorize_redeem(&config.policy, &proof, &replay, custody, now)
                .await?;
            write_json(&status_output(&config, &record))?;
        }
        Command::RecordUserSigned { transaction_hex } => {
            let transaction = read_transaction_hex(transaction_hex)?;
            let coordinator = coordinator(&args, &config, store)?;
            let record = coordinator
                .record_user_signed(&config.policy, &transaction)
                .await?;
            write_json(&status_output(&config, &record))?;
        }
        Command::Submit { .. } => {
            let coordinator = coordinator(&args, &config, store)?;
            let outcome = coordinator.submit(&config.policy).await?;
            write_json(&submit_output(config.policy.sequence_id(), &outcome))?;
        }
        Command::Manifest => {
            let coordinator = coordinator(&args, &config, store)?;
            let manifest = coordinator.evidence_manifest(&config.policy).await?;
            write_json(&manifest)?;
        }
    }
    Ok(())
}

fn validate_config(config: RuntimeConfig) -> Result<ValidatedConfig> {
    if config.schema_version != CONFIG_SCHEMA_VERSION {
        bail!("unsupported BitGo custody config schema version");
    }
    if config.environment != EnvironmentConfig::Test {
        bail!("BitGo production/mainnet is disabled pending completed qualification and review");
    }
    let auth_version = match config.auth_version {
        2 => BitGoAuthVersion::V2,
        3 => BitGoAuthVersion::V3,
        _ => bail!("BitGo auth_version must be 2 or 3"),
    };
    if config.wallet.address_chain_code != P2WSH_EXTERNAL_CHAIN_CODE {
        bail!("BitGo wallet address_chain_code must be native-P2WSH code 20");
    }
    let user = parse_compressed_public_key(&config.wallet.user_public_key)?;
    let backup = parse_compressed_public_key(&config.wallet.backup_public_key)?;
    let bitgo = parse_compressed_public_key(&config.wallet.bitgo_public_key)?;
    let witness_script = ScriptBuf::from_bytes(decode_hex(
        &config.wallet.witness_script_hex,
        "wallet witness script",
    )?);
    let wallet = WalletPolicy::new(
        BitGoCoin::Tbtc4,
        config.wallet.wallet_id,
        config.wallet.address_chain_code,
        user,
        backup,
        bitgo,
        witness_script,
    )?;
    let input_txid = Txid::from_str(&config.spend.input_txid)
        .context("input_txid must be a Bitcoin transaction ID")?;
    let input = InputPolicy::new(
        OutPoint::new(input_txid, config.spend.input_vout),
        config.spend.input_value_sats,
    )?;
    let payout = ScriptBuf::from_bytes(decode_hex(
        &config.spend.payout_script_pubkey_hex,
        "payout scriptPubKey",
    )?);
    let memo = decode_hex(&config.spend.memo_hex, "THORChain memo")?;
    let policy = SpendPolicy::new(
        wallet,
        input,
        payout,
        config.spend.payout_sats,
        memo,
        config.spend.max_fee_sats,
        config.spend.sequence_id,
        config.spend.require_change,
    )?;
    let verifying_contract = EvmAddress::from_str(&config.intent_verification.attestation_oracle)
        .context("attestation_oracle must be an EVM address")?;
    if verifying_contract.is_zero() || config.intent_verification.ethereum_chain_id == 0 {
        bail!("intent verification domain cannot contain zero chain/address values");
    }
    let signer_whitelist = config
        .intent_verification
        .signer_whitelist
        .iter()
        .map(|value| EvmAddress::from_str(value).context("invalid intent signer address"))
        .collect::<Result<Vec<_>>>()?;
    let intent_policy = IntentPolicy {
        signer_whitelist,
        intent_quorum: config.intent_verification.signer_quorum,
        ric_max_age_secs: config.intent_verification.ric_max_age_secs,
    };
    intent_policy
        .validate()
        .map_err(anyhow::Error::msg)
        .context("invalid intent verification policy")?;
    validate_authorization_shape(&config.authorization, config.spend.input_value_sats)?;
    Ok(ValidatedConfig {
        environment: BitGoEnvironment::Test,
        auth_version,
        policy,
        intent_policy,
        verifying_contract,
        ethereum_chain_id: config.intent_verification.ethereum_chain_id,
        authorization: config.authorization,
    })
}

fn validate_authorization_shape(
    authorization: &AuthorizationConfig,
    input_value_sats: u64,
) -> Result<()> {
    if !safe_identifier(&authorization.authorization_id) {
        bail!("authorization_id must be path-safe ASCII");
    }
    if authorization.not_before_unix >= authorization.expires_at_unix {
        bail!("authorization time window is invalid");
    }
    if authorization.max_loss_sats == 0 || input_value_sats > authorization.max_loss_sats {
        bail!("selected input exceeds the written authorization loss cap");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Capability {
    Build,
    IntentAuthorization,
    UserSignedImport,
    FinalSignAndBroadcast,
}

fn preflight_command_authorization(args: &Args, config: &ValidatedConfig) -> Result<()> {
    let capability = match &args.command {
        Command::Status | Command::Manifest => return Ok(()),
        Command::Build => Capability::Build,
        Command::Authorize { .. } => Capability::IntentAuthorization,
        Command::RecordUserSigned { .. } => Capability::UserSignedImport,
        Command::Submit {
            confirm_final_sign_and_broadcast,
        } => {
            if confirm_final_sign_and_broadcast != config.policy.sequence_id() {
                bail!("final-sign-and-broadcast acknowledgement does not match sequence ID");
            }
            Capability::FinalSignAndBroadcast
        }
    };
    require_capability(config, args.authorization_id.as_deref(), capability)
}

fn require_capability(
    config: &ValidatedConfig,
    presented_authorization_id: Option<&str>,
    capability: Capability,
) -> Result<()> {
    let now = now_unix_u64()?;
    let authorization = &config.authorization;
    if presented_authorization_id != Some(authorization.authorization_id.as_str()) {
        bail!("--authorization-id must match the owner-only authorization record");
    }
    if now < authorization.not_before_unix || now > authorization.expires_at_unix {
        bail!("written BitGo authorization is outside its active time window");
    }
    if !authorization.capabilities.contains(&capability) {
        bail!("written BitGo authorization does not enable this capability");
    }
    Ok(())
}

fn coordinator(
    args: &Args,
    config: &ValidatedConfig,
    store: BitGoWorkflowStore,
) -> Result<BitGoCoordinator> {
    let token_path = args
        .access_token_file
        .as_deref()
        .context("--access-token-file is required for this command")?;
    let token = read_owner_only_bytes(token_path, MAX_TOKEN_BYTES, "access token")?;
    let token = std::str::from_utf8(&token).context("access token file must be UTF-8")?;
    let client = BitGoClient::new(
        config.environment,
        config.auth_version,
        token,
        HttpClientPolicy {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_mins(1),
            max_response_bytes: 1024 * 1024,
        },
    )?;
    Ok(BitGoCoordinator::new(client, store))
}

async fn load_exact_policy(
    store: &BitGoWorkflowStore,
    policy: &SpendPolicy,
) -> Result<WorkflowRecord> {
    let record = store.load(policy.sequence_id()).await?;
    if record.policy_commitment() != spend_policy_commitment(policy) {
        bail!("workflow policy commitment does not match configuration");
    }
    Ok(record)
}

fn read_transaction_hex(path: &Path) -> Result<Transaction> {
    let bytes = read_owner_only_bytes(path, MAX_TRANSACTION_HEX_BYTES, "signed transaction")?;
    let text = std::str::from_utf8(&bytes).context("signed transaction file must be UTF-8 hex")?;
    let raw = decode_hex(text.trim(), "signed transaction")?;
    deserialize(&raw).context("signed transaction is not canonical Bitcoin consensus data")
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty() || !value.len().is_multiple_of(2) {
        bail!("{label} must be non-empty even-length hex");
    }
    alloy_primitives::hex::decode(value).with_context(|| format!("{label} contains invalid hex"))
}

fn status_output<'a>(config: &'a ValidatedConfig, record: &'a WorkflowRecord) -> StatusOutput<'a> {
    StatusOutput {
        result: "ok",
        authorization_id: &config.authorization.authorization_id,
        sequence_id: record.sequence_id(),
        phase: phase_name(record.phase()),
        policy_commitment: alloy_primitives::hex::encode(record.policy_commitment()),
        authorization_valid_until_unix: record.authorization_valid_until_unix(),
        pending_approval_id: record.pending_approval_id(),
        transfer_id: record.transfer_id(),
        txid: record.txid().map(|txid| txid.to_string()),
    }
}

fn submit_output<'a>(sequence_id: &'a str, outcome: &'a SubmitOutcome) -> SubmitOutput<'a> {
    match outcome {
        SubmitOutcome::Broadcast {
            transfer_id,
            txid,
            newly_recorded,
        } => SubmitOutput {
            result: "ok",
            sequence_id,
            outcome: "broadcast",
            provider_id: transfer_id,
            txid: Some(txid.to_string()),
            newly_recorded: Some(*newly_recorded),
        },
        SubmitOutcome::PendingApproval {
            approval_id,
            newly_recorded,
        } => SubmitOutput {
            result: "ok",
            sequence_id,
            outcome: "pending_approval",
            provider_id: approval_id,
            txid: None,
            newly_recorded: Some(*newly_recorded),
        },
        SubmitOutcome::Rejected {
            approval_id,
            newly_recorded,
        } => SubmitOutput {
            result: "ok",
            sequence_id,
            outcome: "rejected",
            provider_id: approval_id,
            txid: None,
            newly_recorded: Some(*newly_recorded),
        },
        SubmitOutcome::ReconciliationRequired { transfer, .. } => SubmitOutput {
            result: "blocked",
            sequence_id,
            outcome: "reconciliation_required",
            provider_id: transfer.transfer_id(),
            txid: transfer.txid().map(str::to_owned),
            newly_recorded: None,
        },
    }
}

fn phase_name(phase: WorkflowPhase) -> &'static str {
    match phase {
        WorkflowPhase::BuildReserved => "build_reserved",
        WorkflowPhase::Built => "built",
        WorkflowPhase::IntentAuthorized => "intent_authorized",
        WorkflowPhase::UserSigned => "user_signed",
        WorkflowPhase::SendReserved => "send_reserved",
        WorkflowPhase::PendingApproval => "pending_approval",
        WorkflowPhase::Rejected => "rejected",
        WorkflowPhase::Broadcast => "broadcast",
    }
}

fn write_json<T: Serialize>(value: &T) -> Result<()> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    output.write_all(b"\n")?;
    Ok(())
}

fn read_owner_only_json<T: DeserializeOwned>(path: &Path, max: u64, label: &str) -> Result<T> {
    let bytes = read_owner_only_bytes(path, max, label)?;
    serde_json::from_slice(&bytes).with_context(|| format!("decode {label} JSON"))
}

fn read_owner_only_bytes(path: &Path, max: u64, label: &str) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        bail!("{label} path must be absolute");
    }
    let before = validate_owner_only_file(path, label)?;
    if before.len() > max {
        bail!("{label} exceeds its byte limit");
    }
    let file = File::open(path).with_context(|| format!("open {label}"))?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect open {label}"))?;
    ensure_same_file(&before, &opened, label)?;
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max {
        bail!("{label} exceeds its byte limit");
    }
    Ok(bytes)
}

fn validate_database_path(path: &Path, create: bool) -> Result<()> {
    if !path.is_absolute() {
        bail!("database path must be absolute");
    }
    let parent = path.parent().context("database path has no parent")?;
    validate_owner_only_directory(parent, "database parent")?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_owner_only_file(path, "database")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
            create_owner_only_file(path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!("database does not exist; only the build command may create the workflow DB");
        }
        Err(error) => return Err(error).context("inspect database path"),
    }
    Ok(())
}

#[cfg(unix)]
fn create_owner_only_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .context("create owner-only database")?;
    Ok(())
}

#[cfg(not(unix))]
fn create_owner_only_file(_path: &Path) -> Result<()> {
    bail!("BitGo custody runtime requires Unix owner-only file semantics")
}

fn sqlite_url(path: &Path) -> Result<String> {
    let path = path.to_str().context("database path must be valid UTF-8")?;
    if path.bytes().any(|byte| matches!(byte, b'?' | b'#' | b'%')) {
        bail!("database path contains URL-reserved characters");
    }
    Ok(format!("sqlite://{path}"))
}

#[cfg(unix)]
fn same_file(left: &Path, right: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let left = fs::metadata(left).context("inspect workflow database identity")?;
    let right = fs::metadata(right).context("inspect custody replay database identity")?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(not(unix))]
fn same_file(_left: &Path, _right: &Path) -> Result<bool> {
    bail!("BitGo custody runtime requires Unix file identity semantics")
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn now_unix_u64() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")
        .map(|duration| duration.as_secs())
}

fn now_unix_i64() -> Result<i64> {
    i64::try_from(now_unix_u64()?).context("Unix time exceeds signed range")
}

#[cfg(unix)]
fn validate_owner_only_file(path: &Path, label: &str) -> Result<fs::Metadata> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        bail!("{label} must be an owner-only regular file with one hard link");
    }
    Ok(metadata)
}

#[cfg(not(unix))]
fn validate_owner_only_file(_path: &Path, _label: &str) -> Result<fs::Metadata> {
    bail!("BitGo custody runtime requires Unix owner-only file semantics")
}

#[cfg(unix)]
fn validate_owner_only_directory(path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        bail!("{label} must be an owner-only directory");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_only_directory(_path: &Path, _label: &str) -> Result<()> {
    bail!("BitGo custody runtime requires Unix owner-only directory semantics")
}

#[cfg(unix)]
fn ensure_same_file(before: &fs::Metadata, opened: &fs::Metadata, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        bail!("{label} changed while opening");
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_same_file(_before: &fs::Metadata, _opened: &fs::Metadata, _label: &str) -> Result<()> {
    bail!("BitGo custody runtime requires Unix owner-only file semantics")
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use super::*;

    const USER_PUBKEY: &str = "03c10ac628c880629ed0fd2a0563a898f4882baca45e15668a4d3064cf1ea37988";
    const BACKUP_PUBKEY: &str =
        "03e56f84be4460080618ef869bb7b07096880760f748ba23efab533c2359f923bd";
    const BITGO_PUBKEY: &str = "020ae81372264b5eac5c9dc7fe0b9a32bad00771c3a2c71f6e2c971823c3182ed6";

    fn config(environment: EnvironmentConfig) -> RuntimeConfig {
        let keys = [USER_PUBKEY, BACKUP_PUBKEY, BITGO_PUBKEY]
            .into_iter()
            .map(|value| parse_compressed_public_key(value).expect("key"))
            .collect::<Vec<_>>();
        let witness_script = bitcoin::script::Builder::new()
            .push_int(2)
            .push_key(&keys[0])
            .push_key(&keys[1])
            .push_key(&keys[2])
            .push_int(3)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
            .into_script();
        let payout = bitcoin::Address::p2wpkh(
            &bitcoin::CompressedPublicKey(keys[0].inner),
            bitcoin::Network::Testnet,
        )
        .script_pubkey();
        RuntimeConfig {
            schema_version: CONFIG_SCHEMA_VERSION,
            environment,
            auth_version: 2,
            wallet: WalletConfig {
                wallet_id: "wallet-1".to_owned(),
                address_chain_code: P2WSH_EXTERNAL_CHAIN_CODE,
                user_public_key: USER_PUBKEY.to_owned(),
                backup_public_key: BACKUP_PUBKEY.to_owned(),
                bitgo_public_key: BITGO_PUBKEY.to_owned(),
                witness_script_hex: alloy_primitives::hex::encode(witness_script.as_bytes()),
            },
            spend: SpendConfig {
                input_txid: "11".repeat(32),
                input_vout: 0,
                input_value_sats: 200_000,
                payout_script_pubkey_hex: alloy_primitives::hex::encode(payout.as_bytes()),
                payout_sats: 100_000,
                memo_hex: alloy_primitives::hex::encode(b"=:BTC.BTC:tb1qexample"),
                max_fee_sats: 2_000,
                sequence_id: "xindex-redemption-1".to_owned(),
                require_change: true,
            },
            intent_verification: IntentVerificationConfig {
                ethereum_chain_id: 11_155_111,
                attestation_oracle: "0x1111111111111111111111111111111111111111".to_owned(),
                signer_whitelist: vec![
                    "0x2222222222222222222222222222222222222222".to_owned(),
                    "0x3333333333333333333333333333333333333333".to_owned(),
                    "0x4444444444444444444444444444444444444444".to_owned(),
                ],
                signer_quorum: 2,
                ric_max_age_secs: 900,
            },
            authorization: AuthorizationConfig {
                authorization_id: "auth-1".to_owned(),
                not_before_unix: 1,
                expires_at_unix: u64::MAX,
                max_loss_sats: 200_000,
                capabilities: Vec::new(),
            },
        }
    }

    #[test]
    fn testnet_config_builds_exact_policy_but_capabilities_default_closed() {
        let config = validate_config(config(EnvironmentConfig::Test)).expect("test config");
        assert_eq!(config.policy.sequence_id(), "xindex-redemption-1");
        assert_eq!(config.policy.wallet().coin(), BitGoCoin::Tbtc4);
        assert!(require_capability(&config, Some("auth-1"), Capability::Build).is_err());
        assert!(
            require_capability(&config, Some("auth-1"), Capability::FinalSignAndBroadcast).is_err()
        );
    }

    #[test]
    fn production_environment_is_not_activatable() {
        let result = validate_config(config(EnvironmentConfig::Production));
        assert!(result.is_err());
    }

    #[test]
    fn loss_cap_below_selected_input_is_rejected() {
        let mut value = config(EnvironmentConfig::Test);
        value.authorization.max_loss_sats = value.spend.input_value_sats - 1;
        assert!(validate_config(value).is_err());
    }

    #[test]
    fn database_identity_rejects_lexical_aliases() {
        let root = std::env::current_dir().expect("current directory");
        let direct = root.join("Cargo.toml");
        let alias = root.join("src").join("..").join("Cargo.toml");
        assert!(same_file(&direct, &alias).expect("file identity"));
    }
}
