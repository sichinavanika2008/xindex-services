//! Strict, offline structural validator for a Gate-4 rehearsal bundle.
//!
//! The checker contacts no chain, signer, or custody provider. It validates an
//! owner-only evidence manifest, the exact `BitGo` qualification report, every
//! referenced artifact hash, the independent 3-of-5 observation topology, the
//! `BitGo` self-custody on-chain 2-of-3 topology, and the complete drill
//! inventory. It cannot authenticate the origin of caller-supplied evidence,
//! reviewer identities, provider claims, or Git commits. Consequently, valid
//! input is reported as `format_valid` and exits blocked; this binary cannot
//! produce a Gate-4 pass until independently pinned provenance is implemented.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use axum::http::Uri;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const GATE_SCHEMA_VERSION: u32 = 1;
const BITGO_REPORT_SCHEMA_VERSION: u64 = 1;
const BITGO_REPORT_SCOPE: &str = "development compatibility only; never production approval";

const REQUIRED_DRILLS: [&str; 23] = [
    "G4-MINT-HAPPY",
    "G4-REDEEM-HAPPY",
    "G4-RECOVERY-CONTROLLED",
    "G4-ORACLE-DIVERGENCE",
    "G4-ORACLE-STALE",
    "G4-SEQUENCER-OUTAGE",
    "G4-SIGNER-LOSS",
    "G4-SIGNER-COMPROMISE",
    "G4-THOR-HALT",
    "G4-VAULT-ROTATION",
    "G4-ROUTER-ROTATION",
    "G4-STREAM-PARTIAL",
    "G4-REFUND-FULL",
    "G4-DELAYED-INCLUSION",
    "G4-EMERGENCY-PAUSE",
    "G4-CHALLENGE-INVALIDATION",
    "G4-BITGO-BACKUP-RECOVERY",
    "G4-BITGO-APPROVAL-OUTAGE",
    "G4-BITGO-TAMPER-REJECT",
    "G4-CTD-FORGED-DESTINATION",
    "G4-REPLAY-EQUIVOCATION",
    "G4-VOLUME-CAP",
    "G4-ALERT-WORM",
];

const BITGO_CHECKS: [&str; 11] = [
    "identity",
    "wallet_topology",
    "expected_transaction",
    "build_request",
    "unsigned_psbt",
    "inputs",
    "thorchain_layout",
    "fee",
    "user_signature_preservation",
    "bitgo_cosign_preservation",
    "live_corroboration",
];

const NEGATIVE_CUSTODY_DRILLS: [&str; 8] = [
    "G4-SIGNER-COMPROMISE",
    "G4-THOR-HALT",
    "G4-BITGO-APPROVAL-OUTAGE",
    "G4-BITGO-TAMPER-REJECT",
    "G4-CTD-FORGED-DESTINATION",
    "G4-REPLAY-EQUIVOCATION",
    "G4-VOLUME-CAP",
    "G4-EMERGENCY-PAUSE",
];

const POSITIVE_CUSTODY_DRILLS: [&str; 3] = [
    "G4-REDEEM-HAPPY",
    "G4-STREAM-PARTIAL",
    "G4-BITGO-BACKUP-RECOVERY",
];

const BITGO_DRILLS: [&str; 5] = [
    "G4-BITGO-BACKUP-RECOVERY",
    "G4-BITGO-APPROVAL-OUTAGE",
    "G4-BITGO-TAMPER-REJECT",
    "G4-CTD-FORGED-DESTINATION",
    "G4-REPLAY-EQUIVOCATION",
];

const BITGO_PROVIDER_DRILLS: [&str; 4] = [
    "G4-BITGO-APPROVAL-OUTAGE",
    "G4-BITGO-TAMPER-REJECT",
    "G4-CTD-FORGED-DESTINATION",
    "G4-REPLAY-EQUIVOCATION",
];

#[derive(Debug, Error)]
enum Gate4Error {
    #[error("Gate-4 evidence JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Gate-4 evidence is invalid:\n{0}")]
    Invalid(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gate4Evidence {
    schema_version: u32,
    gate: String,
    environment: String,
    protocol_commit: String,
    services_commit: String,
    started_at_utc: String,
    completed_at_utc: String,
    reviewers: Vec<String>,
    authorization: Artifact,
    bitgo_qualification: BitGoQualification,
    topology: Gate4Topology,
    drills: Vec<Drill>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BitGoQualification {
    report_sha256: String,
    evidence: Artifact,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gate4Topology {
    observation_certification: ObservationTopology,
    custody: CustodyTopology,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationTopology {
    threshold: usize,
    participants: usize,
    members: Vec<ObservationMember>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationMember {
    operator_id: String,
    admin_domain: String,
    infrastructure_domain: String,
    rpc_failure_domain: String,
    certification_pubkey_sha256: String,
    thornode_origins: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyTopology {
    threshold: usize,
    participants: usize,
    provider: String,
    network: String,
    address_type: String,
    wallet_id: String,
    wallet_keyset_sha256: String,
    members: Vec<CustodyMember>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyMember {
    holder_type: String,
    signer_role: String,
    key_id_sha256: String,
    operator_id: String,
    admin_domain: String,
    failure_domain: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Drill {
    id: String,
    status: String,
    started_at_utc: String,
    completed_at_utc: String,
    operators: Vec<String>,
    expected: String,
    observed: String,
    response_time_ms: u64,
    response_time_budget_ms: u64,
    custody_signature_created: bool,
    custody_broadcast_created: bool,
    external_evidence: Vec<ExternalEvidence>,
    artifacts: Vec<Artifact>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalEvidence {
    kind: String,
    environment: String,
    id: String,
    verified: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: String,
    sha256: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct Gate4Summary {
    schema_version: u32,
    gate: &'static str,
    environment: String,
    overall: &'static str,
    protocol_commit: String,
    services_commit: String,
    reviewer_count: usize,
    drill_count: usize,
    artifact_count: usize,
    bitgo_report_sha256: String,
    artifact_inventory_sha256: String,
}

fn run() -> Result<Gate4Summary> {
    let mut args = std::env::args().skip(1);
    let evidence_path = args.next().context(
        "usage: xindex-gate4-check <owner-only-gate4.json> <owner-only-bitgo-report.json>",
    )?;
    let bitgo_path = args.next().context(
        "usage: xindex-gate4-check <owner-only-gate4.json> <owner-only-bitgo-report.json>",
    )?;
    if args.next().is_some() {
        anyhow::bail!("xindex-gate4-check accepts exactly two paths");
    }

    let evidence_path = Path::new(&evidence_path);
    let bitgo_path = Path::new(&bitgo_path);
    let evidence_bytes = read_owner_only(evidence_path, "Gate-4 evidence manifest")?;
    let bitgo_bytes = read_owner_only(bitgo_path, "BitGo qualification report")?;
    let evidence: Gate4Evidence = serde_json::from_slice(&evidence_bytes)?;
    let artifact_hashes = hash_artifacts(&evidence)?;
    Ok(validate_gate4(evidence, &bitgo_bytes, &artifact_hashes)?)
}

fn write_summary(summary: &Gate4Summary) -> Result<()> {
    writeln!(
        std::io::stdout().lock(),
        "{}",
        serde_json::to_string_pretty(summary)?
    )?;
    Ok(())
}

fn main() -> ExitCode {
    match run().and_then(|summary| write_summary(&summary)) {
        Ok(()) => ExitCode::from(2),
        Err(error) => {
            let _ = writeln!(std::io::stderr().lock(), "xindex-gate4-check: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn validate_gate4(
    evidence: Gate4Evidence,
    bitgo_bytes: &[u8],
    artifact_hashes: &HashMap<String, String>,
) -> std::result::Result<Gate4Summary, Gate4Error> {
    let mut errors = Vec::new();
    validate_header(&evidence, &mut errors);
    let allowed_operators = validate_topology(&evidence.topology, &mut errors);
    for reviewer in &evidence.reviewers {
        if allowed_operators.contains(&normalize(reviewer)) {
            errors.push(format!(
                "reviewer {reviewer} must be independent from every Gate-4 operator"
            ));
        }
    }
    validate_bitgo_report(
        &evidence.bitgo_qualification,
        &evidence.topology.custody.wallet_id,
        bitgo_bytes,
        &mut errors,
    )?;
    let artifact_count = validate_artifacts(&evidence, artifact_hashes, &mut errors);
    validate_drills(&evidence.drills, &allowed_operators, &mut errors);
    if !errors.is_empty() {
        return Err(Gate4Error::Invalid(errors.join("\n")));
    }
    Ok(Gate4Summary {
        schema_version: evidence.schema_version,
        gate: "XINDEX_GATE_4",
        environment: evidence.environment,
        overall: "format_valid",
        protocol_commit: evidence.protocol_commit,
        services_commit: evidence.services_commit,
        reviewer_count: evidence.reviewers.len(),
        drill_count: evidence.drills.len(),
        artifact_count,
        bitgo_report_sha256: sha256_hex(bitgo_bytes),
        artifact_inventory_sha256: artifact_inventory_hash(artifact_hashes),
    })
}

fn validate_header(evidence: &Gate4Evidence, errors: &mut Vec<String>) {
    if evidence.schema_version != GATE_SCHEMA_VERSION {
        errors.push(format!("schema_version must equal {GATE_SCHEMA_VERSION}"));
    }
    if evidence.gate != "XINDEX_GATE_4" {
        errors.push("gate must equal XINDEX_GATE_4".to_string());
    }
    if evidence.environment != "sepolia+thorchain-devnet+btc-testnet4" {
        errors.push("environment must equal sepolia+thorchain-devnet+btc-testnet4".to_string());
    }
    validate_commit("protocol_commit", &evidence.protocol_commit, errors);
    validate_commit("services_commit", &evidence.services_commit, errors);
    validate_time_range(
        "Gate-4",
        &evidence.started_at_utc,
        &evidence.completed_at_utc,
        errors,
    );
    validate_distinct_public_values("reviewers", &evidence.reviewers, 2, errors);
}

fn validate_topology(topology: &Gate4Topology, errors: &mut Vec<String>) -> HashSet<String> {
    let observation = validate_observation_topology(&topology.observation_certification, errors);
    let custody = validate_custody_topology(&topology.custody, errors);
    for operator in observation.intersection(&custody) {
        errors.push(format!(
            "operator {operator} is reused across observation and custody trust domains"
        ));
    }
    observation.union(&custody).cloned().collect()
}

fn validate_observation_topology(
    topology: &ObservationTopology,
    errors: &mut Vec<String>,
) -> HashSet<String> {
    if topology.threshold != 3 || topology.participants != 5 || topology.members.len() != 5 {
        errors.push(
            "observation_certification must contain exactly five members with threshold 3"
                .to_string(),
        );
    }
    let mut operators = HashSet::new();
    let mut admins = HashSet::new();
    let mut infrastructure = HashSet::new();
    let mut rpc_domains = HashSet::new();
    let mut keys = HashSet::new();
    for member in &topology.members {
        insert_unique_public(
            "observation operator_id",
            &member.operator_id,
            &mut operators,
            errors,
        );
        insert_unique_public(
            "observation admin_domain",
            &member.admin_domain,
            &mut admins,
            errors,
        );
        insert_unique_public(
            "observation infrastructure_domain",
            &member.infrastructure_domain,
            &mut infrastructure,
            errors,
        );
        insert_unique_public(
            "observation rpc_failure_domain",
            &member.rpc_failure_domain,
            &mut rpc_domains,
            errors,
        );
        if !valid_sha256(&member.certification_pubkey_sha256)
            || !keys.insert(normalize(&member.certification_pubkey_sha256))
        {
            errors.push(format!(
                "operator {} has an invalid or reused certification_pubkey_sha256",
                member.operator_id
            ));
        }
        if member.thornode_origins.len() < 2 {
            errors.push(format!(
                "operator {} requires at least two THORNode origins",
                member.operator_id
            ));
        }
        let mut origins = HashSet::new();
        for origin in &member.thornode_origins {
            if !is_https_origin(origin) || !origins.insert(normalize(origin)) {
                errors.push(format!(
                    "operator {} has an invalid or duplicate THORNode origin",
                    member.operator_id
                ));
            }
        }
    }
    operators
}

fn validate_custody_topology(
    topology: &CustodyTopology,
    errors: &mut Vec<String>,
) -> HashSet<String> {
    if topology.threshold != 2 || topology.participants != 3 || topology.members.len() != 3 {
        errors.push("custody must contain exactly three holders with threshold 2".to_string());
    }
    if topology.provider != "bitgo"
        || topology.network != "bitcoin-testnet4"
        || topology.address_type != "p2wsh"
    {
        errors.push(
            "custody must pin provider=bitgo, network=bitcoin-testnet4 and address_type=p2wsh"
                .to_string(),
        );
    }
    validate_public_value("custody.wallet_id", &topology.wallet_id, errors);
    if !valid_sha256(&topology.wallet_keyset_sha256) {
        errors.push("custody.wallet_keyset_sha256 must be a 64-character SHA-256".to_string());
    }

    let mut key_ids = HashSet::new();
    let mut operators = HashSet::new();
    let mut admins = HashSet::new();
    let mut failures = HashSet::new();
    let mut holders = HashSet::new();
    let mut normal = 0;
    let mut recovery = 0;
    for member in &topology.members {
        if !valid_sha256(&member.key_id_sha256) || !key_ids.insert(normalize(&member.key_id_sha256))
        {
            errors.push(format!(
                "custody holder {} has an invalid or reused key_id_sha256",
                member.holder_type
            ));
        }
        insert_unique_public(
            "custody operator_id",
            &member.operator_id,
            &mut operators,
            errors,
        );
        insert_unique_public(
            "custody admin_domain",
            &member.admin_domain,
            &mut admins,
            errors,
        );
        insert_unique_public(
            "custody failure_domain",
            &member.failure_domain,
            &mut failures,
            errors,
        );
        if !["user", "backup", "bitgo"].contains(&member.holder_type.as_str())
            || !holders.insert(member.holder_type.as_str())
        {
            errors.push(format!(
                "custody has unsupported or duplicate holder_type {}",
                member.holder_type
            ));
        }
        match member.signer_role.as_str() {
            "normal" => normal += 1,
            "recovery" => recovery += 1,
            _ => errors.push(format!(
                "holder {} signer_role must be normal or recovery",
                member.holder_type
            )),
        }
        if (member.holder_type == "user" || member.holder_type == "bitgo")
            && member.signer_role != "normal"
        {
            errors.push(format!(
                "{} holder must have signer_role=normal",
                member.holder_type
            ));
        }
        if member.holder_type == "backup" && member.signer_role != "recovery" {
            errors.push("backup holder must have signer_role=recovery".to_string());
        }
    }
    if holders.len() != 3 || normal != 2 || recovery != 1 {
        errors.push(
            "custody must be one normal user holder, one recovery backup holder and one normal BitGo holder"
                .to_string(),
        );
    }
    operators
}

fn validate_bitgo_report(
    qualification: &BitGoQualification,
    wallet_id: &str,
    bytes: &[u8],
    errors: &mut Vec<String>,
) -> std::result::Result<(), Gate4Error> {
    if !valid_sha256(&qualification.report_sha256)
        || normalize(&qualification.report_sha256) != sha256_hex(bytes)
    {
        errors.push("BitGo qualification report SHA-256 does not match".to_string());
    }
    if !valid_sha256(&qualification.evidence.sha256) {
        errors.push("BitGo qualification evidence SHA-256 is malformed".to_string());
    }
    let report: Value = serde_json::from_slice(bytes)?;
    require_json_value(
        &report,
        "schema_version",
        &Value::from(BITGO_REPORT_SCHEMA_VERSION),
        errors,
    );
    require_json_string(&report, "provider", "bitgo", errors);
    require_json_string(&report, "environment", "test", errors);
    require_json_string(&report, "coin", "tbtc4", errors);
    require_json_string(&report, "wallet_id", wallet_id, errors);
    require_json_string(&report, "scope", BITGO_REPORT_SCOPE, errors);
    require_json_string(&report, "overall", "pass", errors);
    if report
        .get("evidence_sha256")
        .and_then(Value::as_str)
        .map(normalize)
        != Some(normalize(&qualification.evidence.sha256))
    {
        errors.push("BitGo report does not bind the recorded evidence_sha256".to_string());
    }
    validate_bitgo_checks(&report, errors);
    Ok(())
}

fn validate_bitgo_checks(report: &Value, errors: &mut Vec<String>) {
    let Some(checks) = report.get("checks").and_then(Value::as_array) else {
        errors.push("BitGo report has no checks array".to_string());
        return;
    };
    let mut by_id = HashMap::new();
    for check in checks {
        let Some(id) = check.get("id").and_then(Value::as_str) else {
            errors.push("BitGo report contains a check without an id".to_string());
            continue;
        };
        if by_id.insert(id, check).is_some() {
            errors.push(format!("BitGo report contains duplicate check {id}"));
        }
    }
    for id in BITGO_CHECKS {
        match by_id.get(id) {
            Some(check)
                if check.get("required").and_then(Value::as_bool) == Some(true)
                    && check.get("status").and_then(Value::as_str) == Some("pass") => {}
            _ => errors.push(format!(
                "BitGo qualification check {id} is not required/pass"
            )),
        }
    }
    if by_id.len() != BITGO_CHECKS.len() {
        errors.push("BitGo report check inventory is not the exact required set".to_string());
    }
}

fn validate_artifacts(
    evidence: &Gate4Evidence,
    actual: &HashMap<String, String>,
    errors: &mut Vec<String>,
) -> usize {
    let mut declared_paths = HashSet::new();
    let mut declared_hashes = HashSet::new();
    for artifact in std::iter::once(&evidence.authorization)
        .chain(std::iter::once(&evidence.bitgo_qualification.evidence))
        .chain(
            evidence
                .drills
                .iter()
                .flat_map(|drill| drill.artifacts.iter()),
        )
    {
        let path = Path::new(&artifact.path);
        if !path.is_absolute() || is_placeholder(&artifact.path) {
            errors.push(format!(
                "artifact path must be absolute and non-placeholder: {}",
                artifact.path
            ));
        }
        if !declared_paths.insert(artifact.path.clone()) {
            errors.push(format!("artifact path is reused: {}", artifact.path));
        }
        if !valid_sha256(&artifact.sha256) || !declared_hashes.insert(normalize(&artifact.sha256)) {
            errors.push(format!(
                "artifact has an invalid or reused SHA-256: {}",
                artifact.path
            ));
        }
        match actual.get(&artifact.path) {
            Some(hash) if normalize(hash) == normalize(&artifact.sha256) => {}
            _ => errors.push(format!("artifact SHA-256 mismatch: {}", artifact.path)),
        }
    }
    declared_paths.len()
}

fn validate_drills(
    drills: &[Drill],
    allowed_operators: &HashSet<String>,
    errors: &mut Vec<String>,
) {
    let required = REQUIRED_DRILLS.into_iter().collect::<HashSet<_>>();
    let mut seen = HashSet::new();
    for drill in drills {
        if !required.contains(drill.id.as_str()) {
            errors.push(format!("unknown Gate-4 drill id {}", drill.id));
            continue;
        }
        if !seen.insert(drill.id.as_str()) {
            errors.push(format!("duplicate Gate-4 drill id {}", drill.id));
        }
        validate_drill(drill, allowed_operators, errors);
    }
    for id in REQUIRED_DRILLS {
        if !seen.contains(id) {
            errors.push(format!("required Gate-4 drill {id} is missing"));
        }
    }
}

fn validate_drill(drill: &Drill, allowed_operators: &HashSet<String>, errors: &mut Vec<String>) {
    if drill.status != "pass" {
        errors.push(format!("drill {} status is not pass", drill.id));
    }
    validate_time_range(
        &format!("drill {}", drill.id),
        &drill.started_at_utc,
        &drill.completed_at_utc,
        errors,
    );
    let min_operators = if BITGO_DRILLS.contains(&drill.id.as_str()) {
        2
    } else {
        3
    };
    validate_distinct_public_values(
        &format!("drill {} operators", drill.id),
        &drill.operators,
        min_operators,
        errors,
    );
    for operator in &drill.operators {
        if !allowed_operators.contains(&normalize(operator)) {
            errors.push(format!(
                "drill {} references unknown operator {operator}",
                drill.id
            ));
        }
    }
    for (field, value) in [("expected", &drill.expected), ("observed", &drill.observed)] {
        if value.trim().len() < 16 || is_placeholder(value) {
            errors.push(format!(
                "drill {} has inadequate {field} evidence",
                drill.id
            ));
        }
    }
    if drill.response_time_ms == 0
        || drill.response_time_budget_ms == 0
        || drill.response_time_ms > drill.response_time_budget_ms
    {
        errors.push(format!(
            "drill {} exceeded or omitted its operator response-time budget",
            drill.id
        ));
    }
    if drill.artifacts.len() < 2 {
        errors.push(format!(
            "drill {} requires at least a transcript and independent log artifact",
            drill.id
        ));
    }
    validate_external_evidence(drill, errors);
    if NEGATIVE_CUSTODY_DRILLS.contains(&drill.id.as_str())
        && (drill.custody_signature_created || drill.custody_broadcast_created)
    {
        errors.push(format!(
            "negative drill {} produced a custody signature or broadcast",
            drill.id
        ));
    }
    if POSITIVE_CUSTODY_DRILLS.contains(&drill.id.as_str())
        && (!drill.custody_signature_created || !drill.custody_broadcast_created)
    {
        errors.push(format!(
            "positive custody drill {} lacks a signature or broadcast",
            drill.id
        ));
    }
}

fn validate_external_evidence(drill: &Drill, errors: &mut Vec<String>) {
    if drill.external_evidence.is_empty() {
        errors.push(format!("drill {} has no external evidence", drill.id));
        return;
    }
    let mut identities = HashSet::new();
    let allowed_kinds = [
        "transaction",
        "callback",
        "block",
        "provider_request",
        "alert",
        "worm_record",
        "operator_log",
        "ceremony_record",
    ];
    for item in &drill.external_evidence {
        if !allowed_kinds.contains(&item.kind.as_str()) {
            errors.push(format!(
                "drill {} has unsupported external evidence kind {}",
                drill.id, item.kind
            ));
        }
        if is_placeholder(&item.environment) || is_placeholder(&item.id) || !item.verified {
            errors.push(format!(
                "drill {} contains unverified or placeholder external evidence",
                drill.id
            ));
        }
        if !identities.insert(format!(
            "{}:{}:{}",
            normalize(&item.kind),
            normalize(&item.environment),
            normalize(&item.id)
        )) {
            errors.push(format!("drill {} repeats external evidence", drill.id));
        }
    }
    if [
        "G4-MINT-HAPPY",
        "G4-REDEEM-HAPPY",
        "G4-STREAM-PARTIAL",
        "G4-REFUND-FULL",
    ]
    .contains(&drill.id.as_str())
        && !drill
            .external_evidence
            .iter()
            .any(|item| item.kind == "transaction" && item.verified)
    {
        errors.push(format!(
            "drill {} requires a verified transaction",
            drill.id
        ));
    }
    if BITGO_PROVIDER_DRILLS.contains(&drill.id.as_str())
        && !drill
            .external_evidence
            .iter()
            .any(|item| item.kind == "provider_request" && item.verified)
    {
        errors.push(format!(
            "drill {} requires verified BitGo provider-request evidence",
            drill.id
        ));
    }
    if drill.id == "G4-BITGO-BACKUP-RECOVERY" {
        for kind in ["ceremony_record", "transaction"] {
            if !drill
                .external_evidence
                .iter()
                .any(|item| item.kind == kind && item.verified)
            {
                errors.push(format!(
                    "G4-BITGO-BACKUP-RECOVERY requires verified {kind} evidence"
                ));
            }
        }
    }
    if drill.id == "G4-ALERT-WORM" {
        for kind in ["alert", "worm_record"] {
            if !drill
                .external_evidence
                .iter()
                .any(|item| item.kind == kind && item.verified)
            {
                errors.push(format!("G4-ALERT-WORM requires verified {kind} evidence"));
            }
        }
    }
}

fn hash_artifacts(evidence: &Gate4Evidence) -> Result<HashMap<String, String>> {
    let mut hashes = HashMap::new();
    for artifact in std::iter::once(&evidence.authorization)
        .chain(std::iter::once(&evidence.bitgo_qualification.evidence))
        .chain(
            evidence
                .drills
                .iter()
                .flat_map(|drill| drill.artifacts.iter()),
        )
    {
        let path = PathBuf::from(&artifact.path);
        let bytes = read_owner_only(&path, "Gate-4 artifact")?;
        hashes.insert(artifact.path.clone(), sha256_hex(&bytes));
    }
    Ok(hashes)
}

fn read_owner_only(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} at {}", path.display()))?;
    if !path.is_absolute() || !metadata.file_type().is_file() {
        anyhow::bail!("{label} must be an absolute non-symlink regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            anyhow::bail!("{label} must be owner-only (mode 0600) and single-link");
        }
    }
    fs::read(path).with_context(|| format!("read {label} at {}", path.display()))
}

fn validate_commit(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.len() != 40
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().all(|byte| byte == b'0')
    {
        errors.push(format!(
            "{field} must be a non-zero 40-character Git commit"
        ));
    }
}

fn validate_time_range(label: &str, start: &str, end: &str, errors: &mut Vec<String>) {
    if !looks_like_utc_timestamp(start) || !looks_like_utc_timestamp(end) || start >= end {
        errors.push(format!(
            "{label} must have ordered, non-placeholder UTC timestamps"
        ));
    }
}

fn validate_distinct_public_values(
    field: &str,
    values: &[String],
    required: usize,
    errors: &mut Vec<String>,
) {
    let mut distinct = HashSet::new();
    for value in values {
        if is_placeholder(value) || !distinct.insert(normalize(value)) {
            errors.push(format!("{field} contains a placeholder or duplicate value"));
        }
    }
    if distinct.len() < required {
        errors.push(format!(
            "{field} requires at least {required} distinct values"
        ));
    }
}

fn insert_unique_public(
    field: &str,
    value: &str,
    values: &mut HashSet<String>,
    errors: &mut Vec<String>,
) {
    if is_placeholder(value) || !values.insert(normalize(value)) {
        errors.push(format!("{field} is a placeholder or reused: {value}"));
    }
}

fn validate_public_value(field: &str, value: &str, errors: &mut Vec<String>) {
    if is_placeholder(value) {
        errors.push(format!("{field} is empty or a placeholder"));
    }
}

fn require_json_string(report: &Value, field: &str, expected: &str, errors: &mut Vec<String>) {
    if report.get(field).and_then(Value::as_str) != Some(expected) {
        errors.push(format!("BitGo report {field} must equal {expected}"));
    }
}

fn require_json_value(report: &Value, field: &str, expected: &Value, errors: &mut Vec<String>) {
    if report.get(field) != Some(expected) {
        errors.push(format!("BitGo report {field} is invalid"));
    }
}

fn artifact_inventory_hash(hashes: &HashMap<String, String>) -> String {
    let mut entries = hashes.iter().collect::<Vec<_>>();
    entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
    let mut digest = Sha256::new();
    for (path, hash) in entries {
        digest.update(path.as_bytes());
        digest.update([0]);
        digest.update(hash.as_bytes());
        digest.update([b'\n']);
    }
    format!("{:x}", digest.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_sha256(value: &str) -> bool {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_https_origin(value: &str) -> bool {
    value
        .parse::<Uri>()
        .ok()
        .is_some_and(|uri| uri.scheme_str() == Some("https") && uri.authority().is_some())
}

fn looks_like_utc_timestamp(value: &str) -> bool {
    value.len() >= 20
        && value.ends_with('Z')
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value.as_bytes().get(10) == Some(&b'T')
        && value.as_bytes().get(13) == Some(&b':')
        && value.as_bytes().get(16) == Some(&b':')
        && !is_placeholder(value)
}

fn is_placeholder(value: &str) -> bool {
    let normalized = normalize(value);
    normalized.is_empty()
        || normalized
            .chars()
            .all(|character| matches!(character, '_' | '-' | '.'))
        || [
            "tbd",
            "todo",
            "unknown",
            "changeme",
            "placeholder",
            "replace",
            "example",
        ]
        .iter()
        .any(|marker| {
            normalized == *marker
                || normalized.starts_with(&format!("{marker}-"))
                || normalized.starts_with(&format!("{marker}_"))
        })
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "strict synthetic Gate-4 fixtures")]

    use serde_json::json;

    use super::*;

    fn bitgo_report(evidence_hash: &str) -> Value {
        let checks = BITGO_CHECKS
            .into_iter()
            .map(|id| {
                json!({
                    "id": id,
                    "required": true,
                    "status": "pass",
                    "detail": "verified live Testnet4 evidence"
                })
            })
            .collect::<Vec<_>>();
        json!({
            "schema_version": 1,
            "provider": "bitgo",
            "environment": "test",
            "coin": "tbtc4",
            "wallet_id": "bitgo-test-wallet-gate4",
            "generated_at_unix": 1_783_980_000_u64,
            "scope": BITGO_REPORT_SCOPE,
            "evidence_sha256": evidence_hash,
            "overall": "pass",
            "checks": checks
        })
    }

    fn observation_members() -> Vec<Value> {
        (0..5)
            .map(|index| {
                json!({
                    "operator_id": format!("observer-{index}"),
                    "admin_domain": format!("observer-admin-{index}"),
                    "infrastructure_domain": format!("observer-infra-{index}"),
                    "rpc_failure_domain": format!("observer-rpc-{index}"),
                    "certification_pubkey_sha256": format!("{:064x}", index + 10),
                    "thornode_origins": [
                        format!("https://thor-{index}-a.test/"),
                        format!("https://thor-{index}-b.test/")
                    ]
                })
            })
            .collect()
    }

    fn custody_members() -> Vec<Value> {
        vec![
            json!({
                "holder_type": "user",
                "signer_role": "normal",
                "key_id_sha256": "44".repeat(32),
                "operator_id": "custody-user",
                "admin_domain": "custody-user-admin",
                "failure_domain": "custody-user-infra"
            }),
            json!({
                "holder_type": "backup",
                "signer_role": "recovery",
                "key_id_sha256": "55".repeat(32),
                "operator_id": "custody-backup",
                "admin_domain": "custody-backup-admin",
                "failure_domain": "custody-backup-infra"
            }),
            json!({
                "holder_type": "bitgo",
                "signer_role": "normal",
                "key_id_sha256": "66".repeat(32),
                "operator_id": "bitgo",
                "admin_domain": "bitgo-admin",
                "failure_domain": "bitgo-managed"
            }),
        ]
    }

    fn fixture_drills(artifact_hashes: &mut HashMap<String, String>) -> Vec<Value> {
        REQUIRED_DRILLS
            .iter()
            .enumerate()
            .map(|(index, id)| {
                let artifact_a = format!("/private/gate4/{index}-transcript.log");
                let artifact_b = format!("/private/gate4/{index}-operator.log");
                let hash_a = format!("{:064x}", 1000 + index * 2);
                let hash_b = format!("{:064x}", 1001 + index * 2);
                artifact_hashes.insert(artifact_a.clone(), hash_a.clone());
                artifact_hashes.insert(artifact_b.clone(), hash_b.clone());
                let positive = POSITIVE_CUSTODY_DRILLS.contains(id);
                let mut external = if *id == "G4-BITGO-BACKUP-RECOVERY" {
                    vec![json!({
                        "kind": "ceremony_record",
                        "environment": "bitgo-recovery",
                        "id": "backup-recovery-ceremony",
                        "verified": true
                    })]
                } else if BITGO_PROVIDER_DRILLS.contains(id) {
                    vec![json!({
                        "kind": "provider_request",
                        "environment": "bitgo-test",
                        "id": format!("provider-request-{index}"),
                        "verified": true
                    })]
                } else if ["G4-MINT-HAPPY", "G4-REDEEM-HAPPY", "G4-STREAM-PARTIAL", "G4-REFUND-FULL"].contains(id) {
                    vec![json!({
                        "kind": "transaction",
                        "environment": "sepolia-or-signet",
                        "id": format!("transaction-{index}"),
                        "verified": true
                    })]
                } else {
                    vec![json!({
                        "kind": "operator_log",
                        "environment": "gate4-testnet",
                        "id": format!("operator-log-{index}"),
                        "verified": true
                    })]
                };
                if *id == "G4-ALERT-WORM" {
                    external = vec![
                        json!({"kind": "alert", "environment": "gate4-testnet", "id": "alert-1", "verified": true}),
                        json!({"kind": "worm_record", "environment": "gate4-testnet", "id": "worm-1", "verified": true})
                    ];
                }
                if *id == "G4-BITGO-BACKUP-RECOVERY" {
                    external.push(json!({
                        "kind": "transaction",
                        "environment": "bitcoin-testnet4",
                        "id": "backup-recovery-transaction",
                        "verified": true
                    }));
                }
                json!({
                    "id": id,
                    "status": "pass",
                    "started_at_utc": "2026-07-15T10:00:00Z",
                    "completed_at_utc": "2026-07-15T10:01:00Z",
                    "operators": ["observer-0", "observer-1", "observer-2", "custody-user", "custody-backup"],
                    "expected": "The documented fail-closed outcome occurs exactly.",
                    "observed": "The documented fail-closed outcome occurred exactly.",
                    "response_time_ms": 1_000,
                    "response_time_budget_ms": 60_000,
                    "custody_signature_created": positive,
                    "custody_broadcast_created": positive,
                    "external_evidence": external,
                    "artifacts": [
                        {"path": artifact_a, "sha256": hash_a},
                        {"path": artifact_b, "sha256": hash_b}
                    ]
                })
            })
            .collect()
    }

    fn fixture() -> (Value, Vec<u8>, HashMap<String, String>) {
        let bitgo_evidence_hash = "11".repeat(32);
        let bitgo_bytes = serde_json::to_vec(&bitgo_report(&bitgo_evidence_hash)).expect("bitgo");
        let bitgo_report_hash = sha256_hex(&bitgo_bytes);
        let mut artifact_hashes = HashMap::new();
        let authorization_path = "/private/gate4/authorization.txt";
        artifact_hashes.insert(authorization_path.to_string(), "22".repeat(32));
        let bitgo_evidence_path = "/private/gate4/bitgo-evidence.json";
        artifact_hashes.insert(bitgo_evidence_path.to_string(), bitgo_evidence_hash.clone());
        let drills = fixture_drills(&mut artifact_hashes);
        let evidence = json!({
            "schema_version": 1,
            "gate": "XINDEX_GATE_4",
            "environment": "sepolia+thorchain-devnet+btc-testnet4",
            "protocol_commit": "1234567890abcdef1234567890abcdef12345678",
            "services_commit": "abcdef1234567890abcdef1234567890abcdef12",
            "started_at_utc": "2026-07-15T00:00:00Z",
            "completed_at_utc": "2026-07-16T00:00:00Z",
            "reviewers": ["reviewer-alpha", "reviewer-beta"],
            "authorization": {"path": authorization_path, "sha256": "22".repeat(32)},
            "bitgo_qualification": {
                "report_sha256": bitgo_report_hash,
                "evidence": {
                    "path": bitgo_evidence_path,
                    "sha256": bitgo_evidence_hash
                }
            },
            "topology": {
                "observation_certification": {
                    "threshold": 3,
                    "participants": 5,
                    "members": observation_members()
                },
                "custody": {
                    "threshold": 2,
                    "participants": 3,
                    "provider": "bitgo",
                    "network": "bitcoin-testnet4",
                    "address_type": "p2wsh",
                    "wallet_id": "bitgo-test-wallet-gate4",
                    "wallet_keyset_sha256": "33".repeat(32),
                    "members": custody_members()
                }
            },
            "drills": drills
        });
        (evidence, bitgo_bytes, artifact_hashes)
    }

    fn validate_fixture(
        value: Value,
        bitgo: &[u8],
        artifacts: &HashMap<String, String>,
    ) -> Result<Gate4Summary, Gate4Error> {
        let evidence: Gate4Evidence = serde_json::from_value(value)?;
        validate_gate4(evidence, bitgo, artifacts)
    }

    #[test]
    fn self_authored_bundle_is_only_format_valid() {
        let (value, bitgo, artifacts) = fixture();
        let summary = validate_fixture(value, &bitgo, &artifacts).expect("valid Gate-4 bundle");
        assert_eq!(summary.drill_count, REQUIRED_DRILLS.len());
        assert_eq!(summary.overall, "format_valid");
    }

    #[test]
    fn missing_drill_fails_closed() {
        let (mut value, bitgo, artifacts) = fixture();
        value["drills"].as_array_mut().expect("drills").pop();
        let error = validate_fixture(value, &bitgo, &artifacts).expect_err("missing drill");
        assert!(error.to_string().contains("G4-ALERT-WORM"));
    }

    #[test]
    fn collapsed_custody_domain_is_rejected() {
        let (mut value, bitgo, artifacts) = fixture();
        value["topology"]["custody"]["members"][2]["admin_domain"] =
            value["topology"]["custody"]["members"][1]["admin_domain"].clone();
        let error = validate_fixture(value, &bitgo, &artifacts).expect_err("collapsed domain");
        assert!(error.to_string().contains("custody admin_domain"));
    }

    #[test]
    fn negative_drill_cannot_hide_a_signature() {
        let (mut value, bitgo, artifacts) = fixture();
        let drill = value["drills"]
            .as_array_mut()
            .expect("drills")
            .iter_mut()
            .find(|drill| drill["id"] == "G4-CTD-FORGED-DESTINATION")
            .expect("negative drill");
        drill["custody_signature_created"] = json!(true);
        let error = validate_fixture(value, &bitgo, &artifacts).expect_err("signature must fail");
        assert!(error.to_string().contains("produced a custody signature"));
    }

    #[test]
    fn artifact_hash_mismatch_is_rejected() {
        let (value, bitgo, mut artifacts) = fixture();
        artifacts.insert(
            "/private/gate4/0-transcript.log".to_string(),
            "ff".repeat(32),
        );
        let error = validate_fixture(value, &bitgo, &artifacts).expect_err("artifact mismatch");
        assert!(error.to_string().contains("artifact SHA-256 mismatch"));
    }

    #[test]
    fn blocked_bitgo_report_is_rejected() {
        let (mut value, bitgo, artifacts) = fixture();
        let mut report: Value = serde_json::from_slice(&bitgo).expect("report");
        report["overall"] = json!("blocked");
        let blocked = serde_json::to_vec(&report).expect("blocked report");
        value["bitgo_qualification"]["report_sha256"] = json!(sha256_hex(&blocked));
        let error = validate_fixture(value, &blocked, &artifacts).expect_err("blocked BitGo");
        assert!(error.to_string().contains("overall must equal pass"));
    }

    #[test]
    fn mismatched_bitgo_evidence_hash_is_rejected() {
        let (mut value, bitgo, artifacts) = fixture();
        value["bitgo_qualification"]["evidence"]["sha256"] = json!("99".repeat(32));
        let error = validate_fixture(value, &bitgo, &artifacts).expect_err("mismatched evidence");
        assert!(error
            .to_string()
            .contains("does not bind the recorded evidence_sha256"));
    }

    #[test]
    fn mismatched_bitgo_wallet_is_rejected() {
        let (mut value, bitgo, artifacts) = fixture();
        value["topology"]["custody"]["wallet_id"] = json!("different-bitgo-wallet");
        let error = validate_fixture(value, &bitgo, &artifacts).expect_err("mismatched wallet");
        assert!(error.to_string().contains("BitGo report wallet_id"));
    }
}
