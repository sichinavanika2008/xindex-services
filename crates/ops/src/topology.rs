//! Strict validation for the Gate-3 production trust-domain registry.
//!
//! The registry contains public identities and immutable evidence hashes, not
//! secrets. It is deliberately supplied at release time instead of shipping a
//! fake checked-in "production" roster. Validation rejects placeholders,
//! quorum collapse, key reuse, shared administrative failure domains, and
//! source topologies that do not meet the current launch policy.

use std::collections::{HashMap, HashSet};

use axum::http::Uri;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const REQUIRED_ROLES: [(&str, usize, usize); 4] = [
    ("price_signer", 11, 7),
    ("registry_signer", 5, 3),
    ("settlement_observer", 5, 3),
    ("custody_signer", 5, 3),
];

#[derive(Debug, Error)]
pub enum TopologyError {
    #[error("topology JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid Gate-3 topology:\n{0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TopologySummary {
    pub schema_version: u32,
    pub environment: String,
    pub operator_count: usize,
    pub reviewer_count: usize,
    pub roles: Vec<RoleSummary>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RoleSummary {
    pub role: String,
    pub members: usize,
    pub threshold: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Topology {
    schema_version: u32,
    environment: String,
    reviewed_at_utc: String,
    reviewers: Vec<String>,
    operators: Vec<Operator>,
    roles: Vec<Role>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operator {
    #[serde(rename = "operator_id")]
    id: String,
    legal_entity: String,
    cloud_provider: String,
    cloud_account_id: String,
    region: String,
    host_failure_domain: String,
    hsm_provider: String,
    hsm_admin_domain: String,
    network_failure_domain: String,
    rpc_failure_domain: String,
    market_data_failure_domain: String,
    reviewed_by: Vec<String>,
    evidence_sha256: Vec<String>,
    sources: Sources,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sources {
    ethereum_rpc_origin: String,
    bitcoin_rpc_origin: String,
    thornode_origins: Vec<String>,
    cometbft_origins: Vec<String>,
    price_venue_origins: Vec<String>,
    supply_origins: Vec<String>,
    collector_origins: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Role {
    #[serde(rename = "role")]
    name: String,
    threshold: usize,
    members: Vec<RoleMember>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleMember {
    operator_id: String,
    hsm_key_id: String,
    public_key_fingerprint: String,
}

/// Parse and validate one complete production topology registry.
///
/// # Errors
/// Malformed JSON or any incomplete/collapsed trust-domain invariant.
pub fn validate_topology(bytes: &[u8]) -> Result<TopologySummary, TopologyError> {
    let topology: Topology = serde_json::from_slice(bytes)?;
    let mut errors = Vec::new();
    validate_header(&topology, &mut errors);
    let operators = validate_operators(&topology, &mut errors);
    validate_roles(&topology, &operators, &mut errors);
    if !errors.is_empty() {
        return Err(TopologyError::Invalid(errors.join("\n")));
    }
    let mut roles = topology
        .roles
        .iter()
        .map(|role| RoleSummary {
            role: role.name.clone(),
            members: role.members.len(),
            threshold: role.threshold,
        })
        .collect::<Vec<_>>();
    roles.sort_by(|left, right| left.role.cmp(&right.role));
    Ok(TopologySummary {
        schema_version: topology.schema_version,
        environment: topology.environment,
        operator_count: topology.operators.len(),
        reviewer_count: topology.reviewers.len(),
        roles,
    })
}

fn validate_header(topology: &Topology, errors: &mut Vec<String>) {
    if topology.schema_version != 1 {
        errors.push("schema_version must equal 1".to_string());
    }
    if topology.environment != "production" {
        errors.push("environment must equal production".to_string());
    }
    if !looks_like_utc_timestamp(&topology.reviewed_at_utc) {
        errors.push("reviewed_at_utc must be a non-placeholder UTC timestamp".to_string());
    }
    validate_distinct_values("reviewers", &topology.reviewers, 2, errors);
}

fn validate_operators<'a>(
    topology: &'a Topology,
    errors: &mut Vec<String>,
) -> HashMap<&'a str, &'a Operator> {
    if topology.operators.len() < 11 {
        errors.push("at least 11 independent operator records are required".to_string());
    }
    let reviewers = topology.reviewers.iter().map(String::as_str).collect();
    let mut by_id = HashMap::new();
    let mut global_domains: HashMap<&str, HashSet<String>> = HashMap::new();
    for operator in &topology.operators {
        validate_public_value("operator_id", &operator.id, errors);
        validate_public_value("cloud_provider", &operator.cloud_provider, errors);
        validate_public_value("hsm_provider", &operator.hsm_provider, errors);
        if by_id.insert(operator.id.as_str(), operator).is_some() {
            errors.push(format!("duplicate operator_id {}", operator.id));
        }
        for (field, value) in operator_domains(operator) {
            validate_public_value(field, value, errors);
            if !global_domains
                .entry(field)
                .or_default()
                .insert(normalize(value))
            {
                errors.push(format!("{field} is shared by multiple operators: {value}"));
            }
        }
        validate_reviews(operator, &reviewers, errors);
        validate_evidence(operator, errors);
        validate_sources(operator, errors);
    }
    by_id
}

fn operator_domains(operator: &Operator) -> [(&'static str, &str); 9] {
    [
        ("legal_entity", &operator.legal_entity),
        ("cloud_account_id", &operator.cloud_account_id),
        ("region", &operator.region),
        ("host_failure_domain", &operator.host_failure_domain),
        ("hsm_admin_domain", &operator.hsm_admin_domain),
        ("network_failure_domain", &operator.network_failure_domain),
        ("rpc_failure_domain", &operator.rpc_failure_domain),
        (
            "market_data_failure_domain",
            &operator.market_data_failure_domain,
        ),
        ("operator_id", &operator.id),
    ]
}

fn validate_reviews(operator: &Operator, reviewers: &HashSet<&str>, errors: &mut Vec<String>) {
    validate_distinct_values(
        &format!("{}.reviewed_by", operator.id),
        &operator.reviewed_by,
        2,
        errors,
    );
    for reviewer in &operator.reviewed_by {
        if !reviewers.contains(reviewer.as_str()) {
            errors.push(format!(
                "operator {} names reviewer not present in top-level roster: {reviewer}",
                operator.id
            ));
        }
    }
}

fn validate_evidence(operator: &Operator, errors: &mut Vec<String>) {
    if operator.evidence_sha256.is_empty() {
        errors.push(format!(
            "operator {} has no immutable evidence hash",
            operator.id
        ));
    }
    let mut hashes = HashSet::new();
    for hash in &operator.evidence_sha256 {
        let valid = hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit());
        if !valid || !hashes.insert(hash.to_ascii_lowercase()) {
            errors.push(format!(
                "operator {} has an invalid/duplicate evidence SHA-256",
                operator.id
            ));
        }
    }
}

fn validate_sources(operator: &Operator, errors: &mut Vec<String>) {
    let sources = &operator.sources;
    validate_origin(
        &format!("{}.ethereum_rpc_origin", operator.id),
        &sources.ethereum_rpc_origin,
        errors,
    );
    validate_origin(
        &format!("{}.bitcoin_rpc_origin", operator.id),
        &sources.bitcoin_rpc_origin,
        errors,
    );
    for (field, values, required) in [
        ("thornode_origins", &sources.thornode_origins, 3),
        ("cometbft_origins", &sources.cometbft_origins, 3),
        ("price_venue_origins", &sources.price_venue_origins, 3),
        ("supply_origins", &sources.supply_origins, 2),
        ("collector_origins", &sources.collector_origins, 2),
    ] {
        if values.len() < required {
            errors.push(format!(
                "operator {} requires at least {required} {field}",
                operator.id
            ));
        }
        let mut unique = HashSet::new();
        for origin in values {
            validate_origin(&format!("{}.{}", operator.id, field), origin, errors);
            if !unique.insert(normalize(origin)) {
                errors.push(format!(
                    "operator {} has duplicate {field} origin",
                    operator.id
                ));
            }
        }
    }
}

fn validate_roles(
    topology: &Topology,
    operators: &HashMap<&str, &Operator>,
    errors: &mut Vec<String>,
) {
    let mut roles = HashMap::new();
    let mut fingerprints = HashSet::new();
    let mut hsm_keys = HashSet::new();
    let mut participating = HashSet::new();
    for role in &topology.roles {
        validate_public_value("role", &role.name, errors);
        if roles.insert(role.name.as_str(), role).is_some() {
            errors.push(format!("duplicate role {}", role.name));
        }
        if role.threshold == 0
            || role.threshold > role.members.len()
            || role.threshold < role.members.len() / 2 + 1
        {
            errors.push(format!("role {} does not use a strict majority", role.name));
        }
        validate_role_members(
            role,
            operators,
            &mut fingerprints,
            &mut hsm_keys,
            &mut participating,
            errors,
        );
    }
    for (role, members, threshold) in REQUIRED_ROLES {
        match roles.get(role) {
            Some(actual) if actual.members.len() == members && actual.threshold == threshold => {}
            Some(actual) => errors.push(format!(
                "role {role} must be {threshold}-of-{members}, found {}-of-{}",
                actual.threshold,
                actual.members.len()
            )),
            None => errors.push(format!("required role {role} is absent")),
        }
    }
    for operator in operators.keys() {
        if !participating.contains(operator) {
            errors.push(format!("operator {operator} has no role assignment"));
        }
    }
}

fn validate_role_members<'a>(
    role: &Role,
    operators: &HashMap<&'a str, &'a Operator>,
    fingerprints: &mut HashSet<String>,
    hsm_keys: &mut HashSet<String>,
    participating: &mut HashSet<&'a str>,
    errors: &mut Vec<String>,
) {
    let mut member_ids = HashSet::new();
    let mut domains: HashMap<&str, HashSet<String>> = HashMap::new();
    let mut cloud_counts = HashMap::new();
    let mut hsm_counts = HashMap::new();
    let mut ethereum_origins = HashSet::new();
    let mut bitcoin_origins = HashSet::new();
    let mut owned_thornodes = HashSet::new();
    let mut owned_cometbft = HashSet::new();
    for member in &role.members {
        if !member_ids.insert(member.operator_id.as_str()) {
            errors.push(format!(
                "role {} repeats operator {}",
                role.name, member.operator_id
            ));
            continue;
        }
        let Some(operator) = operators.get(member.operator_id.as_str()) else {
            errors.push(format!(
                "role {} references unknown operator {}",
                role.name, member.operator_id
            ));
            continue;
        };
        participating.insert(operator.id.as_str());
        validate_public_value("hsm_key_id", &member.hsm_key_id, errors);
        if !valid_fingerprint(&member.public_key_fingerprint)
            || !fingerprints.insert(normalize(&member.public_key_fingerprint))
        {
            errors.push(format!(
                "role {} has invalid/reused public key fingerprint for {}",
                role.name, member.operator_id
            ));
        }
        let hsm_identity = format!("{}:{}", operator.hsm_admin_domain, member.hsm_key_id);
        if !hsm_keys.insert(normalize(&hsm_identity)) {
            errors.push(format!(
                "role {} reuses an HSM key identity for {}",
                role.name, member.operator_id
            ));
        }
        for (field, value) in operator_domains(operator) {
            if !domains.entry(field).or_default().insert(normalize(value)) {
                errors.push(format!("role {} collapses {field} at {value}", role.name));
            }
        }
        *cloud_counts
            .entry(normalize(&operator.cloud_provider))
            .or_insert(0usize) += 1;
        *hsm_counts
            .entry(normalize(&operator.hsm_provider))
            .or_insert(0usize) += 1;
        insert_role_origin(
            &role.name,
            "ethereum RPC",
            &operator.sources.ethereum_rpc_origin,
            &mut ethereum_origins,
            errors,
        );
        insert_role_origin(
            &role.name,
            "Bitcoin RPC",
            &operator.sources.bitcoin_rpc_origin,
            &mut bitcoin_origins,
            errors,
        );
        if let Some(origin) = operator.sources.thornode_origins.first() {
            insert_role_origin(
                &role.name,
                "owned THORNode",
                origin,
                &mut owned_thornodes,
                errors,
            );
        }
        if let Some(origin) = operator.sources.cometbft_origins.first() {
            insert_role_origin(
                &role.name,
                "owned CometBFT",
                origin,
                &mut owned_cometbft,
                errors,
            );
        }
    }
    let tolerated = role.members.len().saturating_sub(role.threshold);
    validate_concentration(
        &role.name,
        "cloud provider",
        &cloud_counts,
        tolerated,
        errors,
    );
    validate_concentration(&role.name, "HSM provider", &hsm_counts, tolerated, errors);
}

fn insert_role_origin(
    role: &str,
    field: &str,
    origin: &str,
    values: &mut HashSet<String>,
    errors: &mut Vec<String>,
) {
    if !values.insert(normalize(origin)) {
        errors.push(format!("role {role} shares a primary {field} origin"));
    }
}

fn validate_concentration(
    role: &str,
    field: &str,
    counts: &HashMap<String, usize>,
    tolerated: usize,
    errors: &mut Vec<String>,
) {
    for (value, count) in counts {
        if *count > tolerated {
            errors.push(format!(
                "role {role} places {count} members in {field} {value}; at most {tolerated} may share one"
            ));
        }
    }
}

fn validate_distinct_values(
    field: &str,
    values: &[String],
    minimum: usize,
    errors: &mut Vec<String>,
) {
    if values.len() < minimum {
        errors.push(format!("{field} requires at least {minimum} entries"));
    }
    let mut unique = HashSet::new();
    for value in values {
        validate_public_value(field, value, errors);
        if !unique.insert(normalize(value)) {
            errors.push(format!("{field} contains a duplicate"));
        }
    }
}

fn validate_public_value(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.len() > 200 || value.chars().any(char::is_control) || is_placeholder(value) {
        errors.push(format!("{field} is empty, unsafe, or a placeholder"));
    }
}

fn validate_origin(field: &str, raw: &str, errors: &mut Vec<String>) {
    let Ok(uri) = raw.parse::<Uri>() else {
        errors.push(format!("{field} is not a valid HTTPS origin"));
        return;
    };
    let authority = uri.authority();
    let host = authority.map(axum::http::uri::Authority::host);
    let invalid_host = host.is_none_or(|host| {
        let normalized = normalize(host);
        normalized == "localhost"
            || normalized == "127.0.0.1"
            || normalized == "::1"
            || normalized.ends_with(".example")
            || normalized.ends_with(".invalid")
            || normalized == "example.com"
    });
    if uri.scheme_str() != Some("https")
        || authority.is_none()
        || authority.is_some_and(|value| value.as_str().contains('@'))
        || invalid_host
        || uri.path() != "/"
        || uri.query().is_some()
        || is_placeholder(raw)
    {
        errors.push(format!(
            "{field} must be an exact non-placeholder HTTPS origin"
        ));
    }
}

fn looks_like_utc_timestamp(value: &str) -> bool {
    value.len() >= 20
        && value.ends_with('Z')
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value.contains('T')
        && !is_placeholder(value)
}

fn valid_fingerprint(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn is_placeholder(value: &str) -> bool {
    let normalized = normalize(value.trim());
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
            "example",
        ]
        .iter()
        .any(|marker| normalized == *marker || normalized.starts_with(&format!("{marker}-")))
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    fn fixture() -> Value {
        let reviewers = vec!["reviewer-alpha", "reviewer-beta"];
        let operators = (0..11)
            .map(|index| {
                json!({
                    "operator_id": format!("operator-{index}"),
                    "legal_entity": format!("legal-entity-{index}"),
                    "cloud_provider": format!("cloud-{}", index % 4),
                    "cloud_account_id": format!("cloud-account-{index}"),
                    "region": format!("region-{index}"),
                    "host_failure_domain": format!("host-domain-{index}"),
                    "hsm_provider": format!("hsm-provider-{}", index % 4),
                    "hsm_admin_domain": format!("hsm-admin-{index}"),
                    "network_failure_domain": format!("network-{index}"),
                    "rpc_failure_domain": format!("rpc-domain-{index}"),
                    "market_data_failure_domain": format!("market-domain-{index}"),
                    "reviewed_by": reviewers,
                    "evidence_sha256": [format!("{:064x}", index + 1)],
                    "sources": {
                        "ethereum_rpc_origin": format!("https://eth-{index}.prod/"),
                        "bitcoin_rpc_origin": format!("https://btc-{index}.prod/"),
                        "thornode_origins": (0..3).map(|source| format!("https://thor-{index}-{source}.prod/")).collect::<Vec<_>>(),
                        "cometbft_origins": (0..3).map(|source| format!("https://comet-{index}-{source}.prod/")).collect::<Vec<_>>(),
                        "price_venue_origins": (0..3).map(|source| format!("https://price-{index}-{source}.prod/")).collect::<Vec<_>>(),
                        "supply_origins": (0..2).map(|source| format!("https://supply-{index}-{source}.prod/")).collect::<Vec<_>>(),
                        "collector_origins": (0..2).map(|source| format!("https://collector-{index}-{source}.prod/")).collect::<Vec<_>>()
                    }
                })
            })
            .collect::<Vec<_>>();
        let role = |name: &str, members: usize, threshold: usize, offset: usize| {
            json!({
                "role": name,
                "threshold": threshold,
                "members": (0..members).map(|index| json!({
                    "operator_id": format!("operator-{index}"),
                    "hsm_key_id": format!("{name}-key-{index}"),
                    "public_key_fingerprint": format!("sha256:{:064x}", offset + index + 1)
                })).collect::<Vec<_>>()
            })
        };
        json!({
            "schema_version": 1,
            "environment": "production",
            "reviewed_at_utc": "2026-07-13T12:00:00Z",
            "reviewers": reviewers,
            "operators": operators,
            "roles": [
                role("price_signer", 11, 7, 100),
                role("registry_signer", 5, 3, 200),
                role("settlement_observer", 5, 3, 300),
                role("custody_signer", 5, 3, 400)
            ]
        })
    }

    #[test]
    #[expect(clippy::expect_used, reason = "strict synthetic fixture")]
    fn complete_independent_topology_passes() {
        let encoded = serde_json::to_vec(&fixture()).expect("encode");
        let summary = validate_topology(&encoded).expect("valid topology");
        assert_eq!(summary.operator_count, 11);
        assert_eq!(summary.roles.len(), 4);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "strict synthetic fixture")]
    fn shared_failure_domain_is_rejected() {
        let mut value = fixture();
        value["operators"][1]["legal_entity"] = value["operators"][0]["legal_entity"].clone();
        let encoded = serde_json::to_vec(&value).expect("encode");
        let error = validate_topology(&encoded).expect_err("collapse must fail");
        assert!(error.to_string().contains("legal_entity"));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "strict synthetic fixture")]
    fn placeholder_and_reused_key_are_rejected() {
        let mut value = fixture();
        value["operators"][0]["cloud_account_id"] = json!("TBD");
        value["roles"][1]["members"][0]["public_key_fingerprint"] =
            value["roles"][0]["members"][0]["public_key_fingerprint"].clone();
        let encoded = serde_json::to_vec(&value).expect("encode");
        let error = validate_topology(&encoded).expect_err("unsafe topology must fail");
        assert!(error.to_string().contains("placeholder"));
        assert!(error.to_string().contains("reused public key"));
    }
}
