//! Canonical unsigned manifest over the durable `BitGo` workflow artifacts.

use alloy_primitives::B256;
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};
use xindex_bitgo_adapter::SpendPolicy;

use crate::workflow::EvidenceArtifactRow;
use crate::{
    BitGoAuthVersion, BitGoEnvironment, BitGoWorkflowStore, WorkflowError, WorkflowPhase,
    PRODUCTION_ORIGIN, TEST_ORIGIN,
};

const MANIFEST_SCHEMA_VERSION: u32 = 2;
const SIGNING_DOMAIN: &[u8] = b"XINDEX_BITGO_EVIDENCE_MANIFEST_V2";

/// Failure while building or hashing a canonical workflow manifest.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    /// Durable workflow state or an artifact hash was invalid.
    #[error(transparent)]
    Workflow(#[from] WorkflowError),
    /// The selected environment is incompatible with the policy coin.
    #[error("BitGo evidence environment does not match the wallet coin")]
    EnvironmentCoinMismatch,
    /// A canonical length cannot be represented as a `u64`.
    #[error("BitGo evidence manifest length overflow")]
    LengthOverflow,
}

/// One content-addressed durable request, response, or transaction artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceArtifact {
    ordinal: u64,
    kind: String,
    #[serde(serialize_with = "serialize_hex_32")]
    payload_sha256: [u8; 32],
    payload_bytes: u64,
    created_at_unix: u64,
}

impl EvidenceArtifact {
    /// Append-only workflow ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Stable artifact kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// SHA-256 of the exact retained bytes.
    #[must_use]
    pub const fn payload_sha256(&self) -> [u8; 32] {
        self.payload_sha256
    }

    /// Exact retained payload length.
    #[must_use]
    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    /// Local durable-capture timestamp.
    #[must_use]
    pub const fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }
}

impl From<EvidenceArtifactRow> for EvidenceArtifact {
    fn from(row: EvidenceArtifactRow) -> Self {
        Self {
            ordinal: row.ordinal,
            kind: row.kind,
            payload_sha256: row.payload_sha256,
            payload_bytes: row.payload_bytes,
            created_at_unix: row.created_at_unix,
        }
    }
}

/// Versioned canonical manifest generated from one consistent database snapshot.
///
/// The manifest is tamper-detecting, not self-authenticating. Independent
/// reviewers must sign [`Self::signing_digest`] under separately pinned trust
/// anchors before it can establish evidence provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceManifest {
    schema_version: u32,
    provider: String,
    environment: String,
    api_origin: String,
    auth_version: String,
    coin: String,
    wallet_id: String,
    sequence_id: String,
    #[serde(serialize_with = "serialize_hex_32")]
    policy_commitment: [u8; 32],
    workflow_phase: String,
    captured_from_unix: u64,
    captured_through_unix: u64,
    artifacts: Vec<EvidenceArtifact>,
}

impl EvidenceManifest {
    /// Manifest schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Fixed `BitGo` environment label.
    #[must_use]
    pub fn environment(&self) -> &str {
        &self.environment
    }

    /// Explicit `BitGo` request/response HMAC protocol version.
    #[must_use]
    pub fn auth_version(&self) -> &str {
        &self.auth_version
    }

    /// Exact wallet identifier.
    #[must_use]
    pub fn wallet_id(&self) -> &str {
        &self.wallet_id
    }

    /// Exact workflow sequence ID.
    #[must_use]
    pub fn sequence_id(&self) -> &str {
        &self.sequence_id
    }

    /// Commitment to every independent spend-policy field.
    #[must_use]
    pub const fn policy_commitment(&self) -> [u8; 32] {
        self.policy_commitment
    }

    /// Durable workflow phase captured by this manifest.
    #[must_use]
    pub fn workflow_phase(&self) -> &str {
        &self.workflow_phase
    }

    /// Ordered content-addressed artifacts.
    #[must_use]
    pub fn artifacts(&self) -> &[EvidenceArtifact] {
        &self.artifacts
    }

    /// Domain-separated digest for external reviewer signatures.
    ///
    /// # Errors
    /// A string or artifact count cannot be represented as a `u64`.
    pub fn signing_digest(&self) -> Result<B256, EvidenceError> {
        let mut digest = Sha256::new();
        digest.update(SIGNING_DOMAIN);
        digest.update(self.schema_version.to_be_bytes());
        hash_text(&mut digest, &self.provider)?;
        hash_text(&mut digest, &self.environment)?;
        hash_text(&mut digest, &self.api_origin)?;
        hash_text(&mut digest, &self.auth_version)?;
        hash_text(&mut digest, &self.coin)?;
        hash_text(&mut digest, &self.wallet_id)?;
        hash_text(&mut digest, &self.sequence_id)?;
        digest.update(self.policy_commitment);
        hash_text(&mut digest, &self.workflow_phase)?;
        digest.update(self.captured_from_unix.to_be_bytes());
        digest.update(self.captured_through_unix.to_be_bytes());
        digest.update(
            u64::try_from(self.artifacts.len())
                .map_err(|_| EvidenceError::LengthOverflow)?
                .to_be_bytes(),
        );
        for artifact in &self.artifacts {
            digest.update(artifact.ordinal.to_be_bytes());
            hash_text(&mut digest, &artifact.kind)?;
            digest.update(artifact.payload_sha256);
            digest.update(artifact.payload_bytes.to_be_bytes());
            digest.update(artifact.created_at_unix.to_be_bytes());
        }
        Ok(B256::from(<[u8; 32]>::from(digest.finalize())))
    }
}

impl BitGoWorkflowStore {
    /// Build a canonical manifest from one consistent, hash-verified workflow
    /// snapshot. Exact raw payloads remain in the owner-controlled database.
    ///
    /// # Errors
    /// Environment mismatch, policy conflict, corrupt artifact, or database failure.
    pub(crate) async fn evidence_manifest(
        &self,
        environment: BitGoEnvironment,
        auth_version: BitGoAuthVersion,
        policy: &SpendPolicy,
    ) -> Result<EvidenceManifest, EvidenceError> {
        if !environment.accepts(policy.wallet().coin()) {
            return Err(EvidenceError::EnvironmentCoinMismatch);
        }
        let (record, rows) = self.evidence_snapshot(policy).await?;
        let artifacts = rows
            .into_iter()
            .map(EvidenceArtifact::from)
            .collect::<Vec<_>>();
        let captured_from_unix = artifacts
            .iter()
            .map(EvidenceArtifact::created_at_unix)
            .min()
            .unwrap_or_default();
        let captured_through_unix = artifacts
            .iter()
            .map(EvidenceArtifact::created_at_unix)
            .max()
            .unwrap_or_default();
        let (environment, api_origin) = match environment {
            BitGoEnvironment::Test => ("test", TEST_ORIGIN),
            BitGoEnvironment::Production => ("production", PRODUCTION_ORIGIN),
        };
        let mut policy_commitment = [0u8; 32];
        policy_commitment.copy_from_slice(record.policy_commitment().as_slice());
        Ok(EvidenceManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            provider: "bitgo".to_owned(),
            environment: environment.to_owned(),
            api_origin: api_origin.to_owned(),
            auth_version: auth_version.header().to_owned(),
            coin: policy.wallet().coin().as_str().to_owned(),
            wallet_id: policy.wallet().wallet_id().to_owned(),
            sequence_id: policy.sequence_id().to_owned(),
            policy_commitment,
            workflow_phase: phase_name(record.phase()).to_owned(),
            captured_from_unix,
            captured_through_unix,
            artifacts,
        })
    }
}

fn hash_text(digest: &mut Sha256, value: &str) -> Result<(), EvidenceError> {
    digest.update(
        u64::try_from(value.len())
            .map_err(|_| EvidenceError::LengthOverflow)?
            .to_be_bytes(),
    );
    digest.update(value.as_bytes());
    Ok(())
}

const fn phase_name(phase: WorkflowPhase) -> &'static str {
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

fn serialize_hex_32<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&alloy_primitives::hex::encode(value))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test assertions")]

    use super::{EvidenceArtifact, EvidenceManifest, MANIFEST_SCHEMA_VERSION};

    fn manifest(payload_sha256: [u8; 32]) -> EvidenceManifest {
        EvidenceManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            provider: "bitgo".to_owned(),
            environment: "test".to_owned(),
            api_origin: "https://app.bitgo-test.com".to_owned(),
            auth_version: "2.0".to_owned(),
            coin: "tbtc4".to_owned(),
            wallet_id: "wallet-1".to_owned(),
            sequence_id: "sequence-1".to_owned(),
            policy_commitment: [0x11; 32],
            workflow_phase: "built".to_owned(),
            captured_from_unix: 1,
            captured_through_unix: 1,
            artifacts: vec![EvidenceArtifact {
                ordinal: 0,
                kind: "build_request".to_owned(),
                payload_sha256,
                payload_bytes: 12,
                created_at_unix: 1,
            }],
        }
    }

    #[test]
    fn canonical_digest_is_stable_and_binds_artifact_hashes() {
        let first = manifest([0x22; 32]);
        let identical = manifest([0x22; 32]);
        let changed = manifest([0x23; 32]);
        assert_eq!(
            first.signing_digest().expect("digest"),
            identical.signing_digest().expect("digest")
        );
        assert_ne!(
            first.signing_digest().expect("digest"),
            changed.signing_digest().expect("digest")
        );
    }

    #[test]
    fn json_uses_hex_hashes_without_raw_payloads() {
        let encoded = serde_json::to_value(manifest([0x22; 32])).expect("JSON");
        assert_eq!(encoded["schema_version"], 2);
        assert_eq!(encoded["auth_version"], "2.0");
        assert_eq!(encoded["policy_commitment"], "11".repeat(32));
        assert_eq!(encoded["artifacts"][0]["payload_sha256"], "22".repeat(32));
        assert!(encoded["artifacts"][0].get("payload").is_none());
    }
}
