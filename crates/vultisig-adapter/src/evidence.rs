//! Content-addressed, key-free evidence for one finalized Vultisig Bitcoin
//! spend.
//!
//! The configured DKLS participant set recorded here is operational evidence,
//! not a claim that Bitcoin exposes participant roles. The on-chain witness
//! contains only the aggregate public key and one aggregate signature per
//! input.

use std::collections::HashSet;

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::hashes::{sha256, Hash as _};
use bitcoin::{Txid, Wtxid};
use serde::{Serialize, Serializer};
use xindex_custody_core::btc_authorize::BtcCertificateSubject;
use xindex_shared::chain_registry::ChainId;

use crate::{FinalizedBitcoinSpend, PolicyError};

const EVIDENCE_SCHEMA: &str = "xindex.vultisig.bitcoin.aggregate-signature-evidence.v1";
const EVIDENCE_ID_DOMAIN: &[u8] = b"XINDEX/VULTISIG/BTC-AGGREGATE-EVIDENCE/V1";
const MAX_OPAQUE_ID_BYTES: usize = 256;

/// One configured DKLS participant identity.
///
/// `identity_sha256` commits to the reviewed participant/operator identity
/// record. It is deliberately separate from the aggregate Bitcoin public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VultisigParticipantIdentity {
    party_id: String,
    identity_sha256: [u8; 32],
}

impl VultisigParticipantIdentity {
    /// Bind one opaque upstream party ID to one reviewed identity record.
    ///
    /// # Errors
    /// Empty, non-canonical, oversized IDs and zero identity hashes fail.
    pub fn new(
        party_id: impl Into<String>,
        identity_sha256: [u8; 32],
    ) -> Result<Self, PolicyError> {
        let party_id = party_id.into();
        validate_opaque_id(
            "vultisig_evidence_participant",
            "participant party ID",
            &party_id,
        )?;
        if identity_sha256 == [0; 32] {
            return Err(PolicyError::new(
                "vultisig_evidence_participant",
                "participant identity SHA-256 must be non-zero",
            ));
        }
        Ok(Self {
            party_id,
            identity_sha256,
        })
    }

    /// Exact opaque party ID supplied by the pinned Vultisig release.
    #[must_use]
    pub fn party_id(&self) -> &str {
        &self.party_id
    }

    /// SHA-256 of the reviewed participant/operator identity record.
    #[must_use]
    pub const fn identity_sha256(&self) -> [u8; 32] {
        self.identity_sha256
    }
}

/// Reviewed Vultisig release, vault topology, and signing-session context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VultisigSessionContext {
    upstream_release_manifest_sha256: [u8; 32],
    vault_id: String,
    participants: Vec<VultisigParticipantIdentity>,
    threshold: u16,
    session_id: String,
    reshare_epoch: u64,
}

impl VultisigSessionContext {
    /// Validate and canonicalize one configured DKLS session context.
    ///
    /// The release-manifest digest must identify a separately reviewed manifest
    /// that pins the SDK, Verifier, Recipes engine, DKLS implementation,
    /// dependency graph, binaries, and licences. This type does not claim that
    /// such a manifest has been reviewed merely because a non-zero digest was
    /// supplied.
    ///
    /// # Errors
    /// Zero release identity, invalid opaque IDs, an empty/collapsed participant
    /// set, or a threshold outside `1..=participants.len()` fails closed.
    pub fn new(
        upstream_release_manifest_sha256: [u8; 32],
        vault_id: impl Into<String>,
        mut participants: Vec<VultisigParticipantIdentity>,
        threshold: u16,
        session_id: impl Into<String>,
        reshare_epoch: u64,
    ) -> Result<Self, PolicyError> {
        if upstream_release_manifest_sha256 == [0; 32] {
            return Err(PolicyError::new(
                "vultisig_evidence_release",
                "upstream release-manifest SHA-256 must be non-zero",
            ));
        }
        let vault_id = vault_id.into();
        validate_opaque_id("vultisig_evidence_vault", "vault ID", &vault_id)?;
        let session_id = session_id.into();
        validate_opaque_id("vultisig_evidence_session", "session ID", &session_id)?;
        if participants.is_empty() {
            return Err(PolicyError::new(
                "vultisig_evidence_participants",
                "configured DKLS participant set must be non-empty",
            ));
        }
        let participant_count = u16::try_from(participants.len()).map_err(|_| {
            PolicyError::new(
                "vultisig_evidence_participants",
                "configured DKLS participant count exceeds u16",
            )
        })?;
        participants.sort_by(|left, right| left.party_id.cmp(&right.party_id));
        if participants
            .windows(2)
            .any(|pair| pair[0].party_id == pair[1].party_id)
        {
            return Err(PolicyError::new(
                "vultisig_evidence_participants",
                "configured DKLS participant party IDs must be distinct",
            ));
        }
        let mut identity_hashes = HashSet::with_capacity(participants.len());
        if participants
            .iter()
            .any(|participant| !identity_hashes.insert(participant.identity_sha256))
        {
            return Err(PolicyError::new(
                "vultisig_evidence_participants",
                "configured DKLS participant identity hashes must be distinct",
            ));
        }
        if threshold == 0 || threshold > participant_count {
            return Err(PolicyError::new(
                "vultisig_evidence_threshold",
                format!(
                    "DKLS threshold {threshold} is outside 1..={participant_count} configured participants"
                ),
            ));
        }
        Ok(Self {
            upstream_release_manifest_sha256,
            vault_id,
            participants,
            threshold,
            session_id,
            reshare_epoch,
        })
    }

    /// SHA-256 of the separately reviewed upstream release manifest.
    #[must_use]
    pub const fn upstream_release_manifest_sha256(&self) -> [u8; 32] {
        self.upstream_release_manifest_sha256
    }

    /// Exact opaque vault identity.
    #[must_use]
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    /// Canonically ordered configured DKLS participant set.
    #[must_use]
    pub fn participants(&self) -> &[VultisigParticipantIdentity] {
        &self.participants
    }

    /// Configured DKLS signing threshold.
    #[must_use]
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Exact opaque Vultisig signing-session identity.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Monotonic Xindex reshare epoch for this vault topology.
    #[must_use]
    pub const fn reshare_epoch(&self) -> u64 {
        self.reshare_epoch
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ParticipantEvidenceRecord {
    party_id: String,
    identity_sha256: String,
}

#[derive(Debug, Clone)]
enum CustodySubjectFacts {
    Redemption {
        redemption_id: [u8; 32],
        leg_index: u32,
    },
    AcquireCancel {
        cancel_id: [u8; 32],
        intent_id: [u8; 32],
        slot_index: u32,
    },
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum CustodySubjectRecord {
    Redemption {
        redemption_id: String,
        leg_index: u32,
    },
    AcquireCancel {
        cancel_id: String,
        intent_id: String,
        slot_index: u32,
    },
}

#[derive(Debug, Clone)]
struct CustodyEvidenceFacts {
    subject: CustodySubjectFacts,
    certificate_digest: [u8; 32],
    valid_until_unix: u64,
    authorization_observer_signers: Vec<[u8; 20]>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct CustodyEvidenceRecord {
    subject: CustodySubjectRecord,
    certificate_digest: String,
    valid_until_unix: u64,
    authorization_observer_signers: Vec<String>,
}

#[derive(Debug, Clone)]
struct EvidenceFacts {
    chain_hash: ChainHash,
    transaction_bytes: Vec<u8>,
    txid: [u8; 32],
    wtxid: [u8; 32],
    input_count: u64,
    aggregate_public_key: [u8; 33],
    provenance_id: [u8; 32],
    policy_id: [u8; 32],
    custody: CustodyEvidenceFacts,
}

impl EvidenceFacts {
    fn from_spend(spend: &FinalizedBitcoinSpend) -> Result<Self, PolicyError> {
        let custody = spend.custody();
        if custody.chain() != ChainId::Btc {
            return Err(PolicyError::new(
                "vultisig_evidence_chain",
                "finalized Vultisig evidence requires a BTC custody authorization",
            ));
        }
        if custody.spend_txid() != spend.txid() {
            return Err(PolicyError::new(
                "vultisig_evidence_txid",
                "custody one-shot transaction ID differs from the finalized transaction",
            ));
        }
        let subject = match custody.subject() {
            BtcCertificateSubject::Redemption {
                redemption_id,
                leg_index,
            } => CustodySubjectFacts::Redemption {
                redemption_id: redemption_id.0,
                leg_index: *leg_index,
            },
            BtcCertificateSubject::AcquireCancel {
                cancel_id,
                intent_id,
                slot_index,
            } => CustodySubjectFacts::AcquireCancel {
                cancel_id: cancel_id.0,
                intent_id: intent_id.0,
                slot_index: *slot_index,
            },
        };
        let authorization_observer_signers = custody
            .verified_signers()
            .iter()
            .map(|signer| {
                let mut bytes = [0u8; 20];
                bytes.copy_from_slice(signer.as_slice());
                bytes
            })
            .collect();
        let input_count = u64::try_from(spend.input_count()).map_err(|_| {
            PolicyError::new(
                "vultisig_evidence_inputs",
                "finalized Bitcoin input count exceeds u64",
            )
        })?;
        Ok(Self {
            chain_hash: spend.chain_hash(),
            transaction_bytes: spend.transaction_bytes().to_vec(),
            txid: spend.txid(),
            wtxid: spend.wtxid(),
            input_count,
            aggregate_public_key: spend.aggregate_public_key(),
            provenance_id: spend.provenance_id(),
            policy_id: spend.policy_id(),
            custody: CustodyEvidenceFacts {
                subject,
                certificate_digest: custody.certificate_digest().0,
                valid_until_unix: custody.valid_until_unix(),
                authorization_observer_signers,
            },
        })
    }
}

/// Serializable aggregate-signature evidence record.
///
/// The participant list is the configured DKLS vault topology supplied by the
/// reviewed runtime. It is not inferred from, and does not pretend to be
/// visible in, the Bitcoin witness.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VultisigBitcoinEvidenceRecord {
    schema: &'static str,
    network: &'static str,
    chain_genesis_hash: String,
    #[serde(serialize_with = "serialize_hex_32")]
    evidence_id_sha256: [u8; 32],
    upstream_release_manifest_sha256: String,
    vault_id: String,
    configured_dkls_participants: Vec<ParticipantEvidenceRecord>,
    threshold: u16,
    session_id: String,
    reshare_epoch: u64,
    aggregate_public_key: String,
    policy_id: String,
    provenance_id: String,
    txid: String,
    wtxid: String,
    transaction_sha256: String,
    transaction_hex: String,
    input_count: u64,
    custody_authorization: CustodyEvidenceRecord,
}

impl VultisigBitcoinEvidenceRecord {
    /// Schema identifier committed by this record.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        self.schema
    }

    /// Domain-separated SHA-256 committing every semantic field in the record.
    #[must_use]
    pub const fn evidence_id_sha256(&self) -> [u8; 32] {
        self.evidence_id_sha256
    }

    /// Conventional Bitcoin transaction ID.
    #[must_use]
    pub fn txid(&self) -> &str {
        &self.txid
    }

    /// Conventional Bitcoin witness transaction ID.
    #[must_use]
    pub fn wtxid(&self) -> &str {
        &self.wtxid
    }
}

/// Opaque evidence-bound handoff created only from a validated final spend.
///
/// This type owns the non-cloneable [`FinalizedBitcoinSpend`] and its exact
/// evidence record. It performs no network, signing, or broadcast action.
///
/// ```compile_fail
/// use xindex_vultisig_adapter::VultisigBitcoinEvidence;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<VultisigBitcoinEvidence>();
/// ```
///
/// ```compile_fail
/// use xindex_vultisig_adapter::{
///     FinalizedBitcoinSpend, VultisigBitcoinEvidence, VultisigBitcoinEvidenceRecord,
/// };
///
/// fn forge(
///     finalized_spend: FinalizedBitcoinSpend,
///     record: VultisigBitcoinEvidenceRecord,
/// ) -> VultisigBitcoinEvidence {
///     VultisigBitcoinEvidence { finalized_spend, record }
/// }
/// ```
#[derive(Debug)]
pub struct VultisigBitcoinEvidence {
    finalized_spend: FinalizedBitcoinSpend,
    record: VultisigBitcoinEvidenceRecord,
}

impl FinalizedBitcoinSpend {
    /// Consume this validated final-spend capability and bind the configured
    /// Vultisig release, vault topology, session, and reshare epoch into one
    /// evidence handoff.
    ///
    /// # Errors
    /// Fails closed if the custody and finalized transaction identities ever
    /// diverge or if the evidence preimage cannot be represented canonically.
    pub fn bind_vultisig_evidence(
        self,
        session: &VultisigSessionContext,
    ) -> Result<VultisigBitcoinEvidence, PolicyError> {
        let facts = EvidenceFacts::from_spend(&self)?;
        let record = build_evidence_record(&facts, session)?;
        Ok(VultisigBitcoinEvidence {
            finalized_spend: self,
            record,
        })
    }
}

impl VultisigBitcoinEvidence {
    /// Serializable content-addressed evidence record.
    #[must_use]
    pub const fn record(&self) -> &VultisigBitcoinEvidenceRecord {
        &self.record
    }

    /// Exact canonical transaction bytes retained by the validated handoff.
    #[must_use]
    pub fn transaction_bytes(&self) -> &[u8] {
        self.finalized_spend.transaction_bytes()
    }

    /// Exact Testnet4 chain identity carried through the policy and handoff.
    #[must_use]
    pub const fn chain_hash(&self) -> ChainHash {
        self.finalized_spend.chain_hash()
    }

    /// Exact approved transaction ID.
    #[must_use]
    pub const fn txid(&self) -> [u8; 32] {
        self.finalized_spend.txid()
    }

    /// Exact approved witness transaction ID.
    #[must_use]
    pub const fn wtxid(&self) -> [u8; 32] {
        self.finalized_spend.wtxid()
    }
}

fn build_evidence_record(
    facts: &EvidenceFacts,
    session: &VultisigSessionContext,
) -> Result<VultisigBitcoinEvidenceRecord, PolicyError> {
    if facts.chain_hash != ChainHash::TESTNET4 {
        return Err(PolicyError::new(
            "vultisig_evidence_chain",
            "aggregate evidence is restricted to exact Bitcoin Testnet4 identity",
        ));
    }
    if facts.transaction_bytes.is_empty() || facts.input_count == 0 {
        return Err(PolicyError::new(
            "vultisig_evidence_transaction",
            "finalized transaction evidence must be non-empty and have at least one input",
        ));
    }
    if !matches!(facts.aggregate_public_key[0], 0x02 | 0x03) {
        return Err(PolicyError::new(
            "vultisig_evidence_pubkey",
            "aggregate public key must be compressed secp256k1",
        ));
    }
    let transaction_sha256 = sha256::Hash::hash(&facts.transaction_bytes).to_byte_array();
    let evidence_id = compute_evidence_id(facts, session, transaction_sha256)?;
    let participants = session
        .participants
        .iter()
        .map(|participant| ParticipantEvidenceRecord {
            party_id: participant.party_id.clone(),
            identity_sha256: encode_hex(&participant.identity_sha256),
        })
        .collect();
    let custody_authorization = CustodyEvidenceRecord {
        subject: subject_record(&facts.custody.subject),
        certificate_digest: encode_hex(&facts.custody.certificate_digest),
        valid_until_unix: facts.custody.valid_until_unix,
        authorization_observer_signers: facts
            .custody
            .authorization_observer_signers
            .iter()
            .map(|signer| format!("0x{}", encode_hex(signer)))
            .collect(),
    };
    Ok(VultisigBitcoinEvidenceRecord {
        schema: EVIDENCE_SCHEMA,
        network: "bitcoin-testnet4",
        chain_genesis_hash: facts.chain_hash.to_string(),
        evidence_id_sha256: evidence_id,
        upstream_release_manifest_sha256: encode_hex(&session.upstream_release_manifest_sha256),
        vault_id: session.vault_id.clone(),
        configured_dkls_participants: participants,
        threshold: session.threshold,
        session_id: session.session_id.clone(),
        reshare_epoch: session.reshare_epoch,
        aggregate_public_key: encode_hex(&facts.aggregate_public_key),
        policy_id: encode_hex(&facts.policy_id),
        provenance_id: encode_hex(&facts.provenance_id),
        txid: Txid::from_byte_array(facts.txid).to_string(),
        wtxid: Wtxid::from_byte_array(facts.wtxid).to_string(),
        transaction_sha256: encode_hex(&transaction_sha256),
        transaction_hex: encode_hex(&facts.transaction_bytes),
        input_count: facts.input_count,
        custody_authorization,
    })
}

fn compute_evidence_id(
    facts: &EvidenceFacts,
    session: &VultisigSessionContext,
    transaction_sha256: [u8; 32],
) -> Result<[u8; 32], PolicyError> {
    let mut bytes = Vec::new();
    append_len_prefixed(&mut bytes, EVIDENCE_ID_DOMAIN)?;
    bytes.extend_from_slice(facts.chain_hash.as_bytes());
    bytes.extend_from_slice(&facts.policy_id);
    bytes.extend_from_slice(&facts.provenance_id);
    append_custody_subject(&mut bytes, &facts.custody.subject);
    bytes.extend_from_slice(&facts.custody.certificate_digest);
    bytes.extend_from_slice(&facts.custody.valid_until_unix.to_be_bytes());
    append_count(
        &mut bytes,
        facts.custody.authorization_observer_signers.len(),
    )?;
    for signer in &facts.custody.authorization_observer_signers {
        bytes.extend_from_slice(signer);
    }
    bytes.extend_from_slice(&facts.txid);
    bytes.extend_from_slice(&facts.wtxid);
    bytes.extend_from_slice(&transaction_sha256);
    bytes.extend_from_slice(&facts.input_count.to_be_bytes());
    bytes.extend_from_slice(&facts.aggregate_public_key);
    bytes.extend_from_slice(&session.upstream_release_manifest_sha256);
    append_len_prefixed(&mut bytes, session.vault_id.as_bytes())?;
    append_count(&mut bytes, session.participants.len())?;
    for participant in &session.participants {
        append_len_prefixed(&mut bytes, participant.party_id.as_bytes())?;
        bytes.extend_from_slice(&participant.identity_sha256);
    }
    bytes.extend_from_slice(&session.threshold.to_be_bytes());
    append_len_prefixed(&mut bytes, session.session_id.as_bytes())?;
    bytes.extend_from_slice(&session.reshare_epoch.to_be_bytes());
    Ok(sha256::Hash::hash(&bytes).to_byte_array())
}

fn append_custody_subject(bytes: &mut Vec<u8>, subject: &CustodySubjectFacts) {
    match subject {
        CustodySubjectFacts::Redemption {
            redemption_id,
            leg_index,
        } => {
            bytes.push(0);
            bytes.extend_from_slice(redemption_id);
            bytes.extend_from_slice(&leg_index.to_be_bytes());
        }
        CustodySubjectFacts::AcquireCancel {
            cancel_id,
            intent_id,
            slot_index,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(cancel_id);
            bytes.extend_from_slice(intent_id);
            bytes.extend_from_slice(&slot_index.to_be_bytes());
        }
    }
}

fn subject_record(subject: &CustodySubjectFacts) -> CustodySubjectRecord {
    match subject {
        CustodySubjectFacts::Redemption {
            redemption_id,
            leg_index,
        } => CustodySubjectRecord::Redemption {
            redemption_id: encode_hex(redemption_id),
            leg_index: *leg_index,
        },
        CustodySubjectFacts::AcquireCancel {
            cancel_id,
            intent_id,
            slot_index,
        } => CustodySubjectRecord::AcquireCancel {
            cancel_id: encode_hex(cancel_id),
            intent_id: encode_hex(intent_id),
            slot_index: *slot_index,
        },
    }
}

fn append_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), PolicyError> {
    let count = u64::try_from(count).map_err(|_| {
        PolicyError::new(
            "vultisig_evidence_encoding",
            "evidence item count exceeds u64",
        )
    })?;
    bytes.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn append_len_prefixed(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), PolicyError> {
    append_count(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}

fn validate_opaque_id(code: &'static str, label: &str, value: &str) -> Result<(), PolicyError> {
    if value.is_empty()
        || value.len() > MAX_OPAQUE_ID_BYTES
        || value.trim() != value
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(PolicyError::new(
            code,
            format!("{label} must be 1..={MAX_OPAQUE_ID_BYTES} canonical printable ASCII bytes"),
        ));
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn serialize_hex_32<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&encode_hex(value))
}

#[cfg(test)]
fn evidence_facts() -> EvidenceFacts {
    let mut aggregate_public_key = [0x33; 33];
    aggregate_public_key[0] = 0x02;
    EvidenceFacts {
        chain_hash: ChainHash::TESTNET4,
        transaction_bytes: vec![0x02, 0x00, 0x01, 0x00],
        txid: [0x44; 32],
        wtxid: [0x55; 32],
        input_count: 2,
        aggregate_public_key,
        provenance_id: [0x66; 32],
        policy_id: [0x77; 32],
        custody: CustodyEvidenceFacts {
            subject: CustodySubjectFacts::Redemption {
                redemption_id: [0x88; 32],
                leg_index: 3,
            },
            certificate_digest: [0x99; 32],
            valid_until_unix: 1_750_003_600,
            authorization_observer_signers: vec![[0xaa; 20], [0xbb; 20], [0xcc; 20]],
        },
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        clippy::panic_in_result_fn,
        clippy::too_many_lines,
        reason = "test code"
    )]

    use super::*;

    fn participant(
        party_id: &str,
        fingerprint: u8,
    ) -> Result<VultisigParticipantIdentity, PolicyError> {
        VultisigParticipantIdentity::new(party_id, [fingerprint; 32])
    }

    fn context(
        participants: Vec<VultisigParticipantIdentity>,
        threshold: u16,
    ) -> Result<VultisigSessionContext, PolicyError> {
        VultisigSessionContext::new(
            [0x11; 32],
            "vault-testnet4-01",
            participants,
            threshold,
            "550e8400-e29b-41d4-a716-446655440000",
            7,
        )
    }

    #[test]
    fn session_context_canonicalizes_the_configured_participant_set() -> Result<(), PolicyError> {
        let first = context(
            vec![
                participant("party-c", 3)?,
                participant("party-a", 1)?,
                participant("party-b", 2)?,
            ],
            2,
        )?;
        let second = context(
            vec![
                participant("party-b", 2)?,
                participant("party-c", 3)?,
                participant("party-a", 1)?,
            ],
            2,
        )?;

        assert_eq!(first, second);
        assert_eq!(
            first
                .participants()
                .iter()
                .map(VultisigParticipantIdentity::party_id)
                .collect::<Vec<_>>(),
            ["party-a", "party-b", "party-c"]
        );
        Ok(())
    }

    #[test]
    fn session_context_rejects_ambiguous_or_collapsed_topology() -> Result<(), PolicyError> {
        let duplicate_id = context(
            vec![participant("party-a", 1)?, participant("party-a", 2)?],
            2,
        )
        .expect_err("duplicate party ID must fail");
        assert_eq!(duplicate_id.code(), "vultisig_evidence_participants");

        let duplicate_identity = context(
            vec![participant("party-a", 1)?, participant("party-b", 1)?],
            2,
        )
        .expect_err("duplicate participant identity must fail");
        assert_eq!(duplicate_identity.code(), "vultisig_evidence_participants");

        let zero_threshold =
            context(vec![participant("party-a", 1)?], 0).expect_err("zero threshold must fail");
        assert_eq!(zero_threshold.code(), "vultisig_evidence_threshold");

        let oversized_threshold = context(vec![participant("party-a", 1)?], 2)
            .expect_err("threshold above participant count must fail");
        assert_eq!(oversized_threshold.code(), "vultisig_evidence_threshold");
        Ok(())
    }

    #[test]
    fn session_context_rejects_unbound_release_and_noncanonical_ids() -> Result<(), PolicyError> {
        let zero_release = VultisigSessionContext::new(
            [0; 32],
            "vault-testnet4-01",
            vec![participant("party-a", 1)?],
            1,
            "550e8400-e29b-41d4-a716-446655440000",
            0,
        )
        .expect_err("zero release identity must fail");
        assert_eq!(zero_release.code(), "vultisig_evidence_release");

        let zero_participant = VultisigParticipantIdentity::new("party-a", [0; 32])
            .expect_err("zero participant identity must fail");
        assert_eq!(zero_participant.code(), "vultisig_evidence_participant");

        let spaced_participant = VultisigParticipantIdentity::new("party a", [1; 32])
            .expect_err("ambiguous participant ID must fail");
        assert_eq!(spaced_participant.code(), "vultisig_evidence_participant");

        let invalid_vault = VultisigSessionContext::new(
            [0x11; 32],
            "vault-testnet4-01 ",
            vec![participant("party-a", 1)?],
            1,
            "550e8400-e29b-41d4-a716-446655440000",
            0,
        )
        .expect_err("non-canonical vault ID must fail");
        assert_eq!(invalid_vault.code(), "vultisig_evidence_vault");

        let invalid_session = VultisigSessionContext::new(
            [0x11; 32],
            "vault-testnet4-01",
            vec![participant("party-a", 1)?],
            1,
            "session id",
            0,
        )
        .expect_err("non-canonical session ID must fail");
        assert_eq!(invalid_session.code(), "vultisig_evidence_session");
        Ok(())
    }

    #[test]
    fn aggregate_record_binds_every_required_identity_without_claiming_onchain_roles(
    ) -> Result<(), PolicyError> {
        let facts = evidence_facts();
        let session = context(
            vec![participant("party-b", 2)?, participant("party-a", 1)?],
            2,
        )?;
        let record = build_evidence_record(&facts, &session)?;
        let json = serde_json::to_value(&record).expect("serialize evidence");

        assert_eq!(json["schema"], EVIDENCE_SCHEMA);
        assert_eq!(json["threshold"], 2);
        assert_eq!(json["reshareEpoch"], 7);
        assert_eq!(json["configuredDklsParticipants"][0]["partyId"], "party-a");
        assert_eq!(json["configuredDklsParticipants"][1]["partyId"], "party-b");
        assert!(json.get("onchainSigners").is_none());
        assert_ne!(record.evidence_id_sha256(), [0; 32]);
        Ok(())
    }

    #[test]
    fn aggregate_record_identity_changes_for_policy_transaction_and_session_mutations(
    ) -> Result<(), PolicyError> {
        let facts = evidence_facts();
        let session = context(
            vec![participant("party-a", 1)?, participant("party-b", 2)?],
            2,
        )?;
        let baseline = build_evidence_record(&facts, &session)?.evidence_id_sha256();

        let fact_variants = [
            {
                let mut changed = facts.clone();
                changed.policy_id = [0x91; 32];
                changed
            },
            {
                let mut changed = facts.clone();
                changed.provenance_id = [0x92; 32];
                changed
            },
            {
                let mut changed = facts.clone();
                changed.transaction_bytes.push(0x01);
                changed
            },
            {
                let mut changed = facts.clone();
                changed.txid = [0x93; 32];
                changed
            },
            {
                let mut changed = facts.clone();
                changed.wtxid = [0x94; 32];
                changed
            },
            {
                let mut changed = facts.clone();
                changed.aggregate_public_key[1] ^= 0x01;
                changed
            },
            {
                let mut changed = facts.clone();
                changed.custody.certificate_digest = [0x95; 32];
                changed
            },
            {
                let mut changed = facts.clone();
                changed.custody.valid_until_unix += 1;
                changed
            },
            {
                let mut changed = facts.clone();
                changed.custody.authorization_observer_signers[0][0] ^= 0x01;
                changed
            },
        ];
        for changed in fact_variants {
            assert_ne!(
                build_evidence_record(&changed, &session)?.evidence_id_sha256(),
                baseline
            );
        }

        let changed_sessions = [
            VultisigSessionContext::new(
                [0x12; 32],
                "vault-testnet4-01",
                vec![participant("party-a", 1)?, participant("party-b", 2)?],
                2,
                "550e8400-e29b-41d4-a716-446655440000",
                7,
            )?,
            VultisigSessionContext::new(
                [0x11; 32],
                "vault-testnet4-02",
                vec![participant("party-a", 1)?, participant("party-b", 2)?],
                2,
                "550e8400-e29b-41d4-a716-446655440000",
                7,
            )?,
            VultisigSessionContext::new(
                [0x11; 32],
                "vault-testnet4-01",
                vec![participant("party-a", 1)?, participant("party-b", 3)?],
                2,
                "550e8400-e29b-41d4-a716-446655440000",
                7,
            )?,
            VultisigSessionContext::new(
                [0x11; 32],
                "vault-testnet4-01",
                vec![participant("party-a", 1)?, participant("party-b", 2)?],
                1,
                "550e8400-e29b-41d4-a716-446655440000",
                7,
            )?,
            VultisigSessionContext::new(
                [0x11; 32],
                "vault-testnet4-01",
                vec![participant("party-a", 1)?, participant("party-b", 2)?],
                2,
                "550e8400-e29b-41d4-a716-446655440001",
                7,
            )?,
            VultisigSessionContext::new(
                [0x11; 32],
                "vault-testnet4-01",
                vec![participant("party-a", 1)?, participant("party-b", 2)?],
                2,
                "550e8400-e29b-41d4-a716-446655440000",
                8,
            )?,
        ];
        for changed in changed_sessions {
            assert_ne!(
                build_evidence_record(&facts, &changed)?.evidence_id_sha256(),
                baseline
            );
        }
        Ok(())
    }
}
