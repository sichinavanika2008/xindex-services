//! CTD-1 (`DL-CTD-2` Slice B): the thin relay's k-of-n RIC assembly.
//!
//! The relay fans an [`ObserverCertifyRequest`] out to the operators'
//! per-operator observer services and receives one
//! [`ObserverCertifyResponse`] each. Every honest observer that resolved
//! the SAME canonical Asgard inbound from its own diverse sources
//! produces a byte-identical [`RedemptionIntentCertificate`] plaintext;
//! only the signature + signer differ. This module groups the responses
//! by that plaintext and, for any plaintext ≥ `quorum` DISTINCT signers
//! agree on, assembles the [`IntentProof`] the custody daemon verifies.
//!
//! The relay is UNTRUSTED ([[DL-M2B-1]]/`DL-CTD-1`): it performs NO
//! cryptography and grants NO authority. It is a fan-in convenience.
//! Every field of the assembled proof is re-verified statelessly by the
//! custody daemon ([`crate::signer_wire::IntentProof`] →
//! `validate_intent_proof`), which recomputes the digest, recovers each
//! signature against its OWN static whitelist, and binds the spend. The
//! relay's only job is to find a plaintext that enough observers signed.
//!
//! Diverse-source teeth carry through to this layer for free: observers
//! that resolved DIFFERENT Asgard inbounds land in DIFFERENT plaintext
//! groups, so a poisoned minority cannot reach quorum and a poisoned
//! plurality still fails the daemon's whitelist/quorum re-check.

use crate::signer_wire::{
    AcquireCancelProof, IntentProof, ObserverCertifyAccResponse, ObserverCertifyResponse,
};

/// Why a set of observer certifications could not be assembled into a
/// quorum [`IntentProof`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayAssemblyError {
    /// No plaintext was certified by `quorum` or more DISTINCT signers.
    /// Carries the best (largest) distinct-signer count observed so the
    /// operator log shows how close the round came and whether observers
    /// split across incompatible Asgard resolutions.
    #[error(
        "no certified intent reached quorum {quorum}: best agreeing group had \
         {best_distinct} distinct signer(s) across {groups} plaintext group(s)"
    )]
    QuorumNotReached {
        quorum: usize,
        best_distinct: usize,
        groups: usize,
    },
    /// `quorum` was zero — a vacuous assembly that would accept an empty
    /// proof. Caller misconfiguration; fail closed.
    #[error("quorum must be ≥ 1")]
    ZeroQuorum,
}

/// The certified plaintext, byte-identical across all honest observers
/// that resolved the same Asgard inbound. Used as the group key — every
/// RIC-digest input EXCEPT the per-observer signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CertifiedPlaintext {
    chain_id: String,
    redemption_id: String,
    leg_index: String,
    asset_id: String,
    amount: String,
    amount_decimals: u8,
    immediate_target_hash: String,
    memo_hash: String,
    final_destination_hash: String,
    vault_resolved_at: u64,
    asgard_address: String,
}

impl CertifiedPlaintext {
    fn of(resp: &ObserverCertifyResponse) -> Self {
        Self {
            chain_id: format!("{:?}", resp.chain_id),
            redemption_id: resp.redemption_id.clone(),
            leg_index: resp.leg_index.clone(),
            asset_id: resp.asset_id.clone(),
            amount: resp.amount.clone(),
            amount_decimals: resp.amount_decimals,
            immediate_target_hash: resp.immediate_target_hash.clone(),
            memo_hash: resp.memo_hash.clone(),
            final_destination_hash: resp.final_destination_hash.clone(),
            vault_resolved_at: resp.vault_resolved_at,
            asgard_address: resp.asgard_address.clone(),
        }
    }
}

/// Quorum proof paired with the byte-identical raw target supplied by that
/// same distinct-signer quorum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledIntentProof {
    /// Signed certificate proof.
    pub proof: IntentProof,
    /// Exact raw Asgard address agreed by the proof's signer group.
    pub asgard_address: String,
}

/// Assemble a quorum [`IntentProof`] from observer certifications.
///
/// Groups `responses` by certified plaintext, deduplicates each group's
/// signatures by `signer_address` (an observer answering twice counts
/// once), and emits the proof for the FIRST plaintext whose distinct-
/// signer count reaches `quorum`. The signature ordering is the
/// dedup-insertion order of the responses; the daemon re-sorts on
/// recovery, so order is not load-bearing.
///
/// The daemon re-verifies everything — see the module docs — so this
/// function deliberately does NO signature recovery. It only needs to
/// surface a plaintext that enough DISTINCT observers signed.
///
/// # Errors
/// [`RelayAssemblyError::ZeroQuorum`] on `quorum == 0`;
/// [`RelayAssemblyError::QuorumNotReached`] when no plaintext gathered
/// `quorum` distinct signers (including the all-disagree case).
pub fn assemble_intent_proof(
    responses: &[ObserverCertifyResponse],
    quorum: usize,
) -> Result<IntentProof, RelayAssemblyError> {
    assemble_intent_proof_with_target(responses, quorum).map(|assembled| assembled.proof)
}

/// Assemble a proof and its exact raw target from one byte-identical quorum.
///
/// # Errors
/// Returns the same fail-closed errors as [`assemble_intent_proof`].
pub fn assemble_intent_proof_with_target(
    responses: &[ObserverCertifyResponse],
    quorum: usize,
) -> Result<AssembledIntentProof, RelayAssemblyError> {
    if quorum == 0 {
        return Err(RelayAssemblyError::ZeroQuorum);
    }
    // Preserve first-seen plaintext order for deterministic output.
    let mut groups: Vec<(CertifiedPlaintext, Vec<&ObserverCertifyResponse>)> = Vec::new();
    for resp in responses {
        let key = CertifiedPlaintext::of(resp);
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, members)) => {
                // Dedup by signer — one observer answering twice is one
                // vote. Distinct ON THE PLAINTEXT'S signer set.
                if !members
                    .iter()
                    .any(|m| m.signer_address.eq_ignore_ascii_case(&resp.signer_address))
                {
                    members.push(resp);
                }
            }
            None => groups.push((key, vec![resp])),
        }
    }

    let mut best_distinct = 0usize;
    for (plaintext, members) in &groups {
        best_distinct = best_distinct.max(members.len());
        if members.len() >= quorum {
            return Ok(AssembledIntentProof {
                proof: build_proof(plaintext, members),
                asgard_address: plaintext.asgard_address.clone(),
            });
        }
    }
    Err(RelayAssemblyError::QuorumNotReached {
        quorum,
        best_distinct,
        groups: groups.len(),
    })
}

/// Build the wire [`IntentProof`] from one agreeing group. The plaintext
/// fields come from the shared key; the signatures from each distinct
/// member.
fn build_proof(
    plaintext: &CertifiedPlaintext,
    members: &[&ObserverCertifyResponse],
) -> IntentProof {
    IntentProof {
        redemption_id: plaintext.redemption_id.clone(),
        leg_index: plaintext.leg_index.clone(),
        asset_id: plaintext.asset_id.clone(),
        amount: plaintext.amount.clone(),
        amount_decimals: plaintext.amount_decimals,
        immediate_target_hash: plaintext.immediate_target_hash.clone(),
        memo_hash: plaintext.memo_hash.clone(),
        final_destination_hash: plaintext.final_destination_hash.clone(),
        vault_resolved_at: plaintext.vault_resolved_at,
        signatures: members.iter().map(|m| m.signature.clone()).collect(),
    }
}

/// The certified ACC plaintext (CTD-1 Slice C tail) — the mint-cancel
/// sibling of [`CertifiedPlaintext`]. Byte-identical across all honest
/// observers that resolved the same Asgard inbound and pin the same
/// recovery destination.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CertifiedCancelPlaintext {
    chain_id: String,
    cancel_id: String,
    intent_id: String,
    slot_index: String,
    asset_id: String,
    amount: String,
    amount_decimals: u8,
    immediate_target_hash: String,
    memo_hash: String,
    final_destination_hash: String,
    vault_resolved_at: u64,
    asgard_address: String,
}

impl CertifiedCancelPlaintext {
    fn of(resp: &ObserverCertifyAccResponse) -> Self {
        Self {
            chain_id: format!("{:?}", resp.chain_id),
            cancel_id: resp.cancel_id.clone(),
            intent_id: resp.intent_id.clone(),
            slot_index: resp.slot_index.clone(),
            asset_id: resp.asset_id.clone(),
            amount: resp.amount.clone(),
            amount_decimals: resp.amount_decimals,
            immediate_target_hash: resp.immediate_target_hash.clone(),
            memo_hash: resp.memo_hash.clone(),
            final_destination_hash: resp.final_destination_hash.clone(),
            vault_resolved_at: resp.vault_resolved_at,
            asgard_address: resp.asgard_address.clone(),
        }
    }
}

/// Acquire-cancel quorum proof paired with its byte-identical raw target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledAcquireCancelProof {
    /// Signed certificate proof.
    pub proof: AcquireCancelProof,
    /// Exact raw Asgard address agreed by the proof's signer group.
    pub asgard_address: String,
}

/// Assemble a quorum [`AcquireCancelProof`] from observer ACC
/// certifications (CTD-1 Slice C tail) — the mint-cancel sibling of
/// [`assemble_intent_proof`], with the identical grouping / dedup /
/// quorum discipline and the identical trust model: the relay performs
/// NO cryptography; the custody daemon re-verifies the assembled proof
/// statelessly (`validate_acquire_cancel_proof`).
///
/// # Errors
/// [`RelayAssemblyError::ZeroQuorum`] on `quorum == 0`;
/// [`RelayAssemblyError::QuorumNotReached`] when no plaintext gathered
/// `quorum` distinct signers.
pub fn assemble_acquire_cancel_proof(
    responses: &[ObserverCertifyAccResponse],
    quorum: usize,
) -> Result<AcquireCancelProof, RelayAssemblyError> {
    assemble_acquire_cancel_proof_with_target(responses, quorum).map(|assembled| assembled.proof)
}

/// Assemble an acquire-cancel proof and exact raw target from one quorum.
///
/// # Errors
/// Returns the same fail-closed errors as [`assemble_acquire_cancel_proof`].
pub fn assemble_acquire_cancel_proof_with_target(
    responses: &[ObserverCertifyAccResponse],
    quorum: usize,
) -> Result<AssembledAcquireCancelProof, RelayAssemblyError> {
    if quorum == 0 {
        return Err(RelayAssemblyError::ZeroQuorum);
    }
    let mut groups: Vec<(CertifiedCancelPlaintext, Vec<&ObserverCertifyAccResponse>)> = Vec::new();
    for resp in responses {
        let key = CertifiedCancelPlaintext::of(resp);
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, members)) => {
                if !members
                    .iter()
                    .any(|m| m.signer_address.eq_ignore_ascii_case(&resp.signer_address))
                {
                    members.push(resp);
                }
            }
            None => groups.push((key, vec![resp])),
        }
    }

    let mut best_distinct = 0usize;
    for (plaintext, members) in &groups {
        best_distinct = best_distinct.max(members.len());
        if members.len() >= quorum {
            return Ok(AssembledAcquireCancelProof {
                proof: build_cancel_proof(plaintext, members),
                asgard_address: plaintext.asgard_address.clone(),
            });
        }
    }
    Err(RelayAssemblyError::QuorumNotReached {
        quorum,
        best_distinct,
        groups: groups.len(),
    })
}

/// Build the wire [`AcquireCancelProof`] from one agreeing group.
fn build_cancel_proof(
    plaintext: &CertifiedCancelPlaintext,
    members: &[&ObserverCertifyAccResponse],
) -> AcquireCancelProof {
    AcquireCancelProof {
        cancel_id: plaintext.cancel_id.clone(),
        intent_id: plaintext.intent_id.clone(),
        slot_index: plaintext.slot_index.clone(),
        asset_id: plaintext.asset_id.clone(),
        amount: plaintext.amount.clone(),
        amount_decimals: plaintext.amount_decimals,
        immediate_target_hash: plaintext.immediate_target_hash.clone(),
        memo_hash: plaintext.memo_hash.clone(),
        final_destination_hash: plaintext.final_destination_hash.clone(),
        vault_resolved_at: plaintext.vault_resolved_at,
        signatures: members.iter().map(|m| m.signature.clone()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_registry::ChainId;

    fn resp(signer: u8, sig: u8, asgard_hash: &str) -> ObserverCertifyResponse {
        ObserverCertifyResponse {
            chain_id: ChainId::Btc,
            redemption_id: format!("0x{}", "ab".repeat(32)),
            leg_index: "0".to_string(),
            asset_id: format!("0x{}", "a1".repeat(32)),
            amount: "50000000".to_string(),
            amount_decimals: 8,
            immediate_target_hash: asgard_hash.to_string(),
            memo_hash: format!("0x{}", "ef".repeat(32)),
            final_destination_hash: format!("0x{}", "12".repeat(32)),
            vault_resolved_at: 1_750_000_000,
            asgard_address: "bc1qvault".to_string(),
            signature: format!("0x{}", format!("{sig:02x}").repeat(65)),
            signer_address: format!("0x{}", format!("{signer:02x}").repeat(20)),
        }
    }

    fn resp_with_raw(
        signer: u8,
        sig: u8,
        asgard_hash: &str,
        asgard_address: &str,
    ) -> ObserverCertifyResponse {
        let mut response = resp(signer, sig, asgard_hash);
        response.asgard_address = asgard_address.to_string();
        response
    }

    const GOOD: &str = "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    const POISON: &str = "0x6666666666666666666666666666666666666666666666666666666666666666";

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn three_agreeing_observers_assemble_quorum() {
        let responses = vec![
            resp(1, 0xa1, GOOD),
            resp(2, 0xa2, GOOD),
            resp(3, 0xa3, GOOD),
        ];
        let proof = assemble_intent_proof(&responses, 2).expect("must assemble");
        assert_eq!(proof.signatures.len(), 3);
        assert_eq!(proof.immediate_target_hash, GOOD);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn exact_quorum_assembles() {
        let responses = vec![resp(1, 0xa1, GOOD), resp(2, 0xa2, GOOD)];
        let proof = assemble_intent_proof(&responses, 2).expect("must assemble");
        assert_eq!(proof.signatures.len(), 2);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn same_signed_hash_with_conflicting_raw_targets_never_reaches_quorum_in_any_order() {
        let honest = resp_with_raw(1, 0xa1, GOOD, "bc1qcanonical");
        let malicious = resp_with_raw(2, 0xa2, GOOD, "BC1QNONCANONICAL");
        for responses in [
            vec![honest.clone(), malicious.clone()],
            vec![malicious, honest],
        ] {
            let error = assemble_intent_proof(&responses, 2).expect_err("raw split must reject");
            assert_eq!(
                error,
                RelayAssemblyError::QuorumNotReached {
                    quorum: 2,
                    best_distinct: 1,
                    groups: 2,
                }
            );
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn sub_quorum_rejected() {
        let responses = vec![resp(1, 0xa1, GOOD)];
        let err = assemble_intent_proof(&responses, 2).expect_err("must reject");
        assert_eq!(
            err,
            RelayAssemblyError::QuorumNotReached {
                quorum: 2,
                best_distinct: 1,
                groups: 1,
            }
        );
    }

    /// A duplicate signer is ONE vote — two responses from signer 1 do
    /// not reach a quorum of 2.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn duplicate_signer_counts_once() {
        let responses = vec![resp(1, 0xa1, GOOD), resp(1, 0xa9, GOOD)];
        let err = assemble_intent_proof(&responses, 2).expect_err("must reject");
        assert!(matches!(
            err,
            RelayAssemblyError::QuorumNotReached {
                best_distinct: 1,
                ..
            }
        ));
    }

    /// The diverse-source teeth at the relay: a poisoned minority lands
    /// in its own plaintext group and never combines with the honest
    /// majority. With 2 honest + 1 poisoned and quorum 2, the honest
    /// group wins and the proof binds the GOOD target.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn poisoned_minority_does_not_dilute_honest_quorum() {
        let responses = vec![
            resp(1, 0xa1, GOOD),
            resp(2, 0xa2, GOOD),
            resp(3, 0xa3, POISON),
        ];
        let proof = assemble_intent_proof(&responses, 2).expect("honest group reaches quorum");
        assert_eq!(proof.immediate_target_hash, GOOD);
        assert_eq!(proof.signatures.len(), 2);
    }

    /// A split where NEITHER group reaches quorum fails — two honest on
    /// GOOD vs two on POISON, quorum 3: no agreement.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn even_split_below_quorum_fails() {
        let responses = vec![
            resp(1, 0xa1, GOOD),
            resp(2, 0xa2, GOOD),
            resp(3, 0xa3, POISON),
            resp(4, 0xa4, POISON),
        ];
        let err = assemble_intent_proof(&responses, 3).expect_err("must reject");
        assert!(matches!(
            err,
            RelayAssemblyError::QuorumNotReached {
                best_distinct: 2,
                groups: 2,
                ..
            }
        ));
    }

    #[test]
    fn zero_quorum_fails_closed() {
        let responses = vec![resp(1, 0xa1, GOOD)];
        assert_eq!(
            assemble_intent_proof(&responses, 0),
            Err(RelayAssemblyError::ZeroQuorum)
        );
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn empty_responses_reject() {
        let err = assemble_intent_proof(&[], 2).expect_err("must reject");
        assert!(matches!(
            err,
            RelayAssemblyError::QuorumNotReached {
                best_distinct: 0,
                groups: 0,
                ..
            }
        ));
    }

    fn acc_resp(signer: u8, sig: u8, asgard_hash: &str) -> ObserverCertifyAccResponse {
        ObserverCertifyAccResponse {
            chain_id: ChainId::Btc,
            cancel_id: format!("0x{}", "ac".repeat(32)),
            intent_id: format!("0x{}", "1d".repeat(32)),
            slot_index: "1".to_string(),
            asset_id: format!("0x{}", "a1".repeat(32)),
            amount: "50000000".to_string(),
            amount_decimals: 8,
            immediate_target_hash: asgard_hash.to_string(),
            memo_hash: format!("0x{}", "ef".repeat(32)),
            final_destination_hash: format!("0x{}", "12".repeat(32)),
            vault_resolved_at: 1_750_000_000,
            asgard_address: "bc1qvault".to_string(),
            signature: format!("0x{}", format!("{sig:02x}").repeat(65)),
            signer_address: format!("0x{}", format!("{signer:02x}").repeat(20)),
        }
    }

    fn acc_resp_with_raw(
        signer: u8,
        sig: u8,
        asgard_hash: &str,
        asgard_address: &str,
    ) -> ObserverCertifyAccResponse {
        let mut response = acc_resp(signer, sig, asgard_hash);
        response.asgard_address = asgard_address.to_string();
        response
    }

    /// CTD-1 Slice C tail: the ACC assembler applies the same grouping /
    /// dedup / quorum discipline as the RIC assembler.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn acc_quorum_assembles_with_full_plaintext() {
        let responses = vec![acc_resp(1, 0xa1, GOOD), acc_resp(2, 0xa2, GOOD)];
        let proof = assemble_acquire_cancel_proof(&responses, 2).expect("must assemble");
        assert_eq!(proof.signatures.len(), 2);
        assert_eq!(proof.cancel_id, format!("0x{}", "ac".repeat(32)));
        assert_eq!(proof.intent_id, format!("0x{}", "1d".repeat(32)));
        assert_eq!(proof.slot_index, "1");
        assert_eq!(proof.immediate_target_hash, GOOD);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn acc_same_signed_hash_with_conflicting_raw_targets_rejects() {
        let responses = vec![
            acc_resp_with_raw(1, 0xa1, GOOD, "bc1qcanonical"),
            acc_resp_with_raw(2, 0xa2, GOOD, "bc1qother"),
        ];
        let error =
            assemble_acquire_cancel_proof(&responses, 2).expect_err("raw split must reject");
        assert_eq!(
            error,
            RelayAssemblyError::QuorumNotReached {
                quorum: 2,
                best_distinct: 1,
                groups: 2,
            }
        );
    }

    /// A poisoned-target minority lands in its own ACC plaintext group
    /// and never dilutes the honest quorum.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn acc_poisoned_minority_does_not_dilute() {
        let responses = vec![
            acc_resp(1, 0xa1, GOOD),
            acc_resp(2, 0xa2, GOOD),
            acc_resp(3, 0xa3, POISON),
        ];
        let proof = assemble_acquire_cancel_proof(&responses, 2).expect("honest quorum");
        assert_eq!(proof.immediate_target_hash, GOOD);
        assert_eq!(proof.signatures.len(), 2);
    }

    /// A duplicate ACC signer is ONE vote.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn acc_duplicate_signer_counts_once() {
        let responses = vec![acc_resp(1, 0xa1, GOOD), acc_resp(1, 0xa9, GOOD)];
        let err = assemble_acquire_cancel_proof(&responses, 2).expect_err("must reject");
        assert!(matches!(
            err,
            RelayAssemblyError::QuorumNotReached {
                best_distinct: 1,
                ..
            }
        ));
    }

    #[test]
    fn acc_zero_quorum_fails_closed() {
        let responses = vec![acc_resp(1, 0xa1, GOOD)];
        assert_eq!(
            assemble_acquire_cancel_proof(&responses, 0),
            Err(RelayAssemblyError::ZeroQuorum)
        );
    }

    /// Signer-address comparison is case-insensitive — checksummed and
    /// lowercase forms of the same address are ONE signer.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn signer_dedup_is_case_insensitive() {
        let mut a = resp(1, 0xa1, GOOD);
        a.signer_address = "0xAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAb".to_string();
        let mut b = resp(1, 0xa2, GOOD);
        b.signer_address = "0xababababababababababababababababababababab"
            .chars()
            .take(42)
            .collect();
        let responses = vec![a, b];
        let err = assemble_intent_proof(&responses, 2).expect_err("same signer, one vote");
        assert!(matches!(
            err,
            RelayAssemblyError::QuorumNotReached {
                best_distinct: 1,
                ..
            }
        ));
    }
}
