//! CTD-1 (`DL-CTD-2` Slice B): the thin relay's RIC collection.
//!
//! Before the executor dispatches a custody spend, it must attach a
//! k-of-n [`IntentProof`]. The [`RicCollector`] fans an
//! [`ObserverCertifyRequest`] out to the operators' per-operator
//! observer services, gathers their [`ObserverCertifyResponse`]s, and
//! assembles the proof with [`assemble_intent_proof`].
//!
//! The collector is UNTRUSTED ([[DL-M2B-1]]/`DL-CTD-1`): it performs no
//! cryptography and is purely a fan-in. Every observer derives the
//! certified fields from its OWN sources (its Ethereum RPC + its
//! diverse ≥2 `THORChain` sources) and signs with its OWN Set-B daemon;
//! the custody daemon then re-verifies the assembled proof statelessly.
//! A compromised collector can only fail to assemble a proof — it can
//! never forge one, because it cannot produce k-of-n Set-B signatures
//! over a poisoned destination.
//!
//! Per-observer failures are tolerated up to `n - quorum`: the round
//! succeeds as long as `quorum` observers return certificates that
//! agree on one plaintext. A LESS-than-quorum result is a hard error —
//! the executor never dispatches a custody spend without a complete
//! proof (the daemon would reject it anyway, fail-closed).

use std::time::Duration;

use alloy_primitives::B256;
use tracing::warn;
use xindex_shared::chain_registry::ChainId;
use xindex_shared::ric_relay::{assemble_intent_proof, RelayAssemblyError};
use xindex_shared::signer_wire::{IntentProof, ObserverCertifyRequest, ObserverCertifyResponse};

/// Default per-observer HTTP timeout. An observer must resolve Asgard
/// across ≥2 `THORChain` sources before answering, so the budget is
/// looser than a bare signing call but still bounded.
const DEFAULT_TIMEOUT_SECS: u64 = 20;

/// Path of the per-operator observer's certify endpoint.
const CERTIFY_PATH: &str = "/api/v1/certify-ric";

/// A successfully collected k-of-n certificate plus the Asgard inbound
/// the operators agreed on. The executor pays to THIS address (not its
/// own independent resolution) so the spend it builds matches the
/// certified `immediate_target_hash` the custody daemon binds — the
/// observers' k-of-n resolution is authoritative end-to-end.
#[derive(Debug, Clone)]
pub struct CollectedRic {
    /// The assembled k-of-n proof to attach to the spend request.
    pub proof: IntentProof,
    /// The plaintext Asgard inbound address the agreeing observers
    /// resolved (the address whose hash is `proof.immediate_target_hash`).
    pub asgard_address: String,
}

/// Errors collecting a k-of-n RIC.
#[derive(Debug, thiserror::Error)]
pub enum RicCollectError {
    /// Fewer observer URLs configured than the quorum — the collector
    /// could never assemble a proof. Surfaced at construction.
    #[error("{configured} observer URL(s) configured, need ≥ quorum {quorum}")]
    NotEnoughObservers { configured: usize, quorum: usize },
    /// The collected certifications did not assemble into a quorum
    /// proof (too few observers responded, or they split across
    /// incompatible Asgard resolutions).
    #[error("could not assemble quorum RIC: {0}")]
    Assembly(#[from] RelayAssemblyError),
}

/// Posts certify requests to the operators' observer services and
/// assembles the k-of-n [`IntentProof`].
#[derive(Debug, Clone)]
pub struct RicCollector {
    observer_urls: Vec<String>,
    quorum: usize,
    http: reqwest::blocking::Client,
}

impl RicCollector {
    /// Build a collector over the operators' observer base URLs (e.g.
    /// `http://operator-1.internal:9101`), requiring `quorum` agreeing
    /// certificates.
    ///
    /// # Errors
    /// [`RicCollectError::NotEnoughObservers`] if fewer URLs than the
    /// quorum — fail closed at startup, never silently degrade.
    pub fn new(observer_urls: Vec<String>, quorum: usize) -> Result<Self, RicCollectError> {
        Self::with_timeout(
            observer_urls,
            quorum,
            Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        )
    }

    /// As [`RicCollector::new`] with an explicit per-observer timeout.
    ///
    /// # Errors
    /// [`RicCollectError::NotEnoughObservers`].
    pub fn with_timeout(
        observer_urls: Vec<String>,
        quorum: usize,
        timeout: Duration,
    ) -> Result<Self, RicCollectError> {
        if quorum == 0 || observer_urls.len() < quorum {
            return Err(RicCollectError::NotEnoughObservers {
                configured: observer_urls.len(),
                quorum,
            });
        }
        let http = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        Ok(Self {
            observer_urls,
            quorum,
            http,
        })
    }

    /// Collect a k-of-n [`IntentProof`] for one redemption leg. Proposes
    /// `vault_resolved_at` as the shared issuance stamp; each observer
    /// clamps it locally and its Set-B daemon enforces its own signing
    /// window on top.
    ///
    /// # Errors
    /// [`RicCollectError::Assembly`] if fewer than `quorum` observers
    /// returned certificates agreeing on one plaintext.
    pub fn collect(
        &self,
        chain: ChainId,
        redemption_id: B256,
        leg_index: u32,
        vault_resolved_at: u64,
    ) -> Result<CollectedRic, RicCollectError> {
        let req = ObserverCertifyRequest {
            chain_id: chain,
            redemption_id: format!("{redemption_id:#x}"),
            leg_index: leg_index.to_string(),
            vault_resolved_at,
        };
        let mut responses: Vec<ObserverCertifyResponse> = Vec::new();
        for url in &self.observer_urls {
            match self.certify_one(url, &req) {
                Ok(resp) => responses.push(resp),
                // One observer down/disagreeing is tolerated up to
                // n - quorum; log and keep collecting.
                Err(e) => warn!(observer = %url, error = %e, "observer certify failed; skipping"),
            }
        }
        let proof = assemble_intent_proof(&responses, self.quorum)?;
        // Recover the agreed plaintext Asgard address from the winning
        // group (the responses whose certified target hashes to the
        // assembled proof's). They all carry the same address by
        // construction; take the first.
        let asgard_address = responses
            .iter()
            .find(|r| r.immediate_target_hash == proof.immediate_target_hash)
            .map(|r| r.asgard_address.clone())
            .unwrap_or_default();
        Ok(CollectedRic {
            proof,
            asgard_address,
        })
    }

    /// POST one certify request and pin the response. The relay does NOT
    /// verify signatures here (the custody daemon does); it only needs a
    /// well-formed response to feed the assembler.
    fn certify_one(
        &self,
        base_url: &str,
        req: &ObserverCertifyRequest,
    ) -> Result<ObserverCertifyResponse, String> {
        let url = format!("{base_url}{CERTIFY_PATH}");
        let resp = self
            .http
            .post(&url)
            .json(req)
            .send()
            .map_err(|e| format!("transport: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            // The observer's typed error code is in the JSON body; we
            // only log the status + raw body here (the relay never
            // branches on it — it just needs ≥ quorum agreeing certs).
            let body = resp.text().unwrap_or_default();
            return Err(format!("http {}: {body}", status.as_u16()));
        }
        resp.json::<ObserverCertifyResponse>()
            .map_err(|e| format!("response json: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cert_body(signer: u8, sig: u8, target: &str) -> serde_json::Value {
        serde_json::json!({
            "chain_id": "btc",
            "redemption_id": format!("0x{}", "ab".repeat(32)),
            "leg_index": "0",
            "asset_id": format!("0x{}", "a1".repeat(32)),
            "amount": "50000000",
            "amount_decimals": 8,
            "immediate_target_hash": target,
            "memo_hash": format!("0x{}", "ef".repeat(32)),
            "final_destination_hash": format!("0x{}", "12".repeat(32)),
            "vault_resolved_at": 1_750_000_000_u64,
            "asgard_address": "bc1qvault",
            "signature": format!("0x{}", format!("{sig:02x}").repeat(65)),
            "signer_address": format!("0x{}", format!("{signer:02x}").repeat(20)),
        })
    }

    const GOOD: &str = "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    async fn observer(signer: u8, sig: u8, target: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(CERTIFY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(cert_body(signer, sig, target)))
            .mount(&server)
            .await;
        server
    }

    async fn down_observer() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(CERTIFY_PATH))
            .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
                "code": "observer_asgard_unavailable",
                "message": "sources disagree"
            })))
            .mount(&server)
            .await;
        server
    }

    fn rid() -> B256 {
        B256::repeat_byte(0xab)
    }

    #[test]
    fn rejects_fewer_urls_than_quorum() {
        let err = RicCollector::new(vec!["http://a".to_string()], 2).expect_err("must reject");
        assert!(matches!(
            err,
            RicCollectError::NotEnoughObservers {
                configured: 1,
                quorum: 2
            }
        ));
    }

    #[test]
    fn rejects_zero_quorum() {
        let err = RicCollector::new(vec!["http://a".to_string()], 0).expect_err("must reject");
        assert!(matches!(err, RicCollectError::NotEnoughObservers { .. }));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn collects_quorum_from_three_agreeing_observers() {
        let a = observer(1, 0xa1, GOOD).await;
        let b = observer(2, 0xa2, GOOD).await;
        let c = observer(3, 0xa3, GOOD).await;
        let urls = vec![a.uri(), b.uri(), c.uri()];
        let collected = tokio::task::spawn_blocking(move || {
            RicCollector::new(urls, 2).expect("collector").collect(
                ChainId::Btc,
                rid(),
                0,
                1_750_000_000,
            )
        })
        .await
        .expect("join")
        .expect("assemble");
        assert_eq!(collected.proof.signatures.len(), 3);
        assert_eq!(collected.proof.immediate_target_hash, GOOD);
        assert_eq!(collected.asgard_address, "bc1qvault");
    }

    /// One observer down, two healthy + agreeing, quorum 2 → still
    /// assembles. The relay tolerates n - quorum failures.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn tolerates_one_down_observer_at_quorum() {
        let a = observer(1, 0xa1, GOOD).await;
        let b = observer(2, 0xa2, GOOD).await;
        let c = down_observer().await;
        let urls = vec![a.uri(), b.uri(), c.uri()];
        let collected = tokio::task::spawn_blocking(move || {
            RicCollector::new(urls, 2).expect("collector").collect(
                ChainId::Btc,
                rid(),
                0,
                1_750_000_000,
            )
        })
        .await
        .expect("join")
        .expect("assemble");
        assert_eq!(collected.proof.signatures.len(), 2);
    }

    /// Two down, one healthy, quorum 2 → cannot assemble.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sub_quorum_after_failures_errors() {
        let a = observer(1, 0xa1, GOOD).await;
        let b = down_observer().await;
        let c = down_observer().await;
        let urls = vec![a.uri(), b.uri(), c.uri()];
        let err = tokio::task::spawn_blocking(move || {
            RicCollector::new(urls, 2).expect("collector").collect(
                ChainId::Btc,
                rid(),
                0,
                1_750_000_000,
            )
        })
        .await
        .expect("join")
        .expect_err("must fail to assemble");
        assert!(matches!(err, RicCollectError::Assembly(_)));
    }
}
