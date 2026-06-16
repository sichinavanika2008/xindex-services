//! CTD-1 (`DL-CTD-2` refinement 1): diverse-source Asgard agreement.
//!
//! The k-of-n observer floor is only real when each operator resolves
//! the Asgard inbound from its **own, distinct** `THORChain` sources —
//! on a single shared source, "5 independent observers" collapses to
//! "1 source, 5 readers" and one MITM'd endpoint poisons every RIC at
//! once. [`AsgardAgreement`] queries ≥2 configured sources and refuses
//! to yield a vault unless **every responding source agrees** and at
//! least [`MIN_AGREEING_SOURCES`] responded.
//!
//! Strictness is deliberate (fail closed, loud): a *disagreement*
//! between an operator's own sources is an incident signal — one of
//! them is stale, partitioned, or hostile — never something to
//! majority-vote away silently. Halt flags are treated the same way:
//! if ANY agreeing source reports the chain halted or paused, the
//! resolution is refused (a deposit into a halted vault sits unswapped).

use futures_util::future::join_all;

use crate::client::{ThorClient, ThorError};
use crate::types::InboundAddress;

/// Minimum number of sources that must successfully respond (and agree)
/// before a vault resolution is accepted. Hardcoded — not operator-
/// tunable — so a config mistake cannot quietly reduce the gate to a
/// single source.
pub const MIN_AGREEING_SOURCES: usize = 2;

/// Why a diverse-source Asgard resolution was refused.
#[derive(Debug, thiserror::Error)]
pub enum AgreementError {
    /// Fewer than [`MIN_AGREEING_SOURCES`] clients were configured —
    /// the gate would be vacuous. Surfaced at construction.
    #[error("{got} THORChain source(s) configured, need ≥ {MIN_AGREEING_SOURCES}")]
    NotEnoughSourcesConfigured { got: usize },
    /// Fewer than [`MIN_AGREEING_SOURCES`] sources responded
    /// successfully. Carries each failure for the operator log.
    #[error("only {ok} of {total} THORChain sources responded (need ≥ {MIN_AGREEING_SOURCES}): {failures:?}")]
    NotEnoughResponses {
        ok: usize,
        total: usize,
        failures: Vec<String>,
    },
    /// A source returned no inbound entry for the requested chain.
    #[error("source #{source_idx} has no inbound address for chain {chain}")]
    ChainAbsent { source_idx: usize, chain: String },
    /// Two successful sources disagree on the vault — incident signal,
    /// never majority-voted away.
    #[error(
        "THORChain sources disagree on the {chain} Asgard inbound: \
         source #{a_source} says {a_address}, source #{b_source} says {b_address}"
    )]
    Disagreement {
        chain: String,
        a_source: usize,
        a_address: String,
        b_source: usize,
        b_address: String,
    },
    /// An agreeing source reports the chain halted/paused — refuse to
    /// certify a deposit into a paused vault.
    #[error("chain {chain} is halted/paused on THORChain source #{source_idx}")]
    Halted { chain: String, source_idx: usize },
}

/// Outcome of a halt-specific multi-source poll
/// ([`AsgardAgreement::poll_chain_halt`]).
///
/// Distinct from [`AsgardAgreement::resolve_agreed`], which checks the halt
/// flags only AFTER an address/router unanimity check and so returns
/// [`AgreementError::Disagreement`] (never a halt verdict) during a churn
/// rotation. This poll reads the halt flags DIRECTLY, independent of address
/// agreement, so a halt landing mid-churn is still seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaltOutcome {
    /// ≥[`MIN_AGREEING_SOURCES`] sources returned the chain entry and none
    /// report any halt/pause flag.
    Live,
    /// ≥[`MIN_AGREEING_SOURCES`] sources returned the chain entry and at
    /// least one reports `halted` / `*_paused`. Carries the first such source
    /// index for the operator log. ANY responding source's halt flag is
    /// sufficient (mirrors `resolve_agreed`): a hostile source can force a
    /// bounded, auto-expiring, quorum-reversible pause, but can never SUPPRESS
    /// a real halt — the safe direction for a containment trigger.
    Halted { source_idx: usize },
    /// Fewer than [`MIN_AGREEING_SOURCES`] sources returned the chain entry,
    /// so there is no decisive read. NOT a halt trigger — absence of evidence
    /// is not evidence of a halt, and a total outage already fails closed via
    /// the on-chain vault-freshness gate and the custody-spend dispatch gate.
    /// Carries a human-readable reason for the runbook log.
    Indeterminate { reason: String },
}

/// A set of independent `THORChain` sources with an all-must-agree
/// resolution gate. Construct once at startup with the operator's
/// configured (distinct) endpoints.
#[derive(Debug, Clone)]
pub struct AsgardAgreement {
    clients: Vec<ThorClient>,
}

impl AsgardAgreement {
    /// Build the gate over `clients`. Refuses fewer than
    /// [`MIN_AGREEING_SOURCES`] — an observer must never boot into a
    /// single-source configuration.
    ///
    /// # Errors
    /// [`AgreementError::NotEnoughSourcesConfigured`].
    pub fn new(clients: Vec<ThorClient>) -> Result<Self, AgreementError> {
        if clients.len() < MIN_AGREEING_SOURCES {
            return Err(AgreementError::NotEnoughSourcesConfigured { got: clients.len() });
        }
        Ok(Self { clients })
    }

    /// Resolve the inbound vault for `chain` (`"BTC"`, `"ETH"`, …) from
    /// every configured source concurrently and require unanimity among
    /// the ≥[`MIN_AGREEING_SOURCES`] successful responses.
    ///
    /// Agreement is on the load-bearing custody fields: `address` and
    /// `router`. Gas-rate fields may legitimately differ per node view
    /// and are NOT part of the agreement predicate. Halt/pause flags
    /// are OR'd: any agreeing source reporting a halt refuses the
    /// resolution.
    ///
    /// # Errors
    /// [`AgreementError`] on insufficient responses, a missing chain
    /// entry, any address/router disagreement, or any halt flag.
    pub async fn resolve_agreed(&self, chain: &str) -> Result<InboundAddress, AgreementError> {
        let results = join_all(
            self.clients
                .iter()
                .map(|c| async { c.fetch_inbound_addresses().await }),
        )
        .await;

        let total = results.len();
        let mut failures: Vec<String> = Vec::new();
        // (source index, entry) for each source that responded.
        let mut entries: Vec<(usize, InboundAddress)> = Vec::new();
        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(list) => match list.into_iter().find(|e| e.chain == chain) {
                    Some(entry) => entries.push((i, entry)),
                    None => {
                        return Err(AgreementError::ChainAbsent {
                            source_idx: i,
                            chain: chain.to_string(),
                        })
                    }
                },
                Err(e) => failures.push(format!("source #{i}: {}", redact_thor_error(&e))),
            }
        }
        if entries.len() < MIN_AGREEING_SOURCES {
            return Err(AgreementError::NotEnoughResponses {
                ok: entries.len(),
                total,
                failures,
            });
        }

        let (first_source, first) = (entries[0].0, entries[0].1.clone());
        for (source, entry) in &entries[1..] {
            if entry.address != first.address || entry.router != first.router {
                return Err(AgreementError::Disagreement {
                    chain: chain.to_string(),
                    a_source: first_source,
                    a_address: first.address,
                    b_source: *source,
                    b_address: entry.address.clone(),
                });
            }
        }
        for (source, entry) in &entries {
            if entry.halted || entry.chain_trading_paused || entry.global_trading_paused {
                return Err(AgreementError::Halted {
                    chain: chain.to_string(),
                    source_idx: *source,
                });
            }
        }
        Ok(first)
    }

    /// Poll the per-chain halt/pause flags across every configured source,
    /// INDEPENDENT of the address-agreement check. Drives the per-operator
    /// halt watchdog (`xindex-halt-watchdog`), which engages the on-chain
    /// `CustodyGuard.halt()` containment on a sustained halt so new mint and
    /// burn custody lifecycles fail closed while the chain is paused upstream.
    ///
    /// Returns [`HaltOutcome::Halted`] when ≥[`MIN_AGREEING_SOURCES`] sources
    /// returned the chain entry and ANY reports a halt/pause flag;
    /// [`HaltOutcome::Live`] when that quorum responded with none halted;
    /// otherwise [`HaltOutcome::Indeterminate`] (never a halt trigger). Unlike
    /// [`AsgardAgreement::resolve_agreed`], an address disagreement between
    /// sources does NOT mask the halt read.
    pub async fn poll_chain_halt(&self, chain: &str) -> HaltOutcome {
        let results = join_all(
            self.clients
                .iter()
                .map(|c| async { c.fetch_inbound_addresses().await }),
        )
        .await;

        let total = results.len();
        let mut responded_with_chain: usize = 0;
        let mut first_halted: Option<usize> = None;
        let mut failures: Vec<String> = Vec::new();
        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(list) => match list.into_iter().find(|e| e.chain == chain) {
                    Some(entry) => {
                        responded_with_chain += 1;
                        if first_halted.is_none()
                            && (entry.halted
                                || entry.chain_trading_paused
                                || entry.global_trading_paused)
                        {
                            first_halted = Some(i);
                        }
                    }
                    None => failures.push(format!("source #{i}: no inbound entry for {chain}")),
                },
                Err(e) => failures.push(format!("source #{i}: {}", redact_thor_error(&e))),
            }
        }

        if responded_with_chain < MIN_AGREEING_SOURCES {
            return HaltOutcome::Indeterminate {
                reason: format!(
                    "only {responded_with_chain} of {total} sources returned a {chain} entry \
                     (need ≥ {MIN_AGREEING_SOURCES}): {failures:?}"
                ),
            };
        }
        match first_halted {
            Some(source_idx) => HaltOutcome::Halted { source_idx },
            None => HaltOutcome::Live,
        }
    }
}

/// Compress a [`ThorError`] for the multi-source failure log without
/// dragging a full (possibly large) upstream body into the error chain.
/// Truncates on a CHAR boundary (a `THORChain` body may be UTF-8, so a
/// byte slice could split a codepoint and panic).
fn redact_thor_error(e: &ThorError) -> String {
    let s = e.to_string();
    if s.chars().count() > 200 {
        let head: String = s.chars().take(200).collect();
        format!("{head}…")
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn btc_entry(address: &str, halted: bool) -> serde_json::Value {
        serde_json::json!({
            "chain": "BTC",
            "pub_key": "thorpub1example",
            "address": address,
            "halted": halted,
            "global_trading_paused": false,
            "chain_trading_paused": false,
            "chain_lp_actions_paused": false
        })
    }

    async fn mock_source(entries: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/thorchain/inbound_addresses"))
            .respond_with(ResponseTemplate::new(200).set_body_json(entries))
            .mount(&server)
            .await;
        server
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn client_for(server: &MockServer) -> ThorClient {
        ThorClient::with_base_url(server.uri()).expect("client")
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn refuses_single_source_configuration() {
        let err = AsgardAgreement::new(vec![]).expect_err("zero sources must fail");
        assert!(matches!(
            err,
            AgreementError::NotEnoughSourcesConfigured { got: 0 }
        ));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn two_agreeing_sources_resolve() {
        let a = mock_source(serde_json::json!([btc_entry("bc1qvault", false)])).await;
        let b = mock_source(serde_json::json!([btc_entry("bc1qvault", false)])).await;
        let gate = AsgardAgreement::new(vec![client_for(&a), client_for(&b)]).expect("two sources");
        let vault = gate.resolve_agreed("BTC").await.expect("must agree");
        assert_eq!(vault.address, "bc1qvault");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn address_disagreement_is_a_hard_refusal() {
        let a = mock_source(serde_json::json!([btc_entry("bc1qvault", false)])).await;
        let b = mock_source(serde_json::json!([btc_entry("bc1qpoisoned", false)])).await;
        let gate = AsgardAgreement::new(vec![client_for(&a), client_for(&b)]).expect("two sources");
        let err = gate.resolve_agreed("BTC").await.expect_err("must refuse");
        assert!(matches!(err, AgreementError::Disagreement { .. }), "{err}");
    }

    /// Three sources, one poisoned: still a hard refusal — disagreement
    /// is an incident signal, never majority-voted away.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn two_of_three_majority_does_not_override_disagreement() {
        let a = mock_source(serde_json::json!([btc_entry("bc1qvault", false)])).await;
        let b = mock_source(serde_json::json!([btc_entry("bc1qvault", false)])).await;
        let c = mock_source(serde_json::json!([btc_entry("bc1qpoisoned", false)])).await;
        let gate = AsgardAgreement::new(vec![client_for(&a), client_for(&b), client_for(&c)])
            .expect("three sources");
        let err = gate.resolve_agreed("BTC").await.expect_err("must refuse");
        assert!(matches!(err, AgreementError::Disagreement { .. }), "{err}");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, clippy::panic, reason = "test code")]
    async fn one_source_down_leaves_sub_minimum_and_refuses() {
        let a = mock_source(serde_json::json!([btc_entry("bc1qvault", false)])).await;
        // Source b: unroutable port — transport failure.
        let b = ThorClient::with_base_url("http://127.0.0.1:1").expect("client");
        let gate = AsgardAgreement::new(vec![client_for(&a), b]).expect("two sources");
        let err = gate.resolve_agreed("BTC").await.expect_err("must refuse");
        match err {
            AgreementError::NotEnoughResponses {
                ok,
                total,
                failures,
            } => {
                assert_eq!(ok, 1);
                assert_eq!(total, 2);
                assert_eq!(failures.len(), 1);
            }
            other => panic!("wrong error: {other}"),
        }
    }

    /// Two live + one down still resolves: the gate needs ≥2 successful
    /// agreeing responses, not all-configured-responding.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn third_source_down_with_two_agreeing_still_resolves() {
        let a = mock_source(serde_json::json!([btc_entry("bc1qvault", false)])).await;
        let b = mock_source(serde_json::json!([btc_entry("bc1qvault", false)])).await;
        let c = ThorClient::with_base_url("http://127.0.0.1:1").expect("client");
        let gate =
            AsgardAgreement::new(vec![client_for(&a), client_for(&b), c]).expect("three sources");
        let vault = gate.resolve_agreed("BTC").await.expect("two agree");
        assert_eq!(vault.address, "bc1qvault");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn any_halt_flag_refuses() {
        let a = mock_source(serde_json::json!([btc_entry("bc1qvault", false)])).await;
        let b = mock_source(serde_json::json!([btc_entry("bc1qvault", true)])).await;
        let gate = AsgardAgreement::new(vec![client_for(&a), client_for(&b)]).expect("two sources");
        let err = gate.resolve_agreed("BTC").await.expect_err("must refuse");
        assert!(matches!(err, AgreementError::Halted { .. }), "{err}");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn chain_absent_on_any_source_refuses() {
        let a = mock_source(serde_json::json!([btc_entry("bc1qvault", false)])).await;
        let b = mock_source(serde_json::json!([])).await;
        let gate = AsgardAgreement::new(vec![client_for(&a), client_for(&b)]).expect("two sources");
        let err = gate.resolve_agreed("BTC").await.expect_err("must refuse");
        assert!(matches!(err, AgreementError::ChainAbsent { .. }), "{err}");
    }

    /// Gas-rate fields may differ per node view — NOT part of the
    /// agreement predicate (only address/router/halt are load-bearing).
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn gas_rate_difference_does_not_break_agreement() {
        let mut e1 = btc_entry("bc1qvault", false);
        e1["gas_rate"] = serde_json::json!("10");
        let mut e2 = btc_entry("bc1qvault", false);
        e2["gas_rate"] = serde_json::json!("12");
        let a = mock_source(serde_json::json!([e1])).await;
        let b = mock_source(serde_json::json!([e2])).await;
        let gate = AsgardAgreement::new(vec![client_for(&a), client_for(&b)]).expect("two sources");
        let vault = gate.resolve_agreed("BTC").await.expect("must agree");
        assert_eq!(vault.address, "bc1qvault");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn poll_halt_all_live_when_quorum_clean() {
        let a = mock_source(serde_json::json!([btc_entry("bc1qvault", false)])).await;
        let b = mock_source(serde_json::json!([btc_entry("bc1qvault", false)])).await;
        let gate = AsgardAgreement::new(vec![client_for(&a), client_for(&b)]).expect("two sources");
        assert_eq!(gate.poll_chain_halt("BTC").await, HaltOutcome::Live);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn poll_halt_any_source_halted_triggers() {
        let a = mock_source(serde_json::json!([btc_entry("bc1qvault", false)])).await;
        let b = mock_source(serde_json::json!([btc_entry("bc1qvault", true)])).await;
        let gate = AsgardAgreement::new(vec![client_for(&a), client_for(&b)]).expect("two sources");
        assert!(
            matches!(
                gate.poll_chain_halt("BTC").await,
                HaltOutcome::Halted { .. }
            ),
            "any responding source's halt flag must trigger"
        );
    }

    /// The reason `poll_chain_halt` exists separately from `resolve_agreed`:
    /// a halt landing DURING a churn rotation (addresses disagree) must still
    /// be seen. `resolve_agreed` returns `Disagreement` and never reaches its
    /// halt check; `poll_chain_halt` reads the flags independently.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn poll_halt_detected_during_address_churn() {
        let a = mock_source(serde_json::json!([btc_entry("bc1qOLD", true)])).await;
        let b = mock_source(serde_json::json!([btc_entry("bc1qNEW", false)])).await;
        let gate = AsgardAgreement::new(vec![client_for(&a), client_for(&b)]).expect("two sources");
        assert!(
            matches!(
                gate.resolve_agreed("BTC").await,
                Err(AgreementError::Disagreement { .. })
            ),
            "resolve_agreed masks the halt behind the address churn"
        );
        assert!(
            matches!(
                gate.poll_chain_halt("BTC").await,
                HaltOutcome::Halted { .. }
            ),
            "poll_chain_halt sees the halt regardless of the churn"
        );
    }

    /// A single responding source (the other down) is below quorum — even if
    /// it screams HALTED, the verdict is Indeterminate, never a halt trigger:
    /// one hostile/flaky source must not be able to freeze the protocol.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn poll_halt_sub_quorum_is_indeterminate() {
        let a = mock_source(serde_json::json!([btc_entry("bc1qvault", true)])).await;
        let b = ThorClient::with_base_url("http://127.0.0.1:1").expect("client");
        let gate = AsgardAgreement::new(vec![client_for(&a), b]).expect("two sources");
        assert!(
            matches!(
                gate.poll_chain_halt("BTC").await,
                HaltOutcome::Indeterminate { .. }
            ),
            "sub-quorum read must not trigger a halt"
        );
    }

    /// `chain_trading_paused` (not only `halted`) also trips the watchdog.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn poll_halt_chain_trading_paused_triggers() {
        let mut paused = btc_entry("bc1qvault", false);
        paused["chain_trading_paused"] = serde_json::json!(true);
        let a = mock_source(serde_json::json!([btc_entry("bc1qvault", false)])).await;
        let b = mock_source(serde_json::json!([paused])).await;
        let gate = AsgardAgreement::new(vec![client_for(&a), client_for(&b)]).expect("two sources");
        assert!(matches!(
            gate.poll_chain_halt("BTC").await,
            HaltOutcome::Halted { .. }
        ));
    }
}
