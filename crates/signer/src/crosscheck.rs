//! Cross-chain validity check — the signer's #1 trust surface.
//!
//! Before producing an `Attestation` signature, the signer MUST verify
//! that the off-chain reality matches what the contract is being asked
//! to attest. For the BTC.BTC slot:
//!
//! 1. `THORChain`'s Bifrost observers have voted "done" on the inbound
//!    AND queued an outbound action targeting our Bitcoin multisig
//!    address (proves `THORChain` agreed to send the BTC).
//! 2. The Bitcoin chain has a confirmed UTXO at our multisig matching
//!    the expected amount and minimum confirmation depth (proves the
//!    BTC actually arrived — not just that `THORChain` *intended* to send).
//!
//! Either source alone is insufficient: a malicious or compromised
//! `THORChain` run-set could fake step 1; a long Bitcoin reorg could undo
//! step 2 alone. Requiring BOTH gives the signer two independent
//! observations of the same event before risking attestation.
//!
//! ## Variants
//!
//! - [`PassThroughPolicy`] — for local Anvil testing ONLY. Always
//!   succeeds; emits a `WARN` log so accidentally enabling it in
//!   production is loud rather than silent.
//! - [`ThorBtcPolicy`] — production. Hits `THORChain` RPC + a Bitcoin
//!   client; both must agree before [`CrossCheck::verify`] returns Ok.
//!
//! Tests use a hand-rolled in-memory mock to exercise the success path,
//! the "`THORChain` not done yet" path, and the "BTC not confirmed yet"
//! path without any network access.

use async_trait::async_trait;
use bitcoin::{Address, Amount, Network};
use thiserror::Error;
use tracing::{info, warn};

use xindex_chain_btc::{find_arrival, BitcoinChainClient, BitcoinError};
use xindex_chain_thor::{ThorClient, ThorError};

/// Errors surfaced by the cross-check.
#[derive(Debug, Error)]
pub enum CrossCheckError {
    #[error("`THORChain` RPC error: {0}")]
    Thor(#[from] ThorError),
    #[error("Bitcoin chain error: {0}")]
    Btc(#[from] BitcoinError),
    /// `THORChain` has not finished observing the inbound or has no
    /// matching outbound action yet. The signer should poll again
    /// later, NOT sign.
    #[error("`THORChain` not yet ready: {reason}")]
    ThorNotReady { reason: String },
    /// Bitcoin doesn't have a confirmed-enough UTXO at our multisig.
    /// Signer should poll again, NOT sign.
    #[error("Bitcoin UTXO not yet confirmed: needed ≥{needed_sats} sats with ≥{min_confs} confs")]
    BtcNotReady { needed_sats: u64, min_confs: u32 },
    /// `THORChain` agreed but the value doesn't match the on-chain claim.
    /// This is the classic "your inbound was fine but the swap routed
    /// to a different amount" — never sign for a wrong amount.
    #[error("amount mismatch: thor outbound {thor_sats} sats vs claim {claim_sats} sats")]
    AmountMismatch { thor_sats: u64, claim_sats: u64 },
}

/// Async trait so production impls can do RPC calls without blocking
/// the signer event loop. Tests provide an in-memory impl.
#[async_trait]
pub trait CrossCheck: Send + Sync {
    /// `intent_id` is the on-chain bytes32 identifier; the signer hands
    /// it to the policy to look up the corresponding partner-chain
    /// inbound transaction. `expected_sats` is the amount the contract
    /// claims arrived at our multisig — both `THORChain` and Bitcoin must
    /// agree on this number (within tolerance defined by the impl).
    async fn verify(
        &self,
        thor_inbound_tx_hash: &str,
        expected_sats: u64,
    ) -> Result<(), CrossCheckError>;
}

/// **DEV / TEST ONLY.** Always returns Ok. Use in Anvil end-to-end tests
/// where there is no real partner chain to observe.
///
/// Emits a `warn!` log on every call so accidentally wiring this into
/// a Sepolia or mainnet binary is impossible to miss in operator logs.
#[derive(Debug, Default)]
pub struct PassThroughPolicy;

#[async_trait]
impl CrossCheck for PassThroughPolicy {
    async fn verify(
        &self,
        _thor_inbound_tx_hash: &str,
        _expected_sats: u64,
    ) -> Result<(), CrossCheckError> {
        warn!(
            policy = "PassThroughPolicy",
            "cross-check SKIPPED — accept ONLY in Anvil/local tests"
        );
        Ok(())
    }
}

/// Production policy. Requires `THORChain` to report `done` with an
/// outbound action targeting `btc_multisig_address` AND a confirmed
/// Bitcoin UTXO of `expected_sats` (within `tolerance_sats`) at the
/// same address.
///
/// Holds owned clones of both clients; both must outlive the policy.
pub struct ThorBtcPolicy<C: BitcoinChainClient + Send + Sync> {
    thor: ThorClient,
    btc: C,
    btc_multisig_address: Address,
    /// Minimum confirmation depth required on the Bitcoin side. Default
    /// 6 (≈1 hour) for mainnet redemptions; tests use 1.
    min_confirmations: u32,
    /// Maximum allowed difference (in sats) between `THORChain`'s claimed
    /// outbound value and the actual arrived UTXO. Default 0 — exact
    /// equality. Operators can raise this to absorb known fee shapes
    /// if `THORChain`'s accounting and the on-chain UTXO ever diverge.
    tolerance_sats: u64,
}

impl<C: BitcoinChainClient + Send + Sync> std::fmt::Debug for ThorBtcPolicy<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThorBtcPolicy")
            .field("btc_multisig_address", &self.btc_multisig_address)
            .field("min_confirmations", &self.min_confirmations)
            .field("tolerance_sats", &self.tolerance_sats)
            .finish_non_exhaustive()
    }
}

impl<C: BitcoinChainClient + Send + Sync> ThorBtcPolicy<C> {
    /// Construct a production policy.
    ///
    /// `btc_multisig_address` MUST be parsed for the same network the
    /// rest of the stack uses; the constructor accepts any [`Network`]
    /// to keep tests + signet flexible.
    #[must_use]
    pub fn new(
        thor: ThorClient,
        btc: C,
        btc_multisig_address: Address,
        min_confirmations: u32,
        tolerance_sats: u64,
        _network: Network,
    ) -> Self {
        Self {
            thor,
            btc,
            btc_multisig_address,
            min_confirmations,
            tolerance_sats,
        }
    }

    fn within_tolerance(&self, expected: u64, actual: u64) -> bool {
        actual.abs_diff(expected) <= self.tolerance_sats
    }
}

#[async_trait]
impl<C: BitcoinChainClient + Send + Sync> CrossCheck for ThorBtcPolicy<C> {
    async fn verify(
        &self,
        thor_inbound_tx_hash: &str,
        expected_sats: u64,
    ) -> Result<(), CrossCheckError> {
        // Step 1: `THORChain` side.
        let resp = self.thor.tx_status(thor_inbound_tx_hash).await?;
        if resp.observed_tx.status != "done" {
            return Err(CrossCheckError::ThorNotReady {
                reason: format!(
                    "observed_tx.status = {} (expected 'done')",
                    resp.observed_tx.status
                ),
            });
        }
        // We expect at least one outbound action targeting our chain.
        let multisig_str = self.btc_multisig_address.to_string();
        let matching_action = resp
            .actions
            .iter()
            .find(|a| a.chain == "BTC" && a.to_address == multisig_str);
        let action = matching_action.ok_or_else(|| CrossCheckError::ThorNotReady {
            reason: "no BTC outbound action targeting our multisig in `THORChain` response"
                .to_string(),
        })?;
        let thor_sats: u64 =
            action
                .coin
                .amount
                .parse()
                .map_err(|e| CrossCheckError::ThorNotReady {
                    reason: format!("non-integer outbound amount '{}': {e}", action.coin.amount),
                })?;
        if !self.within_tolerance(expected_sats, thor_sats) {
            return Err(CrossCheckError::AmountMismatch {
                thor_sats,
                claim_sats: expected_sats,
            });
        }

        // Step 2: Bitcoin side.
        let needed = Amount::from_sat(expected_sats);
        let utxo = find_arrival(
            &self.btc,
            &self.btc_multisig_address,
            needed,
            self.min_confirmations,
        )?;
        let utxo = utxo.ok_or(CrossCheckError::BtcNotReady {
            needed_sats: expected_sats,
            min_confs: self.min_confirmations,
        })?;
        if !self.within_tolerance(expected_sats, utxo.value.to_sat()) {
            return Err(CrossCheckError::AmountMismatch {
                thor_sats: utxo.value.to_sat(),
                claim_sats: expected_sats,
            });
        }

        info!(
            tx_hash = thor_inbound_tx_hash,
            expected_sats, "cross-check OK — `THORChain` done + BTC UTXO confirmed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Txid;
    use std::str::FromStr;
    use std::sync::Mutex;
    use xindex_chain_btc::{BitcoinTxStatus, BitcoinUtxo};

    /// In-memory Bitcoin client for tests.
    #[derive(Debug, Default)]
    struct StubBtc {
        utxos: Mutex<Vec<BitcoinUtxo>>,
    }
    impl BitcoinChainClient for StubBtc {
        fn get_address_utxos(&self, _addr: &Address) -> Result<Vec<BitcoinUtxo>, BitcoinError> {
            Ok(self
                .utxos
                .lock()
                .map_err(|e| BitcoinError::Upstream(e.to_string()))?
                .clone())
        }
        fn get_tx_status(&self, _txid: &Txid) -> Result<BitcoinTxStatus, BitcoinError> {
            Err(BitcoinError::Upstream("not used".to_string()))
        }
        fn get_tip_height(&self) -> Result<u32, BitcoinError> {
            Ok(800_000)
        }
        fn broadcast(&self, _tx: &bitcoin::Transaction) -> Result<Txid, BitcoinError> {
            Err(BitcoinError::Upstream("not used".to_string()))
        }
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn test_address() -> Address {
        Address::from_str("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
            .expect("addr")
            .require_network(Network::Bitcoin)
            .expect("network")
    }

    #[tokio::test]
    async fn pass_through_always_oks() {
        let p = PassThroughPolicy;
        assert!(p.verify("any-hash", 1_000).await.is_ok());
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_policy_btc_not_ready_when_no_utxo() {
        // Stub a thor client that succeeds; stub BTC has no UTXOs.
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/abc"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": {
                        "tx": {
                            "id": "abc", "chain": "ETH",
                            "from_address": "0xUser", "to_address": "0xRouter",
                            "coins": [], "memo": ""
                        },
                        "status": "done"
                    },
                    "actions": [{
                        "chain": "BTC",
                        "to_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                        "coin": { "asset": "BTC.BTC", "amount": "100000" },
                        "memo": "OUT:abc",
                        "max_gas": []
                    }]
                })),
            )
            .mount(&server)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        let policy = ThorBtcPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        let err = policy
            .verify("abc", 100_000)
            .await
            .expect_err("should reject");
        assert!(matches!(err, CrossCheckError::BtcNotReady { .. }));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_policy_amount_mismatch() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/abc"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": {
                        "tx": {
                            "id": "abc", "chain": "ETH",
                            "from_address": "0xUser", "to_address": "0xRouter",
                            "coins": [], "memo": ""
                        },
                        "status": "done"
                    },
                    "actions": [{
                        "chain": "BTC",
                        "to_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                        "coin": { "asset": "BTC.BTC", "amount": "50000" },
                        "memo": "OUT:abc",
                        "max_gas": []
                    }]
                })),
            )
            .mount(&server)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        let policy = ThorBtcPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        // Claim is 100_000 sats but `THORChain` says 50_000 → mismatch.
        let err = policy
            .verify("abc", 100_000)
            .await
            .expect_err("should reject");
        assert!(matches!(err, CrossCheckError::AmountMismatch { .. }));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_policy_thor_not_done() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/abc"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": {
                        "tx": {
                            "id": "abc", "chain": "ETH",
                            "from_address": "0xUser", "to_address": "0xRouter",
                            "coins": [], "memo": ""
                        },
                        "status": "incomplete"
                    },
                    "actions": []
                })),
            )
            .mount(&server)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        let policy = ThorBtcPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        let err = policy
            .verify("abc", 100_000)
            .await
            .expect_err("should reject");
        assert!(matches!(err, CrossCheckError::ThorNotReady { .. }));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_policy_full_success() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/abc"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": {
                        "tx": {
                            "id": "abc", "chain": "ETH",
                            "from_address": "0xUser", "to_address": "0xRouter",
                            "coins": [], "memo": ""
                        },
                        "status": "done"
                    },
                    "actions": [{
                        "chain": "BTC",
                        "to_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                        "coin": { "asset": "BTC.BTC", "amount": "100000" },
                        "memo": "OUT:abc",
                        "max_gas": []
                    }]
                })),
            )
            .mount(&server)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        // Seed BTC stub with a confirmed UTXO matching the claim.
        let txid =
            Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .expect("txid");
        btc.utxos.lock().expect("lock").push(BitcoinUtxo {
            txid,
            vout: 0,
            value: Amount::from_sat(100_000),
            confirmations: 6,
            block_hash: None,
        });
        let policy = ThorBtcPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        policy.verify("abc", 100_000).await.expect("should pass");
    }
}
