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
//! - [`ThorUtxoPolicy`] — production. Hits `THORChain` RPC + a Bitcoin
//!   client; both must agree before [`CrossCheck::verify`] returns Ok.
//!
//! Tests use a hand-rolled in-memory mock to exercise the success path,
//! the "`THORChain` not done yet" path, and the "BTC not confirmed yet"
//! path without any network access.

use alloy_primitives::Address as EthAddress;
use async_trait::async_trait;
use bitcoin::{Address, Amount, Network};
use thiserror::Error;
use tracing::{info, warn};

use xindex_chain_thor::{ThorClient, ThorError};
use xindex_chain_utxo::{find_arrival, UtxoChainClient, UtxoError};

/// Errors surfaced by the cross-check.
#[derive(Debug, Error)]
pub enum CrossCheckError {
    #[error("`THORChain` RPC error: {0}")]
    Thor(#[from] ThorError),
    #[error("Bitcoin chain error: {0}")]
    Btc(#[from] UtxoError),
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
pub struct ThorUtxoPolicy<C: UtxoChainClient + Send + Sync> {
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

impl<C: UtxoChainClient + Send + Sync> std::fmt::Debug for ThorUtxoPolicy<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThorUtxoPolicy")
            .field("btc_multisig_address", &self.btc_multisig_address)
            .field("min_confirmations", &self.min_confirmations)
            .field("tolerance_sats", &self.tolerance_sats)
            .finish_non_exhaustive()
    }
}

impl<C: UtxoChainClient + Send + Sync> ThorUtxoPolicy<C> {
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
impl<C: UtxoChainClient + Send + Sync> CrossCheck for ThorUtxoPolicy<C> {
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

/* ========================================================================== */
/*            BURN → USDT redemption cross-checks (verify-the-refund)          */
/* ========================================================================== */

/// `THORChain` reports ALL asset amounts in 1e8 fixed precision in its
/// API, regardless of the asset's native decimals. USDT on-chain is
/// 1e6. Converting a `THORChain` ETH.USDT figure to the on-chain ERC20
/// value divides by this factor (1e8 / 1e6 = 100). The mint-side
/// `ThorUtxoPolicy` never needed this because BTC is 1e8 BOTH sides
/// (coincidentally aligned). For USDT they differ — handled explicitly
/// below, with the ON-CHAIN observed value treated as authoritative for
/// the attestation (the `THORChain` figure is only a scaled cross-check),
/// mirroring how the mint side attests the observed Bitcoin sats.
/// `THORChain` truncates to 1e8, so the ÷100 may drop < 1e-6 USDT —
/// absorbed by the tolerance. (Audit note: flagged for the burn-path
/// audit — units/precision is the classic cross-chain bug.)
const THOR_TO_USDT_SCALE: u128 = 100;

/// One observed ERC20 credit to an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Erc20Arrival {
    /// Transferred value in the token's own decimals (USDT: 1e6).
    pub value: u128,
    /// Confirmation depth of the transfer's log at the current tip.
    pub confirmations: u32,
}

/// Error from the ERC20 arrival backend (kept separate from the policy
/// errors so the concrete alloy client in `chain-eth` — which depends
/// on `signer` — implements this trait without a circular dep).
#[derive(Debug, Error)]
pub enum Erc20Error {
    #[error("eth rpc error: {0}")]
    Rpc(String),
}

/// Backend the redemption-delivery policy uses to confirm the USDT
/// actually landed on Ethereum. Trait lives here (not in `chain-eth`)
/// because `chain-eth` depends on `signer`; the concrete alloy-backed
/// impl is injected by the `xindex-attest-redeem` binary — exactly the
/// mint pattern where `UtxoChainClient` lives in `chain-btc` and the
/// concrete `EsploraClient` is wired by the binary.
pub trait Erc20ArrivalClient: Send + Sync {
    /// Every `Transfer(_, to, value)` of `token` observed for `to`,
    /// each with its log's confirmation depth at the current tip.
    ///
    /// # Errors
    /// [`Erc20Error`] if the backend RPC/query fails.
    fn transfers_to(
        &self,
        token: EthAddress,
        to: EthAddress,
    ) -> Result<Vec<Erc20Arrival>, Erc20Error>;
}

/// Mirror of `find_arrival` for an ERC20 credit: first transfer with
/// `value ≥ min_value` and `confirmations ≥ min_confs`.
///
/// # Errors
/// Forwards [`Erc20Error`] from the backend.
pub fn confirm_erc20_arrival<E: Erc20ArrivalClient>(
    client: &E,
    token: EthAddress,
    to: EthAddress,
    min_value: u128,
    min_confs: u32,
) -> Result<Option<Erc20Arrival>, Erc20Error> {
    Ok(client
        .transfers_to(token, to)?
        .into_iter()
        .find(|a| a.value >= min_value && a.confirmations >= min_confs))
}

#[derive(Debug, Error)]
pub enum RedemptionCrossCheckError {
    #[error("`THORChain` RPC error: {0}")]
    Thor(#[from] ThorError),
    #[error("ETH error: {0}")]
    Eth(#[from] Erc20Error),
    #[error("`THORChain` not yet ready: {reason}")]
    ThorNotReady { reason: String },
    #[error("USDT not yet confirmed at IndexToken: need ≥{need_1e6} (1e6) with ≥{confs} confs")]
    UsdtNotReady { need_1e6: u128, confs: u32 },
    #[error("amount mismatch: `THORChain` {thor_1e6} vs on-chain {onchain_1e6} (1e6 USDT)")]
    AmountMismatch { thor_1e6: u128, onchain_1e6: u128 },
    /// `THORChain` REFUNDED instead of delivering. The caller MUST take
    /// the refund-attestation path, NOT attest a delivery (the on-chain
    /// queue makes the two mutually exclusive).
    #[error("`THORChain` refunded (not delivered) — use the refund path")]
    RefundedInstead,
}

#[derive(Debug, Error)]
pub enum RefundCrossCheckError {
    #[error("`THORChain` RPC error: {0}")]
    Thor(#[from] ThorError),
    #[error("Bitcoin chain error: {0}")]
    Btc(#[from] UtxoError),
    #[error("`THORChain` not yet ready: {reason}")]
    ThorNotReady { reason: String },
    #[error("refund BTC not yet confirmed at multisig: need ≥{need_sats} sats ≥{confs} confs")]
    BtcNotReady { need_sats: u64, confs: u32 },
    #[error("amount mismatch: `THORChain` refund {thor_sats} vs UTXO {utxo_sats} sats")]
    AmountMismatch { thor_sats: u64, utxo_sats: u64 },
    /// `THORChain` DELIVERED USDT instead of refunding. The caller MUST
    /// take the delivery-attestation path (mutually exclusive on-chain).
    #[error("`THORChain` delivered (not refunded) — use the delivery path")]
    DeliveredInstead,
}

/// Delivery cross-check. Returns the cross-checked **on-chain** USDT
/// (1e6) the signer should attest — NOT `THORChain`'s figure.
#[async_trait]
pub trait RedemptionCrossCheck: Send + Sync {
    async fn verify(
        &self,
        btc_txid: &str,
        index_token: EthAddress,
    ) -> Result<u128, RedemptionCrossCheckError>;
}

/// Refund cross-check. Returns the cross-checked **on-chain** refunded
/// BTC (sats) the signer should attest.
#[async_trait]
pub trait RefundCrossCheck: Send + Sync {
    async fn verify(&self, btc_txid: &str) -> Result<u64, RefundCrossCheckError>;
}

/// **DEV / TEST ONLY.** Returns a fixed configured amount with a loud
/// `warn!`. For Anvil e2e where there is no real `THORChain`.
#[derive(Debug)]
pub struct PassThroughRedemption {
    pub usdt_1e6: u128,
}
#[async_trait]
impl RedemptionCrossCheck for PassThroughRedemption {
    async fn verify(
        &self,
        _btc_txid: &str,
        _index_token: EthAddress,
    ) -> Result<u128, RedemptionCrossCheckError> {
        warn!(
            policy = "PassThroughRedemption",
            "cross-check SKIPPED — Anvil/local only"
        );
        Ok(self.usdt_1e6)
    }
}

/// **DEV / TEST ONLY.** Fixed refunded-sats with a loud `warn!`.
#[derive(Debug)]
pub struct PassThroughRefund {
    pub btc_sats: u64,
}
#[async_trait]
impl RefundCrossCheck for PassThroughRefund {
    async fn verify(&self, _btc_txid: &str) -> Result<u64, RefundCrossCheckError> {
        warn!(
            policy = "PassThroughRefund",
            "cross-check SKIPPED — Anvil/local only"
        );
        Ok(self.btc_sats)
    }
}

#[inline]
fn within(a: u128, b: u128, tol: u128) -> bool {
    a.abs_diff(b) <= tol
}

/// Lower-cased `0x`-hex of an ETH address for case-insensitive
/// comparison with `THORChain`'s `to_address` (which may be checksummed).
fn eth_addr_lc(a: EthAddress) -> String {
    format!("{a:#x}").to_lowercase()
}

/// Production delivery policy: `THORChain` swapped BTC→USDT and the
/// USDT actually landed at the `IndexToken` contract (R1). Two
/// independent observations, like the mint-side `ThorUtxoPolicy`.
pub struct ThorUtxoToUsdtPolicy<E: Erc20ArrivalClient> {
    thor: ThorClient,
    erc20: E,
    /// Mainnet USDT ERC20 address.
    usdt_token: EthAddress,
    min_confirmations: u32,
    /// Max |thor − on-chain| (in 1e6 USDT) accepted.
    tolerance_1e6: u128,
}

impl<E: Erc20ArrivalClient> std::fmt::Debug for ThorUtxoToUsdtPolicy<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThorUtxoToUsdtPolicy")
            .field("usdt_token", &self.usdt_token)
            .field("min_confirmations", &self.min_confirmations)
            .field("tolerance_1e6", &self.tolerance_1e6)
            .finish_non_exhaustive()
    }
}

impl<E: Erc20ArrivalClient> ThorUtxoToUsdtPolicy<E> {
    #[must_use]
    pub fn new(
        thor: ThorClient,
        erc20: E,
        usdt_token: EthAddress,
        min_confirmations: u32,
        tolerance_1e6: u128,
    ) -> Self {
        Self {
            thor,
            erc20,
            usdt_token,
            min_confirmations,
            tolerance_1e6,
        }
    }
}

#[async_trait]
impl<E: Erc20ArrivalClient> RedemptionCrossCheck for ThorUtxoToUsdtPolicy<E> {
    async fn verify(
        &self,
        btc_txid: &str,
        index_token: EthAddress,
    ) -> Result<u128, RedemptionCrossCheckError> {
        // Step 1 — THORChain.
        let resp = self.thor.tx_status(btc_txid).await?;
        if resp.observed_tx.status != "done" {
            return Err(RedemptionCrossCheckError::ThorNotReady {
                reason: format!("observed_tx.status = {}", resp.observed_tx.status),
            });
        }
        // Mutual-exclusion guard: a REFUND outbound means this is the
        // refund path, never attest delivery.
        if resp
            .actions
            .iter()
            .any(|a| a.chain == "BTC" && a.memo.to_uppercase().starts_with("REFUND:"))
        {
            return Err(RedemptionCrossCheckError::RefundedInstead);
        }
        let want = eth_addr_lc(index_token);
        let action = resp
            .actions
            .iter()
            .find(|a| {
                a.chain == "ETH"
                    && a.coin.asset.to_uppercase().starts_with("ETH.USDT")
                    && a.to_address.to_lowercase() == want
            })
            .ok_or_else(|| RedemptionCrossCheckError::ThorNotReady {
                reason: "no ETH.USDT outbound to the IndexToken yet".to_string(),
            })?;
        let thor_1e8: u128 =
            action
                .coin
                .amount
                .parse()
                .map_err(|e| RedemptionCrossCheckError::ThorNotReady {
                    reason: format!("non-integer outbound amount '{}': {e}", action.coin.amount),
                })?;
        let thor_1e6 = thor_1e8 / THOR_TO_USDT_SCALE;

        // Step 2 — Ethereum (authoritative for the attested amount).
        let floor = thor_1e6.saturating_sub(self.tolerance_1e6);
        let arrival = confirm_erc20_arrival(
            &self.erc20,
            self.usdt_token,
            index_token,
            floor,
            self.min_confirmations,
        )?
        .ok_or(RedemptionCrossCheckError::UsdtNotReady {
            need_1e6: thor_1e6,
            confs: self.min_confirmations,
        })?;
        if !within(thor_1e6, arrival.value, self.tolerance_1e6) {
            return Err(RedemptionCrossCheckError::AmountMismatch {
                thor_1e6,
                onchain_1e6: arrival.value,
            });
        }
        info!(
            btc_txid,
            onchain_usdt_1e6 = arrival.value,
            "redemption cross-check OK"
        );
        // Attest the ON-CHAIN observed value — that is what the
        // IndexToken's USDT balance actually grew by.
        Ok(arrival.value)
    }
}

/// Production refund policy: `THORChain` slip-refunded the BTC to our
/// multisig (`REFUND:<txid>` outbound) and the UTXO actually returned.
/// Disambiguated ONLY by the `REFUND:` memo — never by time.
pub struct ThorUtxoRefundPolicy<C: UtxoChainClient + Send + Sync> {
    thor: ThorClient,
    btc: C,
    btc_multisig_address: Address,
    min_confirmations: u32,
    tolerance_sats: u64,
}

impl<C: UtxoChainClient + Send + Sync> std::fmt::Debug for ThorUtxoRefundPolicy<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThorUtxoRefundPolicy")
            .field("btc_multisig_address", &self.btc_multisig_address)
            .field("min_confirmations", &self.min_confirmations)
            .field("tolerance_sats", &self.tolerance_sats)
            .finish_non_exhaustive()
    }
}

impl<C: UtxoChainClient + Send + Sync> ThorUtxoRefundPolicy<C> {
    #[must_use]
    pub fn new(
        thor: ThorClient,
        btc: C,
        btc_multisig_address: Address,
        min_confirmations: u32,
        tolerance_sats: u64,
    ) -> Self {
        Self {
            thor,
            btc,
            btc_multisig_address,
            min_confirmations,
            tolerance_sats,
        }
    }
}

#[async_trait]
impl<C: UtxoChainClient + Send + Sync> RefundCrossCheck for ThorUtxoRefundPolicy<C> {
    async fn verify(&self, btc_txid: &str) -> Result<u64, RefundCrossCheckError> {
        let resp = self.thor.tx_status(btc_txid).await?;
        if resp.observed_tx.status != "done" {
            return Err(RefundCrossCheckError::ThorNotReady {
                reason: format!("observed_tx.status = {}", resp.observed_tx.status),
            });
        }
        // Mutual-exclusion guard: a USDT delivery means use the delivery
        // path, never attest a refund.
        if resp
            .actions
            .iter()
            .any(|a| a.chain == "ETH" && a.coin.asset.to_uppercase().starts_with("ETH.USDT"))
        {
            return Err(RefundCrossCheckError::DeliveredInstead);
        }
        let multisig = self.btc_multisig_address.to_string();
        let action = resp
            .actions
            .iter()
            .find(|a| {
                a.chain == "BTC"
                    && a.to_address == multisig
                    && a.memo.to_uppercase().starts_with("REFUND:")
                    && a.coin.asset.to_uppercase() == "BTC.BTC"
            })
            .ok_or_else(|| RefundCrossCheckError::ThorNotReady {
                reason: "no BTC REFUND outbound to our multisig yet".to_string(),
            })?;
        let thor_sats: u64 =
            action
                .coin
                .amount
                .parse()
                .map_err(|e| RefundCrossCheckError::ThorNotReady {
                    reason: format!("non-integer refund amount '{}': {e}", action.coin.amount),
                })?;

        // Independent Bitcoin observation. BTC is 1e8 BOTH on THORChain
        // and on-chain (sats) — no scaling, unlike USDT.
        let floor = Amount::from_sat(thor_sats.saturating_sub(self.tolerance_sats));
        let utxo = find_arrival(
            &self.btc,
            &self.btc_multisig_address,
            floor,
            self.min_confirmations,
        )?
        .ok_or(RefundCrossCheckError::BtcNotReady {
            need_sats: thor_sats,
            confs: self.min_confirmations,
        })?;
        let utxo_sats = utxo.value.to_sat();
        if utxo_sats.abs_diff(thor_sats) > self.tolerance_sats {
            return Err(RefundCrossCheckError::AmountMismatch {
                thor_sats,
                utxo_sats,
            });
        }
        info!(btc_txid, refunded_sats = utxo_sats, "refund cross-check OK");
        // Attest the ON-CHAIN UTXO value (authoritative).
        Ok(utxo_sats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Txid;
    use std::str::FromStr;
    use std::sync::Mutex;
    use xindex_chain_utxo::{UtxoEntry, UtxoTxStatus};

    /// In-memory Bitcoin client for tests.
    #[derive(Debug, Default)]
    struct StubBtc {
        utxos: Mutex<Vec<UtxoEntry>>,
    }
    impl UtxoChainClient for StubBtc {
        fn get_address_utxos(&self, _addr: &Address) -> Result<Vec<UtxoEntry>, UtxoError> {
            Ok(self
                .utxos
                .lock()
                .map_err(|e| UtxoError::Upstream(e.to_string()))?
                .clone())
        }
        fn get_tx_status(&self, _txid: &Txid) -> Result<UtxoTxStatus, UtxoError> {
            Err(UtxoError::Upstream("not used".to_string()))
        }
        fn get_tip_height(&self) -> Result<u32, UtxoError> {
            Ok(800_000)
        }
        fn broadcast(&self, _tx: &bitcoin::Transaction) -> Result<Txid, UtxoError> {
            Err(UtxoError::Upstream("not used".to_string()))
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
        let policy = ThorUtxoPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
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
        let policy = ThorUtxoPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        // Claim is 100_000 sats but `THORChain` says 50_000 → mismatch.
        let err = policy
            .verify("abc", 100_000)
            .await
            .expect_err("should reject");
        assert!(matches!(err, CrossCheckError::AmountMismatch { .. }));
    }

    /// `THORChain` response carries actions, but none target our chain
    /// (chain != "BTC"). The cross-check action filter is
    /// `chain == "BTC" && to_address == multisig` — closing this gap
    /// catches the `&&` → `||` mutation. With AND, the find returns
    /// `None` and `ThorNotReady` fires; with OR (the mutation), find
    /// would return Some on any matching `to_address` regardless of
    /// chain, masking a wrong-chain settlement.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_policy_rejects_wrong_chain_action() {
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
                        // chain is ETH (not BTC) but to_address matches
                        // our multisig string. `&&` filter rejects;
                        // `||` mutation would let this through.
                        "chain": "ETH",
                        "to_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                        "coin": { "asset": "ETH.ETH", "amount": "1000000000000000000" },
                        "memo": "OUT:abc",
                        "max_gas": []
                    }]
                })),
            )
            .mount(&server)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        let policy = ThorUtxoPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        let err = policy
            .verify("abc", 100_000)
            .await
            .expect_err("should reject wrong-chain action");
        assert!(
            matches!(err, CrossCheckError::ThorNotReady { .. }),
            "expected ThorNotReady, got {err:?}"
        );
    }

    /// Same defense from the other angle: action chain matches but
    /// `to_address` doesn't. The `&&` filter must reject; `||` would
    /// accept the wrong-address action.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_policy_rejects_wrong_address_action() {
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
                        // Different bc1... address than test_address().
                        "to_address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
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
        let policy = ThorUtxoPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        let err = policy
            .verify("abc", 100_000)
            .await
            .expect_err("should reject wrong-address action");
        assert!(
            matches!(err, CrossCheckError::ThorNotReady { .. }),
            "expected ThorNotReady, got {err:?}"
        );
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
        let policy = ThorUtxoPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
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
        btc.utxos.lock().expect("lock").push(UtxoEntry {
            txid,
            vout: 0,
            value: Amount::from_sat(100_000),
            confirmations: 6,
            block_hash: None,
        });
        let policy = ThorUtxoPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        policy.verify("abc", 100_000).await.expect("should pass");
    }

    /* ----------------- redemption / refund cross-checks ------------------ */

    #[derive(Debug, Default)]
    struct StubErc20 {
        arrivals: Mutex<Vec<Erc20Arrival>>,
    }
    impl Erc20ArrivalClient for StubErc20 {
        fn transfers_to(
            &self,
            _token: EthAddress,
            _to: EthAddress,
        ) -> Result<Vec<Erc20Arrival>, Erc20Error> {
            Ok(self
                .arrivals
                .lock()
                .map_err(|e| Erc20Error::Rpc(e.to_string()))?
                .clone())
        }
    }

    fn idx_token() -> EthAddress {
        EthAddress::from([0x42u8; 20])
    }
    fn usdt_token() -> EthAddress {
        EthAddress::from([0xdau8; 20])
    }

    #[test]
    fn confirm_erc20_arrival_filters_value_and_confs() {
        let c = StubErc20::default();
        #[expect(clippy::expect_used, reason = "test code")]
        {
            c.arrivals.lock().expect("lock").extend([
                Erc20Arrival {
                    value: 10,
                    confirmations: 9,
                }, // too small
                Erc20Arrival {
                    value: 100,
                    confirmations: 1,
                }, // too shallow
                Erc20Arrival {
                    value: 100,
                    confirmations: 6,
                }, // ✓
            ]);
        }
        let got = confirm_erc20_arrival(&c, usdt_token(), idx_token(), 100, 6)
            .ok()
            .flatten();
        assert_eq!(
            got,
            Some(Erc20Arrival {
                value: 100,
                confirmations: 6
            })
        );
    }

    #[tokio::test]
    async fn pass_through_redemption_and_refund_return_configured() {
        let r = PassThroughRedemption {
            usdt_1e6: 70_000_000,
        };
        assert_eq!(r.verify("h", idx_token()).await.ok(), Some(70_000_000));
        let f = PassThroughRefund {
            btc_sats: 99_990_000,
        };
        assert_eq!(f.verify("h").await.ok(), Some(99_990_000));
    }

    /// `THORChain` reports 1e8; on-chain USDT is 1e6. Policy must scale
    /// ÷100, agree within tolerance, and attest the ON-CHAIN value.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_to_usdt_full_success_scales_1e8_to_1e6() {
        let server = wiremock::MockServer::start().await;
        let to_lc = eth_addr_lc(idx_token());
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/btc-in"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": { "tx": { "id":"btc-in","chain":"BTC",
                        "from_address":"bc1qour","to_address":"thor-asgard",
                        "coins":[],"memo":"" }, "status":"done" },
                    "actions": [{
                        "chain":"ETH",
                        "to_address": to_lc,
                        "coin": { "asset":"ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
                                  "amount":"7000000000" },  // 70 USDT in THOR 1e8
                        "memo":"OUT:btc-in",
                        "max_gas":[]
                    }]
                })),
            )
            .mount(&server)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let erc20 = StubErc20::default();
        erc20.arrivals.lock().expect("lock").push(Erc20Arrival {
            value: 70_000_000,
            confirmations: 6,
        }); // 70 USDT 1e6
        let policy = ThorUtxoToUsdtPolicy::new(thor, erc20, usdt_token(), 6, 0);
        let attested = policy.verify("btc-in", idx_token()).await.expect("ok");
        assert_eq!(attested, 70_000_000, "attest the on-chain 1e6 value");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_to_usdt_refunded_instead() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/btc-in"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": { "tx": { "id":"btc-in","chain":"BTC",
                        "from_address":"bc1qour","to_address":"thor-asgard",
                        "coins":[],"memo":"" }, "status":"done" },
                    "actions": [{
                        "chain":"BTC", "to_address":"bc1qour",
                        "coin": { "asset":"BTC.BTC","amount":"99990000" },
                        "memo":"REFUND:btc-in", "max_gas":[]
                    }]
                })),
            )
            .mount(&server)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let policy = ThorUtxoToUsdtPolicy::new(thor, StubErc20::default(), usdt_token(), 6, 0);
        let err = policy
            .verify("btc-in", idx_token())
            .await
            .expect_err("refund must not attest delivery");
        assert!(matches!(err, RedemptionCrossCheckError::RefundedInstead));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_refund_full_success() {
        let server = wiremock::MockServer::start().await;
        let multisig = test_address().to_string();
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/btc-in"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": { "tx": { "id":"btc-in","chain":"BTC",
                        "from_address":"bc1qour","to_address":"thor-asgard",
                        "coins":[],"memo":"" }, "status":"done" },
                    "actions": [{
                        "chain":"BTC", "to_address": multisig,
                        "coin": { "asset":"BTC.BTC","amount":"99990000" }, // sats == 1e8
                        "memo":"REFUND:btc-in", "max_gas":[]
                    }]
                })),
            )
            .mount(&server)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        btc.utxos.lock().expect("lock").push(UtxoEntry {
            txid: Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000abc",
            )
            .expect("txid"),
            vout: 0,
            value: Amount::from_sat(99_990_000),
            confirmations: 6,
            block_hash: None,
        });
        let policy = ThorUtxoRefundPolicy::new(thor, btc, test_address(), 1, 0);
        let attested = policy.verify("btc-in").await.expect("ok");
        assert_eq!(attested, 99_990_000, "attest the on-chain UTXO sats");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_refund_delivered_instead() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/btc-in"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": { "tx": { "id":"btc-in","chain":"BTC",
                        "from_address":"bc1qour","to_address":"thor-asgard",
                        "coins":[],"memo":"" }, "status":"done" },
                    "actions": [{
                        "chain":"ETH", "to_address":"0xindextoken",
                        "coin": { "asset":"ETH.USDT-0XDAC","amount":"7000000000" },
                        "memo":"OUT:btc-in", "max_gas":[]
                    }]
                })),
            )
            .mount(&server)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let policy = ThorUtxoRefundPolicy::new(thor, StubBtc::default(), test_address(), 1, 0);
        let err = policy
            .verify("btc-in")
            .await
            .expect_err("delivery must not attest refund");
        assert!(matches!(err, RefundCrossCheckError::DeliveredInstead));
    }

    /// `ToUsdt` `find` predicate `chain=="ETH" && asset~ETH.USDT &&
    /// to==want`: a decoy that matches chain only (wrong asset) must NOT
    /// be selected. AND → no match → `ThorNotReady`; `||` mutation →
    /// selects the decoy → different error. Kills the chain/asset `&&`.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_to_usdt_rejects_wrong_asset_decoy() {
        let server = wiremock::MockServer::start().await;
        let to_lc = eth_addr_lc(idx_token());
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/btc-in"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": { "tx": { "id":"btc-in","chain":"BTC",
                        "from_address":"bc1qour","to_address":"thor-asgard",
                        "coins":[],"memo":"" }, "status":"done" },
                    "actions": [{
                        "chain":"ETH", "to_address": to_lc,
                        "coin": { "asset":"ETH.ETH", "amount":"7000000000" },
                        "memo":"OUT:btc-in", "max_gas":[]
                    }]
                })),
            )
            .mount(&server)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let policy = ThorUtxoToUsdtPolicy::new(thor, StubErc20::default(), usdt_token(), 6, 0);
        let err = policy
            .verify("btc-in", idx_token())
            .await
            .expect_err("wrong-asset decoy must not be selected");
        assert!(
            matches!(err, RedemptionCrossCheckError::ThorNotReady { .. }),
            "expected ThorNotReady, got {err:?}"
        );
    }

    /// `ToUsdt` `find`: decoy matches chain+asset but WRONG `to_address`.
    /// Kills the `&& a.to_address == want` (`||` would select it).
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_to_usdt_rejects_wrong_destination_decoy() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/btc-in"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": { "tx": { "id":"btc-in","chain":"BTC",
                        "from_address":"bc1qour","to_address":"thor-asgard",
                        "coins":[],"memo":"" }, "status":"done" },
                    "actions": [{
                        "chain":"ETH",
                        "to_address": eth_addr_lc(EthAddress::from([0x99u8;20])),
                        "coin": { "asset":"ETH.USDT-0XDAC", "amount":"7000000000" },
                        "memo":"OUT:btc-in", "max_gas":[]
                    }]
                })),
            )
            .mount(&server)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let policy = ThorUtxoToUsdtPolicy::new(thor, StubErc20::default(), usdt_token(), 6, 0);
        let err = policy
            .verify("btc-in", idx_token())
            .await
            .expect_err("wrong-destination decoy must not be selected");
        assert!(
            matches!(err, RedemptionCrossCheckError::ThorNotReady { .. }),
            "expected ThorNotReady, got {err:?}"
        );
    }

    /// `ToUsdt` mutual-exclusion `.any(|a| a.chain=="BTC" && memo~REFUND:)`.
    /// A genuine delivery that ALSO carries a non-refund BTC action and a
    /// non-BTC REFUND-memo action must still succeed. `&&`→`||` (either
    /// half) would spuriously raise `RefundedInstead`. Asserts Ok.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_to_usdt_success_despite_non_refund_btc_and_foreign_refund() {
        let server = wiremock::MockServer::start().await;
        let to_lc = eth_addr_lc(idx_token());
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/btc-in"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": { "tx": { "id":"btc-in","chain":"BTC",
                        "from_address":"bc1qour","to_address":"thor-asgard",
                        "coins":[],"memo":"" }, "status":"done" },
                    "actions": [
                        { "chain":"BTC", "to_address":"bc1qx",
                          "coin": { "asset":"BTC.BTC","amount":"1" },
                          "memo":"OUT:btc-in", "max_gas":[] },
                        { "chain":"LTC", "to_address":"ltc1q",
                          "coin": { "asset":"LTC.LTC","amount":"1" },
                          "memo":"REFUND:btc-in", "max_gas":[] },
                        { "chain":"ETH", "to_address": to_lc,
                          "coin": { "asset":"ETH.USDT-0XDAC","amount":"7000000000" },
                          "memo":"OUT:btc-in", "max_gas":[] }
                    ]
                })),
            )
            .mount(&server)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let erc20 = StubErc20::default();
        erc20.arrivals.lock().expect("lock").push(Erc20Arrival {
            value: 70_000_000,
            confirmations: 6,
        });
        let policy = ThorUtxoToUsdtPolicy::new(thor, erc20, usdt_token(), 6, 0);
        let attested = policy
            .verify("btc-in", idx_token())
            .await
            .expect("non-refund BTC + foreign REFUND must not block delivery");
        assert_eq!(attested, 70_000_000);
    }

    /// Refund mutual-exclusion `.any(|a| chain=="ETH" && asset~ETH.USDT)`.
    /// A genuine refund that ALSO carries an ETH-non-USDT action and a
    /// non-ETH USDT-named action must still succeed. `&&`→`||` would
    /// spuriously raise `DeliveredInstead`. Asserts Ok.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_refund_success_despite_eth_non_usdt_and_foreign_usdt() {
        let server = wiremock::MockServer::start().await;
        let multisig = test_address().to_string();
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/btc-in"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": { "tx": { "id":"btc-in","chain":"BTC",
                        "from_address":"bc1qour","to_address":"thor-asgard",
                        "coins":[],"memo":"" }, "status":"done" },
                    "actions": [
                        { "chain":"ETH", "to_address":"0xfoo",
                          "coin": { "asset":"ETH.ETH","amount":"1" },
                          "memo":"OUT:btc-in", "max_gas":[] },
                        { "chain":"LTC", "to_address":"ltc1q",
                          "coin": { "asset":"ETH.USDT-0XDAC","amount":"1" },
                          "memo":"OUT:btc-in", "max_gas":[] },
                        { "chain":"BTC", "to_address": multisig,
                          "coin": { "asset":"BTC.BTC","amount":"99990000" },
                          "memo":"REFUND:btc-in", "max_gas":[] }
                    ]
                })),
            )
            .mount(&server)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        btc.utxos.lock().expect("lock").push(UtxoEntry {
            txid: Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000abc",
            )
            .expect("txid"),
            vout: 0,
            value: Amount::from_sat(99_990_000),
            confirmations: 6,
            block_hash: None,
        });
        let policy = ThorUtxoRefundPolicy::new(thor, btc, test_address(), 1, 0);
        let attested = policy
            .verify("btc-in")
            .await
            .expect("ETH-non-USDT + foreign USDT must not block refund");
        assert_eq!(attested, 99_990_000);
    }

    /// Refund `find` predicate: a decoy matching every clause EXCEPT one
    /// must not be selected. Three variants (wrong address / wrong memo /
    /// wrong asset) each kill one `&&` of
    /// `chain && to==multisig && memo~REFUND: && asset==BTC.BTC`.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_refund_find_predicate_is_conjunctive() {
        let multisig = test_address().to_string();
        for (label, to, memo, asset) in [
            (
                "wrong-addr",
                "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                "REFUND:btc-in",
                "BTC.BTC",
            ),
            ("wrong-memo", multisig.as_str(), "OUT:btc-in", "BTC.BTC"),
            (
                "wrong-asset",
                multisig.as_str(),
                "REFUND:btc-in",
                "BTC.RUNE",
            ),
        ] {
            let server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/thorchain/tx/btc-in"))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({
                        "observed_tx": { "tx": { "id":"btc-in","chain":"BTC",
                            "from_address":"bc1qour","to_address":"thor-asgard",
                            "coins":[],"memo":"" }, "status":"done" },
                        "actions": [{
                            "chain":"BTC", "to_address": to,
                            "coin": { "asset": asset, "amount":"99990000" },
                            "memo": memo, "max_gas":[]
                        }]
                    }),
                ))
                .mount(&server)
                .await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let policy = ThorUtxoRefundPolicy::new(thor, StubBtc::default(), test_address(), 1, 0);
            let err = policy
                .verify("btc-in")
                .await
                .expect_err("partial-match decoy must not be selected");
            assert!(
                matches!(err, RefundCrossCheckError::ThorNotReady { .. }),
                "{label}: expected ThorNotReady, got {err:?}"
            );
        }
    }

    /// Refund amount gate `abs_diff(utxo, thor) > tolerance`. A diff
    /// strictly greater than tolerance must reject with `AmountMismatch`;
    /// `>`→`<` would accept it. Tolerance 5, diff 10.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_refund_amount_gate_is_greater_than() {
        let server = wiremock::MockServer::start().await;
        let multisig = test_address().to_string();
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/btc-in"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": { "tx": { "id":"btc-in","chain":"BTC",
                        "from_address":"bc1qour","to_address":"thor-asgard",
                        "coins":[],"memo":"" }, "status":"done" },
                    "actions": [{
                        "chain":"BTC", "to_address": multisig,
                        "coin": { "asset":"BTC.BTC","amount":"100000" },
                        "memo":"REFUND:btc-in", "max_gas":[]
                    }]
                })),
            )
            .mount(&server)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        btc.utxos.lock().expect("lock").push(UtxoEntry {
            txid: Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000abc",
            )
            .expect("txid"),
            vout: 0,
            value: Amount::from_sat(100_010), // diff 10 > tolerance 5
            confirmations: 6,
            block_hash: None,
        });
        let policy = ThorUtxoRefundPolicy::new(thor, btc, test_address(), 1, 5);
        let err = policy
            .verify("btc-in")
            .await
            .expect_err("diff 10 > tolerance 5 must reject");
        assert!(
            matches!(err, RefundCrossCheckError::AmountMismatch { .. }),
            "expected AmountMismatch, got {err:?}"
        );
    }
}

/* ========================================================================== */
/*                  V6 — EVM custody-family cross-checks                       */
/* ========================================================================== */

/// V6: Phase 3.2 EVM custody policies. Symmetric to `ThorUtxoPolicy` /
/// `ThorUtxoRefundPolicy` / `ThorUtxoToUsdtPolicy` but for the Phase
/// 3.2 EVM family (ETH / BSC / AVAX / BASE / POL) where the destination
/// custody is a Safe v1.4.1 multisig.
///
/// ## Why a separate module
///
/// The EVM-side observation is FUNDAMENTALLY DIFFERENT from the UTXO
/// side: native value transfers emit no events, so scanning the Safe
/// address directly produces no logs. Instead we scan the THORChain
/// **Router** contract on the destination chain for a `TransferOut`
/// event whose `to` matches our Safe. The Router is the bridge contract
/// THORChain validators sign and broadcast through; its event surface
/// is what every Phase 3.2 chain shares.
///
/// Compare with UTXO: `find_arrival` scans the multisig address for a
/// confirmed UTXO of the expected amount. The Router-event-scan here is
/// the EVM analogue.
#[expect(
    clippy::doc_markdown,
    reason = "THORChain / SafeTx / IndexToken / ChainId / RPC identifiers \
              are referenced frequently in module documentation; \
              per-identifier backticks add noise without aiding parsing"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "policy constructors carry chain identity + threshold + tolerance \
              config; bundling into a *Config struct adds indirection without \
              cutting the dimensionality"
)]
pub mod evm {
    use super::{
        within, RedemptionCrossCheck, RedemptionCrossCheckError, RefundCrossCheck,
        RefundCrossCheckError,
    };
    use alloy_primitives::{Address as EthAddress, B256, U256};
    use async_trait::async_trait;
    use thiserror::Error;
    use tracing::{info, warn};
    use xindex_chain_evm::{EvmChainClient, EvmChainError, EvmLogEntry, EvmLogFilter};
    use xindex_chain_thor::{ThorClient, ThorError};

    /// `keccak256("TransferOut(address,address,address,uint256,string)")`.
    /// Topic-0 of THORChain Router v6.1's `TransferOut` event — emitted
    /// on every outbound delivery (mint-side native or refund). All
    /// Phase 3.2 chains share the same Router ABI shape; only the
    /// deployed address differs (see
    /// `xindex_shared::chain_registry::ChainId::thorchain_router_address`).
    pub const THOR_TRANSFER_OUT_TOPIC0: B256 = B256::new([
        0xa9, 0xcd, 0x6d, 0xb6, 0x6b, 0x3d, 0xb4, 0x6d, 0xe0, 0x9a, 0x9b, 0xa2, 0xe1, 0xb4, 0xbe,
        0x5a, 0x5c, 0xed, 0x1e, 0xa3, 0x9d, 0xc1, 0x70, 0x55, 0xa2, 0xa7, 0x90, 0x6e, 0x8b, 0xb8,
        0xc7, 0xf8,
    ]);

    /// `keccak256("Transfer(address,address,uint256)")` — the ERC20
    /// Transfer event topic-0. Pinned (the standard signature never
    /// changes). Used by [`ThorEvmToUsdtPolicy`] to verify USDT landed
    /// at the IndexToken on Ethereum.
    pub const ERC20_TRANSFER_TOPIC0: B256 = B256::new([
        0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d,
        0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23,
        0xb3, 0xef,
    ]);

    /// Errors for the V6 EVM cross-check policies. Distinct from the
    /// UTXO error enums so the consumer (V7 executor / attestation
    /// binary) gets a tight pattern match per family.
    #[derive(Debug, Error)]
    pub enum EvmCrossCheckError {
        /// `THORChain` RPC failure.
        #[error("`THORChain` RPC error: {0}")]
        Thor(#[from] ThorError),
        /// EVM chain RPC failure.
        #[error("EVM chain error: {0}")]
        Evm(#[from] EvmChainError),
        /// `THORChain` not yet ready (status pending, missing action,
        /// non-integer amount).
        #[error("`THORChain` not yet ready: {reason}")]
        ThorNotReady {
            /// Human-readable detail.
            reason: String,
        },
        /// The destination chain has no `TransferOut` event matching
        /// our `(safe, amount, min_confs)` yet. The signer should poll
        /// again, NOT sign.
        #[error(
            "EVM TransferOut not yet confirmed: need ≥{need_wei} wei to {safe:#x} with ≥{min_confs} confs"
        )]
        EvmNotReady {
            /// Min wei the action claims.
            need_wei: u128,
            /// Min confirmation depth required.
            min_confs: u32,
            /// The Safe expected to receive.
            safe: EthAddress,
        },
        /// `THORChain` amount disagrees with the on-chain log's value.
        /// Never sign for a wrong amount.
        #[error("amount mismatch: thor {thor_wei} wei vs on-chain {onchain_wei} wei")]
        AmountMismatch {
            /// `THORChain`-reported wei.
            thor_wei: u128,
            /// EVM-log-decoded wei.
            onchain_wei: u128,
        },
        /// Mint path observed a REFUND action — caller MUST attest via
        /// the refund policy, never delivery (mutually exclusive on-chain).
        #[error("`THORChain` refunded (not delivered) — use the refund path")]
        RefundedInstead,
        /// Refund path observed a delivery action — caller MUST attest
        /// via the delivery policy.
        #[error("`THORChain` delivered (not refunded) — use the delivery path")]
        DeliveredInstead,
    }

    /// One observed `TransferOut` event from a THORChain Router. Used
    /// internally by [`find_router_transfer_out`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RouterTransferOut {
        /// Wei value the Router transferred to `to`.
        pub value_wei: u128,
        /// Recipient (the Safe expected to receive).
        pub to: EthAddress,
        /// Tx-hash the event was emitted in.
        pub transaction_hash: B256,
        /// Confirmation depth at the current tip.
        pub confirmations: u32,
    }

    /// Scan the Router contract on `client.chain()` for a
    /// `TransferOut` event whose `to` argument matches `safe` and
    /// whose `value` is ≥ `min_value_wei` with ≥ `min_confs`
    /// confirmations. Returns the FIRST match (most recent
    /// `eth_get_logs` ordering).
    ///
    /// The Router event signature is
    /// `TransferOut(address indexed vault, address indexed to,
    ///              address asset, uint256 amount, string memo)`.
    /// The `to` argument is indexed → `topic[2]`. We over-filter on
    /// `topic[0]` + `topic[2]` and decode `(asset, amount, memo)` from
    /// `data`.
    ///
    /// # Errors
    /// [`EvmCrossCheckError::Evm`] on RPC failure;
    /// [`EvmCrossCheckError::EvmNotReady`] is NOT returned here — the
    /// caller distinguishes "no match" (= `Ok(None)`) from "not enough
    /// confs" (also `Ok(None)` if every match is too shallow).
    pub async fn find_router_transfer_out<E: EvmChainClient>(
        client: &E,
        router: EthAddress,
        safe: EthAddress,
        min_value_wei: u128,
        min_confs: u32,
        lookback_blocks: u64,
    ) -> Result<Option<RouterTransferOut>, EvmCrossCheckError> {
        let tip = client.block_number().await?;
        let from_block = tip.saturating_sub(lookback_blocks);
        let safe_topic = address_to_topic(safe);
        let filter = EvmLogFilter {
            from_block: Some(from_block),
            to_block: Some(tip),
            address: Some(router),
            topic0: Some(THOR_TRANSFER_OUT_TOPIC0),
            // topic[1] = vault (any); topic[2] = to (= safe).
            topics_1_3: [None, Some(safe_topic), None],
        };
        let logs = client.eth_get_logs(filter).await?;
        for log in logs {
            if let Some(decoded) = decode_router_transfer_out(&log, tip) {
                if decoded.value_wei >= min_value_wei && decoded.confirmations >= min_confs {
                    return Ok(Some(decoded));
                }
            }
        }
        Ok(None)
    }

    /// Scan an ERC20 token's `Transfer` events for one targeting
    /// `to_addr` with `value ≥ min_value` and `confirmations ≥
    /// min_confs`. Used by [`ThorEvmToUsdtPolicy`] for the USDT-arrival
    /// check on Ethereum.
    ///
    /// # Errors
    /// As [`find_router_transfer_out`].
    pub async fn find_erc20_transfer_to<E: EvmChainClient>(
        client: &E,
        token: EthAddress,
        to_addr: EthAddress,
        min_value: u128,
        min_confs: u32,
        lookback_blocks: u64,
    ) -> Result<Option<RouterTransferOut>, EvmCrossCheckError> {
        let tip = client.block_number().await?;
        let from_block = tip.saturating_sub(lookback_blocks);
        let to_topic = address_to_topic(to_addr);
        let filter = EvmLogFilter {
            from_block: Some(from_block),
            to_block: Some(tip),
            address: Some(token),
            topic0: Some(ERC20_TRANSFER_TOPIC0),
            // topic[1] = from (any); topic[2] = to (= to_addr).
            topics_1_3: [None, Some(to_topic), None],
        };
        let logs = client.eth_get_logs(filter).await?;
        for log in logs {
            if let Some(decoded) = decode_erc20_transfer(&log, to_addr, tip) {
                if decoded.value_wei >= min_value && decoded.confirmations >= min_confs {
                    return Ok(Some(decoded));
                }
            }
        }
        Ok(None)
    }

    /// 20-byte address → 32-byte topic (left-padded with 12 zero
    /// bytes — the ABI encoding for `address` in topics).
    fn address_to_topic(a: EthAddress) -> B256 {
        let mut out = [0u8; 32];
        out[12..].copy_from_slice(a.as_slice());
        B256::from(out)
    }

    /// Decode the non-indexed args of a THORChain Router `TransferOut`
    /// event: `(address asset, uint256 amount, string memo)`. We only
    /// extract `amount` here — `asset` and `memo` are not needed for
    /// the cross-check (the policy validates amount + recipient).
    fn decode_router_transfer_out(log: &EvmLogEntry, tip: u64) -> Option<RouterTransferOut> {
        // `topic[2]` = to (indexed).
        let to_topic = *log.topics.get(2)?;
        let mut to_bytes = [0u8; 20];
        to_bytes.copy_from_slice(&to_topic.as_slice()[12..]);
        let to = EthAddress::from(to_bytes);
        // `data` ABI: address (32) ‖ uint256 (32) ‖ offset (32) ‖
        //             length (32) ‖ memo-bytes (padded).
        // We only need the amount at offset 32..64.
        let data = log.data.as_ref();
        if data.len() < 64 {
            return None;
        }
        let amount_word: [u8; 32] = data[32..64].try_into().ok()?;
        let amount = U256::from_be_slice(&amount_word);
        let value_wei = u128::try_from(amount).ok()?;
        let confirmations = u32::try_from(tip.saturating_sub(log.block_number).saturating_add(1))
            .unwrap_or(u32::MAX);
        Some(RouterTransferOut {
            value_wei,
            to,
            transaction_hash: log.transaction_hash,
            confirmations,
        })
    }

    /// Decode an ERC20 Transfer log. `topic[2]` = to (indexed). `data`
    /// is the 32-byte value.
    fn decode_erc20_transfer(
        log: &EvmLogEntry,
        expected_to: EthAddress,
        tip: u64,
    ) -> Option<RouterTransferOut> {
        let to_topic = *log.topics.get(2)?;
        let mut to_bytes = [0u8; 20];
        to_bytes.copy_from_slice(&to_topic.as_slice()[12..]);
        let to = EthAddress::from(to_bytes);
        if to != expected_to {
            return None;
        }
        let data = log.data.as_ref();
        if data.len() != 32 {
            return None;
        }
        let value_word: [u8; 32] = data.try_into().ok()?;
        let value = U256::from_be_slice(&value_word);
        let value_wei = u128::try_from(value).ok()?;
        let confirmations = u32::try_from(tip.saturating_sub(log.block_number).saturating_add(1))
            .unwrap_or(u32::MAX);
        Some(RouterTransferOut {
            value_wei,
            to,
            transaction_hash: log.transaction_hash,
            confirmations,
        })
    }

    // ──────────────────────────────────────────────────────────────
    // Policy: mint-side delivery on the EVM family
    // ──────────────────────────────────────────────────────────────

    /// Mint-side cross-check: returns `Ok(observed_wei)` when both
    /// `THORChain` reports `done` with a matching EVM outbound action
    /// AND the destination chain's Router emitted a `TransferOut` to
    /// the Safe.
    #[async_trait]
    pub trait EvmDeliveryCrossCheck: Send + Sync {
        /// `thor_inbound_tx_hash` is the inbound (the user's mint USDT
        /// deposit on Ethereum). The policy looks up the THORChain
        /// outbound action targeting our Safe + the on-chain
        /// confirmation.
        async fn verify(
            &self,
            thor_inbound_tx_hash: &str,
            expected_wei: u128,
        ) -> Result<u128, EvmCrossCheckError>;
    }

    /// Production mint policy: `THORChain` swapped USDT → native_X and
    /// the native value actually landed at the Safe (Router emitted
    /// `TransferOut`).
    pub struct ThorEvmPolicy<E: EvmChainClient> {
        thor: ThorClient,
        evm: E,
        /// The Safe contract address on the destination chain.
        safe_address: EthAddress,
        /// THORChain Router contract on the destination chain.
        router_address: EthAddress,
        /// `THORChain` chain string (`ETH` / `BSC` / `AVAX` / `BASE` /
        /// `POL`). Filter for the action's `chain` field.
        thor_chain_label: &'static str,
        min_confirmations: u32,
        /// Max |thor − on-chain| wei.
        tolerance_wei: u128,
        /// How far back `eth_get_logs` scans. Defaults to a 24-hour
        /// window worth of blocks for the configured chain — long
        /// enough to absorb the THORChain delivery latency.
        lookback_blocks: u64,
    }

    impl<E: EvmChainClient> std::fmt::Debug for ThorEvmPolicy<E> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ThorEvmPolicy")
                .field("safe_address", &self.safe_address)
                .field("router_address", &self.router_address)
                .field("thor_chain_label", &self.thor_chain_label)
                .field("min_confirmations", &self.min_confirmations)
                .field("tolerance_wei", &self.tolerance_wei)
                .field("lookback_blocks", &self.lookback_blocks)
                .finish_non_exhaustive()
        }
    }

    impl<E: EvmChainClient> ThorEvmPolicy<E> {
        /// Construct. `thor_chain_label` must match the
        /// destination chain's THORChain identifier
        /// (`ChainId::thor_asset` minus the asset suffix:
        /// `"ETH"` for `ETH.ETH`, `"BSC"` for `BSC.BNB`, etc.).
        #[must_use]
        pub fn new(
            thor: ThorClient,
            evm: E,
            safe_address: EthAddress,
            router_address: EthAddress,
            thor_chain_label: &'static str,
            min_confirmations: u32,
            tolerance_wei: u128,
            lookback_blocks: u64,
        ) -> Self {
            Self {
                thor,
                evm,
                safe_address,
                router_address,
                thor_chain_label,
                min_confirmations,
                tolerance_wei,
                lookback_blocks,
            }
        }
    }

    #[async_trait]
    impl<E: EvmChainClient> EvmDeliveryCrossCheck for ThorEvmPolicy<E> {
        async fn verify(
            &self,
            thor_inbound_tx_hash: &str,
            expected_wei: u128,
        ) -> Result<u128, EvmCrossCheckError> {
            let resp = self.thor.tx_status(thor_inbound_tx_hash).await?;
            if resp.observed_tx.status != "done" {
                return Err(EvmCrossCheckError::ThorNotReady {
                    reason: format!(
                        "observed_tx.status = {} (expected 'done')",
                        resp.observed_tx.status
                    ),
                });
            }
            // REFUND memo on this chain → caller used the wrong path.
            if resp.actions.iter().any(|a| {
                a.chain == self.thor_chain_label && a.memo.to_uppercase().starts_with("REFUND:")
            }) {
                return Err(EvmCrossCheckError::RefundedInstead);
            }
            let safe_str = format!("{:#x}", self.safe_address);
            let action = resp
                .actions
                .iter()
                .find(|a| {
                    a.chain == self.thor_chain_label && a.to_address.to_lowercase() == safe_str
                })
                .ok_or_else(|| EvmCrossCheckError::ThorNotReady {
                    reason: format!(
                        "no {chain} outbound action to {safe_str} in THORChain response",
                        chain = self.thor_chain_label,
                    ),
                })?;
            let thor_wei: u128 =
                action
                    .coin
                    .amount
                    .parse()
                    .map_err(|e| EvmCrossCheckError::ThorNotReady {
                        reason: format!(
                            "non-integer outbound amount '{}': {e}",
                            action.coin.amount
                        ),
                    })?;
            if !within(expected_wei, thor_wei, self.tolerance_wei) {
                return Err(EvmCrossCheckError::AmountMismatch {
                    thor_wei,
                    onchain_wei: expected_wei,
                });
            }
            let floor = thor_wei.saturating_sub(self.tolerance_wei);
            let observed = find_router_transfer_out(
                &self.evm,
                self.router_address,
                self.safe_address,
                floor,
                self.min_confirmations,
                self.lookback_blocks,
            )
            .await?
            .ok_or_else(|| EvmCrossCheckError::EvmNotReady {
                need_wei: thor_wei,
                min_confs: self.min_confirmations,
                safe: self.safe_address,
            })?;
            if !within(thor_wei, observed.value_wei, self.tolerance_wei) {
                return Err(EvmCrossCheckError::AmountMismatch {
                    thor_wei,
                    onchain_wei: observed.value_wei,
                });
            }
            info!(
                thor_inbound_tx_hash,
                safe = ?self.safe_address,
                observed_wei = observed.value_wei,
                "EVM mint cross-check OK"
            );
            // Attest the ON-CHAIN value — authoritative.
            Ok(observed.value_wei)
        }
    }

    /// Refund policy: `THORChain` slip-refunded native_X back to our
    /// Safe (`REFUND:<txid>` memo) and the Router emitted the
    /// `TransferOut` accordingly. Mutually exclusive with the delivery
    /// path — disambiguated by the `REFUND:` memo.
    pub struct ThorEvmRefundPolicy<E: EvmChainClient> {
        thor: ThorClient,
        evm: E,
        safe_address: EthAddress,
        router_address: EthAddress,
        thor_chain_label: &'static str,
        min_confirmations: u32,
        tolerance_wei: u128,
        lookback_blocks: u64,
    }

    impl<E: EvmChainClient> std::fmt::Debug for ThorEvmRefundPolicy<E> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ThorEvmRefundPolicy")
                .field("safe_address", &self.safe_address)
                .field("thor_chain_label", &self.thor_chain_label)
                .finish_non_exhaustive()
        }
    }

    impl<E: EvmChainClient> ThorEvmRefundPolicy<E> {
        #[must_use]
        pub fn new(
            thor: ThorClient,
            evm: E,
            safe_address: EthAddress,
            router_address: EthAddress,
            thor_chain_label: &'static str,
            min_confirmations: u32,
            tolerance_wei: u128,
            lookback_blocks: u64,
        ) -> Self {
            Self {
                thor,
                evm,
                safe_address,
                router_address,
                thor_chain_label,
                min_confirmations,
                tolerance_wei,
                lookback_blocks,
            }
        }
    }

    #[async_trait]
    impl<E: EvmChainClient> RefundCrossCheck for ThorEvmRefundPolicy<E> {
        async fn verify(&self, thor_inbound_tx_hash: &str) -> Result<u64, RefundCrossCheckError> {
            let resp = self.thor.tx_status(thor_inbound_tx_hash).await?;
            if resp.observed_tx.status != "done" {
                return Err(RefundCrossCheckError::ThorNotReady {
                    reason: format!("observed_tx.status = {}", resp.observed_tx.status),
                });
            }
            // Mutual-exclusion: a delivery (USDT or native to user wallet)
            // means caller picked the wrong path.
            if resp.actions.iter().any(|a| {
                a.chain == self.thor_chain_label && !a.memo.to_uppercase().starts_with("REFUND:")
            }) {
                return Err(RefundCrossCheckError::DeliveredInstead);
            }
            let safe_str = format!("{:#x}", self.safe_address);
            let action = resp
                .actions
                .iter()
                .find(|a| {
                    a.chain == self.thor_chain_label
                        && a.to_address.to_lowercase() == safe_str
                        && a.memo.to_uppercase().starts_with("REFUND:")
                })
                .ok_or_else(|| RefundCrossCheckError::ThorNotReady {
                    reason: "no REFUND action targeting our Safe".to_string(),
                })?;
            let thor_wei: u128 =
                action
                    .coin
                    .amount
                    .parse()
                    .map_err(|e| RefundCrossCheckError::ThorNotReady {
                        reason: format!("non-integer refund amount '{}': {e}", action.coin.amount),
                    })?;
            let floor = thor_wei.saturating_sub(self.tolerance_wei);
            let observed = find_router_transfer_out(
                &self.evm,
                self.router_address,
                self.safe_address,
                floor,
                self.min_confirmations,
                self.lookback_blocks,
            )
            .await
            .map_err(|e| match e {
                EvmCrossCheckError::Evm(inner) => {
                    // Re-cast to the refund error shape — same root cause.
                    RefundCrossCheckError::ThorNotReady {
                        reason: format!("EVM RPC failure: {inner}"),
                    }
                }
                other => RefundCrossCheckError::ThorNotReady {
                    reason: format!("EVM lookup failed: {other}"),
                },
            })?
            .ok_or_else(|| RefundCrossCheckError::BtcNotReady {
                // `BtcNotReady` is misnamed at this layer — the variant
                // is reused for "destination chain not ready" across
                // refund families. Variant rename is a v2 refactor.
                need_sats: u64::try_from(thor_wei).unwrap_or(u64::MAX),
                confs: self.min_confirmations,
            })?;
            if !within(thor_wei, observed.value_wei, self.tolerance_wei) {
                // Re-use the existing AmountMismatch shape (sats-named
                // but semantically "smallest-unit").
                return Err(RefundCrossCheckError::AmountMismatch {
                    thor_sats: u64::try_from(thor_wei).unwrap_or(u64::MAX),
                    utxo_sats: u64::try_from(observed.value_wei).unwrap_or(u64::MAX),
                });
            }
            warn!(
                thor_inbound_tx_hash,
                refund_wei = observed.value_wei,
                "EVM refund cross-check OK"
            );
            // `RefundCrossCheck::verify` returns `u64`. EVM wei truncates
            // — but the on-chain attestation amount field is a u256 we
            // cast from here. Cap at u64::MAX to be safe; the actual
            // refund attestation path lifts via a wider numeric carrier
            // (V7 follow-up).
            Ok(u64::try_from(observed.value_wei).unwrap_or(u64::MAX))
        }
    }

    /// Redeem-side cross-check: USDT delivered to IndexToken on
    /// Ethereum AFTER our Safe-on-X swapped native_X → USDT via
    /// THORChain. The `<E>` is an Ethereum-mainnet `EvmChainClient`;
    /// the policy scans the USDT contract for a `Transfer` log to the
    /// IndexToken.
    pub struct ThorEvmToUsdtPolicy<E: EvmChainClient> {
        thor: ThorClient,
        evm: E,
        /// USDT ERC20 contract on Ethereum.
        usdt_token: EthAddress,
        min_confirmations: u32,
        /// Max |thor − on-chain| in 1e6 USDT units.
        tolerance_1e6: u128,
        lookback_blocks: u64,
    }

    impl<E: EvmChainClient> std::fmt::Debug for ThorEvmToUsdtPolicy<E> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ThorEvmToUsdtPolicy")
                .field("usdt_token", &self.usdt_token)
                .field("min_confirmations", &self.min_confirmations)
                .finish_non_exhaustive()
        }
    }

    impl<E: EvmChainClient> ThorEvmToUsdtPolicy<E> {
        #[must_use]
        pub fn new(
            thor: ThorClient,
            evm: E,
            usdt_token: EthAddress,
            min_confirmations: u32,
            tolerance_1e6: u128,
            lookback_blocks: u64,
        ) -> Self {
            Self {
                thor,
                evm,
                usdt_token,
                min_confirmations,
                tolerance_1e6,
                lookback_blocks,
            }
        }
    }

    /// `THORChain` reports all amounts in 1e8 fixed precision; USDT
    /// on-chain is 1e6. Divide-down by 100 (mirrors the UTXO ToUsdt
    /// policy's `THOR_TO_USDT_SCALE` constant).
    const THOR_TO_USDT_SCALE: u128 = 100;

    #[async_trait]
    impl<E: EvmChainClient> RedemptionCrossCheck for ThorEvmToUsdtPolicy<E> {
        async fn verify(
            &self,
            evm_inbound_tx_hash: &str,
            index_token: EthAddress,
        ) -> Result<u128, RedemptionCrossCheckError> {
            let resp = self.thor.tx_status(evm_inbound_tx_hash).await?;
            if resp.observed_tx.status != "done" {
                return Err(RedemptionCrossCheckError::ThorNotReady {
                    reason: format!("observed_tx.status = {}", resp.observed_tx.status),
                });
            }
            if resp
                .actions
                .iter()
                .any(|a| a.chain == "ETH" && a.memo.to_uppercase().starts_with("REFUND:"))
            {
                return Err(RedemptionCrossCheckError::RefundedInstead);
            }
            let want = format!("{index_token:#x}");
            let action = resp
                .actions
                .iter()
                .find(|a| {
                    a.chain == "ETH"
                        && a.coin.asset.to_uppercase().starts_with("ETH.USDT")
                        && a.to_address.to_lowercase() == want
                })
                .ok_or_else(|| RedemptionCrossCheckError::ThorNotReady {
                    reason: "no ETH.USDT outbound to the IndexToken yet".to_string(),
                })?;
            let thor_1e8: u128 = action.coin.amount.parse().map_err(|e| {
                RedemptionCrossCheckError::ThorNotReady {
                    reason: format!("non-integer outbound amount '{}': {e}", action.coin.amount),
                }
            })?;
            let thor_1e6 = thor_1e8 / THOR_TO_USDT_SCALE;
            let floor = thor_1e6.saturating_sub(self.tolerance_1e6);
            let arrival = find_erc20_transfer_to(
                &self.evm,
                self.usdt_token,
                index_token,
                floor,
                self.min_confirmations,
                self.lookback_blocks,
            )
            .await
            .map_err(|e| match e {
                EvmCrossCheckError::Evm(inner) => {
                    RedemptionCrossCheckError::Eth(super::Erc20Error::Rpc(format!("{inner}")))
                }
                other => RedemptionCrossCheckError::ThorNotReady {
                    reason: format!("EVM lookup failed: {other}"),
                },
            })?
            .ok_or(RedemptionCrossCheckError::UsdtNotReady {
                need_1e6: thor_1e6,
                confs: self.min_confirmations,
            })?;
            if !within(thor_1e6, arrival.value_wei, self.tolerance_1e6) {
                return Err(RedemptionCrossCheckError::AmountMismatch {
                    thor_1e6,
                    onchain_1e6: arrival.value_wei,
                });
            }
            info!(
                evm_inbound_tx_hash,
                onchain_usdt_1e6 = arrival.value_wei,
                "EVM redeem cross-check OK"
            );
            Ok(arrival.value_wei)
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Tests
    // ──────────────────────────────────────────────────────────────

    #[cfg(test)]
    mod tests {
        use super::*;
        use alloy_primitives::{Address, Bytes};
        use std::sync::Mutex;
        use xindex_chain_evm::{EvmConfirmedReceipt, EvmTransactionSummary};
        use xindex_shared::chain_registry::{ChainId, EvmTxType};

        /// In-memory `EvmChainClient` for tests. Holds canned logs +
        /// a current tip; everything else stubbed.
        #[derive(Debug)]
        struct StubEvm {
            chain: ChainId,
            tip: Mutex<u64>,
            logs: Mutex<Vec<EvmLogEntry>>,
        }

        impl StubEvm {
            fn new(chain: ChainId, tip: u64) -> Self {
                Self {
                    chain,
                    tip: Mutex::new(tip),
                    logs: Mutex::new(Vec::new()),
                }
            }
            #[expect(clippy::expect_used, reason = "test code")]
            fn push(&self, log: EvmLogEntry) {
                self.logs.lock().expect("lock").push(log);
            }
        }

        impl EvmChainClient for StubEvm {
            fn chain(&self) -> ChainId {
                self.chain
            }
            fn evm_chain_id(&self) -> u64 {
                #[expect(clippy::expect_used, reason = "test code")]
                self.chain.evm_chain_id().expect("evm")
            }
            fn tx_type(&self) -> EvmTxType {
                #[expect(clippy::expect_used, reason = "test code")]
                self.chain.tx_type().expect("evm")
            }
            async fn block_number(&self) -> Result<u64, EvmChainError> {
                #[expect(clippy::expect_used, reason = "test code")]
                Ok(*self.tip.lock().expect("lock"))
            }
            async fn safe_nonce(&self, _safe: Address) -> Result<u64, EvmChainError> {
                Ok(0)
            }
            async fn eth_call(&self, _to: Address, _data: Bytes) -> Result<Bytes, EvmChainError> {
                Ok(Bytes::new())
            }
            async fn eth_get_transaction_by_hash(
                &self,
                _hash: B256,
            ) -> Result<Option<EvmTransactionSummary>, EvmChainError> {
                Ok(None)
            }
            async fn eth_get_logs(
                &self,
                filter: EvmLogFilter,
            ) -> Result<Vec<EvmLogEntry>, EvmChainError> {
                #[expect(clippy::expect_used, reason = "test code")]
                let all = self.logs.lock().expect("lock").clone();
                let out: Vec<EvmLogEntry> = all
                    .into_iter()
                    .filter(|l| {
                        let in_range = filter.from_block.is_none_or(|f| l.block_number >= f)
                            && filter.to_block.is_none_or(|t| l.block_number <= t);
                        let addr_ok = filter.address.is_none_or(|a| l.address == a);
                        let topic0_ok = filter.topic0.is_none_or(|t| l.topics.first() == Some(&t));
                        let topic_filters_ok =
                            filter.topics_1_3.iter().enumerate().all(|(i, opt)| {
                                opt.is_none_or(|want| l.topics.get(i + 1) == Some(&want))
                            });
                        in_range && addr_ok && topic0_ok && topic_filters_ok
                    })
                    .collect();
                Ok(out)
            }
            async fn submit_raw(&self, _raw: Bytes) -> Result<B256, EvmChainError> {
                Ok(B256::ZERO)
            }
            async fn wait_for_confirmations(
                &self,
                _hash: B256,
                _depth: u32,
                _timeout: std::time::Duration,
            ) -> Result<EvmConfirmedReceipt, EvmChainError> {
                unreachable!()
            }
        }

        fn router_log(router: Address, safe: Address, wei: u128, block: u64) -> EvmLogEntry {
            // topics: [topic0, vault (any), to (= safe)]
            let mut to_topic = [0u8; 32];
            to_topic[12..].copy_from_slice(safe.as_slice());
            // data: address (32) | uint256 amount (32) | offset (32) | length (32) | memo
            let mut data = vec![0u8; 64];
            data[32..64].copy_from_slice(&U256::from(wei).to_be_bytes::<32>());
            data.extend_from_slice(&[0u8; 32]); // offset
            data.extend_from_slice(&[0u8; 32]); // length=0
            EvmLogEntry {
                address: router,
                topics: vec![
                    THOR_TRANSFER_OUT_TOPIC0,
                    B256::ZERO, // vault (any)
                    B256::from(to_topic),
                ],
                data: Bytes::from(data),
                block_number: block,
                transaction_hash: B256::ZERO,
            }
        }

        fn erc20_transfer_log(
            token: Address,
            from: Address,
            to: Address,
            value: u128,
            block: u64,
        ) -> EvmLogEntry {
            let mut from_topic = [0u8; 32];
            from_topic[12..].copy_from_slice(from.as_slice());
            let mut to_topic = [0u8; 32];
            to_topic[12..].copy_from_slice(to.as_slice());
            let data = U256::from(value).to_be_bytes::<32>();
            EvmLogEntry {
                address: token,
                topics: vec![
                    ERC20_TRANSFER_TOPIC0,
                    B256::from(from_topic),
                    B256::from(to_topic),
                ],
                data: Bytes::from(data.to_vec()),
                block_number: block,
                transaction_hash: B256::ZERO,
            }
        }

        const SAFE: Address = Address::new([0xab; 20]);
        const ROUTER: Address = Address::new([0xcd; 20]);

        async fn thor_done_responder(action_json: serde_json::Value) -> wiremock::MockServer {
            let server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/thorchain/tx/abc"))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({
                        "observed_tx": {
                            "tx": {
                                "id": "abc", "chain": "ETH",
                                "from_address": "0xUser", "to_address": "0xRouter",
                                "coins": [], "memo": ""
                            },
                            "status": "done"
                        },
                        "actions": [action_json],
                    }),
                ))
                .mount(&server)
                .await;
            server
        }

        /// Mint path happy case: THORChain reports done with a matching
        /// outbound; EVM Router emitted a TransferOut to the Safe at
        /// the expected amount + enough confs.
        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn evm_mint_policy_success_returns_observed_wei() {
            let safe_str = format!("{SAFE:#x}");
            let server = thor_done_responder(serde_json::json!({
                "chain": "ETH",
                "to_address": safe_str,
                "coin": { "asset": "ETH.ETH", "amount": "1000000000000000000" },
                "memo": "OUT:abc",
                "max_gas": []
            }))
            .await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let evm = StubEvm::new(ChainId::Eth, 100);
            evm.push(router_log(ROUTER, SAFE, 1_000_000_000_000_000_000, 95));
            let policy = ThorEvmPolicy::new(thor, evm, SAFE, ROUTER, "ETH", 3, 0, 1000);
            let out = policy
                .verify("abc", 1_000_000_000_000_000_000)
                .await
                .expect("ok");
            assert_eq!(out, 1_000_000_000_000_000_000);
        }

        /// THORChain says done but EVM Router has no matching log →
        /// EvmNotReady.
        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn evm_mint_policy_evm_not_ready_when_no_log() {
            let safe_str = format!("{SAFE:#x}");
            let server = thor_done_responder(serde_json::json!({
                "chain": "ETH",
                "to_address": safe_str,
                "coin": { "asset": "ETH.ETH", "amount": "5000" },
                "memo": "OUT:abc",
                "max_gas": []
            }))
            .await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let evm = StubEvm::new(ChainId::Eth, 100);
            // No log pushed.
            let policy = ThorEvmPolicy::new(thor, evm, SAFE, ROUTER, "ETH", 3, 0, 1000);
            let err = policy
                .verify("abc", 5_000)
                .await
                .expect_err("should reject");
            assert!(
                matches!(err, EvmCrossCheckError::EvmNotReady { .. }),
                "expected EvmNotReady, got {err:?}"
            );
        }

        /// Mint path: REFUND memo on the same chain → RefundedInstead.
        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn evm_mint_policy_refunded_instead() {
            let safe_str = format!("{SAFE:#x}");
            let server = thor_done_responder(serde_json::json!({
                "chain": "ETH",
                "to_address": safe_str,
                "coin": { "asset": "ETH.ETH", "amount": "5000" },
                "memo": "REFUND:abc",
                "max_gas": []
            }))
            .await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let evm = StubEvm::new(ChainId::Eth, 100);
            let policy = ThorEvmPolicy::new(thor, evm, SAFE, ROUTER, "ETH", 3, 0, 1000);
            let err = policy
                .verify("abc", 5_000)
                .await
                .expect_err("should reject");
            assert!(
                matches!(err, EvmCrossCheckError::RefundedInstead),
                "expected RefundedInstead, got {err:?}"
            );
        }

        /// Mint path: THORChain claim doesn't match the on-chain log
        /// → AmountMismatch.
        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn evm_mint_policy_amount_mismatch() {
            let safe_str = format!("{SAFE:#x}");
            let server = thor_done_responder(serde_json::json!({
                "chain": "ETH",
                "to_address": safe_str,
                "coin": { "asset": "ETH.ETH", "amount": "1000" },
                "memo": "OUT:abc",
                "max_gas": []
            }))
            .await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let evm = StubEvm::new(ChainId::Eth, 100);
            // On-chain log has DIFFERENT amount than THORChain claims.
            evm.push(router_log(ROUTER, SAFE, 9_999, 95));
            let policy = ThorEvmPolicy::new(thor, evm, SAFE, ROUTER, "ETH", 3, 0, 1000);
            let err = policy
                .verify("abc", 1_000)
                .await
                .expect_err("should reject");
            assert!(
                matches!(err, EvmCrossCheckError::AmountMismatch { .. }),
                "expected AmountMismatch, got {err:?}"
            );
        }

        /// Refund happy path: THORChain REFUND action to Safe + Router
        /// emitted matching TransferOut.
        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn evm_refund_policy_success() {
            let safe_str = format!("{SAFE:#x}");
            let server = thor_done_responder(serde_json::json!({
                "chain": "ETH",
                "to_address": safe_str,
                "coin": { "asset": "ETH.ETH", "amount": "777" },
                "memo": "REFUND:abc",
                "max_gas": []
            }))
            .await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let evm = StubEvm::new(ChainId::Eth, 50);
            evm.push(router_log(ROUTER, SAFE, 777, 45));
            let policy = ThorEvmRefundPolicy::new(thor, evm, SAFE, ROUTER, "ETH", 3, 0, 1000);
            let out = policy.verify("abc").await.expect("ok");
            assert_eq!(out, 777);
        }

        /// Refund path: delivery action present (non-REFUND memo) →
        /// DeliveredInstead.
        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn evm_refund_policy_delivered_instead() {
            let safe_str = format!("{SAFE:#x}");
            let server = thor_done_responder(serde_json::json!({
                "chain": "ETH",
                "to_address": safe_str,
                "coin": { "asset": "ETH.ETH", "amount": "777" },
                "memo": "OUT:abc",
                "max_gas": []
            }))
            .await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let evm = StubEvm::new(ChainId::Eth, 50);
            let policy = ThorEvmRefundPolicy::new(thor, evm, SAFE, ROUTER, "ETH", 3, 0, 1000);
            let err = policy.verify("abc").await.expect_err("should reject");
            assert!(
                matches!(err, RefundCrossCheckError::DeliveredInstead),
                "expected DeliveredInstead, got {err:?}"
            );
        }

        /// USDT redeem happy path: THORChain ETH.USDT outbound to
        /// IndexToken + USDT contract emitted matching Transfer log.
        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn evm_redeem_to_usdt_success() {
            const USDT: Address = Address::new([0x33; 20]);
            const INDEX_TOKEN: Address = Address::new([0x44; 20]);
            let it_str = format!("{INDEX_TOKEN:#x}");
            let server = thor_done_responder(serde_json::json!({
                "chain": "ETH",
                "to_address": it_str,
                "coin": { "asset": "ETH.USDT-0xdAC17F958D2ee523a2206206994597C13D831ec7", "amount": "100000000" },
                "memo": "OUT:abc",
                "max_gas": []
            }))
            .await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let evm = StubEvm::new(ChainId::Eth, 100);
            // 1e8 in THORChain units / 100 = 1e6 = 1,000,000 USDT (1e6).
            evm.push(erc20_transfer_log(
                USDT,
                Address::new([0x55; 20]),
                INDEX_TOKEN,
                1_000_000,
                95,
            ));
            let policy = ThorEvmToUsdtPolicy::new(thor, evm, USDT, 3, 0, 1000);
            let out = policy.verify("abc", INDEX_TOKEN).await.expect("ok");
            assert_eq!(out, 1_000_000);
        }
    }
}
