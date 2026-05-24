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

use alloy_primitives::Address as EthAddress;
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

/* ========================================================================== */
/*            BURN → USDT redemption cross-checks (verify-the-refund)          */
/* ========================================================================== */

/// `THORChain` reports ALL asset amounts in 1e8 fixed precision in its
/// API, regardless of the asset's native decimals. USDT on-chain is
/// 1e6. Converting a `THORChain` ETH.USDT figure to the on-chain ERC20
/// value divides by this factor (1e8 / 1e6 = 100). The mint-side
/// `ThorBtcPolicy` never needed this because BTC is 1e8 BOTH sides
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
/// mint pattern where `BitcoinChainClient` lives in `chain-btc` and the
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
    Btc(#[from] BitcoinError),
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
/// independent observations, like the mint-side `ThorBtcPolicy`.
pub struct ThorBtcToUsdtPolicy<E: Erc20ArrivalClient> {
    thor: ThorClient,
    erc20: E,
    /// Mainnet USDT ERC20 address.
    usdt_token: EthAddress,
    min_confirmations: u32,
    /// Max |thor − on-chain| (in 1e6 USDT) accepted.
    tolerance_1e6: u128,
}

impl<E: Erc20ArrivalClient> std::fmt::Debug for ThorBtcToUsdtPolicy<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThorBtcToUsdtPolicy")
            .field("usdt_token", &self.usdt_token)
            .field("min_confirmations", &self.min_confirmations)
            .field("tolerance_1e6", &self.tolerance_1e6)
            .finish_non_exhaustive()
    }
}

impl<E: Erc20ArrivalClient> ThorBtcToUsdtPolicy<E> {
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
impl<E: Erc20ArrivalClient> RedemptionCrossCheck for ThorBtcToUsdtPolicy<E> {
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
pub struct ThorBtcRefundPolicy<C: BitcoinChainClient + Send + Sync> {
    thor: ThorClient,
    btc: C,
    btc_multisig_address: Address,
    min_confirmations: u32,
    tolerance_sats: u64,
}

impl<C: BitcoinChainClient + Send + Sync> std::fmt::Debug for ThorBtcRefundPolicy<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThorBtcRefundPolicy")
            .field("btc_multisig_address", &self.btc_multisig_address)
            .field("min_confirmations", &self.min_confirmations)
            .field("tolerance_sats", &self.tolerance_sats)
            .finish_non_exhaustive()
    }
}

impl<C: BitcoinChainClient + Send + Sync> ThorBtcRefundPolicy<C> {
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
impl<C: BitcoinChainClient + Send + Sync> RefundCrossCheck for ThorBtcRefundPolicy<C> {
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
        let policy = ThorBtcPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
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
        let policy = ThorBtcPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
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
        let policy = ThorBtcToUsdtPolicy::new(thor, erc20, usdt_token(), 6, 0);
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
        let policy = ThorBtcToUsdtPolicy::new(thor, StubErc20::default(), usdt_token(), 6, 0);
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
        btc.utxos.lock().expect("lock").push(BitcoinUtxo {
            txid: Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000abc",
            )
            .expect("txid"),
            vout: 0,
            value: Amount::from_sat(99_990_000),
            confirmations: 6,
            block_hash: None,
        });
        let policy = ThorBtcRefundPolicy::new(thor, btc, test_address(), 1, 0);
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
        let policy = ThorBtcRefundPolicy::new(thor, StubBtc::default(), test_address(), 1, 0);
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
        let policy = ThorBtcToUsdtPolicy::new(thor, StubErc20::default(), usdt_token(), 6, 0);
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
        let policy = ThorBtcToUsdtPolicy::new(thor, StubErc20::default(), usdt_token(), 6, 0);
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
        let policy = ThorBtcToUsdtPolicy::new(thor, erc20, usdt_token(), 6, 0);
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
        btc.utxos.lock().expect("lock").push(BitcoinUtxo {
            txid: Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000abc",
            )
            .expect("txid"),
            vout: 0,
            value: Amount::from_sat(99_990_000),
            confirmations: 6,
            block_hash: None,
        });
        let policy = ThorBtcRefundPolicy::new(thor, btc, test_address(), 1, 0);
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
            let policy = ThorBtcRefundPolicy::new(thor, StubBtc::default(), test_address(), 1, 0);
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
        btc.utxos.lock().expect("lock").push(BitcoinUtxo {
            txid: Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000abc",
            )
            .expect("txid"),
            vout: 0,
            value: Amount::from_sat(100_010), // diff 10 > tolerance 5
            confirmations: 6,
            block_hash: None,
        });
        let policy = ThorBtcRefundPolicy::new(thor, btc, test_address(), 1, 5);
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
