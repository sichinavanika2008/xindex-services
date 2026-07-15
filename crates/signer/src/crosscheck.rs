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

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::{Address as EthAddress, B256};
use async_trait::async_trait;
use bitcoin::hashes::Hash;
#[cfg(test)]
use bitcoin::Amount;
use bitcoin::Txid;
use bitcoin::{Address, Network};
use serde::Serialize;
use std::str::FromStr;
use thiserror::Error;
use tracing::{info, warn};

use xindex_chain_thor::{
    HistoricalAsgardMembership, InboundAddress, ThorClient, ThorError, TxDetailsResponse,
    TxResponse,
};
use xindex_chain_utxo::{UtxoChainClient, UtxoError};
use xindex_shared::consumed_inflow::{
    AnyConsumedInflow, ConsumedInflowError, ConsumedInflowStore, InflowConsumeOutcome,
};
use xindex_shared::native_inflow::{
    AnyNativeInflow, NativeFlowKind, NativeInflowClaim, NativeInflowError, NativeInflowOutcome,
    NativeInflowStore,
};

/// Errors surfaced by the cross-check.
#[derive(Debug, Error)]
pub enum CrossCheckError {
    #[error("`THORChain` RPC error: {0}")]
    Thor(#[from] ThorError),
    #[error("Bitcoin chain error: {0}")]
    Btc(#[from] UtxoError),
    #[error("native inflow ledger: {0}")]
    NativeLedger(#[from] NativeInflowError),
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
    native_inflows: Arc<AnyNativeInflow>,
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
            native_inflows: Arc::new(AnyNativeInflow::memory()),
        }
    }

    #[must_use]
    pub fn with_native_inflows(
        thor: ThorClient,
        btc: C,
        btc_multisig_address: Address,
        min_confirmations: u32,
        tolerance_sats: u64,
        native_inflows: Arc<AnyNativeInflow>,
    ) -> Self {
        Self {
            thor,
            btc,
            btc_multisig_address,
            min_confirmations,
            tolerance_sats,
            native_inflows,
        }
    }

    fn within_tolerance(&self, expected: u64, actual: u64) -> bool {
        actual.abs_diff(expected) <= self.tolerance_sats
    }

    /// Resolve and consume the actual finalized BTC delivery for a mint slot.
    /// This is the production path for current intents whose async preview is
    /// intentionally zero: the attested amount comes from the exact observed
    /// `THORChain` outbound and Bitcoin UTXO, never from the preview.
    ///
    /// # Errors
    /// Returns [`CrossCheckError`] unless the planned action, observed
    /// outbound, live Asgard funder, confirmed UTXO, and one-shot ledger all
    /// agree on one unambiguous delivery.
    pub async fn observe_settlement(
        &self,
        thor_inbound_tx_hash: &str,
        intent_id: B256,
        slot_index: u32,
    ) -> Result<u64, CrossCheckError> {
        self.verify_settlement(thor_inbound_tx_hash, None, intent_id, slot_index)
            .await
    }

    /// Resolve and consume a mint delivery from a caller-supplied, already
    /// quorum-agreed `THORChain` snapshot. Production settlement observers use
    /// this path so the policy cannot re-query one primary source after the
    /// three-source evidence set was fixed.
    ///
    /// # Errors
    /// The same fail-closed policy errors as [`Self::observe_settlement`].
    #[expect(
        clippy::too_many_arguments,
        reason = "the snapshot API binds transaction views, current halt state, historical membership, and lifecycle identity"
    )]
    pub async fn observe_settlement_from_snapshot(
        &self,
        thor_inbound_tx_hash: &str,
        status: &TxResponse,
        details: &TxDetailsResponse,
        current_vault: &InboundAddress,
        historical_membership: &HistoricalAsgardMembership,
        intent_id: B256,
        slot_index: u32,
    ) -> Result<u64, CrossCheckError> {
        self.verify_settlement_snapshot(
            thor_inbound_tx_hash,
            status,
            details,
            current_vault,
            historical_membership,
            None,
            intent_id,
            slot_index,
        )
        .await
    }

    async fn verify_settlement(
        &self,
        thor_inbound_tx_hash: &str,
        expected_sats: Option<u64>,
        lifecycle_id: B256,
        slot_index: u32,
    ) -> Result<u64, CrossCheckError> {
        let status = self.thor.tx_status(thor_inbound_tx_hash).await?;
        let details = self.thor.tx_details(thor_inbound_tx_hash).await?;
        let historical_membership = self
            .thor
            .historical_asgard_membership(&status, "BTC")
            .await?;
        let current_vault = self.thor.vault_for_chain("BTC").await?.ok_or_else(|| {
            CrossCheckError::ThorNotReady {
                reason: "no BTC inbound address from THORChain".to_string(),
            }
        })?;
        self.verify_settlement_snapshot(
            thor_inbound_tx_hash,
            &status,
            &details,
            &current_vault,
            &historical_membership,
            expected_sats,
            lifecycle_id,
            slot_index,
        )
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the snapshot policy deliberately binds the agreed THOR views, Bitcoin observation, and durable lifecycle claim in one auditable sequence"
    )]
    async fn verify_settlement_snapshot(
        &self,
        thor_inbound_tx_hash: &str,
        resp: &TxResponse,
        details: &TxDetailsResponse,
        current_vault: &InboundAddress,
        historical_membership: &HistoricalAsgardMembership,
        expected_sats: Option<u64>,
        lifecycle_id: B256,
        slot_index: u32,
    ) -> Result<u64, CrossCheckError> {
        if lifecycle_id == B256::ZERO {
            return Err(CrossCheckError::ThorNotReady {
                reason: "mint lifecycle id is zero".to_string(),
            });
        }
        if resp.observed_tx.status != "done" {
            return Err(CrossCheckError::ThorNotReady {
                reason: format!(
                    "observed_tx.status = {} (expected 'done')",
                    resp.observed_tx.status
                ),
            });
        }
        let multisig = self.btc_multisig_address.to_string();
        let actions: Vec<_> = resp
            .actions
            .iter()
            .filter(|action| {
                action.chain == "BTC"
                    && action.to_address == multisig
                    && action.coin.asset.eq_ignore_ascii_case("BTC.BTC")
            })
            .collect();
        if actions.len() != 1 {
            return Err(CrossCheckError::ThorNotReady {
                reason: format!(
                    "expected exactly one BTC.BTC action to custody, got {}",
                    actions.len()
                ),
            });
        }
        let action = actions[0];
        let thor_sats: u64 =
            action
                .coin
                .amount
                .parse()
                .map_err(|error| CrossCheckError::ThorNotReady {
                    reason: format!(
                        "non-integer outbound amount '{}': {error}",
                        action.coin.amount
                    ),
                })?;
        if thor_sats == 0 {
            return Err(CrossCheckError::ThorNotReady {
                reason: "zero BTC outbound amount".to_string(),
            });
        }
        if let Some(expected) = expected_sats {
            if !self.within_tolerance(expected, thor_sats) {
                return Err(CrossCheckError::AmountMismatch {
                    thor_sats,
                    claim_sats: expected,
                });
            }
        }

        let matching_outbounds: Vec<_> = details
            .out_txs
            .iter()
            .filter(|outbound| {
                outbound.chain == "BTC"
                    && outbound.to_address == multisig
                    && outbound.coins.iter().any(|coin| {
                        coin.asset.eq_ignore_ascii_case("BTC.BTC")
                            && coin
                                .amount
                                .parse::<u64>()
                                .is_ok_and(|amount| self.within_tolerance(thor_sats, amount))
                    })
            })
            .collect();
        if matching_outbounds.len() != 1 {
            return Err(CrossCheckError::ThorNotReady {
                reason: format!(
                    "expected exactly one observed BTC outbound, got {}",
                    matching_outbounds.len()
                ),
            });
        }
        let observed_txid = Txid::from_str(&matching_outbounds[0].id).map_err(|error| {
            CrossCheckError::ThorNotReady {
                reason: format!("observed BTC outbound txid is invalid: {error}"),
            }
        })?;

        if current_vault.chain != "BTC"
            || current_vault.address.is_empty()
            || current_vault.halted
            || current_vault.chain_trading_paused
            || current_vault.global_trading_paused
            || current_vault.chain_lp_actions_paused
        {
            return Err(CrossCheckError::ThorNotReady {
                reason: "BTC trading or LP actions halted on THORChain".to_string(),
            });
        }
        if historical_membership.chain != "BTC"
            || historical_membership.addresses.is_empty()
            || resp.historical_asgard_height().ok() != Some(historical_membership.height)
        {
            return Err(CrossCheckError::ThorNotReady {
                reason: "historical BTC Asgard membership does not match finalised height"
                    .to_string(),
            });
        }

        let utxos = self.btc.get_address_utxos(&self.btc_multisig_address)?;
        let candidates: Vec<_> = utxos
            .iter()
            .filter(|utxo| {
                utxo.txid == observed_txid
                    && utxo.confirmations >= self.min_confirmations
                    && self.within_tolerance(thor_sats, utxo.value.to_sat())
            })
            .collect();
        if candidates.is_empty() {
            return Err(CrossCheckError::BtcNotReady {
                needed_sats: thor_sats,
                min_confs: self.min_confirmations,
            });
        }
        if candidates.len() != 1 {
            return Err(CrossCheckError::ThorNotReady {
                reason: format!(
                    "observed BTC transaction has {} ambiguous custody outputs",
                    candidates.len()
                ),
            });
        }
        let utxo = candidates[0];
        let actual_sats = utxo.value.to_sat();
        if let Some(expected) = expected_sats {
            if !self.within_tolerance(expected, actual_sats) {
                return Err(CrossCheckError::AmountMismatch {
                    thor_sats: actual_sats,
                    claim_sats: expected,
                });
            }
        }
        let funders = self.btc.tx_input_addresses(&utxo.txid)?;
        if !funders
            .iter()
            .any(|funder| historical_membership.contains(funder))
        {
            return Err(CrossCheckError::ThorNotReady {
                reason: "BTC UTXO not funded by historical active/retiring Asgard membership"
                    .to_string(),
            });
        }

        let physical_hash = B256::from(utxo.txid.to_raw_hash().to_byte_array());
        let outcome = self
            .native_inflows
            .consume(
                xindex_shared::chain_registry::ChainId::Btc,
                physical_hash,
                utxo.vout,
                NativeInflowClaim {
                    kind: NativeFlowKind::MintDelivery,
                    lifecycle_id,
                    leg_index: slot_index,
                },
                observation_time()?,
            )
            .await?;
        if matches!(outcome, NativeInflowOutcome::Conflict { .. }) {
            return Err(CrossCheckError::ThorNotReady {
                reason: "observed BTC output was already consumed by another lifecycle".to_string(),
            });
        }

        info!(
            tx_hash = thor_inbound_tx_hash,
            actual_sats, "cross-check OK — THORChain observed outbound + exact BTC UTXO confirmed"
        );
        Ok(actual_sats)
    }
}

#[async_trait]
impl<C: UtxoChainClient + Send + Sync> CrossCheck for ThorUtxoPolicy<C> {
    async fn verify(
        &self,
        thor_inbound_tx_hash: &str,
        expected_sats: u64,
    ) -> Result<(), CrossCheckError> {
        let lifecycle_id =
            parse_thor_hash(thor_inbound_tx_hash).ok_or_else(|| CrossCheckError::ThorNotReady {
                reason: "THOR inbound hash is not bytes32".to_string(),
            })?;
        self.verify_settlement(thor_inbound_tx_hash, Some(expected_sats), lifecycle_id, 0)
            .await?;
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Erc20Arrival {
    /// Transferred value in the token's own decimals (USDT: 1e6).
    pub value: u128,
    /// Confirmation depth of the transfer's log at the current tip.
    pub confirmations: u32,
    /// Hash of the transaction the `Transfer` log was emitted in. Bound 1:1
    /// against the `THORChain` OBSERVED outbound hash (RUST-004) so an arrival
    /// from an unrelated transaction can never be credited.
    pub transaction_hash: B256,
    /// Index of the `Transfer` log within its transaction. Together with
    /// `transaction_hash` it identifies the physical inflow uniquely — a
    /// batched outbound tx can emit several `Transfer` logs to the same
    /// address, and each must be consumed by at most one redemption leg.
    pub log_index: u64,
}

/// The 1:1 binding context for a consumed ERC20 inflow (RUST-004): which
/// redemption leg is claiming it, and the `THORChain` OBSERVED outbound hash
/// the on-chain `Transfer` must originate from.
#[derive(Debug, Clone, Copy)]
pub struct InflowBinding {
    /// On-chain `redemptionId` the cross-check is attesting.
    pub redemption_id: B256,
    /// Per-leg index within that redemption.
    pub leg_index: u32,
    /// `THORChain` OBSERVED outbound tx hash (from `tx/details` `out_txs`) that
    /// delivered the USDT. The on-chain `Transfer.transaction_hash` must equal
    /// this.
    pub expected_outbound_hash: B256,
}

/// Error from confirming + consuming an ERC20 inflow (RUST-004): either the
/// arrival backend ([`Erc20Error`]) or the consumed-inflow ledger
/// ([`ConsumedInflowError`]) failed.
#[derive(Debug, Error)]
pub enum InflowError {
    #[error("eth arrival error: {0}")]
    Eth(#[from] Erc20Error),
    #[error("consumed-inflow ledger error: {0}")]
    Ledger(#[from] ConsumedInflowError),
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

/// Confirm a USDT inflow AND make it single-use (RUST-004). The first
/// `Transfer` to `to` that (1) clears `value ≥ min_value`, (2) is at least
/// `min_confs` deep, (3) was emitted by the `THORChain` OBSERVED outbound tx
/// (`binding.expected_outbound_hash`), AND (4) is not already consumed by a
/// DIFFERENT redemption leg is returned — and atomically recorded as
/// consumed by `binding`'s leg. A physical inflow already claimed by another
/// leg is skipped; if none qualifies, `Ok(None)`.
///
/// # Errors
/// [`InflowError::Eth`] from the arrival backend; [`InflowError::Ledger`]
/// from the consumed-inflow store.
pub async fn confirm_erc20_arrival<E: Erc20ArrivalClient>(
    client: &E,
    store: &AnyConsumedInflow,
    token: EthAddress,
    to: EthAddress,
    min_value: u128,
    min_confs: u32,
    binding: &InflowBinding,
) -> Result<Option<Erc20Arrival>, InflowError> {
    let arrivals = client.transfers_to(token, to)?;
    confirm_erc20_arrival_from_snapshot(store, &arrivals, min_value, min_confs, binding)
        .await
        .map_err(Into::into)
}

/// Confirm and consume one arrival from a caller-supplied finalized snapshot.
/// Production settlement observers preserve that exact snapshot as raw RPC
/// evidence and pass the decoded arrivals here, preventing a second RPC query
/// between evidence capture and HSM release.
///
/// # Errors
/// [`ConsumedInflowError`] if the one-shot ledger cannot be read or updated.
pub async fn confirm_erc20_arrival_from_snapshot(
    store: &AnyConsumedInflow,
    arrivals: &[Erc20Arrival],
    min_value: u128,
    min_confs: u32,
    binding: &InflowBinding,
) -> Result<Option<Erc20Arrival>, ConsumedInflowError> {
    for arrival in arrivals {
        if arrival.value >= min_value
            && arrival.confirmations >= min_confs
            && arrival.transaction_hash == binding.expected_outbound_hash
            && claim_inflow(store, binding, arrival.transaction_hash, arrival.log_index).await?
        {
            return Ok(Some(arrival.clone()));
        }
    }
    Ok(None)
}

/// Try to claim a physical inflow `(tx_hash, log_index)` for `binding`'s leg.
/// `Ok(true)` = claimed (newly or already by us) → credit it; `Ok(false)` =
/// a DIFFERENT leg already consumed it → skip (RUST-004 double-credit guard).
///
/// # Errors
/// [`ConsumedInflowError`] if the ledger query fails.
async fn claim_inflow(
    store: &AnyConsumedInflow,
    binding: &InflowBinding,
    tx_hash: B256,
    log_index: u64,
) -> Result<bool, ConsumedInflowError> {
    match store
        .consume_inflow(binding.redemption_id, binding.leg_index, tx_hash, log_index)
        .await?
    {
        InflowConsumeOutcome::Consumed | InflowConsumeOutcome::AlreadyByThisLeg => Ok(true),
        InflowConsumeOutcome::ConflictByOtherLeg {
            existing_redemption_id,
            existing_leg_index,
        } => {
            warn!(
                redemption_id = %binding.redemption_id,
                leg_index = binding.leg_index,
                %tx_hash,
                log_index,
                %existing_redemption_id,
                existing_leg_index,
                "USDT inflow already consumed by another redemption leg — skipping (RUST-004)"
            );
            Ok(false)
        }
        InflowConsumeOutcome::ConflictByOtherInflow {
            existing_tx_hash,
            existing_log_index,
        } => {
            warn!(
                redemption_id = %binding.redemption_id,
                leg_index = binding.leg_index,
                %tx_hash,
                log_index,
                %existing_tx_hash,
                existing_log_index,
                "redemption leg already selected a different USDT inflow — skipping"
            );
            Ok(false)
        }
    }
}

/// Parse a `THORChain` tx id (`Tx.id`: uppercase hex, no `0x`, 64 chars) into a
/// [`B256`] for comparison with an on-chain `0x`-hex `transaction_hash`. Case-
/// and prefix-insensitive; `None` if it is not exactly 32 bytes of hex.
fn parse_thor_hash(s: &str) -> Option<B256> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.len() != 64 {
        return None;
    }
    let bytes = alloy_primitives::hex::decode(s).ok()?;
    B256::try_from(bytes.as_slice()).ok()
}

/// RUST-004: resolve the `THORChain` OBSERVED outbound ETH tx hash that
/// delivered USDT to `index_token`, from the `tx/details` view (its `out_txs`
/// carry the on-chain hash; the `tx_status` `actions` are PLANNED outbounds
/// with none). `Ok(None)` while no observed ETH outbound to `index_token`
/// exists yet (retry, not fail).
///
/// # Errors
/// Forwards [`ThorError`] from the `tx/details` RPC.
async fn observed_usdt_outbound_hash(
    thor: &ThorClient,
    inbound_hash: &str,
    index_token: EthAddress,
) -> Result<Option<B256>, ThorError> {
    let details = thor.tx_details(inbound_hash).await?;
    let want = eth_addr_lc(index_token);
    Ok(details.out_txs.iter().find_map(|o| {
        if o.chain == "ETH" && o.to_address.to_lowercase() == want {
            parse_thor_hash(&o.id)
        } else {
            None
        }
    }))
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
    /// The consumed-inflow ledger query failed (RUST-004).
    #[error("consumed-inflow ledger error: {0}")]
    Ledger(#[from] ConsumedInflowError),
}

impl From<InflowError> for RedemptionCrossCheckError {
    fn from(e: InflowError) -> Self {
        match e {
            InflowError::Eth(x) => Self::Eth(x),
            InflowError::Ledger(x) => Self::Ledger(x),
        }
    }
}

#[derive(Debug, Error)]
pub enum RefundCrossCheckError {
    #[error("`THORChain` RPC error: {0}")]
    Thor(#[from] ThorError),
    #[error("Bitcoin chain error: {0}")]
    Btc(#[from] UtxoError),
    #[error("native inflow ledger: {0}")]
    NativeLedger(#[from] NativeInflowError),
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
///
/// `redemption_id` / `leg_index` identify the on-chain leg being attested;
/// the policy records the physical USDT inflow it credits against this leg in
/// the consumed-inflow ledger so no other leg can cite the same inflow
/// (RUST-004).
#[async_trait]
pub trait RedemptionCrossCheck: Send + Sync {
    async fn verify(
        &self,
        btc_txid: &str,
        index_token: EthAddress,
        redemption_id: B256,
        leg_index: u32,
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
        _redemption_id: B256,
        _leg_index: u32,
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

fn observation_time() -> Result<u64, NativeInflowError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| NativeInflowError::Decode(format!("system clock: {error}")))
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
    /// Consumed-inflow ledger making each physical USDT delivery single-use
    /// (RUST-004). Shared across all delivery / streamed policies in the
    /// process so a delivery and a streamed settlement can never both credit
    /// the same inflow.
    store: Arc<AnyConsumedInflow>,
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
        store: Arc<AnyConsumedInflow>,
    ) -> Self {
        Self {
            thor,
            erc20,
            usdt_token,
            min_confirmations,
            tolerance_1e6,
            store,
        }
    }
}

#[async_trait]
impl<E: Erc20ArrivalClient> RedemptionCrossCheck for ThorUtxoToUsdtPolicy<E> {
    async fn verify(
        &self,
        btc_txid: &str,
        index_token: EthAddress,
        redemption_id: B256,
        leg_index: u32,
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

        // RUST-004: bind to the `THORChain` OBSERVED outbound tx hash (tx/details
        // out_txs), so the credited on-chain Transfer must originate from this
        // specific delivery — not just any USDT transfer ≥ floor to the
        // IndexToken. No observed ETH outbound yet ⇒ retry, never sign.
        let expected_outbound_hash = observed_usdt_outbound_hash(&self.thor, btc_txid, index_token)
            .await?
            .ok_or_else(|| RedemptionCrossCheckError::ThorNotReady {
                reason: "no observed ETH.USDT outbound hash in tx/details yet".to_string(),
            })?;

        // Step 2 — Ethereum (authoritative for the attested amount). The
        // arrival is consumed in the ledger so no other leg can cite it.
        let floor = thor_1e6.saturating_sub(self.tolerance_1e6);
        let arrival = confirm_erc20_arrival(
            &self.erc20,
            &self.store,
            self.usdt_token,
            index_token,
            floor,
            self.min_confirmations,
            &InflowBinding {
                redemption_id,
                leg_index,
                expected_outbound_hash,
            },
        )
        .await?
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
    native_inflows: Arc<AnyNativeInflow>,
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
            native_inflows: Arc::new(AnyNativeInflow::memory()),
        }
    }

    #[must_use]
    pub fn with_native_inflows(
        thor: ThorClient,
        btc: C,
        btc_multisig_address: Address,
        min_confirmations: u32,
        tolerance_sats: u64,
        native_inflows: Arc<AnyNativeInflow>,
    ) -> Self {
        Self {
            thor,
            btc,
            btc_multisig_address,
            min_confirmations,
            tolerance_sats,
            native_inflows,
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "refund verification deliberately keeps outcome exclusion, observed outbound, finalized UTXO, Asgard-funder, and one-shot-ledger checks in one fail-closed sequence"
)]
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

        // The planned action carries no destination-chain transaction ID.
        // Resolve the observed Bitcoin outbound and bind the later UTXO check
        // to that exact transaction rather than accepting any same-valued
        // output sent to the public custody address.
        let details = self.thor.tx_details(btc_txid).await?;
        let observed = details
            .out_txs
            .iter()
            .find(|outbound| {
                outbound.chain == "BTC"
                    && outbound.to_address == multisig
                    && outbound.coins.iter().any(|coin| {
                        coin.asset.eq_ignore_ascii_case("BTC.BTC")
                            && coin.amount.parse::<u64>().is_ok_and(|amount| {
                                amount.abs_diff(thor_sats) <= self.tolerance_sats
                            })
                    })
            })
            .ok_or_else(|| RefundCrossCheckError::ThorNotReady {
                reason: "no observed BTC refund tx in tx/details".to_string(),
            })?;
        let observed_txid =
            Txid::from_str(&observed.id).map_err(|error| RefundCrossCheckError::ThorNotReady {
                reason: format!("observed BTC refund txid is invalid: {error}"),
            })?;

        // Bind sender identity to the active/retiring Asgard set at the
        // finalized settlement height. Current inbound state is consulted
        // separately and only for the live halt gate.
        let historical_membership = self.thor.historical_asgard_membership(&resp, "BTC").await?;
        let current_vault = self.thor.vault_for_chain("BTC").await?.ok_or_else(|| {
            RefundCrossCheckError::ThorNotReady {
                reason: "no BTC inbound address from THORChain".to_string(),
            }
        })?;
        if current_vault.chain != "BTC"
            || current_vault.address.is_empty()
            || current_vault.halted
            || current_vault.chain_trading_paused
            || current_vault.global_trading_paused
            || current_vault.chain_lp_actions_paused
        {
            return Err(RefundCrossCheckError::ThorNotReady {
                reason: "BTC trading or LP actions halted on THORChain".to_string(),
            });
        }

        // Independent Bitcoin observation. BTC is 1e8 BOTH on THORChain
        // and on-chain (sats) — no scaling, unlike USDT.
        let utxos = self.btc.get_address_utxos(&self.btc_multisig_address)?;
        let utxo = utxos
            .iter()
            .find(|utxo| {
                utxo.txid == observed_txid
                    && utxo.confirmations >= self.min_confirmations
                    && utxo.value.to_sat().abs_diff(thor_sats) <= self.tolerance_sats
            })
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

        // Bind the refund UTXO's funding inputs to the historical set.
        let funders = self.btc.tx_input_addresses(&utxo.txid)?;
        if !funders
            .iter()
            .any(|funder| historical_membership.contains(funder))
        {
            return Err(RefundCrossCheckError::ThorNotReady {
                reason:
                    "BTC refund UTXO not funded by historical active/retiring Asgard membership"
                        .to_string(),
            });
        }
        let lifecycle_id =
            parse_thor_hash(btc_txid).ok_or_else(|| RefundCrossCheckError::ThorNotReady {
                reason: "BTC inbound hash is not bytes32".to_string(),
            })?;
        let physical_hash = B256::from(utxo.txid.to_raw_hash().to_byte_array());
        let claim = self
            .native_inflows
            .consume(
                xindex_shared::chain_registry::ChainId::Btc,
                physical_hash,
                utxo.vout,
                NativeInflowClaim {
                    kind: NativeFlowKind::RedemptionRefund,
                    lifecycle_id,
                    leg_index: 0,
                },
                observation_time()?,
            )
            .await?;
        if matches!(claim, NativeInflowOutcome::Conflict { .. }) {
            return Err(RefundCrossCheckError::ThorNotReady {
                reason: "observed BTC refund output was already consumed by another lifecycle"
                    .to_string(),
            });
        }
        info!(btc_txid, refunded_sats = utxo_sats, "refund cross-check OK");
        // Attest the ON-CHAIN UTXO value (authoritative).
        Ok(utxo_sats)
    }
}

/* -------------------------------------------------------------------------- */
/*              COMBINED STREAMED-SETTLEMENT CROSS-CHECK (burn)               */
/* -------------------------------------------------------------------------- */

/// The on-chain-observed outcome of a partially-filled streaming redeem
/// swap. Either field may be zero (a full delivery or a full refund); a
/// genuine partial carries both non-zero. Both are the AUTHORITATIVE
/// on-chain figures, NOT `THORChain`'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamedOutcome {
    /// USDT delivered to the `IndexToken` (1e6), observed on Ethereum.
    pub delivered_usdt_1e6: u128,
    /// Native BTC refunded to our custody (sats), observed on Bitcoin.
    pub refunded_sats: u64,
}

#[derive(Debug, Error)]
pub enum StreamedSettlementCrossCheckError {
    #[error("`THORChain` RPC error: {0}")]
    Thor(#[from] ThorError),
    #[error("ETH error: {0}")]
    Eth(#[from] Erc20Error),
    #[error("Bitcoin chain error: {0}")]
    Btc(#[from] UtxoError),
    #[error("`THORChain` not yet ready: {reason}")]
    ThorNotReady { reason: String },
    #[error("USDT not yet confirmed at IndexToken: need ≥{need_1e6} (1e6) with ≥{confs} confs")]
    UsdtNotReady { need_1e6: u128, confs: u32 },
    #[error("refund BTC not yet confirmed at multisig: need ≥{need_sats} sats ≥{confs} confs")]
    BtcNotReady { need_sats: u64, confs: u32 },
    #[error("USDT amount mismatch: `THORChain` {thor_1e6} vs on-chain {onchain_1e6} (1e6)")]
    UsdtAmountMismatch { thor_1e6: u128, onchain_1e6: u128 },
    #[error("refund amount mismatch: `THORChain` {thor_sats} vs UTXO {utxo_sats} sats")]
    BtcAmountMismatch { thor_sats: u64, utxo_sats: u64 },
    /// Neither a USDT delivery NOR a BTC refund outbound is observable yet
    /// — the streamed swap has produced no leg, so there is nothing to
    /// settle (retry once `THORChain` emits the outbound(s)).
    #[error("streamed settlement has neither a delivery nor a refund yet")]
    NoSettlement,
    /// The consumed-inflow ledger query failed (RUST-004).
    #[error("consumed-inflow ledger error: {0}")]
    Ledger(#[from] ConsumedInflowError),
    #[error("native inflow ledger: {0}")]
    NativeLedger(#[from] NativeInflowError),
}

impl From<InflowError> for StreamedSettlementCrossCheckError {
    fn from(e: InflowError) -> Self {
        match e {
            InflowError::Eth(x) => Self::Eth(x),
            InflowError::Ledger(x) => Self::Ledger(x),
        }
    }
}

/// Combined streamed-settlement cross-check (re-audit-gated burn-side
/// streaming). A streaming redeem swap can partially fill, producing BOTH
/// a USDT delivery to the `IndexToken` AND a native-asset refund to our
/// custody. Returns the on-chain-observed amount for each leg the
/// signer should attest via `AttestationOracle.attestStreamedSettlement`.
///
/// **Finality:** the caller (coordinator) MUST invoke this only once the
/// streaming swap has FULLY finalised — otherwise a partial that has
/// emitted only its delivery outbound (refund still pending) would settle
/// delivery-only and under-credit the refund. The finality gate
/// (`tx_status` `swap_finalised.completed` / `EventStreamingSwap`) is the
/// coordinator's responsibility; this policy verifies the already-final
/// outcome.
#[async_trait]
pub trait StreamedSettlementCrossCheck: Send + Sync {
    async fn verify(
        &self,
        btc_txid: &str,
        index_token: EthAddress,
        redemption_id: B256,
        leg_index: u32,
    ) -> Result<StreamedOutcome, StreamedSettlementCrossCheckError>;
}

/// Production combined policy: observes the delivery leg (Ethereum USDT
/// arrival) AND the refund leg (Bitcoin UTXO to multisig, vault-bound)
/// for one finalised streaming redeem swap. Unlike the XOR delivery /
/// refund policies, it accepts BOTH (or either) on the same `btc_txid`.
pub struct ThorUtxoStreamedSettlementPolicy<E: Erc20ArrivalClient, C: UtxoChainClient + Send + Sync>
{
    thor: ThorClient,
    erc20: E,
    btc: C,
    usdt_token: EthAddress,
    btc_multisig_address: Address,
    min_confirmations: u32,
    tolerance_1e6: u128,
    tolerance_sats: u64,
    /// Consumed-inflow ledger (RUST-004), shared with the XOR delivery policy
    /// so a streamed settlement and a plain delivery can never both credit the
    /// same physical USDT inflow.
    store: Arc<AnyConsumedInflow>,
    /// Shared native-output ledger. A physical BTC refund output can be
    /// credited to only one redemption lifecycle across both the plain and
    /// streamed settlement paths.
    native_inflows: Arc<AnyNativeInflow>,
}

impl<E: Erc20ArrivalClient, C: UtxoChainClient + Send + Sync> std::fmt::Debug
    for ThorUtxoStreamedSettlementPolicy<E, C>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThorUtxoStreamedSettlementPolicy")
            .field("usdt_token", &self.usdt_token)
            .field("btc_multisig_address", &self.btc_multisig_address)
            .field("min_confirmations", &self.min_confirmations)
            .field("tolerance_1e6", &self.tolerance_1e6)
            .field("tolerance_sats", &self.tolerance_sats)
            .finish_non_exhaustive()
    }
}

impl<E: Erc20ArrivalClient, C: UtxoChainClient + Send + Sync>
    ThorUtxoStreamedSettlementPolicy<E, C>
{
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "combined policy threads both the delivery (erc20, usdt_token, tolerance_1e6) and refund (btc, multisig, tolerance_sats) verification params plus the RUST-004 consumed-inflow ledger"
    )]
    pub fn new(
        thor: ThorClient,
        erc20: E,
        btc: C,
        usdt_token: EthAddress,
        btc_multisig_address: Address,
        min_confirmations: u32,
        tolerance_1e6: u128,
        tolerance_sats: u64,
        store: Arc<AnyConsumedInflow>,
    ) -> Self {
        Self {
            thor,
            erc20,
            btc,
            usdt_token,
            btc_multisig_address,
            min_confirmations,
            tolerance_1e6,
            tolerance_sats,
            store,
            native_inflows: Arc::new(AnyNativeInflow::memory()),
        }
    }

    /// Construct the production policy with both durable inflow ledgers.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "combined policy threads both delivery and refund verification parameters plus two durable one-shot ledgers"
    )]
    pub fn with_native_inflows(
        thor: ThorClient,
        erc20: E,
        btc: C,
        usdt_token: EthAddress,
        btc_multisig_address: Address,
        min_confirmations: u32,
        tolerance_1e6: u128,
        tolerance_sats: u64,
        store: Arc<AnyConsumedInflow>,
        native_inflows: Arc<AnyNativeInflow>,
    ) -> Self {
        Self {
            thor,
            erc20,
            btc,
            usdt_token,
            btc_multisig_address,
            min_confirmations,
            tolerance_1e6,
            tolerance_sats,
            store,
            native_inflows,
        }
    }

    /// Delivery leg: `Ok(None)` if `THORChain` emitted no USDT outbound
    /// (a full refund); `Ok(Some(value_1e6))` once the on-chain arrival is
    /// confirmed; an error while the THOR action is present but the
    /// on-chain USDT is not yet confirmed / mismatched.
    #[expect(
        clippy::too_many_lines,
        reason = "delivery snapshot validation deliberately remains a linear evidence-to-ledger policy"
    )]
    async fn verify_delivery_leg(
        &self,
        resp: &TxResponse,
        details: &TxDetailsResponse,
        arrivals: &[Erc20Arrival],
        index_token: EthAddress,
        redemption_id: B256,
        leg_index: u32,
    ) -> Result<Option<u128>, StreamedSettlementCrossCheckError> {
        let want = eth_addr_lc(index_token);
        let actions: Vec<_> = resp
            .actions
            .iter()
            .filter(|action| {
                action.chain == "ETH"
                    && action.coin.asset.to_uppercase().starts_with("ETH.USDT")
                    && action.to_address.to_lowercase() == want
            })
            .collect();
        if actions.is_empty() {
            let unexplained = details.out_txs.iter().any(|outbound| {
                outbound.chain == "ETH"
                    && outbound.to_address.to_lowercase() == want
                    && outbound
                        .coins
                        .iter()
                        .any(|coin| coin.asset.to_uppercase().starts_with("ETH.USDT"))
            });
            if unexplained {
                return Err(StreamedSettlementCrossCheckError::ThorNotReady {
                    reason: "observed ETH.USDT outbound has no matching planned action".to_string(),
                });
            }
            return Ok(None);
        }
        if actions.len() != 1 {
            return Err(StreamedSettlementCrossCheckError::ThorNotReady {
                reason: format!(
                    "expected at most one ETH.USDT delivery action, got {}",
                    actions.len()
                ),
            });
        }
        let action = actions[0];
        let thor_1e8: u128 = action.coin.amount.parse().map_err(|e| {
            StreamedSettlementCrossCheckError::ThorNotReady {
                reason: format!("non-integer outbound amount '{}': {e}", action.coin.amount),
            }
        })?;
        let thor_1e6 = thor_1e8 / THOR_TO_USDT_SCALE;
        if thor_1e8 == 0 || thor_1e6 == 0 {
            return Err(StreamedSettlementCrossCheckError::ThorNotReady {
                reason: "zero/sub-base-unit ETH.USDT delivery action".to_string(),
            });
        }
        let matching_outbounds: Vec<_> = details
            .out_txs
            .iter()
            .filter(|outbound| {
                outbound.chain == "ETH"
                    && outbound.to_address.to_lowercase() == want
                    && outbound.coins.iter().any(|coin| {
                        coin.asset.to_uppercase().starts_with("ETH.USDT")
                            && coin.amount.parse::<u128>().is_ok_and(|amount_1e8| {
                                within(
                                    thor_1e6,
                                    amount_1e8 / THOR_TO_USDT_SCALE,
                                    self.tolerance_1e6,
                                )
                            })
                    })
            })
            .collect();
        if matching_outbounds.len() != 1 {
            return Err(StreamedSettlementCrossCheckError::ThorNotReady {
                reason: format!(
                    "expected exactly one observed ETH.USDT outbound, got {}",
                    matching_outbounds.len()
                ),
            });
        }
        let expected_outbound_hash =
            parse_thor_hash(&matching_outbounds[0].id).ok_or_else(|| {
                StreamedSettlementCrossCheckError::ThorNotReady {
                    reason: "observed ETH.USDT outbound hash is invalid".to_string(),
                }
            })?;
        let floor = thor_1e6.saturating_sub(self.tolerance_1e6);
        let arrival = confirm_erc20_arrival_from_snapshot(
            &self.store,
            arrivals,
            floor,
            self.min_confirmations,
            &InflowBinding {
                redemption_id,
                leg_index,
                expected_outbound_hash,
            },
        )
        .await?
        .ok_or(StreamedSettlementCrossCheckError::UsdtNotReady {
            need_1e6: thor_1e6,
            confs: self.min_confirmations,
        })?;
        if !within(thor_1e6, arrival.value, self.tolerance_1e6) {
            return Err(StreamedSettlementCrossCheckError::UsdtAmountMismatch {
                thor_1e6,
                onchain_1e6: arrival.value,
            });
        }
        Ok(Some(arrival.value))
    }

    /// Refund leg: `Ok(None)` if `THORChain` emitted no BTC refund (a full
    /// delivery); `Ok(Some(sats))` once the vault-bound UTXO is confirmed.
    #[expect(
        clippy::too_many_lines,
        reason = "refund snapshot validation deliberately remains a linear evidence-to-ledger policy"
    )]
    async fn verify_refund_leg(
        &self,
        resp: &TxResponse,
        details: &TxDetailsResponse,
        historical_membership: &HistoricalAsgardMembership,
        redemption_id: B256,
        leg_index: u32,
    ) -> Result<Option<u64>, StreamedSettlementCrossCheckError> {
        let multisig = self.btc_multisig_address.to_string();
        let actions: Vec<_> = resp
            .actions
            .iter()
            .filter(|action| {
                action.chain == "BTC"
                    && action.to_address == multisig
                    && action.memo.to_uppercase().starts_with("REFUND:")
                    && action.coin.asset.to_uppercase() == "BTC.BTC"
            })
            .collect();
        if actions.is_empty() {
            let unexplained = details.out_txs.iter().any(|outbound| {
                outbound.chain == "BTC"
                    && outbound.to_address == multisig
                    && outbound
                        .coins
                        .iter()
                        .any(|coin| coin.asset.eq_ignore_ascii_case("BTC.BTC"))
            });
            if unexplained {
                return Err(StreamedSettlementCrossCheckError::ThorNotReady {
                    reason: "observed BTC custody outbound has no matching refund action"
                        .to_string(),
                });
            }
            return Ok(None);
        }
        if actions.len() != 1 {
            return Err(StreamedSettlementCrossCheckError::ThorNotReady {
                reason: format!(
                    "expected at most one BTC refund action, got {}",
                    actions.len()
                ),
            });
        }
        let action = actions[0];
        let thor_sats: u64 = action.coin.amount.parse().map_err(|e| {
            StreamedSettlementCrossCheckError::ThorNotReady {
                reason: format!("non-integer refund amount '{}': {e}", action.coin.amount),
            }
        })?;
        if thor_sats == 0 {
            return Err(StreamedSettlementCrossCheckError::ThorNotReady {
                reason: "zero BTC refund amount".to_string(),
            });
        }

        let observed: Vec<_> = details
            .out_txs
            .iter()
            .filter(|outbound| {
                outbound.chain == "BTC"
                    && outbound.to_address == multisig
                    && outbound.coins.iter().any(|coin| {
                        coin.asset.eq_ignore_ascii_case("BTC.BTC")
                            && coin.amount.parse::<u64>().is_ok_and(|amount| {
                                amount.abs_diff(thor_sats) <= self.tolerance_sats
                            })
                    })
            })
            .collect();
        if observed.len() != 1 {
            return Err(StreamedSettlementCrossCheckError::ThorNotReady {
                reason: format!(
                    "expected exactly one observed BTC refund outbound, got {}",
                    observed.len()
                ),
            });
        }
        let observed_txid = Txid::from_str(&observed[0].id).map_err(|error| {
            StreamedSettlementCrossCheckError::ThorNotReady {
                reason: format!("observed BTC refund txid is invalid: {error}"),
            }
        })?;

        let utxos = self.btc.get_address_utxos(&self.btc_multisig_address)?;
        let candidates: Vec<_> = utxos
            .iter()
            .filter(|utxo| {
                utxo.txid == observed_txid
                    && utxo.confirmations >= self.min_confirmations
                    && utxo.value.to_sat().abs_diff(thor_sats) <= self.tolerance_sats
            })
            .collect();
        if candidates.is_empty() {
            return Err(StreamedSettlementCrossCheckError::BtcNotReady {
                need_sats: thor_sats,
                confs: self.min_confirmations,
            });
        }
        if candidates.len() != 1 {
            return Err(StreamedSettlementCrossCheckError::ThorNotReady {
                reason: format!(
                    "observed BTC refund has {} ambiguous custody outputs",
                    candidates.len()
                ),
            });
        }
        let utxo = candidates[0];
        let utxo_sats = utxo.value.to_sat();
        if utxo_sats.abs_diff(thor_sats) > self.tolerance_sats {
            return Err(StreamedSettlementCrossCheckError::BtcAmountMismatch {
                thor_sats,
                utxo_sats,
            });
        }
        let funders = self.btc.tx_input_addresses(&utxo.txid)?;
        if !funders
            .iter()
            .any(|funder| historical_membership.contains(funder))
        {
            return Err(StreamedSettlementCrossCheckError::ThorNotReady {
                reason:
                    "BTC refund UTXO not funded by historical active/retiring Asgard membership"
                        .to_string(),
            });
        }

        let physical_hash = B256::from(utxo.txid.to_raw_hash().to_byte_array());
        let claim = self
            .native_inflows
            .consume(
                xindex_shared::chain_registry::ChainId::Btc,
                physical_hash,
                utxo.vout,
                NativeInflowClaim {
                    kind: NativeFlowKind::RedemptionRefund,
                    lifecycle_id: redemption_id,
                    leg_index,
                },
                observation_time()?,
            )
            .await?;
        if matches!(claim, NativeInflowOutcome::Conflict { .. }) {
            return Err(StreamedSettlementCrossCheckError::ThorNotReady {
                reason: "observed BTC refund output was already consumed by another lifecycle"
                    .to_string(),
            });
        }
        Ok(Some(utxo_sats))
    }

    /// Verify a finalized redemption outcome against the exact snapshots a
    /// production observer already quorum-agreed and persisted as evidence.
    /// No `THORNode` or Ethereum RPC call occurs in this method; only the
    /// independently configured Bitcoin client and durable one-shot ledgers
    /// are consulted.
    ///
    /// # Errors
    /// Any mismatch, ambiguity, missing confirmation, or ledger conflict.
    #[expect(
        clippy::too_many_arguments,
        reason = "the API explicitly binds every agreed THOR/Ethereum snapshot and on-chain lifecycle identity"
    )]
    pub async fn verify_from_snapshot(
        &self,
        resp: &TxResponse,
        details: &TxDetailsResponse,
        current_vault: &InboundAddress,
        historical_membership: &HistoricalAsgardMembership,
        arrivals: &[Erc20Arrival],
        btc_txid: &str,
        index_token: EthAddress,
        redemption_id: B256,
        leg_index: u32,
    ) -> Result<StreamedOutcome, StreamedSettlementCrossCheckError> {
        if redemption_id == B256::ZERO || index_token == EthAddress::ZERO {
            return Err(StreamedSettlementCrossCheckError::ThorNotReady {
                reason: "zero redemption or destination identity".to_string(),
            });
        }
        if resp.observed_tx.status != "done"
            || resp.observed_tx.tx.chain != "BTC"
            || !resp.observed_tx.tx.id.eq_ignore_ascii_case(btc_txid)
        {
            return Err(StreamedSettlementCrossCheckError::ThorNotReady {
                reason: "agreed THOR snapshot is not the completed requested BTC inbound"
                    .to_string(),
            });
        }
        if current_vault.chain != "BTC"
            || current_vault.address.is_empty()
            || current_vault.halted
            || current_vault.chain_trading_paused
            || current_vault.global_trading_paused
            || current_vault.chain_lp_actions_paused
        {
            return Err(StreamedSettlementCrossCheckError::ThorNotReady {
                reason: "agreed BTC vault is missing, halted, or LP-paused".to_string(),
            });
        }
        if historical_membership.chain != "BTC"
            || historical_membership.addresses.is_empty()
            || resp.historical_asgard_height().ok() != Some(historical_membership.height)
        {
            return Err(StreamedSettlementCrossCheckError::ThorNotReady {
                reason: "historical BTC Asgard membership does not match finalised height"
                    .to_string(),
            });
        }
        let delivered = self
            .verify_delivery_leg(
                resp,
                details,
                arrivals,
                index_token,
                redemption_id,
                leg_index,
            )
            .await?;
        let refunded = self
            .verify_refund_leg(
                resp,
                details,
                historical_membership,
                redemption_id,
                leg_index,
            )
            .await?;
        match (delivered, refunded) {
            (None, None) => Err(StreamedSettlementCrossCheckError::NoSettlement),
            (delivery, refund) => {
                let outcome = StreamedOutcome {
                    delivered_usdt_1e6: delivery.unwrap_or(0),
                    refunded_sats: refund.unwrap_or(0),
                };
                info!(
                    btc_txid,
                    delivered_usdt_1e6 = outcome.delivered_usdt_1e6,
                    refunded_sats = outcome.refunded_sats,
                    "snapshot-bound streamed-settlement cross-check OK"
                );
                Ok(outcome)
            }
        }
    }
}

#[async_trait]
impl<E: Erc20ArrivalClient, C: UtxoChainClient + Send + Sync> StreamedSettlementCrossCheck
    for ThorUtxoStreamedSettlementPolicy<E, C>
{
    async fn verify(
        &self,
        btc_txid: &str,
        index_token: EthAddress,
        redemption_id: B256,
        leg_index: u32,
    ) -> Result<StreamedOutcome, StreamedSettlementCrossCheckError> {
        let resp = self.thor.tx_status(btc_txid).await?;
        let details = self.thor.tx_details(btc_txid).await?;
        let historical_membership = self.thor.historical_asgard_membership(&resp, "BTC").await?;
        let current_vault = self.thor.vault_for_chain("BTC").await?.ok_or_else(|| {
            StreamedSettlementCrossCheckError::ThorNotReady {
                reason: "no BTC inbound address from THORChain".to_string(),
            }
        })?;
        let arrivals = self.erc20.transfers_to(self.usdt_token, index_token)?;
        self.verify_from_snapshot(
            &resp,
            &details,
            &current_vault,
            &historical_membership,
            &arrivals,
            btc_txid,
            index_token,
            redemption_id,
            leg_index,
        )
        .await
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
        fn tx_input_addresses(&self, _txid: &Txid) -> Result<Vec<String>, UtxoError> {
            Ok(vec![ASGARD_BTC.to_string()])
        }
    }

    /// Mainnet bech32 address standing in for the live Asgard vault that
    /// funds every BTC UTXO `StubBtc` reports.
    const ASGARD_BTC: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    /// Canonical `THORChain` inbound transaction ID used by mint-policy
    /// fixtures. Keeping this bytes32-shaped prevents negative tests from
    /// short-circuiting at the request-shape gate before reaching the policy
    /// branch they intend to exercise.
    const THOR_INBOUND_HASH: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    /// Observed BTC outbound selected by the `tx/details` fixture.
    const BTC_OUTBOUND_TXID: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    /// Mock `GET /thorchain/inbound_addresses` returning a single BTC vault
    /// with the given address + halted flag.
    async fn mount_btc_current_inbound(
        server: &wiremock::MockServer,
        vault_addr: &str,
        halted: bool,
    ) {
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/inbound_addresses"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "chain": "BTC", "pub_key": "thorpub1addwnpepq", "address": vault_addr,
                    "halted": halted,
                    "global_trading_paused": false,
                    "chain_trading_paused": false,
                    "chain_lp_actions_paused": false
                }])),
            )
            .mount(server)
            .await;
    }

    /// Mock the exact source-height active/retiring Asgard set used for
    /// historical settlement identity.
    async fn mount_btc_historical_asgard(
        server: &wiremock::MockServer,
        height: u64,
        vault_addr: &str,
    ) {
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/vaults/asgard"))
            .and(wiremock::matchers::query_param(
                "height",
                height.to_string(),
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "pub_key": "thorpub1historical",
                    "type": "AsgardVault",
                    "status": "ActiveVault",
                    "status_since": height.saturating_sub(10),
                    "addresses": [{ "chain": "BTC", "address": vault_addr }]
                }])),
            )
            .mount(server)
            .await;
    }

    /// Default fixture where current and historical membership have not
    /// rotated. Rotation regressions mount the two snapshots separately.
    async fn mount_btc_inbound(server: &wiremock::MockServer, vault_addr: &str, halted: bool) {
        mount_btc_current_inbound(server, vault_addr, halted).await;
        mount_btc_historical_asgard(server, 100, vault_addr).await;
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn test_address() -> Address {
        Address::from_str("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
            .expect("addr")
            .require_network(Network::Bitcoin)
            .expect("network")
    }

    /// Mount the observed BTC outbound required by the settlement policy.
    /// Tests choose the amount explicitly so action, details, and on-chain
    /// fixtures cannot silently drift apart.
    async fn mount_btc_outbound_details(server: &wiremock::MockServer, amount_sats: u64) {
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!(
                "/thorchain/tx/details/{THOR_INBOUND_HASH}"
            )))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "out_txs": [{
                        "id": BTC_OUTBOUND_TXID,
                        "chain": "BTC",
                        "to_address": test_address().to_string(),
                        "coins": [{ "asset": "BTC.BTC", "amount": amount_sats.to_string() }]
                    }]
                })),
            )
            .mount(server)
            .await;
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
            .and(wiremock::matchers::path(format!(
                "/thorchain/tx/{THOR_INBOUND_HASH}"
            )))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": {
                        "tx": {
                            "id": THOR_INBOUND_HASH, "chain": "ETH",
                            "from_address": "0xUser", "to_address": "0xRouter",
                            "coins": [], "memo": ""
                        },
                        "status": "done"
                    },
                    "finalised_height": 100,
                    "actions": [{
                        "chain": "BTC",
                        "to_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                        "coin": { "asset": "BTC.BTC", "amount": "100000" },
                        "memo": format!("OUT:{THOR_INBOUND_HASH}"),
                        "max_gas": []
                    }]
                })),
            )
            .mount(&server)
            .await;
        mount_btc_outbound_details(&server, 100_000).await;
        mount_btc_inbound(&server, ASGARD_BTC, false).await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        let policy = ThorUtxoPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        let err = policy
            .verify(THOR_INBOUND_HASH, 100_000)
            .await
            .expect_err("should reject");
        assert!(matches!(err, CrossCheckError::BtcNotReady { .. }));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_policy_amount_mismatch() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!(
                "/thorchain/tx/{THOR_INBOUND_HASH}"
            )))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": {
                        "tx": {
                            "id": THOR_INBOUND_HASH, "chain": "ETH",
                            "from_address": "0xUser", "to_address": "0xRouter",
                            "coins": [], "memo": ""
                        },
                        "status": "done"
                    },
                    "finalised_height": 100,
                    "actions": [{
                        "chain": "BTC",
                        "to_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                        "coin": { "asset": "BTC.BTC", "amount": "50000" },
                        "memo": format!("OUT:{THOR_INBOUND_HASH}"),
                        "max_gas": []
                    }]
                })),
            )
            .mount(&server)
            .await;
        mount_btc_outbound_details(&server, 50_000).await;
        mount_btc_inbound(&server, ASGARD_BTC, false).await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        let policy = ThorUtxoPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        // Claim is 100_000 sats but `THORChain` says 50_000 → mismatch.
        let err = policy
            .verify(THOR_INBOUND_HASH, 100_000)
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
            .and(wiremock::matchers::path(format!(
                "/thorchain/tx/{THOR_INBOUND_HASH}"
            )))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": {
                        "tx": {
                            "id": THOR_INBOUND_HASH, "chain": "ETH",
                            "from_address": "0xUser", "to_address": "0xRouter",
                            "coins": [], "memo": ""
                        },
                        "status": "done"
                    },
                    "finalised_height": 100,
                    "actions": [{
                        // chain is ETH (not BTC) but to_address matches
                        // our multisig string. `&&` filter rejects;
                        // `||` mutation would let this through.
                        "chain": "ETH",
                        "to_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                        "coin": { "asset": "ETH.ETH", "amount": "1000000000000000000" },
                        "memo": format!("OUT:{THOR_INBOUND_HASH}"),
                        "max_gas": []
                    }]
                })),
            )
            .mount(&server)
            .await;
        mount_btc_outbound_details(&server, 100_000).await;
        mount_btc_inbound(&server, ASGARD_BTC, false).await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        let policy = ThorUtxoPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        let err = policy
            .verify(THOR_INBOUND_HASH, 100_000)
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
            .and(wiremock::matchers::path(format!(
                "/thorchain/tx/{THOR_INBOUND_HASH}"
            )))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": {
                        "tx": {
                            "id": THOR_INBOUND_HASH, "chain": "ETH",
                            "from_address": "0xUser", "to_address": "0xRouter",
                            "coins": [], "memo": ""
                        },
                        "status": "done"
                    },
                    "finalised_height": 100,
                    "actions": [{
                        "chain": "BTC",
                        // Different bc1... address than test_address().
                        "to_address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                        "coin": { "asset": "BTC.BTC", "amount": "100000" },
                        "memo": format!("OUT:{THOR_INBOUND_HASH}"),
                        "max_gas": []
                    }]
                })),
            )
            .mount(&server)
            .await;
        mount_btc_outbound_details(&server, 100_000).await;
        mount_btc_inbound(&server, ASGARD_BTC, false).await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        let policy = ThorUtxoPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        let err = policy
            .verify(THOR_INBOUND_HASH, 100_000)
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
            .and(wiremock::matchers::path(format!(
                "/thorchain/tx/{THOR_INBOUND_HASH}"
            )))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": {
                        "tx": {
                            "id": THOR_INBOUND_HASH, "chain": "ETH",
                            "from_address": "0xUser", "to_address": "0xRouter",
                            "coins": [], "memo": ""
                        },
                        "status": "incomplete"
                    },
                    "finalised_height": 100,
                    "actions": []
                })),
            )
            .mount(&server)
            .await;
        mount_btc_outbound_details(&server, 100_000).await;
        mount_btc_inbound(&server, ASGARD_BTC, false).await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        let policy = ThorUtxoPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        let err = policy
            .verify(THOR_INBOUND_HASH, 100_000)
            .await
            .expect_err("should reject");
        assert!(matches!(err, CrossCheckError::ThorNotReady { .. }));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_policy_full_success() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!(
                "/thorchain/tx/{THOR_INBOUND_HASH}"
            )))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": {
                        "tx": {
                            "id": THOR_INBOUND_HASH, "chain": "ETH",
                            "from_address": "0xUser", "to_address": "0xRouter",
                            "coins": [], "memo": ""
                        },
                        "status": "done"
                    },
                    "finalised_height": 100,
                    "actions": [{
                        "chain": "BTC",
                        "to_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                        "coin": { "asset": "BTC.BTC", "amount": "100000" },
                        "memo": format!("OUT:{THOR_INBOUND_HASH}"),
                        "max_gas": []
                    }]
                })),
            )
            .mount(&server)
            .await;
        mount_btc_outbound_details(&server, 100_000).await;
        // The settlement happened at height 100 while vault A was active.
        // Current membership has already rotated to vault B at height 101.
        mount_btc_historical_asgard(&server, 100, ASGARD_BTC).await;
        mount_btc_current_inbound(&server, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", false)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        // Seed BTC stub with a confirmed UTXO matching the claim.
        let txid = Txid::from_str(BTC_OUTBOUND_TXID).expect("txid");
        btc.utxos.lock().expect("lock").push(UtxoEntry {
            txid,
            vout: 0,
            value: Amount::from_sat(100_000),
            confirmations: 6,
            block_hash: None,
        });
        let policy = ThorUtxoPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        policy
            .verify(THOR_INBOUND_HASH, 100_000)
            .await
            .expect("should pass");
    }

    /// M03 negative rotation case: an address absent from the historical
    /// height-100 set stays ineligible even if it is the current vault later.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_policy_rejects_utxo_not_from_asgard() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!(
                "/thorchain/tx/{THOR_INBOUND_HASH}"
            )))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": {
                        "tx": {
                            "id": THOR_INBOUND_HASH, "chain": "ETH",
                            "from_address": "0xUser", "to_address": "0xRouter",
                            "coins": [], "memo": ""
                        },
                        "status": "done"
                    },
                    "finalised_height": 100,
                    "actions": [{
                        "chain": "BTC",
                        "to_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                        "coin": { "asset": "BTC.BTC", "amount": "100000" },
                        "memo": format!("OUT:{THOR_INBOUND_HASH}"),
                        "max_gas": []
                    }]
                })),
            )
            .mount(&server)
            .await;
        mount_btc_outbound_details(&server, 100_000).await;
        mount_btc_historical_asgard(&server, 100, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
            .await;
        // StubBtc reports ASGARD_BTC as funder, and it became current only
        // after the settlement height.
        mount_btc_current_inbound(&server, ASGARD_BTC, false).await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        let txid = Txid::from_str(BTC_OUTBOUND_TXID).expect("txid");
        btc.utxos.lock().expect("lock").push(UtxoEntry {
            txid,
            vout: 0,
            value: Amount::from_sat(100_000),
            confirmations: 6,
            block_hash: None,
        });
        let policy = ThorUtxoPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        let err = policy
            .verify(THOR_INBOUND_HASH, 100_000)
            .await
            .expect_err("must reject UTXO not from Asgard");
        assert!(
            matches!(err, CrossCheckError::ThorNotReady { .. }),
            "expected ThorNotReady, got {err:?}"
        );
    }

    /// Halt gate (audit L8): `THORChain` reports BTC trading halted →
    /// `ThorNotReady` even when the UTXO + sender would otherwise match.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn thor_btc_policy_rejects_when_btc_halted() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!(
                "/thorchain/tx/{THOR_INBOUND_HASH}"
            )))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": {
                        "tx": {
                            "id": THOR_INBOUND_HASH, "chain": "ETH",
                            "from_address": "0xUser", "to_address": "0xRouter",
                            "coins": [], "memo": ""
                        },
                        "status": "done"
                    },
                    "finalised_height": 100,
                    "actions": [{
                        "chain": "BTC",
                        "to_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                        "coin": { "asset": "BTC.BTC", "amount": "100000" },
                        "memo": format!("OUT:{THOR_INBOUND_HASH}"),
                        "max_gas": []
                    }]
                })),
            )
            .mount(&server)
            .await;
        mount_btc_outbound_details(&server, 100_000).await;
        mount_btc_inbound(&server, ASGARD_BTC, true).await; // halted
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let btc = StubBtc::default();
        let txid = Txid::from_str(BTC_OUTBOUND_TXID).expect("txid");
        btc.utxos.lock().expect("lock").push(UtxoEntry {
            txid,
            vout: 0,
            value: Amount::from_sat(100_000),
            confirmations: 6,
            block_hash: None,
        });
        let policy = ThorUtxoPolicy::new(thor, btc, test_address(), 1, 0, Network::Bitcoin);
        let err = policy
            .verify(THOR_INBOUND_HASH, 100_000)
            .await
            .expect_err("must reject while halted");
        assert!(
            matches!(err, CrossCheckError::ThorNotReady { .. }),
            "expected ThorNotReady, got {err:?}"
        );
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

    /// `THORChain` `Tx.id` form (uppercase hex, no `0x`) of the OBSERVED
    /// outbound the RUST-004 delivery tests bind to.
    fn out_hash_hex() -> String {
        "AB".repeat(32)
    }
    /// The same hash as a [`B256`] (what an on-chain `Transfer` would carry).
    fn out_hash() -> B256 {
        B256::repeat_byte(0xAB)
    }
    /// A test `redemptionId`.
    fn rid() -> B256 {
        B256::repeat_byte(0xD1)
    }
    /// An [`Erc20Arrival`] carrying the bound outbound hash + log 0 (the
    /// common single-delivery-per-tx case the success tests exercise).
    fn arrival(value: u128, confirmations: u32) -> Erc20Arrival {
        Erc20Arrival {
            value,
            confirmations,
            transaction_hash: out_hash(),
            log_index: 0,
        }
    }
    /// Fresh in-memory consumed-inflow ledger for a test.
    async fn mem_store() -> Arc<AnyConsumedInflow> {
        Arc::new(
            AnyConsumedInflow::connect(None)
                .await
                .unwrap_or_else(|e| unreachable!("in-memory connect: {e}")),
        )
    }
    /// Mount the `tx/details` mock whose single ETH `out_tx` to `eth_to`
    /// carries [`out_hash_hex`] — the OBSERVED outbound hash the delivery
    /// cross-check binds the on-chain USDT `Transfer` to (RUST-004).
    async fn mount_tx_details(server: &wiremock::MockServer, hash: &str, eth_to: EthAddress) {
        let to_lc = eth_addr_lc(eth_to);
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!(
                "/thorchain/tx/details/{hash}"
            )))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "out_txs": [{
                        "id": out_hash_hex(),
                        "chain": "ETH",
                        "to_address": to_lc,
                        "coins": [{
                            "asset": "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
                            "amount": "7000000000"
                        }]
                    }]
                })),
            )
            .mount(server)
            .await;
    }

    async fn mount_streamed_tx_details(
        server: &wiremock::MockServer,
        hash: &str,
        eth_to: EthAddress,
        eth_amount_1e8: Option<&str>,
        refund_sats: Option<&str>,
    ) {
        let mut outbounds = Vec::new();
        if let Some(amount) = eth_amount_1e8 {
            outbounds.push(serde_json::json!({
                "id": out_hash_hex(),
                "chain": "ETH",
                "to_address": eth_addr_lc(eth_to),
                "coins": [{
                    "asset": "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
                    "amount": amount
                }]
            }));
        }
        if let Some(amount) = refund_sats {
            outbounds.push(serde_json::json!({
                "id": "0000000000000000000000000000000000000000000000000000000000000abc",
                "chain": "BTC",
                "to_address": test_address().to_string(),
                "coins": [{ "asset": "BTC.BTC", "amount": amount }]
            }));
        }
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!(
                "/thorchain/tx/details/{hash}"
            )))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "out_txs": outbounds })),
            )
            .mount(server)
            .await;
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn confirm_erc20_arrival_filters_value_confs_and_hash() {
        let c = StubErc20::default();
        c.arrivals.lock().expect("lock").extend([
            arrival(10, 9),  // too small
            arrival(100, 1), // too shallow
            Erc20Arrival {
                value: 100,
                confirmations: 6,
                transaction_hash: B256::repeat_byte(0xCC), // wrong outbound hash
                log_index: 1,
            },
            arrival(100, 6), // ✓ value + confs + bound hash
        ]);
        let store = mem_store().await;
        let binding = InflowBinding {
            redemption_id: B256::repeat_byte(0x01),
            leg_index: 0,
            expected_outbound_hash: out_hash(),
        };
        let got = confirm_erc20_arrival(&c, &store, usdt_token(), idx_token(), 100, 6, &binding)
            .await
            .ok()
            .flatten();
        assert_eq!(got, Some(arrival(100, 6)));
    }

    #[tokio::test]
    async fn pass_through_redemption_and_refund_return_configured() {
        let r = PassThroughRedemption {
            usdt_1e6: 70_000_000,
        };
        assert_eq!(
            r.verify("h", idx_token(), rid(), 0).await.ok(),
            Some(70_000_000)
        );
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
        mount_tx_details(&server, "btc-in", idx_token()).await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let erc20 = StubErc20::default();
        erc20
            .arrivals
            .lock()
            .expect("lock")
            .push(arrival(70_000_000, 6)); // 70 USDT 1e6
        let policy = ThorUtxoToUsdtPolicy::new(thor, erc20, usdt_token(), 6, 0, mem_store().await);
        let attested = policy
            .verify("btc-in", idx_token(), rid(), 0)
            .await
            .expect("ok");
        assert_eq!(attested, 70_000_000, "attest the on-chain 1e6 value");
    }

    /// Mount a standard burn→USDT delivery `tx_status`: `done` + one ETH.USDT
    /// outbound action of 70 USDT (1e8) to the `IndexToken`.
    async fn mount_delivery_thor(server: &wiremock::MockServer, hash: &str) {
        let to_lc = eth_addr_lc(idx_token());
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!("/thorchain/tx/{hash}")))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": { "tx": { "id": hash, "chain":"BTC",
                        "from_address":"bc1qour","to_address":"thor-asgard",
                        "coins":[],"memo":"" }, "status":"done" },
                    "actions": [{
                        "chain":"ETH", "to_address": to_lc,
                        "coin": { "asset":"ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
                                  "amount":"7000000000" },
                        "memo":"OUT:", "max_gas":[]
                    }]
                })),
            )
            .mount(server)
            .await;
    }

    /// RUST-004: a physical inflow already consumed by a DIFFERENT redemption
    /// leg must NOT be credited again — the second redemption gets
    /// `UsdtNotReady` (no double-credit, basket stays whole).
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rust004_inflow_consumed_by_other_leg_is_skipped() {
        let server = wiremock::MockServer::start().await;
        mount_delivery_thor(&server, "btc-in").await;
        mount_tx_details(&server, "btc-in", idx_token()).await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let erc20 = StubErc20::default();
        erc20
            .arrivals
            .lock()
            .expect("lock")
            .push(arrival(70_000_000, 6));
        let store = mem_store().await;
        // A different redemption already consumed this exact (tx_hash, log).
        store
            .consume_inflow(B256::repeat_byte(0xEE), 0, out_hash(), 0)
            .await
            .expect("pre-consume");
        let policy = ThorUtxoToUsdtPolicy::new(thor, erc20, usdt_token(), 6, 0, store);
        let err = policy
            .verify("btc-in", idx_token(), rid(), 0)
            .await
            .expect_err("must not double-credit a consumed inflow");
        assert!(
            matches!(err, RedemptionCrossCheckError::UsdtNotReady { .. }),
            "got {err:?}"
        );
    }

    /// RUST-004: an on-chain USDT arrival whose `transaction_hash` is NOT the
    /// `THORChain` OBSERVED outbound is ignored (an unrelated / decoy transfer
    /// to the `IndexToken` can never be credited).
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rust004_non_matching_outbound_hash_ignored() {
        let server = wiremock::MockServer::start().await;
        mount_delivery_thor(&server, "btc-in").await;
        mount_tx_details(&server, "btc-in", idx_token()).await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let erc20 = StubErc20::default();
        erc20.arrivals.lock().expect("lock").push(Erc20Arrival {
            value: 70_000_000,
            confirmations: 6,
            transaction_hash: B256::repeat_byte(0xCC), // a different tx
            log_index: 0,
        });
        let policy = ThorUtxoToUsdtPolicy::new(thor, erc20, usdt_token(), 6, 0, mem_store().await);
        let err = policy
            .verify("btc-in", idx_token(), rid(), 0)
            .await
            .expect_err("arrival from an unrelated tx must not be credited");
        assert!(
            matches!(err, RedemptionCrossCheckError::UsdtNotReady { .. }),
            "got {err:?}"
        );
    }

    /// RUST-004: while `THORChain` has queued the ETH.USDT outbound but its
    /// `tx/details` `out_txs` is still empty (not yet observed on-chain), the
    /// cross-check is NOT ready and the signer must retry, never sign.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rust004_empty_out_txs_is_not_ready() {
        let server = wiremock::MockServer::start().await;
        mount_delivery_thor(&server, "btc-in").await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/details/btc-in"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "out_txs": [] })),
            )
            .mount(&server)
            .await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let erc20 = StubErc20::default();
        erc20
            .arrivals
            .lock()
            .expect("lock")
            .push(arrival(70_000_000, 6));
        let policy = ThorUtxoToUsdtPolicy::new(thor, erc20, usdt_token(), 6, 0, mem_store().await);
        let err = policy
            .verify("btc-in", idx_token(), rid(), 0)
            .await
            .expect_err("no observed outbound hash yet");
        assert!(
            matches!(err, RedemptionCrossCheckError::ThorNotReady { .. }),
            "got {err:?}"
        );
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
        let policy = ThorUtxoToUsdtPolicy::new(
            thor,
            StubErc20::default(),
            usdt_token(),
            6,
            0,
            mem_store().await,
        );
        let err = policy
            .verify("btc-in", idx_token(), rid(), 0)
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
            .and(wiremock::matchers::path(format!(
                "/thorchain/tx/{THOR_INBOUND_HASH}"
            )))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": { "tx": { "id":THOR_INBOUND_HASH,"chain":"BTC",
                        "from_address":"bc1qour","to_address":"thor-asgard",
                        "coins":[],"memo":"" }, "status":"done" },
                    "finalised_height": 100,
                    "actions": [{
                        "chain":"BTC", "to_address": multisig,
                        "coin": { "asset":"BTC.BTC","amount":"99990000" }, // sats == 1e8
                        "memo":format!("REFUND:{THOR_INBOUND_HASH}"), "max_gas":[]
                    }]
                })),
            )
            .mount(&server)
            .await;
        mount_streamed_tx_details(
            &server,
            THOR_INBOUND_HASH,
            idx_token(),
            None,
            Some("99990000"),
        )
        .await;
        mount_btc_inbound(&server, ASGARD_BTC, false).await;
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
        let attested = policy.verify(THOR_INBOUND_HASH).await.expect("ok");
        assert_eq!(attested, 99_990_000, "attest the on-chain UTXO sats");
    }

    /* ------------- combined streamed-settlement (burn streaming) ------------- */

    /// Partial fill: `THORChain` emitted BOTH an ETH.USDT delivery to the
    /// `IndexToken` AND a BTC `REFUND:` to our multisig on the same inbound.
    /// The combined policy returns both on-chain-observed amounts.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn streamed_partial_fill_returns_both_legs() {
        let server = wiremock::MockServer::start().await;
        let to_lc = eth_addr_lc(idx_token());
        let multisig = test_address().to_string();
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/streamed-in"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": { "tx": { "id":"streamed-in","chain":"BTC",
                        "from_address":"bc1qour","to_address":"thor-asgard",
                        "coins":[],"memo":"" }, "status":"done" },
                    "finalised_height": 100,
                    "actions": [
                        {
                            "chain":"ETH", "to_address": to_lc,
                            "coin": { "asset":"ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
                                      "amount":"7000000000" }, // 70 USDT 1e8
                            "memo":"OUT:streamed-in", "max_gas":[]
                        },
                        {
                            "chain":"BTC", "to_address": multisig,
                            "coin": { "asset":"BTC.BTC","amount":"30000000" }, // 0.3 BTC refunded
                            "memo":"REFUND:streamed-in", "max_gas":[]
                        }
                    ]
                })),
            )
            .mount(&server)
            .await;
        mount_btc_inbound(&server, ASGARD_BTC, false).await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let erc20 = StubErc20::default();
        erc20
            .arrivals
            .lock()
            .expect("lock")
            .push(arrival(70_000_000, 6));
        mount_streamed_tx_details(
            &server,
            "streamed-in",
            idx_token(),
            Some("7000000000"),
            Some("30000000"),
        )
        .await;
        let btc = StubBtc::default();
        btc.utxos.lock().expect("lock").push(UtxoEntry {
            txid: Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000abc",
            )
            .expect("txid"),
            vout: 0,
            value: Amount::from_sat(30_000_000),
            confirmations: 6,
            block_hash: None,
        });
        let policy = ThorUtxoStreamedSettlementPolicy::new(
            thor,
            erc20,
            btc,
            usdt_token(),
            test_address(),
            1,
            0,
            0,
            mem_store().await,
        );
        let outcome = policy
            .verify("streamed-in", idx_token(), rid(), 0)
            .await
            .expect("ok");
        assert_eq!(
            outcome.delivered_usdt_1e6, 70_000_000,
            "delivered USDT (1e6)"
        );
        assert_eq!(outcome.refunded_sats, 30_000_000, "refunded BTC (sats)");
    }

    /// Full delivery: only the ETH.USDT outbound exists → refund leg is
    /// zero (a streamed swap that fully filled).
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn streamed_full_delivery_returns_zero_refund() {
        let server = wiremock::MockServer::start().await;
        let to_lc = eth_addr_lc(idx_token());
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/streamed-in"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": { "tx": { "id":"streamed-in","chain":"BTC",
                        "from_address":"bc1qour","to_address":"thor-asgard",
                        "coins":[],"memo":"" }, "status":"done" },
                    "finalised_height": 100,
                    "actions": [{
                        "chain":"ETH", "to_address": to_lc,
                        "coin": { "asset":"ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
                                  "amount":"9000000000" }, // 90 USDT 1e8
                        "memo":"OUT:streamed-in", "max_gas":[]
                    }]
                })),
            )
            .mount(&server)
            .await;
        mount_btc_inbound(&server, ASGARD_BTC, false).await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let erc20 = StubErc20::default();
        erc20
            .arrivals
            .lock()
            .expect("lock")
            .push(arrival(90_000_000, 6));
        mount_streamed_tx_details(
            &server,
            "streamed-in",
            idx_token(),
            Some("9000000000"),
            None,
        )
        .await;
        let policy = ThorUtxoStreamedSettlementPolicy::new(
            thor,
            erc20,
            StubBtc::default(),
            usdt_token(),
            test_address(),
            1,
            0,
            0,
            mem_store().await,
        );
        let outcome = policy
            .verify("streamed-in", idx_token(), rid(), 0)
            .await
            .expect("ok");
        assert_eq!(outcome.delivered_usdt_1e6, 90_000_000);
        assert_eq!(outcome.refunded_sats, 0, "no refund leg ⇒ zero");
    }

    /// No outbound yet: neither a delivery nor a refund action exists →
    /// `NoSettlement` (the coordinator retries once the stream finalises).
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn streamed_no_outbound_errors_no_settlement() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/thorchain/tx/streamed-in"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": { "tx": { "id":"streamed-in","chain":"BTC",
                        "from_address":"bc1qour","to_address":"thor-asgard",
                        "coins":[],"memo":"" }, "status":"done" },
                    "finalised_height": 100,
                    "actions": []
                })),
            )
            .mount(&server)
            .await;
        mount_streamed_tx_details(&server, "streamed-in", idx_token(), None, None).await;
        mount_btc_inbound(&server, ASGARD_BTC, false).await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let policy = ThorUtxoStreamedSettlementPolicy::new(
            thor,
            StubErc20::default(),
            StubBtc::default(),
            usdt_token(),
            test_address(),
            1,
            0,
            0,
            mem_store().await,
        );
        let err = policy
            .verify("streamed-in", idx_token(), rid(), 0)
            .await
            .expect_err("nothing to settle");
        assert!(matches!(
            err,
            StreamedSettlementCrossCheckError::NoSettlement
        ));
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
        let policy = ThorUtxoToUsdtPolicy::new(
            thor,
            StubErc20::default(),
            usdt_token(),
            6,
            0,
            mem_store().await,
        );
        let err = policy
            .verify("btc-in", idx_token(), rid(), 0)
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
        let policy = ThorUtxoToUsdtPolicy::new(
            thor,
            StubErc20::default(),
            usdt_token(),
            6,
            0,
            mem_store().await,
        );
        let err = policy
            .verify("btc-in", idx_token(), rid(), 0)
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
        mount_tx_details(&server, "btc-in", idx_token()).await;
        let thor = ThorClient::with_base_url(server.uri()).expect("thor");
        let erc20 = StubErc20::default();
        erc20
            .arrivals
            .lock()
            .expect("lock")
            .push(arrival(70_000_000, 6));
        let policy = ThorUtxoToUsdtPolicy::new(thor, erc20, usdt_token(), 6, 0, mem_store().await);
        let attested = policy
            .verify("btc-in", idx_token(), rid(), 0)
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
            .and(wiremock::matchers::path(format!(
                "/thorchain/tx/{THOR_INBOUND_HASH}"
            )))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "observed_tx": { "tx": { "id":THOR_INBOUND_HASH,"chain":"BTC",
                        "from_address":"bc1qour","to_address":"thor-asgard",
                        "coins":[],"memo":"" }, "status":"done" },
                    "finalised_height": 100,
                    "actions": [
                        { "chain":"ETH", "to_address":"0xfoo",
                          "coin": { "asset":"ETH.ETH","amount":"1" },
                          "memo":"OUT:btc-in", "max_gas":[] },
                        { "chain":"LTC", "to_address":"ltc1q",
                          "coin": { "asset":"ETH.USDT-0XDAC","amount":"1" },
                          "memo":"OUT:btc-in", "max_gas":[] },
                        { "chain":"BTC", "to_address": multisig,
                          "coin": { "asset":"BTC.BTC","amount":"99990000" },
                          "memo":format!("REFUND:{THOR_INBOUND_HASH}"), "max_gas":[] }
                    ]
                })),
            )
            .mount(&server)
            .await;
        mount_streamed_tx_details(
            &server,
            THOR_INBOUND_HASH,
            idx_token(),
            None,
            Some("99990000"),
        )
        .await;
        mount_btc_inbound(&server, ASGARD_BTC, false).await;
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
            .verify(THOR_INBOUND_HASH)
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

    /// A refund UTXO outside the configured amount tolerance is not an
    /// eligible observation. Tolerance 5, diff 10, so the policy must remain
    /// not-ready rather than selecting the mismatched output.
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
                    "finalised_height": 100,
                    "actions": [{
                        "chain":"BTC", "to_address": multisig,
                        "coin": { "asset":"BTC.BTC","amount":"100000" },
                        "memo":"REFUND:btc-in", "max_gas":[]
                    }]
                })),
            )
            .mount(&server)
            .await;
        mount_streamed_tx_details(&server, "btc-in", idx_token(), None, Some("100000")).await;
        mount_btc_inbound(&server, ASGARD_BTC, false).await;
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
            matches!(err, RefundCrossCheckError::BtcNotReady { .. }),
            "expected BtcNotReady, got {err:?}"
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
        claim_inflow, observed_usdt_outbound_hash, within, InflowBinding, RedemptionCrossCheck,
        RedemptionCrossCheckError, RefundCrossCheck, RefundCrossCheckError,
    };
    use alloy_primitives::{Address as EthAddress, B256, U256};
    use async_trait::async_trait;
    use std::sync::Arc;
    use thiserror::Error;
    use tracing::{info, warn};
    use xindex_chain_evm::{EvmChainClient, EvmChainError, EvmLogEntry, EvmLogFilter};
    use xindex_chain_thor::{ThorClient, ThorError};
    use xindex_shared::consumed_inflow::{AnyConsumedInflow, ConsumedInflowError};

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
        /// The Router `TransferOut` delivered a different asset than the
        /// policy expects (audit L5). Never sign for a wrong asset.
        #[error("asset mismatch: delivered {delivered:#x} vs expected {expected:#x}")]
        AssetMismatch {
            /// Asset decoded from the Router event.
            delivered: EthAddress,
            /// Asset the policy was configured to expect.
            expected: EthAddress,
        },
        /// Mint path observed a REFUND action — caller MUST attest via
        /// the refund policy, never delivery (mutually exclusive on-chain).
        #[error("`THORChain` refunded (not delivered) — use the refund path")]
        RefundedInstead,
        /// Refund path observed a delivery action — caller MUST attest
        /// via the delivery policy.
        #[error("`THORChain` delivered (not refunded) — use the delivery path")]
        DeliveredInstead,
        /// The consumed-inflow ledger query failed (RUST-004).
        #[error("consumed-inflow ledger error: {0}")]
        Ledger(#[from] ConsumedInflowError),
    }

    /// One observed `TransferOut` event from a THORChain Router. Used
    /// internally by [`find_router_transfer_out`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RouterTransferOut {
        /// Wei value the Router transferred to `to`.
        pub value_wei: u128,
        /// Recipient (the Safe expected to receive).
        pub to: EthAddress,
        /// Delivered asset address (Router event `data[0..32]`). The zero
        /// address denotes the chain's native coin (ETH/BNB/AVAX). Bound
        /// against the policy's expected native asset (audit L5).
        pub asset: EthAddress,
        /// Tx-hash the event was emitted in.
        pub transaction_hash: B256,
        /// Index of the log within its block (RUST-004 consumed-inflow key).
        pub log_index: u64,
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
            if let Some(decoded) = decode_router_transfer_out(&log, router, safe, tip) {
                if decoded.value_wei >= min_value_wei && decoded.confirmations >= min_confs {
                    return Ok(Some(decoded));
                }
            }
        }
        Ok(None)
    }

    /// Scan an ERC20 token's `Transfer` events for one targeting `to_addr`
    /// with `value ≥ min_value`, `confirmations ≥ min_confs`, emitted by the
    /// `THORChain` OBSERVED outbound tx (`binding.expected_outbound_hash`), AND
    /// not already consumed by a different redemption leg — then mark it
    /// consumed (RUST-004, parity with [`super::confirm_erc20_arrival`]). Used
    /// by [`ThorEvmToUsdtPolicy`] for the USDT-arrival check on Ethereum.
    ///
    /// # Errors
    /// [`EvmCrossCheckError::Evm`] on RPC failure; [`EvmCrossCheckError::Ledger`]
    /// if the consumed-inflow store query fails.
    #[expect(
        clippy::too_many_arguments,
        reason = "threads the arrival filter (token, to, min_value, min_confs, lookback) plus the RUST-004 ledger (store) and binding"
    )]
    pub async fn find_erc20_transfer_to<E: EvmChainClient>(
        client: &E,
        store: &AnyConsumedInflow,
        token: EthAddress,
        to_addr: EthAddress,
        min_value: u128,
        min_confs: u32,
        lookback_blocks: u64,
        binding: &InflowBinding,
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
            if let Some(decoded) = decode_erc20_transfer(&log, token, to_addr, tip) {
                if decoded.value_wei >= min_value
                    && decoded.confirmations >= min_confs
                    && decoded.transaction_hash == binding.expected_outbound_hash
                    && claim_inflow(store, binding, decoded.transaction_hash, decoded.log_index)
                        .await?
                {
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
    fn decode_router_transfer_out(
        log: &EvmLogEntry,
        expected_contract: EthAddress,
        expected_to: EthAddress,
        tip: u64,
    ) -> Option<RouterTransferOut> {
        // Client-side emitter re-assert (audit I5): the node-side address
        // filter already binds the emitting contract to the Router, but a
        // non-compliant RPC could return a log from another contract.
        if log.address != expected_contract {
            return None;
        }
        // `topic[2]` = to (indexed).
        let to_topic = *log.topics.get(2)?;
        let mut to_bytes = [0u8; 20];
        to_bytes.copy_from_slice(&to_topic.as_slice()[12..]);
        let to = EthAddress::from(to_bytes);
        // Client-side recipient re-assert (audit L6): the node-side topic
        // filter already binds `to`, but a non-compliant RPC could ignore
        // it; mirror decode_erc20_transfer's defensive check.
        if to != expected_to {
            return None;
        }
        // `data` ABI: address (32) ‖ uint256 (32) ‖ offset (32) ‖
        //             length (32) ‖ memo-bytes (padded).
        // Decode asset at 0..32 (left-padded address) and amount at 32..64.
        let data = log.data.as_ref();
        if data.len() < 64 {
            return None;
        }
        let mut asset_bytes = [0u8; 20];
        asset_bytes.copy_from_slice(&data[12..32]);
        let asset = EthAddress::from(asset_bytes);
        let amount_word: [u8; 32] = data[32..64].try_into().ok()?;
        let amount = U256::from_be_slice(&amount_word);
        let value_wei = u128::try_from(amount).ok()?;
        let confirmations = u32::try_from(tip.saturating_sub(log.block_number).saturating_add(1))
            .unwrap_or(u32::MAX);
        Some(RouterTransferOut {
            value_wei,
            to,
            asset,
            transaction_hash: log.transaction_hash,
            log_index: log.log_index,
            confirmations,
        })
    }

    /// Decode an ERC20 Transfer log. `topic[2]` = to (indexed). `data`
    /// is the 32-byte value.
    fn decode_erc20_transfer(
        log: &EvmLogEntry,
        expected_token: EthAddress,
        expected_to: EthAddress,
        tip: u64,
    ) -> Option<RouterTransferOut> {
        // Client-side emitter re-assert (audit I5): the emitting contract of
        // an ERC20 Transfer IS the token; a non-compliant RPC ignoring the
        // address filter could otherwise smuggle a Transfer from another token.
        if log.address != expected_token {
            return None;
        }
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
            // For an ERC20 Transfer the emitting contract IS the token.
            asset: log.address,
            transaction_hash: log.transaction_hash,
            log_index: log.log_index,
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
        /// Expected delivered asset (Router event `data[0..32]`). `None`
        /// skips the asset binding (preserves the prior behaviour);
        /// `Some(addr)` rejects any `TransferOut` whose decoded asset
        /// differs — e.g. `Some(EthAddress::ZERO)` for native ETH (audit L5).
        expected_asset: Option<EthAddress>,
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
                .field("expected_asset", &self.expected_asset)
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
        ///
        /// `expected_asset` binds the delivered asset decoded from the
        /// Router `TransferOut` event (audit L5). Pass `Some(addr)` to
        /// require an exact asset (`Some(EthAddress::ZERO)` for the native
        /// coin); `None` skips the binding.
        #[must_use]
        pub fn new(
            thor: ThorClient,
            evm: E,
            safe_address: EthAddress,
            router_address: EthAddress,
            thor_chain_label: &'static str,
            expected_asset: Option<EthAddress>,
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
                expected_asset,
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
            // Refuse while this EVM chain's trading is halted on THORChain
            // (defense-in-depth — an operator incident signal, audit L8).
            let vault = self
                .thor
                .vault_for_chain(self.thor_chain_label)
                .await?
                .ok_or_else(|| EvmCrossCheckError::ThorNotReady {
                    reason: format!(
                        "no {} inbound address from THORChain",
                        self.thor_chain_label
                    ),
                })?;
            if vault.halted || vault.chain_trading_paused || vault.global_trading_paused {
                return Err(EvmCrossCheckError::ThorNotReady {
                    reason: format!("{} trading halted on THORChain", self.thor_chain_label),
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
            // Bind the delivered asset (audit L5). `None` skips the check.
            if let Some(expected) = self.expected_asset {
                if observed.asset != expected {
                    return Err(EvmCrossCheckError::AssetMismatch {
                        delivered: observed.asset,
                        expected,
                    });
                }
            }
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
            // Refuse while this EVM chain's trading is halted on THORChain
            // (defense-in-depth — an operator incident signal, audit L8).
            let vault = self
                .thor
                .vault_for_chain(self.thor_chain_label)
                .await?
                .ok_or_else(|| RefundCrossCheckError::ThorNotReady {
                    reason: format!(
                        "no {} inbound address from THORChain",
                        self.thor_chain_label
                    ),
                })?;
            if vault.halted || vault.chain_trading_paused || vault.global_trading_paused {
                return Err(RefundCrossCheckError::ThorNotReady {
                    reason: format!("{} trading halted on THORChain", self.thor_chain_label),
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
        /// Consumed-inflow ledger making each physical USDT delivery
        /// single-use (RUST-004).
        store: Arc<AnyConsumedInflow>,
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
            store: Arc<AnyConsumedInflow>,
        ) -> Self {
            Self {
                thor,
                evm,
                usdt_token,
                min_confirmations,
                tolerance_1e6,
                lookback_blocks,
                store,
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
            redemption_id: B256,
            leg_index: u32,
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
            // RUST-004: bind to the `THORChain` OBSERVED outbound tx hash
            // (tx/details out_txs) before crediting any USDT arrival.
            let expected_outbound_hash =
                observed_usdt_outbound_hash(&self.thor, evm_inbound_tx_hash, index_token)
                    .await?
                    .ok_or_else(|| RedemptionCrossCheckError::ThorNotReady {
                        reason: "no observed ETH.USDT outbound hash in tx/details yet".to_string(),
                    })?;
            let floor = thor_1e6.saturating_sub(self.tolerance_1e6);
            let arrival = find_erc20_transfer_to(
                &self.evm,
                &self.store,
                self.usdt_token,
                index_token,
                floor,
                self.min_confirmations,
                self.lookback_blocks,
                &InflowBinding {
                    redemption_id,
                    leg_index,
                    expected_outbound_hash,
                },
            )
            .await
            .map_err(|e| match e {
                EvmCrossCheckError::Evm(inner) => {
                    RedemptionCrossCheckError::Eth(super::Erc20Error::Rpc(format!("{inner}")))
                }
                EvmCrossCheckError::Ledger(inner) => RedemptionCrossCheckError::Ledger(inner),
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
        use std::sync::{Arc, Mutex};
        use xindex_chain_evm::{EvmConfirmedReceipt, EvmTransactionSummary};
        use xindex_shared::chain_registry::{ChainId, EvmTxType};
        use xindex_shared::consumed_inflow::AnyConsumedInflow;

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
                log_index: 0,
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
                // RUST-004: bind the redeem-side arrival to the observed
                // outbound hash the success test's tx/details mock advertises.
                transaction_hash: OUT_HASH,
                log_index: 0,
            }
        }

        const SAFE: Address = Address::new([0xab; 20]);
        const ROUTER: Address = Address::new([0xcd; 20]);
        /// RUST-004: the observed ETH outbound hash the redeem-to-USDT test
        /// binds to (matches `erc20_transfer_log` + the tx/details mock).
        const OUT_HASH: B256 = B256::new([0xAB; 32]);

        fn rid() -> B256 {
            B256::repeat_byte(0xD1)
        }
        async fn mem_store() -> Arc<AnyConsumedInflow> {
            Arc::new(
                AnyConsumedInflow::connect(None)
                    .await
                    .unwrap_or_else(|e| unreachable!("mem: {e}")),
            )
        }

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

        /// Mock `GET /thorchain/inbound_addresses` returning a single ETH
        /// vault with the given halted flag (address is irrelevant for the
        /// EVM policies — they have no sender binding, only the halt gate).
        async fn mount_eth_inbound(server: &wiremock::MockServer, halted: bool) {
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/thorchain/inbound_addresses"))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                    serde_json::json!([{
                        "chain": "ETH", "pub_key": "thorpub1addwnpepq",
                        "address": "0xeAf72A36ec9F0F8D90C0E5e3b9C2A95eAfBcDef0",
                        "router": "0xD37BbE5744D730a1d98d8DC97c42F0Ca46aD7146",
                        "halted": halted,
                        "global_trading_paused": false,
                        "chain_trading_paused": false,
                        "chain_lp_actions_paused": false
                    }]),
                ))
                .mount(server)
                .await;
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
            mount_eth_inbound(&server, false).await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let evm = StubEvm::new(ChainId::Eth, 100);
            evm.push(router_log(ROUTER, SAFE, 1_000_000_000_000_000_000, 95));
            // router_log encodes the asset word as all-zero → native ETH.
            let policy = ThorEvmPolicy::new(
                thor,
                evm,
                SAFE,
                ROUTER,
                "ETH",
                Some(Address::ZERO),
                3,
                0,
                1000,
            );
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
            mount_eth_inbound(&server, false).await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let evm = StubEvm::new(ChainId::Eth, 100);
            // No log pushed.
            let policy = ThorEvmPolicy::new(thor, evm, SAFE, ROUTER, "ETH", None, 3, 0, 1000);
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
            mount_eth_inbound(&server, false).await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let evm = StubEvm::new(ChainId::Eth, 100);
            let policy = ThorEvmPolicy::new(thor, evm, SAFE, ROUTER, "ETH", None, 3, 0, 1000);
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
            mount_eth_inbound(&server, false).await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let evm = StubEvm::new(ChainId::Eth, 100);
            // On-chain log has DIFFERENT amount than THORChain claims.
            evm.push(router_log(ROUTER, SAFE, 9_999, 95));
            let policy = ThorEvmPolicy::new(thor, evm, SAFE, ROUTER, "ETH", None, 3, 0, 1000);
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
            mount_eth_inbound(&server, false).await;
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
            mount_eth_inbound(&server, false).await;
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
            // RUST-004: the observed outbound the redeem-side arrival binds to.
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/thorchain/tx/details/abc"))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({
                        "out_txs": [{ "id": "AB".repeat(32), "chain": "ETH",
                            "to_address": it_str,
                            "coins": [{"asset":"ETH.USDT","amount":"100000000"}] }]
                    }),
                ))
                .mount(&server)
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
            let policy = ThorEvmToUsdtPolicy::new(thor, evm, USDT, 3, 0, 1000, mem_store().await);
            let out = policy
                .verify("abc", INDEX_TOKEN, rid(), 0)
                .await
                .expect("ok");
            assert_eq!(out, 1_000_000);
        }

        /// Halt gate (audit L8): THORChain reports ETH trading halted →
        /// ThorNotReady even when THORChain reports done.
        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn evm_mint_policy_rejects_when_eth_halted() {
            let safe_str = format!("{SAFE:#x}");
            let server = thor_done_responder(serde_json::json!({
                "chain": "ETH",
                "to_address": safe_str,
                "coin": { "asset": "ETH.ETH", "amount": "1000000000000000000" },
                "memo": "OUT:abc",
                "max_gas": []
            }))
            .await;
            mount_eth_inbound(&server, true).await; // halted
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let evm = StubEvm::new(ChainId::Eth, 100);
            evm.push(router_log(ROUTER, SAFE, 1_000_000_000_000_000_000, 95));
            let policy = ThorEvmPolicy::new(
                thor,
                evm,
                SAFE,
                ROUTER,
                "ETH",
                Some(Address::ZERO),
                3,
                0,
                1000,
            );
            let err = policy
                .verify("abc", 1_000_000_000_000_000_000)
                .await
                .expect_err("must reject while halted");
            assert!(
                matches!(err, EvmCrossCheckError::ThorNotReady { .. }),
                "expected ThorNotReady, got {err:?}"
            );
        }

        /// Asset binding (audit L5): the Router delivered a non-zero asset
        /// (an ERC20) but the policy expects native ETH (zero address) →
        /// AssetMismatch.
        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn evm_mint_policy_rejects_wrong_asset() {
            const WRONG_ASSET: Address = Address::new([0x99; 20]);
            let safe_str = format!("{SAFE:#x}");
            let server = thor_done_responder(serde_json::json!({
                "chain": "ETH",
                "to_address": safe_str,
                "coin": { "asset": "ETH.ETH", "amount": "1000000000000000000" },
                "memo": "OUT:abc",
                "max_gas": []
            }))
            .await;
            mount_eth_inbound(&server, false).await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let evm = StubEvm::new(ChainId::Eth, 100);
            // Encode a non-zero asset word in data[0..32].
            let mut to_topic = [0u8; 32];
            to_topic[12..].copy_from_slice(SAFE.as_slice());
            let mut data = vec![0u8; 64];
            data[12..32].copy_from_slice(WRONG_ASSET.as_slice()); // asset
            data[32..64]
                .copy_from_slice(&U256::from(1_000_000_000_000_000_000u128).to_be_bytes::<32>());
            data.extend_from_slice(&[0u8; 32]); // offset
            data.extend_from_slice(&[0u8; 32]); // length=0
            evm.push(EvmLogEntry {
                address: ROUTER,
                topics: vec![THOR_TRANSFER_OUT_TOPIC0, B256::ZERO, B256::from(to_topic)],
                data: Bytes::from(data),
                block_number: 95,
                transaction_hash: B256::ZERO,
                log_index: 0,
            });
            // Policy expects native ETH (zero asset) but the event delivered
            // WRONG_ASSET.
            let policy = ThorEvmPolicy::new(
                thor,
                evm,
                SAFE,
                ROUTER,
                "ETH",
                Some(Address::ZERO),
                3,
                0,
                1000,
            );
            let err = policy
                .verify("abc", 1_000_000_000_000_000_000)
                .await
                .expect_err("must reject wrong asset");
            assert!(
                matches!(err, EvmCrossCheckError::AssetMismatch { .. }),
                "expected AssetMismatch, got {err:?}"
            );
        }
    }
}

/// C6: Phase 3.3 Cosmos custody cross-check policies. Symmetric to the
/// UTXO (`ThorUtxoToUsdtPolicy` / `ThorUtxoRefundPolicy`) and EVM ([`evm`])
/// families, for the Cosmos custody family (GAIA / ATOM) where the
/// destination custody is a LegacyAminoPubKey k-of-n multisig.
///
/// ## Why it mirrors the UTXO side, not the EVM side
///
/// A Cosmos delivery/refund is a NATIVE bank transfer — no Router contract,
/// no event-bearing token — so (unlike EVM, which scans the THORChain
/// Router's TransferOut log) the observation is a `transfer` event on the
/// destination address, exactly like scanning a Bitcoin multisig for an
/// arriving UTXO. The redemption DELIVERY leg is identical across all
/// families (USDT lands on Ethereum), so the delivery policy reuses the
/// shared `Erc20ArrivalClient`; only the refund leg is Cosmos-specific.
///
/// ## Refund binds to the Asgard vault (DL-P3.3)
///
/// A refund is uatom returning to our multisig. Because our multisig bech32
/// address is public, a recipient+amount match alone is forgeable by anyone
/// who pays it; the refund policy additionally requires the on-chain
/// `transfer.sender` to equal the live THORChain GAIA Asgard vault (resolved
/// via `/thorchain/inbound_addresses`), and refuses to attest while GAIA
/// trading is halted.
#[expect(
    clippy::doc_markdown,
    reason = "THORChain / GAIA / ATOM / Asgard / RPC identifiers recur \
              throughout this module's docs; per-identifier backticks add \
              noise without aiding parsing"
)]
pub mod cosmos {
    use super::{
        confirm_erc20_arrival, observed_usdt_outbound_hash, within, Erc20ArrivalClient,
        InflowBinding, RedemptionCrossCheck, RedemptionCrossCheckError, RefundCrossCheck,
        RefundCrossCheckError,
    };
    use alloy_primitives::{Address as EthAddress, B256};
    use async_trait::async_trait;
    use std::sync::Arc;
    use tracing::{info, warn};
    use xindex_chain_cosmos::{CosmosChainClient, CosmosChainError};
    use xindex_chain_thor::ThorClient;
    use xindex_shared::consumed_inflow::AnyConsumedInflow;

    /// THORChain reports every asset in 1e8; native uatom is 1e6 (GAIA), so
    /// a refund's THORChain amount is divided by 100 to compare with the
    /// on-chain uatom value (the R-T2 analogue — see KNOWN_FINDINGS).
    const THOR_TO_ATOM_SCALE: u128 = 100;
    /// THORChain 1e8 vs on-chain USDT 1e6 — the delivery leg lands USDT on
    /// Ethereum, identical to the UTXO/EVM delivery.
    const THOR_TO_USDT_SCALE: u128 = 100;
    /// THORChain chain label for Cosmos Hub.
    const GAIA_CHAIN: &str = "GAIA";
    /// THORChain asset for native ATOM.
    const GAIA_ASSET: &str = "GAIA.ATOM";
    /// Native micro-denom for ATOM.
    const UATOM_DENOM: &str = "uatom";

    /// Production delivery policy: THORChain swapped ATOM→USDT and the USDT
    /// actually landed at the IndexToken on Ethereum. Two independent
    /// observations, mirroring `ThorUtxoToUsdtPolicy`; only the refund
    /// mutual-exclusion guard is Cosmos-specific (GAIA, not BTC).
    pub struct ThorCosmosToUsdtPolicy<E: Erc20ArrivalClient> {
        thor: ThorClient,
        erc20: E,
        usdt_token: EthAddress,
        min_confirmations: u32,
        tolerance_1e6: u128,
        /// Consumed-inflow ledger making each physical USDT delivery
        /// single-use (RUST-004).
        store: Arc<AnyConsumedInflow>,
    }

    impl<E: Erc20ArrivalClient> std::fmt::Debug for ThorCosmosToUsdtPolicy<E> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ThorCosmosToUsdtPolicy")
                .field("usdt_token", &self.usdt_token)
                .field("min_confirmations", &self.min_confirmations)
                .field("tolerance_1e6", &self.tolerance_1e6)
                .finish_non_exhaustive()
        }
    }

    impl<E: Erc20ArrivalClient> ThorCosmosToUsdtPolicy<E> {
        #[must_use]
        pub fn new(
            thor: ThorClient,
            erc20: E,
            usdt_token: EthAddress,
            min_confirmations: u32,
            tolerance_1e6: u128,
            store: Arc<AnyConsumedInflow>,
        ) -> Self {
            Self {
                thor,
                erc20,
                usdt_token,
                min_confirmations,
                tolerance_1e6,
                store,
            }
        }
    }

    #[async_trait]
    impl<E: Erc20ArrivalClient> RedemptionCrossCheck for ThorCosmosToUsdtPolicy<E> {
        async fn verify(
            &self,
            cosmos_inbound_hash: &str,
            index_token: EthAddress,
            redemption_id: B256,
            leg_index: u32,
        ) -> Result<u128, RedemptionCrossCheckError> {
            let resp = self.thor.tx_status(cosmos_inbound_hash).await?;
            if resp.observed_tx.status != "done" {
                return Err(RedemptionCrossCheckError::ThorNotReady {
                    reason: format!("observed_tx.status = {}", resp.observed_tx.status),
                });
            }
            // Mutual-exclusion: a GAIA REFUND outbound means this is the
            // refund path, never attest a delivery.
            if resp
                .actions
                .iter()
                .any(|a| a.chain == GAIA_CHAIN && a.memo.to_uppercase().starts_with("REFUND:"))
            {
                return Err(RedemptionCrossCheckError::RefundedInstead);
            }
            let want = format!("{index_token:#x}").to_lowercase();
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
            // RUST-004: bind to the OBSERVED outbound tx hash + consume inflow.
            let expected_outbound_hash =
                observed_usdt_outbound_hash(&self.thor, cosmos_inbound_hash, index_token)
                    .await?
                    .ok_or_else(|| RedemptionCrossCheckError::ThorNotReady {
                        reason: "no observed ETH.USDT outbound hash in tx/details yet".to_string(),
                    })?;
            let floor = thor_1e6.saturating_sub(self.tolerance_1e6);
            let arrival = confirm_erc20_arrival(
                &self.erc20,
                &self.store,
                self.usdt_token,
                index_token,
                floor,
                self.min_confirmations,
                &InflowBinding {
                    redemption_id,
                    leg_index,
                    expected_outbound_hash,
                },
            )
            .await?
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
                cosmos_inbound_hash,
                onchain_usdt_1e6 = arrival.value,
                "cosmos redemption cross-check OK"
            );
            // Attest the ON-CHAIN observed value (what the IndexToken's USDT
            // balance actually grew by), not THORChain's figure.
            Ok(arrival.value)
        }
    }

    /// Production refund policy: THORChain slip-refunded ATOM to our
    /// multisig (`REFUND:<hash>` GAIA outbound) and the uatom actually
    /// returned FROM the live Asgard vault. Disambiguated from a delivery
    /// ONLY by the USDT-outbound mutual exclusion + the `REFUND:` memo —
    /// never by time.
    pub struct ThorCosmosRefundPolicy<C: CosmosChainClient> {
        thor: ThorClient,
        cosmos: C,
        multisig_address: String,
        min_confirmations: u32,
        tolerance_uatom: u128,
        lookback_blocks: u64,
    }

    impl<C: CosmosChainClient> std::fmt::Debug for ThorCosmosRefundPolicy<C> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ThorCosmosRefundPolicy")
                .field("multisig_address", &self.multisig_address)
                .field("min_confirmations", &self.min_confirmations)
                .field("tolerance_uatom", &self.tolerance_uatom)
                .finish_non_exhaustive()
        }
    }

    impl<C: CosmosChainClient> ThorCosmosRefundPolicy<C> {
        #[must_use]
        pub fn new(
            thor: ThorClient,
            cosmos: C,
            multisig_address: String,
            min_confirmations: u32,
            tolerance_uatom: u128,
            lookback_blocks: u64,
        ) -> Self {
            Self {
                thor,
                cosmos,
                multisig_address,
                min_confirmations,
                tolerance_uatom,
                lookback_blocks,
            }
        }
    }

    #[async_trait]
    impl<C: CosmosChainClient> RefundCrossCheck for ThorCosmosRefundPolicy<C> {
        async fn verify(&self, cosmos_inbound_hash: &str) -> Result<u64, RefundCrossCheckError> {
            let resp = self.thor.tx_status(cosmos_inbound_hash).await?;
            if resp.observed_tx.status != "done" {
                return Err(RefundCrossCheckError::ThorNotReady {
                    reason: format!("observed_tx.status = {}", resp.observed_tx.status),
                });
            }
            // Mutual-exclusion: a USDT delivery means use the delivery path.
            if resp
                .actions
                .iter()
                .any(|a| a.chain == "ETH" && a.coin.asset.to_uppercase().starts_with("ETH.USDT"))
            {
                return Err(RefundCrossCheckError::DeliveredInstead);
            }
            let action = resp
                .actions
                .iter()
                .find(|a| {
                    a.chain == GAIA_CHAIN
                        && a.to_address == self.multisig_address
                        && a.memo.to_uppercase().starts_with("REFUND:")
                        && a.coin.asset.to_uppercase() == GAIA_ASSET
                })
                .ok_or_else(|| RefundCrossCheckError::ThorNotReady {
                    reason: "no GAIA REFUND outbound to our multisig yet".to_string(),
                })?;
            let thor_1e8: u128 =
                action
                    .coin
                    .amount
                    .parse()
                    .map_err(|e| RefundCrossCheckError::ThorNotReady {
                        reason: format!("non-integer refund amount '{}': {e}", action.coin.amount),
                    })?;
            let thor_uatom = thor_1e8 / THOR_TO_ATOM_SCALE;

            // Resolve the live Asgard vault — the refund MUST originate
            // there (sender binding). Refuse while GAIA trading is halted.
            let vault = self
                .thor
                .vault_for_chain(GAIA_CHAIN)
                .await?
                .ok_or_else(|| RefundCrossCheckError::ThorNotReady {
                    reason: "no GAIA inbound address from THORChain".to_string(),
                })?;
            if vault.halted || vault.chain_trading_paused || vault.global_trading_paused {
                return Err(RefundCrossCheckError::ThorNotReady {
                    reason: "GAIA trading halted on THORChain".to_string(),
                });
            }

            let floor = thor_uatom.saturating_sub(self.tolerance_uatom);
            let observed = find_cosmos_arrival(
                &self.cosmos,
                &self.multisig_address,
                &vault.address,
                UATOM_DENOM,
                floor,
                self.min_confirmations,
                self.lookback_blocks,
            )
            .await
            .map_err(|e| RefundCrossCheckError::ThorNotReady {
                reason: format!("cosmos arrival lookup failed: {e}"),
            })?
            .ok_or(RefundCrossCheckError::BtcNotReady {
                // Variant is family-shared and smallest-unit; "sats" naming
                // is historical (a v2 rename), the value is uatom here.
                need_sats: u64::try_from(thor_uatom).unwrap_or(u64::MAX),
                confs: self.min_confirmations,
            })?;
            if observed.abs_diff(thor_uatom) > self.tolerance_uatom {
                return Err(RefundCrossCheckError::AmountMismatch {
                    thor_sats: u64::try_from(thor_uatom).unwrap_or(u64::MAX),
                    utxo_sats: u64::try_from(observed).unwrap_or(u64::MAX),
                });
            }
            warn!(
                cosmos_inbound_hash,
                refund_uatom = observed,
                asgard = %vault.address,
                "cosmos refund cross-check OK"
            );
            Ok(u64::try_from(observed).unwrap_or(u64::MAX))
        }
    }

    /// First `transfer` to `multisig` with `sender == expected_sender`,
    /// `denom == expected_denom`, `amount >= min_value`, and at least
    /// `min_confs` inclusion depth at the chain tip. `None` = not yet
    /// observed (the signer polls again, never attests).
    async fn find_cosmos_arrival<C: CosmosChainClient>(
        cosmos: &C,
        multisig: &str,
        expected_sender: &str,
        expected_denom: &str,
        min_value: u128,
        min_confs: u32,
        lookback_blocks: u64,
    ) -> Result<Option<u128>, CosmosChainError> {
        let tip = cosmos.latest_height().await?;
        let min_height = tip.saturating_sub(lookback_blocks);
        let transfers = cosmos.transfers_to(multisig, min_height).await?;
        for t in transfers {
            let confs = tip.saturating_sub(t.height).saturating_add(1);
            if t.sender == expected_sender
                && t.denom == expected_denom
                && t.amount >= min_value
                && confs >= u64::from(min_confs)
            {
                return Ok(Some(t.amount));
            }
        }
        Ok(None)
    }

    #[cfg(test)]
    mod tests {
        use super::super::{Erc20Arrival, Erc20ArrivalClient, Erc20Error};
        use super::{
            RedemptionCrossCheck, RedemptionCrossCheckError, RefundCrossCheck,
            RefundCrossCheckError, ThorCosmosRefundPolicy, ThorCosmosToUsdtPolicy,
        };
        use alloy_primitives::{Address as EthAddress, B256};
        use std::future::ready;
        use std::sync::Arc;
        use xindex_chain_cosmos::{
            CosmosAccount, CosmosBroadcastOutcome, CosmosChainClient, CosmosChainError,
            CosmosTransfer,
        };
        use xindex_chain_thor::ThorClient;
        use xindex_shared::chain_registry::ChainId;
        use xindex_shared::consumed_inflow::AnyConsumedInflow;

        const INDEX_TOKEN: EthAddress = EthAddress::new([0x11; 20]);
        const USDT: EthAddress = EthAddress::new([0x22; 20]);
        const MULTISIG: &str = "cosmos1vault0multisig";
        const ASGARD: &str = "cosmos1asgard0vault";

        /// RUST-004: the OBSERVED ETH outbound hash the delivery tests bind to.
        fn out_hash() -> B256 {
            B256::repeat_byte(0xAB)
        }
        /// A test `redemptionId`.
        fn rid() -> B256 {
            B256::repeat_byte(0xD1)
        }
        /// An [`Erc20Arrival`] carrying the bound outbound hash + log 0.
        fn arrival(value: u128, confirmations: u32) -> Erc20Arrival {
            Erc20Arrival {
                value,
                confirmations,
                transaction_hash: out_hash(),
                log_index: 0,
            }
        }
        /// Fresh in-memory consumed-inflow ledger.
        async fn mem_store() -> Arc<AnyConsumedInflow> {
            Arc::new(
                AnyConsumedInflow::connect(None)
                    .await
                    .unwrap_or_else(|e| unreachable!("mem: {e}")),
            )
        }
        /// Mock `tx/details` with an observed ETH `out_tx` to `eth_to` carrying
        /// [`out_hash`] (RUST-004 1:1 inflow bind).
        async fn mount_tx_details(server: &wiremock::MockServer, hash: &str, eth_to: EthAddress) {
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path(format!(
                    "/thorchain/tx/details/{hash}"
                )))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({
                        "out_txs": [{ "id": "AB".repeat(32), "chain": "ETH",
                            "to_address": format!("{eth_to:#x}"),
                            "coins": [{"asset":"ETH.USDT-0XDAC","amount":"100000000"}] }]
                    }),
                ))
                .mount(server)
                .await;
        }

        /// In-memory ERC20 arrival backend.
        #[derive(Default)]
        struct StubErc20 {
            arrivals: Vec<Erc20Arrival>,
        }
        impl Erc20ArrivalClient for StubErc20 {
            fn transfers_to(
                &self,
                _token: EthAddress,
                _to: EthAddress,
            ) -> Result<Vec<Erc20Arrival>, Erc20Error> {
                Ok(self.arrivals.clone())
            }
        }

        /// In-memory Cosmos client. `ready(..)` (not `async fn`) keeps the
        /// stubs free of `clippy::unused_async`.
        struct StubCosmos {
            tip: u64,
            transfers: Vec<CosmosTransfer>,
        }
        impl CosmosChainClient for StubCosmos {
            fn chain(&self) -> ChainId {
                ChainId::Gaia
            }
            #[expect(
                clippy::unnecessary_literal_bound,
                reason = "test stub returns a fixed consensus chain-id"
            )]
            fn cosmos_chain_id(&self) -> &str {
                "cosmoshub-4"
            }
            fn account(
                &self,
                _address: &str,
            ) -> impl std::future::Future<Output = Result<CosmosAccount, CosmosChainError>> + Send
            {
                ready(Ok(CosmosAccount {
                    account_number: 1,
                    sequence: 0,
                }))
            }
            fn latest_height(
                &self,
            ) -> impl std::future::Future<Output = Result<u64, CosmosChainError>> + Send
            {
                ready(Ok(self.tip))
            }
            fn transfers_to(
                &self,
                _recipient: &str,
                min_height: u64,
            ) -> impl std::future::Future<Output = Result<Vec<CosmosTransfer>, CosmosChainError>> + Send
            {
                let v: Vec<CosmosTransfer> = self
                    .transfers
                    .iter()
                    .filter(|t| t.height >= min_height)
                    .cloned()
                    .collect();
                ready(Ok(v))
            }
            fn broadcast_tx_sync(
                &self,
                _tx_raw: &[u8],
            ) -> impl std::future::Future<Output = Result<CosmosBroadcastOutcome, CosmosChainError>> + Send
            {
                ready(Err(CosmosChainError::Rpc("not used in tests".to_string())))
            }
        }

        fn transfer(sender: &str, amount: u128, denom: &str, height: u64) -> CosmosTransfer {
            CosmosTransfer {
                height,
                txhash: "GAIATX".to_string(),
                sender: sender.to_string(),
                recipient: MULTISIG.to_string(),
                amount,
                denom: denom.to_string(),
            }
        }

        /// Mock `GET /thorchain/tx/{hash}` with the given actions JSON.
        async fn mount_tx(server: &wiremock::MockServer, hash: &str, actions: serde_json::Value) {
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path(format!("/thorchain/tx/{hash}")))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({
                        "observed_tx": {
                            "tx": { "id": hash, "chain": "GAIA", "from_address": "cosmos1user",
                                    "to_address": ASGARD, "coins": [], "memo": "" },
                            "status": "done"
                        },
                        "actions": actions
                    }),
                ))
                .mount(server)
                .await;
        }

        /// Mock `GET /thorchain/inbound_addresses` returning a GAIA vault.
        async fn mount_inbound(server: &wiremock::MockServer, halted: bool) {
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/thorchain/inbound_addresses"))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                    serde_json::json!([{
                        "chain": "GAIA", "pub_key": "thorpub1addwnpepq", "address": ASGARD,
                        "halted": halted,
                        "global_trading_paused": false,
                        "chain_trading_paused": false,
                        "chain_lp_actions_paused": false
                    }]),
                ))
                .mount(server)
                .await;
        }

        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn refund_ok_when_uatom_returns_from_asgard() {
            let server = wiremock::MockServer::start().await;
            // 5 ATOM refund: THORChain 1e8 = 500_000_000 → 5_000_000 uatom.
            mount_tx(
                &server,
                "gaia-in",
                serde_json::json!([{ "chain": "GAIA", "to_address": MULTISIG,
                    "coin": {"asset": "GAIA.ATOM", "amount": "500000000"},
                    "memo": "REFUND:gaia-in", "max_gas": [] }]),
            )
            .await;
            mount_inbound(&server, false).await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let cosmos = StubCosmos {
                tip: 100,
                transfers: vec![transfer(ASGARD, 5_000_000, "uatom", 100)],
            };
            let policy =
                ThorCosmosRefundPolicy::new(thor, cosmos, MULTISIG.to_string(), 1, 0, 1000);
            let out = policy.verify("gaia-in").await.expect("refund ok");
            assert_eq!(out, 5_000_000);
        }

        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn refund_rejects_wrong_sender() {
            let server = wiremock::MockServer::start().await;
            mount_tx(
                &server,
                "gaia-in",
                serde_json::json!([{ "chain": "GAIA", "to_address": MULTISIG,
                    "coin": {"asset": "GAIA.ATOM", "amount": "500000000"},
                    "memo": "REFUND:gaia-in", "max_gas": [] }]),
            )
            .await;
            mount_inbound(&server, false).await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            // The uatom arrives, exact amount — but NOT from the Asgard vault.
            let cosmos = StubCosmos {
                tip: 100,
                transfers: vec![transfer("cosmos1attacker", 5_000_000, "uatom", 100)],
            };
            let policy =
                ThorCosmosRefundPolicy::new(thor, cosmos, MULTISIG.to_string(), 1, 0, 1000);
            let err = policy.verify("gaia-in").await.expect_err("must reject");
            assert!(
                matches!(err, RefundCrossCheckError::BtcNotReady { .. }),
                "got {err:?}"
            );
        }

        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn refund_rejects_when_gaia_halted() {
            let server = wiremock::MockServer::start().await;
            mount_tx(
                &server,
                "gaia-in",
                serde_json::json!([{ "chain": "GAIA", "to_address": MULTISIG,
                    "coin": {"asset": "GAIA.ATOM", "amount": "500000000"},
                    "memo": "REFUND:gaia-in", "max_gas": [] }]),
            )
            .await;
            mount_inbound(&server, true).await; // halted
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let cosmos = StubCosmos {
                tip: 100,
                transfers: vec![transfer(ASGARD, 5_000_000, "uatom", 100)],
            };
            let policy =
                ThorCosmosRefundPolicy::new(thor, cosmos, MULTISIG.to_string(), 1, 0, 1000);
            let err = policy.verify("gaia-in").await.expect_err("must reject");
            assert!(
                matches!(err, RefundCrossCheckError::ThorNotReady { .. }),
                "got {err:?}"
            );
        }

        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn refund_delivered_instead_when_usdt_outbound_present() {
            let server = wiremock::MockServer::start().await;
            mount_tx(
                &server,
                "gaia-in",
                serde_json::json!([{ "chain": "ETH", "to_address": "0xindex",
                    "coin": {"asset": "ETH.USDT-0XDAC", "amount": "100000000"},
                    "memo": "OUT:gaia-in", "max_gas": [] }]),
            )
            .await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let cosmos = StubCosmos {
                tip: 100,
                transfers: vec![],
            };
            let policy =
                ThorCosmosRefundPolicy::new(thor, cosmos, MULTISIG.to_string(), 1, 0, 1000);
            let err = policy.verify("gaia-in").await.expect_err("must reject");
            assert!(
                matches!(err, RefundCrossCheckError::DeliveredInstead),
                "got {err:?}"
            );
        }

        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn delivery_ok_when_usdt_lands_on_eth() {
            let server = wiremock::MockServer::start().await;
            let want = format!("{INDEX_TOKEN:#x}");
            mount_tx(
                &server,
                "gaia-in",
                serde_json::json!([{ "chain": "ETH", "to_address": want,
                    "coin": {"asset": "ETH.USDT-0XDAC", "amount": "100000000"},
                    "memo": "OUT:gaia-in", "max_gas": [] }]),
            )
            .await;
            mount_tx_details(&server, "gaia-in", INDEX_TOKEN).await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            // 1e8 / 100 = 1e6 USDT, and the same lands on-chain.
            let erc20 = StubErc20 {
                arrivals: vec![arrival(1_000_000, 5)],
            };
            let policy = ThorCosmosToUsdtPolicy::new(thor, erc20, USDT, 3, 0, mem_store().await);
            let out = policy
                .verify("gaia-in", INDEX_TOKEN, rid(), 0)
                .await
                .expect("delivery ok");
            assert_eq!(out, 1_000_000);
        }

        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn delivery_refunded_instead_when_gaia_refund_present() {
            let server = wiremock::MockServer::start().await;
            mount_tx(
                &server,
                "gaia-in",
                serde_json::json!([{ "chain": "GAIA", "to_address": MULTISIG,
                    "coin": {"asset": "GAIA.ATOM", "amount": "500000000"},
                    "memo": "REFUND:gaia-in", "max_gas": [] }]),
            )
            .await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let policy = ThorCosmosToUsdtPolicy::new(
                thor,
                StubErc20::default(),
                USDT,
                3,
                0,
                mem_store().await,
            );
            let err = policy
                .verify("gaia-in", INDEX_TOKEN, rid(), 0)
                .await
                .expect_err("must reject");
            assert!(
                matches!(err, RedemptionCrossCheckError::RefundedInstead),
                "got {err:?}"
            );
        }

        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn delivery_amount_mismatch_when_onchain_differs() {
            let server = wiremock::MockServer::start().await;
            let want = format!("{INDEX_TOKEN:#x}");
            mount_tx(
                &server,
                "gaia-in",
                serde_json::json!([{ "chain": "ETH", "to_address": want,
                    "coin": {"asset": "ETH.USDT-0XDAC", "amount": "100000000"},
                    "memo": "OUT:gaia-in", "max_gas": [] }]),
            )
            .await;
            mount_tx_details(&server, "gaia-in", INDEX_TOKEN).await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            // THORChain says 1e6; on-chain shows more, tolerance 0 → mismatch.
            let erc20 = StubErc20 {
                arrivals: vec![arrival(1_100_000, 5)],
            };
            let policy = ThorCosmosToUsdtPolicy::new(thor, erc20, USDT, 3, 0, mem_store().await);
            let err = policy
                .verify("gaia-in", INDEX_TOKEN, rid(), 0)
                .await
                .expect_err("must reject");
            assert!(
                matches!(err, RedemptionCrossCheckError::AmountMismatch { .. }),
                "got {err:?}"
            );
        }
    }
}

/// C6 (Phase 4.4): XRP redemption + refund cross-check policies.
///
/// Direct mirror of [`cosmos`]: two independent observations
/// (THORChain + on-chain), the delivery/refund mutual-exclusion via the
/// `REFUND:` memo, and live-Asgard-vault sender binding. The XRP-specific
/// item is `delivered_amount`: the on-chain refund value comes from
/// [`xindex_chain_xrp::XrpTransfer::delivered_drops`], which the
/// `chain-xrp` parser sources from `meta.delivered_amount` (never
/// `Amount`) — so a `tfPartialPayment` cannot make a 1-drop delivery
/// count as full value.
#[expect(
    clippy::doc_markdown,
    reason = "THORChain / XRP / Asgard / RPC identifiers recur throughout \
              this module's docs; per-identifier backticks add noise without \
              aiding parsing"
)]
pub mod xrp {
    use super::{
        confirm_erc20_arrival, observed_usdt_outbound_hash, within, Erc20ArrivalClient,
        InflowBinding, RedemptionCrossCheck, RedemptionCrossCheckError, RefundCrossCheck,
        RefundCrossCheckError,
    };
    use alloy_primitives::{Address as EthAddress, B256};
    use async_trait::async_trait;
    use std::sync::Arc;
    use tracing::{info, warn};
    use xindex_chain_thor::ThorClient;
    use xindex_chain_xrp::{XrpChainClient, XrpChainError};
    use xindex_shared::consumed_inflow::AnyConsumedInflow;

    /// THORChain reports every asset in 1e8; native XRP is 1e6 (drops), so
    /// a refund's THORChain amount is divided by 100 to compare with the
    /// on-chain drops value (same scale as ATOM).
    const THOR_TO_XRP_SCALE: u128 = 100;
    /// THORChain 1e8 vs on-chain USDT 1e6 — the delivery leg lands USDT on
    /// Ethereum, identical to the UTXO/EVM/Cosmos delivery.
    const THOR_TO_USDT_SCALE: u128 = 100;
    /// THORChain chain label for the XRP Ledger.
    const XRP_CHAIN: &str = "XRP";
    /// THORChain asset for native XRP.
    const XRP_ASSET: &str = "XRP.XRP";

    /// Production delivery policy: THORChain swapped XRP→USDT and the USDT
    /// actually landed at the `IndexToken` on Ethereum. Two independent
    /// observations, mirroring `ThorCosmosToUsdtPolicy`; only the refund
    /// mutual-exclusion guard is XRP-specific.
    pub struct ThorXrpToUsdtPolicy<E: Erc20ArrivalClient> {
        thor: ThorClient,
        erc20: E,
        usdt_token: EthAddress,
        min_confirmations: u32,
        tolerance_1e6: u128,
        /// Consumed-inflow ledger making each physical USDT delivery
        /// single-use (RUST-004).
        store: Arc<AnyConsumedInflow>,
    }

    impl<E: Erc20ArrivalClient> std::fmt::Debug for ThorXrpToUsdtPolicy<E> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ThorXrpToUsdtPolicy")
                .field("usdt_token", &self.usdt_token)
                .field("min_confirmations", &self.min_confirmations)
                .field("tolerance_1e6", &self.tolerance_1e6)
                .finish_non_exhaustive()
        }
    }

    impl<E: Erc20ArrivalClient> ThorXrpToUsdtPolicy<E> {
        #[must_use]
        pub fn new(
            thor: ThorClient,
            erc20: E,
            usdt_token: EthAddress,
            min_confirmations: u32,
            tolerance_1e6: u128,
            store: Arc<AnyConsumedInflow>,
        ) -> Self {
            Self {
                thor,
                erc20,
                usdt_token,
                min_confirmations,
                tolerance_1e6,
                store,
            }
        }
    }

    #[async_trait]
    impl<E: Erc20ArrivalClient> RedemptionCrossCheck for ThorXrpToUsdtPolicy<E> {
        async fn verify(
            &self,
            xrp_inbound_hash: &str,
            index_token: EthAddress,
            redemption_id: B256,
            leg_index: u32,
        ) -> Result<u128, RedemptionCrossCheckError> {
            let resp = self.thor.tx_status(xrp_inbound_hash).await?;
            if resp.observed_tx.status != "done" {
                return Err(RedemptionCrossCheckError::ThorNotReady {
                    reason: format!("observed_tx.status = {}", resp.observed_tx.status),
                });
            }
            // Mutual-exclusion: an XRP REFUND outbound means this is the
            // refund path, never attest a delivery.
            if resp
                .actions
                .iter()
                .any(|a| a.chain == XRP_CHAIN && a.memo.to_uppercase().starts_with("REFUND:"))
            {
                return Err(RedemptionCrossCheckError::RefundedInstead);
            }
            let want = format!("{index_token:#x}").to_lowercase();
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
            // RUST-004: bind to the OBSERVED outbound tx hash + consume inflow.
            let expected_outbound_hash =
                observed_usdt_outbound_hash(&self.thor, xrp_inbound_hash, index_token)
                    .await?
                    .ok_or_else(|| RedemptionCrossCheckError::ThorNotReady {
                        reason: "no observed ETH.USDT outbound hash in tx/details yet".to_string(),
                    })?;
            let floor = thor_1e6.saturating_sub(self.tolerance_1e6);
            let arrival = confirm_erc20_arrival(
                &self.erc20,
                &self.store,
                self.usdt_token,
                index_token,
                floor,
                self.min_confirmations,
                &InflowBinding {
                    redemption_id,
                    leg_index,
                    expected_outbound_hash,
                },
            )
            .await?
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
                xrp_inbound_hash,
                onchain_usdt_1e6 = arrival.value,
                "xrp redemption cross-check OK"
            );
            // Attest the ON-CHAIN observed value, not THORChain's figure.
            Ok(arrival.value)
        }
    }

    /// Production refund policy: THORChain slip-refunded XRP to our
    /// multisig (`REFUND:<hash>` XRP outbound) and the drops actually
    /// returned FROM the live Asgard vault. Disambiguated from a delivery
    /// ONLY by the USDT-outbound mutual exclusion + the `REFUND:` memo —
    /// never by time. The on-chain value is `delivered_amount`, not
    /// `Amount` (partial-payment defence).
    pub struct ThorXrpRefundPolicy<C: XrpChainClient> {
        thor: ThorClient,
        xrp: C,
        multisig_address: String,
        min_confirmations: u32,
        tolerance_drops: u128,
        lookback_ledgers: u64,
    }

    impl<C: XrpChainClient> std::fmt::Debug for ThorXrpRefundPolicy<C> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ThorXrpRefundPolicy")
                .field("multisig_address", &self.multisig_address)
                .field("min_confirmations", &self.min_confirmations)
                .field("tolerance_drops", &self.tolerance_drops)
                .finish_non_exhaustive()
        }
    }

    impl<C: XrpChainClient> ThorXrpRefundPolicy<C> {
        #[must_use]
        pub fn new(
            thor: ThorClient,
            xrp: C,
            multisig_address: String,
            min_confirmations: u32,
            tolerance_drops: u128,
            lookback_ledgers: u64,
        ) -> Self {
            Self {
                thor,
                xrp,
                multisig_address,
                min_confirmations,
                tolerance_drops,
                lookback_ledgers,
            }
        }
    }

    #[async_trait]
    impl<C: XrpChainClient> RefundCrossCheck for ThorXrpRefundPolicy<C> {
        async fn verify(&self, xrp_inbound_hash: &str) -> Result<u64, RefundCrossCheckError> {
            let resp = self.thor.tx_status(xrp_inbound_hash).await?;
            if resp.observed_tx.status != "done" {
                return Err(RefundCrossCheckError::ThorNotReady {
                    reason: format!("observed_tx.status = {}", resp.observed_tx.status),
                });
            }
            // Mutual-exclusion: a USDT delivery means use the delivery path.
            if resp
                .actions
                .iter()
                .any(|a| a.chain == "ETH" && a.coin.asset.to_uppercase().starts_with("ETH.USDT"))
            {
                return Err(RefundCrossCheckError::DeliveredInstead);
            }
            let action = resp
                .actions
                .iter()
                .find(|a| {
                    a.chain == XRP_CHAIN
                        && a.to_address == self.multisig_address
                        && a.memo.to_uppercase().starts_with("REFUND:")
                        && a.coin.asset.to_uppercase() == XRP_ASSET
                })
                .ok_or_else(|| RefundCrossCheckError::ThorNotReady {
                    reason: "no XRP REFUND outbound to our multisig yet".to_string(),
                })?;
            let thor_1e8: u128 =
                action
                    .coin
                    .amount
                    .parse()
                    .map_err(|e| RefundCrossCheckError::ThorNotReady {
                        reason: format!("non-integer refund amount '{}': {e}", action.coin.amount),
                    })?;
            let thor_drops = thor_1e8 / THOR_TO_XRP_SCALE;

            // Resolve the live Asgard vault — the refund MUST originate
            // there (sender binding). Refuse while XRP trading is halted.
            let vault = self.thor.vault_for_chain(XRP_CHAIN).await?.ok_or_else(|| {
                RefundCrossCheckError::ThorNotReady {
                    reason: "no XRP inbound address from THORChain".to_string(),
                }
            })?;
            if vault.halted || vault.chain_trading_paused || vault.global_trading_paused {
                return Err(RefundCrossCheckError::ThorNotReady {
                    reason: "XRP trading halted on THORChain".to_string(),
                });
            }

            let floor = thor_drops.saturating_sub(self.tolerance_drops);
            let observed = find_xrp_arrival(
                &self.xrp,
                &self.multisig_address,
                &vault.address,
                floor,
                self.min_confirmations,
                self.lookback_ledgers,
            )
            .await
            .map_err(|e| RefundCrossCheckError::ThorNotReady {
                reason: format!("xrp arrival lookup failed: {e}"),
            })?
            .ok_or(RefundCrossCheckError::BtcNotReady {
                // Variant is family-shared smallest-unit; "sats" naming is
                // historical (a v2 rename), the value is drops here.
                need_sats: u64::try_from(thor_drops).unwrap_or(u64::MAX),
                confs: self.min_confirmations,
            })?;
            if observed.abs_diff(thor_drops) > self.tolerance_drops {
                return Err(RefundCrossCheckError::AmountMismatch {
                    thor_sats: u64::try_from(thor_drops).unwrap_or(u64::MAX),
                    utxo_sats: u64::try_from(observed).unwrap_or(u64::MAX),
                });
            }
            warn!(
                xrp_inbound_hash,
                refund_drops = observed,
                asgard = %vault.address,
                "xrp refund cross-check OK"
            );
            Ok(u64::try_from(observed).unwrap_or(u64::MAX))
        }
    }

    /// First validated `Payment` to `multisig` with
    /// `sender == expected_sender`, `delivered_drops >= min_value`, and at
    /// least `min_confs` inclusion depth at the validated tip. `None` =
    /// not yet observed (the signer polls again, never attests). The value
    /// is `delivered_amount` (the `chain-xrp` parser never reads `Amount`).
    async fn find_xrp_arrival<C: XrpChainClient>(
        xrp: &C,
        multisig: &str,
        expected_sender: &str,
        min_value: u128,
        min_confs: u32,
        lookback_ledgers: u64,
    ) -> Result<Option<u128>, XrpChainError> {
        let tip = xrp.latest_validated_ledger().await?;
        let min_ledger = tip.saturating_sub(lookback_ledgers);
        let transfers = xrp.transfers_to(multisig, min_ledger).await?;
        for t in transfers {
            let confs = tip.saturating_sub(t.ledger_index).saturating_add(1);
            if t.sender == expected_sender
                && t.delivered_drops >= min_value
                && confs >= u64::from(min_confs)
            {
                return Ok(Some(t.delivered_drops));
            }
        }
        Ok(None)
    }

    #[cfg(test)]
    mod tests {
        use super::super::{Erc20Arrival, Erc20ArrivalClient, Erc20Error};
        use super::{
            RedemptionCrossCheck, RedemptionCrossCheckError, RefundCrossCheck,
            RefundCrossCheckError, ThorXrpRefundPolicy, ThorXrpToUsdtPolicy,
        };
        use alloy_primitives::{Address as EthAddress, B256};
        use std::future::ready;
        use std::sync::Arc;
        use xindex_chain_thor::ThorClient;
        use xindex_chain_xrp::{
            XrpAccount, XrpChainClient, XrpChainError, XrpSubmitOutcome, XrpTransfer,
        };
        use xindex_shared::chain_registry::ChainId;
        use xindex_shared::consumed_inflow::AnyConsumedInflow;

        const INDEX_TOKEN: EthAddress = EthAddress::new([0x11; 20]);
        const USDT: EthAddress = EthAddress::new([0x22; 20]);
        const MULTISIG: &str = "rVaultMultisig00000000000000000000";
        const ASGARD: &str = "rAsgardVault000000000000000000000";

        /// RUST-004: the OBSERVED ETH outbound hash the delivery tests bind to.
        fn out_hash() -> B256 {
            B256::repeat_byte(0xAB)
        }
        /// A test `redemptionId`.
        fn rid() -> B256 {
            B256::repeat_byte(0xD1)
        }
        /// An [`Erc20Arrival`] carrying the bound outbound hash + log 0.
        fn arrival(value: u128, confirmations: u32) -> Erc20Arrival {
            Erc20Arrival {
                value,
                confirmations,
                transaction_hash: out_hash(),
                log_index: 0,
            }
        }
        /// Fresh in-memory consumed-inflow ledger.
        async fn mem_store() -> Arc<AnyConsumedInflow> {
            Arc::new(
                AnyConsumedInflow::connect(None)
                    .await
                    .unwrap_or_else(|e| unreachable!("mem: {e}")),
            )
        }
        /// Mock `tx/details` with an observed ETH `out_tx` to `eth_to` carrying
        /// [`out_hash`] (RUST-004 1:1 inflow bind).
        async fn mount_tx_details(server: &wiremock::MockServer, hash: &str, eth_to: EthAddress) {
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path(format!(
                    "/thorchain/tx/details/{hash}"
                )))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({
                        "out_txs": [{ "id": "AB".repeat(32), "chain": "ETH",
                            "to_address": format!("{eth_to:#x}"),
                            "coins": [{"asset":"ETH.USDT-0XDAC","amount":"100000000"}] }]
                    }),
                ))
                .mount(server)
                .await;
        }

        #[derive(Default)]
        struct StubErc20 {
            arrivals: Vec<Erc20Arrival>,
        }
        impl Erc20ArrivalClient for StubErc20 {
            fn transfers_to(
                &self,
                _token: EthAddress,
                _to: EthAddress,
            ) -> Result<Vec<Erc20Arrival>, Erc20Error> {
                Ok(self.arrivals.clone())
            }
        }

        struct StubXrp {
            tip: u64,
            transfers: Vec<XrpTransfer>,
        }
        impl XrpChainClient for StubXrp {
            fn chain(&self) -> ChainId {
                ChainId::Xrp
            }
            fn account_info(
                &self,
                _address: &str,
            ) -> impl std::future::Future<Output = Result<XrpAccount, XrpChainError>> + Send
            {
                ready(Ok(XrpAccount { sequence: 0 }))
            }
            fn ledger_current(
                &self,
            ) -> impl std::future::Future<Output = Result<u64, XrpChainError>> + Send {
                ready(Ok(self.tip))
            }
            fn latest_validated_ledger(
                &self,
            ) -> impl std::future::Future<Output = Result<u64, XrpChainError>> + Send {
                ready(Ok(self.tip))
            }
            fn transfers_to(
                &self,
                _destination: &str,
                min_ledger: u64,
            ) -> impl std::future::Future<Output = Result<Vec<XrpTransfer>, XrpChainError>> + Send
            {
                let v: Vec<XrpTransfer> = self
                    .transfers
                    .iter()
                    .filter(|t| t.ledger_index >= min_ledger)
                    .cloned()
                    .collect();
                ready(Ok(v))
            }
            fn submit_tx_blob(
                &self,
                _tx_blob: &[u8],
            ) -> impl std::future::Future<Output = Result<XrpSubmitOutcome, XrpChainError>> + Send
            {
                ready(Err(XrpChainError::Rpc("not used in tests".to_string())))
            }
        }

        fn transfer(sender: &str, drops: u128, ledger: u64) -> XrpTransfer {
            XrpTransfer {
                ledger_index: ledger,
                txhash: "XRPTX".to_string(),
                sender: sender.to_string(),
                destination: MULTISIG.to_string(),
                delivered_drops: drops,
            }
        }

        async fn mount_tx(server: &wiremock::MockServer, hash: &str, actions: serde_json::Value) {
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path(format!("/thorchain/tx/{hash}")))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({
                        "observed_tx": {
                            "tx": { "id": hash, "chain": "XRP", "from_address": "rUser",
                                    "to_address": ASGARD, "coins": [], "memo": "" },
                            "status": "done"
                        },
                        "actions": actions
                    }),
                ))
                .mount(server)
                .await;
        }

        async fn mount_inbound(server: &wiremock::MockServer, halted: bool) {
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/thorchain/inbound_addresses"))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                    serde_json::json!([{
                        "chain": "XRP", "pub_key": "thorpub1addwnpepq", "address": ASGARD,
                        "halted": halted,
                        "global_trading_paused": false,
                        "chain_trading_paused": false,
                        "chain_lp_actions_paused": false
                    }]),
                ))
                .mount(server)
                .await;
        }

        fn refund_action() -> serde_json::Value {
            // 5 XRP refund: THORChain 1e8 = 500_000_000 → 5_000_000 drops.
            serde_json::json!([{ "chain": "XRP", "to_address": MULTISIG,
                "coin": {"asset": "XRP.XRP", "amount": "500000000"},
                "memo": "REFUND:xrp-in", "max_gas": [] }])
        }

        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn refund_ok_when_drops_return_from_asgard() {
            let server = wiremock::MockServer::start().await;
            mount_tx(&server, "xrp-in", refund_action()).await;
            mount_inbound(&server, false).await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let xrp = StubXrp {
                tip: 100,
                transfers: vec![transfer(ASGARD, 5_000_000, 100)],
            };
            let policy = ThorXrpRefundPolicy::new(thor, xrp, MULTISIG.to_string(), 1, 0, 1000);
            let out = policy.verify("xrp-in").await.expect("refund ok");
            assert_eq!(out, 5_000_000);
        }

        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn refund_rejects_wrong_sender() {
            let server = wiremock::MockServer::start().await;
            mount_tx(&server, "xrp-in", refund_action()).await;
            mount_inbound(&server, false).await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            // Exact drops arrive — but NOT from the Asgard vault.
            let xrp = StubXrp {
                tip: 100,
                transfers: vec![transfer("rAttacker00000000000000000000000", 5_000_000, 100)],
            };
            let policy = ThorXrpRefundPolicy::new(thor, xrp, MULTISIG.to_string(), 1, 0, 1000);
            let err = policy.verify("xrp-in").await.expect_err("must reject");
            assert!(
                matches!(err, RefundCrossCheckError::BtcNotReady { .. }),
                "got {err:?}"
            );
        }

        /// SECURITY: a `tfPartialPayment` that delivered only 1 drop (the
        /// `delivered_drops` the parser surfaced) does NOT meet the 5 XRP
        /// floor — even though a THORChain `Amount` of 5 XRP was claimed.
        /// The cross-check refuses (the partial-payment defence end-to-end).
        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn refund_rejects_partial_payment_under_floor() {
            let server = wiremock::MockServer::start().await;
            mount_tx(&server, "xrp-in", refund_action()).await;
            mount_inbound(&server, false).await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            // From the right vault, but only 1 drop actually delivered.
            let xrp = StubXrp {
                tip: 100,
                transfers: vec![transfer(ASGARD, 1, 100)],
            };
            let policy = ThorXrpRefundPolicy::new(thor, xrp, MULTISIG.to_string(), 1, 0, 1000);
            let err = policy.verify("xrp-in").await.expect_err("must reject");
            assert!(
                matches!(err, RefundCrossCheckError::BtcNotReady { .. }),
                "got {err:?}"
            );
        }

        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn refund_rejects_when_xrp_halted() {
            let server = wiremock::MockServer::start().await;
            mount_tx(&server, "xrp-in", refund_action()).await;
            mount_inbound(&server, true).await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let xrp = StubXrp {
                tip: 100,
                transfers: vec![transfer(ASGARD, 5_000_000, 100)],
            };
            let policy = ThorXrpRefundPolicy::new(thor, xrp, MULTISIG.to_string(), 1, 0, 1000);
            let err = policy.verify("xrp-in").await.expect_err("must reject");
            assert!(
                matches!(err, RefundCrossCheckError::ThorNotReady { .. }),
                "got {err:?}"
            );
        }

        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn delivery_ok_when_usdt_lands() {
            let server = wiremock::MockServer::start().await;
            let want = format!("{INDEX_TOKEN:#x}").to_lowercase();
            mount_tx(
                &server,
                "xrp-in",
                serde_json::json!([{ "chain": "ETH", "to_address": want,
                    "coin": {"asset": "ETH.USDT", "amount": "70000000"}, "memo": "", "max_gas": [] }]),
            )
            .await;
            mount_tx_details(&server, "xrp-in", INDEX_TOKEN).await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let erc20 = StubErc20 {
                arrivals: vec![arrival(700_000, 5)],
            };
            let policy = ThorXrpToUsdtPolicy::new(thor, erc20, USDT, 3, 0, mem_store().await);
            let out = policy
                .verify("xrp-in", INDEX_TOKEN, rid(), 0)
                .await
                .expect("delivery ok");
            assert_eq!(out, 700_000);
        }

        #[tokio::test]
        #[expect(clippy::expect_used, reason = "test code")]
        async fn delivery_rejects_when_refunded_instead() {
            let server = wiremock::MockServer::start().await;
            mount_tx(&server, "xrp-in", refund_action()).await;
            let thor = ThorClient::with_base_url(server.uri()).expect("thor");
            let policy =
                ThorXrpToUsdtPolicy::new(thor, StubErc20::default(), USDT, 3, 0, mem_store().await);
            let err = policy
                .verify("xrp-in", INDEX_TOKEN, rid(), 0)
                .await
                .expect_err("must reject");
            assert!(
                matches!(err, RedemptionCrossCheckError::RefundedInstead),
                "got {err:?}"
            );
        }
    }
}
