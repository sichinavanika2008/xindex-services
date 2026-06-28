//! EVM redeem leg under Cobo MPC custody (`DL-CUSTODY-COBO-1`).
//!
//! The Cobo replacement for the Safe + cosigner-fleet flow ([`crate::evm_redeem`]).
//! Under Cobo MPC the EVM custody key is a single-sig MPC address, so a redeem
//! leg is a single contract-call to the THORChain Router — no Safe, no k-of-n
//! aggregation, no execTransaction wrapper. The flow:
//!
//! 1. Build the `Router.depositWithExpiry(vault, address(0), amount, memo, expiry)`
//!    calldata (the same ABI the callback's binder re-derives).
//! 2. Store the prepared spend in the SHARED prepare store keyed by the Cobo
//!    `request_id`, so the callback can bind it (`decide_evm_deposit`).
//! 3. Submit a BuildOnly contract-call to Cobo.
//! 4. `sign_and_broadcast` — the TSS Node signs HERE, firing our callback;
//!    APPROVE iff the spend matches the k-of-n RIC.
//! 5. Poll to confirmation.
//!
//! PROVISIONAL until the `api.dev.cobo.com` dev-env (W3): the RECONCILE markers
//! (Cobo chain-id strings, the decimal `value` units, status names) +
//! `docs/runbooks/cobo-btc-gate.md`.

#![expect(
    clippy::doc_markdown,
    reason = "module-level: many Cobo / THORChain / depositWithExpiry / \
              TransactionStatus / request_id identifiers — per-identifier \
              backticks add noise without aiding parsing"
)]

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolCall;
use thiserror::Error;
use xindex_cobo_client::types::{
    ContractCallDestination, ContractCallParams, ContractCallSource, TransactionDetail,
    TransactionStatus,
};
use xindex_cobo_client::CoboApi;
use xindex_custody_core::prepare::{EvmPrepared, PrepareStore, PreparedSpend};
use xindex_shared::chain_registry::ChainId;
use xindex_shared::thorchain_router::depositWithExpiryCall;

use crate::evm_redeem::EvmRedeemTask;

/// Errors surfaced by the Cobo EVM redeem executor.
#[derive(Debug, Error)]
pub enum CoboEvmError {
    /// Task's chain is not in the EVM custody family / mismatched executor.
    #[error("ChainId {0:?} is not the EVM chain this executor serves")]
    NotEvmChain(ChainId),
    /// THORChain Router address not registered for this chain.
    #[error("no THORChain Router address registered for chain {0:?}")]
    NoRouterAddress(ChainId),
    /// No Cobo chain-id string mapping for this chain.
    #[error("no Cobo chain-id mapping for chain {0:?}")]
    NoCoboChainId(ChainId),
    /// Failed to persist the prepared spend (the callback would then have no
    /// context and fail-close, so we abort BEFORE submitting to Cobo).
    #[error("prepare store: {0}")]
    Prepare(String),
    /// A Cobo API call failed.
    #[error("cobo api: {0}")]
    Cobo(String),
    /// Polling exhausted before the transaction reached `want`.
    #[error("transaction {id} did not reach {want} (last status {got:?}) after polling")]
    PollTimeout {
        /// Cobo transaction id.
        id: String,
        /// The status we were waiting for.
        want: &'static str,
        /// The last status observed.
        got: TransactionStatus,
    },
    /// The transaction reached a terminal failure (Failed / Rejected — e.g. a
    /// callback REJECT) before `want`.
    #[error("transaction {id} terminated as {got:?} before {want}")]
    Terminated {
        /// Cobo transaction id.
        id: String,
        /// The status we were waiting for.
        want: &'static str,
        /// The terminal status observed.
        got: TransactionStatus,
    },
}

/// Static per-executor configuration. One executor per Cobo MPC wallet / chain.
#[derive(Debug, Clone)]
pub struct CoboEvmRedeemConfig {
    /// The EVM chain this executor serves.
    pub chain: ChainId,
    /// Cobo MPC wallet id (org-controlled) to spend from.
    pub wallet_id: String,
    /// Our Cobo MPC address on `chain` (the contract-call source).
    pub mpc_address: Address,
    /// THORChain Asgard vault on this chain (rotates; the binary refreshes
    /// from the inbound-addresses registry before each leg).
    pub vault: Address,
    /// Seconds-from-now `depositWithExpiry` expiry (THORChain rejects < 60 min;
    /// 2 hours is the default).
    pub expiry_offset_secs: u64,
    /// Delay between status polls.
    pub poll_interval: Duration,
    /// Max status polls before [`CoboEvmError::PollTimeout`].
    pub poll_max_attempts: u32,
}

/// Cobo EVM redeem executor. Submission + signing happen inside Cobo, gated by
/// our callback; this orchestrates the build → submit → sign → confirm flow.
pub struct CoboEvmRedeemExecutor<C, P> {
    config: CoboEvmRedeemConfig,
    cobo: Arc<C>,
    prepare: Arc<P>,
}

impl<C, P> std::fmt::Debug for CoboEvmRedeemExecutor<C, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoboEvmRedeemExecutor")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// The result of a completed Cobo EVM redeem leg.
#[derive(Debug, Clone)]
pub struct CoboEvmRedeemOutcome {
    /// Destination chain.
    pub chain: ChainId,
    /// Originating dispatch id (broadcast registry key).
    pub dispatch_id: B256,
    /// Originating redemption id (attestation correlation).
    pub redemption_id: B256,
    /// Cobo's transaction id.
    pub cobo_transaction_id: String,
    /// On-chain transaction hash, once confirmed.
    pub transaction_hash: Option<String>,
}

impl<C: CoboApi, P: PrepareStore> CoboEvmRedeemExecutor<C, P> {
    /// Construct.
    #[must_use]
    pub fn new(config: CoboEvmRedeemConfig, cobo: Arc<C>, prepare: Arc<P>) -> Self {
        Self {
            config,
            cobo,
            prepare,
        }
    }

    /// Borrow the configuration.
    #[must_use]
    pub fn config(&self) -> &CoboEvmRedeemConfig {
        &self.config
    }

    /// Execute one EVM redeem leg through Cobo: prepare → contract-call
    /// (BuildOnly) → sign-and-broadcast → poll to confirmation.
    ///
    /// # Errors
    /// Any [`CoboEvmError`] variant.
    pub async fn execute_leg(
        &self,
        task: &EvmRedeemTask,
    ) -> Result<CoboEvmRedeemOutcome, CoboEvmError> {
        if task.chain != self.config.chain {
            return Err(CoboEvmError::NotEvmChain(task.chain));
        }
        let router = task
            .chain
            .thorchain_router_address()
            .ok_or(CoboEvmError::NoRouterAddress(task.chain))?;
        let cobo_chain =
            cobo_chain_id(task.chain).ok_or(CoboEvmError::NoCoboChainId(task.chain))?;

        let expiry = U256::from(now_secs().saturating_add(self.config.expiry_offset_secs));
        let calldata = depositWithExpiryCall {
            vault: self.config.vault,
            asset: Address::ZERO,
            amount: task.amount_wei,
            memo: task.memo.clone(),
            expiry,
        }
        .abi_encode();

        // The Cobo request_id is our correlation id: the prepare-store key the
        // callback looks up AND Cobo's own idempotency key. A re-drive of the
        // same RIC needs a fresh request_id → a fresh spend_identity → the
        // decision core's one-shot rejects it.
        let request_id = format!("{:#x}", task.dispatch_id);

        // Persist the prepared spend BEFORE submitting — the callback binds
        // against this; a missing context fail-closes the spend.
        self.prepare
            .put(
                request_id.clone(),
                PreparedSpend::Evm(EvmPrepared {
                    chain: task.chain,
                    to: router,
                    value: task.amount_wei,
                    data: calldata.clone(),
                    ric: task.intent_proof.clone(),
                    spend_identity: request_id.clone().into_bytes(),
                }),
            )
            .await
            .map_err(|e| CoboEvmError::Prepare(e.to_string()))?;

        let params = ContractCallParams {
            request_id: request_id.clone(),
            chain_id: cobo_chain.to_string(),
            source: ContractCallSource {
                source_type: "Org-Controlled".to_string(),
                wallet_id: self.config.wallet_id.clone(),
                address: format!("{:#x}", self.config.mpc_address),
            },
            destination: ContractCallDestination {
                destination_type: "EVM_Contract".to_string(),
                address: format!("{router:#x}"),
                calldata: format!("0x{}", alloy_primitives::hex::encode(&calldata)),
                // RECONCILE AT DEV-ENV: decimal coin units, exact-amount risk.
                value: Some(wei_to_decimal(task.amount_wei)),
            },
            transaction_process_type: "BuildOnly".to_string(),
        };

        let created = self
            .cobo
            .contract_call(&params)
            .await
            .map_err(|e| CoboEvmError::Cobo(e.to_string()))?;
        let tx_id = created.transaction_id;

        // Wait for the BuildOnly tx to be built (not yet signed).
        self.poll_until(&tx_id, "Built", TransactionStatus::is_built)
            .await?;

        // Sign + broadcast: the TSS Node signs here, firing our callback.
        self.cobo
            .sign_and_broadcast(&tx_id)
            .await
            .map_err(|e| CoboEvmError::Cobo(e.to_string()))?;

        // Wait for on-chain confirmation.
        let detail = self
            .poll_until(&tx_id, "Completed", TransactionStatus::is_completed)
            .await?;

        Ok(CoboEvmRedeemOutcome {
            chain: task.chain,
            dispatch_id: task.dispatch_id,
            redemption_id: task.redemption_id,
            cobo_transaction_id: tx_id,
            transaction_hash: detail.transaction_hash,
        })
    }

    /// Poll `get_transaction` until `pred` holds (success) or the tx terminates
    /// otherwise / polling exhausts.
    async fn poll_until(
        &self,
        tx_id: &str,
        want: &'static str,
        pred: fn(TransactionStatus) -> bool,
    ) -> Result<TransactionDetail, CoboEvmError> {
        let mut last = TransactionStatus::Unknown;
        for _ in 0..self.config.poll_max_attempts {
            let detail = self
                .cobo
                .get_transaction(tx_id)
                .await
                .map_err(|e| CoboEvmError::Cobo(e.to_string()))?;
            last = detail.status;
            if pred(detail.status) {
                return Ok(detail);
            }
            if detail.status.is_terminal() {
                return Err(CoboEvmError::Terminated {
                    id: tx_id.to_string(),
                    want,
                    got: last,
                });
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
        Err(CoboEvmError::PollTimeout {
            id: tx_id.to_string(),
            want,
            got: last,
        })
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Cobo's chain-id string for an EVM chain. RECONCILE AT DEV-ENV: confirm the
/// exact strings against Cobo's "List enabled chains".
fn cobo_chain_id(chain: ChainId) -> Option<&'static str> {
    match chain {
        ChainId::Eth => Some("ETH"),
        ChainId::Bsc => Some("BSC"),
        ChainId::Avax => Some("AVAX"),
        ChainId::Base => Some("BASE"),
        ChainId::Pol => Some("POL"),
        ChainId::Btc
        | ChainId::Ltc
        | ChainId::Bch
        | ChainId::Doge
        | ChainId::Zec
        | ChainId::Gaia
        | ChainId::Noble
        | ChainId::Xrp
        | ChainId::Sol
        | ChainId::Tron => None,
    }
}

/// Format a wei amount as an exact decimal coin string (18 decimals), e.g.
/// `1500000000000000000` → `"1.5"`. RECONCILE AT DEV-ENV: confirm Cobo's
/// decimal→wei conversion is exact so `msg.value` equals the certified amount.
fn wei_to_decimal(wei: U256) -> String {
    const DECIMALS: usize = 18;
    let digits = wei.to_string();
    let (int_part, frac_part) = if digits.len() > DECIMALS {
        let split = digits.len() - DECIMALS;
        (digits[..split].to_string(), digits[split..].to_string())
    } else {
        ("0".to_string(), format!("{digits:0>DECIMALS$}"))
    };
    let frac_trimmed = frac_part.trim_end_matches('0');
    if frac_trimmed.is_empty() {
        int_part
    } else {
        format!("{int_part}.{frac_trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use tokio::sync::Mutex as TokioMutex;
    use xindex_cobo_client::types::CreatedTransaction;
    use xindex_cobo_client::CoboError;
    use xindex_custody_core::prepare::InMemoryPrepareStore;

    /// Stub Cobo API: `contract_call` returns Built; `get_transaction` pops the
    /// next scripted status; `sign_and_broadcast` is a no-op success.
    struct StubCobo {
        statuses: TokioMutex<VecDeque<TransactionStatus>>,
        hash: Option<String>,
    }

    impl StubCobo {
        fn new(statuses: Vec<TransactionStatus>, hash: Option<&str>) -> Self {
            Self {
                statuses: TokioMutex::new(statuses.into()),
                hash: hash.map(str::to_string),
            }
        }
    }

    impl CoboApi for StubCobo {
        async fn contract_call(
            &self,
            params: &ContractCallParams,
        ) -> Result<CreatedTransaction, CoboError> {
            Ok(CreatedTransaction {
                request_id: params.request_id.clone(),
                transaction_id: "tx-1".to_string(),
                status: TransactionStatus::Built,
            })
        }
        async fn sign_and_broadcast(
            &self,
            transaction_id: &str,
        ) -> Result<CreatedTransaction, CoboError> {
            Ok(CreatedTransaction {
                request_id: "r".to_string(),
                transaction_id: transaction_id.to_string(),
                status: TransactionStatus::Broadcasting,
            })
        }
        async fn get_transaction(
            &self,
            transaction_id: &str,
        ) -> Result<TransactionDetail, CoboError> {
            let status = self
                .statuses
                .lock()
                .await
                .pop_front()
                .unwrap_or(TransactionStatus::Unknown);
            Ok(TransactionDetail {
                transaction_id: transaction_id.to_string(),
                request_id: "r".to_string(),
                status,
                transaction_hash: self.hash.clone(),
            })
        }
    }

    fn config() -> CoboEvmRedeemConfig {
        CoboEvmRedeemConfig {
            chain: ChainId::Eth,
            wallet_id: "wallet-1".to_string(),
            mpc_address: Address::repeat_byte(0xa0),
            vault: Address::repeat_byte(0x11),
            expiry_offset_secs: 7200,
            poll_interval: Duration::ZERO,
            poll_max_attempts: 5,
        }
    }

    fn task(chain: ChainId) -> EvmRedeemTask {
        EvmRedeemTask {
            dispatch_id: B256::repeat_byte(0xd1),
            redemption_id: B256::repeat_byte(0xd2),
            chain,
            memo: "=:ETH.USDT:0xrecipient:990000".to_string(),
            amount_wei: U256::from(1_500_000_000_000_000_000u64),
            intent_proof: None,
        }
    }

    #[test]
    fn wei_to_decimal_is_exact() {
        assert_eq!(
            wei_to_decimal(U256::from(1_000_000_000_000_000_000u64)),
            "1"
        );
        assert_eq!(
            wei_to_decimal(U256::from(1_500_000_000_000_000_000u64)),
            "1.5"
        );
        assert_eq!(wei_to_decimal(U256::from(123u64)), "0.000000000000000123");
        assert_eq!(wei_to_decimal(U256::ZERO), "0");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn happy_path_prepares_then_completes() {
        let prepare = Arc::new(InMemoryPrepareStore::new());
        // Built (build-poll), then Completed (confirm-poll).
        let cobo = Arc::new(StubCobo::new(
            vec![TransactionStatus::Built, TransactionStatus::Completed],
            Some("0xhash"),
        ));
        let exec = CoboEvmRedeemExecutor::new(config(), cobo, Arc::clone(&prepare));
        let outcome = exec.execute_leg(&task(ChainId::Eth)).await.expect("leg");
        assert_eq!(outcome.cobo_transaction_id, "tx-1");
        assert_eq!(outcome.transaction_hash.as_deref(), Some("0xhash"));
        // The prepared spend was stored under the dispatch-id request id.
        let request_id = format!("{:#x}", outcome.dispatch_id);
        let stored = prepare.get(&request_id).await.expect("get");
        assert!(matches!(stored, Some(PreparedSpend::Evm(_))));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rejected_by_callback_surfaces_terminated() {
        let prepare = Arc::new(InMemoryPrepareStore::new());
        // Built, then Rejected (a callback REJECT marks the tx Rejected).
        let cobo = Arc::new(StubCobo::new(
            vec![TransactionStatus::Built, TransactionStatus::Rejected],
            None,
        ));
        let exec = CoboEvmRedeemExecutor::new(config(), cobo, prepare);
        let err = exec
            .execute_leg(&task(ChainId::Eth))
            .await
            .expect_err("rejected");
        assert!(matches!(
            err,
            CoboEvmError::Terminated {
                got: TransactionStatus::Rejected,
                ..
            }
        ));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn wrong_chain_rejected() {
        let prepare = Arc::new(InMemoryPrepareStore::new());
        let cobo = Arc::new(StubCobo::new(vec![], None));
        let exec = CoboEvmRedeemExecutor::new(config(), cobo, prepare);
        let err = exec
            .execute_leg(&task(ChainId::Bsc))
            .await
            .expect_err("wrong chain");
        assert!(matches!(err, CoboEvmError::NotEvmChain(ChainId::Bsc)));
    }
}
