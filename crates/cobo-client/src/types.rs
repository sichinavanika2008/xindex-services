//! Cobo v2 request/response types for the EVM contract-call path.
//!
//! Hand-rolled from Cobo's public docs + the Go/Python SDKs (no Rust SDK).
//! PROVISIONAL — reconcile field-by-field against `api.dev.cobo.com` (W3).

use serde::{Deserialize, Serialize};

/// `POST /v2/transactions/contract_call` body (`ContractCallParams`).
#[derive(Debug, Clone, Serialize)]
pub struct ContractCallParams {
    /// Idempotency key (also our `xindex-custody-node` prepare correlation id).
    pub request_id: String,
    /// Chain id string, e.g. `"ETH"`.
    pub chain_id: String,
    /// The MPC source wallet.
    pub source: ContractCallSource,
    /// The contract destination + calldata.
    pub destination: ContractCallDestination,
    /// `"BuildOnly"` (build, then `sign_and_broadcast`) or `"AutoProcess"`.
    pub transaction_process_type: String,
}

/// `MpcContractCallSource` — the org-controlled MPC wallet to spend from.
#[derive(Debug, Clone, Serialize)]
pub struct ContractCallSource {
    /// Discriminator, e.g. `"Org-Controlled"`.
    pub source_type: String,
    /// Cobo wallet id (UUID).
    pub wallet_id: String,
    /// The MPC address that calls the contract.
    pub address: String,
}

/// `EvmContractCallDestination` — the contract + calldata (+ optional native
/// value).
#[derive(Debug, Clone, Serialize)]
pub struct ContractCallDestination {
    /// Discriminator, e.g. `"EVM_Contract"`.
    pub destination_type: String,
    /// The contract address (the `THORChain` Router).
    pub address: String,
    /// Hex-encoded calldata (`Router.depositWithExpiry(...)`).
    pub calldata: String,
    /// Native coin amount as a DECIMAL string in coin units (e.g. `"1.5"`),
    /// NOT wei. RECONCILE AT DEV-ENV: confirm the decimal→wei conversion is
    /// exact so `msg.value` equals the certified amount.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// The tracking object returned by `contract_call` / `sign_and_broadcast`.
#[derive(Debug, Clone, Deserialize)]
pub struct CreatedTransaction {
    /// The request id echoed back.
    #[serde(default)]
    pub request_id: String,
    /// Cobo's transaction id (UUID) — used for `sign_and_broadcast` / polling.
    pub transaction_id: String,
    /// Current status.
    #[serde(default)]
    pub status: TransactionStatus,
}

/// `GET /v2/transactions/{id}` detail.
#[derive(Debug, Clone, Deserialize)]
pub struct TransactionDetail {
    /// Cobo's transaction id.
    pub transaction_id: String,
    /// The request id.
    #[serde(default)]
    pub request_id: String,
    /// Current status.
    pub status: TransactionStatus,
    /// On-chain transaction hash, once broadcast.
    #[serde(default)]
    pub transaction_hash: Option<String>,
}

/// Cobo transaction status. Unknown values map to [`TransactionStatus::Unknown`]
/// so a new server-side status never breaks deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
pub enum TransactionStatus {
    /// Accepted, not yet processed.
    Submitted,
    /// AML/compliance screening.
    PendingScreening,
    /// Awaiting org authorization.
    PendingAuthorization,
    /// Awaiting signature (the TSS Node is signing → our callback fires).
    PendingSignature,
    /// Built (a `BuildOnly` tx ready for `sign_and_broadcast`).
    Built,
    /// Broadcasting to the chain.
    Broadcasting,
    /// Broadcast, awaiting confirmations.
    Confirming,
    /// Confirmed on-chain.
    Completed,
    /// Terminally failed.
    Failed,
    /// Rejected (by policy / a callback REJECT).
    Rejected,
    /// Generic pending.
    Pending,
    /// Any status this client does not model.
    #[serde(other)]
    #[default]
    Unknown,
}

impl TransactionStatus {
    /// Confirmed on-chain.
    #[must_use]
    pub fn is_completed(self) -> bool {
        matches!(self, TransactionStatus::Completed)
    }

    /// Ready for `sign_and_broadcast`.
    #[must_use]
    pub fn is_built(self) -> bool {
        matches!(self, TransactionStatus::Built)
    }

    /// No further progress will happen (poll loops should stop).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TransactionStatus::Completed | TransactionStatus::Failed | TransactionStatus::Rejected
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn status_deserializes_known_and_unknown() {
        let completed: TransactionStatus = serde_json::from_str("\"Completed\"").expect("known");
        assert_eq!(completed, TransactionStatus::Completed);
        assert!(completed.is_completed());
        assert!(completed.is_terminal());

        let novel: TransactionStatus = serde_json::from_str("\"SomeNewStatus\"").expect("unknown");
        assert_eq!(novel, TransactionStatus::Unknown);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn contract_call_params_serializes_with_optional_value() {
        let p = ContractCallParams {
            request_id: "r1".to_string(),
            chain_id: "ETH".to_string(),
            source: ContractCallSource {
                source_type: "Org-Controlled".to_string(),
                wallet_id: "w1".to_string(),
                address: "0xabc".to_string(),
            },
            destination: ContractCallDestination {
                destination_type: "EVM_Contract".to_string(),
                address: "0xrouter".to_string(),
                calldata: "0xdead".to_string(),
                value: None,
            },
            transaction_process_type: "BuildOnly".to_string(),
        };
        let json = serde_json::to_string(&p).expect("serialize");
        assert!(json.contains("\"transaction_process_type\":\"BuildOnly\""));
        // value omitted when None.
        assert!(!json.contains("\"value\""));
    }
}
