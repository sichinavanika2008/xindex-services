//! Per-operator finalized settlement derivation and typed HSM release.
//!
//! The observer reads logical events from its durable finalized journal,
//! requires exact semantic agreement across three `THORNode` sources, validates
//! the proposed Bitcoin inbound transaction against the finalized dispatch,
//! performs independent destination-chain checks, persists an append-only
//! evidence envelope, and only then invokes its one local signer daemon.

use std::str::FromStr;
use std::sync::Arc;

use alloy_primitives::{Address as EthAddress, B256, U256};
use alloy_sol_types::Eip712Domain;
use bitcoin::{Address, Network, Txid};
use serde::Serialize;
use thiserror::Error;
use xindex_chain_thor::{
    InboundAddress, RawResponse, ThorClient, TxDetailsResponse, TxResponse, TxStatusResponse,
};
use xindex_chain_utxo::{EsploraClient, UtxoError, UtxoTransactionFacts};
use xindex_shared::consumed_inflow::AnyConsumedInflow;
use xindex_shared::eip712::{
    attestation, redemption_attestation, refund_attestation, streamed_settlement,
};
use xindex_shared::evidence::{EvidenceError, EvidenceStore};
use xindex_shared::native_inflow::AnyNativeInflow;
use xindex_shared::settlement_wire::{
    MintSettlementRequest, RedemptionSettlementRequest, SignedDeliverySettlement,
    SignedMintSettlement, SignedRefundSettlement, SignedStreamedSettlement,
};
use xindex_signer::crosscheck::{
    CrossCheckError, Erc20Error, StreamedSettlementCrossCheckError, ThorUtxoPolicy,
    ThorUtxoStreamedSettlementPolicy,
};
use xindex_signer::remote::RemoteHsmBackend;
use xindex_signer::{HsmBackend, SignerError};

use crate::erc20::{FinalizedErc20Observation, FinalizedRpcErc20LogClient};
use crate::finalized_observer::{
    FinalizedDispatchRecord, FinalizedMintRecord, FinalizedObserverError,
    SqliteFinalizedObserverStore,
};

/// Fixed launch parameters for one BTC settlement observer.
#[derive(Debug, Clone)]
pub struct BtcSettlementConfig {
    /// Safe public operator identifier used in evidence records.
    pub operator_id: String,
    /// Canonical `keccak256("BTC.BTC")` asset id.
    pub asset_id: B256,
    /// Adapter's native-token sentinel.
    pub target_token: EthAddress,
    /// Custody address receiving mint outbounds and refund outbounds.
    pub btc_custody_address: Address,
    /// Launch production network (Bitcoin mainnet).
    pub btc_network: Network,
    /// Independent Esplora-compatible endpoint.
    pub esplora_url: String,
    /// Bitcoin confirmation floor.
    pub btc_min_confirmations: u32,
    /// Maximum sat discrepancy accepted between THOR and Bitcoin.
    pub btc_tolerance_sats: u64,
    /// Canonical Ethereum USDT contract.
    pub usdt_token: EthAddress,
    /// Finalized Ethereum JSON-RPC endpoint.
    pub ethereum_rpc_url: String,
    /// Bounded finalized transfer lookback.
    pub ethereum_lookback_blocks: u64,
    /// Maximum USDT base-unit discrepancy.
    pub usdt_tolerance_1e6: u128,
}

/// Errors returned before any settlement response is released.
#[derive(Debug, Error)]
pub enum SettlementObserverError {
    /// Static construction error.
    #[error("invalid settlement observer configuration: {0}")]
    Configuration(String),
    /// Malformed/unexpected trigger.
    #[error("invalid settlement request: {0}")]
    BadRequest(String),
    /// Finalized logical event is not present.
    #[error("finalized settlement event not found")]
    NotFound,
    /// Independent sources have not reached a safe, agreed outcome.
    #[error("settlement not ready: {0}")]
    NotReady(String),
    /// Finalized journal failure.
    #[error("finalized journal: {0}")]
    Journal(#[from] FinalizedObserverError),
    /// Mint cross-check failure.
    #[error("mint cross-check: {0}")]
    Mint(#[from] CrossCheckError),
    /// Redemption cross-check failure.
    #[error("redemption cross-check: {0}")]
    Redemption(#[from] StreamedSettlementCrossCheckError),
    /// Evidence persistence failure.
    #[error("pre-sign evidence: {0}")]
    Evidence(#[from] EvidenceError),
    /// Independent Bitcoin query/decode failure.
    #[error("Bitcoin observation: {0}")]
    Bitcoin(#[from] UtxoError),
    /// Finalized ERC-20 query/decode failure.
    #[error("Ethereum settlement observation: {0}")]
    Ethereum(#[from] Erc20Error),
    /// Signer daemon/HSM refusal or transport failure.
    #[error("signer unavailable: {0}")]
    Signer(#[from] SignerError),
    /// Blocking worker failed.
    #[error("blocking worker failed")]
    Worker,
}

#[derive(Debug, Clone)]
struct ThorSource {
    id: String,
    client: ThorClient,
}

#[derive(Debug)]
struct AgreedThorTx {
    status: TxResponse,
    details: TxDetailsResponse,
    stages: Option<TxStatusResponse>,
    vault: InboundAddress,
    raw: Vec<ThorRawEvidence>,
}

#[derive(Debug)]
struct ThorSourceObservation {
    source_id: String,
    status: RawResponse<TxResponse>,
    details: RawResponse<TxDetailsResponse>,
    stages: Option<RawResponse<TxStatusResponse>>,
    vault: InboundAddress,
    inbound_body: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ThorRawEvidence {
    source_id: String,
    status_body: String,
    details_body: String,
    stages_body: Option<String>,
    inbound_body: String,
}

#[derive(Debug)]
struct RedemptionObservation {
    dispatch: FinalizedDispatchRecord,
    outcome: xindex_signer::crosscheck::StreamedOutcome,
    streaming: bool,
    evidence_hash: B256,
}

/// Concrete launch observer. One instance belongs to one independent
/// operator and one HSM signer identity.
pub struct BtcSettlementObserver {
    config: BtcSettlementConfig,
    store: SqliteFinalizedObserverStore,
    thor_sources: Vec<ThorSource>,
    mint_policy: ThorUtxoPolicy<EsploraClient>,
    redemption_policy: ThorUtxoStreamedSettlementPolicy<FinalizedRpcErc20LogClient, EsploraClient>,
    btc_evidence: EsploraClient,
    eth_evidence: FinalizedRpcErc20LogClient,
    signer: RemoteHsmBackend,
    domain: Eip712Domain,
    evidence: EvidenceStore,
}

impl std::fmt::Debug for BtcSettlementObserver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BtcSettlementObserver")
            .field("operator_id", &self.config.operator_id)
            .field("asset_id", &self.config.asset_id)
            .finish_non_exhaustive()
    }
}

impl BtcSettlementObserver {
    /// Build one operator observer with shared durable inflow ledgers.
    ///
    /// # Errors
    /// Fewer/more than three distinct THOR source ids or an unsafe zero
    /// launch parameter.
    #[expect(
        clippy::too_many_arguments,
        reason = "construction explicitly binds journal, three source clients, two ledgers, evidence, domain, and the operator-local signer"
    )]
    pub fn new(
        config: BtcSettlementConfig,
        store: SqliteFinalizedObserverStore,
        thor_sources: Vec<(String, ThorClient)>,
        signer: RemoteHsmBackend,
        domain: Eip712Domain,
        evidence: EvidenceStore,
        consumed_inflows: Arc<AnyConsumedInflow>,
        native_inflows: Arc<AnyNativeInflow>,
    ) -> Result<Self, SettlementObserverError> {
        let unique_ids: std::collections::HashSet<_> =
            thor_sources.iter().map(|(id, _)| id.as_str()).collect();
        if thor_sources.len() != 3
            || unique_ids.len() != 3
            || config.operator_id.is_empty()
            || config.asset_id == B256::ZERO
            || config.target_token == EthAddress::ZERO
            || config.btc_min_confirmations == 0
            || config.ethereum_lookback_blocks == 0
            || config.usdt_token == EthAddress::ZERO
        {
            return Err(SettlementObserverError::Configuration(
                "launch identities/source count/confirmation bounds are invalid".to_string(),
            ));
        }
        let primary = thor_sources[0].1.clone();
        let mint_policy = ThorUtxoPolicy::with_native_inflows(
            primary.clone(),
            EsploraClient::with_url(config.btc_network, &config.esplora_url),
            config.btc_custody_address.clone(),
            config.btc_min_confirmations,
            config.btc_tolerance_sats,
            Arc::clone(&native_inflows),
        );
        let redemption_policy = ThorUtxoStreamedSettlementPolicy::with_native_inflows(
            primary,
            FinalizedRpcErc20LogClient::new(
                &config.ethereum_rpc_url,
                config.ethereum_lookback_blocks,
            ),
            EsploraClient::with_url(config.btc_network, &config.esplora_url),
            config.usdt_token,
            config.btc_custody_address.clone(),
            config.btc_min_confirmations,
            config.usdt_tolerance_1e6,
            config.btc_tolerance_sats,
            consumed_inflows,
            native_inflows,
        );
        Ok(Self {
            btc_evidence: EsploraClient::with_url(config.btc_network, &config.esplora_url),
            eth_evidence: FinalizedRpcErc20LogClient::new(
                &config.ethereum_rpc_url,
                config.ethereum_lookback_blocks,
            ),
            config,
            store,
            thor_sources: thor_sources
                .into_iter()
                .map(|(id, client)| ThorSource { id, client })
                .collect(),
            mint_policy,
            redemption_policy,
            signer,
            domain,
            evidence,
        })
    }

    /// Observe, evidence, and sign one current mint slot.
    ///
    /// # Errors
    /// Any malformed request, missing finalized pair, source disagreement,
    /// cross-check failure, evidence failure, or signer refusal.
    pub async fn certify_mint(
        &self,
        request: &MintSettlementRequest,
        now: u64,
    ) -> Result<SignedMintSettlement, SettlementObserverError> {
        let intent_id = parse_b256("intent_id", &request.intent_id)?;
        let slot_index = parse_launch_index("slot_index", &request.slot_index)?;
        let record = self
            .store
            .mint(intent_id, slot_index)
            .await?
            .ok_or(SettlementObserverError::NotFound)?;
        self.validate_mint_record(&record)?;
        let inbound_hash = format!("{:x}", record.source_transaction_hash);
        let agreed = self.poll_thor(&inbound_hash, false).await?;
        validate_thor_inbound_id(&agreed.status, &inbound_hash)?;
        let amount = self
            .mint_policy
            .observe_settlement_from_snapshot(
                &inbound_hash,
                &agreed.status,
                &agreed.details,
                &agreed.vault,
                intent_id,
                slot_index,
            )
            .await?;
        let outbound = observed_btc_txid(
            &agreed.details,
            &self.config.btc_custody_address.to_string(),
            amount,
            self.config.btc_tolerance_sats,
        )?;
        let btc_facts = self.btc_evidence.transaction_facts(&outbound)?;
        let evidence_hash =
            self.persist_mint_evidence(&record, &agreed, &btc_facts, amount, now)?;
        let payload = attestation(intent_id, U256::from(slot_index), U256::from(amount));
        let signature = self.sign_mint(payload).await?;
        Ok(SignedMintSettlement {
            intent_id: format!("{intent_id:#x}"),
            slot_index: slot_index.to_string(),
            attested_amount: amount.to_string(),
            signer_address: format!("{:#x}", self.signer.signer_address()),
            signature: encode_signature(signature),
            evidence_hash: format!("{evidence_hash:#x}"),
            observed_at: now,
        })
    }

    /// Observe and sign a non-streaming delivery-only redemption outcome.
    ///
    /// # Errors
    /// Any validation/evidence/signer failure or a refund/streamed outcome.
    pub async fn certify_delivery(
        &self,
        request: &RedemptionSettlementRequest,
        now: u64,
    ) -> Result<SignedDeliverySettlement, SettlementObserverError> {
        let observed = self.observe_redemption(request, now).await?;
        if observed.streaming
            || observed.outcome.delivered_usdt_1e6 == 0
            || observed.outcome.refunded_sats != 0
        {
            return Err(SettlementObserverError::NotReady(
                "outcome is not non-streaming delivery-only".to_string(),
            ));
        }
        let payload = redemption_attestation(
            observed.dispatch.redemption_id,
            U256::from(observed.dispatch.leg_index),
            self.config.asset_id,
            U256::from(observed.outcome.delivered_usdt_1e6),
        );
        let signature = self.sign_delivery(payload).await?;
        Ok(SignedDeliverySettlement {
            redemption_id: format!("{:#x}", observed.dispatch.redemption_id),
            leg_index: observed.dispatch.leg_index.to_string(),
            asset_id: format!("{:#x}", self.config.asset_id),
            delivered_amount: observed.outcome.delivered_usdt_1e6.to_string(),
            signer_address: format!("{:#x}", self.signer.signer_address()),
            signature: encode_signature(signature),
            evidence_hash: format!("{:#x}", observed.evidence_hash),
            observed_at: now,
        })
    }

    /// Observe and sign a non-streaming refund-only redemption outcome.
    ///
    /// # Errors
    /// Any validation/evidence/signer failure or a delivery/streamed outcome.
    pub async fn certify_refund(
        &self,
        request: &RedemptionSettlementRequest,
        now: u64,
    ) -> Result<SignedRefundSettlement, SettlementObserverError> {
        let observed = self.observe_redemption(request, now).await?;
        if observed.streaming
            || observed.outcome.delivered_usdt_1e6 != 0
            || observed.outcome.refunded_sats == 0
        {
            return Err(SettlementObserverError::NotReady(
                "outcome is not non-streaming refund-only".to_string(),
            ));
        }
        let payload = refund_attestation(
            observed.dispatch.redemption_id,
            U256::from(observed.dispatch.leg_index),
            self.config.asset_id,
            U256::from(observed.outcome.refunded_sats),
        );
        let signature = self.sign_refund(payload).await?;
        Ok(SignedRefundSettlement {
            redemption_id: format!("{:#x}", observed.dispatch.redemption_id),
            leg_index: observed.dispatch.leg_index.to_string(),
            asset_id: format!("{:#x}", self.config.asset_id),
            refunded_amount: observed.outcome.refunded_sats.to_string(),
            signer_address: format!("{:#x}", self.signer.signer_address()),
            signature: encode_signature(signature),
            evidence_hash: format!("{:#x}", observed.evidence_hash),
            observed_at: now,
        })
    }

    /// Observe and sign a fully-finalized streamed redemption outcome.
    ///
    /// # Errors
    /// Any validation/evidence/signer failure or a non-streaming outcome.
    pub async fn certify_streamed(
        &self,
        request: &RedemptionSettlementRequest,
        now: u64,
    ) -> Result<SignedStreamedSettlement, SettlementObserverError> {
        let observed = self.observe_redemption(request, now).await?;
        if !observed.streaming
            || (observed.outcome.delivered_usdt_1e6 == 0 && observed.outcome.refunded_sats == 0)
        {
            return Err(SettlementObserverError::NotReady(
                "outcome is not a finalized streaming settlement".to_string(),
            ));
        }
        let payload = streamed_settlement(
            observed.dispatch.redemption_id,
            U256::from(observed.dispatch.leg_index),
            self.config.asset_id,
            U256::from(observed.outcome.delivered_usdt_1e6),
            U256::from(observed.outcome.refunded_sats),
        );
        let signature = self.sign_streamed(payload).await?;
        Ok(SignedStreamedSettlement {
            redemption_id: format!("{:#x}", observed.dispatch.redemption_id),
            leg_index: observed.dispatch.leg_index.to_string(),
            asset_id: format!("{:#x}", self.config.asset_id),
            delivered_usdt: observed.outcome.delivered_usdt_1e6.to_string(),
            refunded_native: observed.outcome.refunded_sats.to_string(),
            signer_address: format!("{:#x}", self.signer.signer_address()),
            signature: encode_signature(signature),
            evidence_hash: format!("{:#x}", observed.evidence_hash),
            observed_at: now,
        })
    }

    async fn observe_redemption(
        &self,
        request: &RedemptionSettlementRequest,
        now: u64,
    ) -> Result<RedemptionObservation, SettlementObserverError> {
        let redemption_id = parse_b256("redemption_id", &request.redemption_id)?;
        let leg_index = parse_launch_index("leg_index", &request.leg_index)?;
        let inbound_txid = parse_txid(&request.inbound_tx_hash)?;
        let dispatch = self
            .store
            .dispatch(redemption_id, leg_index)
            .await?
            .ok_or(SettlementObserverError::NotFound)?;
        self.validate_dispatch(&dispatch)?;
        let inbound_hash = inbound_txid.to_string();
        let agreed = self.poll_thor(&inbound_hash, true).await?;
        let stages = agreed
            .stages
            .as_ref()
            .ok_or_else(|| SettlementObserverError::NotReady("missing swap stages".to_string()))?;
        if !stages.is_swap_finalised() {
            return Err(SettlementObserverError::NotReady(
                "THORChain swap is not fully finalized".to_string(),
            ));
        }
        let streaming = stages
            .stages
            .swap_status
            .as_ref()
            .and_then(|status| status.streaming.as_ref())
            .is_some();
        let btc_facts = self.btc_evidence.transaction_facts(&inbound_txid)?;
        validate_redemption_inbound(
            &agreed.status,
            &agreed.vault,
            &dispatch,
            &self.config.btc_custody_address,
            self.config.btc_network,
            self.config.btc_min_confirmations,
            &btc_facts,
        )?;
        let eth_observation = self
            .eth_evidence
            .transfers_to_evidence(self.config.usdt_token, dispatch.facts.final_destination)?;
        let outcome = self
            .redemption_policy
            .verify_from_snapshot(
                &agreed.status,
                &agreed.details,
                &agreed.vault,
                &eth_observation.arrivals,
                &inbound_hash,
                dispatch.facts.final_destination,
                redemption_id,
                leg_index,
            )
            .await?;
        let refund_facts = observed_refund_txid(
            &agreed.details,
            &self.config.btc_custody_address.to_string(),
            outcome.refunded_sats,
            self.config.btc_tolerance_sats,
        )?
        .map(|txid| self.btc_evidence.transaction_facts(&txid))
        .transpose()?;
        let evidence_hash = self.persist_redemption_evidence(
            &dispatch,
            &inbound_hash,
            &agreed,
            &btc_facts,
            refund_facts.as_ref(),
            &eth_observation,
            outcome,
            streaming,
            now,
        )?;
        Ok(RedemptionObservation {
            dispatch,
            outcome,
            streaming,
            evidence_hash,
        })
    }

    async fn poll_thor(
        &self,
        inbound_hash: &str,
        include_stages: bool,
    ) -> Result<AgreedThorTx, SettlementObserverError> {
        let mut observations = Vec::with_capacity(self.thor_sources.len());
        for source in &self.thor_sources {
            let status = source
                .client
                .tx_status_evidence(inbound_hash)
                .await
                .map_err(|error| SettlementObserverError::NotReady(error.to_string()))?;
            let details = source
                .client
                .tx_details_evidence(inbound_hash)
                .await
                .map_err(|error| SettlementObserverError::NotReady(error.to_string()))?;
            let stages = if include_stages {
                Some(
                    source
                        .client
                        .tx_status_stages_evidence(inbound_hash)
                        .await
                        .map_err(|error| SettlementObserverError::NotReady(error.to_string()))?,
                )
            } else {
                None
            };
            let inbound = source
                .client
                .inbound_evidence()
                .await
                .map_err(|error| SettlementObserverError::NotReady(error.to_string()))?;
            let vaults: Vec<_> = inbound
                .value
                .iter()
                .filter(|entry| entry.chain == "BTC")
                .cloned()
                .collect();
            if vaults.len() != 1 {
                return Err(SettlementObserverError::NotReady(format!(
                    "THOR source {} returned {} BTC inbound rows",
                    source.id,
                    vaults.len()
                )));
            }
            observations.push(ThorSourceObservation {
                source_id: source.id.clone(),
                status,
                details,
                stages,
                vault: vaults[0].clone(),
                inbound_body: inbound.raw_body,
            });
        }
        let first = observations
            .first()
            .ok_or_else(|| SettlementObserverError::Configuration("no THOR sources".to_string()))?;
        if observations.iter().skip(1).any(|observation| {
            observation.status.value != first.status.value
                || observation.details.value != first.details.value
                || observation.stages.as_ref().map(|value| &value.value)
                    != first.stages.as_ref().map(|value| &value.value)
                || observation.vault != first.vault
        }) {
            return Err(SettlementObserverError::NotReady(
                "THOR sources disagree on transaction status/details/stages/BTC vault".to_string(),
            ));
        }
        let raw = observations
            .iter()
            .map(|observation| ThorRawEvidence {
                source_id: observation.source_id.clone(),
                status_body: observation.status.raw_body.clone(),
                details_body: observation.details.raw_body.clone(),
                stages_body: observation
                    .stages
                    .as_ref()
                    .map(|value| value.raw_body.clone()),
                inbound_body: observation.inbound_body.clone(),
            })
            .collect();
        Ok(AgreedThorTx {
            status: first.status.value.clone(),
            details: first.details.value.clone(),
            stages: first.stages.as_ref().map(|value| value.value.clone()),
            vault: first.vault.clone(),
            raw,
        })
    }

    fn validate_mint_record(
        &self,
        record: &FinalizedMintRecord,
    ) -> Result<(), SettlementObserverError> {
        if record.slot_index != 0 || record.slot_asset_id != self.config.asset_id {
            return Err(SettlementObserverError::BadRequest(
                "mint slot/asset metadata mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_dispatch(
        &self,
        dispatch: &FinalizedDispatchRecord,
    ) -> Result<(), SettlementObserverError> {
        if dispatch.leg_index != 0 || dispatch.target_token != self.config.target_token {
            return Err(SettlementObserverError::BadRequest(
                "redemption leg/target metadata mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn persist_mint_evidence(
        &self,
        record: &FinalizedMintRecord,
        thor: &AgreedThorTx,
        btc: &UtxoTransactionFacts,
        amount: u64,
        now: u64,
    ) -> Result<B256, SettlementObserverError> {
        let value = serde_json::json!({
            "schema": "xindex.settlement-presign.v1",
            "operatorId": self.config.operator_id,
            "kind": "mint",
            "observedAt": now,
            "intentId": format!("{:#x}", record.intent_id),
            "slotIndex": record.slot_index,
            "assetId": format!("{:#x}", record.slot_asset_id),
            "attestedAmount": amount.to_string(),
            "ethereum": mint_record_json(record),
            "thorSources": thor.raw,
            "agreedBtcVault": thor.vault,
            "bitcoinOutbound": btc,
        });
        self.persist_value("settlement-mint", &value)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the evidence envelope intentionally binds every independent input and derived outcome"
    )]
    fn persist_redemption_evidence(
        &self,
        dispatch: &FinalizedDispatchRecord,
        inbound_hash: &str,
        thor: &AgreedThorTx,
        inbound_btc: &UtxoTransactionFacts,
        refund_btc: Option<&UtxoTransactionFacts>,
        ethereum: &FinalizedErc20Observation,
        outcome: xindex_signer::crosscheck::StreamedOutcome,
        streaming: bool,
        now: u64,
    ) -> Result<B256, SettlementObserverError> {
        let value = serde_json::json!({
            "schema": "xindex.settlement-presign.v1",
            "operatorId": self.config.operator_id,
            "kind": if streaming { "streamed" } else if outcome.delivered_usdt_1e6 > 0 { "delivery" } else { "refund" },
            "observedAt": now,
            "redemptionId": format!("{:#x}", dispatch.redemption_id),
            "legIndex": dispatch.leg_index,
            "assetId": format!("{:#x}", self.config.asset_id),
            "deliveredUsdt": outcome.delivered_usdt_1e6.to_string(),
            "refundedNative": outcome.refunded_sats.to_string(),
            "inboundTxHash": inbound_hash,
            "ethereum": dispatch_record_json(dispatch),
            "thorSources": thor.raw,
            "agreedBtcVault": thor.vault,
            "bitcoinInbound": inbound_btc,
            "bitcoinRefund": refund_btc,
            "finalizedEthereumObservation": ethereum,
        });
        self.persist_value("settlement-redemption", &value)
    }

    fn persist_value<T: Serialize>(
        &self,
        prefix: &str,
        value: &T,
    ) -> Result<B256, SettlementObserverError> {
        let encoded = serde_json::to_vec(value).map_err(EvidenceError::Serialization)?;
        let hash = alloy_primitives::keccak256(&encoded);
        self.evidence.persist_hashed(prefix, value)?;
        Ok(hash)
    }

    async fn sign_mint(
        &self,
        payload: xindex_shared::eip712::Attestation,
    ) -> Result<[u8; 65], SettlementObserverError> {
        let signer = self.signer.clone();
        let domain = self.domain.clone();
        tokio::task::spawn_blocking(move || signer.sign_attestation_msg(&domain, &payload))
            .await
            .map_err(|_| SettlementObserverError::Worker)?
            .map_err(Into::into)
    }

    async fn sign_delivery(
        &self,
        payload: xindex_shared::eip712::AsyncLegDeliveryAttestation,
    ) -> Result<[u8; 65], SettlementObserverError> {
        let signer = self.signer.clone();
        let domain = self.domain.clone();
        tokio::task::spawn_blocking(move || {
            signer.sign_redemption_attestation_msg(&domain, &payload)
        })
        .await
        .map_err(|_| SettlementObserverError::Worker)?
        .map_err(Into::into)
    }

    async fn sign_refund(
        &self,
        payload: xindex_shared::eip712::AsyncLegRefundAttestation,
    ) -> Result<[u8; 65], SettlementObserverError> {
        let signer = self.signer.clone();
        let domain = self.domain.clone();
        tokio::task::spawn_blocking(move || signer.sign_refund_attestation_msg(&domain, &payload))
            .await
            .map_err(|_| SettlementObserverError::Worker)?
            .map_err(Into::into)
    }

    async fn sign_streamed(
        &self,
        payload: xindex_shared::eip712::AsyncLegStreamedSettlement,
    ) -> Result<[u8; 65], SettlementObserverError> {
        let signer = self.signer.clone();
        let domain = self.domain.clone();
        tokio::task::spawn_blocking(move || signer.sign_streamed_settlement_msg(&domain, &payload))
            .await
            .map_err(|_| SettlementObserverError::Worker)?
            .map_err(Into::into)
    }
}

fn parse_b256(label: &str, raw: &str) -> Result<B256, SettlementObserverError> {
    let value = B256::from_str(raw)
        .map_err(|error| SettlementObserverError::BadRequest(format!("{label}: {error}")))?;
    if value == B256::ZERO {
        return Err(SettlementObserverError::BadRequest(format!(
            "{label} is zero"
        )));
    }
    Ok(value)
}

fn parse_launch_index(label: &str, raw: &str) -> Result<u32, SettlementObserverError> {
    let value = U256::from_str_radix(raw, 10)
        .map_err(|error| SettlementObserverError::BadRequest(format!("{label}: {error}")))?;
    let value = u32::try_from(value)
        .map_err(|error| SettlementObserverError::BadRequest(format!("{label}: {error}")))?;
    if value != 0 {
        return Err(SettlementObserverError::BadRequest(format!(
            "{label} must be zero in launch scope"
        )));
    }
    Ok(value)
}

fn parse_txid(raw: &str) -> Result<Txid, SettlementObserverError> {
    Txid::from_str(raw.strip_prefix("0x").unwrap_or(raw))
        .map_err(|error| SettlementObserverError::BadRequest(format!("inbound txid: {error}")))
}

fn validate_thor_inbound_id(
    status: &TxResponse,
    expected: &str,
) -> Result<(), SettlementObserverError> {
    if !status.observed_tx.tx.id.eq_ignore_ascii_case(expected) {
        return Err(SettlementObserverError::NotReady(
            "THOR observed a different inbound id".to_string(),
        ));
    }
    Ok(())
}

fn observed_btc_txid(
    details: &TxDetailsResponse,
    custody: &str,
    amount: u64,
    tolerance: u64,
) -> Result<Txid, SettlementObserverError> {
    let matches: Vec<_> = details
        .out_txs
        .iter()
        .filter(|outbound| {
            outbound.chain == "BTC"
                && outbound.to_address == custody
                && outbound.coins.iter().any(|coin| {
                    coin.asset.eq_ignore_ascii_case("BTC.BTC")
                        && coin
                            .amount
                            .parse::<u64>()
                            .is_ok_and(|value| value.abs_diff(amount) <= tolerance)
                })
        })
        .collect();
    if matches.len() != 1 {
        return Err(SettlementObserverError::NotReady(format!(
            "expected one observed BTC outbound, got {}",
            matches.len()
        )));
    }
    Txid::from_str(&matches[0].id)
        .map_err(|error| SettlementObserverError::NotReady(format!("observed BTC txid: {error}")))
}

fn observed_refund_txid(
    details: &TxDetailsResponse,
    custody: &str,
    refunded_sats: u64,
    tolerance: u64,
) -> Result<Option<Txid>, SettlementObserverError> {
    if refunded_sats == 0 {
        return Ok(None);
    }
    observed_btc_txid(details, custody, refunded_sats, tolerance).map(Some)
}

fn validate_redemption_inbound(
    status: &TxResponse,
    vault: &InboundAddress,
    dispatch: &FinalizedDispatchRecord,
    custody: &Address,
    network: Network,
    min_confirmations: u32,
    btc: &UtxoTransactionFacts,
) -> Result<(), SettlementObserverError> {
    let tx = &status.observed_tx.tx;
    let dispatch_amount: u64 = dispatch.facts.amount.try_into().map_err(|_| {
        SettlementObserverError::BadRequest("dispatch amount exceeds u64".to_string())
    })?;
    if status.observed_tx.status != "done"
        || !tx.id.eq_ignore_ascii_case(&btc.txid)
        || tx.chain != "BTC"
        || tx.from_address != custody.to_string()
        || vault.chain != "BTC"
        || vault.address.is_empty()
        || tx.to_address != vault.address
        || vault.halted
        || vault.global_trading_paused
        || vault.chain_trading_paused
        || vault.chain_lp_actions_paused
        || tx.memo.as_bytes() != dispatch.facts.memo
        || tx.coins.len() != 1
        || !tx.coins[0].asset.eq_ignore_ascii_case("BTC.BTC")
        || tx.coins[0].amount.parse::<u64>().ok() != Some(dispatch_amount)
        || !btc.confirmed
        || btc.confirmations < min_confirmations
        || btc.input_addresses.is_empty()
        || btc
            .input_addresses
            .iter()
            .any(|address| address != &custody.to_string())
    {
        return Err(SettlementObserverError::NotReady(
            "Bitcoin inbound does not exactly match finalized dispatch/THOR observation"
                .to_string(),
        ));
    }
    let asgard = Address::from_str(&tx.to_address)
        .map_err(|error| SettlementObserverError::NotReady(format!("Asgard address: {error}")))?
        .require_network(network)
        .map_err(|error| SettlementObserverError::NotReady(format!("Asgard network: {error}")))?;
    let payment_script = alloy_primitives::hex::encode(asgard.script_pubkey().as_bytes());
    let memo_push = bitcoin::script::PushBytesBuf::try_from(dispatch.facts.memo.clone())
        .map_err(|error| SettlementObserverError::BadRequest(format!("memo push: {error}")))?;
    let memo_script = bitcoin::ScriptBuf::new_op_return(&memo_push);
    let memo_script = alloy_primitives::hex::encode(memo_script.as_bytes());
    let payment_count = btc
        .outputs
        .iter()
        .filter(|output| {
            output.value_sats == dispatch_amount && output.script_pubkey_hex == payment_script
        })
        .count();
    let memo_count = btc
        .outputs
        .iter()
        .filter(|output| output.value_sats == 0 && output.script_pubkey_hex == memo_script)
        .count();
    if payment_count != 1 || memo_count != 1 {
        return Err(SettlementObserverError::NotReady(
            "Bitcoin inbound lacks one exact Asgard payment and one exact memo".to_string(),
        ));
    }
    Ok(())
}

fn mint_record_json(record: &FinalizedMintRecord) -> serde_json::Value {
    serde_json::json!({
        "sourceBlock": record.source_block,
        "sourceBlockHash": format!("{:#x}", record.source_block_hash),
        "sourceTransactionHash": format!("{:#x}", record.source_transaction_hash),
        "sourceTransactionIndex": record.source_transaction_index,
        "intentLogIndex": record.intent_log_index,
        "acquireLogIndex": record.acquire_log_index,
        "indexToken": format!("{:#x}", record.index_token),
        "fundingToken": format!("{:#x}", record.funding_token),
        "amountIn": record.amount_in.to_string(),
        "deadline": record.deadline,
        "acquireMemo": String::from_utf8_lossy(&record.acquire_memo),
        "acquireVault": format!("{:#x}", record.acquire_vault),
    })
}

fn dispatch_record_json(dispatch: &FinalizedDispatchRecord) -> serde_json::Value {
    serde_json::json!({
        "dispatchId": format!("{:#x}", dispatch.dispatch_id),
        "targetToken": format!("{:#x}", dispatch.target_token),
        "amount": dispatch.facts.amount.to_string(),
        "memo": String::from_utf8_lossy(&dispatch.facts.memo),
        "finalDestination": format!("{:#x}", dispatch.facts.final_destination),
        "sourceBlock": dispatch.source_block,
        "sourceBlockHash": format!("{:#x}", dispatch.source_block_hash),
        "sourceTransactionHash": format!("{:#x}", dispatch.source_transaction_hash),
        "sourceTransactionIndex": dispatch.source_transaction_index,
        "sourceLogIndex": dispatch.source_log_index,
    })
}

fn encode_signature(signature: [u8; 65]) -> String {
    format!("0x{}", alloy_primitives::hex::encode(signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_index_and_txid_parsers_fail_closed() {
        assert_eq!(parse_launch_index("slot", "0").ok(), Some(0));
        assert!(parse_launch_index("slot", "1").is_err());
        assert!(parse_launch_index("slot", "-1").is_err());
        assert!(parse_txid("not-a-txid").is_err());
    }
}
