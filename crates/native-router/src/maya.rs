use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{keccak256, B256};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::Instant;
use xindex_ops::network::HttpClientPolicy;

use crate::catalog::{ambiguous_maya_execution_assets, canonical_maya_asset, maya_execution_asset};
use crate::http::BoundedJsonClient;
use crate::math::{parse_positive_u128, scale_ceil, scale_exact, scale_floor};
use crate::NativeRouterError;

pub const MAINNET_NODE: &str = "https://mayanode.mayachain.info/";
pub const MAYA_BLOCK_SECONDS: u32 = 6;
pub const MAX_QUOTE_AGE_SECONDS: u64 = 10 * 60;

#[derive(Clone, Debug)]
pub struct MayaClient {
    http: BoundedJsonClient,
    next_quote_slot: Arc<Mutex<Instant>>,
}

impl MayaClient {
    /// Build a client for Maya's hosted mainnet node.
    ///
    /// # Errors
    /// Invalid HTTP policy or client construction.
    pub fn mainnet(policy: HttpClientPolicy) -> Result<Self, NativeRouterError> {
        Self::new(MAINNET_NODE, policy)
    }

    /// Build a client for one independently operated reviewed HTTPS Maya node.
    ///
    /// # Errors
    /// Non-HTTPS URL, invalid policy, or client construction.
    pub fn new(base_url: &str, policy: HttpClientPolicy) -> Result<Self, NativeRouterError> {
        Ok(Self::from_http(BoundedJsonClient::new(base_url, policy)?))
    }

    #[cfg(test)]
    fn loopback(base_url: &str, policy: HttpClientPolicy) -> Result<Self, NativeRouterError> {
        Ok(Self::from_http(BoundedJsonClient::new_loopback(
            base_url, policy,
        )?))
    }

    fn from_http(http: BoundedJsonClient) -> Self {
        Self {
            http,
            next_quote_slot: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Fetch all pools. Only `status == Available` becomes quote-eligible.
    ///
    /// # Errors
    /// Transport, status, size, JSON or catalog-validation failure.
    pub async fn catalog(&self) -> Result<MayaCatalog, NativeRouterError> {
        let pools: Vec<MayaPool> = self.http.get("mayachain/pools", &()).await?;
        MayaCatalog::try_from(pools)
    }

    /// Fetch the uncached current vault/router/halt envelope.
    ///
    /// # Errors
    /// Transport, status, size or JSON failure.
    pub async fn inbound_addresses(&self) -> Result<Vec<MayaInboundAddress>, NativeRouterError> {
        self.http.get("mayachain/inbound_addresses", &()).await
    }

    /// Fetch one quote while enforcing Maya's documented one-request/second
    /// client rate limit. A fresh call is made every time; inbound data and
    /// quotes are never cached by this crate.
    ///
    /// # Errors
    /// Invalid request, transport, status, size or JSON failure.
    pub async fn quote(&self, request: &MayaQuoteRequest) -> Result<MayaQuote, NativeRouterError> {
        request.validate()?;
        let scheduled = {
            let mut next = self.next_quote_slot.lock().await;
            let now = Instant::now();
            let scheduled = (*next).max(now);
            *next = scheduled + Duration::from_secs(1);
            scheduled
        };
        tokio::time::sleep_until(scheduled).await;
        let query = MayaQuoteQuery {
            from_asset: &request.from_asset,
            to_asset: &request.to_asset,
            amount: request.amount_provider_units.to_string(),
            destination: &request.destination,
            liquidity_tolerance_bps: request.liquidity_tolerance_bps,
            streaming_interval: request.streaming_interval,
            streaming_quantity: request.maximum_streaming_quantity,
        };
        self.http.get("mayachain/quote/swap", &query).await
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MayaPool {
    pub asset: String,
    pub status: String,
    pub decimals: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MayaCatalogAsset {
    pub full_asset: String,
    pub execution_asset: String,
    pub provider_asset_id: B256,
    pub execution_asset_id: B256,
    /// Maya quote/memo amounts use 1e8 except native CACAO at 1e10.
    pub provider_decimals: u8,
    /// Informational pool metadata only. Governance must independently pin
    /// the real destination-chain decimals before enabling the asset.
    pub reported_asset_decimals: Option<u8>,
    pub available: bool,
    pub execution_alias_ambiguous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MayaCatalog {
    pub assets: Vec<MayaCatalogAsset>,
}

impl TryFrom<Vec<MayaPool>> for MayaCatalog {
    type Error = NativeRouterError;

    fn try_from(pools: Vec<MayaPool>) -> Result<Self, Self::Error> {
        let mut normalized = Vec::with_capacity(pools.len() + 1);
        let mut seen = HashSet::new();
        for pool in pools {
            let full_asset = canonical_maya_asset(&pool.asset)?;
            if pool.status.is_empty() || !seen.insert(full_asset.clone()) {
                return Err(NativeRouterError::InvalidProviderData(
                    "duplicate Maya pool or empty status",
                ));
            }
            if pool.decimals.is_some_and(|decimals| decimals > 18) {
                return Err(NativeRouterError::InvalidProviderData(
                    "Maya pool decimals exceed 18",
                ));
            }
            normalized.push((full_asset, pool.status == "Available", pool.decimals, 8u8));
        }
        if seen.insert("MAYA.CACAO".to_string()) {
            normalized.push(("MAYA.CACAO".to_string(), true, Some(10), 10));
        }
        let ambiguous = ambiguous_maya_execution_assets(
            normalized
                .iter()
                .filter(|(_, available, _, _)| *available)
                .map(|(asset, _, _, _)| asset.as_str()),
        );
        let mut assets = normalized
            .into_iter()
            .map(|(full_asset, available, decimals, provider_decimals)| {
                let execution_asset = maya_execution_asset(&full_asset)?;
                let execution_alias_ambiguous = ambiguous.contains(&execution_asset);
                Ok(MayaCatalogAsset {
                    provider_asset_id: keccak256(full_asset.as_bytes()),
                    execution_asset_id: keccak256(execution_asset.as_bytes()),
                    full_asset,
                    execution_asset,
                    provider_decimals,
                    reported_asset_decimals: decimals,
                    available,
                    execution_alias_ambiguous,
                })
            })
            .collect::<Result<Vec<_>, NativeRouterError>>()?;
        assets.sort_by(|left, right| left.full_asset.cmp(&right.full_asset));
        Ok(Self { assets })
    }
}

impl MayaCatalog {
    #[must_use]
    pub fn asset(&self, full_asset: &str) -> Option<&MayaCatalogAsset> {
        canonical_maya_asset(full_asset).ok().and_then(|canonical| {
            self.assets
                .iter()
                .find(|asset| asset.full_asset == canonical)
        })
    }

    #[must_use]
    pub fn is_quote_eligible(&self, full_asset: &str) -> bool {
        self.asset(full_asset)
            .is_some_and(|asset| asset.available && !asset.execution_alias_ambiguous)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MayaInboundAddress {
    pub chain: String,
    pub address: String,
    pub router: Option<String>,
    pub halted: bool,
    pub global_trading_paused: Option<bool>,
    pub chain_trading_paused: Option<bool>,
    pub chain_lp_actions_paused: Option<bool>,
}

impl MayaInboundAddress {
    #[must_use]
    pub fn trading_healthy(&self) -> bool {
        !self.halted
            && self.global_trading_paused != Some(true)
            && self.chain_trading_paused != Some(true)
            && self.chain_lp_actions_paused != Some(true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MayaInboundRoute {
    pub chain: String,
    pub vault: String,
    pub router: String,
}

/// Require independently fetched inbound snapshots to agree on one healthy
/// chain's current vault and Router. Optional pause fields are absent when
/// false under Maya's `OpenAPI` schema; explicit true always rejects.
///
/// # Errors
/// Fewer than two sources, missing/duplicate chain entry, any halt, missing
/// Router, or source disagreement.
pub fn consensus_inbound(
    snapshots: &[Vec<MayaInboundAddress>],
    source_chain: &str,
    minimum_sources: usize,
) -> Result<MayaInboundRoute, NativeRouterError> {
    let required = minimum_sources.max(2);
    if snapshots.len() < required {
        return Err(NativeRouterError::InsufficientSources {
            supplied: snapshots.len(),
            required,
        });
    }
    let mut selected = Vec::with_capacity(snapshots.len());
    for snapshot in snapshots {
        let matches = snapshot
            .iter()
            .filter(|entry| entry.chain.eq_ignore_ascii_case(source_chain))
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(NativeRouterError::InvalidProviderData(
                "Maya inbound snapshot lacks one unique source chain",
            ));
        }
        let entry = matches[0];
        if !entry.trading_healthy() || entry.address.is_empty() {
            return Err(NativeRouterError::AssetUnavailable(
                source_chain.to_string(),
            ));
        }
        let router = entry
            .router
            .as_ref()
            .filter(|router| !router.is_empty())
            .ok_or(NativeRouterError::InvalidProviderData(
                "Maya EVM inbound entry lacks Router",
            ))?;
        selected.push(MayaInboundRoute {
            chain: source_chain.to_ascii_uppercase(),
            vault: entry.address.to_ascii_lowercase(),
            router: router.to_ascii_lowercase(),
        });
    }
    let first = selected
        .first()
        .ok_or(NativeRouterError::InsufficientSources {
            supplied: 0,
            required,
        })?;
    if selected.iter().any(|entry| entry != first) {
        return Err(NativeRouterError::SourceDisagreement(
            "Maya inbound vault/Router",
        ));
    }
    Ok(first.clone())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MayaQuoteRequest {
    pub from_asset: String,
    pub to_asset: String,
    pub amount_provider_units: u128,
    pub amount_input_native_units: u128,
    pub source_native_decimals: u8,
    pub destination: String,
    pub liquidity_tolerance_bps: u16,
    pub streaming_interval: u16,
    pub maximum_streaming_quantity: u16,
}

impl MayaQuoteRequest {
    /// Convert the exact source-chain amount to Maya's quote scale without
    /// silently dropping sub-1e8 precision.
    ///
    /// # Errors
    /// Invalid asset notation, address, decimals, zero values or lossy scale.
    #[expect(
        clippy::too_many_arguments,
        reason = "the quote API fields and source-chain amount bind are explicit"
    )]
    pub fn new(
        from_asset: &str,
        to_asset: &str,
        amount_input_native_units: u128,
        source_native_decimals: u8,
        destination: String,
        liquidity_tolerance_bps: u16,
        streaming_interval: u16,
        maximum_streaming_quantity: u16,
    ) -> Result<Self, NativeRouterError> {
        let from_asset = canonical_maya_asset(from_asset)?;
        let to_asset = canonical_maya_asset(to_asset)?;
        let provider_decimals = if from_asset == "MAYA.CACAO" { 10 } else { 8 };
        let amount_provider_units = scale_exact(
            amount_input_native_units,
            source_native_decimals,
            provider_decimals,
        )?;
        let request = Self {
            from_asset,
            to_asset,
            amount_provider_units,
            amount_input_native_units,
            source_native_decimals,
            destination,
            liquidity_tolerance_bps,
            streaming_interval,
            maximum_streaming_quantity,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), NativeRouterError> {
        if self.from_asset == self.to_asset
            || self.amount_provider_units == 0
            || self.amount_input_native_units == 0
            || self.destination.is_empty()
            || self.destination.len() > 180
            || self.liquidity_tolerance_bps == 0
            || self.liquidity_tolerance_bps > 100
            || self.streaming_interval == 0
            || self.maximum_streaming_quantity == 0
            || self.maximum_streaming_quantity > 256
        {
            return Err(NativeRouterError::Policy("invalid Maya quote request"));
        }
        canonical_maya_asset(&self.from_asset)?;
        canonical_maya_asset(&self.to_asset)?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct MayaQuoteQuery<'a> {
    from_asset: &'a str,
    to_asset: &'a str,
    amount: String,
    destination: &'a str,
    liquidity_tolerance_bps: u16,
    streaming_interval: u16,
    streaming_quantity: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MayaQuoteFees {
    pub asset: String,
    pub affiliate: Option<String>,
    pub outbound: Option<String>,
    pub liquidity: String,
    pub total: String,
    pub slippage_bps: u16,
    pub total_bps: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MayaQuote {
    pub inbound_address: Option<String>,
    pub inbound_confirmation_blocks: Option<u64>,
    pub inbound_confirmation_seconds: Option<u64>,
    pub outbound_delay_blocks: u64,
    pub outbound_delay_seconds: u64,
    pub fees: MayaQuoteFees,
    pub router: Option<String>,
    pub expiry: u64,
    pub warning: String,
    pub notes: String,
    pub memo: Option<String>,
    pub expected_amount_out: String,
    pub max_streaming_quantity: Option<u16>,
    pub streaming_swap_blocks: Option<u32>,
    pub streaming_swap_seconds: Option<u32>,
    pub total_swap_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedMayaQuote {
    pub vault: String,
    pub router: String,
    pub memo: String,
    pub expiry: u64,
    pub expected_amount_provider_units: u128,
    pub minimum_amount_provider_units: u128,
    pub expected_amount_native_units: u128,
    pub minimum_amount_native_units: u128,
    pub chunks: u16,
    pub interval_blocks: u16,
    pub stream_duration_seconds: u32,
    pub total_duration_seconds: u64,
    pub reported_total_bps: u16,
}

impl MayaQuote {
    /// Validate the quote against independent inbound consensus, the exact
    /// request, Maya's full-pool identity, reduced memo identity, freshness,
    /// zero-affiliate policy and stream timing.
    ///
    /// # Errors
    /// Any mismatch, stale quote, malformed memo/amount, excessive fee or
    /// inconsistent stream metadata.
    #[expect(
        clippy::too_many_lines,
        reason = "linear quote validation keeps all provider-field binds auditable in one place"
    )]
    pub fn validate(
        &self,
        request: &MayaQuoteRequest,
        inbound: &MayaInboundRoute,
        now: u64,
        destination_native_decimals: u8,
    ) -> Result<ValidatedMayaQuote, NativeRouterError> {
        request.validate()?;
        if inbound.chain != "ETH" || self.warning.is_empty() || self.notes.is_empty() {
            return Err(NativeRouterError::InvalidProviderData(
                "Maya quote lacks required source/warning/notes",
            ));
        }
        if self.expiry <= now || self.expiry > now.saturating_add(MAX_QUOTE_AGE_SECONDS) {
            return Err(NativeRouterError::Policy("Maya quote is stale or overlong"));
        }
        let vault = self
            .inbound_address
            .as_ref()
            .ok_or(NativeRouterError::InvalidProviderData(
                "Maya quote lacks inbound address",
            ))?
            .to_ascii_lowercase();
        let router = self
            .router
            .as_ref()
            .ok_or(NativeRouterError::InvalidProviderData(
                "Maya quote lacks Router",
            ))?
            .to_ascii_lowercase();
        if vault != inbound.vault || router != inbound.router {
            return Err(NativeRouterError::SourceDisagreement(
                "Maya quote and inbound state",
            ));
        }
        let fee_asset = canonical_maya_asset(&self.fees.asset)?;
        if fee_asset != request.to_asset
            || parse_optional_amount(self.fees.affiliate.as_deref(), "maya.fees.affiliate")? != 0
            || self.fees.total_bps > 100
            || self.fees.slippage_bps > 100
        {
            return Err(NativeRouterError::Policy(
                "Maya fee asset, affiliate, or cost violates policy",
            ));
        }
        parse_optional_amount(self.fees.outbound.as_deref(), "maya.fees.outbound")?;
        parse_canonical_amount(&self.fees.liquidity, "maya.fees.liquidity")?;
        parse_canonical_amount(&self.fees.total, "maya.fees.total")?;

        let expected_provider =
            parse_positive_u128(&self.expected_amount_out, "maya.expected_amount_out")?;
        let memo = self
            .memo
            .as_ref()
            .ok_or(NativeRouterError::InvalidProviderData(
                "Maya quote lacks swap memo",
            ))?;
        let parsed = parse_swap_memo(memo)?;
        let retained_bps = u128::from(10_000u16 - request.liquidity_tolerance_bps);
        let requested_minimum_provider = (expected_provider / 10_000) * retained_bps
            + ((expected_provider % 10_000) * retained_bps) / 10_000;
        if parsed.asset != maya_execution_asset(&request.to_asset)?
            || parsed.destination != request.destination
            || parsed.interval != request.streaming_interval
            || parsed.quantity > request.maximum_streaming_quantity
            || parsed.minimum < requested_minimum_provider
        {
            return Err(NativeRouterError::InvalidProviderData(
                "Maya memo differs from quote request",
            ));
        }
        if self
            .max_streaming_quantity
            .is_some_and(|maximum| parsed.quantity > maximum)
        {
            return Err(NativeRouterError::InvalidProviderData(
                "Maya memo exceeds quoted stream maximum",
            ));
        }
        let intervals = u32::from(parsed.quantity - 1);
        let blocks = intervals
            .checked_mul(u32::from(parsed.interval))
            .ok_or(NativeRouterError::Policy("Maya stream blocks overflow"))?;
        let stream_seconds = blocks
            .checked_mul(MAYA_BLOCK_SECONDS)
            .ok_or(NativeRouterError::Policy("Maya stream duration overflow"))?;
        if parsed.quantity > 1
            && (self.streaming_swap_blocks != Some(blocks)
                || self.streaming_swap_seconds != Some(stream_seconds))
        {
            return Err(NativeRouterError::InvalidProviderData(
                "Maya response stream duration differs from memo",
            ));
        }
        let total_duration = self.total_swap_seconds.unwrap_or_else(|| {
            self.inbound_confirmation_seconds
                .unwrap_or(0)
                .saturating_add(u64::from(stream_seconds))
                .saturating_add(self.outbound_delay_seconds)
        });
        if total_duration < u64::from(stream_seconds) {
            return Err(NativeRouterError::InvalidProviderData(
                "Maya total duration is shorter than stream",
            ));
        }
        let provider_decimals = if request.to_asset == "MAYA.CACAO" {
            10
        } else {
            8
        };
        let expected_native = scale_floor(
            expected_provider,
            provider_decimals,
            destination_native_decimals,
        )?;
        let minimum_native = scale_ceil(
            parsed.minimum,
            provider_decimals,
            destination_native_decimals,
        )?;
        if minimum_native == 0 || minimum_native > expected_native {
            return Err(NativeRouterError::Policy(
                "invalid scaled Maya output floor",
            ));
        }
        Ok(ValidatedMayaQuote {
            vault,
            router,
            memo: memo.clone(),
            expiry: self.expiry,
            expected_amount_provider_units: expected_provider,
            minimum_amount_provider_units: parsed.minimum,
            expected_amount_native_units: expected_native,
            minimum_amount_native_units: minimum_native,
            chunks: parsed.quantity,
            interval_blocks: parsed.interval,
            stream_duration_seconds: stream_seconds,
            total_duration_seconds: total_duration,
            reported_total_bps: self.fees.total_bps,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedSwapMemo {
    asset: String,
    destination: String,
    minimum: u128,
    interval: u16,
    quantity: u16,
}

fn parse_swap_memo(memo: &str) -> Result<ParsedSwapMemo, NativeRouterError> {
    if memo.len() > 250 || !memo.is_ascii() {
        return Err(NativeRouterError::InvalidField {
            field: "maya.memo",
            reason: "non-ASCII or over 250 bytes".to_string(),
        });
    }
    let fields = memo.split(':').collect::<Vec<_>>();
    if fields.len() != 4 || fields[0] != "=" || fields[1].is_empty() || fields[2].is_empty() {
        return Err(NativeRouterError::InvalidField {
            field: "maya.memo",
            reason: "not an exact swap/asset/destination/limit memo".to_string(),
        });
    }
    let stream = fields[3].split('/').collect::<Vec<_>>();
    if stream.len() != 3 {
        return Err(NativeRouterError::InvalidField {
            field: "maya.memo",
            reason: "missing exact minimum/interval/quantity".to_string(),
        });
    }
    let minimum = parse_memo_amount(stream[0])?;
    let interval = stream[1]
        .parse::<u16>()
        .map_err(|_| NativeRouterError::InvalidField {
            field: "maya.memo.interval",
            reason: "not uint16".to_string(),
        })?;
    let quantity = stream[2]
        .parse::<u16>()
        .map_err(|_| NativeRouterError::InvalidField {
            field: "maya.memo.quantity",
            reason: "not uint16".to_string(),
        })?;
    if minimum == 0 || interval == 0 || quantity == 0 || quantity > 256 {
        return Err(NativeRouterError::Policy("invalid Maya memo stream values"));
    }
    Ok(ParsedSwapMemo {
        // Keep the exact memo spelling. Solidity hashes these bytes directly,
        // so normalizing here could approve a route that later reverts.
        asset: fields[1].to_string(),
        destination: fields[2].to_string(),
        minimum,
        interval,
        quantity,
    })
}

fn parse_memo_amount(value: &str) -> Result<u128, NativeRouterError> {
    let (base, exponent) = value
        .split_once(['e', 'E'])
        .map_or((value, None), |(base, exponent)| (base, Some(exponent)));
    let base = parse_positive_u128(base, "maya.memo.minimum")?;
    let Some(exponent) = exponent else {
        return Ok(base);
    };
    if exponent.is_empty() || exponent.contains(['e', 'E']) {
        return Err(NativeRouterError::InvalidField {
            field: "maya.memo.minimum",
            reason: "invalid scientific notation".to_string(),
        });
    }
    let exponent = exponent
        .parse::<u32>()
        .map_err(|_| NativeRouterError::InvalidField {
            field: "maya.memo.minimum",
            reason: "invalid scientific exponent".to_string(),
        })?;
    base.checked_mul(
        10u128
            .checked_pow(exponent)
            .ok_or(NativeRouterError::InvalidField {
                field: "maya.memo.minimum",
                reason: "scientific exponent overflows uint128".to_string(),
            })?,
    )
    .ok_or(NativeRouterError::InvalidField {
        field: "maya.memo.minimum",
        reason: "scientific amount overflows uint128".to_string(),
    })
}

fn parse_canonical_amount(value: &str, field: &'static str) -> Result<u128, NativeRouterError> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(NativeRouterError::InvalidField {
            field,
            reason: "not a canonical unsigned integer".to_string(),
        });
    }
    value
        .parse::<u128>()
        .map_err(|_| NativeRouterError::InvalidField {
            field,
            reason: "outside uint128 or not decimal".to_string(),
        })
}

fn parse_optional_amount(
    value: Option<&str>,
    field: &'static str,
) -> Result<u128, NativeRouterError> {
    value.map_or(Ok(0), |value| parse_canonical_amount(value, field))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures must fail loudly")]

    use std::time::Duration;

    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn policy() -> HttpClientPolicy {
        HttpClientPolicy {
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(2),
            max_response_bytes: 64 * 1024,
        }
    }

    fn inbound() -> MayaInboundRoute {
        MayaInboundRoute {
            chain: "ETH".to_string(),
            vault: "0x6a16f961e24e6e90bd9f950f768dc42a7f305664".to_string(),
            router: "0xe3985e6b61b814f7cdb188766562ba71b446b46d".to_string(),
        }
    }

    fn request() -> MayaQuoteRequest {
        MayaQuoteRequest::new(
            "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
            "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831",
            100_000_000,
            6,
            "0x1111111111111111111111111111111111111111".to_string(),
            50,
            3,
            10,
        )
        .expect("request")
    }

    #[test]
    fn catalog_uses_every_available_pool_and_explicit_cacao() {
        let catalog = MayaCatalog::try_from(vec![
            MayaPool {
                asset: "BTC.BTC".to_string(),
                status: "Available".to_string(),
                decimals: Some(8),
            },
            MayaPool {
                asset: "ARB.USDC-0X1111111111111111111111111111111111111111".to_string(),
                status: "Staged".to_string(),
                decimals: Some(6),
            },
        ])
        .expect("catalog");
        assert!(catalog.is_quote_eligible("BTC.BTC"));
        assert!(catalog.is_quote_eligible("MAYA.CACAO"));
        assert!(!catalog.is_quote_eligible("ARB.USDC-0X1111111111111111111111111111111111111111"));
    }

    #[test]
    fn inbound_consensus_rejects_halts_and_disagreement() {
        let healthy = MayaInboundAddress {
            chain: "ETH".to_string(),
            address: inbound().vault,
            router: Some(inbound().router),
            halted: false,
            global_trading_paused: None,
            chain_trading_paused: None,
            chain_lp_actions_paused: None,
        };
        assert_eq!(
            consensus_inbound(&[vec![healthy.clone()], vec![healthy.clone()]], "ETH", 2)
                .expect("consensus"),
            inbound()
        );
        let mut halted = healthy.clone();
        halted.chain_trading_paused = Some(true);
        assert!(consensus_inbound(&[vec![healthy], vec![halted]], "ETH", 2).is_err());
    }

    #[test]
    fn live_shape_quote_validates_reduced_asset_and_first_chunk_timing() {
        let quote: MayaQuote = serde_json::from_value(json!({
            "inbound_address": inbound().vault,
            "inbound_confirmation_blocks": 2,
            "inbound_confirmation_seconds": 24,
            "outbound_delay_blocks": 0,
            "outbound_delay_seconds": 0,
            "fees": {
                "asset": "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831",
                "affiliate": "0",
                "outbound": "12297800",
                "liquidity": "22038100",
                "total": "34335900",
                "slippage_bps": 32,
                "total_bps": 34
            },
            "router": inbound().router,
            "expiry": 1_800_000_500u64,
            "warning": "Do not cache this response.",
            "notes": "Use depositWithExpiry.",
            "memo": "=:ARB.USDC:0x1111111111111111111111111111111111111111:9911516186/3/7",
            "expected_amount_out": "9961322800",
            "max_streaming_quantity": 7,
            "streaming_swap_blocks": 18,
            "streaming_swap_seconds": 108,
            "total_swap_seconds": 132
        }))
        .expect("fixture");
        let validated = quote
            .validate(&request(), &inbound(), 1_800_000_000, 6)
            .expect("valid quote");
        assert_eq!(validated.chunks, 7);
        assert_eq!(validated.stream_duration_seconds, 108);
        assert_eq!(validated.expected_amount_native_units, 99_613_228);
        assert_eq!(validated.minimum_amount_native_units, 99_115_162);
    }

    #[test]
    fn live_shape_quote_validates_native_asset_short_name() {
        let request = MayaQuoteRequest::new(
            "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
            "BTC.BTC",
            1_000_000_000,
            6,
            "1BitcoinEaterAddressDontSendf59kuE".to_string(),
            50,
            1,
            10,
        )
        .expect("request");
        let quote: MayaQuote = serde_json::from_value(json!({
            "inbound_address": inbound().vault,
            "inbound_confirmation_blocks": 2,
            "inbound_confirmation_seconds": 24,
            "outbound_delay_blocks": 0,
            "outbound_delay_seconds": 0,
            "fees": {
                "asset": "BTC.BTC",
                "affiliate": "0",
                "outbound": "3000",
                "liquidity": "3144",
                "total": "6144",
                "slippage_bps": 30,
                "total_bps": 39
            },
            "router": inbound().router,
            "expiry": 1_800_000_500u64,
            "warning": "Do not cache this response.",
            "notes": "Use depositWithExpiry.",
            "memo": "=:b:1BitcoinEaterAddressDontSendf59kuE:1539782/1/8",
            "expected_amount_out": "1547520",
            "max_streaming_quantity": 8,
            "streaming_swap_blocks": 7,
            "streaming_swap_seconds": 42,
            "total_swap_seconds": 66
        }))
        .expect("current live response shape");
        let validated = quote
            .validate(&request, &inbound(), 1_800_000_000, 8)
            .expect("valid quote");
        assert_eq!(validated.chunks, 8);
        assert_eq!(validated.stream_duration_seconds, 42);
        assert_eq!(validated.minimum_amount_native_units, 1_539_782);
    }

    #[test]
    fn scientific_memo_amount_is_exact() {
        let parsed = parse_swap_memo("=:BTC.BTC:bc1qdestination:995e5/3/10").expect("memo");
        assert_eq!(parsed.minimum, 99_500_000);
        assert!(parse_swap_memo("=:BTC.BTC:bc1qdestination:99.5e6/3/10").is_err());
    }

    #[tokio::test]
    async fn quote_request_uses_liquidity_tolerance_and_explicit_streaming() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/mayachain/quote/swap"))
            .and(query_param(
                "from_asset",
                "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
            ))
            .and(query_param(
                "to_asset",
                "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831",
            ))
            .and(query_param("amount", "10000000000"))
            .and(query_param("liquidity_tolerance_bps", "50"))
            .and(query_param("streaming_interval", "3"))
            .and(query_param("streaming_quantity", "10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "outbound_delay_blocks": 0,
                "outbound_delay_seconds": 0,
                "fees": {"asset": "BTC.BTC", "liquidity": "0", "total": "0", "slippage_bps": 0, "total_bps": 0},
                "expiry": 1,
                "warning": "warning",
                "notes": "notes",
                "expected_amount_out": "1"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = MayaClient::loopback(&server.uri(), policy()).expect("client");
        let _quote = client.quote(&request()).await.expect("quote");
    }
}
