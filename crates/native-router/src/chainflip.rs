use std::collections::HashSet;

use alloy_primitives::Address;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use xindex_ops::network::HttpClientPolicy;

use crate::catalog::{chainflip_asset, ChainflipAssetDescriptor};
use crate::http::BoundedJsonClient;
use crate::math::parse_positive_u128;
use crate::NativeRouterError;

pub const MAINNET_BACKEND: &str = "https://chainflip-swap.chainflip.io/";
const STATE_CHAIN_BLOCK_SECONDS: u32 = 6;
const MAX_EXECUTION_DURATION_SECONDS: u32 = 24 * 60 * 60;

#[derive(Debug, Clone)]
pub struct ChainflipClient {
    http: BoundedJsonClient,
}

impl ChainflipClient {
    /// Build a mainnet client using the official SDK backend origin.
    ///
    /// # Errors
    /// Invalid HTTP policy or client construction.
    pub fn mainnet(policy: HttpClientPolicy) -> Result<Self, NativeRouterError> {
        Self::new(MAINNET_BACKEND, policy)
    }

    /// Build a client for a reviewed HTTPS backend or broker facade.
    ///
    /// # Errors
    /// Non-HTTPS URL, invalid policy, or client construction.
    pub fn new(base_url: &str, policy: HttpClientPolicy) -> Result<Self, NativeRouterError> {
        Ok(Self {
            http: BoundedJsonClient::new(base_url, policy)?,
        })
    }

    #[cfg(test)]
    fn loopback(base_url: &str, policy: HttpClientPolicy) -> Result<Self, NativeRouterError> {
        Ok(Self {
            http: BoundedJsonClient::new_loopback(base_url, policy)?,
        })
    }

    /// Fetch the exact live asset-state envelope consumed by Chainflip's SDK.
    ///
    /// # Errors
    /// Transport, status, size, JSON or catalog-validation failure.
    pub async fn catalog(&self) -> Result<ChainflipCatalog, NativeRouterError> {
        let response: NetworkInfoResponse = self.http.get("api/networkInfo", &()).await?;
        ChainflipCatalog::try_from(response)
    }

    /// Fetch all regular/DCA quotes for one exact vault-swap pair.
    ///
    /// # Errors
    /// Invalid amount, transport, status, size or response JSON.
    pub async fn quotes(
        &self,
        request: &ChainflipQuoteRequest,
    ) -> Result<Vec<ChainflipQuote>, NativeRouterError> {
        request.validate()?;
        let query = QuoteQuery {
            src_chain: request.source.chain,
            src_asset: request.source.symbol,
            dest_chain: request.destination.chain,
            dest_asset: request.destination.symbol,
            amount: request.amount.to_string(),
            is_vault_swap: "true",
            is_on_chain: "false",
            dca_v2_enabled: "true",
        };
        self.http.get("v2/quote", &query).await
    }

    /// Ask the official backend/broker implementation to encode the evolving
    /// SCALE `cf_parameters` payload and the outer EVM Vault call.
    ///
    /// # Errors
    /// Invalid request, transport, status, size or response JSON.
    pub async fn encode_vault_swap(
        &self,
        request: &ChainflipEncodingRequest,
    ) -> Result<EncodedVaultSwapData, NativeRouterError> {
        request.validate()?;
        self.http.post("api/encodeVaultSwapData", request).await
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkInfoResponse {
    assets: Vec<NetworkAssetState>,
    cf_broker_commission_bps: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[expect(
    clippy::struct_excessive_bools,
    reason = "exact mirror of Chainflip's required networkInfo asset flags"
)]
struct NetworkAssetState {
    asset: String,
    vault_swap_deposits_enabled: bool,
    deposit_channel_deposits_enabled: bool,
    deposit_channel_creation_enabled: bool,
    egress_enabled: bool,
    boost_deposits_enabled: bool,
    live_price_protection_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "callers must inspect every independent upstream capability flag"
)]
pub struct ChainflipAssetState {
    pub descriptor: ChainflipAssetDescriptor,
    pub vault_swap_deposits_enabled: bool,
    pub deposit_channel_deposits_enabled: bool,
    pub deposit_channel_creation_enabled: bool,
    pub egress_enabled: bool,
    pub boost_deposits_enabled: bool,
    pub live_price_protection_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainflipCatalog {
    pub assets: Vec<ChainflipAssetState>,
    pub unknown_assets: Vec<String>,
    pub advertised_broker_commission_bps: u16,
}

impl TryFrom<NetworkInfoResponse> for ChainflipCatalog {
    type Error = NativeRouterError;

    fn try_from(response: NetworkInfoResponse) -> Result<Self, Self::Error> {
        let mut seen = HashSet::new();
        let mut assets = Vec::new();
        let mut unknown_assets = Vec::new();
        for state in response.assets {
            if state.asset.is_empty() || !seen.insert(state.asset.clone()) {
                return Err(NativeRouterError::InvalidProviderData(
                    "duplicate or empty Chainflip asset",
                ));
            }
            let Some(descriptor) = chainflip_asset(&state.asset) else {
                unknown_assets.push(state.asset);
                continue;
            };
            assets.push(ChainflipAssetState {
                descriptor,
                vault_swap_deposits_enabled: state.vault_swap_deposits_enabled,
                deposit_channel_deposits_enabled: state.deposit_channel_deposits_enabled,
                deposit_channel_creation_enabled: state.deposit_channel_creation_enabled,
                egress_enabled: state.egress_enabled,
                boost_deposits_enabled: state.boost_deposits_enabled,
                live_price_protection_enabled: state.live_price_protection_enabled,
            });
        }
        assets.sort_by_key(|state| state.descriptor.destination_token);
        unknown_assets.sort();
        Ok(Self {
            assets,
            unknown_assets,
            advertised_broker_commission_bps: response.cf_broker_commission_bps,
        })
    }
}

impl ChainflipCatalog {
    #[must_use]
    pub fn state(&self, asset: ChainflipAssetDescriptor) -> Option<&ChainflipAssetState> {
        self.assets
            .iter()
            .find(|state| state.descriptor.internal_asset == asset.internal_asset)
    }

    /// Both the exact source vault ingress and destination egress must be live.
    #[must_use]
    pub fn supports_vault_route(
        &self,
        source: ChainflipAssetDescriptor,
        destination: ChainflipAssetDescriptor,
    ) -> bool {
        self.state(source)
            .is_some_and(|state| state.vault_swap_deposits_enabled)
            && self
                .state(destination)
                .is_some_and(|state| state.egress_enabled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainflipQuoteRequest {
    pub source: ChainflipAssetDescriptor,
    pub destination: ChainflipAssetDescriptor,
    pub amount: u128,
}

impl ChainflipQuoteRequest {
    fn validate(&self) -> Result<(), NativeRouterError> {
        if self.amount == 0 {
            return Err(NativeRouterError::InvalidField {
                field: "chainflip.amount",
                reason: "must be in 1..2^128".to_string(),
            });
        }
        if self.source == self.destination {
            return Err(NativeRouterError::Policy(
                "source and destination asset match",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct QuoteQuery<'a> {
    src_chain: &'a str,
    src_asset: &'a str,
    dest_chain: &'a str,
    dest_asset: &'a str,
    amount: String,
    is_vault_swap: &'static str,
    is_on_chain: &'static str,
    dca_v2_enabled: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainAsset {
    pub chain: String,
    pub asset: String,
}

impl From<ChainflipAssetDescriptor> for ChainAsset {
    fn from(value: ChainflipAssetDescriptor) -> Self {
        Self {
            chain: value.chain.to_string(),
            asset: value.symbol.to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainflipFee {
    pub r#type: String,
    pub chain: String,
    pub asset: String,
    pub amount: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DcaParams {
    pub number_of_chunks: u16,
    pub chunk_interval_blocks: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EstimatedDurations {
    pub deposit: u64,
    pub swap: u64,
    pub egress: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainflipQuote {
    pub r#type: String,
    pub src_asset: ChainAsset,
    pub dest_asset: ChainAsset,
    pub is_vault_swap: bool,
    /// The current backend omits this response field even though the request
    /// explicitly sets `isOnChain=false`. An explicit `true` still fails.
    pub is_on_chain: Option<bool>,
    pub deposit_amount: String,
    pub egress_amount: String,
    pub included_fees: Vec<ChainflipFee>,
    pub low_liquidity_warning: Option<bool>,
    pub estimated_duration_seconds: u64,
    pub estimated_durations_seconds: EstimatedDurations,
    pub estimated_price: String,
    pub recommended_slippage_tolerance_percent: serde_json::Number,
    pub recommended_retry_duration_minutes: serde_json::Number,
    pub recommended_live_price_slippage_tolerance_percent: Option<serde_json::Number>,
    pub dca_params: Option<DcaParams>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedChainflipQuote {
    pub source: ChainflipAssetDescriptor,
    pub destination: ChainflipAssetDescriptor,
    pub deposit_amount: u128,
    pub quote_type: ChainflipQuoteType,
    pub expected_amount_out: u128,
    pub estimated_price: String,
    pub chunks: u16,
    pub chunk_interval_blocks: u16,
    pub execution_duration_seconds: u32,
    pub recommended_slippage_tolerance_bps: u16,
    pub recommended_live_price_slippage_tolerance_bps: Option<u16>,
    pub retry_duration_blocks: u32,
    pub total_duration_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainflipQuoteType {
    Regular,
    Dca,
}

impl ChainflipQuote {
    /// Bind every quote field that controls eligibility and stream shape to the
    /// exact request. Unknown fee types remain visible but malformed fees and
    /// non-zero broker charges reject.
    ///
    /// # Errors
    /// Any request mismatch, low-liquidity warning, malformed amount or DCA
    /// shape.
    #[expect(
        clippy::too_many_lines,
        reason = "one atomic quote validation binds every provider-controlled field"
    )]
    pub fn validate(
        &self,
        request: &ChainflipQuoteRequest,
    ) -> Result<ValidatedChainflipQuote, NativeRouterError> {
        request.validate()?;
        let source = ChainAsset::from(request.source);
        let destination = ChainAsset::from(request.destination);
        if self.src_asset != source
            || self.dest_asset != destination
            || !self.is_vault_swap
            || self.is_on_chain == Some(true)
            || self.deposit_amount != request.amount.to_string()
        {
            return Err(NativeRouterError::InvalidProviderData(
                "Chainflip quote differs from request",
            ));
        }
        if self.low_liquidity_warning != Some(false) {
            return Err(NativeRouterError::Policy(
                "Chainflip quote has low or unknown liquidity",
            ));
        }
        for fee in &self.included_fees {
            let amount = parse_canonical_u128(&fee.amount, "chainflip.fee.amount")?;
            if fee.chain.is_empty() || fee.asset.is_empty() || fee.r#type.is_empty() {
                return Err(NativeRouterError::InvalidProviderData(
                    "Chainflip fee identity is empty",
                ));
            }
            if fee.r#type == "BROKER" && amount != 0 {
                return Err(NativeRouterError::Policy(
                    "Chainflip broker commission must be zero",
                ));
            }
        }
        validate_decimal(&self.estimated_price, "chainflip.estimatedPrice")?;
        let expected_amount_out =
            parse_positive_u128(&self.egress_amount, "chainflip.egressAmount")?;
        let recommended_slippage_tolerance_bps = percent_to_floor_bps(
            &self.recommended_slippage_tolerance_percent,
            "chainflip.recommendedSlippageTolerancePercent",
        )?;
        let recommended_live_price_slippage_tolerance_bps = self
            .recommended_live_price_slippage_tolerance_percent
            .as_ref()
            .map(|value| {
                percent_to_floor_bps(
                    value,
                    "chainflip.recommendedLivePriceSlippageTolerancePercent",
                )
            })
            .transpose()?;
        let retry_duration_blocks = retry_minutes_to_blocks(
            &self.recommended_retry_duration_minutes,
            "chainflip.recommendedRetryDurationMinutes",
        )?;
        let retry_duration_seconds = retry_duration_blocks
            .checked_mul(STATE_CHAIN_BLOCK_SECONDS)
            .ok_or(NativeRouterError::Policy(
                "Chainflip retry duration overflows seconds",
            ))?;
        let (quote_type, chunks, interval, stream_duration) = match self.r#type.as_str() {
            "REGULAR" => {
                if self.dca_params.is_some() {
                    return Err(NativeRouterError::InvalidProviderData(
                        "regular Chainflip quote contains DCA parameters",
                    ));
                }
                (ChainflipQuoteType::Regular, 1, 0, 0)
            }
            "DCA" => {
                let dca = self
                    .dca_params
                    .ok_or(NativeRouterError::InvalidProviderData(
                        "DCA Chainflip quote lacks parameters",
                    ))?;
                if dca.number_of_chunks < 2
                    || dca.number_of_chunks > 256
                    || dca.chunk_interval_blocks == 0
                    || self.estimated_durations_seconds.swap == 0
                {
                    return Err(NativeRouterError::InvalidProviderData(
                        "invalid Chainflip DCA shape",
                    ));
                }
                let duration =
                    u32::try_from(self.estimated_durations_seconds.swap).map_err(|_| {
                        NativeRouterError::InvalidProviderData(
                            "Chainflip DCA duration exceeds uint32",
                        )
                    })?;
                (
                    ChainflipQuoteType::Dca,
                    dca.number_of_chunks,
                    dca.chunk_interval_blocks,
                    duration,
                )
            }
            _ => {
                return Err(NativeRouterError::InvalidProviderData(
                    "unknown Chainflip quote type",
                ));
            }
        };
        let execution_duration_seconds =
            stream_duration.checked_add(retry_duration_seconds).ok_or(
                NativeRouterError::Policy("Chainflip execution duration overflows seconds"),
            )?;
        if execution_duration_seconds > MAX_EXECUTION_DURATION_SECONDS {
            return Err(NativeRouterError::Policy(
                "Chainflip execution duration exceeds 24 hours",
            ));
        }
        Ok(ValidatedChainflipQuote {
            source: request.source,
            destination: request.destination,
            deposit_amount: request.amount,
            quote_type,
            expected_amount_out,
            estimated_price: self.estimated_price.clone(),
            chunks,
            chunk_interval_blocks: interval,
            execution_duration_seconds,
            recommended_slippage_tolerance_bps,
            recommended_live_price_slippage_tolerance_bps,
            retry_duration_blocks,
            total_duration_seconds: self.estimated_duration_seconds,
        })
    }
}

fn parse_canonical_u128(value: &str, field: &'static str) -> Result<u128, NativeRouterError> {
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

fn validate_decimal(value: &str, field: &'static str) -> Result<(), NativeRouterError> {
    let mut dot = false;
    let mut digits = 0usize;
    if value.is_empty() || value.len() > 160 {
        return Err(NativeRouterError::InvalidField {
            field,
            reason: "empty or overlong".to_string(),
        });
    }
    for character in value.bytes() {
        if character == b'.' && !dot {
            dot = true;
        } else if character.is_ascii_digit() {
            digits += 1;
        } else {
            return Err(NativeRouterError::InvalidField {
                field,
                reason: "not an unsigned decimal".to_string(),
            });
        }
    }
    if digits == 0 || value.starts_with('.') || value.ends_with('.') {
        return Err(NativeRouterError::InvalidField {
            field,
            reason: "not a canonical unsigned decimal".to_string(),
        });
    }
    Ok(())
}

fn parse_decimal_ratio_field(
    value: &str,
    field: &'static str,
) -> Result<(BigUint, u32), NativeRouterError> {
    validate_decimal(value, field)?;
    let (integer, fractional) = value.split_once('.').map_or((value, ""), |parts| parts);
    let scale = u32::try_from(fractional.len()).map_err(|_| NativeRouterError::InvalidField {
        field,
        reason: "fraction scale exceeds uint32".to_string(),
    })?;
    let joined = format!("{integer}{fractional}");
    let numerator = BigUint::parse_bytes(joined.as_bytes(), 10).ok_or(
        NativeRouterError::InvalidProviderData("failed to parse Chainflip decimal"),
    )?;
    Ok((numerator, scale))
}

fn parse_decimal_ratio(value: &str) -> Result<(BigUint, u32), NativeRouterError> {
    let parsed = parse_decimal_ratio_field(value, "chainflip.estimatedPrice")?;
    let (numerator, scale) = parsed;
    if numerator == BigUint::from(0u8) {
        return Err(NativeRouterError::InvalidProviderData(
            "Chainflip estimated price is zero",
        ));
    }
    Ok((numerator, scale))
}

fn percent_to_floor_bps(
    value: &serde_json::Number,
    field: &'static str,
) -> Result<u16, NativeRouterError> {
    let raw = value.to_string();
    let (numerator, scale) = parse_decimal_ratio_field(&raw, field)?;
    let denominator = BigUint::from(10u8).pow(scale);
    let bps = numerator * BigUint::from(100u8) / denominator;
    let parsed =
        bps.to_str_radix(10)
            .parse::<u16>()
            .map_err(|_| NativeRouterError::InvalidField {
                field,
                reason: "outside 1..=10000 basis points".to_string(),
            })?;
    if parsed == 0 || parsed > 10_000 {
        return Err(NativeRouterError::InvalidField {
            field,
            reason: "outside 1..=10000 basis points".to_string(),
        });
    }
    Ok(parsed)
}

fn retry_minutes_to_blocks(
    value: &serde_json::Number,
    field: &'static str,
) -> Result<u32, NativeRouterError> {
    let raw = value.to_string();
    let (numerator, scale) = parse_decimal_ratio_field(&raw, field)?;
    let denominator = BigUint::from(10u8).pow(scale);
    let scaled = numerator * BigUint::from(60u32 / STATE_CHAIN_BLOCK_SECONDS);
    let blocks = (scaled + (&denominator - BigUint::from(1u8))) / denominator;
    let parsed =
        blocks
            .to_str_radix(10)
            .parse::<u32>()
            .map_err(|_| NativeRouterError::InvalidField {
                field,
                reason: "retry duration exceeds uint32 blocks".to_string(),
            })?;
    if parsed == 0 || parsed > MAX_EXECUTION_DURATION_SECONDS / STATE_CHAIN_BLOCK_SECONDS {
        return Err(NativeRouterError::InvalidField {
            field,
            reason: "outside 1 block..=24 hours".to_string(),
        });
    }
    Ok(parsed)
}

fn round_half_up(numerator: BigUint, denominator: &BigUint) -> BigUint {
    (numerator + denominator / 2u8) / denominator
}

/// Reproduce the current official SDK's two `BigNumber.toFixed` half-up
/// operations: first quantize the tolerance-adjusted estimated price to the
/// destination decimals, then convert that price to Q128 at source precision.
///
/// # Errors
/// Invalid decimal, zero result, decimals above 18 or tolerance above 100%.
pub fn min_price_x128(
    estimated_price: &str,
    source_decimals: u8,
    destination_decimals: u8,
    tolerance_bps: u16,
) -> Result<String, NativeRouterError> {
    if source_decimals > 18 || destination_decimals > 18 || tolerance_bps > 10_000 {
        return Err(NativeRouterError::Policy(
            "invalid Chainflip min-price parameters",
        ));
    }
    let (price_numerator, price_scale) = parse_decimal_ratio(estimated_price)?;
    let quantize_numerator = price_numerator
        * BigUint::from(10_000u16 - tolerance_bps)
        * BigUint::from(10u8).pow(u32::from(destination_decimals));
    let quantize_denominator = BigUint::from(10u8).pow(price_scale) * BigUint::from(10_000u16);
    let minimum_at_destination_scale = round_half_up(quantize_numerator, &quantize_denominator);
    if minimum_at_destination_scale == BigUint::from(0u8) {
        return Err(NativeRouterError::Policy("Chainflip minimum price is zero"));
    }
    let q128_numerator = minimum_at_destination_scale * (BigUint::from(1u8) << 128usize);
    let q128_denominator = BigUint::from(10u8).pow(u32::from(source_decimals));
    let encoded = round_half_up(q128_numerator, &q128_denominator);
    Ok(encoded.to_str_radix(10))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FillOrKillParams {
    pub retry_duration_blocks: u32,
    pub refund_address: String,
    pub min_price_x128: String,
    pub max_oracle_price_slippage: Option<u16>,
    pub refund_ccm_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainflipEncodingRequest {
    pub src_asset: ChainAsset,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_address: Option<String>,
    pub dest_asset: ChainAsset,
    pub dest_address: String,
    pub amount: String,
    pub commission_bps: u16,
    pub fill_or_kill_params: FillOrKillParams,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dca_params: Option<DcaParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broker_account: Option<String>,
}

impl ChainflipEncodingRequest {
    /// Construct a zero-commission encoding request from one validated quote.
    /// `refund_address` and `destination_address` remain chain-specific and
    /// must already have passed the caller's reviewed address codec.
    ///
    /// # Errors
    /// Invalid addresses, tolerance, quote recommendation, amount or price
    /// encoding.
    #[expect(
        clippy::too_many_arguments,
        reason = "all provider-controlled encoding inputs are deliberately explicit"
    )]
    pub fn from_quote(
        source: ChainflipAssetDescriptor,
        destination: ChainflipAssetDescriptor,
        amount: u128,
        destination_address: String,
        refund_address: String,
        source_address: Option<String>,
        quote: &ValidatedChainflipQuote,
        tolerance_bps: u16,
    ) -> Result<Self, NativeRouterError> {
        if destination_address.is_empty()
            || refund_address.is_empty()
            || source != quote.source
            || destination != quote.destination
            || amount != quote.deposit_amount
            || tolerance_bps == 0
            || tolerance_bps > 100
            || tolerance_bps > quote.recommended_slippage_tolerance_bps
        {
            return Err(NativeRouterError::Policy(
                "invalid Chainflip address or quote-bounded slippage policy",
            ));
        }
        let dca_params = match quote.quote_type {
            ChainflipQuoteType::Regular => None,
            ChainflipQuoteType::Dca => Some(DcaParams {
                number_of_chunks: quote.chunks,
                chunk_interval_blocks: quote.chunk_interval_blocks,
            }),
        };
        let request = Self {
            src_asset: source.into(),
            src_address: source_address,
            dest_asset: destination.into(),
            dest_address: destination_address,
            amount: amount.to_string(),
            commission_bps: 0,
            fill_or_kill_params: FillOrKillParams {
                retry_duration_blocks: quote.retry_duration_blocks,
                refund_address,
                min_price_x128: min_price_x128(
                    &quote.estimated_price,
                    source.decimals,
                    destination.decimals,
                    tolerance_bps,
                )?,
                max_oracle_price_slippage: quote
                    .recommended_live_price_slippage_tolerance_bps
                    .map(|bps| bps.min(100)),
                refund_ccm_metadata: None,
            },
            dca_params,
            broker_account: None,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), NativeRouterError> {
        if self.src_asset == self.dest_asset
            || self.dest_address.is_empty()
            || self.fill_or_kill_params.refund_address.is_empty()
            || self.fill_or_kill_params.retry_duration_blocks == 0
            || self.fill_or_kill_params.retry_duration_blocks
                > MAX_EXECUTION_DURATION_SECONDS / STATE_CHAIN_BLOCK_SECONDS
            || self.commission_bps != 0
            || self.broker_account.is_some()
            || self.fill_or_kill_params.refund_ccm_metadata.is_some()
            || self
                .fill_or_kill_params
                .max_oracle_price_slippage
                .is_some_and(|bps| bps == 0 || bps > 100)
        {
            return Err(NativeRouterError::Policy(
                "Chainflip encoding request violates zero-commission policy",
            ));
        }
        parse_positive_u128(&self.amount, "chainflip.encoding.amount")?;
        parse_positive_u128(
            &self.fill_or_kill_params.min_price_x128,
            "chainflip.minPriceX128",
        )?;
        if let Some(dca) = self.dca_params {
            if dca.number_of_chunks < 2
                || dca.number_of_chunks > 256
                || dca.chunk_interval_blocks == 0
            {
                return Err(NativeRouterError::Policy("invalid Chainflip DCA request"));
            }
        }
        Ok(())
    }

    /// Rebuild every quote-derived encoding field instead of trusting a
    /// coordinator-supplied request object.
    ///
    /// # Errors
    /// Any source/destination/amount/DCA/min-price mismatch or base policy
    /// violation.
    pub fn validate_against_quote(
        &self,
        source: ChainflipAssetDescriptor,
        destination: ChainflipAssetDescriptor,
        amount: u128,
        quote: &ValidatedChainflipQuote,
        tolerance_bps: u16,
    ) -> Result<(), NativeRouterError> {
        self.validate()?;
        let expected_dca = match quote.quote_type {
            ChainflipQuoteType::Regular => None,
            ChainflipQuoteType::Dca => Some(DcaParams {
                number_of_chunks: quote.chunks,
                chunk_interval_blocks: quote.chunk_interval_blocks,
            }),
        };
        if self.src_asset != ChainAsset::from(source)
            || self.dest_asset != ChainAsset::from(destination)
            || self.amount != amount.to_string()
            || source != quote.source
            || destination != quote.destination
            || amount != quote.deposit_amount
            || self.dca_params != expected_dca
            || self.fill_or_kill_params.retry_duration_blocks != quote.retry_duration_blocks
            || self.fill_or_kill_params.max_oracle_price_slippage
                != quote
                    .recommended_live_price_slippage_tolerance_bps
                    .map(|bps| bps.min(100))
            || tolerance_bps == 0
            || tolerance_bps > 100
            || tolerance_bps > quote.recommended_slippage_tolerance_bps
            || self.fill_or_kill_params.min_price_x128
                != min_price_x128(
                    &quote.estimated_price,
                    source.decimals,
                    destination.decimals,
                    tolerance_bps,
                )?
        {
            return Err(NativeRouterError::InvalidProviderData(
                "Chainflip encoding request differs from selected quote",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "chain")]
pub enum EncodedVaultSwapData {
    Bitcoin {
        #[serde(rename = "nulldataPayload")]
        nulldata_payload: String,
        #[serde(rename = "depositAddress")]
        deposit_address: String,
    },
    Ethereum {
        value: String,
        to: String,
        calldata: String,
        #[serde(rename = "sourceTokenAddress")]
        source_token_address: Option<String>,
    },
    Arbitrum {
        value: String,
        to: String,
        calldata: String,
        #[serde(rename = "sourceTokenAddress")]
        source_token_address: Option<String>,
    },
    Tron {
        calldata: String,
        value: String,
        to: String,
        note: String,
        #[serde(rename = "sourceTokenAddress")]
        source_token_address: Option<String>,
    },
    Solana {
        #[serde(rename = "programId")]
        program_id: String,
        data: String,
        accounts: Vec<SolanaAccount>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolanaAccount {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// Exact-match consensus for provider encoders. This is intentionally byte
/// equality: a second encoder is not a fallback and any divergence blocks the
/// route before funds leave Ethereum.
///
/// # Errors
/// Too few sources or any differing response.
pub fn consensus_encoding(
    responses: &[EncodedVaultSwapData],
    minimum_sources: usize,
) -> Result<&EncodedVaultSwapData, NativeRouterError> {
    if minimum_sources < 2 || responses.len() < minimum_sources {
        return Err(NativeRouterError::InsufficientSources {
            supplied: responses.len(),
            required: minimum_sources.max(2),
        });
    }
    let first = responses
        .first()
        .ok_or(NativeRouterError::InsufficientSources {
            supplied: 0,
            required: minimum_sources,
        })?;
    if responses.iter().any(|response| response != first) {
        return Err(NativeRouterError::SourceDisagreement(
            "Chainflip encoded payload",
        ));
    }
    Ok(first)
}

/// Parse an EVM address without accepting truncated or non-hex provider data.
pub(crate) fn parse_address(raw: &str, field: &'static str) -> Result<Address, NativeRouterError> {
    raw.parse::<Address>()
        .map_err(|_| NativeRouterError::InvalidField {
            field,
            reason: "not a 20-byte EVM address".to_string(),
        })
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures must fail loudly")]

    use std::time::Duration;

    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::catalog::{chainflip_asset, CHAINFLIP_ASSETS};

    fn policy() -> HttpClientPolicy {
        HttpClientPolicy {
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(2),
            max_response_bytes: 64 * 1024,
        }
    }

    fn descriptor(name: &str) -> ChainflipAssetDescriptor {
        chainflip_asset(name).expect("known test descriptor")
    }

    #[test]
    fn network_info_covers_all_known_assets_and_surfaces_unknown() {
        let assets = CHAINFLIP_ASSETS
            .iter()
            .map(|asset| {
                json!({
                    "asset": asset.internal_asset,
                    "vaultSwapDepositsEnabled": true,
                    "depositChannelDepositsEnabled": true,
                    "depositChannelCreationEnabled": true,
                    "egressEnabled": true,
                    "boostDepositsEnabled": true,
                    "livePriceProtectionEnabled": true
                })
            })
            .chain(std::iter::once(json!({
                "asset": "FutureAsset",
                "vaultSwapDepositsEnabled": true,
                "depositChannelDepositsEnabled": true,
                "depositChannelCreationEnabled": true,
                "egressEnabled": true,
                "boostDepositsEnabled": true,
                "livePriceProtectionEnabled": true
            })))
            .collect::<Vec<_>>();
        let response: NetworkInfoResponse = serde_json::from_value(json!({
            "assets": assets,
            "cfBrokerCommissionBps": 30
        }))
        .expect("fixture");
        let catalog = ChainflipCatalog::try_from(response).expect("catalog");
        assert_eq!(catalog.assets.len(), 17);
        assert_eq!(catalog.unknown_assets, vec!["FutureAsset"]);
        assert!(catalog.supports_vault_route(descriptor("Usdt"), descriptor("Btc")));
    }

    #[test]
    fn min_price_matches_official_sdk_rounding_shape() {
        // price 0.000_010_25 BTC per USDT; 50 bps tolerance, USDT(6) -> BTC(8).
        assert_eq!(
            min_price_x128("0.00001025", 6, 8, 50).expect("price"),
            "347088014259357232732642099580403576"
        );
        assert!(min_price_x128("1e3", 6, 8, 50).is_err());
    }

    #[tokio::test]
    async fn quote_request_uses_current_official_query_fields() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/quote"))
            .and(query_param("srcChain", "Ethereum"))
            .and(query_param("srcAsset", "USDT"))
            .and(query_param("destChain", "Bitcoin"))
            .and(query_param("destAsset", "BTC"))
            .and(query_param("amount", "100000000"))
            .and(query_param("isVaultSwap", "true"))
            .and(query_param("isOnChain", "false"))
            .and(query_param("dcaV2Enabled", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<serde_json::Value>::new()))
            .expect(1)
            .mount(&server)
            .await;
        let client = ChainflipClient::loopback(&server.uri(), policy()).expect("client");
        let request = ChainflipQuoteRequest {
            source: descriptor("Usdt"),
            destination: descriptor("Btc"),
            amount: 100_000_000,
        };
        let quotes = client.quotes(&request).await.expect("quotes");
        assert!(quotes.is_empty());
    }

    #[test]
    fn quote_rejects_unknown_liquidity_and_broker_fee() {
        let request = ChainflipQuoteRequest {
            source: descriptor("Usdt"),
            destination: descriptor("Btc"),
            amount: 100_000_000,
        };
        let mut quote: ChainflipQuote = serde_json::from_value(json!({
            "type": "REGULAR",
            "srcAsset": {"chain": "Ethereum", "asset": "USDT"},
            "destAsset": {"chain": "Bitcoin", "asset": "BTC"},
            "isVaultSwap": true,
            "isOnChain": false,
            "depositAmount": "100000000",
            "egressAmount": "99500000",
            "includedFees": [],
            "estimatedDurationSeconds": 60,
            "estimatedDurationsSeconds": {"deposit": 10, "swap": 20, "egress": 30},
            "estimatedPrice": "0.995",
            "recommendedSlippageTolerancePercent": 0.5,
            "recommendedRetryDurationMinutes": 30,
            "recommendedLivePriceSlippageTolerancePercent": 0.75
        }))
        .expect("fixture");
        assert!(quote.validate(&request).is_err());
        quote.low_liquidity_warning = Some(false);
        quote.included_fees.push(ChainflipFee {
            r#type: "BROKER".to_string(),
            chain: "Bitcoin".to_string(),
            asset: "BTC".to_string(),
            amount: "1".to_string(),
        });
        assert!(quote.validate(&request).is_err());
    }

    #[test]
    fn quote_accepts_current_live_shape_without_is_on_chain() {
        let request = ChainflipQuoteRequest {
            source: descriptor("Usdt"),
            destination: descriptor("Btc"),
            amount: 20_000_000,
        };
        let mut quote: ChainflipQuote = serde_json::from_value(json!({
            "type": "REGULAR",
            "srcAsset": {"chain": "Ethereum", "asset": "USDT"},
            "destAsset": {"chain": "Bitcoin", "asset": "BTC"},
            "isVaultSwap": true,
            "depositAmount": "20000000",
            "egressAmount": "29589",
            "includedFees": [
                {"chain": "Ethereum", "asset": "USDT", "amount": "0", "type": "INGRESS"},
                {"chain": "Ethereum", "asset": "USDC", "amount": "500000", "type": "NETWORK"},
                {"chain": "Bitcoin", "asset": "BTC", "amount": "863", "type": "EGRESS"}
            ],
            "lowLiquidityWarning": false,
            "estimatedDurationsSeconds": {"swap": 12, "deposit": 60, "egress": 390},
            "estimatedDurationSeconds": 462,
            "estimatedPrice": "0.000015226",
            "recommendedSlippageTolerancePercent": 0.5,
            "recommendedRetryDurationMinutes": 30,
            "recommendedLivePriceSlippageTolerancePercent": 0.75
        }))
        .expect("current live response shape");
        let validated = quote.validate(&request).expect("valid live quote");
        assert_eq!(validated.execution_duration_seconds, 30 * 60);
        assert_eq!(validated.retry_duration_blocks, 300);
        assert_eq!(validated.recommended_slippage_tolerance_bps, 50);
        assert_eq!(
            validated.recommended_live_price_slippage_tolerance_bps,
            Some(75)
        );

        let encoding = ChainflipEncodingRequest::from_quote(
            request.source,
            request.destination,
            request.amount,
            "bc1qdestination".to_string(),
            format!("{:#x}", Address::repeat_byte(3)),
            Some(format!("{:#x}", Address::repeat_byte(4))),
            &validated,
            50,
        )
        .expect("quote-bound encoding");
        assert_eq!(encoding.fill_or_kill_params.retry_duration_blocks, 300);
        assert_eq!(
            encoding.fill_or_kill_params.max_oracle_price_slippage,
            Some(75)
        );
        assert!(ChainflipEncodingRequest::from_quote(
            request.source,
            request.destination,
            request.amount,
            "bc1qdestination".to_string(),
            format!("{:#x}", Address::repeat_byte(3)),
            None,
            &validated,
            51,
        )
        .is_err());

        let mut tampered = encoding;
        tampered.fill_or_kill_params.retry_duration_blocks = 299;
        assert!(tampered
            .validate_against_quote(
                request.source,
                request.destination,
                request.amount,
                &validated,
                50,
            )
            .is_err());

        quote.is_on_chain = Some(true);
        assert!(quote.validate(&request).is_err());
    }

    #[test]
    fn dca_execution_duration_adds_quote_retry_window() {
        let request = ChainflipQuoteRequest {
            source: descriptor("Usdt"),
            destination: descriptor("Btc"),
            amount: 100_000_000,
        };
        let mut quote: ChainflipQuote = serde_json::from_value(json!({
            "type": "DCA",
            "srcAsset": {"chain": "Ethereum", "asset": "USDT"},
            "destAsset": {"chain": "Bitcoin", "asset": "BTC"},
            "isVaultSwap": true,
            "isOnChain": false,
            "depositAmount": "100000000",
            "egressAmount": "99500000",
            "includedFees": [],
            "lowLiquidityWarning": false,
            "estimatedDurationSeconds": 200,
            "estimatedDurationsSeconds": {"deposit": 30, "swap": 120, "egress": 50},
            "estimatedPrice": "0.995",
            "recommendedSlippageTolerancePercent": 0.5,
            "recommendedRetryDurationMinutes": 30,
            "recommendedLivePriceSlippageTolerancePercent": 0.75,
            "dcaParams": {"numberOfChunks": 10, "chunkIntervalBlocks": 2}
        }))
        .expect("DCA fixture");
        let validated = quote.validate(&request).expect("valid DCA quote");
        assert_eq!(validated.chunks, 10);
        assert_eq!(validated.chunk_interval_blocks, 2);
        assert_eq!(validated.execution_duration_seconds, 120 + 30 * 60);

        quote.recommended_retry_duration_minutes = serde_json::Number::from(24 * 60);
        assert!(quote.validate(&request).is_err());
    }

    #[test]
    fn encoding_consensus_requires_two_identical_sources() {
        let response = EncodedVaultSwapData::Ethereum {
            value: "0".to_string(),
            to: format!("{:#x}", Address::repeat_byte(1)),
            calldata: "0x1234".to_string(),
            source_token_address: Some(format!("{:#x}", Address::repeat_byte(2))),
        };
        assert!(consensus_encoding(std::slice::from_ref(&response), 2).is_err());
        assert_eq!(
            consensus_encoding(&[response.clone(), response.clone()], 2).expect("consensus"),
            &response
        );
    }
}
