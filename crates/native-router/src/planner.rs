use alloy_primitives::{Address, B256, U256};

use crate::catalog::{maya_evm_token_address, ChainflipAssetDescriptor, Provider};
use crate::chainflip::{
    ChainflipCatalog, ChainflipEncodingRequest, ChainflipQuoteRequest, EncodedVaultSwapData,
    ValidatedChainflipQuote,
};
use crate::maya::{MayaCatalog, MayaInboundRoute, MayaQuote, MayaQuoteRequest};
use crate::payload::{chainflip_route_call, maya_route_call};
use crate::selection::{GovernanceBinding, RouteCandidate};
use crate::NativeRouterError;

#[derive(Debug)]
pub struct ChainflipCandidateInput<'a> {
    pub catalog: &'a ChainflipCatalog,
    pub source: ChainflipAssetDescriptor,
    pub destination: ChainflipAssetDescriptor,
    pub quote: &'a ValidatedChainflipQuote,
    pub encoding_request: &'a ChainflipEncodingRequest,
    pub encoded_payload: &'a EncodedVaultSwapData,
    pub governance: GovernanceBinding,
    pub source_token: Address,
    /// Destination bytes independently produced by the reviewed codec for the
    /// exact destination chain. They must equal the provider calldata.
    pub destination_address_bytes: &'a [u8],
    pub amount_input_native_units: u128,
    pub reference_amount_out: u128,
    pub execution_tolerance_bps: u16,
    pub observed_at: u64,
    pub valid_until: u64,
    pub evidence_hash: B256,
}

/// Bind catalog state, governance mapping, quote, official encoding request,
/// independently agreed payload and economics into one Chainflip candidate.
///
/// # Errors
/// Any live-state, mapping, quote, payload, amount or lifetime mismatch.
pub fn chainflip_candidate(
    input: ChainflipCandidateInput<'_>,
) -> Result<RouteCandidate, NativeRouterError> {
    require_chainflip_evm_token_source(input.source)?;
    if !input
        .catalog
        .supports_vault_route(input.source, input.destination)
    {
        return Err(NativeRouterError::AssetUnavailable(
            input.destination.canonical_name(),
        ));
    }
    require_chainflip_mapping(&input.governance, input.destination)?;
    input.encoding_request.validate_against_quote(
        input.source,
        input.destination,
        input.amount_input_native_units,
        input.quote,
        input.execution_tolerance_bps,
    )?;
    if input.execution_tolerance_bps == 0 || input.execution_tolerance_bps > 100 {
        return Err(NativeRouterError::Policy(
            "Chainflip execution tolerance must be in 1..=100 bps",
        ));
    }
    let minimum_amount_out = input
        .quote
        .expected_amount_out
        .checked_mul(u128::from(10_000u16 - input.execution_tolerance_bps))
        .ok_or(NativeRouterError::Policy(
            "Chainflip minimum output overflow",
        ))?
        / 10_000;
    if minimum_amount_out == 0
        || input.observed_at == 0
        || input.valid_until <= input.observed_at
        || input.valid_until - input.observed_at > 10 * 60
    {
        return Err(NativeRouterError::Policy(
            "invalid Chainflip floor or authorization lifetime",
        ));
    }
    let amount = U256::from(input.amount_input_native_units);
    let call = chainflip_route_call(
        input.encoded_payload,
        input.governance.endpoint,
        input.source_token,
        amount,
        input.destination,
        input.destination_address_bytes,
    )?;
    Ok(RouteCandidate {
        provider: Provider::Chainflip,
        governance: input.governance,
        calls: vec![call],
        expected_amount_out: input.quote.expected_amount_out,
        minimum_amount_out,
        reference_amount_out: input.reference_amount_out,
        chunks: input.quote.chunks,
        stream_duration_seconds: input.quote.execution_duration_seconds,
        observed_at: input.observed_at,
        valid_until: input.valid_until,
        evidence_hash: input.evidence_hash,
    })
}

fn require_chainflip_mapping(
    governance: &GovernanceBinding,
    destination: ChainflipAssetDescriptor,
) -> Result<(), NativeRouterError> {
    let expected_id = destination.provider_asset_id();
    if governance.provider_id != Provider::Chainflip.id()
        || governance.provider_asset_id != expected_id
        || governance.execution_asset_id != expected_id
        || governance.destination_chain != destination.destination_chain
        || governance.destination_token != destination.destination_token
        || governance.provider_decimals != destination.decimals
        || governance.native_decimals != destination.decimals
        || governance.dispatch_mode != 0
        || governance.stream_block_seconds != 0
    {
        return Err(NativeRouterError::Policy(
            "Chainflip governance asset mapping differs from official catalog",
        ));
    }
    Ok(())
}

fn require_chainflip_evm_token_source(
    source: ChainflipAssetDescriptor,
) -> Result<(), NativeRouterError> {
    if source.chain != "Ethereum" || source.internal_asset == "Eth" {
        return Err(NativeRouterError::Policy(
            "Chainflip xSwapToken route requires an Ethereum ERC-20 source asset",
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub struct MayaCandidateInput<'a> {
    pub catalog: &'a MayaCatalog,
    pub request: &'a MayaQuoteRequest,
    pub quote: &'a MayaQuote,
    pub inbound: &'a MayaInboundRoute,
    pub governance: GovernanceBinding,
    pub source_token: Address,
    pub reference_amount_out: u128,
    pub observed_at: u64,
    pub now: u64,
    pub evidence_hash: B256,
}

/// Bind Maya's dynamic pool catalog, multi-source inbound state, fresh quote,
/// reduced memo asset, governance mapping and exact Router call.
///
/// # Errors
/// Any unsupported pool, mapping, quote, inbound, scale or payload mismatch.
pub fn maya_candidate(input: MayaCandidateInput<'_>) -> Result<RouteCandidate, NativeRouterError> {
    if !input.catalog.is_quote_eligible(&input.request.from_asset)
        || !input.catalog.is_quote_eligible(&input.request.to_asset)
        || !input.request.from_asset.starts_with("ETH.")
        || input.request.from_asset == "ETH.ETH"
    {
        return Err(NativeRouterError::AssetUnavailable(
            input.request.to_asset.clone(),
        ));
    }
    let source = input
        .catalog
        .asset(&input.request.from_asset)
        .ok_or_else(|| NativeRouterError::UnsupportedAsset(input.request.from_asset.clone()))?;
    if maya_evm_token_address(&source.full_asset)? != input.source_token {
        return Err(NativeRouterError::Policy(
            "Maya source pool contract differs from funding token",
        ));
    }
    let destination = input
        .catalog
        .asset(&input.request.to_asset)
        .ok_or_else(|| NativeRouterError::UnsupportedAsset(input.request.to_asset.clone()))?;
    if input.governance.provider_id != Provider::Maya.id()
        || input.governance.provider_asset_id != destination.provider_asset_id
        || input.governance.execution_asset_id != destination.execution_asset_id
        || input.governance.destination_chain != 0
        || input.governance.destination_token != 0
        || input.governance.provider_decimals != destination.provider_decimals
        || input.governance.dispatch_mode != 0
        || input.governance.stream_block_seconds != 6
    {
        return Err(NativeRouterError::Policy(
            "Maya governance asset mapping differs from live catalog",
        ));
    }
    let validated = input.quote.validate(
        input.request,
        input.inbound,
        input.now,
        input.governance.native_decimals,
    )?;
    let call = maya_route_call(
        &validated,
        input.governance.endpoint,
        input.source_token,
        U256::from(input.request.amount_input_native_units),
    )?;
    Ok(RouteCandidate {
        provider: Provider::Maya,
        governance: input.governance,
        calls: vec![call],
        expected_amount_out: validated.expected_amount_native_units,
        minimum_amount_out: validated.minimum_amount_native_units,
        reference_amount_out: input.reference_amount_out,
        chunks: validated.chunks,
        stream_duration_seconds: validated.stream_duration_seconds,
        observed_at: input.observed_at,
        valid_until: validated.expiry,
        evidence_hash: input.evidence_hash,
    })
}

/// Convenience check used before fetching a Chainflip quote.
///
/// # Errors
/// The pair is not currently live in the catalog.
pub fn require_chainflip_pair(
    catalog: &ChainflipCatalog,
    request: &ChainflipQuoteRequest,
) -> Result<(), NativeRouterError> {
    require_chainflip_evm_token_source(request.source)?;
    if catalog.supports_vault_route(request.source, request.destination) {
        Ok(())
    } else {
        Err(NativeRouterError::AssetUnavailable(
            request.destination.canonical_name(),
        ))
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures must fail loudly")]

    use alloy_primitives::{keccak256, Address, B256};
    use serde_json::json;

    use super::*;
    use crate::catalog::{chainflip_asset, Provider, CHAINFLIP_ASSETS};
    use crate::maya::{MayaCatalog, MayaPool};

    #[test]
    fn maya_candidate_rejects_full_pool_hash_mismatch() {
        let catalog = MayaCatalog::try_from(vec![
            MayaPool {
                asset: "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7".to_string(),
                status: "Available".to_string(),
                decimals: Some(6),
            },
            MayaPool {
                asset: "BTC.BTC".to_string(),
                status: "Available".to_string(),
                decimals: Some(8),
            },
        ])
        .expect("catalog");
        let request = MayaQuoteRequest::new(
            "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
            "BTC.BTC",
            1_000_000,
            6,
            "bc1qdestination".to_string(),
            50,
            1,
            1,
        )
        .expect("request");
        let router = Address::repeat_byte(0x11);
        let governance = GovernanceBinding {
            provider_id: Provider::Maya.id(),
            provider_config_hash: B256::repeat_byte(1),
            asset_id: keccak256("BTC.BTC"),
            provider_asset_config_hash: B256::repeat_byte(2),
            provider_asset_id: B256::repeat_byte(0xff),
            execution_asset_id: keccak256("b"),
            destination_chain: 0,
            destination_token: 0,
            provider_decimals: 8,
            native_decimals: 8,
            endpoint: router,
            dispatch_mode: 0,
            max_total_cost_bps: 100,
            max_chunks: 256,
            max_stream_duration_seconds: 24 * 60 * 60,
            stream_block_seconds: 6,
            enabled: true,
            asset_enabled: true,
        };
        let quote: MayaQuote = serde_json::from_value(json!({
            "inbound_address": format!("{:#x}", Address::repeat_byte(0x22)),
            "outbound_delay_blocks": 0,
            "outbound_delay_seconds": 0,
            "fees": {"asset": "BTC.BTC", "liquidity": "0", "total": "0", "slippage_bps": 0, "total_bps": 0},
            "router": format!("{router:#x}"),
            "expiry": 1_800_000_300u64,
            "warning": "warning",
            "notes": "notes",
            "memo": "=:b:bc1qdestination:995000/1/1",
            "expected_amount_out": "1000000"
        }))
        .expect("quote");
        let inbound = MayaInboundRoute {
            chain: "ETH".to_string(),
            vault: format!("{:#x}", Address::repeat_byte(0x22)),
            router: format!("{router:#x}"),
        };
        let source_token = "0xdac17f958d2ee523a2206206994597c13d831ec7"
            .parse::<Address>()
            .expect("source token");
        assert!(maya_candidate(MayaCandidateInput {
            catalog: &catalog,
            request: &request,
            quote: &quote,
            inbound: &inbound,
            governance,
            source_token,
            reference_amount_out: 1_000_000,
            observed_at: 1_800_000_000,
            now: 1_800_000_000,
            evidence_hash: B256::repeat_byte(4),
        })
        .is_err());
    }

    #[test]
    fn every_current_chainflip_asset_has_an_exact_governance_mapping() {
        for destination in CHAINFLIP_ASSETS {
            let governance = GovernanceBinding {
                provider_id: Provider::Chainflip.id(),
                provider_config_hash: B256::repeat_byte(1),
                asset_id: keccak256(destination.canonical_name()),
                provider_asset_config_hash: B256::repeat_byte(2),
                provider_asset_id: destination.provider_asset_id(),
                execution_asset_id: destination.provider_asset_id(),
                destination_chain: destination.destination_chain,
                destination_token: destination.destination_token,
                provider_decimals: destination.decimals,
                native_decimals: destination.decimals,
                endpoint: Address::repeat_byte(0x11),
                dispatch_mode: 0,
                max_total_cost_bps: 100,
                max_chunks: 256,
                max_stream_duration_seconds: 24 * 60 * 60,
                stream_block_seconds: 0,
                enabled: true,
                asset_enabled: true,
            };
            assert!(require_chainflip_mapping(&governance, destination).is_ok());
        }
    }

    #[test]
    fn erc20_dispatch_rejects_native_and_non_ethereum_sources() {
        assert!(require_chainflip_evm_token_source(chainflip_asset("Usdt").expect("USDT")).is_ok());
        assert!(require_chainflip_evm_token_source(chainflip_asset("Eth").expect("ETH")).is_err());
        assert!(require_chainflip_evm_token_source(chainflip_asset("Btc").expect("BTC")).is_err());
        assert!(require_chainflip_evm_token_source(chainflip_asset("Sol").expect("SOL")).is_err());
    }
}
