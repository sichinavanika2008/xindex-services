use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::{eip712_domain, sol, Eip712Domain, SolStruct, SolValue};

use crate::payload::RouteCall as ProviderRouteCall;
use crate::selection::ValidatedRoute;
use crate::NativeRouterError;

sol! {
    /// Exact mirror of `INativeRouteRegistry.RouteAuthorization`.
    struct RouteAuthorization {
        uint8 kind;
        bytes32 requestId;
        bytes32 providerId;
        bytes32 providerConfigHash;
        bytes32 assetId;
        bytes32 providerAssetConfigHash;
        address adapter;
        address indexToken;
        address originator;
        address inputAsset;
        address outputAsset;
        uint256 amountIn;
        uint256 minAmountOut;
        uint256 expectedAmountOut;
        uint16 quotedCostBps;
        uint16 chunks;
        uint32 streamDuration;
        uint64 issuedAt;
        uint64 validUntil;
        uint256 nonce;
        bytes32 payloadHash;
    }

    struct RouteCall {
        address target;
        uint256 amount;
        bytes data;
    }

    struct MintRouteHints {
        RouteAuthorization authorization;
        RouteCall[] calls;
        bytes[] signatures;
    }
}

pub const ROUTE_AUTHORIZATION_TYPE_STRING: &[u8] = b"RouteAuthorization(uint8 kind,bytes32 requestId,bytes32 providerId,bytes32 providerConfigHash,bytes32 assetId,bytes32 providerAssetConfigHash,address adapter,address indexToken,address originator,address inputAsset,address outputAsset,uint256 amountIn,uint256 minAmountOut,uint256 expectedAmountOut,uint16 quotedCostBps,uint16 chunks,uint32 streamDuration,uint64 issuedAt,uint64 validUntil,uint256 nonce,bytes32 payloadHash)";

#[must_use]
pub fn route_authorization_typehash() -> B256 {
    keccak256(ROUTE_AUTHORIZATION_TYPE_STRING)
}

/// EIP-712 domain from `NativeRouteRegistry`'s constructor.
#[must_use]
pub fn native_route_domain(chain_id: u64, verifying_contract: Address) -> Eip712Domain {
    eip712_domain! {
        name: "Xindex Native Route Registry",
        version: "1",
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    }
}

#[must_use]
pub fn route_authorization_signing_hash(
    authorization: &RouteAuthorization,
    domain: &Eip712Domain,
) -> B256 {
    authorization.eip712_signing_hash(domain)
}

/// Convert one selected route plus request identity into the exact EIP-712
/// plaintext independently reconstructed by every signer.
///
/// # Errors
/// Zero identities/addresses, invalid kind/time, amount mismatch, or payload
/// drift since route selection.
#[expect(
    clippy::too_many_arguments,
    reason = "the on-chain authorization identity is intentionally explicit"
)]
pub fn authorization_from_selected(
    kind: u8,
    request_id: B256,
    adapter: Address,
    index_token: Address,
    originator: Address,
    input_asset: Address,
    output_asset: Address,
    amount_in: U256,
    issued_at: u64,
    nonce: U256,
    route: &ValidatedRoute,
) -> Result<RouteAuthorization, NativeRouterError> {
    if kind > 1
        || request_id == B256::ZERO
        || [adapter, index_token, originator, input_asset, output_asset].contains(&Address::ZERO)
        || amount_in.is_zero()
        || issued_at == 0
        || issued_at >= route.candidate.valid_until
        || route.payload_hash != crate::payload::route_calls_hash(&route.candidate.calls)
    {
        return Err(NativeRouterError::Policy(
            "invalid native-route authorization identity",
        ));
    }
    let call_amount = route
        .candidate
        .calls
        .iter()
        .try_fold(U256::ZERO, |total, call| total.checked_add(call.amount))
        .ok_or(NativeRouterError::Policy(
            "route amount sum overflows uint256",
        ))?;
    if call_amount != amount_in {
        return Err(NativeRouterError::Policy(
            "authorization amount differs from route calls",
        ));
    }
    Ok(RouteAuthorization {
        kind,
        requestId: request_id,
        providerId: route.candidate.governance.provider_id,
        providerConfigHash: route.candidate.governance.provider_config_hash,
        assetId: route.candidate.governance.asset_id,
        providerAssetConfigHash: route.candidate.governance.provider_asset_config_hash,
        adapter,
        indexToken: index_token,
        originator,
        inputAsset: input_asset,
        outputAsset: output_asset,
        amountIn: amount_in,
        minAmountOut: U256::from(route.candidate.minimum_amount_out),
        expectedAmountOut: U256::from(route.candidate.expected_amount_out),
        quotedCostBps: route.quoted_cost_bps,
        chunks: route.candidate.chunks,
        streamDuration: route.candidate.stream_duration_seconds,
        issuedAt: issued_at,
        validUntil: route.candidate.valid_until,
        nonce,
        payloadHash: route.payload_hash,
    })
}

/// Encode the exact `IMultiRailAsyncAdapter.MintRouteHints` tuple after
/// rechecking that its calls still match the signed payload hash.
///
/// # Errors
/// Empty signatures, malformed signature lengths, or payload mismatch.
pub fn encode_mint_route_hints(
    authorization: RouteAuthorization,
    calls: &[ProviderRouteCall],
    signatures: &[Bytes],
) -> Result<Bytes, NativeRouterError> {
    if signatures.is_empty() || signatures.iter().any(|signature| signature.len() != 65) {
        return Err(NativeRouterError::Policy(
            "route quorum signatures are empty or malformed",
        ));
    }
    if authorization.payloadHash != crate::payload::route_calls_hash(calls) {
        return Err(NativeRouterError::Policy(
            "signed payload hash differs from route calls",
        ));
    }
    let calls = calls
        .iter()
        .map(|call| RouteCall {
            target: call.target,
            amount: call.amount,
            data: call.data.clone(),
        })
        .collect();
    Ok(Bytes::from(
        MintRouteHints {
            authorization,
            calls,
            signatures: signatures.to_vec(),
        }
        .abi_encode(),
    ))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures must fail loudly")]

    use super::*;
    use crate::catalog::Provider;
    use crate::payload::RouteCall as ProviderRouteCall;
    use crate::selection::{GovernanceBinding, RouteCandidate, RoutePolicy};
    use alloy_primitives::{b256, Bytes};

    fn authorization() -> (RouteAuthorization, Vec<ProviderRouteCall>) {
        let endpoint = Address::repeat_byte(0x11);
        let calls = vec![ProviderRouteCall {
            target: endpoint,
            amount: U256::from(100u64),
            data: Bytes::from_static(b"payload"),
        }];
        let candidate = RouteCandidate {
            provider: Provider::Chainflip,
            governance: GovernanceBinding {
                provider_id: Provider::Chainflip.id(),
                provider_config_hash: B256::repeat_byte(2),
                asset_id: B256::repeat_byte(3),
                provider_asset_config_hash: B256::repeat_byte(4),
                provider_asset_id: B256::repeat_byte(5),
                execution_asset_id: B256::repeat_byte(6),
                destination_chain: 3,
                destination_token: 5,
                provider_decimals: 8,
                native_decimals: 8,
                endpoint,
                dispatch_mode: 0,
                max_total_cost_bps: 100,
                max_chunks: 256,
                max_stream_duration_seconds: 24 * 60 * 60,
                stream_block_seconds: 0,
                enabled: true,
                asset_enabled: true,
            },
            calls: calls.clone(),
            expected_amount_out: 100_000,
            minimum_amount_out: 99_500,
            reference_amount_out: 100_000,
            chunks: 1,
            stream_duration_seconds: 0,
            observed_at: 1_800_000_000,
            valid_until: 1_800_000_300,
            evidence_hash: B256::repeat_byte(7),
        };
        let route = candidate
            .validate(RoutePolicy::default(), 1_800_000_010)
            .expect("route");
        let authorization = authorization_from_selected(
            0,
            B256::repeat_byte(6),
            Address::repeat_byte(7),
            Address::repeat_byte(8),
            Address::repeat_byte(9),
            Address::repeat_byte(10),
            Address::repeat_byte(11),
            U256::from(100u64),
            1_800_000_010,
            U256::from(12u64),
            &route,
        )
        .expect("authorization");
        (authorization, calls)
    }

    #[test]
    fn typehash_and_domain_are_pinned() {
        assert_eq!(
            RouteAuthorization::eip712_root_type().as_bytes(),
            ROUTE_AUTHORIZATION_TYPE_STRING
        );
        assert_eq!(
            RouteAuthorization::eip712_encode_type().as_bytes(),
            ROUTE_AUTHORIZATION_TYPE_STRING
        );
        assert_eq!(
            route_authorization_typehash(),
            b256!("0xac1250ae2cb1d4e3a85e6d32e6e28612c77c4739d6ace87b049aa0881c6659d5")
        );
        assert_ne!(
            native_route_domain(1, Address::repeat_byte(0xcc)).separator(),
            B256::ZERO
        );
    }

    #[test]
    fn struct_hash_matches_solidity_golden() {
        let authorization = RouteAuthorization {
            kind: 0,
            requestId: B256::repeat_byte(0x11),
            providerId: B256::repeat_byte(0x22),
            providerConfigHash: B256::repeat_byte(0x33),
            assetId: B256::repeat_byte(0x44),
            providerAssetConfigHash: B256::repeat_byte(0x55),
            adapter: Address::repeat_byte(0x11),
            indexToken: Address::repeat_byte(0x22),
            originator: Address::repeat_byte(0x33),
            inputAsset: Address::repeat_byte(0x44),
            outputAsset: Address::repeat_byte(0x55),
            amountIn: U256::from(100u64),
            minAmountOut: U256::from(90u64),
            expectedAmountOut: U256::from(100u64),
            quotedCostBps: 5,
            chunks: 2,
            streamDuration: 18,
            issuedAt: 1_800_000_000,
            validUntil: 1_800_000_300,
            nonce: U256::from(9u64),
            payloadHash: B256::repeat_byte(0x66),
        };
        assert_eq!(
            authorization.eip712_hash_struct(),
            b256!("0x6651595fb73ffab88672893d49a3ec5d7e0971cf2e6ecbd274893c7656b3cc6a")
        );
    }

    #[test]
    fn mint_hints_round_trip_canonically() {
        let (authorization, calls) = authorization();
        let signatures = vec![Bytes::from(vec![0x11; 65]), Bytes::from(vec![0x22; 65])];
        let encoded = encode_mint_route_hints(authorization, &calls, &signatures).expect("hints");
        let decoded = <MintRouteHints as SolValue>::abi_decode(&encoded, true).expect("decode");
        assert_eq!(decoded.calls.len(), 1);
        assert_eq!(decoded.signatures, signatures);
        assert_eq!(decoded.abi_encode(), encoded);
    }
}
