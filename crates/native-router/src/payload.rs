use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::{sol, SolCall, SolValue};

use crate::catalog::ChainflipAssetDescriptor;
use crate::chainflip::{parse_address, EncodedVaultSwapData};
use crate::maya::ValidatedMayaQuote;
use crate::NativeRouterError;

sol! {
    interface IChainflipVault {
        function xSwapToken(
            uint32 dstChain,
            bytes dstAddress,
            uint32 dstToken,
            address srcToken,
            uint256 amount,
            bytes cfParameters
        ) external;
    }

    interface IMayaRouter {
        function depositWithExpiry(
            address payable vault,
            address asset,
            uint256 amount,
            string calldata memo,
            uint256 expiration
        ) external;
    }

    struct SolRouteCall {
        address target;
        uint256 amount;
        bytes data;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCall {
    pub target: Address,
    pub amount: U256,
    pub data: Bytes,
}

impl From<&RouteCall> for SolRouteCall {
    fn from(value: &RouteCall) -> Self {
        Self {
            target: value.target,
            amount: value.amount,
            data: value.data.clone(),
        }
    }
}

/// Validate the exact outer Ethereum Vault call returned by independently
/// agreeing Chainflip encoders. The evolving `cfParameters` bytes remain
/// opaque to Solidity; signers retain and validate the encoding requests and
/// require byte-identical encoder output before this function is called.
///
/// # Errors
/// Non-Ethereum response, non-zero ETH value, endpoint/source-token mismatch,
/// non-canonical ABI, wrong destination IDs/amount, or unbounded empty fields.
pub fn chainflip_route_call(
    encoded: &EncodedVaultSwapData,
    pinned_vault: Address,
    source_token: Address,
    amount: U256,
    destination: ChainflipAssetDescriptor,
    expected_destination_address: &[u8],
) -> Result<RouteCall, NativeRouterError> {
    if pinned_vault == Address::ZERO
        || source_token == Address::ZERO
        || amount.is_zero()
        || expected_destination_address.is_empty()
        || expected_destination_address.len() > 256
    {
        return Err(NativeRouterError::Policy(
            "invalid Chainflip endpoint, source token, amount, or destination",
        ));
    }
    let EncodedVaultSwapData::Ethereum {
        value,
        to,
        calldata,
        source_token_address,
    } = encoded
    else {
        return Err(NativeRouterError::InvalidProviderData(
            "Chainflip source encoding is not Ethereum",
        ));
    };
    if value != "0"
        || parse_address(to, "chainflip.to")? != pinned_vault
        || source_token_address
            .as_deref()
            .map(|raw| parse_address(raw, "chainflip.sourceTokenAddress"))
            .transpose()?
            != Some(source_token)
    {
        return Err(NativeRouterError::InvalidProviderData(
            "Chainflip Ethereum envelope differs from pinned route",
        ));
    }
    let data = decode_hex(calldata, "chainflip.calldata")?;
    if data.len() > 4096 {
        return Err(NativeRouterError::Policy(
            "Chainflip calldata exceeds adapter bound",
        ));
    }
    let call = IChainflipVault::xSwapTokenCall::abi_decode(&data, true)
        .map_err(|_| NativeRouterError::InvalidCalldata)?;
    if call.abi_encode() != data
        || call.dstChain != destination.destination_chain
        || call.dstToken != destination.destination_token
        || call.dstAddress.as_ref() != expected_destination_address
        || call.srcToken != source_token
        || call.amount != amount
        || call.dstAddress.is_empty()
        || call.dstAddress.len() > 256
        || call.cfParameters.is_empty()
    {
        return Err(NativeRouterError::InvalidCalldata);
    }
    Ok(RouteCall {
        target: pinned_vault,
        amount,
        data: Bytes::from(data),
    })
}

/// Build the sole canonical Ethereum `depositWithExpiry` call from a fully
/// validated Maya quote and independent inbound consensus.
///
/// # Errors
/// Invalid/mismatched Router or vault address, zero token/amount, or calldata
/// exceeding the adapter bound.
pub fn maya_route_call(
    quote: &ValidatedMayaQuote,
    pinned_router: Address,
    source_token: Address,
    amount_input_native_units: U256,
) -> Result<RouteCall, NativeRouterError> {
    if pinned_router == Address::ZERO
        || source_token == Address::ZERO
        || amount_input_native_units.is_zero()
    {
        return Err(NativeRouterError::Policy(
            "zero Maya Router, source token, or amount",
        ));
    }
    let router = parse_address(&quote.router, "maya.router")?;
    let vault = parse_address(&quote.vault, "maya.vault")?;
    if router != pinned_router || vault == Address::ZERO {
        return Err(NativeRouterError::SourceDisagreement(
            "Maya quote and pinned Router",
        ));
    }
    let data = IMayaRouter::depositWithExpiryCall {
        vault,
        asset: source_token,
        amount: amount_input_native_units,
        memo: quote.memo.clone(),
        expiration: U256::from(quote.expiry),
    }
    .abi_encode();
    if data.len() > 4096 {
        return Err(NativeRouterError::Policy(
            "Maya calldata exceeds adapter bound",
        ));
    }
    Ok(RouteCall {
        target: pinned_router,
        amount: amount_input_native_units,
        data: Bytes::from(data),
    })
}

/// Solidity parity for `keccak256(abi.encode(RouteCall[]))`.
#[must_use]
pub fn route_calls_hash(calls: &[RouteCall]) -> B256 {
    let solidity = calls.iter().map(SolRouteCall::from).collect::<Vec<_>>();
    keccak256(solidity.abi_encode())
}

fn decode_hex(raw: &str, field: &'static str) -> Result<Vec<u8>, NativeRouterError> {
    let value = raw
        .strip_prefix("0x")
        .ok_or(NativeRouterError::InvalidField {
            field,
            reason: "missing 0x prefix".to_string(),
        })?;
    alloy_primitives::hex::decode(value).map_err(|_| NativeRouterError::InvalidField {
        field,
        reason: "invalid hex".to_string(),
    })
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures must fail loudly")]

    use super::*;
    use crate::catalog::chainflip_asset;

    #[test]
    fn chainflip_response_is_decoded_and_rebound() {
        let vault = Address::repeat_byte(0x11);
        let source = Address::repeat_byte(0x22);
        let amount = U256::from(100_000_000u64);
        let destination = chainflip_asset("Btc").expect("asset");
        let calldata = IChainflipVault::xSwapTokenCall {
            dstChain: destination.destination_chain,
            dstAddress: Bytes::from_static(b"destination"),
            dstToken: destination.destination_token,
            srcToken: source,
            amount,
            cfParameters: Bytes::from_static(b"official-encoding"),
        }
        .abi_encode();
        let encoded = EncodedVaultSwapData::Ethereum {
            value: "0".to_string(),
            to: format!("{vault:#x}"),
            calldata: format!("0x{}", alloy_primitives::hex::encode(calldata)),
            source_token_address: Some(format!("{source:#x}")),
        };
        let route =
            chainflip_route_call(&encoded, vault, source, amount, destination, b"destination")
                .expect("valid response");
        assert_eq!(route.target, vault);
        assert_eq!(route.amount, amount);
        assert_ne!(route_calls_hash(&[route]), B256::ZERO);
    }

    #[test]
    fn chainflip_wrong_destination_id_rejects() {
        let vault = Address::repeat_byte(0x11);
        let source = Address::repeat_byte(0x22);
        let amount = U256::from(100u64);
        let calldata = IChainflipVault::xSwapTokenCall {
            dstChain: 1,
            dstAddress: Bytes::from_static(b"destination"),
            dstToken: 1,
            srcToken: source,
            amount,
            cfParameters: Bytes::from_static(b"parameters"),
        }
        .abi_encode();
        let encoded = EncodedVaultSwapData::Ethereum {
            value: "0".to_string(),
            to: format!("{vault:#x}"),
            calldata: format!("0x{}", alloy_primitives::hex::encode(calldata)),
            source_token_address: Some(format!("{source:#x}")),
        };
        assert!(chainflip_route_call(
            &encoded,
            vault,
            source,
            amount,
            chainflip_asset("Btc").expect("asset"),
            b"destination"
        )
        .is_err());

        assert!(chainflip_route_call(
            &encoded,
            vault,
            source,
            amount,
            chainflip_asset("Eth").expect("asset"),
            b"different-destination"
        )
        .is_err());
    }
}
