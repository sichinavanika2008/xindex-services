use std::collections::HashSet;

use alloy_primitives::{keccak256, Address, B256};

use crate::NativeRouterError;

/// Rails implemented by the typed payload builders in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Provider {
    Chainflip,
    Maya,
}

impl Provider {
    #[must_use]
    pub fn id(self) -> B256 {
        match self {
            Self::Chainflip => keccak256("CHAINFLIP"),
            Self::Maya => keccak256("MAYA"),
        }
    }
}

/// Canonical table from `@chainflip/utils` 2.2.0 and the EVM vault encoding
/// reference. Runtime availability still comes from `/api/networkInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainflipAssetDescriptor {
    pub internal_asset: &'static str,
    pub chain: &'static str,
    pub symbol: &'static str,
    pub decimals: u8,
    pub destination_chain: u32,
    pub destination_token: u32,
}

impl ChainflipAssetDescriptor {
    #[must_use]
    pub fn canonical_name(self) -> String {
        format!("{}:{}", self.chain, self.symbol)
    }

    #[must_use]
    pub fn provider_asset_id(self) -> B256 {
        keccak256(self.canonical_name())
    }
}

pub const CHAINFLIP_ASSETS: [ChainflipAssetDescriptor; 17] = [
    ChainflipAssetDescriptor {
        internal_asset: "Eth",
        chain: "Ethereum",
        symbol: "ETH",
        decimals: 18,
        destination_chain: 1,
        destination_token: 1,
    },
    ChainflipAssetDescriptor {
        internal_asset: "Flip",
        chain: "Ethereum",
        symbol: "FLIP",
        decimals: 18,
        destination_chain: 1,
        destination_token: 2,
    },
    ChainflipAssetDescriptor {
        internal_asset: "Usdc",
        chain: "Ethereum",
        symbol: "USDC",
        decimals: 6,
        destination_chain: 1,
        destination_token: 3,
    },
    ChainflipAssetDescriptor {
        internal_asset: "Btc",
        chain: "Bitcoin",
        symbol: "BTC",
        decimals: 8,
        destination_chain: 3,
        destination_token: 5,
    },
    ChainflipAssetDescriptor {
        internal_asset: "ArbEth",
        chain: "Arbitrum",
        symbol: "ETH",
        decimals: 18,
        destination_chain: 4,
        destination_token: 6,
    },
    ChainflipAssetDescriptor {
        internal_asset: "ArbUsdc",
        chain: "Arbitrum",
        symbol: "USDC",
        decimals: 6,
        destination_chain: 4,
        destination_token: 7,
    },
    ChainflipAssetDescriptor {
        internal_asset: "Usdt",
        chain: "Ethereum",
        symbol: "USDT",
        decimals: 6,
        destination_chain: 1,
        destination_token: 8,
    },
    ChainflipAssetDescriptor {
        internal_asset: "Sol",
        chain: "Solana",
        symbol: "SOL",
        decimals: 9,
        destination_chain: 5,
        destination_token: 9,
    },
    ChainflipAssetDescriptor {
        internal_asset: "SolUsdc",
        chain: "Solana",
        symbol: "USDC",
        decimals: 6,
        destination_chain: 5,
        destination_token: 10,
    },
    ChainflipAssetDescriptor {
        internal_asset: "HubDot",
        chain: "Assethub",
        symbol: "DOT",
        decimals: 10,
        destination_chain: 6,
        destination_token: 11,
    },
    ChainflipAssetDescriptor {
        internal_asset: "HubUsdt",
        chain: "Assethub",
        symbol: "USDT",
        decimals: 6,
        destination_chain: 6,
        destination_token: 12,
    },
    ChainflipAssetDescriptor {
        internal_asset: "HubUsdc",
        chain: "Assethub",
        symbol: "USDC",
        decimals: 6,
        destination_chain: 6,
        destination_token: 13,
    },
    ChainflipAssetDescriptor {
        internal_asset: "Wbtc",
        chain: "Ethereum",
        symbol: "WBTC",
        decimals: 8,
        destination_chain: 1,
        destination_token: 14,
    },
    ChainflipAssetDescriptor {
        internal_asset: "ArbUsdt",
        chain: "Arbitrum",
        symbol: "USDT",
        decimals: 6,
        destination_chain: 4,
        destination_token: 15,
    },
    ChainflipAssetDescriptor {
        internal_asset: "SolUsdt",
        chain: "Solana",
        symbol: "USDT",
        decimals: 6,
        destination_chain: 5,
        destination_token: 16,
    },
    ChainflipAssetDescriptor {
        internal_asset: "Trx",
        chain: "Tron",
        symbol: "TRX",
        decimals: 6,
        destination_chain: 7,
        destination_token: 17,
    },
    ChainflipAssetDescriptor {
        internal_asset: "TrxUsdt",
        chain: "Tron",
        symbol: "USDT",
        decimals: 6,
        destination_chain: 7,
        destination_token: 18,
    },
];

#[must_use]
pub fn chainflip_asset(internal_asset: &str) -> Option<ChainflipAssetDescriptor> {
    CHAINFLIP_ASSETS
        .iter()
        .copied()
        .find(|asset| asset.internal_asset == internal_asset)
}

/// Normalize the full pool identity returned by Maya's `/pools` endpoint.
/// The protocol's asset notation is case-insensitive, while Xindex hashes one
/// uppercase representation so independent signers cannot diverge on casing.
///
/// # Errors
/// Empty, overlong, memo-breaking or malformed asset notation.
pub fn canonical_maya_asset(raw: &str) -> Result<String, NativeRouterError> {
    if raw.is_empty() || raw.len() > 180 || !raw.is_ascii() {
        return Err(NativeRouterError::InvalidField {
            field: "maya.asset",
            reason: "empty, non-ASCII, or overlong".to_string(),
        });
    }
    let canonical = raw.to_ascii_uppercase();
    let mut parts = canonical.split('.');
    let chain = parts.next().unwrap_or_default();
    let asset = parts.next().unwrap_or_default();
    if chain.is_empty()
        || asset.is_empty()
        || parts.next().is_some()
        || !canonical
            .bytes()
            .all(|character| character.is_ascii_alphanumeric() || b"._-".contains(&character))
    {
        return Err(NativeRouterError::InvalidField {
            field: "maya.asset",
            reason: "invalid full asset notation".to_string(),
        });
    }
    Ok(canonical)
}

/// Maya's quote endpoint reduces EVM token pool identities in memos by
/// dropping the `-contract` suffix and uses the protocol's documented
/// one-character names for native assets. The full pool hash and this exact
/// memo execution hash are deliberately stored separately on-chain.
///
/// # Errors
/// Malformed full asset notation.
pub fn maya_execution_asset(full_asset: &str) -> Result<String, NativeRouterError> {
    let canonical = canonical_maya_asset(full_asset)?;
    let native_short = match canonical.as_str() {
        "THOR.RUNE" => Some("r"),
        "BTC.BTC" => Some("b"),
        "ETH.ETH" => Some("e"),
        "KUJI.KUJI" => Some("k"),
        "DASH.DASH" => Some("d"),
        "MAYA.CACAO" => Some("m"),
        "ARB.ETH" => Some("a"),
        "XRD.XRD" => Some("x"),
        "ZEC.ZEC" => Some("z"),
        _ => None,
    };
    if let Some(short) = native_short {
        return Ok(short.to_string());
    }
    let (chain, asset) =
        canonical
            .split_once('.')
            .ok_or(NativeRouterError::InvalidProviderData(
                "Maya asset lacks chain separator",
            ))?;
    let symbol = asset.split_once('-').map_or(asset, |(symbol, _)| symbol);
    if symbol.is_empty() {
        return Err(NativeRouterError::InvalidProviderData(
            "Maya memo asset symbol is empty",
        ));
    }
    Ok(format!("{chain}.{symbol}"))
}

/// Extract the exact Ethereum ERC-20 contract embedded in a Maya pool ID.
/// Native `ETH.ETH` and symbol-only aliases are intentionally unsupported by
/// the ERC-20 Router builder.
///
/// # Errors
/// Non-Ethereum/native assets, a missing contract suffix, zero address or a
/// malformed 20-byte contract.
pub fn maya_evm_token_address(full_asset: &str) -> Result<Address, NativeRouterError> {
    let canonical = canonical_maya_asset(full_asset)?;
    let (chain, asset) =
        canonical
            .split_once('.')
            .ok_or(NativeRouterError::InvalidProviderData(
                "Maya asset lacks chain separator",
            ))?;
    let (symbol, contract) = asset
        .rsplit_once('-')
        .ok_or(NativeRouterError::UnsupportedAsset(canonical.clone()))?;
    if chain != "ETH" || symbol.is_empty() || contract.len() != 42 || !contract.starts_with("0X") {
        return Err(NativeRouterError::UnsupportedAsset(canonical));
    }
    let normalized = format!("0x{}", &contract[2..]);
    let address = normalized
        .parse::<Address>()
        .map_err(|_| NativeRouterError::InvalidField {
            field: "maya.fromAsset",
            reason: "invalid Ethereum token contract".to_string(),
        })?;
    if address == Address::ZERO {
        return Err(NativeRouterError::InvalidField {
            field: "maya.fromAsset",
            reason: "zero Ethereum token contract".to_string(),
        });
    }
    Ok(address)
}

/// Return aliases that identify more than one available Maya pool. Ambiguous
/// aliases are surfaced in the catalog but never eligible for signing.
#[must_use]
pub fn ambiguous_maya_execution_assets<'a>(
    full_assets: impl IntoIterator<Item = &'a str>,
) -> HashSet<String> {
    let mut seen = HashSet::new();
    let mut ambiguous = HashSet::new();
    for full_asset in full_assets {
        if let Ok(alias) = maya_execution_asset(full_asset) {
            if !seen.insert(alias.clone()) {
                ambiguous.insert(alias);
            }
        }
    }
    ambiguous
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures must fail loudly")]

    use std::collections::HashSet;

    use super::*;

    #[test]
    fn chainflip_table_covers_every_current_contract_id_once() {
        assert_eq!(CHAINFLIP_ASSETS.len(), 17);
        assert_eq!(
            CHAINFLIP_ASSETS
                .iter()
                .map(|asset| asset.internal_asset)
                .collect::<HashSet<_>>()
                .len(),
            17
        );
        assert_eq!(
            CHAINFLIP_ASSETS
                .iter()
                .map(|asset| asset.destination_token)
                .collect::<HashSet<_>>()
                .len(),
            17
        );
        assert!(!CHAINFLIP_ASSETS
            .iter()
            .any(|asset| asset.destination_token == 4));
        assert_eq!(chainflip_asset("Btc").map(|asset| asset.decimals), Some(8));
        assert_eq!(
            chainflip_asset("HubDot").map(|asset| asset.destination_chain),
            Some(6)
        );
    }

    #[test]
    fn maya_full_pool_and_execution_alias_are_distinct() {
        let full = "arb.usdc-0xaf88d065e77c8cc2239327c5edb3a432268e5831";
        assert_eq!(
            canonical_maya_asset(full).expect("valid fixture"),
            "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831"
        );
        assert_eq!(
            maya_execution_asset(full).expect("valid fixture"),
            "ARB.USDC"
        );
        assert_eq!(
            maya_evm_token_address("ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7")
                .expect("Ethereum token"),
            "0xdac17f958d2ee523a2206206994597c13d831ec7"
                .parse::<Address>()
                .expect("address")
        );
        assert!(maya_evm_token_address("ETH.ETH").is_err());
    }

    #[test]
    fn ambiguous_maya_aliases_are_detected() {
        let assets = [
            "ARB.USDC-0X1111111111111111111111111111111111111111",
            "ARB.USDC-0X2222222222222222222222222222222222222222",
            "BTC.BTC",
        ];
        assert_eq!(
            ambiguous_maya_execution_assets(assets),
            HashSet::from(["ARB.USDC".to_string()])
        );
    }

    #[test]
    fn maya_native_memo_names_match_documented_shortening() {
        let cases = [
            ("THOR.RUNE", "r"),
            ("BTC.BTC", "b"),
            ("ETH.ETH", "e"),
            ("KUJI.KUJI", "k"),
            ("DASH.DASH", "d"),
            ("MAYA.CACAO", "m"),
            ("ARB.ETH", "a"),
            ("XRD.XRD", "x"),
            ("ZEC.ZEC", "z"),
        ];
        for (full, short) in cases {
            assert_eq!(maya_execution_asset(full).expect("short asset"), short);
        }
        assert_eq!(
            maya_execution_asset("ADA.ADA").expect("full asset"),
            "ADA.ADA"
        );
    }
}
