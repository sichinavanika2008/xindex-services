//! Wire format for independently-produced NAV price attestations.
//!
//! Numeric EVM values are decimal strings rather than JSON numbers. This keeps
//! the full `uint256` range lossless across operators and makes the exact
//! plaintext being quorum-grouped explicit. The collector still recomputes the
//! EIP-712 digest and recovers the signer; none of these fields are trusted just
//! because they decoded successfully.

use serde::{Deserialize, Serialize};

/// One price signer's independently-produced, recoverable EIP-712 signature.
///
/// `assetId`, `priceWad`, `supply`, and `timestamp` are the complete
/// `PriceAttestation` plaintext. A collector MUST group on all four fields and
/// MUST NOT combine signatures from merely "close" prices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPriceMessage {
    /// Registry asset id (`bytes32`, 0x-prefixed hex).
    pub asset_id: String,
    /// Canonicalized WAD price (`uint256`, decimal string).
    pub price_wad: String,
    /// Canonicalized raw circulating supply (`uint256`, decimal string).
    pub supply: String,
    /// Deterministic observation epoch (unix seconds).
    pub timestamp: u64,
    /// Address expected to recover from `signature` (0x-prefixed hex).
    pub signer_address: String,
    /// Recoverable ECDSA signature (`r || s || v`, 65-byte 0x-prefixed hex).
    pub signature: String,
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]

    use super::*;

    #[test]
    fn round_trip_keeps_supply_and_uint256_values_lossless() {
        let msg = SignedPriceMessage {
            asset_id: format!("0x{}", "ab".repeat(32)),
            price_wad:
                "115792089237316195423570985008687907853269984665640564039457584007913129639935"
                    .to_string(),
            supply: "2100000000000000".to_string(),
            timestamp: 1_800_000_000,
            signer_address: format!("0x{}", "12".repeat(20)),
            signature: format!("0x{}", "34".repeat(65)),
        };
        let json = serde_json::to_string(&msg).expect("serialize");
        assert!(json.contains("\"supply\":\"2100000000000000\""));
        assert_eq!(
            serde_json::from_str::<SignedPriceMessage>(&json).expect("deserialize"),
            msg
        );
    }

    #[test]
    fn unknown_fields_fail_closed() {
        let json = format!(
            r#"{{"assetId":"0x{}","priceWad":"1","supply":"1","timestamp":1,"signerAddress":"0x{}","signature":"0x{}","price":"2"}}"#,
            "ab".repeat(32),
            "12".repeat(20),
            "34".repeat(65)
        );
        assert!(serde_json::from_str::<SignedPriceMessage>(&json).is_err());
    }
}
