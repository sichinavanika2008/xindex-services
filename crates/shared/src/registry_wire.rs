//! Lossless wire messages for independently produced `THORChain` registry
//! signatures. Numeric EVM values use decimal strings; every collector
//! recomputes the EIP-712 digest and recovers the signer before counting it.

use serde::{Deserialize, Serialize};

/// One operator's signature over the complete `InboundState` plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedInboundStateMessage {
    pub vault: String,
    pub router: String,
    pub pause_flags: u8,
    pub observed_at: u64,
    pub valid_until: u64,
    pub sequence: u64,
    pub source_hash: String,
    pub signer_address: String,
    pub signature: String,
}

/// One operator's signature over the complete `QuoteAuthorization` plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedQuoteAuthorizationMessage {
    pub adapter: String,
    pub index_token: String,
    pub originator: String,
    pub funding_token: String,
    pub target_token: String,
    pub amount_in: String,
    pub custody_hash: String,
    pub inbound_state_hash: String,
    pub memo_hash: String,
    pub dispatch_deadline: u64,
    pub quote_nonce: u64,
    pub quote_hash: String,
    pub signer_address: String,
    pub signature: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(clippy::expect_used, reason = "test fixture")]
    fn quote_uint256_round_trip_is_lossless() {
        let message = SignedQuoteAuthorizationMessage {
            adapter: format!("0x{}", "11".repeat(20)),
            index_token: format!("0x{}", "22".repeat(20)),
            originator: format!("0x{}", "33".repeat(20)),
            funding_token: format!("0x{}", "44".repeat(20)),
            target_token: format!("0x{}", "55".repeat(20)),
            amount_in:
                "115792089237316195423570985008687907853269984665640564039457584007913129639935"
                    .to_string(),
            custody_hash: format!("0x{}", "66".repeat(32)),
            inbound_state_hash: format!("0x{}", "77".repeat(32)),
            memo_hash: format!("0x{}", "88".repeat(32)),
            dispatch_deadline: 1_800_000_060,
            quote_nonce: 9,
            quote_hash: format!("0x{}", "99".repeat(32)),
            signer_address: format!("0x{}", "aa".repeat(20)),
            signature: format!("0x{}", "bb".repeat(65)),
        };
        let encoded = serde_json::to_string(&message).expect("serialize");
        assert_eq!(
            serde_json::from_str::<SignedQuoteAuthorizationMessage>(&encoded).expect("deserialize"),
            message
        );
    }

    #[test]
    fn inbound_unknown_fields_fail_closed() {
        let raw = format!(
            r#"{{"vault":"0x{}","router":"0x{}","pauseFlags":0,"observedAt":1,"validUntil":2,"sequence":3,"sourceHash":"0x{}","signerAddress":"0x{}","signature":"0x{}","paused":false}}"#,
            "11".repeat(20),
            "22".repeat(20),
            "33".repeat(32),
            "44".repeat(20),
            "55".repeat(65)
        );
        assert!(serde_json::from_str::<SignedInboundStateMessage>(&raw).is_err());
    }
}
