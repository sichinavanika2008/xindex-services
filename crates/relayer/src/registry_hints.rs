//! Canonical ABI encoding for `ThorchainAdapter.AcquireHints`.

use std::str::FromStr;

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolValue};
use thiserror::Error;
use xindex_chain_thor::QuoteCandidate;

use crate::registry_collector::ReadyQuote;

sol! {
    struct AcquireHints {
        uint256 minOutNative;
        bytes32 expectedCustodyHash;
        bytes32 expectedInboundHash;
        uint64 dispatchDeadline;
        uint256 interval;
        uint256 quantity;
        uint64 quoteNonce;
        bytes32 quoteHash;
        bytes[] quoteSignatures;
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryHintError {
    #[error("invalid candidate field: {0}")]
    InvalidField(&'static str),
    #[error("quorum payload differs from the common candidate")]
    PayloadMismatch,
}

/// Match the quorum-recovered plaintext against the common candidate and
/// return the sole canonical ABI encoding accepted by the adapter.
///
/// # Errors
/// Malformed candidate integers/addresses or any payload mismatch.
pub fn encode_acquire_hints(
    candidate: &QuoteCandidate,
    ready: &ReadyQuote,
) -> Result<Bytes, RegistryHintError> {
    let expected = quote_payload_from_candidate(candidate)?;
    let min_out = U256::from_str_radix(&candidate.decision.min_out_1e8, 10)
        .map_err(|_| RegistryHintError::InvalidField("minOutNative"))?;
    if min_out.is_zero() {
        return Err(RegistryHintError::InvalidField("minOutNative"));
    }
    let payload = ready.payload;
    if payload != expected {
        return Err(RegistryHintError::PayloadMismatch);
    }
    let hints = AcquireHints {
        minOutNative: min_out,
        expectedCustodyHash: candidate.custody_hash,
        expectedInboundHash: candidate.inbound_state_hash,
        dispatchDeadline: candidate.decision.dispatch_deadline,
        interval: U256::from(candidate.evidence.request.streaming_interval),
        quantity: U256::from(candidate.evidence.request.streaming_quantity),
        quoteNonce: expected.quote_nonce,
        quoteHash: candidate.decision.quote_hash,
        quoteSignatures: ready.signatures.iter().copied().map(Bytes::from).collect(),
    };
    Ok(Bytes::from(hints.abi_encode()))
}

/// Reconstruct the exact signed quote plaintext from a common candidate.
///
/// # Errors
/// Malformed address/integer fields or nonce exhaustion.
pub fn quote_payload_from_candidate(
    candidate: &QuoteCandidate,
) -> Result<crate::registry_collector::QuotePayload, RegistryHintError> {
    Ok(crate::registry_collector::QuotePayload {
        adapter: parse_address(&candidate.adapter)?,
        index_token: parse_address(&candidate.index_token)?,
        originator: parse_address(&candidate.originator)?,
        funding_token: parse_address(&candidate.funding_token)?,
        target_token: parse_address(&candidate.target_token)?,
        amount_in: U256::from_str_radix(&candidate.amount_in, 10)
            .map_err(|_| RegistryHintError::InvalidField("amountIn"))?,
        custody_hash: candidate.custody_hash,
        inbound_state_hash: candidate.inbound_state_hash,
        memo_hash: alloy_primitives::keccak256(candidate.decision.memo.as_bytes()),
        dispatch_deadline: candidate.decision.dispatch_deadline,
        quote_nonce: candidate
            .finalized_onchain_nonce
            .checked_add(1)
            .ok_or(RegistryHintError::InvalidField("quoteNonce"))?,
        quote_hash: candidate.decision.quote_hash,
    })
}

fn parse_address(raw: &str) -> Result<Address, RegistryHintError> {
    Address::from_str(raw).map_err(|_| RegistryHintError::InvalidField("address"))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use alloy_primitives::B256;
    use xindex_chain_thor::{
        QuoteDecision, QuoteEvidence, SwapQuoteFees, SwapQuoteRequest, SwapQuoteResponse,
    };

    use super::*;
    use crate::registry_collector::QuotePayload;

    fn fixture() -> (QuoteCandidate, ReadyQuote) {
        let adapter = Address::repeat_byte(1);
        let index_token = Address::repeat_byte(2);
        let originator = Address::repeat_byte(3);
        let funding_token = Address::repeat_byte(4);
        let target_token = Address::repeat_byte(5);
        let custody = B256::repeat_byte(6);
        let inbound = B256::repeat_byte(7);
        let quote_hash = B256::repeat_byte(8);
        let memo = format!("=:BTC.BTC:bc1qcustody/{originator:#x}:990000/1/1");
        let candidate = QuoteCandidate {
            evidence: QuoteEvidence {
                schema: "xindex.thorchain-quote-evidence.v1".to_string(),
                quote_source_id: "coordinator".to_string(),
                request: SwapQuoteRequest {
                    from_asset: "ETH.USDT-0XDAC17F".to_string(),
                    to_asset: "BTC.BTC".to_string(),
                    amount: "100000000".to_string(),
                    destination: "bc1qcustody".to_string(),
                    refund_address: format!("{originator:#x}"),
                    liquidity_tolerance_bps: 100,
                    streaming_interval: 1,
                    streaming_quantity: 1,
                },
                response: SwapQuoteResponse {
                    inbound_address: format!("{:#x}", Address::repeat_byte(9)),
                    inbound_confirmation_blocks: 1,
                    inbound_confirmation_seconds: 1,
                    outbound_delay_blocks: 1,
                    outbound_delay_seconds: 1,
                    fees: SwapQuoteFees {
                        asset: "BTC.BTC".to_string(),
                        affiliate: "0".to_string(),
                        outbound: "1".to_string(),
                        liquidity: "1".to_string(),
                        total: "2".to_string(),
                        slippage_bps: 1,
                        total_bps: 2,
                    },
                    expiry: 2_000,
                    warning: "fresh".to_string(),
                    dust_threshold: "1".to_string(),
                    recommended_min_amount_in: "1".to_string(),
                    recommended_gas_rate: "1".to_string(),
                    gas_rate_units: "gwei".to_string(),
                    memo: memo.clone(),
                    expected_amount_out: "1000000".to_string(),
                    max_streaming_quantity: 1,
                    streaming_swap_blocks: 0,
                    streaming_swap_seconds: 0,
                    total_swap_seconds: 1,
                },
                raw_quote_hash: B256::repeat_byte(10),
                external_prices: Vec::new(),
            },
            raw_quote_body: "{}".to_string(),
            decision: QuoteDecision {
                min_out_1e8: "990000".to_string(),
                memo: memo.clone(),
                dispatch_deadline: 1_900,
                quote_hash,
            },
            adapter: format!("{adapter:#x}"),
            index_token: format!("{index_token:#x}"),
            originator: format!("{originator:#x}"),
            funding_token: format!("{funding_token:#x}"),
            target_token: format!("{target_token:#x}"),
            amount_in: "1000000".to_string(),
            custody_hash: custody,
            inbound_state_hash: inbound,
            current_state_valid_until: 2_000,
            finalized_onchain_nonce: 4,
        };
        let ready = ReadyQuote {
            payload: QuotePayload {
                adapter,
                index_token,
                originator,
                funding_token,
                target_token,
                amount_in: U256::from(1_000_000u64),
                custody_hash: custody,
                inbound_state_hash: inbound,
                memo_hash: alloy_primitives::keccak256(memo.as_bytes()),
                dispatch_deadline: 1_900,
                quote_nonce: 5,
                quote_hash,
            },
            signatures: vec![[1u8; 65], [2u8; 65], [3u8; 65]],
        };
        (candidate, ready)
    }

    #[test]
    fn canonical_hints_round_trip_and_payload_mismatch_refuses() {
        let (candidate, mut ready) = fixture();
        let encoded = encode_acquire_hints(&candidate, &ready).expect("encode");
        let decoded = AcquireHints::abi_decode(&encoded, true).expect("canonical decode");
        assert_eq!(decoded.minOutNative, U256::from(990_000u64));
        assert_eq!(decoded.quoteNonce, 5);
        assert_eq!(decoded.quoteSignatures.len(), 3);

        ready.payload.memo_hash = B256::repeat_byte(0xff);
        assert_eq!(
            encode_acquire_hints(&candidate, &ready),
            Err(RegistryHintError::PayloadMismatch)
        );
    }
}
