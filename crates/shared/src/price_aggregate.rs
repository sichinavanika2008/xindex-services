//! Robust off-chain price aggregation for the NAV oracle (workstream A,
//! `DL-INDEX-METHOD-ORACLE-1`).
//!
//! Each k-of-n price signer fetches the SAME asset price from MULTIPLE
//! independent venues and combines them here into one manipulation-resistant
//! value before it signs a [`PriceAttestation`](crate::eip712::PriceAttestation).
//! A single (or minority) corrupted / illiquid / stale venue is rejected as an
//! outlier; if too few venues agree, aggregation **fails closed** (the signer
//! must NOT sign) — the off-chain analogue of the on-chain L1 bounds / L2
//! Chainlink-divergence guards. Pure `U256` math, no I/O, so the security
//! properties are exhaustively unit-tested.

use alloy_primitives::U256;
use thiserror::Error;

/// Basis-points denominator (100% = 10000 bps).
const BPS: u64 = 10_000;

/// Why aggregation refused to produce a price. Every variant is fail-closed:
/// the caller MUST NOT sign a price when aggregation errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AggregateError {
    /// Fewer venue quotes than the configured floor.
    #[error("too few venue quotes: {got} < required {min}")]
    TooFewVenues {
        /// Number of quotes supplied.
        got: usize,
        /// Required minimum.
        min: usize,
    },
    /// After discarding outliers, too few quotes remained within the band —
    /// the venues do not agree, so no price is trustworthy.
    #[error("no consensus: {survivors} quotes within {max_deviation_bps} bps of median < required {min}")]
    NoConsensus {
        /// Quotes that survived the outlier filter.
        survivors: usize,
        /// Required minimum.
        min: usize,
        /// The band half-width used.
        max_deviation_bps: u32,
    },
    /// A venue reported a zero price — a feed error; refuse the whole batch.
    #[error("a venue quote was zero")]
    ZeroQuote,
}

/// Combine independent venue price quotes (each a WAD-scaled price for the
/// SAME asset) into one robust price.
///
/// 1. Require at least `min_venues` (clamped to ≥1) quotes, else
///    [`AggregateError::TooFewVenues`]; reject a zero quote
///    ([`AggregateError::ZeroQuote`]).
/// 2. Take the median of all quotes as the reference.
/// 3. Discard every quote deviating more than `max_deviation_bps` from that
///    reference (an outlier / manipulated venue).
/// 4. Require at least `min_venues` survivors, else
///    [`AggregateError::NoConsensus`].
/// 5. Return the median of the survivors.
///
/// # Errors
/// Fails CLOSED with [`AggregateError`] when consensus is insufficient.
pub fn aggregate_price(
    quotes: &[U256],
    min_venues: usize,
    max_deviation_bps: u32,
) -> Result<U256, AggregateError> {
    let min = min_venues.max(1);
    if quotes.len() < min {
        return Err(AggregateError::TooFewVenues {
            got: quotes.len(),
            min,
        });
    }
    if quotes.iter().any(U256::is_zero) {
        return Err(AggregateError::ZeroQuote);
    }
    let reference = median(quotes);
    let survivors: Vec<U256> = quotes
        .iter()
        .copied()
        .filter(|&q| within_bps(q, reference, max_deviation_bps))
        .collect();
    if survivors.len() < min {
        return Err(AggregateError::NoConsensus {
            survivors: survivors.len(),
            min,
            max_deviation_bps,
        });
    }
    Ok(median(&survivors))
}

/// Median of a NON-EMPTY slice (callers guarantee non-empty via the
/// `min_venues ≥ 1` floor). Sorts a copy; even counts average the two middle.
fn median(values: &[U256]) -> U256 {
    let mut v = values.to_vec();
    v.sort_unstable();
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        avg(v[n / 2 - 1], v[n / 2])
    }
}

/// `(a + b) / 2` (rounding down) without overflowing `U256` — `a + b` can
/// exceed `U256::MAX`. The carry bit is 1 only when both operands are odd.
fn avg(a: U256, b: U256) -> U256 {
    (a >> 1) + (b >> 1) + (a & b & U256::from(1u8))
}

/// Is `q` within `bps` of `reference`? Cross-multiplied to avoid precision
/// loss / division: `|q - reference| * BPS <= reference * bps`.
/// `saturating_mul` is a safety net (realistic WAD prices never saturate).
fn within_bps(q: U256, reference: U256, bps: u32) -> bool {
    let diff = if q > reference {
        q - reference
    } else {
        reference - q
    };
    diff.saturating_mul(U256::from(BPS)) <= reference.saturating_mul(U256::from(bps))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(n: u64) -> U256 {
        U256::from(n)
    }

    #[test]
    fn agreeing_venues_return_median() {
        assert_eq!(
            aggregate_price(&[u(100), u(101), u(102)], 3, 5000),
            Ok(u(101))
        );
    }

    #[test]
    fn single_outlier_is_rejected() {
        // 1000 is a 10x manipulated venue; rejected, median of the honest four.
        assert_eq!(
            aggregate_price(&[u(100), u(100), u(100), u(100), u(1000)], 3, 5000),
            Ok(u(100))
        );
    }

    #[test]
    fn too_few_venues_fails_closed() {
        assert_eq!(
            aggregate_price(&[u(100), u(100)], 3, 5000),
            Err(AggregateError::TooFewVenues { got: 2, min: 3 })
        );
    }

    #[test]
    fn no_consensus_fails_closed() {
        // median 100; band ±50% = [50,150]; the 10000 outlier leaves only 2
        // survivors < min 3 → no trustworthy price.
        assert_eq!(
            aggregate_price(&[u(100), u(100), u(10_000)], 3, 5000),
            Err(AggregateError::NoConsensus {
                survivors: 2,
                min: 3,
                max_deviation_bps: 5000
            })
        );
    }

    #[test]
    fn zero_quote_is_rejected() {
        assert_eq!(
            aggregate_price(&[u(100), u(0), u(100)], 3, 5000),
            Err(AggregateError::ZeroQuote)
        );
    }

    #[test]
    fn even_count_averages_two_middle() {
        // sorted [100,200,300,400] → avg(200,300) = 250.
        assert_eq!(
            aggregate_price(&[u(400), u(100), u(300), u(200)], 2, 9000),
            Ok(u(250))
        );
    }

    #[test]
    fn min_venues_clamped_to_one() {
        // min_venues 0 is treated as 1; an empty slice still fails closed
        // rather than panicking in `median`.
        assert_eq!(
            aggregate_price(&[], 0, 5000),
            Err(AggregateError::TooFewVenues { got: 0, min: 1 })
        );
        assert_eq!(aggregate_price(&[u(7)], 0, 5000), Ok(u(7)));
    }

    #[test]
    fn within_bps_boundary_is_inclusive() {
        // reference 100, 10% band: 110 is exactly on the edge (within), 111 is
        // outside. Use min 1 so the survivor set is just the edge quote.
        assert!(within_bps(u(110), u(100), 1000));
        assert!(!within_bps(u(111), u(100), 1000));
        assert!(within_bps(u(90), u(100), 1000));
        assert!(!within_bps(u(89), u(100), 1000));
    }

    #[test]
    fn avg_does_not_overflow_near_u256_max() {
        let max = U256::MAX;
        assert_eq!(avg(max, max), max);
        // two large evens: avg is their midpoint, no overflow.
        let big = max - U256::from(3u8); // even (MAX is odd)
        assert_eq!(avg(big, big), big);
        assert_eq!(avg(U256::from(2u8), U256::from(4u8)), U256::from(3u8));
        // both odd → carry: avg(3,5) = 4.
        assert_eq!(avg(U256::from(3u8), U256::from(5u8)), U256::from(4u8));
    }
}
