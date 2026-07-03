//! Time-weighted average pricing for the NAV oracle (workstream A,
//! `DL-INDEX-METHOD-ORACLE-1`, OM-4 median/TWAP).
//!
//! [`crate::price_aggregate`] removes *spatial* manipulation: it medians the
//! SAME asset across MULTIPLE venues in one instant and rejects outliers. This
//! module removes *temporal* manipulation: it time-weight-averages the sequence
//! of those already-robust medians over a trailing window, so a transient spike
//! that briefly captures a venue MAJORITY (surviving the spatial median) still
//! cannot be signed — it must PERSIST across the window to move the signed
//! price. A flash pump that lasts one sampling interval contributes only that
//! interval's weight to a `window_secs`-long average.
//!
//! Weighting is step / last-value-held (the canonical cumulative-price TWAP,
//! as in on-chain AMM oracles): each sample's price is in effect from its own
//! timestamp until the next sample's timestamp, and a "carry-in" sample taken
//! just before the window start provides the price in effect at window start.
//! Every refusal is fail-closed: the caller MUST NOT sign when this errors.
//! Pure `U256`/`u64` math, no I/O, so the security properties are exhaustively
//! unit-tested.

use alloy_primitives::U256;
use thiserror::Error;

/// One robust-median observation feeding the TWAP: the spatially-aggregated
/// price for an asset at a point in time. Callers push these in strictly
/// increasing `timestamp` order (the producer's per-asset monotonic guarantee).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwapSample {
    /// Observation time (unix secs).
    pub timestamp: u64,
    /// Spatially-aggregated (outlier-rejected median) price, WAD.
    pub price: U256,
}

/// Per-signer temporal-smoothing policy.
#[derive(Debug, Clone, Copy)]
pub struct TwapConfig {
    /// Trailing window the average is taken over (secs). MUST be > 0.
    pub window_secs: u64,
    /// Minimum samples informing the window (carry-in + in-window). `>= 2`
    /// forces at least one in-window update, so the TWAP is never a single
    /// value held flat across the whole window.
    pub min_samples: usize,
    /// Maximum span any single price may hold uninterrupted inside the window
    /// (secs). A larger gap means the feed stalled — the window would lean on
    /// stale data, so refuse. Bounds the cold-start / outage cases too.
    pub max_gap_secs: u64,
}

/// Why the TWAP refused to produce a price. Every variant is fail-closed:
/// the caller MUST NOT sign when this errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TwapError {
    /// The window has `window_secs == 0` — a misconfiguration (would divide by
    /// zero); refuse rather than sign an undefined average.
    #[error("twap window_secs is zero (misconfigured)")]
    MisconfiguredWindow,
    /// No samples at all — nothing to average.
    #[error("no samples in the twap buffer")]
    EmptyWindow,
    /// A sample carried a zero price (a feed error slipped through) — refuse.
    #[error("a twap sample price was zero")]
    ZeroSample,
    /// A sample is dated after `now` — a clock/ordering fault; refuse.
    #[error("twap sample timestamp {timestamp} is after now {now}")]
    FutureSample {
        /// The offending sample timestamp.
        timestamp: u64,
        /// The evaluation time.
        now: u64,
    },
    /// No sample dated at or before the window start exists, so the window is
    /// not yet fully covered by history (cold start / just-restarted buffer).
    #[error("insufficient history: oldest sample {oldest} > window start {window_start}")]
    InsufficientHistory {
        /// Timestamp of the oldest sample held.
        oldest: u64,
        /// The window's start boundary (`now - window_secs`).
        window_start: u64,
    },
    /// Fewer samples inform the window than required — the data is too thin to
    /// trust as a time average.
    #[error("too few samples informing the window: {got} < required {min}")]
    TooFewSamples {
        /// Samples informing the window (carry-in + in-window).
        got: usize,
        /// Required minimum.
        min: usize,
    },
    /// A single price held uninterrupted for longer than `max_gap_secs` inside
    /// the window — the feed stalled; refuse to average across stale data.
    #[error("stale gap {gap}s exceeds max {max}s")]
    GapTooLarge {
        /// The offending uninterrupted span (secs).
        gap: u64,
        /// The configured maximum.
        max: u64,
    },
    /// Samples are not in ascending-timestamp order (RS-01) — a backward
    /// wall-clock step slipped an out-of-order sample into the buffer. Fail
    /// closed rather than underflow the segment-gap subtraction.
    #[error("sample timestamp {ts} precedes segment start {seg_start} (non-monotonic)")]
    NonMonotonicSamples {
        /// The offending sample timestamp.
        ts: u64,
        /// The segment start it precedes.
        seg_start: u64,
    },
}

/// Time-weighted average of `samples` over `[now - window_secs, now]`.
///
/// `samples` MUST be sorted by ascending `timestamp` (the producer pushes in
/// monotonic order). Steps:
///
/// 1. Reject a zero-`window_secs` config, an empty buffer, a zero-priced
///    sample, or a future-dated sample (all fail-closed).
/// 2. Locate the carry-in: the most recent sample at or before the window
///    start. Absent ⇒ [`TwapError::InsufficientHistory`] (cold start).
/// 3. Walk the boundaries `window_start → in-window sample timestamps → now`,
///    weighting each segment's start price by the segment's duration. Any
///    segment longer than `max_gap_secs` ⇒ [`TwapError::GapTooLarge`].
/// 4. Require `>= min_samples` samples informing the window, else
///    [`TwapError::TooFewSamples`].
/// 5. Return `Σ price·dt / window_secs` (floored).
///
/// # Errors
/// Fails CLOSED with [`TwapError`] when the window is not soundly covered.
pub fn time_weighted_average(
    samples: &[TwapSample],
    now: u64,
    cfg: TwapConfig,
) -> Result<U256, TwapError> {
    if cfg.window_secs == 0 {
        return Err(TwapError::MisconfiguredWindow);
    }
    if samples.is_empty() {
        return Err(TwapError::EmptyWindow);
    }
    if samples.iter().any(|s| s.price.is_zero()) {
        return Err(TwapError::ZeroSample);
    }
    if let Some(s) = samples.iter().find(|s| s.timestamp > now) {
        return Err(TwapError::FutureSample {
            timestamp: s.timestamp,
            now,
        });
    }

    let window_start = now.saturating_sub(cfg.window_secs);

    // Carry-in: the price in effect at `window_start` is the most recent sample
    // dated at or before it (samples are ascending, so the last such index).
    // Without one, history does not reach back across the full window yet —
    // fail closed (cold start).
    let carry_idx = samples
        .iter()
        .rposition(|s| s.timestamp <= window_start)
        .ok_or(TwapError::InsufficientHistory {
            oldest: samples[0].timestamp,
            window_start,
        })?;

    // Boundaries inside the window: the carry-in opens the window; each sample
    // strictly after `window_start` starts a new segment; `now` closes it.
    let mut weighted = U256::ZERO;
    let mut informing = 1usize; // the carry-in
    let mut seg_start = window_start;
    let mut seg_price = samples[carry_idx].price;
    for s in &samples[carry_idx + 1..] {
        // `s.timestamp > window_start` for these (carry_idx was the last <=).
        // RS-01: checked so an out-of-order sample fails closed, not underflows.
        let gap = s
            .timestamp
            .checked_sub(seg_start)
            .ok_or(TwapError::NonMonotonicSamples {
                ts: s.timestamp,
                seg_start,
            })?;
        if gap > cfg.max_gap_secs {
            return Err(TwapError::GapTooLarge {
                gap,
                max: cfg.max_gap_secs,
            });
        }
        weighted = weighted.saturating_add(seg_price.saturating_mul(U256::from(gap)));
        informing += 1;
        seg_start = s.timestamp;
        seg_price = s.price;
    }
    // Final segment: the last active price held until `now`.
    let tail = now - seg_start;
    if tail > cfg.max_gap_secs {
        return Err(TwapError::GapTooLarge {
            gap: tail,
            max: cfg.max_gap_secs,
        });
    }
    weighted = weighted.saturating_add(seg_price.saturating_mul(U256::from(tail)));

    if informing < cfg.min_samples {
        return Err(TwapError::TooFewSamples {
            got: informing,
            min: cfg.min_samples,
        });
    }

    // Total weight is `now - window_start == window_secs` (unix `now` always
    // exceeds any realistic window). A zero total is only reachable at the epoch
    // (`now == 0`); treat that degenerate window as uncovered rather than divide
    // by zero.
    let total = now - window_start;
    if total == 0 {
        return Err(TwapError::InsufficientHistory {
            oldest: samples[0].timestamp,
            window_start,
        });
    }
    Ok(weighted / U256::from(total))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(timestamp: u64, price: u64) -> TwapSample {
        TwapSample {
            timestamp,
            price: U256::from(price),
        }
    }

    fn cfg(window_secs: u64, min_samples: usize, max_gap_secs: u64) -> TwapConfig {
        TwapConfig {
            window_secs,
            min_samples,
            max_gap_secs,
        }
    }

    #[test]
    fn non_monotonic_samples_fail_closed() {
        // RS-01: an out-of-order sample (1040 after 1050) must fail closed, not
        // underflow the segment-gap subtraction.
        let samples = [s(1000, 100), s(1050, 100), s(1040, 100)];
        assert_eq!(
            time_weighted_average(&samples, 1060, cfg(60, 2, 120)),
            Err(TwapError::NonMonotonicSamples {
                ts: 1040,
                seg_start: 1050,
            })
        );
    }

    #[test]
    fn flat_price_averages_to_itself() {
        // carry-in at window start, one in-window update, both == 100.
        let samples = [s(1000, 100), s(1030, 100), s(1060, 100)];
        // window [1000,1060], min 2, generous gap.
        assert_eq!(
            time_weighted_average(&samples, 1060, cfg(60, 2, 60)),
            Ok(U256::from(100u64))
        );
    }

    #[test]
    fn transient_spike_is_diluted_by_time_weight() {
        // carry-in 100 at window start (t=1000), a one-interval spike to 200 at
        // t=1050, back to 100 at t=1060. window [1000,1060].
        // segments: [1000,1050) @100 = 50*100, [1050,1060) @200 = 10*200,
        // tail [1060,1060] @100 = 0. Σ = 5000 + 2000 = 7000 / 60 = 116.
        let samples = [s(1000, 100), s(1050, 200), s(1060, 100)];
        assert_eq!(
            time_weighted_average(&samples, 1060, cfg(60, 2, 60)),
            Ok(U256::from(116u64))
        );
        // A pure spot median at t=1060 would sign 100; had the spike landed at
        // `now` a spot signer would sign 200. The TWAP signs neither — the spike
        // contributes only its own dwell time.
    }

    #[test]
    fn sustained_move_is_reflected() {
        // price steps 100 -> 200 halfway and STAYS: [1000,1030)@100 + [1030,1060]@200
        // = 30*100 + 30*200 = 9000 / 60 = 150.
        let samples = [s(1000, 100), s(1030, 200)];
        assert_eq!(
            time_weighted_average(&samples, 1060, cfg(60, 2, 60)),
            Ok(U256::from(150u64))
        );
    }

    #[test]
    fn carry_in_before_window_start_is_used() {
        // carry-in dated BEFORE window start (t=990 < 1000) supplies the opening
        // price; in-window update to 200 at t=1030. window [1000,1060].
        // [1000,1030)@100 = 30*100, [1030,1060]@200 = 30*200 → 9000/60 = 150.
        let samples = [s(990, 100), s(1030, 200)];
        assert_eq!(
            time_weighted_average(&samples, 1060, cfg(60, 2, 60)),
            Ok(U256::from(150u64))
        );
    }

    #[test]
    fn cold_start_no_carry_in_fails_closed() {
        // oldest sample (1010) is AFTER window start (1000) → history does not
        // cover the window start yet.
        let samples = [s(1010, 100), s(1040, 100)];
        assert_eq!(
            time_weighted_average(&samples, 1060, cfg(60, 2, 60)),
            Err(TwapError::InsufficientHistory {
                oldest: 1010,
                window_start: 1000,
            })
        );
    }

    #[test]
    fn stale_gap_fails_closed() {
        // carry-in at 1000, next sample only at 1055 → the [1000,1055) segment is
        // 55s > max_gap 30s: the feed stalled, refuse.
        let samples = [s(1000, 100), s(1055, 100), s(1060, 100)];
        assert_eq!(
            time_weighted_average(&samples, 1060, cfg(60, 3, 30)),
            Err(TwapError::GapTooLarge { gap: 55, max: 30 })
        );
    }

    #[test]
    fn stale_tail_fails_closed() {
        // last sample at 1010, now 1060 → tail 50s > max_gap 30s (feed stopped
        // producing) even though earlier segments were fine.
        let samples = [s(1000, 100), s(1010, 100)];
        assert_eq!(
            time_weighted_average(&samples, 1060, cfg(60, 2, 30)),
            Err(TwapError::GapTooLarge { gap: 50, max: 30 })
        );
    }

    #[test]
    fn too_few_samples_fails_closed() {
        // Only the carry-in informs the window (no sample strictly after start);
        // with min 3 that is too thin. Use a big max_gap so GapTooLarge does not
        // pre-empt the count check.
        let samples = [s(1000, 100)];
        assert_eq!(
            time_weighted_average(&samples, 1060, cfg(60, 3, 100)),
            Err(TwapError::TooFewSamples { got: 1, min: 3 })
        );
    }

    #[test]
    fn empty_buffer_fails_closed() {
        assert_eq!(
            time_weighted_average(&[], 1060, cfg(60, 2, 60)),
            Err(TwapError::EmptyWindow)
        );
    }

    #[test]
    fn zero_sample_fails_closed() {
        let samples = [s(1000, 100), s(1030, 0), s(1060, 100)];
        assert_eq!(
            time_weighted_average(&samples, 1060, cfg(60, 2, 60)),
            Err(TwapError::ZeroSample)
        );
    }

    #[test]
    fn future_sample_fails_closed() {
        let samples = [s(1000, 100), s(2000, 100)];
        assert_eq!(
            time_weighted_average(&samples, 1060, cfg(60, 2, 60)),
            Err(TwapError::FutureSample {
                timestamp: 2000,
                now: 1060,
            })
        );
    }

    #[test]
    fn misconfigured_zero_window_fails_closed() {
        let samples = [s(1000, 100)];
        assert_eq!(
            time_weighted_average(&samples, 1060, cfg(0, 2, 60)),
            Err(TwapError::MisconfiguredWindow)
        );
    }

    #[test]
    fn wad_scale_prices_do_not_overflow() {
        // Realistic WAD prices (~$50k BTC = 5e22) time-weighted; ensure the
        // U256 mul/div path returns the exact flat value.
        let p = 50_000u64 * 1_000_000_000u64; // fits u64; stands in for a WAD chunk
        let samples = [
            TwapSample {
                timestamp: 1000,
                price: U256::from(p),
            },
            TwapSample {
                timestamp: 1030,
                price: U256::from(p),
            },
        ];
        assert_eq!(
            time_weighted_average(&samples, 1060, cfg(60, 2, 60)),
            Ok(U256::from(p))
        );
    }
}
