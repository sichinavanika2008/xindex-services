//! Off-chain `THORChain` streaming-swap **hint-builder** (plan Part A2; the
//! mandatory deadline-margin gate for the burn side too).
//!
//! Given live pool depth and the swap size, computes the `(interval,
//! quantity)` stream shape the on-chain adapters consume. The split cuts
//! the slip-based liquidity fee by ~`(N-1)/N` for `N = quantity`
//! sub-swaps; only the slip shrinks (outbound/gas/affiliate fees are
//! unchanged — `adr-010-streaming-swaps`).
//!
//! Three gates, in order:
//!   1. **Size-gate** — if estimated slip is below `min_slip_bps`, don't
//!      stream (the latency isn't worth it for a small swap).
//!   2. **On-chain bound** — `quantity * max(interval, 1) <=`
//!      [`MAX_STREAM_BLOCKS`], mirroring `ThorchainAdapter` so the produced
//!      hint never reverts `InvalidStreamParams`.
//!   3. **Deadline-margin gate** (mandatory) — the worst-case stream
//!      duration must finish comfortably inside the intent deadline, with
//!      `deadline_margin_secs` reserved for native confirmation +
//!      attestation. Streaming narrows the already-tight 30-min
//!      `MIN_INTENT_HORIZON` against BTC confirmation latency, so a stream
//!      that can't fit falls back to a single swap.
//!
//! This is a **reference** implementation: the slip model (`x/(x+X)`) and
//! the per-sub-swap target are deliberately simple. It is pure (no I/O) and
//! unit-tested; the `xindex-hint-builder` binary wraps it over
//! `ThorClient::pools()`.

/// `THORChain` block time, in seconds. Stream duration =
/// `quantity * interval * THOR_BLOCK_SECS`.
pub const THOR_BLOCK_SECS: u64 = 6;

/// Mirror of `ThorchainAdapter.MAX_STREAM_BLOCKS` — the on-chain bound on
/// `quantity * max(interval, 1)`. The hint-builder MUST NOT exceed it or
/// the adapter reverts `ThorchainAdapter_InvalidStreamParams`.
pub const MAX_STREAM_BLOCKS: u64 = 150;

/// The streaming-swap shape: `quantity` sub-swaps, `interval` `THORChain`
/// blocks apart. `quantity <= 1` is a plain single swap (streaming off).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamPlan {
    pub interval: u64,
    pub quantity: u64,
}

impl StreamPlan {
    /// A plain, non-streaming single swap.
    pub const NON_STREAMING: Self = Self {
        interval: 0,
        quantity: 1,
    };

    /// Whether this plan actually streams (`quantity >= 2`).
    #[must_use]
    pub const fn is_streaming(&self) -> bool {
        self.quantity >= 2
    }

    /// Worst-case stream duration in seconds (`interval == 0` counts as one
    /// block, matching the on-chain span bound).
    #[must_use]
    pub const fn duration_secs(&self) -> u64 {
        let eff_interval = if self.interval == 0 { 1 } else { self.interval };
        self.quantity
            .saturating_mul(eff_interval)
            .saturating_mul(THOR_BLOCK_SECS)
    }
}

/// Tunables for the hint-builder, all keeper-configurable.
#[derive(Debug, Clone, Copy)]
pub struct HintParams {
    /// Below this estimated slip (bps), don't stream — a small swap isn't
    /// worth the added latency.
    pub min_slip_bps: u64,
    /// Target slip per sub-swap (bps). Smaller ⇒ more sub-swaps ⇒ less
    /// aggregate slip but a longer stream. Sets how aggressively to split.
    pub target_subswap_slip_bps: u64,
    /// Blocks between sub-swaps (`0` ⇒ rapid). Bounds `quantity` via
    /// [`MAX_STREAM_BLOCKS`].
    pub interval_blocks: u64,
    /// Seconds reserved before the intent deadline for native-chain
    /// confirmation + k-of-n attestation. The stream must finish this far
    /// inside the deadline.
    pub deadline_margin_secs: u64,
}

impl Default for HintParams {
    fn default() -> Self {
        Self {
            // 10 bps: below this the slip saving doesn't justify the latency.
            min_slip_bps: 10,
            // 5 bps per sub-swap: a reasonable default split granularity.
            target_subswap_slip_bps: 5,
            // 1 block between sub-swaps (~6s); rapid enough, still bounded.
            interval_blocks: 1,
            // 20 min: BTC confirmation (~10 min for a few confs) + attestation
            // headroom. Conservative against the 30-min MIN_INTENT_HORIZON.
            deadline_margin_secs: 20 * 60,
        }
    }
}

/// Estimated slip in basis points for swapping `swap_size` into a pool whose
/// input-side depth is `pool_depth` (`THORChain` `x/(x+X)`). Both in the same
/// fixed-point units. Returns `0` when the depth is unknown (denominator 0).
#[must_use]
pub fn slip_bps(swap_size: u128, pool_depth: u128) -> u64 {
    let denom = swap_size.saturating_add(pool_depth);
    if denom == 0 {
        return 0;
    }
    // swap_size/(swap_size+depth) * 10_000, saturating to a full 100% if the
    // arithmetic somehow overflows u64 (it cannot: the ratio is ≤ 10_000).
    u64::try_from(swap_size.saturating_mul(10_000) / denom).unwrap_or(10_000)
}

/// Compute the streaming-swap plan for one swap leg.
///
/// `swap_size` and `pool_depth` are in the same fixed-point units (e.g. 1e8
/// sats for BTC). `now_secs` / `deadline_secs` are unix seconds; the stream
/// must finish at least `deadline_margin_secs` before the deadline. Returns
/// [`StreamPlan::NON_STREAMING`] whenever streaming is unwarranted or won't
/// fit — the caller passes that through as a plain single swap.
#[must_use]
pub fn plan_stream(
    swap_size: u128,
    pool_depth: u128,
    now_secs: u64,
    deadline_secs: u64,
    p: &HintParams,
) -> StreamPlan {
    // Unknown / empty pool depth ⇒ do NOT stream. `pool_depth == 0` is the
    // sentinel `xindex-hint-builder::pool_depth` emits for a non-`Available`
    // (Staged/Suspended/missing) pool. Without this guard `slip_bps` returns a
    // full 100% slip for `(swap_size > 0, depth 0)` — `swap_size / swap_size`
    // — which would drive MAXIMAL streaming, the exact opposite of the
    // "streaming disabled" intent. A single plain swap is the safe fallback
    // (AUD-HINT-SENTINEL).
    if pool_depth == 0 {
        return StreamPlan::NON_STREAMING;
    }

    let slip = slip_bps(swap_size, pool_depth);
    if slip < p.min_slip_bps {
        return StreamPlan::NON_STREAMING;
    }

    let eff_interval = p.interval_blocks.max(1);

    // Desired split: enough sub-swaps to push each below the per-sub-swap
    // target slip (ceil so we round toward more protection), at least 2.
    let target = p.target_subswap_slip_bps.max(1);
    let mut quantity = slip.div_ceil(target).max(2);

    // Gate 2 — on-chain bound: quantity * eff_interval ≤ MAX_STREAM_BLOCKS.
    quantity = quantity.min(MAX_STREAM_BLOCKS / eff_interval);

    // Gate 3 — deadline margin: the worst-case span must fit the budget.
    let budget_secs = deadline_secs
        .saturating_sub(now_secs)
        .saturating_sub(p.deadline_margin_secs);
    let max_blocks_by_deadline = budget_secs / THOR_BLOCK_SECS;
    quantity = quantity.min(max_blocks_by_deadline / eff_interval);

    if quantity < 2 {
        return StreamPlan::NON_STREAMING;
    }
    StreamPlan {
        interval: p.interval_blocks,
        quantity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slip_is_zero_for_zero_swap_or_unknown_depth() {
        assert_eq!(slip_bps(0, 1_000), 0);
        assert_eq!(slip_bps(0, 0), 0);
    }

    #[test]
    fn slip_grows_with_size_relative_to_depth() {
        // 1% of depth ⇒ ~99 bps; equal to depth ⇒ 5000 bps.
        assert_eq!(slip_bps(1, 99), 100); // 1/100 = 1% = 100 bps
        assert_eq!(slip_bps(100, 100), 5_000); // 50%
    }

    #[test]
    fn small_swap_does_not_stream() {
        // 5 bps slip < default min_slip_bps (10) ⇒ plain swap.
        let p = HintParams::default();
        let plan = plan_stream(5, 9_995, 1_000, 1_000_000, &p);
        assert_eq!(plan, StreamPlan::NON_STREAMING);
        assert!(!plan.is_streaming());
    }

    #[test]
    fn large_swap_streams_within_onchain_bound() {
        let p = HintParams::default();
        // swap == pool depth ⇒ 5000 bps slip ⇒ wants ~1000 sub-swaps but
        // MAX_STREAM_BLOCKS=150 caps it (interval 1 ⇒ quantity ≤ 150).
        let plan = plan_stream(1_000, 1_000, 0, 4 * 3600, &p);
        assert!(plan.is_streaming());
        assert!(plan.quantity >= 2);
        assert!(
            plan.quantity * plan.interval.max(1) <= MAX_STREAM_BLOCKS,
            "must respect on-chain MAX_STREAM_BLOCKS"
        );
    }

    #[test]
    fn moderate_slip_splits_proportionally() {
        // 40 bps slip, 5 bps target ⇒ ceil(40/5)=8 sub-swaps.
        let p = HintParams::default();
        // slip_bps(40, 9960) = 40/10000 = 40 bps.
        let plan = plan_stream(40, 9_960, 0, 4 * 3600, &p);
        assert_eq!(plan.quantity, 8);
        assert_eq!(plan.interval, 1);
    }

    #[test]
    fn tight_deadline_caps_or_disables_streaming() {
        let p = HintParams::default();
        // Deadline only 21 min out; margin 20 min ⇒ 60s budget ⇒ 10 blocks
        // ⇒ quantity ≤ 10. A 5000-bps slip would want 150 but is capped.
        let plan = plan_stream(1_000, 1_000, 0, 21 * 60, &p);
        assert!(plan.quantity <= 10, "deadline budget caps the split");
        assert!(plan.duration_secs() <= 60, "stream fits the budget");
    }

    #[test]
    fn deadline_with_no_room_falls_back_to_single_swap() {
        let p = HintParams::default();
        // Deadline inside the margin ⇒ zero budget ⇒ non-streaming.
        let plan = plan_stream(1_000, 1_000, 0, 19 * 60, &p);
        assert_eq!(plan, StreamPlan::NON_STREAMING);
    }

    #[test]
    fn zero_depth_does_not_stream() {
        // AUD-HINT-SENTINEL: `pool_depth == 0` (empty/unavailable pool, the
        // hint-builder's sentinel) must NOT stream. Pre-fix `slip_bps` mapped
        // it to a 100% slip → maximal streaming; the guard now falls back to a
        // single swap regardless of swap size or deadline room.
        let p = HintParams::default();
        let plan = plan_stream(1_000_000, 0, 0, 4 * 3600, &p);
        assert_eq!(plan, StreamPlan::NON_STREAMING);
        assert!(!plan.is_streaming());
    }
}
