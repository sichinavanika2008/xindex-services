use alloy_primitives::{Address, B256};

use crate::catalog::Provider;
use crate::math::ceil_bps;
use crate::payload::{route_calls_hash, RouteCall};
use crate::NativeRouterError;

/// Finalized on-chain configuration snapshot independently read by every
/// route signer before it evaluates a quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceBinding {
    pub provider_id: B256,
    pub provider_config_hash: B256,
    pub asset_id: B256,
    pub provider_asset_config_hash: B256,
    pub provider_asset_id: B256,
    pub execution_asset_id: B256,
    pub destination_chain: u32,
    pub destination_token: u32,
    pub provider_decimals: u8,
    pub native_decimals: u8,
    pub endpoint: Address,
    pub dispatch_mode: u8,
    pub max_total_cost_bps: u16,
    pub max_chunks: u16,
    pub max_stream_duration_seconds: u32,
    pub stream_block_seconds: u16,
    pub enabled: bool,
    pub asset_enabled: bool,
}

/// One fully reconstructed provider route. `reference_amount_out` must come
/// from Xindex's independent price/reference path, never from the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCandidate {
    pub provider: Provider,
    pub governance: GovernanceBinding,
    pub calls: Vec<RouteCall>,
    pub expected_amount_out: u128,
    pub minimum_amount_out: u128,
    pub reference_amount_out: u128,
    pub chunks: u16,
    pub stream_duration_seconds: u32,
    pub observed_at: u64,
    pub valid_until: u64,
    pub evidence_hash: B256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutePolicy {
    pub max_total_cost_bps: u16,
    pub max_quote_age_seconds: u64,
    pub minimum_remaining_validity_seconds: u64,
    pub max_chunks: u16,
    pub max_stream_duration_seconds: u32,
}

impl Default for RoutePolicy {
    fn default() -> Self {
        Self {
            max_total_cost_bps: 100,
            max_quote_age_seconds: 120,
            minimum_remaining_validity_seconds: 30,
            max_chunks: 256,
            max_stream_duration_seconds: 24 * 60 * 60,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRoute {
    pub candidate: RouteCandidate,
    pub payload_hash: B256,
    pub quoted_cost_bps: u16,
    pub execution_tolerance_bps: u16,
    pub total_cost_bps: u16,
}

impl RouteCandidate {
    /// Apply the same combined cost shape enforced by `NativeRouteRegistry`,
    /// plus freshness, governance and dispatch-payload checks.
    ///
    /// # Errors
    /// Any stale/disabled/mismatched route or cost/stream bound violation.
    pub fn validate(
        &self,
        policy: RoutePolicy,
        now: u64,
    ) -> Result<ValidatedRoute, NativeRouterError> {
        validate_policy(policy)?;
        if !self.governance.enabled
            || !self.governance.asset_enabled
            || self.governance.provider_id != self.provider.id()
            || self.governance.provider_config_hash == B256::ZERO
            || self.governance.asset_id == B256::ZERO
            || self.governance.provider_asset_config_hash == B256::ZERO
            || self.governance.provider_asset_id == B256::ZERO
            || self.governance.execution_asset_id == B256::ZERO
            || self.governance.provider_decimals > 18
            || self.governance.native_decimals > 18
            || self.governance.dispatch_mode != 0
            || self.governance.max_total_cost_bps > 100
            || self.governance.max_chunks == 0
            || self.governance.max_chunks > 256
            || self.governance.max_stream_duration_seconds > 24 * 60 * 60
            || (self.governance.max_chunks == 1 && self.governance.max_stream_duration_seconds != 0)
            || (self.governance.max_chunks > 1 && self.governance.max_stream_duration_seconds == 0)
            || ((self.governance.destination_chain == 0)
                != (self.governance.destination_token == 0))
            || self.governance.endpoint == Address::ZERO
            || self.evidence_hash == B256::ZERO
        {
            return Err(NativeRouterError::Policy(
                "disabled or incomplete governance/evidence binding",
            ));
        }
        if self.calls.len() != 1
            || self.calls[0].target != self.governance.endpoint
            || self.calls[0].amount.is_zero()
            || self.calls[0].data.is_empty()
        {
            return Err(NativeRouterError::Policy("invalid route-call envelope"));
        }
        if self.expected_amount_out == 0
            || self.minimum_amount_out == 0
            || self.reference_amount_out == 0
            || self.minimum_amount_out > self.expected_amount_out
        {
            return Err(NativeRouterError::Policy("invalid route output amounts"));
        }
        if self.observed_at == 0
            || self.observed_at > now
            || now - self.observed_at > policy.max_quote_age_seconds
            || self.valid_until < now.saturating_add(policy.minimum_remaining_validity_seconds)
            || self.valid_until <= self.observed_at
            || self.valid_until - self.observed_at > 10 * 60
        {
            return Err(NativeRouterError::Policy("stale or invalid route lifetime"));
        }
        if self.chunks == 0
            || self.chunks > policy.max_chunks
            || self.chunks > self.governance.max_chunks
            || self.stream_duration_seconds > policy.max_stream_duration_seconds
            || self.stream_duration_seconds > self.governance.max_stream_duration_seconds
            || (self.chunks == 1
                && self.stream_duration_seconds != 0
                && self.provider != Provider::Chainflip)
            || (self.chunks > 1 && self.stream_duration_seconds == 0)
        {
            return Err(NativeRouterError::Policy("invalid route stream shape"));
        }

        let economic_loss = self
            .reference_amount_out
            .saturating_sub(self.expected_amount_out);
        let quoted_cost_bps = ceil_bps(economic_loss, self.reference_amount_out)?;
        let execution_tolerance_bps = ceil_bps(
            self.expected_amount_out - self.minimum_amount_out,
            self.expected_amount_out,
        )?;
        let total = u32::from(quoted_cost_bps) + u32::from(execution_tolerance_bps);
        if total > u32::from(policy.max_total_cost_bps)
            || total > u32::from(self.governance.max_total_cost_bps)
        {
            return Err(NativeRouterError::Policy(
                "combined route cost exceeds configured ceiling",
            ));
        }
        let total_cost_bps = u16::try_from(total)
            .map_err(|_| NativeRouterError::Policy("combined cost exceeds uint16"))?;
        Ok(ValidatedRoute {
            candidate: self.clone(),
            payload_hash: route_calls_hash(&self.calls),
            quoted_cost_bps,
            execution_tolerance_bps,
            total_cost_bps,
        })
    }
}

fn validate_policy(policy: RoutePolicy) -> Result<(), NativeRouterError> {
    if policy.max_total_cost_bps == 0
        || policy.max_total_cost_bps > 100
        || policy.max_quote_age_seconds == 0
        || policy.minimum_remaining_validity_seconds == 0
        || policy.max_chunks == 0
        || policy.max_chunks > 256
        || policy.max_stream_duration_seconds == 0
        || policy.max_stream_duration_seconds > 24 * 60 * 60
    {
        return Err(NativeRouterError::Policy("invalid route selector policy"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRejection {
    pub provider: Provider,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionReport {
    pub selected: Option<ValidatedRoute>,
    pub rejected: Vec<CandidateRejection>,
}

/// Evaluate every rail and select by combined all-in bps, then higher expected
/// output, then deterministic provider order. Invalid candidates are retained
/// as explicit rejection records; they are never silently used as fallback.
#[must_use]
pub fn evaluate_routes(
    candidates: &[RouteCandidate],
    policy: RoutePolicy,
    now: u64,
) -> SelectionReport {
    let mut eligible = Vec::new();
    let mut rejected = Vec::new();
    for candidate in candidates {
        match candidate.validate(policy, now) {
            Ok(validated) => eligible.push(validated),
            Err(error) => rejected.push(CandidateRejection {
                provider: candidate.provider,
                reason: error.to_string(),
            }),
        }
    }
    eligible.sort_by(|left, right| {
        left.total_cost_bps
            .cmp(&right.total_cost_bps)
            .then_with(|| {
                right
                    .candidate
                    .expected_amount_out
                    .cmp(&left.candidate.expected_amount_out)
            })
            .then_with(|| left.candidate.provider.cmp(&right.candidate.provider))
    });
    SelectionReport {
        selected: eligible.into_iter().next(),
        rejected,
    }
}

/// A route can be replaced only while no dispatch has occurred. After funds
/// leave Ethereum, reconciliation/refund must finish before a new selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedSelection {
    route: ValidatedRoute,
    dispatched: bool,
}

impl PinnedSelection {
    #[must_use]
    pub const fn new(route: ValidatedRoute) -> Self {
        Self {
            route,
            dispatched: false,
        }
    }

    #[must_use]
    pub const fn route(&self) -> &ValidatedRoute {
        &self.route
    }

    /// Replace a quote only while no transfer or contract call was dispatched.
    ///
    /// # Errors
    /// Funds have already been dispatched on the pinned route.
    pub fn replace_before_dispatch(
        &mut self,
        route: ValidatedRoute,
    ) -> Result<(), NativeRouterError> {
        if self.dispatched {
            return Err(NativeRouterError::Policy(
                "provider cannot change after dispatch",
            ));
        }
        self.route = route;
        Ok(())
    }

    /// Mark the one-time boundary after which the provider cannot change.
    ///
    /// # Errors
    /// The selection was already dispatched.
    pub fn mark_dispatched(&mut self) -> Result<(), NativeRouterError> {
        if self.dispatched {
            return Err(NativeRouterError::Policy("route already dispatched"));
        }
        self.dispatched = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures must fail loudly")]

    use alloy_primitives::{Bytes, U256};

    use super::*;

    fn candidate(
        provider: Provider,
        expected: u128,
        minimum: u128,
        reference: u128,
    ) -> RouteCandidate {
        let endpoint = match provider {
            Provider::Chainflip => Address::repeat_byte(0x11),
            Provider::Maya => Address::repeat_byte(0x22),
        };
        RouteCandidate {
            provider,
            governance: GovernanceBinding {
                provider_id: provider.id(),
                provider_config_hash: B256::repeat_byte(1),
                asset_id: B256::repeat_byte(2),
                provider_asset_config_hash: B256::repeat_byte(3),
                provider_asset_id: B256::repeat_byte(4),
                execution_asset_id: B256::repeat_byte(5),
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
            calls: vec![RouteCall {
                target: endpoint,
                amount: U256::from(100u64),
                data: Bytes::from_static(b"payload"),
            }],
            expected_amount_out: expected,
            minimum_amount_out: minimum,
            reference_amount_out: reference,
            chunks: 1,
            stream_duration_seconds: if provider == Provider::Chainflip {
                30 * 60
            } else {
                0
            },
            observed_at: 1_800_000_000,
            valid_until: 1_800_000_300,
            evidence_hash: B256::repeat_byte(6),
        }
    }

    #[test]
    fn selector_chooses_lowest_combined_cost_not_provider_preference() {
        let chainflip = candidate(Provider::Chainflip, 99_700, 99_500, 100_000);
        let maya = candidate(Provider::Maya, 99_800, 99_600, 100_000);
        let report = evaluate_routes(&[chainflip, maya], RoutePolicy::default(), 1_800_000_010);
        let selected = report.selected.expect("eligible route");
        assert_eq!(selected.candidate.provider, Provider::Maya);
        assert_eq!(selected.quoted_cost_bps, 20);
        assert_eq!(selected.execution_tolerance_bps, 21);
        assert_eq!(selected.total_cost_bps, 41);
    }

    #[test]
    fn excessive_cost_is_reported_and_never_selected() {
        let expensive = candidate(Provider::Chainflip, 99_000, 98_000, 100_000);
        let report = evaluate_routes(&[expensive], RoutePolicy::default(), 1_800_000_010);
        assert!(report.selected.is_none());
        assert_eq!(report.rejected.len(), 1);
    }

    #[test]
    fn provider_is_immutable_after_dispatch() {
        let first = candidate(Provider::Chainflip, 99_700, 99_500, 100_000)
            .validate(RoutePolicy::default(), 1_800_000_010)
            .expect("candidate");
        let second = candidate(Provider::Maya, 99_800, 99_600, 100_000)
            .validate(RoutePolicy::default(), 1_800_000_010)
            .expect("candidate");
        let mut pinned = PinnedSelection::new(first);
        pinned.mark_dispatched().expect("first dispatch");
        assert!(pinned.replace_before_dispatch(second).is_err());
        assert!(pinned.mark_dispatched().is_err());
    }
}
