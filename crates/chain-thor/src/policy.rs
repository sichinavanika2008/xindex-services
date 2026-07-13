//! Deterministic, fail-closed policy for `THORChain` inbound snapshots and swap
//! quotes.
//!
//! The on-chain registry cannot inspect `THORChain`. This module is therefore
//! the executable trust boundary used by each independent signer:
//!
//! - derive every pause bit from three complete REST/CometBFT snapshots;
//! - commit a canonical, reproducible source bundle with Keccak-256;
//! - require full allowlisted pool identities (never ticker-only matching);
//! - validate the exact quote request/response, fees, dust, duration and memo;
//! - combine the THOR liquidity limit with an independent three-source price
//!   floor; and
//! - let an operator compare a common quorum candidate with its own source
//!   bundle without requiring operator-specific evidence hashes to match.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use alloy_primitives::{keccak256, B256, U256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::agreement::MIN_AGREEING_SOURCES;
use crate::types::{
    ConsensusTip, InboundAddress, Mimir, Pool, SwapQuoteRequest, SwapQuoteResponse,
};

pub const PAUSE_CHAIN_HALTED: u8 = 1 << 0;
pub const PAUSE_GLOBAL_TRADING: u8 = 1 << 1;
pub const PAUSE_CHAIN_TRADING: u8 = 1 << 2;
pub const PAUSE_SIGNING: u8 = 1 << 3;
pub const PAUSE_STREAMING: u8 = 1 << 4;
pub const PAUSE_STALE_CONSENSUS: u8 = 1 << 5;
pub const PAUSE_TARGET_OR_POOL: u8 = 1 << 6;

/// Hashes of the exact raw bodies persisted by a source poller.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceResponseHashes {
    pub inbound: B256,
    pub mimir: B256,
    pub pools: B256,
    pub consensus: B256,
}

/// Prior tip retained by the poller so a fresh-looking frozen response cannot
/// pass merely because its block timestamp is close to the host clock.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TipCheckpoint {
    pub height: u64,
    pub observed_at: u64,
    /// Durable proof that the source advanced at least once after its initial
    /// enrollment. Repeating the first-seen height must not bootstrap a live
    /// state.
    pub proven_advance: bool,
}

/// One complete independent `THORNode` + `CometBFT` observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceSnapshot {
    /// Public operator/source identity. It is evidence metadata, never a URL
    /// containing credentials.
    pub source_id: String,
    pub observed_at: u64,
    pub consensus: ConsensusTip,
    pub previous_tip: Option<TipCheckpoint>,
    pub inbound: Vec<InboundAddress>,
    pub mimir: Mimir,
    pub pools: Vec<Pool>,
    pub response_hashes: SourceResponseHashes,
}

/// Static route policy shared by candidate producers and independent signers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InboundPolicy {
    /// Funding/source chain. Current Xindex mint routing is Ethereum.
    pub source_chain: String,
    /// Source plus every enabled native target chain.
    pub enabled_chains: Vec<String>,
    /// Full canonical pool rows (`CHAIN.TICKER[-CONTRACT]`).
    pub allowlisted_pools: Vec<String>,
    /// Two expected six-second blocks in production.
    pub max_tip_age_secs: u64,
    /// Height skew that triggers the stale/ambiguous bit.
    pub max_height_skew: u64,
}

/// Canonical evidence actually committed by `source_hash`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalSourceBundle {
    pub schema: String,
    pub source_chain: String,
    pub enabled_chains: Vec<String>,
    pub allowlisted_pools: Vec<String>,
    pub sources: Vec<CanonicalSourceSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalSourceSnapshot {
    pub source_id: String,
    pub observed_at: u64,
    pub consensus: ConsensusTip,
    pub previous_tip: Option<TipCheckpoint>,
    pub inbound: Vec<InboundAddress>,
    pub mimir: BTreeMap<String, i64>,
    pub pools: Vec<Pool>,
    pub response_hashes: SourceResponseHashes,
}

/// Policy result before on-chain timestamp/sequence fields are attached.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DerivedInbound {
    pub vault: String,
    pub router: String,
    pub pause_flags: u8,
    pub source_hash: B256,
    pub bundle: CanonicalSourceBundle,
}

/// Common unsigned inbound candidate distributed by the untrusted collector.
/// Every signer recomputes the bundle hash, polls its own sources and reads the
/// finalized on-chain sequence before this can reach its HSM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InboundCandidate {
    pub derived: DerivedInbound,
    pub observed_at: u64,
    pub valid_until: u64,
    pub sequence: u64,
}

/// Independent price ratio used to protect one quote. Prices are WAD values
/// for one whole funding/target asset in the same numeraire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalPriceObservation {
    pub source_id: String,
    pub funding_price_wad: String,
    pub target_price_wad: String,
    pub observed_at: u64,
    pub raw_response_hash: B256,
}

/// Common quote evidence. Raw response bytes live in the append-only evidence
/// file; `raw_quote_hash` binds those bytes into the signed `quote_hash`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuoteEvidence {
    pub schema: String,
    pub quote_source_id: String,
    pub request: SwapQuoteRequest,
    pub response: SwapQuoteResponse,
    pub raw_quote_hash: B256,
    pub external_prices: Vec<ExternalPriceObservation>,
}

/// Quote safety settings. Values are startup-reviewed policy, never accepted
/// from a per-request coordinator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuotePolicy {
    pub allowlisted_assets: Vec<String>,
    pub min_price_sources: usize,
    pub max_price_age_secs: u64,
    pub max_price_deviation_bps: u16,
    /// Applied to the independent median output. `9_900` is a 1% floor.
    pub external_floor_bps: u16,
    pub max_dispatch_ttl_secs: u64,
    pub max_stream_blocks: u64,
    pub max_total_swap_secs: u64,
}

/// Fully validated values used to construct adapter hints and the typed quote.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuoteDecision {
    pub min_out_1e8: String,
    pub memo: String,
    pub dispatch_deadline: u64,
    pub quote_hash: B256,
}

/// Common unsigned exact-quote candidate. Address/amount/hash fields mirror
/// `QuoteAuthorization`; the evidence/decision carries the plaintext adapter
/// hint that produces `memoHash`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuoteCandidate {
    pub evidence: QuoteEvidence,
    /// Exact bounded UTF-8 quote response returned by the common producer.
    /// Signers decode it again and require byte-hash/value equality before
    /// retaining it in their append-only evidence store.
    pub raw_quote_body: String,
    pub decision: QuoteDecision,
    pub adapter: String,
    pub index_token: String,
    pub originator: String,
    pub funding_token: String,
    pub target_token: String,
    pub amount_in: String,
    pub custody_hash: B256,
    pub inbound_state_hash: B256,
    pub current_state_valid_until: u64,
    pub finalized_onchain_nonce: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ThorPolicyError {
    #[error("configuration: {0}")]
    Configuration(String),
    #[error("source evidence: {0}")]
    Source(String),
    #[error("source disagreement: {0}")]
    Disagreement(String),
    #[error("quote policy: {0}")]
    Quote(String),
    #[error("canonical serialization: {0}")]
    Serialization(String),
}

/// Derive the registry vault/router, aggregate pause bits and canonical source
/// commitment from exactly three complete source snapshots.
///
/// # Errors
/// Invalid configuration/evidence or a vault/router disagreement. Halt, pool
/// and consensus faults are represented as pause bits so a quorum can publish
/// a positive fail-closed state instead of leaving an old live state active.
pub fn derive_inbound(
    policy: &InboundPolicy,
    snapshots: &[SourceSnapshot],
    now: u64,
) -> Result<DerivedInbound, ThorPolicyError> {
    let normalized_policy = normalize_inbound_policy(policy)?;
    if snapshots.len() != MIN_AGREEING_SOURCES {
        return Err(ThorPolicyError::Source(format!(
            "exactly {MIN_AGREEING_SOURCES} complete sources required, got {}",
            snapshots.len()
        )));
    }
    let relevant_mimir = relevant_mimir_keys(&normalized_policy);
    let mut sources = snapshots
        .iter()
        .map(|snapshot| canonicalize_source(snapshot, &normalized_policy, &relevant_mimir))
        .collect::<Result<Vec<_>, _>>()?;
    sources.sort_by(|left, right| left.source_id.cmp(&right.source_id));
    if sources
        .windows(2)
        .any(|pair| pair[0].source_id == pair[1].source_id)
    {
        return Err(ThorPolicyError::Source(
            "source identities must be distinct".to_string(),
        ));
    }

    let source_rows = sources
        .iter()
        .map(|source| required_inbound(&source.inbound, &normalized_policy.source_chain))
        .collect::<Result<Vec<_>, _>>()?;
    let vault = source_rows[0].address.to_ascii_lowercase();
    let router = source_rows[0]
        .router
        .as_deref()
        .ok_or_else(|| ThorPolicyError::Source("source-chain Router is absent".to_string()))?
        .to_ascii_lowercase();
    if vault.is_empty() || router.is_empty() {
        return Err(ThorPolicyError::Source(
            "source-chain vault/Router is empty".to_string(),
        ));
    }
    for row in &source_rows[1..] {
        let candidate_router = row.router.as_deref().unwrap_or_default();
        if !row.address.eq_ignore_ascii_case(&vault)
            || !candidate_router.eq_ignore_ascii_case(&router)
        {
            return Err(ThorPolicyError::Disagreement(format!(
                "{} vault/Router differs across sources",
                normalized_policy.source_chain
            )));
        }
    }

    let mut pause_flags = 0u8;
    let heights = sources
        .iter()
        .map(|source| source.consensus.height)
        .collect::<Vec<_>>();
    let min_height = heights.iter().copied().min().unwrap_or(0);
    let max_height = heights.iter().copied().max().unwrap_or(0);
    if max_height.saturating_sub(min_height) > normalized_policy.max_height_skew {
        pause_flags |= PAUSE_STALE_CONSENSUS;
    }

    for source in &sources {
        pause_flags |= source_pause_flags(source, &normalized_policy, now);
    }

    let bundle = CanonicalSourceBundle {
        schema: "xindex.thorchain-inbound-source.v1".to_string(),
        source_chain: normalized_policy.source_chain,
        enabled_chains: normalized_policy.enabled_chains,
        allowlisted_pools: normalized_policy.allowlisted_pools,
        sources,
    };
    let source_hash = hash_serialized(&bundle)?;
    Ok(DerivedInbound {
        vault,
        router,
        pause_flags,
        source_hash,
        bundle,
    })
}

/// Compare a common quorum candidate with one operator's independently
/// derived facts. Operator-specific evidence hashes and heights may differ;
/// the fund-moving vault/Router must match, and the candidate may never clear
/// a pause bit observed locally. Extra pause bits are safe containment.
///
/// # Errors
/// Candidate tampering, a custody-field mismatch or suppressed local pause.
pub fn validate_independent_inbound(
    candidate: &DerivedInbound,
    local: &DerivedInbound,
) -> Result<(), ThorPolicyError> {
    if hash_serialized(&candidate.bundle)? != candidate.source_hash {
        return Err(ThorPolicyError::Source(
            "candidate sourceHash does not commit its bundle".to_string(),
        ));
    }
    if !candidate.vault.eq_ignore_ascii_case(&local.vault)
        || !candidate.router.eq_ignore_ascii_case(&local.router)
    {
        return Err(ThorPolicyError::Disagreement(
            "candidate vault/Router differs from independent observation".to_string(),
        ));
    }
    if candidate.pause_flags & local.pause_flags != local.pause_flags {
        return Err(ThorPolicyError::Disagreement(format!(
            "candidate pause flags 0x{:02x} suppress local flags 0x{:02x}",
            candidate.pause_flags, local.pause_flags
        )));
    }
    Ok(())
}

/// Re-run the complete inbound policy over the common candidate's committed
/// bundle and require an exact result. This is distinct from
/// [`validate_independent_inbound`]: the latter compares fund-moving facts
/// against an operator's private sources, while this check proves the
/// coordinator did not attach a valid bundle hash to an arbitrary
/// vault/Router/pause result.
///
/// # Errors
/// Invalid bundle policy/schema, a non-canonical derivation, or any underlying
/// source-policy failure.
pub fn validate_common_inbound(
    policy: &InboundPolicy,
    candidate: &DerivedInbound,
    now: u64,
) -> Result<(), ThorPolicyError> {
    let normalized_policy = normalize_inbound_policy(policy)?;
    if candidate.bundle.schema != "xindex.thorchain-inbound-source.v1"
        || candidate.bundle.source_chain != normalized_policy.source_chain
        || candidate.bundle.enabled_chains != normalized_policy.enabled_chains
        || candidate.bundle.allowlisted_pools != normalized_policy.allowlisted_pools
    {
        return Err(ThorPolicyError::Source(
            "candidate bundle policy or schema differs from local policy".to_string(),
        ));
    }
    let snapshots = candidate
        .bundle
        .sources
        .iter()
        .map(|source| SourceSnapshot {
            source_id: source.source_id.clone(),
            observed_at: source.observed_at,
            consensus: source.consensus.clone(),
            previous_tip: source.previous_tip.clone(),
            inbound: source.inbound.clone(),
            mimir: source.mimir.clone(),
            pools: source.pools.clone(),
            response_hashes: source.response_hashes.clone(),
        })
        .collect::<Vec<_>>();
    let derived = derive_inbound(&normalized_policy, &snapshots, now)?;
    if &derived != candidate {
        return Err(ThorPolicyError::Disagreement(
            "candidate fields are not the exact derivation of its bundle".to_string(),
        ));
    }
    Ok(())
}

/// Validate a complete quote evidence bundle and construct the exact full-asset
/// memo, stricter `LIM`, deadline and audit hash.
///
/// # Errors
/// Any incomplete/ambiguous response, stale/discordant external price set,
/// unsafe amount, pool abbreviation collision, memo mismatch or duration bound.
#[expect(
    clippy::too_many_lines,
    reason = "linear fail-closed quote validation keeps every signed boundary visible"
)]
pub fn evaluate_quote(
    policy: &QuotePolicy,
    evidence: &QuoteEvidence,
    expected_vault: &str,
    inbound_valid_until: u64,
    now: u64,
) -> Result<QuoteDecision, ThorPolicyError> {
    validate_quote_policy(policy)?;
    validate_public_id(&evidence.quote_source_id)?;
    if evidence.schema != "xindex.thorchain-quote-evidence.v1" {
        return Err(ThorPolicyError::Quote(
            "unknown quote evidence schema".to_string(),
        ));
    }
    if evidence.raw_quote_hash == B256::ZERO {
        return Err(ThorPolicyError::Quote(
            "raw quote response hash is zero".to_string(),
        ));
    }
    validate_quote_request(&evidence.request)?;
    let from_asset =
        require_allowlisted_asset(&policy.allowlisted_assets, &evidence.request.from_asset)?;
    let to_asset =
        require_allowlisted_asset(&policy.allowlisted_assets, &evidence.request.to_asset)?;
    if from_asset == to_asset {
        return Err(ThorPolicyError::Quote(
            "from/to assets must differ".to_string(),
        ));
    }
    if !address_eq(&evidence.response.inbound_address, expected_vault) {
        return Err(ThorPolicyError::Quote(
            "quote inbound address differs from attested vault".to_string(),
        ));
    }
    if evidence.response.expiry <= now || inbound_valid_until <= now {
        return Err(ThorPolicyError::Quote(
            "quote or inbound state is expired".to_string(),
        ));
    }
    if evidence.response.warning.trim().is_empty() {
        return Err(ThorPolicyError::Quote(
            "quote warning is absent".to_string(),
        ));
    }

    let amount = parse_u256("request amount", &evidence.request.amount)?;
    let dust = parse_u256("dust threshold", &evidence.response.dust_threshold)?;
    let recommended_min = parse_u256(
        "recommended minimum input",
        &evidence.response.recommended_min_amount_in,
    )?;
    if amount < dust || amount < recommended_min {
        return Err(ThorPolicyError::Quote(
            "input is below dust or recommended minimum".to_string(),
        ));
    }
    if evidence.response.recommended_gas_rate.trim().is_empty()
        || evidence.response.gas_rate_units.trim().is_empty()
    {
        return Err(ThorPolicyError::Quote(
            "recommended gas rate or units are absent".to_string(),
        ));
    }
    validate_fees(&evidence.response, &policy.allowlisted_assets, to_asset)?;

    let parsed_memo = parse_swap_memo(&evidence.response.memo)?;
    let resolved_memo_asset = resolve_asset(&policy.allowlisted_assets, parsed_memo.asset)?;
    if resolved_memo_asset != to_asset {
        return Err(ThorPolicyError::Quote(
            "quote memo resolves to a different target asset".to_string(),
        ));
    }
    if !address_eq(parsed_memo.destination, &evidence.request.destination)
        || !address_eq(parsed_memo.refund, &evidence.request.refund_address)
    {
        return Err(ThorPolicyError::Quote(
            "quote memo destination/refund differs from request".to_string(),
        ));
    }
    if parsed_memo.interval != evidence.request.streaming_interval
        || parsed_memo.quantity != evidence.request.streaming_quantity
    {
        return Err(ThorPolicyError::Quote(
            "quote memo changed explicit streaming parameters".to_string(),
        ));
    }
    let span = parsed_memo
        .quantity
        .checked_mul(parsed_memo.interval.max(1))
        .ok_or_else(|| ThorPolicyError::Quote("stream span overflows".to_string()))?;
    if span > policy.max_stream_blocks {
        return Err(ThorPolicyError::Quote(format!(
            "stream span {span} exceeds {} blocks",
            policy.max_stream_blocks
        )));
    }
    if parsed_memo.quantity > 1 && evidence.response.max_streaming_quantity < parsed_memo.quantity {
        return Err(ThorPolicyError::Quote(
            "quote reports a lower maximum streaming quantity".to_string(),
        ));
    }
    if evidence.response.streaming_swap_blocks > policy.max_stream_blocks
        || evidence.response.total_swap_seconds == 0
        || evidence.response.total_swap_seconds > policy.max_total_swap_secs
    {
        return Err(ThorPolicyError::Quote(
            "quote duration exceeds policy or is zero".to_string(),
        ));
    }

    let expected_out =
        parse_nonzero_u256("expected output", &evidence.response.expected_amount_out)?;
    let thor_limit = parse_nonzero_u256("memo liquidity limit", parsed_memo.limit)?;
    if thor_limit > expected_out {
        return Err(ThorPolicyError::Quote(
            "THOR quote limit exceeds expected output".to_string(),
        ));
    }
    let external_floor = independent_price_floor(policy, evidence, amount, now)?;
    let min_out = thor_limit.max(external_floor);
    if min_out > expected_out {
        return Err(ThorPolicyError::Quote(
            "independent price floor exceeds THOR expected output".to_string(),
        ));
    }

    let dispatch_deadline = evidence
        .response
        .expiry
        .min(inbound_valid_until)
        .min(now.saturating_add(policy.max_dispatch_ttl_secs));
    if dispatch_deadline <= now {
        return Err(ThorPolicyError::Quote(
            "no safe dispatch window remains".to_string(),
        ));
    }
    let memo = format!(
        "=:{to_asset}:{}/{}:{}/{}/{}",
        evidence.request.destination,
        evidence.request.refund_address,
        min_out,
        parsed_memo.interval,
        parsed_memo.quantity
    );
    let quote_hash = hash_quote_evidence(evidence)?;
    Ok(QuoteDecision {
        min_out_1e8: min_out.to_string(),
        memo,
        dispatch_deadline,
        quote_hash,
    })
}

/// Require a common candidate to be at least as protective as one operator's
/// independently sourced decision. The candidate bundle remains the common
/// `quoteHash`; the local evidence is retained separately by that signer.
///
/// # Errors
/// A weaker LIM, longer deadline, or different fund-moving request.
pub fn validate_independent_quote(
    candidate_evidence: &QuoteEvidence,
    candidate: &QuoteDecision,
    local_evidence: &QuoteEvidence,
    local: &QuoteDecision,
) -> Result<(), ThorPolicyError> {
    if candidate_evidence.request != local_evidence.request {
        return Err(ThorPolicyError::Disagreement(
            "candidate quote request differs from independent request".to_string(),
        ));
    }
    if hash_quote_evidence(candidate_evidence)? != candidate.quote_hash {
        return Err(ThorPolicyError::Quote(
            "candidate quoteHash does not commit its evidence".to_string(),
        ));
    }
    let candidate_min = parse_nonzero_u256("candidate minimum", &candidate.min_out_1e8)?;
    let local_min = parse_nonzero_u256("local minimum", &local.min_out_1e8)?;
    if candidate_min < local_min {
        return Err(ThorPolicyError::Disagreement(
            "candidate LIM is weaker than independent policy".to_string(),
        ));
    }
    if candidate.dispatch_deadline > local.dispatch_deadline {
        return Err(ThorPolicyError::Disagreement(
            "candidate deadline outlives independent quote".to_string(),
        ));
    }
    let expected_memo = rebuild_memo_with_limit(&local.memo, candidate_min)?;
    if candidate.memo != expected_memo {
        return Err(ThorPolicyError::Disagreement(
            "candidate memo is not the exact stronger independent memo".to_string(),
        ));
    }
    Ok(())
}

/// Decode and hash the common producer's exact quote response, then rerun the
/// full local quote policy and require the advertised decision byte-for-byte.
///
/// # Errors
/// Oversized/malformed raw evidence, a raw hash/value mismatch, or a decision
/// that is not the exact policy result.
pub fn validate_common_quote(
    policy: &QuotePolicy,
    candidate: &QuoteCandidate,
    expected_vault: &str,
    inbound_valid_until: u64,
    now: u64,
) -> Result<(), ThorPolicyError> {
    const MAX_COMMON_QUOTE_BYTES: usize = 2 * 1024 * 1024;
    if candidate.raw_quote_body.is_empty()
        || candidate.raw_quote_body.len() > MAX_COMMON_QUOTE_BYTES
    {
        return Err(ThorPolicyError::Quote(
            "common raw quote is empty or exceeds 2 MiB".to_string(),
        ));
    }
    if keccak256(candidate.raw_quote_body.as_bytes()) != candidate.evidence.raw_quote_hash {
        return Err(ThorPolicyError::Quote(
            "common raw quote hash differs from evidence".to_string(),
        ));
    }
    let decoded: SwapQuoteResponse = serde_json::from_str(&candidate.raw_quote_body)
        .map_err(|error| ThorPolicyError::Quote(format!("common raw quote decode: {error}")))?;
    if decoded != candidate.evidence.response {
        return Err(ThorPolicyError::Quote(
            "common raw quote value differs from evidence".to_string(),
        ));
    }
    let decision = evaluate_quote(
        policy,
        &candidate.evidence,
        expected_vault,
        inbound_valid_until,
        now,
    )?;
    if decision != candidate.decision {
        return Err(ThorPolicyError::Disagreement(
            "common quote decision is not the exact policy result".to_string(),
        ));
    }
    Ok(())
}

/// Convert EVM token base units to `THORChain` Base (1e8). For tokens with more
/// than eight decimals, non-exact values are rejected instead of silently
/// rounding the amount sent to a different quote amount.
///
/// # Errors
/// Decimal exponent overflow, multiplication overflow or non-exact downscale.
pub fn evm_raw_to_thor(raw: U256, decimals: u8) -> Result<U256, ThorPolicyError> {
    scale_decimals(raw, decimals, 8)
}

/// Convert `THORChain` Base (1e8) back to token base units with the same exactness
/// rule.
///
/// # Errors
/// Decimal exponent overflow, multiplication overflow or non-exact downscale.
pub fn thor_to_evm_raw(raw: U256, decimals: u8) -> Result<U256, ThorPolicyError> {
    scale_decimals(raw, 8, decimals)
}

fn scale_decimals(value: U256, from: u8, to: u8) -> Result<U256, ThorPolicyError> {
    if from == to {
        return Ok(value);
    }
    let exponent = from.abs_diff(to);
    let factor = pow10(exponent)?;
    if from < to {
        value.checked_mul(factor).ok_or_else(|| {
            ThorPolicyError::Quote("decimal upscaling overflows uint256".to_string())
        })
    } else {
        if value % factor != U256::ZERO {
            return Err(ThorPolicyError::Quote(
                "amount is not exactly representable in THORChain Base".to_string(),
            ));
        }
        Ok(value / factor)
    }
}

fn pow10(exponent: u8) -> Result<U256, ThorPolicyError> {
    let mut value = U256::from(1u8);
    for _ in 0..exponent {
        value = value.checked_mul(U256::from(10u8)).ok_or_else(|| {
            ThorPolicyError::Quote("decimal scaling factor overflows uint256".to_string())
        })?;
    }
    Ok(value)
}

fn normalize_inbound_policy(policy: &InboundPolicy) -> Result<InboundPolicy, ThorPolicyError> {
    if policy.max_tip_age_secs == 0 || policy.max_height_skew == 0 {
        return Err(ThorPolicyError::Configuration(
            "tip age and height skew must be non-zero".to_string(),
        ));
    }
    let source_chain = canonical_chain(&policy.source_chain)?;
    let mut enabled_chains = policy
        .enabled_chains
        .iter()
        .map(|chain| canonical_chain(chain))
        .collect::<Result<Vec<_>, _>>()?;
    enabled_chains.sort();
    enabled_chains.dedup();
    if !enabled_chains.contains(&source_chain) {
        return Err(ThorPolicyError::Configuration(
            "enabled chains must include source chain".to_string(),
        ));
    }
    let mut allowlisted_pools = policy
        .allowlisted_pools
        .iter()
        .map(|asset| canonical_asset(asset))
        .collect::<Result<Vec<_>, _>>()?;
    allowlisted_pools.sort();
    allowlisted_pools.dedup();
    if allowlisted_pools.is_empty() {
        return Err(ThorPolicyError::Configuration(
            "at least one full pool asset is required".to_string(),
        ));
    }
    for asset in &allowlisted_pools {
        let chain = asset.split_once('.').map_or("", |(chain, _)| chain);
        if !enabled_chains.iter().any(|enabled| enabled == chain) {
            return Err(ThorPolicyError::Configuration(format!(
                "pool {asset} belongs to disabled chain {chain}"
            )));
        }
    }
    Ok(InboundPolicy {
        source_chain,
        enabled_chains,
        allowlisted_pools,
        max_tip_age_secs: policy.max_tip_age_secs,
        max_height_skew: policy.max_height_skew,
    })
}

fn canonicalize_source(
    snapshot: &SourceSnapshot,
    policy: &InboundPolicy,
    relevant_mimir: &BTreeSet<String>,
) -> Result<CanonicalSourceSnapshot, ThorPolicyError> {
    validate_public_id(&snapshot.source_id)?;
    if snapshot.observed_at == 0 {
        return Err(ThorPolicyError::Source(format!(
            "{} has zero observation time",
            snapshot.source_id
        )));
    }
    if snapshot.consensus.height == 0
        || snapshot.consensus.node_id.trim().is_empty()
        || snapshot.consensus.network.trim().is_empty()
        || snapshot.consensus.block_hash.trim().is_empty()
    {
        return Err(ThorPolicyError::Source(format!(
            "{} has incomplete consensus identity/tip",
            snapshot.source_id
        )));
    }
    if [
        snapshot.response_hashes.inbound,
        snapshot.response_hashes.mimir,
        snapshot.response_hashes.pools,
        snapshot.response_hashes.consensus,
    ]
    .contains(&B256::ZERO)
    {
        return Err(ThorPolicyError::Source(format!(
            "{} has a zero raw response hash",
            snapshot.source_id
        )));
    }

    let mut inbound = Vec::with_capacity(policy.enabled_chains.len());
    for chain in &policy.enabled_chains {
        match find_unique_inbound(&snapshot.inbound, chain)? {
            Some(row) => inbound.push(normalize_inbound(row)),
            None => {
                // Missing target routes are represented by bit 6. Missing the
                // source chain is fatal because there is no safe vault/Router.
                if chain == &policy.source_chain {
                    return Err(ThorPolicyError::Source(format!(
                        "{} has no {} inbound row",
                        snapshot.source_id, chain
                    )));
                }
            }
        }
    }
    inbound.sort_by(|left, right| left.chain.cmp(&right.chain));

    let normalized_mimir = normalize_mimir(&snapshot.mimir)?;
    let mimir = relevant_mimir
        .iter()
        .map(|key| (key.clone(), normalized_mimir.get(key).copied().unwrap_or(0)))
        .collect();

    let mut pools = Vec::with_capacity(policy.allowlisted_pools.len());
    for asset in &policy.allowlisted_pools {
        if let Some(pool) = find_unique_pool(&snapshot.pools, asset)? {
            pools.push(normalize_pool(pool));
        }
    }
    pools.sort_by(|left, right| left.asset.cmp(&right.asset));

    Ok(CanonicalSourceSnapshot {
        source_id: snapshot.source_id.clone(),
        observed_at: snapshot.observed_at,
        consensus: snapshot.consensus.clone(),
        previous_tip: snapshot.previous_tip.clone(),
        inbound,
        mimir,
        pools,
        response_hashes: snapshot.response_hashes.clone(),
    })
}

fn source_pause_flags(source: &CanonicalSourceSnapshot, policy: &InboundPolicy, now: u64) -> u8 {
    let mut flags = 0u8;
    if source.consensus.catching_up
        || source.consensus.block_time_unix > now
        || now.saturating_sub(source.consensus.block_time_unix) > policy.max_tip_age_secs
        || now.saturating_sub(source.observed_at) > policy.max_tip_age_secs
    {
        flags |= PAUSE_STALE_CONSENSUS;
    }
    if let Some(previous) = &source.previous_tip {
        if !previous.proven_advance
            || (source.observed_at.saturating_sub(previous.observed_at) >= policy.max_tip_age_secs
                && source.consensus.height <= previous.height)
        {
            flags |= PAUSE_STALE_CONSENSUS;
        }
    } else {
        // A first poll cannot prove advancement. It may be stored as evidence,
        // but never produce a live inbound state.
        flags |= PAUSE_STALE_CONSENSUS;
    }

    if mimir_enabled(&source.mimir, "HALTTRADING") {
        flags |= PAUSE_GLOBAL_TRADING;
    }
    if mimir_enabled(&source.mimir, "HALTCHAINGLOBAL") {
        flags |= PAUSE_CHAIN_HALTED;
    }
    if mimir_enabled(&source.mimir, "STREAMINGSWAPPAUSE") {
        flags |= PAUSE_STREAMING;
    }
    if mimir_enabled(&source.mimir, "PAUSELP") {
        flags |= PAUSE_TARGET_OR_POOL;
    }

    for chain in &policy.enabled_chains {
        if let Some(row) = source.inbound.iter().find(|row| &row.chain == chain) {
            if row.halted {
                flags |= PAUSE_CHAIN_HALTED;
            }
            if row.global_trading_paused {
                flags |= PAUSE_GLOBAL_TRADING;
            }
            if row.chain_trading_paused {
                flags |= PAUSE_CHAIN_TRADING;
            }
            if row.chain_lp_actions_paused {
                flags |= PAUSE_TARGET_OR_POOL;
            }
        } else {
            flags |= PAUSE_TARGET_OR_POOL;
        }
        if mimir_enabled(&source.mimir, &format!("HALT{chain}CHAIN"))
            || mimir_enabled(&source.mimir, &format!("SOLVENCYHALT{chain}"))
        {
            flags |= PAUSE_CHAIN_HALTED;
        }
        if mimir_enabled(&source.mimir, &format!("HALT{chain}TRADING")) {
            flags |= PAUSE_CHAIN_TRADING;
        }
        if mimir_enabled(&source.mimir, &format!("HALTSIGNING{chain}")) {
            flags |= PAUSE_SIGNING;
        }
        if mimir_enabled(&source.mimir, &format!("PAUSELP{chain}")) {
            flags |= PAUSE_TARGET_OR_POOL;
        }
    }

    for asset in &policy.allowlisted_pools {
        if !source
            .pools
            .iter()
            .any(|pool| pool.asset == *asset && pool.status == "Available")
            || mimir_enabled(
                &source.mimir,
                &format!("PAUSELPDEPOSIT-{}", asset.replace('.', "-")),
            )
        {
            flags |= PAUSE_TARGET_OR_POOL;
        }
    }
    flags
}

fn relevant_mimir_keys(policy: &InboundPolicy) -> BTreeSet<String> {
    let mut keys = BTreeSet::from([
        "HALTTRADING".to_string(),
        "HALTCHAINGLOBAL".to_string(),
        "STREAMINGSWAPPAUSE".to_string(),
        "PAUSELP".to_string(),
    ]);
    for chain in &policy.enabled_chains {
        keys.insert(format!("HALT{chain}CHAIN"));
        keys.insert(format!("HALT{chain}TRADING"));
        keys.insert(format!("HALTSIGNING{chain}"));
        keys.insert(format!("PAUSELP{chain}"));
        keys.insert(format!("SOLVENCYHALT{chain}"));
    }
    for asset in &policy.allowlisted_pools {
        keys.insert(format!("PAUSELPDEPOSIT-{}", asset.replace('.', "-")));
    }
    keys
}

fn normalize_mimir(mimir: &Mimir) -> Result<BTreeMap<String, i64>, ThorPolicyError> {
    let mut normalized = BTreeMap::new();
    for (key, value) in mimir {
        let key = key.to_ascii_uppercase();
        if let Some(previous) = normalized.insert(key.clone(), *value) {
            if previous != *value {
                return Err(ThorPolicyError::Source(format!(
                    "Mimir key {key} appears twice with different case/value"
                )));
            }
        }
    }
    Ok(normalized)
}

fn mimir_enabled(mimir: &BTreeMap<String, i64>, key: &str) -> bool {
    mimir.get(key).copied().unwrap_or(0) > 0
}

fn required_inbound<'a>(
    rows: &'a [InboundAddress],
    chain: &str,
) -> Result<&'a InboundAddress, ThorPolicyError> {
    rows.iter()
        .find(|row| row.chain == chain)
        .ok_or_else(|| ThorPolicyError::Source(format!("missing canonical inbound row {chain}")))
}

fn find_unique_inbound<'a>(
    rows: &'a [InboundAddress],
    chain: &str,
) -> Result<Option<&'a InboundAddress>, ThorPolicyError> {
    let mut matches = rows
        .iter()
        .filter(|row| row.chain.eq_ignore_ascii_case(chain));
    let first = matches.next();
    if matches.next().is_some() {
        return Err(ThorPolicyError::Source(format!(
            "duplicate inbound rows for {chain}"
        )));
    }
    Ok(first)
}

fn find_unique_pool<'a>(
    pools: &'a [Pool],
    asset: &str,
) -> Result<Option<&'a Pool>, ThorPolicyError> {
    let mut matches = pools
        .iter()
        .filter(|pool| pool.asset.eq_ignore_ascii_case(asset));
    let first = matches.next();
    if matches.next().is_some() {
        return Err(ThorPolicyError::Source(format!(
            "duplicate pool rows for {asset}"
        )));
    }
    Ok(first)
}

fn normalize_inbound(row: &InboundAddress) -> InboundAddress {
    InboundAddress {
        chain: row.chain.to_ascii_uppercase(),
        pub_key: row.pub_key.clone(),
        address: row.address.to_ascii_lowercase(),
        router: row.router.as_ref().map(|value| value.to_ascii_lowercase()),
        halted: row.halted,
        global_trading_paused: row.global_trading_paused,
        chain_trading_paused: row.chain_trading_paused,
        chain_lp_actions_paused: row.chain_lp_actions_paused,
        gas_rate: row.gas_rate.clone(),
        gas_rate_units: row.gas_rate_units.clone(),
    }
}

fn normalize_pool(pool: &Pool) -> Pool {
    Pool {
        asset: pool.asset.to_ascii_uppercase(),
        status: pool.status.clone(),
        balance_asset: pool.balance_asset.clone(),
        balance_rune: pool.balance_rune.clone(),
        asset_tor_price: pool.asset_tor_price.clone(),
    }
}

fn canonical_chain(raw: &str) -> Result<String, ThorPolicyError> {
    if raw.is_empty()
        || raw.len() > 16
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(ThorPolicyError::Configuration(format!(
            "chain '{raw}' must be canonical uppercase alphanumeric"
        )));
    }
    Ok(raw.to_string())
}

fn canonical_asset(raw: &str) -> Result<String, ThorPolicyError> {
    let Some((chain, symbol)) = raw.split_once('.') else {
        return Err(ThorPolicyError::Configuration(format!(
            "asset '{raw}' must contain one dot"
        )));
    };
    if symbol.is_empty()
        || symbol.contains('.')
        || raw.len() > 128
        || !raw.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
    {
        return Err(ThorPolicyError::Configuration(format!(
            "asset '{raw}' is not full canonical uppercase notation"
        )));
    }
    canonical_chain(chain)?;
    Ok(raw.to_string())
}

fn validate_public_id(raw: &str) -> Result<(), ThorPolicyError> {
    if raw.is_empty()
        || raw.len() > 128
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ThorPolicyError::Source(
            "source id must be a public alphanumeric label, not a URL/credential".to_string(),
        ));
    }
    Ok(())
}

fn validate_quote_policy(policy: &QuotePolicy) -> Result<(), ThorPolicyError> {
    if policy.allowlisted_assets.is_empty()
        || policy.min_price_sources < 3
        || policy.max_price_age_secs == 0
        || policy.max_price_deviation_bps == 0
        || policy.max_price_deviation_bps >= 10_000
        || policy.external_floor_bps == 0
        || policy.external_floor_bps > 10_000
        || policy.max_dispatch_ttl_secs == 0
        || policy.max_stream_blocks == 0
        || policy.max_total_swap_secs == 0
    {
        return Err(ThorPolicyError::Configuration(
            "quote policy contains an unsafe zero/range value".to_string(),
        ));
    }
    let mut seen = HashSet::new();
    for asset in &policy.allowlisted_assets {
        canonical_asset(asset)?;
        if !seen.insert(asset) {
            return Err(ThorPolicyError::Configuration(format!(
                "duplicate quote asset {asset}"
            )));
        }
    }
    Ok(())
}

fn validate_quote_request(request: &SwapQuoteRequest) -> Result<(), ThorPolicyError> {
    if request.from_asset.is_empty()
        || request.to_asset.is_empty()
        || request.destination.is_empty()
        || request.refund_address.is_empty()
        || request.amount.is_empty()
        || !(1..10_000).contains(&request.liquidity_tolerance_bps)
        || request.streaming_quantity == 0
        || (request.streaming_quantity == 1 && request.streaming_interval != 1)
    {
        return Err(ThorPolicyError::Quote(
            "quote request is incomplete or uses implicit/invalid bounds".to_string(),
        ));
    }
    Ok(())
}

fn require_allowlisted_asset<'a>(
    allowlist: &'a [String],
    requested: &str,
) -> Result<&'a str, ThorPolicyError> {
    canonical_asset(requested)?;
    allowlist
        .iter()
        .find(|asset| asset.as_str() == requested)
        .map(String::as_str)
        .ok_or_else(|| ThorPolicyError::Quote(format!("asset {requested} is not allowlisted")))
}

fn resolve_asset<'a>(
    allowlist: &'a [String],
    possibly_short: &str,
) -> Result<&'a str, ThorPolicyError> {
    let upper = possibly_short.to_ascii_uppercase();
    let mut matches = allowlist
        .iter()
        .filter(|asset| asset.as_str() == upper || asset.starts_with(&upper));
    let first = matches.next().ok_or_else(|| {
        ThorPolicyError::Quote(format!(
            "quote asset {possibly_short} has no allowlisted resolution"
        ))
    })?;
    if matches.next().is_some() {
        return Err(ThorPolicyError::Quote(format!(
            "quote asset {possibly_short} is an ambiguous abbreviation"
        )));
    }
    Ok(first)
}

fn validate_fees(
    response: &SwapQuoteResponse,
    allowlist: &[String],
    target_asset: &str,
) -> Result<(), ThorPolicyError> {
    if resolve_asset(allowlist, &response.fees.asset)? != target_asset {
        return Err(ThorPolicyError::Quote(
            "fee asset differs from target asset".to_string(),
        ));
    }
    let affiliate = parse_u256("affiliate fee", &response.fees.affiliate)?;
    let _outbound = parse_u256("outbound fee", &response.fees.outbound)?;
    let _liquidity = parse_u256("liquidity fee", &response.fees.liquidity)?;
    let _total = parse_u256("total fee", &response.fees.total)?;
    if affiliate != U256::ZERO {
        return Err(ThorPolicyError::Quote(
            "affiliate fee must be zero".to_string(),
        ));
    }
    if response.fees.slippage_bps >= 10_000 || response.fees.total_bps >= 10_000 {
        return Err(ThorPolicyError::Quote(
            "quote fee/slippage basis points are out of range".to_string(),
        ));
    }
    Ok(())
}

struct ParsedMemo<'a> {
    asset: &'a str,
    destination: &'a str,
    refund: &'a str,
    limit: &'a str,
    interval: u64,
    quantity: u64,
}

fn parse_swap_memo(raw: &str) -> Result<ParsedMemo<'_>, ThorPolicyError> {
    let fields = raw.split(':').collect::<Vec<_>>();
    if fields.len() != 4 || fields[0] != "=" {
        return Err(ThorPolicyError::Quote(
            "quote memo is not exact =:ASSET:DEST/REFUND:LIM/INT/QTY".to_string(),
        ));
    }
    let destinations = fields[2].split('/').collect::<Vec<_>>();
    let limit = fields[3].split('/').collect::<Vec<_>>();
    if destinations.len() != 2
        || destinations.iter().any(|field| field.is_empty())
        || limit.len() != 3
        || limit.iter().any(|field| field.is_empty())
    {
        return Err(ThorPolicyError::Quote(
            "quote memo has implicit, empty or extra fields".to_string(),
        ));
    }
    let interval = limit[1]
        .parse::<u64>()
        .map_err(|error| ThorPolicyError::Quote(format!("memo interval: {error}")))?;
    let quantity = limit[2]
        .parse::<u64>()
        .map_err(|error| ThorPolicyError::Quote(format!("memo quantity: {error}")))?;
    Ok(ParsedMemo {
        asset: fields[1],
        destination: destinations[0],
        refund: destinations[1],
        limit: limit[0],
        interval,
        quantity,
    })
}

fn independent_price_floor(
    policy: &QuotePolicy,
    evidence: &QuoteEvidence,
    amount: U256,
    now: u64,
) -> Result<U256, ThorPolicyError> {
    if evidence.external_prices.len() < policy.min_price_sources {
        return Err(ThorPolicyError::Quote(format!(
            "only {} external price sources, need {}",
            evidence.external_prices.len(),
            policy.min_price_sources
        )));
    }
    let mut identities = HashSet::new();
    let mut outputs = Vec::with_capacity(evidence.external_prices.len());
    for observation in &evidence.external_prices {
        validate_public_id(&observation.source_id)?;
        if !identities.insert(&observation.source_id) {
            return Err(ThorPolicyError::Quote(
                "external price source identities must be distinct".to_string(),
            ));
        }
        if observation.raw_response_hash == B256::ZERO
            || observation.observed_at == 0
            || observation.observed_at > now
            || now - observation.observed_at > policy.max_price_age_secs
        {
            return Err(ThorPolicyError::Quote(
                "external price evidence is missing, stale or future-dated".to_string(),
            ));
        }
        let funding = parse_nonzero_u256("funding price", &observation.funding_price_wad)?;
        let target = parse_nonzero_u256("target price", &observation.target_price_wad)?;
        let output = amount
            .checked_mul(funding)
            .ok_or_else(|| ThorPolicyError::Quote("price conversion overflows".to_string()))?
            / target;
        if output == U256::ZERO {
            return Err(ThorPolicyError::Quote(
                "external price conversion rounds to zero".to_string(),
            ));
        }
        outputs.push(output);
    }
    outputs.sort_unstable();
    let median = outputs[outputs.len() / 2];
    for output in &outputs {
        let deviation = if *output >= median {
            *output - median
        } else {
            median - *output
        };
        let lhs = deviation
            .checked_mul(U256::from(10_000u64))
            .ok_or_else(|| ThorPolicyError::Quote("price deviation overflows".to_string()))?;
        let rhs = median
            .checked_mul(U256::from(policy.max_price_deviation_bps))
            .ok_or_else(|| ThorPolicyError::Quote("price deviation bound overflows".to_string()))?;
        if lhs > rhs {
            return Err(ThorPolicyError::Quote(
                "external price sources exceed the deviation bound".to_string(),
            ));
        }
    }
    median
        .checked_mul(U256::from(policy.external_floor_bps))
        .map(|value| value / U256::from(10_000u64))
        .ok_or_else(|| ThorPolicyError::Quote("external floor overflows".to_string()))
}

fn hash_quote_evidence(evidence: &QuoteEvidence) -> Result<B256, ThorPolicyError> {
    let mut canonical = evidence.clone();
    canonical
        .external_prices
        .sort_by(|left, right| left.source_id.cmp(&right.source_id));
    hash_serialized(&canonical)
}

fn hash_serialized<T: Serialize>(value: &T) -> Result<B256, ThorPolicyError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| ThorPolicyError::Serialization(error.to_string()))?;
    Ok(keccak256(encoded))
}

fn parse_u256(field: &'static str, raw: &str) -> Result<U256, ThorPolicyError> {
    U256::from_str_radix(raw, 10)
        .map_err(|error| ThorPolicyError::Quote(format!("{field} is not uint256: {error}")))
}

fn parse_nonzero_u256(field: &'static str, raw: &str) -> Result<U256, ThorPolicyError> {
    let value = parse_u256(field, raw)?;
    if value == U256::ZERO {
        return Err(ThorPolicyError::Quote(format!("{field} is zero")));
    }
    Ok(value)
}

fn address_eq(left: &str, right: &str) -> bool {
    if left.starts_with("0x") && right.starts_with("0x") {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

fn rebuild_memo_with_limit(memo: &str, min_out: U256) -> Result<String, ThorPolicyError> {
    let parsed = parse_swap_memo(memo)?;
    Ok(format!(
        "=:{}:{}/{}:{}/{}/{}",
        parsed.asset, parsed.destination, parsed.refund, min_out, parsed.interval, parsed.quantity
    ))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use super::*;

    fn inbound(chain: &str, address: &str, router: Option<&str>) -> InboundAddress {
        InboundAddress {
            chain: chain.to_string(),
            pub_key: "thorpub1source".to_string(),
            address: address.to_string(),
            router: router.map(str::to_string),
            halted: false,
            global_trading_paused: false,
            chain_trading_paused: false,
            chain_lp_actions_paused: false,
            gas_rate: Some("10".to_string()),
            gas_rate_units: Some("gwei".to_string()),
        }
    }

    fn pool(asset: &str) -> Pool {
        Pool {
            asset: asset.to_string(),
            status: "Available".to_string(),
            balance_asset: "100000000000".to_string(),
            balance_rune: "200000000000".to_string(),
            asset_tor_price: Some("500000000".to_string()),
        }
    }

    fn snapshot(id: &str, height: u64, now: u64) -> SourceSnapshot {
        SourceSnapshot {
            source_id: id.to_string(),
            observed_at: now,
            consensus: ConsensusTip {
                node_id: format!("node-{id}"),
                network: "thorchain-mainnet-v1".to_string(),
                version: "1.0.0".to_string(),
                block_hash: format!("HASH{height}"),
                height,
                block_time_unix: now - 2,
                catching_up: false,
            },
            previous_tip: Some(TipCheckpoint {
                height: height - 1,
                observed_at: now - 6,
                proven_advance: true,
            }),
            inbound: vec![
                inbound(
                    "ETH",
                    "0x1111111111111111111111111111111111111111",
                    Some("0x2222222222222222222222222222222222222222"),
                ),
                inbound("BTC", "bc1qvault", None),
            ],
            mimir: BTreeMap::new(),
            pools: vec![pool("BTC.BTC"), pool("ETH.USDT-0XDAC17F")],
            response_hashes: SourceResponseHashes {
                inbound: B256::repeat_byte(1),
                mimir: B256::repeat_byte(2),
                pools: B256::repeat_byte(3),
                consensus: B256::repeat_byte(4),
            },
        }
    }

    fn inbound_policy() -> InboundPolicy {
        InboundPolicy {
            source_chain: "ETH".to_string(),
            enabled_chains: vec!["ETH".to_string(), "BTC".to_string()],
            allowlisted_pools: vec!["BTC.BTC".to_string(), "ETH.USDT-0XDAC17F".to_string()],
            max_tip_age_secs: 12,
            max_height_skew: 2,
        }
    }

    #[test]
    fn healthy_three_source_bundle_is_live_and_order_independent() {
        let now = 1_800_000_000;
        let a = snapshot("owned", 100, now);
        let b = snapshot("provider-a", 101, now);
        let c = snapshot("provider-b", 100, now);
        let left = derive_inbound(&inbound_policy(), &[a.clone(), b.clone(), c.clone()], now)
            .expect("healthy bundle");
        let right = derive_inbound(&inbound_policy(), &[c, a, b], now).expect("reordered bundle");
        assert_eq!(left.pause_flags, 0);
        assert_eq!(left.source_hash, right.source_hash);
        assert_eq!(left.vault, "0x1111111111111111111111111111111111111111");
    }

    #[test]
    fn source_cannot_bootstrap_liveness_without_a_proven_tip_advance() {
        let now = 1_800_000_000;
        let mut first_seen = [
            snapshot("owned", 100, now),
            snapshot("provider-a", 100, now),
            snapshot("provider-b", 100, now),
        ];
        for source in &mut first_seen {
            source.previous_tip = None;
        }
        let first = derive_inbound(&inbound_policy(), &first_seen, now).expect("first poll");
        assert_ne!(first.pause_flags & PAUSE_STALE_CONSENSUS, 0);

        let mut repeated = first_seen;
        for source in &mut repeated {
            source.previous_tip = Some(TipCheckpoint {
                height: 100,
                observed_at: now - 6,
                proven_advance: false,
            });
        }
        let repeated = derive_inbound(&inbound_policy(), &repeated, now).expect("repeated poll");
        assert_ne!(repeated.pause_flags & PAUSE_STALE_CONSENSUS, 0);

        let advanced = [
            snapshot("owned", 101, now),
            snapshot("provider-a", 101, now),
            snapshot("provider-b", 101, now),
        ];
        let live = derive_inbound(&inbound_policy(), &advanced, now).expect("advanced poll");
        assert_eq!(live.pause_flags & PAUSE_STALE_CONSENSUS, 0);
    }

    #[test]
    fn common_candidate_must_be_exact_derivation_of_committed_bundle() {
        let now = 1_800_000_000;
        let snapshots = [
            snapshot("owned", 100, now),
            snapshot("provider-a", 101, now),
            snapshot("provider-b", 100, now),
        ];
        let candidate =
            derive_inbound(&inbound_policy(), &snapshots, now).expect("candidate derivation");
        validate_common_inbound(&inbound_policy(), &candidate, now).expect("exact candidate");

        let mut arbitrary = candidate.clone();
        arbitrary.pause_flags |= PAUSE_SIGNING;
        assert!(validate_common_inbound(&inbound_policy(), &arbitrary, now).is_err());

        let mut tampered = candidate;
        tampered.bundle.sources[0].consensus.height += 1;
        assert!(validate_common_inbound(&inbound_policy(), &tampered, now).is_err());
    }

    #[test]
    fn halt_stale_tip_and_missing_pool_set_fail_closed_bits() {
        let now = 1_800_000_000;
        let a = snapshot("owned", 100, now);
        let mut b = snapshot("provider-a", 100, now);
        let c = snapshot("provider-b", 100, now);
        b.mimir.insert("HaltSigningBTC".to_string(), 1);
        b.consensus.block_time_unix = now - 20;
        b.pools.retain(|row| row.asset != "BTC.BTC");
        let derived = derive_inbound(&inbound_policy(), &[a, b, c], now).expect("paused bundle");
        assert_eq!(
            derived.pause_flags & (PAUSE_SIGNING | PAUSE_STALE_CONSENSUS | PAUSE_TARGET_OR_POOL),
            PAUSE_SIGNING | PAUSE_STALE_CONSENSUS | PAUSE_TARGET_OR_POOL
        );
    }

    #[test]
    fn independent_candidate_cannot_clear_local_pause() {
        let now = 1_800_000_000;
        let snapshots = [
            snapshot("owned", 100, now),
            snapshot("provider-a", 100, now),
            snapshot("provider-b", 100, now),
        ];
        let mut candidate = derive_inbound(&inbound_policy(), &snapshots, now).expect("candidate");
        let mut local = candidate.clone();
        local.pause_flags = PAUSE_SIGNING;
        assert!(validate_independent_inbound(&candidate, &local).is_err());
        candidate.pause_flags = PAUSE_SIGNING | PAUSE_STALE_CONSENSUS;
        assert!(validate_independent_inbound(&candidate, &local).is_ok());
    }

    fn quote_response() -> SwapQuoteResponse {
        SwapQuoteResponse {
            inbound_address: "0x1111111111111111111111111111111111111111".to_string(),
            inbound_confirmation_blocks: 2,
            inbound_confirmation_seconds: 24,
            outbound_delay_blocks: 10,
            outbound_delay_seconds: 60,
            fees: crate::types::SwapQuoteFees {
                asset: "BTC.B".to_string(),
                affiliate: "0".to_string(),
                outbound: "100".to_string(),
                liquidity: "200".to_string(),
                total: "300".to_string(),
                slippage_bps: 20,
                total_bps: 30,
            },
            expiry: 1_800_000_120,
            warning: "Do not cache; expires soon".to_string(),
            dust_threshold: "100".to_string(),
            recommended_min_amount_in: "1000".to_string(),
            recommended_gas_rate: "20".to_string(),
            gas_rate_units: "gwei".to_string(),
            memo: "=:BTC.B:bc1qcustody/0x3333333333333333333333333333333333333333:950000/1/1"
                .to_string(),
            expected_amount_out: "1000000".to_string(),
            max_streaming_quantity: 1,
            streaming_swap_blocks: 0,
            streaming_swap_seconds: 0,
            total_swap_seconds: 84,
        }
    }

    fn quote_evidence() -> QuoteEvidence {
        QuoteEvidence {
            schema: "xindex.thorchain-quote-evidence.v1".to_string(),
            quote_source_id: "canonical-quote".to_string(),
            request: SwapQuoteRequest {
                from_asset: "ETH.USDT-0XDAC17F".to_string(),
                to_asset: "BTC.BTC".to_string(),
                amount: "1000000".to_string(),
                destination: "bc1qcustody".to_string(),
                refund_address: "0x3333333333333333333333333333333333333333".to_string(),
                liquidity_tolerance_bps: 500,
                streaming_interval: 1,
                streaming_quantity: 1,
            },
            response: quote_response(),
            raw_quote_hash: B256::repeat_byte(9),
            external_prices: [
                ("price-a", "1000000000000000000", "1000000000000000000"),
                ("price-b", "1001000000000000000", "1000000000000000000"),
                ("price-c", "999000000000000000", "1000000000000000000"),
            ]
            .into_iter()
            .enumerate()
            .map(
                |(index, (source_id, funding, target))| ExternalPriceObservation {
                    source_id: source_id.to_string(),
                    funding_price_wad: funding.to_string(),
                    target_price_wad: target.to_string(),
                    observed_at: 1_800_000_000,
                    raw_response_hash: B256::repeat_byte(u8::try_from(index + 10).expect("byte")),
                },
            )
            .collect(),
        }
    }

    fn quote_policy() -> QuotePolicy {
        QuotePolicy {
            allowlisted_assets: vec!["ETH.USDT-0XDAC17F".to_string(), "BTC.BTC".to_string()],
            min_price_sources: 3,
            max_price_age_secs: 60,
            max_price_deviation_bps: 100,
            external_floor_bps: 9_900,
            max_dispatch_ttl_secs: 90,
            max_stream_blocks: 150,
            max_total_swap_secs: 1_800,
        }
    }

    #[test]
    fn quote_uses_stricter_external_floor_and_full_asset_memo() {
        let evidence = quote_evidence();
        let decision = evaluate_quote(
            &quote_policy(),
            &evidence,
            "0x1111111111111111111111111111111111111111",
            1_800_000_100,
            1_800_000_000,
        )
        .expect("safe quote");
        assert_eq!(decision.min_out_1e8, "990000");
        assert_eq!(
            decision.memo,
            "=:BTC.BTC:bc1qcustody/0x3333333333333333333333333333333333333333:990000/1/1"
        );
        assert_eq!(decision.dispatch_deadline, 1_800_000_090);
        assert_ne!(decision.quote_hash, B256::ZERO);
    }

    #[test]
    fn common_quote_requires_exact_raw_response_and_decision() {
        let mut evidence = quote_evidence();
        let raw = serde_json::to_string(&evidence.response).expect("raw quote");
        evidence.raw_quote_hash = keccak256(raw.as_bytes());
        let decision = evaluate_quote(
            &quote_policy(),
            &evidence,
            "0x1111111111111111111111111111111111111111",
            1_800_000_100,
            1_800_000_000,
        )
        .expect("decision");
        let mut candidate = QuoteCandidate {
            evidence,
            raw_quote_body: raw,
            decision,
            adapter: format!("0x{}", "11".repeat(20)),
            index_token: format!("0x{}", "22".repeat(20)),
            originator: format!("0x{}", "33".repeat(20)),
            funding_token: format!("0x{}", "44".repeat(20)),
            target_token: format!("0x{}", "55".repeat(20)),
            amount_in: "1000000".to_string(),
            custody_hash: B256::repeat_byte(6),
            inbound_state_hash: B256::repeat_byte(7),
            current_state_valid_until: 1_800_000_100,
            finalized_onchain_nonce: 4,
        };
        validate_common_quote(
            &quote_policy(),
            &candidate,
            "0x1111111111111111111111111111111111111111",
            1_800_000_100,
            1_800_000_000,
        )
        .expect("exact common quote");
        candidate.raw_quote_body.push(' ');
        assert!(validate_common_quote(
            &quote_policy(),
            &candidate,
            "0x1111111111111111111111111111111111111111",
            1_800_000_100,
            1_800_000_000,
        )
        .is_err());
    }

    #[test]
    fn quote_rejects_affiliate_and_ambiguous_abbreviation() {
        let mut evidence = quote_evidence();
        evidence.response.fees.affiliate = "1".to_string();
        assert!(evaluate_quote(
            &quote_policy(),
            &evidence,
            "0x1111111111111111111111111111111111111111",
            1_800_000_100,
            1_800_000_000,
        )
        .is_err());

        let mut policy = quote_policy();
        policy.allowlisted_assets.push("BTC.BCH".to_string());
        evidence.response.fees.affiliate = "0".to_string();
        assert!(evaluate_quote(
            &policy,
            &evidence,
            "0x1111111111111111111111111111111111111111",
            1_800_000_100,
            1_800_000_000,
        )
        .is_err());
    }

    #[test]
    fn decimal_conversion_is_exact_and_symmetric() {
        let usdt = U256::from(1_234_567u64);
        let thor = evm_raw_to_thor(usdt, 6).expect("6 to 8 decimals");
        assert_eq!(thor, U256::from(123_456_700u64));
        assert_eq!(thor_to_evm_raw(thor, 6).expect("8 to 6"), usdt);
        assert!(evm_raw_to_thor(U256::from(1u8), 18).is_err());
    }
}
