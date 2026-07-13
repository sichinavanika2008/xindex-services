//! Self-driven price-attestation signing (workstream A,
//! `DL-INDEX-METHOD-ORACLE-1`).
//!
//! Unlike the custody handlers (which sign a coordinator-supplied request), a
//! price signer is a PRODUCER: it fetches the asset price from multiple
//! independent venues, aggregates them itself (median + outlier rejection,
//! [`xindex_shared::price_aggregate`]), and signs its OWN robust price — it
//! never signs a price it was handed. That is the CTD-1 "don't trust the
//! coordinator for the thing you sign" property applied to the NAV oracle.
//!
//! This module is the signing CORE: spatial median across venues
//! ([`xindex_shared::price_aggregate`]) -> temporal TWAP over the trailing
//! window ([`xindex_shared::price_twap`]) -> per-asset monotonic
//! (anti-equivocation) guard -> EIP-712 digest -> HSM sign -> recover-verify
//! (the M6 backstop). The venue HTTP clients that supply the quotes and the
//! publish loop are a separate I/O layer on top of this.

use alloy_primitives::{Address, PrimitiveSignature, B256, U256};
use alloy_sol_types::Eip712Domain;
use thiserror::Error;
use xindex_shared::eip712::{price_attestation, price_attestation_signing_hash};
use xindex_shared::price_aggregate::{aggregate_price, AggregateError};
use xindex_shared::price_twap::{time_weighted_average, TwapConfig, TwapError, TwapSample};

use crate::web3signer::{HsmDigestSigner, HsmError};

/// Per-signer price policy.
#[derive(Debug, Clone, Copy)]
pub struct PricePolicy {
    /// Minimum independent PRICE venues required (fail closed below this).
    pub min_venues: usize,
    /// Maximum deviation from the median before a quote is an outlier (applies
    /// to both the price and the supply aggregation).
    pub max_deviation_bps: u32,
    /// Minimum independent SUPPLY sources required. Separate (and typically
    /// lower) than `min_venues`: far fewer independent circulating-supply feeds
    /// exist than price venues, and supply is slow-moving. It is signed because
    /// it is part of the deployed EIP-712/on-chain quote shape; the current NAV
    /// consumer reads price only, so supply is not presently a mint input.
    pub supply_min_venues: usize,
    /// Decimal significant digits retained in the signed price. Every signer
    /// applies the same deterministic floor after its independent TWAP. This
    /// makes close honest observations converge to byte-identical payloads;
    /// the collector still requires an exact k-of-n match.
    pub price_significant_digits: u8,
    /// Decimal significant digits retained in the signed raw supply. Supply is
    /// slow moving, but it is still part of the EIP-712 plaintext and therefore
    /// must be canonicalized identically across signers.
    pub supply_significant_digits: u8,
    /// Temporal smoothing applied to the sequence of spatial medians, AFTER the
    /// venue outlier rejection (OM-4). Removes flash / one-interval manipulation
    /// that briefly captures a venue majority.
    pub twap: TwapConfig,
}

/// One fully-aggregated price observation to sign.
#[derive(Debug, Clone)]
pub struct PriceObservation {
    /// Registry asset id (keccak of the `THORChain` asset string).
    pub asset_id: B256,
    /// The robust price the signature commits to — the spatial median passed
    /// through the temporal TWAP (both fail-closed upstream).
    pub price_wad: U256,
    /// Token supply attested and stored alongside the price. The current NAV
    /// consumer discards it, but it remains part of the deployed signed shape.
    pub supply: U256,
    /// Observation time (unix secs); MUST strictly exceed `last_signed_at`.
    pub timestamp: u64,
    /// The last timestamp this signer signed for this asset (anti-equivocation
    /// monotonic guard; `None` for the first observation).
    pub last_signed_at: Option<u64>,
}

/// A complete signed price attestation. The collector needs every signed field
/// (including supply) to group byte-identical payloads safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPrice {
    /// Registry asset id committed by the signature.
    pub asset_id: B256,
    /// The aggregated (robust) price the signature commits to.
    pub price_wad: U256,
    /// Raw circulating supply committed by the signature.
    pub supply: U256,
    /// Deterministic observation epoch committed by the signature.
    pub timestamp: u64,
    /// Address recovered from the signature (and pinned to the configured HSM
    /// address before this value is returned).
    pub signer_address: Address,
    /// 65-byte recoverable ECDSA signature over the EIP-712 digest.
    pub signature: [u8; 65],
}

/// Why a price signing was refused (all fail-closed).
#[derive(Debug, Error)]
pub enum PriceSignError {
    /// Venue aggregation did not reach consensus.
    #[error("price aggregation: {0}")]
    Aggregate(#[from] AggregateError),
    /// Temporal TWAP smoothing did not produce a trustworthy price (cold start,
    /// stale feed, or too-thin window — all fail-closed).
    #[error("price twap: {0}")]
    Twap(#[from] TwapError),
    /// Significant-digit canonicalization was misconfigured. Signing without
    /// canonicalization would silently destroy exact quorum liveness.
    #[error("{field} significant digits must be in 1..=78 (got {digits})")]
    InvalidCanonicalDigits {
        /// Policy field that was invalid.
        field: &'static str,
        /// Rejected significant-digit count.
        digits: u8,
    },
    /// `timestamp` did not strictly exceed the last signed timestamp for this
    /// asset — refuse, lest two prices be signed for one instant (equivocation).
    #[error("non-monotonic timestamp {timestamp} <= last signed {last}")]
    NonMonotonic {
        /// The rejected observation timestamp.
        timestamp: u64,
        /// The last timestamp already signed for this asset.
        last: u64,
    },
    /// HSM signing failed.
    #[error("hsm: {0}")]
    Hsm(#[from] HsmError),
    /// The HSM signature did not recover to the configured signer address
    /// (M6 backstop — catches an HSM key-mapping bug before publishing).
    #[error("signature recovered to {recovered}, expected {expected}")]
    RecoverMismatch {
        /// Address the returned signature recovered to.
        recovered: Address,
        /// Address the signer key was expected to be.
        expected: Address,
    },
    /// The HSM returned bytes that do not parse / recover as a 65-byte ECDSA
    /// signature.
    #[error("signature parse: {0}")]
    SignatureParse(String),
}

/// Enforce strictly-increasing per-asset timestamps. A signer that only ever
/// signs increasing timestamps for an asset can never sign two prices for the
/// same instant, so it cannot equivocate.
fn check_monotonic(timestamp: u64, last_signed_at: Option<u64>) -> Result<(), PriceSignError> {
    match last_signed_at {
        Some(last) if timestamp <= last => Err(PriceSignError::NonMonotonic { timestamp, last }),
        _ => Ok(()),
    }
}

/// Sign an already-aggregated `PriceObservation` (spatial median → TWAP done by
/// the caller) as a `PriceAttestation` with the HSM, then verify the signature
/// recovers to `signer_address`. Enforces the per-asset monotonic guard first.
///
/// # Errors
/// Fails CLOSED with [`PriceSignError`]: a non-monotonic timestamp, an HSM
/// error, or a recover-verify mismatch.
pub async fn sign_observed_price<H: HsmDigestSigner>(
    hsm: &H,
    signer_address: Address,
    domain: &Eip712Domain,
    obs: &PriceObservation,
) -> Result<SignedPrice, PriceSignError> {
    check_monotonic(obs.timestamp, obs.last_signed_at)?;
    let att = price_attestation(obs.asset_id, obs.price_wad, obs.supply, obs.timestamp);
    let digest = price_attestation_signing_hash(&att, domain);
    let signature = hsm.sign_digest(signer_address, digest).await?;
    // PriceAttestationOracle uses OpenZeppelin ECDSA, which enforces EIP-2
    // low-S. Normalize defensively (Web3Signer normally already emits low-S)
    // and recover-verify the exact canonical bytes we publish.
    let parsed = PrimitiveSignature::try_from(&signature[..])
        .map_err(|e| PriceSignError::SignatureParse(e.to_string()))?;
    let canonical = parsed.normalize_s().unwrap_or(parsed);
    let recovered = canonical
        .recover_address_from_prehash(&digest)
        .map_err(|e| PriceSignError::SignatureParse(e.to_string()))?;
    if recovered != signer_address {
        return Err(PriceSignError::RecoverMismatch {
            recovered,
            expected: signer_address,
        });
    }
    Ok(SignedPrice {
        asset_id: obs.asset_id,
        price_wad: obs.price_wad,
        supply: obs.supply,
        timestamp: obs.timestamp,
        signer_address,
        signature: canonical.as_bytes(),
    })
}

/// Deterministically floor a decimal integer to `significant_digits` decimal
/// significant digits. This is deliberately an integer operation over the
/// already-robust observation; it does not introduce a coordinator-chosen
/// price. For example, `43_217` at four digits becomes `43_210`.
///
/// The maximum downward movement is less than `10^(1-digits)` of the value
/// (four digits: <10 bps). Production config is validated separately so a
/// coarse setting cannot be introduced accidentally.
fn canonicalize_significant(value: U256, significant_digits: u8) -> U256 {
    let decimal_digits = value.to_string().len();
    let keep = usize::from(significant_digits);
    if decimal_digits <= keep {
        return value;
    }
    let mut quantum = U256::from(1u8);
    for _ in 0..(decimal_digits - keep) {
        // `decimal_digits <= 78` for U256 and we only raise to at most
        // 10^77 here, so this multiplication cannot saturate.
        quantum = quantum.saturating_mul(U256::from(10u8));
    }
    (value / quantum) * quantum
}

fn validate_canonical_digits(policy: PricePolicy) -> Result<(), PriceSignError> {
    if !(1..=78).contains(&policy.price_significant_digits) {
        return Err(PriceSignError::InvalidCanonicalDigits {
            field: "price",
            digits: policy.price_significant_digits,
        });
    }
    if !(1..=78).contains(&policy.supply_significant_digits) {
        return Err(PriceSignError::InvalidCanonicalDigits {
            field: "supply",
            digits: policy.supply_significant_digits,
        });
    }
    Ok(())
}

/// Where to source one asset's price + circulating supply for a producer step.
#[derive(Debug)]
pub struct ProducerInputs<'a> {
    /// Registry asset id.
    pub asset_id: B256,
    /// Token decimals (scales the sourced circulating supply to raw units).
    pub decimals: u8,
    /// Independent price feeds (CEX tickers).
    pub price_feeds: &'a [crate::price_venue::Feed<'a>],
    /// Independent circulating-supply feeds.
    pub supply_feeds: &'a [crate::price_supply::SupplyFeed<'a>],
    /// Observation time (unix secs); strictly increasing per asset.
    pub timestamp: u64,
    /// Last timestamp signed for this asset (monotonic guard).
    pub last_signed_at: Option<u64>,
}

/// Already-sourced observations plus the exact signing identity. The binary
/// uses this shape after durably persisting the raw provider responses, so the
/// values aggregated here are provably the values present in its evidence
/// bundle rather than a second HTTP fetch.
#[derive(Debug)]
pub struct ObservedProducerInputs<'a> {
    pub asset_id: B256,
    pub price_quotes: &'a [U256],
    pub supply_quotes: &'a [U256],
    pub timestamp: u64,
    pub last_signed_at: Option<u64>,
}

/// The full self-driven producer step for one asset: source price + supply from
/// the configured venues, spatially median each (outlier-rejected, fail-closed),
/// record the price sample into the per-asset TWAP `history`, temporally average
/// the trailing window, and sign the result. `history` is the caller-owned
/// rolling buffer for THIS asset; it accumulates across producer ticks and is
/// coarse-pruned here.
///
/// The two robustness layers are complementary: the spatial median defeats a
/// single manipulated venue in one instant; the TWAP defeats a spike that
/// briefly captures a venue majority — it must persist across the window to move
/// the signed price. Both fail closed, so a thin/stale window signs nothing.
///
/// # Errors
/// [`PriceSignError`] — price or supply venue-consensus failure, insufficient /
/// stale TWAP window, non-monotonic timestamp, HSM error, or recover-verify
/// mismatch (all fail-closed).
pub async fn produce_signed_price<H: HsmDigestSigner>(
    hsm: &H,
    signer_address: Address,
    domain: &Eip712Domain,
    policy: PricePolicy,
    input: &ProducerInputs<'_>,
    history: &mut Vec<TwapSample>,
) -> Result<SignedPrice, PriceSignError> {
    validate_canonical_digits(policy)?;
    let price_quotes = crate::price_venue::source_quotes(input.price_feeds).await;
    let supply_quotes =
        crate::price_supply::source_supply(input.supply_feeds, input.decimals).await;
    produce_signed_price_from_observations(
        hsm,
        signer_address,
        domain,
        policy,
        &ObservedProducerInputs {
            asset_id: input.asset_id,
            price_quotes: &price_quotes,
            supply_quotes: &supply_quotes,
            timestamp: input.timestamp,
            last_signed_at: input.last_signed_at,
        },
        history,
    )
    .await
}

/// Aggregate, TWAP and sign values whose exact raw source responses were
/// already persisted by the caller.
///
/// # Errors
/// Same fail-closed errors as [`produce_signed_price`].
pub async fn produce_signed_price_from_observations<H: HsmDigestSigner>(
    hsm: &H,
    signer_address: Address,
    domain: &Eip712Domain,
    policy: PricePolicy,
    input: &ObservedProducerInputs<'_>,
    history: &mut Vec<TwapSample>,
) -> Result<SignedPrice, PriceSignError> {
    validate_canonical_digits(policy)?;
    // Spatial layer: median across venues, outlier-rejected (fail-closed). A
    // consensus failure returns BEFORE recording a sample, so a bad round never
    // pollutes the TWAP buffer.
    let spatial = aggregate_price(
        input.price_quotes,
        policy.min_venues,
        policy.max_deviation_bps,
    )?;
    let supply = aggregate_price(
        input.supply_quotes,
        policy.supply_min_venues,
        policy.max_deviation_bps,
    )?;
    // Temporal layer: record this robust sample, then time-weight-average the
    // window. Cold start / stale feed / thin window fail closed inside the TWAP.
    record_sample(history, input.timestamp, spatial, policy.twap);
    let price_wad = time_weighted_average(history, input.timestamp, policy.twap)?;
    // Coordination layer: honest operators observe independently, then each
    // applies the SAME deterministic epoch (caller) and significant-digit
    // flooring (here). No coordinator supplies a price. The untrusted collector
    // groups only exact four-field matches and cannot average signatures.
    let price_wad = canonicalize_significant(price_wad, policy.price_significant_digits);
    let supply = canonicalize_significant(supply, policy.supply_significant_digits);
    let obs = PriceObservation {
        asset_id: input.asset_id,
        price_wad,
        supply,
        timestamp: input.timestamp,
        last_signed_at: input.last_signed_at,
    };
    sign_observed_price(hsm, signer_address, domain, &obs).await
}

/// Append the fresh spatial-median sample to the per-asset TWAP buffer and drop
/// samples older than twice the window. The 2× margin keeps memory bounded
/// while always retaining the carry-in sample a sound TWAP needs (a carry-in
/// older than that would fail the TWAP gap guard anyway).
///
/// RS-01: keep the buffer strictly ascending. A backward wall-clock step on the
/// (trusted) signing host would otherwise slip an out-of-order sample in and
/// underflow the TWAP segment-gap math; drop any sample not newer than the last.
fn record_sample(history: &mut Vec<TwapSample>, timestamp: u64, price: U256, cfg: TwapConfig) {
    if history
        .last()
        .is_some_and(|last| timestamp <= last.timestamp)
    {
        return;
    }
    history.push(TwapSample { timestamp, price });
    let cutoff = timestamp.saturating_sub(cfg.window_secs.saturating_mul(2));
    history.retain(|s| s.timestamp >= cutoff);
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, clippy::unwrap_used, reason = "test code")]
    use super::*;
    use k256::ecdsa::SigningKey;
    use xindex_shared::eip712::price_oracle_domain;

    /// HSM stub that signs the prehash with a software test key, returning a
    /// recoverable 65-byte `r ‖ s ‖ v` (the same convention as production).
    struct StubHsm {
        sk: SigningKey,
    }

    #[async_trait::async_trait]
    impl HsmDigestSigner for StubHsm {
        async fn sign_digest(&self, _address: Address, digest: B256) -> Result<[u8; 65], HsmError> {
            let (sig, recid) = self
                .sk
                .sign_prehash_recoverable(digest.as_slice())
                .map_err(|e| HsmError::Decode(format!("test sign: {e}")))?;
            let mut out = [0u8; 65];
            out[..64].copy_from_slice(sig.to_bytes().as_ref());
            out[64] = 27 + recid.to_byte();
            Ok(out)
        }
    }

    fn key_and_addr(seed: u8) -> (SigningKey, Address) {
        let sk = SigningKey::from_slice(&[seed; 32]).expect("key");
        let vk = sk.verifying_key();
        let unc = vk.to_encoded_point(false);
        let hash = alloy_primitives::keccak256(&unc.as_bytes()[1..]);
        (sk, Address::from_slice(&hash[12..]))
    }

    #[test]
    fn record_sample_drops_out_of_order() {
        // RS-01: a backward-clock sample not newer than the last is dropped, so
        // the buffer stays strictly ascending for the TWAP gap math.
        let cfg = TwapConfig {
            window_secs: 60,
            min_samples: 2,
            max_gap_secs: 60,
        };
        let mut history = Vec::new();
        record_sample(&mut history, 1000, U256::from(100u64), cfg);
        record_sample(&mut history, 1030, U256::from(101u64), cfg);
        record_sample(&mut history, 1020, U256::from(999u64), cfg); // backward → dropped
        record_sample(&mut history, 1030, U256::from(999u64), cfg); // equal → dropped
        let ts: Vec<u64> = history.iter().map(|s| s.timestamp).collect();
        assert_eq!(ts, vec![1000, 1030]);
    }

    fn domain() -> Eip712Domain {
        price_oracle_domain(1, Address::repeat_byte(0xcc))
    }

    fn policy() -> PricePolicy {
        PricePolicy {
            min_venues: 3,
            max_deviation_bps: 5000,
            supply_min_venues: 1,
            price_significant_digits: 4,
            supply_significant_digits: 6,
            // 60s window, ≥2 informing samples, ≤60s per stale gap.
            twap: TwapConfig {
                window_secs: 60,
                min_samples: 2,
                max_gap_secs: 60,
            },
        }
    }

    #[test]
    fn canonicalization_converges_close_observations_exactly() {
        assert_eq!(
            canonicalize_significant(U256::from(43_217u64), 4),
            U256::from(43_210u64)
        );
        assert_eq!(
            canonicalize_significant(U256::from(43_219u64), 4),
            U256::from(43_210u64)
        );
        assert_eq!(
            canonicalize_significant(U256::from(999u64), 4),
            U256::from(999u64)
        );
    }

    #[tokio::test]
    async fn invalid_canonicalization_policy_fails_before_hsm() {
        let (sk, addr) = key_and_addr(7);
        let hsm = StubHsm { sk };
        let mut bad = policy();
        bad.price_significant_digits = 0;
        let input = ProducerInputs {
            asset_id: B256::repeat_byte(0x11),
            decimals: 8,
            price_feeds: &[],
            supply_feeds: &[],
            timestamp: 1000,
            last_signed_at: None,
        };
        let err = produce_signed_price(&hsm, addr, &domain(), bad, &input, &mut Vec::new())
            .await
            .expect_err("invalid policy must fail first");
        assert!(matches!(
            err,
            PriceSignError::InvalidCanonicalDigits { field: "price", .. }
        ));
    }

    /// A carry-in sample dated at `window_start` (`now - window_secs`) priced at
    /// `price`, so the TWAP has coverage back across the window in the warm-path
    /// tests.
    fn warm_history(now: u64, price: u64) -> Vec<TwapSample> {
        vec![TwapSample {
            timestamp: now - 60,
            price: U256::from(price),
        }]
    }

    #[tokio::test]
    async fn signs_given_robust_price_and_recovers_to_signer() {
        let (sk, addr) = key_and_addr(7);
        let hsm = StubHsm { sk };
        let obs = PriceObservation {
            asset_id: B256::repeat_byte(0x11),
            price_wad: U256::from(101u64),
            supply: U256::from(1_000_000u64),
            timestamp: 1000,
            last_signed_at: Some(999),
        };
        let signed = sign_observed_price(&hsm, addr, &domain(), &obs)
            .await
            .expect("sign");
        // The signature commits to the aggregated price handed in (101).
        assert_eq!(signed.price_wad, U256::from(101u64));
        // Independent cross-check: the sig recovers to the signer over the
        // digest of that price (so it can't have signed a stray value).
        let att = price_attestation(obs.asset_id, U256::from(101u64), obs.supply, obs.timestamp);
        let digest = price_attestation_signing_hash(&att, &domain());
        let recovered = PrimitiveSignature::try_from(&signed.signature[..])
            .unwrap()
            .recover_address_from_prehash(&digest)
            .unwrap();
        assert_eq!(recovered, addr);
    }

    #[tokio::test]
    async fn rejects_non_monotonic_timestamp() {
        let (sk, addr) = key_and_addr(7);
        let hsm = StubHsm { sk };
        let obs = PriceObservation {
            asset_id: B256::repeat_byte(0x11),
            price_wad: U256::from(100u64),
            supply: U256::from(1_000_000u64),
            timestamp: 500,
            last_signed_at: Some(500), // equal → equivocation risk → refuse
        };
        let err = sign_observed_price(&hsm, addr, &domain(), &obs)
            .await
            .expect_err("must reject");
        assert!(matches!(err, PriceSignError::NonMonotonic { .. }));
    }

    #[derive(Debug)]
    struct FixedVenue(U256);
    #[async_trait::async_trait]
    impl crate::price_venue::PriceVenue for FixedVenue {
        fn name(&self) -> &'static str {
            "fixed"
        }
        async fn fetch_price_observation(
            &self,
            symbol: &str,
        ) -> Result<crate::price_venue::SourcedValue, crate::price_venue::VenueError> {
            Ok(crate::price_venue::SourcedValue {
                source: "fixed",
                subject: symbol.to_string(),
                value: self.0,
                response_hash: B256::repeat_byte(1),
                raw_response: "fixed".to_string(),
            })
        }
    }

    #[derive(Debug)]
    struct FixedSupply(U256);
    #[async_trait::async_trait]
    impl crate::price_supply::SupplySource for FixedSupply {
        fn name(&self) -> &'static str {
            "fixed"
        }
        async fn circulating_supply_observation(
            &self,
            id: &str,
            _decimals: u8,
        ) -> Result<crate::price_venue::SourcedValue, crate::price_venue::VenueError> {
            Ok(crate::price_venue::SourcedValue {
                source: "fixed",
                subject: id.to_string(),
                value: self.0,
                response_hash: B256::repeat_byte(1),
                raw_response: "fixed".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn produce_sources_medians_and_signs() {
        use crate::price_supply::SupplyFeed;
        use crate::price_venue::Feed;
        let (sk, addr) = key_and_addr(7);
        let hsm = StubHsm { sk };
        let (p1, p2, p3) = (
            FixedVenue(U256::from(100u64)),
            FixedVenue(U256::from(101u64)),
            FixedVenue(U256::from(102u64)),
        );
        let sup = FixedSupply(U256::from(1_000_000u64));
        let price_feeds = [
            Feed {
                venue: &p1,
                symbol: "X",
            },
            Feed {
                venue: &p2,
                symbol: "X",
            },
            Feed {
                venue: &p3,
                symbol: "X",
            },
        ];
        let supply_feeds = [SupplyFeed {
            source: &sup,
            id: "x",
        }];
        let input = ProducerInputs {
            asset_id: B256::repeat_byte(0x11),
            decimals: 8,
            price_feeds: &price_feeds,
            supply_feeds: &supply_feeds,
            timestamp: 1000,
            last_signed_at: None,
        };
        // Warm buffer: a carry-in at the window start priced at the same stable
        // 101, so the TWAP of a stable series is that value.
        let mut history = warm_history(1000, 101);
        let signed = produce_signed_price(&hsm, addr, &domain(), policy(), &input, &mut history)
            .await
            .expect("produce");
        // Spatial median (101) time-averaged over a stable window → 101.
        assert_eq!(signed.price_wad, U256::from(101u64));
    }

    #[tokio::test]
    async fn produce_dilutes_fresh_spike_via_twap() {
        use crate::price_supply::SupplyFeed;
        use crate::price_venue::Feed;
        let (sk, addr) = key_and_addr(7);
        let hsm = StubHsm { sk };
        // Every venue reads a spiked 200 this round — the spatial median cannot
        // help (the spike captured the WHOLE venue set).
        let spike = FixedVenue(U256::from(200u64));
        let sup = FixedSupply(U256::from(1_000_000u64));
        let price_feeds = [
            Feed {
                venue: &spike,
                symbol: "X",
            },
            Feed {
                venue: &spike,
                symbol: "X",
            },
            Feed {
                venue: &spike,
                symbol: "X",
            },
        ];
        let supply_feeds = [SupplyFeed {
            source: &sup,
            id: "x",
        }];
        let input = ProducerInputs {
            asset_id: B256::repeat_byte(0x22),
            decimals: 8,
            price_feeds: &price_feeds,
            supply_feeds: &supply_feeds,
            timestamp: 1060,
            last_signed_at: None,
        };
        // History held a stable 100 across the whole window (carry-in at 1000).
        let mut history = warm_history(1060, 100);
        let signed = produce_signed_price(&hsm, addr, &domain(), policy(), &input, &mut history)
            .await
            .expect("produce");
        // The 200 spike lands at `now` with ZERO dwell, so the TWAP is the 100
        // that held all window: the signer commits to 100, NOT the 200 spatial
        // median. Persistence — not a single spike — is required to move price.
        assert_eq!(signed.price_wad, U256::from(100u64));
    }

    #[tokio::test]
    async fn produce_cold_start_fails_closed() {
        use crate::price_supply::SupplyFeed;
        use crate::price_venue::Feed;
        let (sk, addr) = key_and_addr(7);
        let hsm = StubHsm { sk };
        let v = FixedVenue(U256::from(100u64));
        let sup = FixedSupply(U256::from(1_000_000u64));
        let price_feeds = [
            Feed {
                venue: &v,
                symbol: "X",
            },
            Feed {
                venue: &v,
                symbol: "X",
            },
            Feed {
                venue: &v,
                symbol: "X",
            },
        ];
        let supply_feeds = [SupplyFeed {
            source: &sup,
            id: "x",
        }];
        let input = ProducerInputs {
            asset_id: B256::repeat_byte(0x33),
            decimals: 8,
            price_feeds: &price_feeds,
            supply_feeds: &supply_feeds,
            timestamp: 1000,
            last_signed_at: None,
        };
        // Empty buffer → no history covering the window start → fail closed; the
        // round's robust sample is still recorded so later ticks succeed.
        let mut history = Vec::new();
        let err = produce_signed_price(&hsm, addr, &domain(), policy(), &input, &mut history)
            .await
            .expect_err("cold start must fail closed");
        assert!(matches!(err, PriceSignError::Twap(_)));
        assert_eq!(history.len(), 1, "the round's robust sample is recorded");
    }

    #[tokio::test]
    async fn produce_fails_closed_on_insufficient_venue_consensus() {
        use crate::price_supply::SupplyFeed;
        use crate::price_venue::Feed;
        let (sk, addr) = key_and_addr(7);
        let hsm = StubHsm { sk };
        let v = FixedVenue(U256::from(100u64));
        let sup = FixedSupply(U256::from(1_000_000u64));
        // 1 venue feed < min_venues 3 → spatial aggregation fails BEFORE any
        // sample is recorded (a bad round never pollutes the TWAP buffer).
        let price_feeds = [Feed {
            venue: &v,
            symbol: "X",
        }];
        let supply_feeds = [SupplyFeed {
            source: &sup,
            id: "x",
        }];
        let input = ProducerInputs {
            asset_id: B256::repeat_byte(0x44),
            decimals: 8,
            price_feeds: &price_feeds,
            supply_feeds: &supply_feeds,
            timestamp: 1000,
            last_signed_at: None,
        };
        let mut history = warm_history(1000, 100);
        let before = history.len();
        let err = produce_signed_price(&hsm, addr, &domain(), policy(), &input, &mut history)
            .await
            .expect_err("insufficient venues must fail closed");
        assert!(matches!(err, PriceSignError::Aggregate(_)));
        assert_eq!(
            history.len(),
            before,
            "a failed spatial round records no sample"
        );
    }
}
