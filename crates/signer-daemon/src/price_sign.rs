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
//! This module is the signing CORE: aggregate -> per-asset monotonic
//! (anti-equivocation) guard -> EIP-712 digest -> HSM sign -> recover-verify
//! (the M6 backstop). The venue HTTP clients that supply the quotes and the
//! publish loop are a separate I/O layer on top of this.

use alloy_primitives::{Address, PrimitiveSignature, B256, U256};
use alloy_sol_types::Eip712Domain;
use thiserror::Error;
use xindex_shared::eip712::{price_attestation, price_attestation_signing_hash};
use xindex_shared::price_aggregate::{aggregate_price, AggregateError};

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
    /// exist than price venues, and supply is slow-moving + less manipulable,
    /// so it is additionally backstopped by the on-chain absolute-bounds (L1)
    /// guard.
    pub supply_min_venues: usize,
}

/// One price observation to sign.
#[derive(Debug, Clone)]
pub struct PriceObservation<'a> {
    /// Registry asset id (keccak of the `THORChain` asset string).
    pub asset_id: B256,
    /// Independent venue quotes (WAD) for this asset.
    pub venue_quotes: &'a [U256],
    /// Token supply attested alongside the price (NAV input).
    pub supply: U256,
    /// Observation time (unix secs); MUST strictly exceed `last_signed_at`.
    pub timestamp: u64,
    /// The last timestamp this signer signed for this asset (anti-equivocation
    /// monotonic guard; `None` for the first observation).
    pub last_signed_at: Option<u64>,
}

/// A signed price attestation: the aggregated price + the 65-byte signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPrice {
    /// The aggregated (robust) price the signature commits to.
    pub price_wad: U256,
    /// 65-byte recoverable ECDSA signature over the EIP-712 digest.
    pub signature: [u8; 65],
}

/// Why a price signing was refused (all fail-closed).
#[derive(Debug, Error)]
pub enum PriceSignError {
    /// Venue aggregation did not reach consensus.
    #[error("price aggregation: {0}")]
    Aggregate(#[from] AggregateError),
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

/// Aggregate the venue quotes, then sign the resulting `PriceAttestation` with
/// the HSM and verify the signature recovers to `signer_address`.
///
/// # Errors
/// Fails CLOSED with [`PriceSignError`]: insufficient venue consensus, a
/// non-monotonic timestamp, an HSM error, or a recover-verify mismatch.
pub async fn sign_observed_price<H: HsmDigestSigner>(
    hsm: &H,
    signer_address: Address,
    domain: &Eip712Domain,
    policy: PricePolicy,
    obs: &PriceObservation<'_>,
) -> Result<SignedPrice, PriceSignError> {
    check_monotonic(obs.timestamp, obs.last_signed_at)?;
    let price_wad = aggregate_price(
        obs.venue_quotes,
        policy.min_venues,
        policy.max_deviation_bps,
    )?;
    let att = price_attestation(obs.asset_id, price_wad, obs.supply, obs.timestamp);
    let digest = price_attestation_signing_hash(&att, domain);
    let signature = hsm.sign_digest(signer_address, digest).await?;
    let recovered = PrimitiveSignature::try_from(&signature[..])
        .map_err(|e| PriceSignError::SignatureParse(e.to_string()))?
        .recover_address_from_prehash(&digest)
        .map_err(|e| PriceSignError::SignatureParse(e.to_string()))?;
    if recovered != signer_address {
        return Err(PriceSignError::RecoverMismatch {
            recovered,
            expected: signer_address,
        });
    }
    Ok(SignedPrice {
        price_wad,
        signature,
    })
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

/// The full self-driven producer step for one asset: source price + supply from
/// the configured venues, median each (outlier-rejected, fail-closed), then
/// sign the resulting `PriceAttestation`. `supply` is medianed here; `price` is
/// medianed inside [`sign_observed_price`].
///
/// # Errors
/// [`PriceSignError`] — price or supply consensus failure, non-monotonic
/// timestamp, HSM error, or recover-verify mismatch (all fail-closed).
pub async fn produce_signed_price<H: HsmDigestSigner>(
    hsm: &H,
    signer_address: Address,
    domain: &Eip712Domain,
    policy: PricePolicy,
    input: &ProducerInputs<'_>,
) -> Result<SignedPrice, PriceSignError> {
    let price_quotes = crate::price_venue::source_quotes(input.price_feeds).await;
    let supply_quotes =
        crate::price_supply::source_supply(input.supply_feeds, input.decimals).await;
    let supply = aggregate_price(
        &supply_quotes,
        policy.supply_min_venues,
        policy.max_deviation_bps,
    )?;
    let obs = PriceObservation {
        asset_id: input.asset_id,
        venue_quotes: &price_quotes,
        supply,
        timestamp: input.timestamp,
        last_signed_at: input.last_signed_at,
    };
    sign_observed_price(hsm, signer_address, domain, policy, &obs).await
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

    fn domain() -> Eip712Domain {
        price_oracle_domain(1, Address::repeat_byte(0xcc))
    }

    fn policy() -> PricePolicy {
        PricePolicy {
            min_venues: 3,
            max_deviation_bps: 5000,
            supply_min_venues: 1,
        }
    }

    #[tokio::test]
    async fn signs_aggregated_median_and_recovers_to_signer() {
        let (sk, addr) = key_and_addr(7);
        let hsm = StubHsm { sk };
        let quotes = [U256::from(100u64), U256::from(101u64), U256::from(102u64)];
        let obs = PriceObservation {
            asset_id: B256::repeat_byte(0x11),
            venue_quotes: &quotes,
            supply: U256::from(1_000_000u64),
            timestamp: 1000,
            last_signed_at: Some(999),
        };
        let signed = sign_observed_price(&hsm, addr, &domain(), policy(), &obs)
            .await
            .expect("sign");
        // The signature commits to the venue MEDIAN (101), not any single feed.
        assert_eq!(signed.price_wad, U256::from(101u64));
        // Independent cross-check: the sig recovers to the signer over the
        // digest of the AGGREGATED price (so it can't have signed a stray value).
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
        let quotes = [U256::from(100u64), U256::from(100u64), U256::from(100u64)];
        let obs = PriceObservation {
            asset_id: B256::repeat_byte(0x11),
            venue_quotes: &quotes,
            supply: U256::from(1_000_000u64),
            timestamp: 500,
            last_signed_at: Some(500), // equal → equivocation risk → refuse
        };
        let err = sign_observed_price(&hsm, addr, &domain(), policy(), &obs)
            .await
            .expect_err("must reject");
        assert!(matches!(err, PriceSignError::NonMonotonic { .. }));
    }

    #[tokio::test]
    async fn fails_closed_on_insufficient_venue_consensus() {
        let (sk, addr) = key_and_addr(7);
        let hsm = StubHsm { sk };
        let quotes = [U256::from(100u64)]; // 1 < min 3
        let obs = PriceObservation {
            asset_id: B256::repeat_byte(0x11),
            venue_quotes: &quotes,
            supply: U256::from(1_000_000u64),
            timestamp: 1000,
            last_signed_at: None,
        };
        let err = sign_observed_price(&hsm, addr, &domain(), policy(), &obs)
            .await
            .expect_err("must reject");
        assert!(matches!(err, PriceSignError::Aggregate(_)));
    }

    #[derive(Debug)]
    struct FixedVenue(U256);
    #[async_trait::async_trait]
    impl crate::price_venue::PriceVenue for FixedVenue {
        fn name(&self) -> &'static str {
            "fixed"
        }
        async fn fetch_price_wad(
            &self,
            _symbol: &str,
        ) -> Result<U256, crate::price_venue::VenueError> {
            Ok(self.0)
        }
    }

    #[derive(Debug)]
    struct FixedSupply(U256);
    #[async_trait::async_trait]
    impl crate::price_supply::SupplySource for FixedSupply {
        fn name(&self) -> &'static str {
            "fixed"
        }
        async fn circulating_supply_raw(
            &self,
            _id: &str,
            _decimals: u8,
        ) -> Result<U256, crate::price_venue::VenueError> {
            Ok(self.0)
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
        let (s1, s2, s3) = (
            FixedSupply(U256::from(1_000_000u64)),
            FixedSupply(U256::from(1_000_000u64)),
            FixedSupply(U256::from(1_000_000u64)),
        );
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
        let supply_feeds = [
            SupplyFeed {
                source: &s1,
                id: "x",
            },
            SupplyFeed {
                source: &s2,
                id: "x",
            },
            SupplyFeed {
                source: &s3,
                id: "x",
            },
        ];
        let input = ProducerInputs {
            asset_id: B256::repeat_byte(0x11),
            decimals: 8,
            price_feeds: &price_feeds,
            supply_feeds: &supply_feeds,
            timestamp: 1000,
            last_signed_at: None,
        };
        let signed = produce_signed_price(&hsm, addr, &domain(), policy(), &input)
            .await
            .expect("produce");
        // Signs the MEDIAN price (101) over the median supply.
        assert_eq!(signed.price_wad, U256::from(101u64));
    }
}
