//! Per-chain registry: maps each supported chain to its `THORChain`
//! asset name, decimals, confirmation depth, `OP_RETURN` policy, fee
//! unit, and EIP-712 `assetId` binding.
//!
//! The `const fn` table is the canonical Rust mirror of the on-chain
//! `assetId` constants. Adding a chain: extend the enum, add a `match`
//! arm in each lookup, add test vectors. The compiler walks every
//! callsite through every arm — there is no default fallthrough.
//!
//! ## Phase 3.1 scope
//!
//! `Btc` / `Ltc` / `Bch` / `Doge` / `Zec` — the UTXO custody family
//! (`CustodyFamily::Utxo`). EVM / Cosmos / Solana / Substrate families
//! are Phase 3.2+ and will reuse this enum.

use std::fmt;
use std::str::FromStr;

use alloy_primitives::{keccak256, B256};
use serde::{Deserialize, Serialize};

/// Per-chain identifier. UTXO family today; other families land in
/// Phase 3.2+. The string form (`"btc"`, `"ltc"`, ...) is the wire
/// representation everywhere — JSON requests (`PsbtInputSignRequest`),
/// `SQLite` TEXT columns (`redemption_dispatch.chain`), and CLI args
/// (`--chain ltc`). Hex / decimal is reserved for byte-level
/// quantities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainId {
    /// Bitcoin (mainnet/signet — distinguished at the client layer).
    Btc,
    /// Litecoin.
    Ltc,
    /// Bitcoin Cash.
    Bch,
    /// Dogecoin.
    Doge,
    /// Zcash (transparent t-addr only; z-addr is out of scope).
    Zec,
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Btc => "btc",
            Self::Ltc => "ltc",
            Self::Bch => "bch",
            Self::Doge => "doge",
            Self::Zec => "zec",
        })
    }
}

/// Error returned by [`ChainId::from_str`] when the input doesn't
/// match a known chain. Case-insensitive on input (`"BTC"` /
/// `"Btc"` / `"btc"` all parse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseChainIdError(pub String);

impl fmt::Display for ParseChainIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown chain id: {}", self.0)
    }
}

impl std::error::Error for ParseChainIdError {}

impl FromStr for ChainId {
    type Err = ParseChainIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "btc" => Ok(Self::Btc),
            "ltc" => Ok(Self::Ltc),
            "bch" => Ok(Self::Bch),
            "doge" => Ok(Self::Doge),
            "zec" => Ok(Self::Zec),
            other => Err(ParseChainIdError(other.to_string())),
        }
    }
}

/// Custody-side classification used to dispatch to the right
/// signing / address / fee implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyFamily {
    /// UTXO chains: native multisig via descriptor + PSBT.
    Utxo,
    // Evm, Cosmos, Solana, Substrate — Phase 3.2+.
}

/// Fee-rate unit per chain. `SegWit` chains charge per virtual byte (the
/// witness-discounted weight unit); legacy / no-segwit chains charge
/// per raw byte. Mixing them produces a fee that is up to 4× wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeUnit {
    /// sat/vB — `SegWit`-bearing chains (BTC, LTC).
    PerVbyte,
    /// sat/B (raw byte) — legacy chains without `SegWit` (BCH, DOGE, ZEC).
    PerByte,
}

impl ChainId {
    /// `THORChain` asset string, e.g. `"BTC.BTC"`. Used in swap memos
    /// and as the canonical input to [`Self::asset_id_hash`].
    #[must_use]
    pub const fn thor_asset(self) -> &'static str {
        match self {
            Self::Btc => "BTC.BTC",
            Self::Ltc => "LTC.LTC",
            Self::Bch => "BCH.BCH",
            Self::Doge => "DOGE.DOGE",
            Self::Zec => "ZEC.ZEC",
        }
    }

    /// Custody family. All Phase 3.1 chains are UTXO.
    #[must_use]
    pub const fn custody_family(self) -> CustodyFamily {
        match self {
            Self::Btc | Self::Ltc | Self::Bch | Self::Doge | Self::Zec => CustodyFamily::Utxo,
        }
    }

    /// Native-unit decimals. All Bitcoin-family chains use 8.
    #[must_use]
    pub const fn decimals(self) -> u8 {
        match self {
            Self::Btc | Self::Ltc | Self::Bch | Self::Doge | Self::Zec => 8,
        }
    }

    /// Native-unit scale (`10^decimals`). All 8-decimal chains use
    /// `100_000_000`.
    #[must_use]
    pub const fn scale(self) -> u64 {
        match self {
            Self::Btc | Self::Ltc | Self::Bch | Self::Doge | Self::Zec => 100_000_000,
        }
    }

    /// Confirmation depth before the signer attests a delivery /
    /// refund. Per `THORChain` `bifrost/pkg/chainclients/*` heuristics:
    /// BTC 6, LTC 12 (10-min target ÷ 2.5-min blocks ⇒ 4× BTC's
    /// timewise; pinned 12 by bifrost), BCH 6 (matches BTC),
    /// **DOGE 40** (1-min blocks + reorg history), ZEC 10.
    #[must_use]
    pub const fn conf_depth(self) -> u32 {
        match self {
            Self::Btc | Self::Bch => 6,
            Self::Ltc => 12,
            Self::Doge => 40,
            Self::Zec => 10,
        }
    }

    /// Maximum bytes carryable in an `OP_RETURN` standard-relay output.
    /// 80 is the Bitcoin Core default; BCH raised the limit to 220 in
    /// 2019 (`MAY 2019` HF). Affects `THORChain` affiliate-fee memos
    /// which can exceed 80 on BCH.
    #[must_use]
    pub const fn op_return_max(self) -> usize {
        match self {
            Self::Bch => 220,
            Self::Btc | Self::Ltc | Self::Doge | Self::Zec => 80,
        }
    }

    /// Fee unit per chain. `SegWit` chains use `PerVbyte`; legacy /
    /// no-segwit chains use `PerByte` (their "vbyte" is just a byte).
    #[must_use]
    pub const fn fee_unit(self) -> FeeUnit {
        match self {
            Self::Btc | Self::Ltc => FeeUnit::PerVbyte,
            Self::Bch | Self::Doge | Self::Zec => FeeUnit::PerByte,
        }
    }

    /// EIP-712 `assetId` = `keccak256(thor_asset)`. Matches the
    /// on-chain `IndexFactory` recognized-asset constants verbatim:
    /// both sides hash the same UTF-8 bytes. Used by the per-leg
    /// `AsyncLegDeliveryAttestation` / `AsyncLegRefundAttestation`
    /// typed data — the signer must compute the same literal as the
    /// `legAssetIds[i]` bytes32 emitted on-chain.
    #[must_use]
    pub fn asset_id_hash(self) -> B256 {
        keccak256(self.thor_asset().as_bytes())
    }

    /// Reverse of [`asset_id_hash`]: lookup the `ChainId` for an
    /// on-chain `legAssetIds[i]` value. Returns `None` if the asset
    /// hash doesn't match any Phase 3.1 UTXO-family chain.
    ///
    /// Used by `xindex-attest-redeem` to route per-leg cross-checks:
    /// `ev.legAssetIds[i]` → `ChainId` → per-chain dispatch lookup +
    /// Esplora client + `THORChain` chain-query endpoint.
    #[must_use]
    pub fn from_asset_id(asset_id: B256) -> Option<Self> {
        [Self::Btc, Self::Ltc, Self::Bch, Self::Doge, Self::Zec]
            .into_iter()
            .find(|c| c.asset_id_hash() == asset_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical `THORChain` asset strings. Pinned — changing any of
    /// these breaks the on-chain `IndexFactory` constants which hash
    /// the same UTF-8 bytes.
    #[test]
    fn thor_asset_strings_match_thorchain_convention() {
        assert_eq!(ChainId::Btc.thor_asset(), "BTC.BTC");
        assert_eq!(ChainId::Ltc.thor_asset(), "LTC.LTC");
        assert_eq!(ChainId::Bch.thor_asset(), "BCH.BCH");
        assert_eq!(ChainId::Doge.thor_asset(), "DOGE.DOGE");
        assert_eq!(ChainId::Zec.thor_asset(), "ZEC.ZEC");
    }

    #[test]
    fn all_phase_3_1_chains_are_utxo_family_with_8_decimals() {
        for c in [
            ChainId::Btc,
            ChainId::Ltc,
            ChainId::Bch,
            ChainId::Doge,
            ChainId::Zec,
        ] {
            assert_eq!(c.custody_family(), CustodyFamily::Utxo);
            assert_eq!(c.decimals(), 8);
            assert_eq!(c.scale(), 100_000_000);
        }
    }

    /// Confirmation depths verbatim from `THORChain` Bifrost.
    /// Hard-pinned — a typo here under-confirms a refund attestation
    /// and the signer could attest a tx that later gets reorged out.
    #[test]
    fn conf_depths_match_bifrost_heuristics() {
        assert_eq!(ChainId::Btc.conf_depth(), 6);
        assert_eq!(ChainId::Ltc.conf_depth(), 12);
        assert_eq!(ChainId::Bch.conf_depth(), 6);
        // DOGE 40: 1-min blocks + historical reorg vulnerability.
        assert_eq!(ChainId::Doge.conf_depth(), 40);
        assert_eq!(ChainId::Zec.conf_depth(), 10);
    }

    /// BCH's 2019 post-fork relay policy raised the `OP_RETURN` limit
    /// to 220 bytes; the rest of the family stays at the 80-byte Core
    /// default. Affiliate-fee memos can exceed 80 on BCH.
    #[test]
    fn op_return_max_per_relay_policy() {
        assert_eq!(ChainId::Btc.op_return_max(), 80);
        assert_eq!(ChainId::Ltc.op_return_max(), 80);
        assert_eq!(ChainId::Bch.op_return_max(), 220);
        assert_eq!(ChainId::Doge.op_return_max(), 80);
        assert_eq!(ChainId::Zec.op_return_max(), 80);
    }

    /// Fee unit per `SegWit` availability. BCH/DOGE/ZEC have no
    /// `SegWit` so vbyte = byte; sending sat/vB to a sat/B chain
    /// underpays by up to 4× and the relay rejects the tx.
    #[test]
    fn fee_unit_per_segwit_status() {
        assert_eq!(ChainId::Btc.fee_unit(), FeeUnit::PerVbyte);
        assert_eq!(ChainId::Ltc.fee_unit(), FeeUnit::PerVbyte);
        assert_eq!(ChainId::Bch.fee_unit(), FeeUnit::PerByte);
        assert_eq!(ChainId::Doge.fee_unit(), FeeUnit::PerByte);
        assert_eq!(ChainId::Zec.fee_unit(), FeeUnit::PerByte);
    }

    /// `asset_id_hash` is `keccak256(thor_asset.as_bytes())`. Both
    /// pinning the formula (mirror of Solidity) and verifying distinct
    /// chains produce distinct hashes (anti-collision sanity).
    /// Round-trip: `ChainId` ↔ string form (`Display` + `FromStr`).
    /// Used by JSON wire (`PsbtInputSignRequest`), `SQLite` TEXT columns,
    /// and CLI args. Mixed-case input is normalised to lowercase.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn display_fromstr_round_trip_and_case_insensitive() {
        for c in [
            ChainId::Btc,
            ChainId::Ltc,
            ChainId::Bch,
            ChainId::Doge,
            ChainId::Zec,
        ] {
            let s = c.to_string();
            let back: ChainId = s.parse().expect("parse");
            assert_eq!(back, c);
        }
        assert_eq!("BTC".parse::<ChainId>().expect("uppercase"), ChainId::Btc);
        assert_eq!("Ltc".parse::<ChainId>().expect("mixed"), ChainId::Ltc);
        assert!("ada".parse::<ChainId>().is_err());
    }

    /// Serde uses the lowercase string form (matches Display/FromStr).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn serde_uses_lowercase_strings() {
        let json = serde_json::to_string(&ChainId::Btc).expect("ser");
        assert_eq!(json, "\"btc\"");
        let back: ChainId = serde_json::from_str("\"ltc\"").expect("de");
        assert_eq!(back, ChainId::Ltc);
    }

    /// U10: round-trip `ChainId` → `asset_id_hash` → `ChainId` via
    /// `from_asset_id`. Bogus hash returns None. Used by
    /// `xindex-attest-redeem` to route per-leg cross-checks.
    #[test]
    fn from_asset_id_round_trip_and_rejects_unknown() {
        for c in [
            ChainId::Btc,
            ChainId::Ltc,
            ChainId::Bch,
            ChainId::Doge,
            ChainId::Zec,
        ] {
            assert_eq!(ChainId::from_asset_id(c.asset_id_hash()), Some(c));
        }
        // Unknown / bogus asset hash → None (not silently mapped to BTC).
        let bogus = B256::repeat_byte(0xff);
        assert_eq!(ChainId::from_asset_id(bogus), None);
    }

    #[test]
    fn asset_id_hash_matches_keccak256_of_thor_asset_bytes() {
        for c in [
            ChainId::Btc,
            ChainId::Ltc,
            ChainId::Bch,
            ChainId::Doge,
            ChainId::Zec,
        ] {
            let expected = keccak256(c.thor_asset().as_bytes());
            assert_eq!(c.asset_id_hash(), expected);
        }
        // All five hashes are pairwise distinct.
        let hashes: Vec<B256> = [
            ChainId::Btc,
            ChainId::Ltc,
            ChainId::Bch,
            ChainId::Doge,
            ChainId::Zec,
        ]
        .into_iter()
        .map(ChainId::asset_id_hash)
        .collect();
        for (i, a) in hashes.iter().enumerate() {
            for (j, b) in hashes.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "asset_id_hash collision: idx {i} vs {j}");
                }
            }
        }
    }
}
