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

use alloy_primitives::{keccak256, B256};

/// Per-chain identifier. UTXO family today; other families land in
/// Phase 3.2+.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
