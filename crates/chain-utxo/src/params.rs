//! Per-chain runtime parameters for the UTXO custody family.
//!
//! [`UtxoParams`] is the single source of truth for the chain-specific
//! constants the executor, signer, descriptor, codec, and watcher all
//! need. One `const` table per chain in this module; the rest of the
//! stack reads via [`UtxoParams::for_chain`].
//!
//! ## Phase 3.1 scope
//!
//! Five chains: `Btc`, `Ltc`, `Bch`, `Doge`, `Zec`. All `CustodyFamily::Utxo`.
//! BTC + LTC use `SegWit` P2WSH; BCH/DOGE/ZEC use P2SH-legacy (DOGE has
//! no `SegWit`; BCH dropped `SegWit` after the 2017 fork; ZEC's
//! transparent layer is P2SH only).
//!
//! ## Why a single `for_chain(ChainId)` over a builder
//!
//! Every value here is **operationally pinned** — a typo
//! (`conf_depth = 4` for DOGE instead of 40) silently weakens
//! reorg-resistance. A `match` over `ChainId` makes every new chain
//! a compiler error at every callsite that consumes a field.

use xindex_shared::chain_registry::{ChainId, FeeUnit};

/// Multisig script template per chain. Drives both the descriptor
/// string (U4) and the sighash branch (U5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptKind {
    /// `wsh(multi(K, pk_1, ..., pk_N))` — P2WSH SegWit-v0. Used by
    /// BTC and LTC (the only Phase 3.1 chains with `SegWit`).
    P2wsh,
    /// `sh(multi(K, pk_1, ..., pk_N))` — bare P2SH-legacy. Used by
    /// BCH (no `SegWit` post-fork), DOGE (pre-`SegWit`), and ZEC
    /// (transparent t-addr layer is P2SH only).
    P2shLegacy,
}

/// Per-chain runtime parameters. One `const` table per `ChainId`;
/// see the bottom of this module.
#[derive(Debug, Clone, Copy)]
pub struct UtxoParams {
    /// Chain identity. Distinct from the `bitcoin::Network` variant
    /// (mainnet/signet/testnet/regtest), which is environment-bound
    /// and supplied by the operator.
    pub chain_id: ChainId,
    /// Confirmations the signer waits before attesting a delivery or
    /// refund. Per `THORChain` Bifrost heuristics; mirrors
    /// `ChainId::conf_depth`.
    pub conf_depth: u32,
    /// Multisig script template — P2WSH (segwit) vs P2SH-legacy.
    pub script_kind: ScriptKind,
    /// `OP_RETURN` standard-relay max bytes. 80 by Bitcoin Core
    /// default; 220 on BCH after the 2019 policy bump.
    pub op_return_max: usize,
    /// Fee-rate unit. `PerVbyte` for segwit chains; `PerByte` for
    /// legacy chains where vbyte = byte (no witness discount).
    pub fee_unit: FeeUnit,
    /// `THORChain` asset string used in swap memos
    /// (`=:<thor_asset>:<dest>:<lim>`). Mirrors
    /// `ChainId::thor_asset`.
    pub thor_asset: &'static str,
    /// Native-unit scale (`10^decimals`). All 8-decimal chains use
    /// `100_000_000`.
    pub scale: u64,
    /// Standard-relay dust limit (sats). Outputs below this are
    /// non-standard and the network won't relay them. Conservative
    /// value across the family: 546 sats (the P2PKH/P2SH dust); the
    /// finer 294-sat P2WSH dust would also work for BTC/LTC but
    /// 546 is universally safe.
    pub dust_sats: u64,
}

impl UtxoParams {
    /// Look up the per-chain const table. Inlined — every callsite
    /// resolves at compile time, so a new `ChainId` variant produces
    /// a `match` exhaustiveness error and not a runtime panic.
    #[must_use]
    pub const fn for_chain(chain_id: ChainId) -> &'static UtxoParams {
        match chain_id {
            ChainId::Btc => &BTC_PARAMS,
            ChainId::Ltc => &LTC_PARAMS,
            ChainId::Bch => &BCH_PARAMS,
            ChainId::Doge => &DOGE_PARAMS,
            ChainId::Zec => &ZEC_PARAMS,
            // Non-UTXO custody chains belong to their own crates: EVM
            // (Phase 3.2) to `chain-evm`, Cosmos (Phase 3.3, Gaia) to
            // `chain-cosmos`, XRP (Phase 4.4) to `chain-xrp`, Solana
            // (Phase 4.5) to `chain-solana`, TRON (Phase 4.6) to
            // `chain-tron`. Caller routing must dispatch on `CustodyFamily`
            // before reaching this lookup.
            ChainId::Eth
            | ChainId::Bsc
            | ChainId::Avax
            | ChainId::Base
            | ChainId::Pol
            | ChainId::Gaia
            | ChainId::Xrp
            | ChainId::Sol
            | ChainId::Tron => {
                unreachable!()
            }
        }
    }
}

/// Bitcoin mainnet. P2WSH, 6 conf, 80-byte `OP_RETURN`, sat/vB.
const BTC_PARAMS: UtxoParams = UtxoParams {
    chain_id: ChainId::Btc,
    conf_depth: 6,
    script_kind: ScriptKind::P2wsh,
    op_return_max: 80,
    fee_unit: FeeUnit::PerVbyte,
    thor_asset: "BTC.BTC",
    scale: 100_000_000,
    dust_sats: 546,
};

/// Litecoin. P2WSH (LTC has `SegWit`), 12 conf (4× BTC's 2.5-min vs
/// 10-min block ratio), 80-byte `OP_RETURN`, sat/vB.
const LTC_PARAMS: UtxoParams = UtxoParams {
    chain_id: ChainId::Ltc,
    conf_depth: 12,
    script_kind: ScriptKind::P2wsh,
    op_return_max: 80,
    fee_unit: FeeUnit::PerVbyte,
    thor_asset: "LTC.LTC",
    scale: 100_000_000,
    dust_sats: 546,
};

/// Bitcoin Cash. P2SH-legacy (BCH dropped `SegWit` after the 2017
/// fork), 6 conf, **220-byte `OP_RETURN`** (raised by the BCH 2019
/// relay-policy update), sat/B.
const BCH_PARAMS: UtxoParams = UtxoParams {
    chain_id: ChainId::Bch,
    conf_depth: 6,
    script_kind: ScriptKind::P2shLegacy,
    op_return_max: 220,
    fee_unit: FeeUnit::PerByte,
    thor_asset: "BCH.BCH",
    scale: 100_000_000,
    dust_sats: 546,
};

/// Dogecoin. P2SH-legacy (pre-`SegWit`), **40 conf** (1-min blocks +
/// historical reorg-vulnerability heuristic from `THORChain`
/// Bifrost), 80-byte `OP_RETURN`, sat/B.
const DOGE_PARAMS: UtxoParams = UtxoParams {
    chain_id: ChainId::Doge,
    conf_depth: 40,
    script_kind: ScriptKind::P2shLegacy,
    op_return_max: 80,
    fee_unit: FeeUnit::PerByte,
    thor_asset: "DOGE.DOGE",
    scale: 100_000_000,
    dust_sats: 546,
};

/// Zcash transparent (t-addr) layer. P2SH-legacy, 10 conf, 80-byte
/// `OP_RETURN`, sat/B. Z-addr (shielded) is out of scope per
/// DL-P3-7 — t-addr only.
const ZEC_PARAMS: UtxoParams = UtxoParams {
    chain_id: ChainId::Zec,
    conf_depth: 10,
    script_kind: ScriptKind::P2shLegacy,
    op_return_max: 80,
    fee_unit: FeeUnit::PerByte,
    thor_asset: "ZEC.ZEC",
    scale: 100_000_000,
    dust_sats: 546,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `ChainId` variant resolves to a const table.
    #[test]
    fn for_chain_covers_every_variant() {
        for c in [
            ChainId::Btc,
            ChainId::Ltc,
            ChainId::Bch,
            ChainId::Doge,
            ChainId::Zec,
        ] {
            let p = UtxoParams::for_chain(c);
            assert_eq!(p.chain_id, c);
        }
    }

    /// Per-chain params agree with the `ChainId` standalone lookups
    /// in `xindex-shared::chain_registry`. Drift between the two
    /// sources is a class of bugs we want to fail closed.
    #[test]
    fn params_agree_with_chain_registry() {
        for c in [
            ChainId::Btc,
            ChainId::Ltc,
            ChainId::Bch,
            ChainId::Doge,
            ChainId::Zec,
        ] {
            let p = UtxoParams::for_chain(c);
            assert_eq!(p.conf_depth, c.conf_depth(), "{c:?} conf_depth");
            assert_eq!(p.op_return_max, c.op_return_max(), "{c:?} op_return_max");
            assert_eq!(p.fee_unit, c.fee_unit(), "{c:?} fee_unit");
            assert_eq!(p.thor_asset, c.thor_asset(), "{c:?} thor_asset");
            assert_eq!(p.scale, c.scale(), "{c:?} scale");
        }
    }

    /// Script kind per `SegWit` availability. The descriptor and
    /// sighash branches (U4/U5) consume this; a wrong value would
    /// build a descriptor for the wrong script class and signatures
    /// would fail validation at broadcast time.
    #[test]
    fn script_kind_per_segwit_availability() {
        assert_eq!(
            UtxoParams::for_chain(ChainId::Btc).script_kind,
            ScriptKind::P2wsh
        );
        assert_eq!(
            UtxoParams::for_chain(ChainId::Ltc).script_kind,
            ScriptKind::P2wsh
        );
        assert_eq!(
            UtxoParams::for_chain(ChainId::Bch).script_kind,
            ScriptKind::P2shLegacy
        );
        assert_eq!(
            UtxoParams::for_chain(ChainId::Doge).script_kind,
            ScriptKind::P2shLegacy
        );
        assert_eq!(
            UtxoParams::for_chain(ChainId::Zec).script_kind,
            ScriptKind::P2shLegacy
        );
    }

    /// Dust limit is 546 across the family — universally
    /// relay-standard. A regression to 0 would create unspendable
    /// dust change outputs; a regression above 546 would over-pay.
    #[test]
    fn dust_sats_is_universally_546() {
        for c in [
            ChainId::Btc,
            ChainId::Ltc,
            ChainId::Bch,
            ChainId::Doge,
            ChainId::Zec,
        ] {
            assert_eq!(UtxoParams::for_chain(c).dust_sats, 546, "{c:?} dust_sats");
        }
    }
}
