//! Per-chain registry: maps each supported chain to its `THORChain`
//! asset name, decimals, confirmation depth, `OP_RETURN` policy, fee
//! unit, and EIP-712 `assetId` binding.
//!
//! The `const fn` table is the canonical Rust mirror of the on-chain
//! `assetId` constants. Adding a chain: extend the enum, add a `match`
//! arm in each lookup, add test vectors. The compiler walks every
//! callsite through every arm — there is no default fallthrough.
//!
//! ## Phase 3.1 + 3.2 + 3.3 + 4.4 scope
//!
//! `Btc` / `Ltc` / `Bch` / `Doge` / `Zec` — the UTXO custody family
//! (`CustodyFamily::Utxo`). `Eth` / `Bsc` / `Avax` / `Base` / `Pol` —
//! the EVM custody family (`CustodyFamily::Evm`), Safe v1.4.1 k-of-n
//! direct multisig per chain. `Gaia` — the Cosmos custody family
//! (`CustodyFamily::Cosmos`), `LegacyAminoPubKey` k-of-n multisig
//! (`GAIA.ATOM`). `Xrp` — the XRP custody family
//! (`CustodyFamily::Xrp`), native `SignerList` k-of-n multisig
//! (`XRP.XRP`). `Sol` — the Solana custody family
//! (`CustodyFamily::Solana`), Squads V4 program multisig over native
//! SOL (`SOL.SOL`). Substrate is a future family and will reuse this enum.

use std::fmt;
use std::str::FromStr;

use alloy_primitives::{address, keccak256, Address, B256};
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
    /// Ethereum mainnet.
    Eth,
    /// BNB Smart Chain.
    Bsc,
    /// Avalanche C-Chain.
    Avax,
    /// Base (Coinbase L2).
    Base,
    /// Polygon `PoS`.
    Pol,
    /// Cosmos Hub (GAIA / ATOM). Cosmos custody family.
    Gaia,
    /// XRP Ledger (XRP). XRP custody family — native `SignerList`
    /// k-of-n multisig.
    Xrp,
    /// Solana (SOL). Solana custody family — Squads V4 program multisig
    /// over native SOL (no account-level k-of-n exists for native SOL;
    /// FROST/TSS is deferred, so a program multisig is required).
    Sol,
    /// TRON (TRX). TRON custody family — native account-permission k-of-n
    /// multisig (an `Active` `Permission` with weighted keys + threshold).
    /// Every member signs the IDENTICAL `txID = sha256(raw_data)`; the
    /// 65-byte recoverable sigs append to `Transaction.signature[]` and the
    /// node sums weights — distinct from XRP's per-signer blob.
    Tron,
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Btc => "btc",
            Self::Ltc => "ltc",
            Self::Bch => "bch",
            Self::Doge => "doge",
            Self::Zec => "zec",
            Self::Eth => "eth",
            Self::Bsc => "bsc",
            Self::Avax => "avax",
            Self::Base => "base",
            Self::Pol => "pol",
            Self::Gaia => "gaia",
            Self::Xrp => "xrp",
            Self::Sol => "sol",
            Self::Tron => "tron",
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
            "eth" => Ok(Self::Eth),
            "bsc" => Ok(Self::Bsc),
            "avax" => Ok(Self::Avax),
            "base" => Ok(Self::Base),
            "pol" => Ok(Self::Pol),
            "gaia" => Ok(Self::Gaia),
            "xrp" => Ok(Self::Xrp),
            "sol" => Ok(Self::Sol),
            "tron" => Ok(Self::Tron),
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
    /// EVM chains: Safe v1.4.1 k-of-n smart-contract multisig via
    /// `execTransaction` (DL-P3-4, DL-P3.2-3).
    Evm,
    /// Cosmos-SDK chains: native `LegacyAminoPubKey` k-of-n multisig
    /// account, amino-JSON signing (DL-P3.3-2/3/4).
    Cosmos,
    /// XRP Ledger: native `SignerList` k-of-n multisig account, `STObject`
    /// binary signing. Each signer signs a per-signer multi-signing blob
    /// (`SMT\0 ‖ tx ‖ own-AccountID`) — distinct from Cosmos where all
    /// members sign identical sign-bytes (DL-P4.4-*).
    Xrp,
    /// Solana: Squads V4 program multisig over native SOL. A redemption
    /// is a 1+threshold+1 on-chain choreography (propose → approve×T →
    /// execute), ed25519 signing, NOT a single assembled tx — distinct
    /// from every other family. Core Solana has no account-level k-of-n
    /// for native SOL, so a program multisig is required (DL-2026-05-09).
    Solana,
    /// TRON: native account-permission k-of-n multisig. An account's
    /// `Active` `Permission` lists weighted keys + a threshold; a tx is
    /// valid when the summed weights of the attached signatures reach the
    /// threshold. All members sign the identical `txID = sha256(raw_data)`
    /// (the `Permission_id` is inside `raw_data`, so it is bound into the
    /// hash) — no per-signer payload divergence, unlike XRP (DL-P4.6-*).
    Tron,
    // Substrate — future family.
}

/// Fee-rate unit per chain. UTXO `SegWit` chains charge per virtual byte
/// (witness-discounted weight unit); UTXO legacy / no-segwit chains
/// charge per raw byte; EVM chains charge per gas-unit (`gwei`). Mixing
/// UTXO units produces a fee up to 4× wrong; mixing EVM with UTXO is a
/// type error caught here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeUnit {
    /// sat/vB — `SegWit`-bearing chains (BTC, LTC).
    PerVbyte,
    /// sat/B (raw byte) — legacy chains without `SegWit` (BCH, DOGE, ZEC).
    PerByte,
    /// wei/gas — EVM chains. Translated to / from gwei at the wire.
    PerGwei,
    /// `uatom`/gas — Cosmos-SDK chains. Fee = `gas_limit × gas_price`
    /// denominated in the native micro-unit (`uatom` for GAIA); distinct
    /// from `PerGwei` (different base unit, no gwei translation).
    PerCosmosGas,
    /// drops (flat) — XRP. The XRPL transaction cost is a flat fee in
    /// drops set by the network reference fee, NOT a per-size or per-gas
    /// rate; for a multi-signed tx it is `base_fee × (1 + signer_count)`.
    /// Distinct from every rate-based unit.
    FlatXrpDrops,
    /// lamports — Solana. The fee is two-part: a fixed base of 5000
    /// lamports per signature, plus an optional prioritization fee of
    /// `compute_unit_price` (micro-lamports per compute unit) ×
    /// `compute_unit_limit`. Because a Squads redemption broadcasts
    /// `1 + threshold + 1` separate single-signer txs, each pays its own
    /// base + priority — there is no per-size or per-gas rate. Distinct
    /// from every other unit.
    SolanaComputeUnits,
    /// resource units — TRON. A TRON transaction burns two distinct
    /// resources: `bandwidth` (per serialized byte, covered first by the
    /// daily free-net allowance then by burned TRX or staked Energy) and,
    /// for a `TriggerSmartContract` (TRC20), `energy` (per VM step, capped
    /// by the tx's `fee_limit` in `sun`). A plain `TransferContract` (TRX)
    /// pays bandwidth only. There is no single per-byte or per-gas scalar
    /// — distinct from every other unit.
    TronResource,
}

/// EVM transaction type per chain. Phase 3.2 picks one per chain at
/// `chain_registry::tx_type`; the executor selects the matching
/// `alloy` builder (`TxEip1559` vs `TxLegacy`). BSC long resisted
/// EIP-1559 — its mempool still routes legacy txs by default
/// (DL-P3.2-4 locked).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmTxType {
    /// Type-2 EIP-1559 (`max_fee_per_gas` + `max_priority_fee_per_gas`).
    Eip1559,
    /// Type-0 legacy (`gas_price`).
    Legacy,
}

/// Compile-time `&[ChainId]` of every supported chain. Used by
/// `from_asset_id` and the test-side full-coverage iteration.
pub const ALL_CHAINS: &[ChainId] = &[
    ChainId::Btc,
    ChainId::Ltc,
    ChainId::Bch,
    ChainId::Doge,
    ChainId::Zec,
    ChainId::Eth,
    ChainId::Bsc,
    ChainId::Avax,
    ChainId::Base,
    ChainId::Pol,
    ChainId::Gaia,
    ChainId::Xrp,
    ChainId::Sol,
    ChainId::Tron,
];

impl ChainId {
    /// `THORChain` asset string, e.g. `"BTC.BTC"` / `"ETH.ETH"`. Used
    /// in swap memos and as the canonical input to [`Self::asset_id_hash`].
    /// EVM gas-token names per `THORChain` `Bifrost`: `ETH.ETH`,
    /// `BSC.BNB`, `AVAX.AVAX`, `BASE.ETH`, `POL.MATIC`.
    #[must_use]
    pub const fn thor_asset(self) -> &'static str {
        match self {
            Self::Btc => "BTC.BTC",
            Self::Ltc => "LTC.LTC",
            Self::Bch => "BCH.BCH",
            Self::Doge => "DOGE.DOGE",
            Self::Zec => "ZEC.ZEC",
            Self::Eth => "ETH.ETH",
            Self::Bsc => "BSC.BNB",
            Self::Avax => "AVAX.AVAX",
            Self::Base => "BASE.ETH",
            Self::Pol => "POL.MATIC",
            Self::Gaia => "GAIA.ATOM",
            Self::Xrp => "XRP.XRP",
            Self::Sol => "SOL.SOL",
            Self::Tron => "TRON.TRX",
        }
    }

    /// Custody family. UTXO for Phase 3.1 chains; EVM (Safe v1.4.1
    /// multisig) for Phase 3.2 chains; Cosmos (`LegacyAminoPubKey`
    /// multisig) for Phase 3.3 chains; XRP (native `SignerList`
    /// multisig) for Phase 4.4; Solana (Squads V4) for Phase 4.5; TRON
    /// (native account-permission multisig) for Phase 4.6.
    #[must_use]
    pub const fn custody_family(self) -> CustodyFamily {
        match self {
            Self::Btc | Self::Ltc | Self::Bch | Self::Doge | Self::Zec => CustodyFamily::Utxo,
            Self::Eth | Self::Bsc | Self::Avax | Self::Base | Self::Pol => CustodyFamily::Evm,
            Self::Gaia => CustodyFamily::Cosmos,
            Self::Xrp => CustodyFamily::Xrp,
            Self::Sol => CustodyFamily::Solana,
            Self::Tron => CustodyFamily::Tron,
        }
    }

    /// Native-unit decimals. UTXO family = 8 (sat); EVM family = 18 (wei);
    /// Cosmos GAIA = 6 (`uatom`); XRP = 6 (drops, 1 XRP = 10^6 drops);
    /// Solana = 9 (lamports, 1 SOL = 10^9 lamports); TRON = 6 (`sun`,
    /// 1 TRX = 10^6 sun; TRC20 USDT on TRON is also 6-decimal).
    #[must_use]
    pub const fn decimals(self) -> u8 {
        match self {
            Self::Btc | Self::Ltc | Self::Bch | Self::Doge | Self::Zec => 8,
            Self::Eth | Self::Bsc | Self::Avax | Self::Base | Self::Pol => 18,
            Self::Gaia | Self::Xrp | Self::Tron => 6,
            Self::Sol => 9,
        }
    }

    /// Native-unit scale (`10^decimals`) as `u64`. **Non-EVM only**
    /// (UTXO `10^8`, Cosmos GAIA `10^6`, Solana `10^9`). EVM chains have `10^18` which
    /// overflows `u64`; calling this on an EVM chain is a programming
    /// error. Use [`Self::scale_u128`] for any code that may run on the
    /// EVM family.
    ///
    /// # Panics
    /// Panics on `Eth` / `Bsc` / `Avax` / `Base` / `Pol`.
    #[must_use]
    #[expect(
        clippy::panic,
        reason = "intentional fail-loud guard against EVM-callers using a u64 path; \
                  EVM 10^18 overflows u64. Workspace clippy.panic = deny is correct \
                  for production code, but this const fn is the exception that names \
                  itself u64."
    )]
    pub const fn scale(self) -> u64 {
        match self {
            Self::Btc | Self::Ltc | Self::Bch | Self::Doge | Self::Zec => 100_000_000,
            Self::Gaia | Self::Xrp | Self::Tron => 1_000_000,
            Self::Sol => 1_000_000_000,
            Self::Eth | Self::Bsc | Self::Avax | Self::Base | Self::Pol => {
                panic!("ChainId::scale() does not fit u64 for the EVM family — use scale_u128()")
            }
        }
    }

    /// Native-unit scale (`10^decimals`) as `u128`. Works for all
    /// chains (`10^18 < u128::MAX`); the canonical accessor for any
    /// code that touches both UTXO and EVM families (chain-evm,
    /// safe-evm, executor).
    #[must_use]
    pub const fn scale_u128(self) -> u128 {
        match self {
            Self::Btc | Self::Ltc | Self::Bch | Self::Doge | Self::Zec => 100_000_000,
            Self::Gaia | Self::Xrp | Self::Tron => 1_000_000,
            Self::Sol => 1_000_000_000,
            Self::Eth | Self::Bsc | Self::Avax | Self::Base | Self::Pol => {
                1_000_000_000_000_000_000
            }
        }
    }

    /// Confirmation depth before the signer attests a delivery /
    /// refund. UTXO per `THORChain` Bifrost: BTC 6, LTC 12, BCH 6,
    /// DOGE 40, ZEC 10. EVM per Bifrost finality models: ETH 12
    /// (proof-of-stake near-instant finality at 2 epochs ≈ 12.8 min),
    /// BSC 20 (3-sec blocks, 1-min effective), AVAX 5 (post-Apricot
    /// rapid finality), BASE 30 (L2 sequencer + ~5-min L1 anchoring),
    /// POL 64 (heimdall-bor 256-block checkpointing → conservative).
    /// GAIA 1 — Tendermint instant finality (a committed block is final
    /// under <1/3 Byzantine); 1 = read the including block after commit
    /// (Bifrost reads tip-1 to dodge the block-results race).
    /// XRP 1 — XRPL gives deterministic finality on validated ledgers
    /// (`THORChain` Bifrost waits 0); 1 = require one validated ledger on
    /// top of the including ledger, the same conservative margin as GAIA.
    /// The `chain-xrp` client MUST only count txs from validated ledgers.
    /// SOL 1 — Solana's `finalized` commitment is irreversible (a rooted
    /// slot has supermajority lockout); `THORChain` Bifrost scans at
    /// commitment `finalized`. 1 = one finalized observation, the same
    /// conservative margin as GAIA/XRP. The `chain-solana` client MUST
    /// only count txs at commitment `finalized`.
    /// TRON 19 — TRON has NO single-block deterministic finality (unlike
    /// GAIA/XRP/SOL): a block is irreversible only after 2/3+1 of the 27
    /// super-representatives confirm it, ~19 blocks (≈57 s at 3-s blocks).
    /// `THORChain` Bifrost reports TRON solvency at height-19, so we wait
    /// the full SR finality window before attesting a delivery/refund.
    #[must_use]
    #[expect(
        clippy::match_same_arms,
        reason = "BTC/BCH share 6 confs as a Bifrost coincidence (different consensus); \
                  LTC/ETH share 12 by coincidence (PoW vs PoS finality); GAIA/XRP/SOL \
                  share 1 by coincidence (Tendermint vs XRPL-consensus vs Solana \
                  finalized-commitment finality). Merging arms would imply a shared \
                  reason that does not exist."
    )]
    pub const fn conf_depth(self) -> u32 {
        match self {
            Self::Btc | Self::Bch => 6,
            Self::Ltc => 12,
            Self::Doge => 40,
            Self::Zec => 10,
            Self::Eth => 12,
            Self::Bsc => 20,
            Self::Avax => 5,
            Self::Base => 30,
            Self::Pol => 64,
            Self::Gaia => 1,
            Self::Xrp => 1,
            Self::Sol => 1,
            Self::Tron => 19,
        }
    }

    /// Maximum bytes carryable in an `OP_RETURN` standard-relay output
    /// (UTXO chains). `0` for EVM chains (memos live in calldata),
    /// Cosmos chains (the `THORChain` memo lives in the tx `memo` field,
    /// ≤250 bytes, enforced by the Cosmos tx builder — not here), and XRP
    /// (the memo lives in the `Memos` array, hex-encoded `MemoData`), and
    /// Solana (the memo lives in an SPL-Memo program instruction), and TRON
    /// (the memo lives in the `raw_data.data` field; length is bounded by
    /// the tx builder, not here).
    #[must_use]
    pub const fn op_return_max(self) -> usize {
        match self {
            Self::Bch => 220,
            Self::Btc | Self::Ltc | Self::Doge | Self::Zec => 80,
            Self::Eth
            | Self::Bsc
            | Self::Avax
            | Self::Base
            | Self::Pol
            | Self::Gaia
            | Self::Xrp
            | Self::Sol
            | Self::Tron => 0,
        }
    }

    /// Daemon-side upper bound (sats) on the implied miner fee
    /// (`Σ inputs − Σ outputs`) of a redemption spend, used by the UTXO
    /// PSBT signer to bound a fee-burning grief (M2b partial floor): a
    /// malicious coordinator that omits the change output would otherwise
    /// burn the entire residue to miners. The honest redemption fee is
    /// `tx_size × fee_rate` — a few hundred thousand sats even at extreme
    /// congestion — so these ceilings are deliberately generous and never
    /// reject an honest spend; they only cap how much can be destroyed.
    /// **Tighten per-chain at the DL-P3-7 mainnet gate.** `u64::MAX`
    /// (no cap) for non-UTXO chains, which have their own fee models and
    /// never reach this path.
    #[must_use]
    pub const fn max_redeem_fee_sats(self) -> u64 {
        match self {
            Self::Btc => 1_000_000,
            Self::Ltc | Self::Bch | Self::Zec => 5_000_000,
            Self::Doge => 1_000_000_000,
            Self::Eth
            | Self::Bsc
            | Self::Avax
            | Self::Base
            | Self::Pol
            | Self::Gaia
            | Self::Xrp
            | Self::Sol
            | Self::Tron => u64::MAX,
        }
    }

    /// Fee unit per chain. UTXO `SegWit` → `PerVbyte`; UTXO legacy →
    /// `PerByte`; EVM → `PerGwei`; Cosmos → `PerCosmosGas`; XRP →
    /// `FlatXrpDrops`; Solana → `SolanaComputeUnits`; TRON → `TronResource`.
    #[must_use]
    pub const fn fee_unit(self) -> FeeUnit {
        match self {
            Self::Btc | Self::Ltc => FeeUnit::PerVbyte,
            Self::Bch | Self::Doge | Self::Zec => FeeUnit::PerByte,
            Self::Eth | Self::Bsc | Self::Avax | Self::Base | Self::Pol => FeeUnit::PerGwei,
            Self::Gaia => FeeUnit::PerCosmosGas,
            Self::Xrp => FeeUnit::FlatXrpDrops,
            Self::Sol => FeeUnit::SolanaComputeUnits,
            Self::Tron => FeeUnit::TronResource,
        }
    }

    /// EVM transaction type per chain. UTXO and Cosmos chains return
    /// `None` (the EVM tx-type concept is meaningless for them).
    /// DL-P3.2-4: EIP-1559 on ETH/AVAX/BASE/POL; legacy on BSC.
    #[must_use]
    pub const fn tx_type(self) -> Option<EvmTxType> {
        match self {
            Self::Eth | Self::Avax | Self::Base | Self::Pol => Some(EvmTxType::Eip1559),
            Self::Bsc => Some(EvmTxType::Legacy),
            Self::Btc
            | Self::Ltc
            | Self::Bch
            | Self::Doge
            | Self::Zec
            | Self::Gaia
            | Self::Xrp
            | Self::Sol
            | Self::Tron => None,
        }
    }

    /// EVM chain ID (the `chainId` field used in EIP-155 + EIP-712
    /// domain separators). UTXO chains return `None`.
    #[must_use]
    pub const fn evm_chain_id(self) -> Option<u64> {
        match self {
            Self::Eth => Some(1),
            Self::Bsc => Some(56),
            Self::Avax => Some(43_114),
            Self::Base => Some(8_453),
            Self::Pol => Some(137),
            Self::Btc
            | Self::Ltc
            | Self::Bch
            | Self::Doge
            | Self::Zec
            | Self::Gaia
            | Self::Xrp
            | Self::Sol
            | Self::Tron => None,
        }
    }

    /// `THORChain` Router contract address on the chain itself. The
    /// executor sends Safe `execTransaction` output to this address to
    /// initiate a swap back to USDT on Ethereum. UTXO, Cosmos, XRP, Solana,
    /// and TRON chains return `None` (their `THORChain` side is an `Asgard`
    /// vault / account address served by `ThorchainVaultRegistry`; the TRON
    /// redeem leg is a native multisig transfer from our account, not a
    /// router call).
    ///
    /// **DL-P3.2-5: placeholders pending source citation.** These
    /// addresses MUST be pinned from a specific `THORChain` docs
    /// commit before V10 mainnet deploy. Returning `address(0)` here
    /// ensures any premature mainnet attempt fails loudly (Safe
    /// `execTransaction` to the zero address would revert at the
    /// receiver gate). V7 (executor) and V10 (Solidity registration)
    /// pin the real addresses with source citation; V11
    /// `KNOWN_FINDINGS` records the pin verification.
    #[must_use]
    pub fn thorchain_router_address(self) -> Option<Address> {
        match self {
            Self::Eth | Self::Bsc | Self::Avax | Self::Base | Self::Pol => {
                Some(address!("0000000000000000000000000000000000000000"))
            }
            Self::Btc
            | Self::Ltc
            | Self::Bch
            | Self::Doge
            | Self::Zec
            | Self::Gaia
            | Self::Xrp
            | Self::Sol
            | Self::Tron => None,
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
    /// hash doesn't match any supported chain. Iterates [`ALL_CHAINS`].
    ///
    /// Used by `xindex-attest-redeem` to route per-leg cross-checks:
    /// `ev.legAssetIds[i]` → `ChainId` → per-chain dispatch lookup +
    /// chain client + `THORChain` chain-query endpoint.
    #[must_use]
    pub fn from_asset_id(asset_id: B256) -> Option<Self> {
        ALL_CHAINS
            .iter()
            .copied()
            .find(|c| c.asset_id_hash() == asset_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical `THORChain` asset strings. Pinned — changing any of
    /// these breaks the on-chain `IndexFactory` constants which hash
    /// the same UTF-8 bytes. EVM gas-token names per Bifrost
    /// convention (`ETH.ETH`, `BSC.BNB`, `AVAX.AVAX`, `BASE.ETH`,
    /// `POL.MATIC`).
    #[test]
    fn thor_asset_strings_match_thorchain_convention() {
        assert_eq!(ChainId::Btc.thor_asset(), "BTC.BTC");
        assert_eq!(ChainId::Ltc.thor_asset(), "LTC.LTC");
        assert_eq!(ChainId::Bch.thor_asset(), "BCH.BCH");
        assert_eq!(ChainId::Doge.thor_asset(), "DOGE.DOGE");
        assert_eq!(ChainId::Zec.thor_asset(), "ZEC.ZEC");
        assert_eq!(ChainId::Eth.thor_asset(), "ETH.ETH");
        assert_eq!(ChainId::Bsc.thor_asset(), "BSC.BNB");
        assert_eq!(ChainId::Avax.thor_asset(), "AVAX.AVAX");
        assert_eq!(ChainId::Base.thor_asset(), "BASE.ETH");
        assert_eq!(ChainId::Pol.thor_asset(), "POL.MATIC");
        assert_eq!(ChainId::Gaia.thor_asset(), "GAIA.ATOM");
        assert_eq!(ChainId::Xrp.thor_asset(), "XRP.XRP");
        assert_eq!(ChainId::Sol.thor_asset(), "SOL.SOL");
        assert_eq!(ChainId::Tron.thor_asset(), "TRON.TRX");
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
            assert_eq!(c.scale_u128(), 100_000_000_u128);
            assert_eq!(c.tx_type(), None);
            assert_eq!(c.evm_chain_id(), None);
            assert_eq!(c.thorchain_router_address(), None);
        }
    }

    #[test]
    fn all_phase_3_2_chains_are_evm_family_with_18_decimals() {
        for c in [
            ChainId::Eth,
            ChainId::Bsc,
            ChainId::Avax,
            ChainId::Base,
            ChainId::Pol,
        ] {
            assert_eq!(c.custody_family(), CustodyFamily::Evm);
            assert_eq!(c.decimals(), 18);
            assert_eq!(c.scale_u128(), 1_000_000_000_000_000_000_u128);
            assert_eq!(c.fee_unit(), FeeUnit::PerGwei);
            assert_eq!(c.op_return_max(), 0);
            assert!(c.tx_type().is_some());
            assert!(c.evm_chain_id().is_some());
            assert!(c.thorchain_router_address().is_some());
        }
    }

    /// Phase 3.3 Cosmos family: GAIA = ATOM, 6-dec (`uatom`), instant
    /// finality, memo in tx field (no `OP_RETURN`), `PerCosmosGas` fee
    /// unit, no EVM tx-type / chain-id / router. `scale()` fits u64 (10^6).
    #[test]
    fn all_phase_3_3_chains_are_cosmos_family_with_6_decimals() {
        // Single-chain family today (NOBLE follow-on adds a second row).
        let c = ChainId::Gaia;
        assert_eq!(c.custody_family(), CustodyFamily::Cosmos);
        assert_eq!(c.decimals(), 6);
        assert_eq!(c.scale(), 1_000_000);
        assert_eq!(c.scale_u128(), 1_000_000_u128);
        assert_eq!(c.fee_unit(), FeeUnit::PerCosmosGas);
        assert_eq!(c.op_return_max(), 0);
        assert_eq!(c.tx_type(), None);
        assert_eq!(c.evm_chain_id(), None);
        assert_eq!(c.thorchain_router_address(), None);
    }

    /// Phase 4.4 XRP family: XRP = XRP.XRP, 6-dec (drops), deterministic
    /// finality (conf 1), memo in the `Memos` array (no `OP_RETURN`),
    /// `FlatXrpDrops` fee unit, no EVM tx-type / chain-id / router.
    /// `scale()` fits u64 (10^6).
    #[test]
    fn xrp_is_xrp_family_with_6_decimals() {
        let c = ChainId::Xrp;
        assert_eq!(c.custody_family(), CustodyFamily::Xrp);
        assert_eq!(c.decimals(), 6);
        assert_eq!(c.scale(), 1_000_000);
        assert_eq!(c.scale_u128(), 1_000_000_u128);
        assert_eq!(c.conf_depth(), 1);
        assert_eq!(c.fee_unit(), FeeUnit::FlatXrpDrops);
        assert_eq!(c.op_return_max(), 0);
        assert_eq!(c.tx_type(), None);
        assert_eq!(c.evm_chain_id(), None);
        assert_eq!(c.thorchain_router_address(), None);
    }

    /// Phase 4.5 Solana family: SOL = SOL.SOL, 9-dec (lamports),
    /// finalized-commitment finality (conf 1), memo in an SPL-Memo
    /// instruction (no `OP_RETURN`), `SolanaComputeUnits` fee unit, no EVM
    /// tx-type / chain-id / router. `scale()` fits u64 (10^9).
    #[test]
    fn sol_is_solana_family_with_9_decimals() {
        let c = ChainId::Sol;
        assert_eq!(c.custody_family(), CustodyFamily::Solana);
        assert_eq!(c.decimals(), 9);
        assert_eq!(c.scale(), 1_000_000_000);
        assert_eq!(c.scale_u128(), 1_000_000_000_u128);
        assert_eq!(c.conf_depth(), 1);
        assert_eq!(c.fee_unit(), FeeUnit::SolanaComputeUnits);
        assert_eq!(c.op_return_max(), 0);
        assert_eq!(c.tx_type(), None);
        assert_eq!(c.evm_chain_id(), None);
        assert_eq!(c.thorchain_router_address(), None);
    }

    /// Phase 4.6 TRON family: TRON = TRON.TRX, 6-dec (`sun`), SR finality
    /// (conf 19), memo in the `raw_data.data` field (no `OP_RETURN`),
    /// `TronResource` fee unit, no EVM tx-type / chain-id / router.
    /// `scale()` fits u64 (10^6).
    #[test]
    fn tron_is_tron_family_with_6_decimals() {
        let c = ChainId::Tron;
        assert_eq!(c.custody_family(), CustodyFamily::Tron);
        assert_eq!(c.decimals(), 6);
        assert_eq!(c.scale(), 1_000_000);
        assert_eq!(c.scale_u128(), 1_000_000_u128);
        assert_eq!(c.conf_depth(), 19);
        assert_eq!(c.fee_unit(), FeeUnit::TronResource);
        assert_eq!(c.op_return_max(), 0);
        assert_eq!(c.tx_type(), None);
        assert_eq!(c.evm_chain_id(), None);
        assert_eq!(c.thorchain_router_address(), None);
    }

    /// Tx-type per DL-P3.2-4: EIP-1559 on ETH/AVAX/BASE/POL; legacy on BSC.
    #[test]
    fn tx_type_per_chain_matches_dl_p32_4() {
        assert_eq!(ChainId::Eth.tx_type(), Some(EvmTxType::Eip1559));
        assert_eq!(ChainId::Avax.tx_type(), Some(EvmTxType::Eip1559));
        assert_eq!(ChainId::Base.tx_type(), Some(EvmTxType::Eip1559));
        assert_eq!(ChainId::Pol.tx_type(), Some(EvmTxType::Eip1559));
        assert_eq!(ChainId::Bsc.tx_type(), Some(EvmTxType::Legacy));
    }

    /// EVM chain IDs pinned per EIP-155 mainnet assignments.
    #[test]
    fn evm_chain_ids_match_mainnet() {
        assert_eq!(ChainId::Eth.evm_chain_id(), Some(1));
        assert_eq!(ChainId::Bsc.evm_chain_id(), Some(56));
        assert_eq!(ChainId::Avax.evm_chain_id(), Some(43_114));
        assert_eq!(ChainId::Base.evm_chain_id(), Some(8_453));
        assert_eq!(ChainId::Pol.evm_chain_id(), Some(137));
    }

    /// `ChainId::scale()` panics on EVM chains — those callers must
    /// use `scale_u128`. Pinning the panic so a silent EVM regression
    /// (`scale()` returning 0 or wrapping `10^18 mod 2^64`) is
    /// impossible.
    #[test]
    #[should_panic(expected = "does not fit u64")]
    fn scale_u64_panics_on_evm() {
        let _ = ChainId::Eth.scale();
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
        // EVM family per Bifrost finality models.
        assert_eq!(ChainId::Eth.conf_depth(), 12);
        assert_eq!(ChainId::Bsc.conf_depth(), 20);
        assert_eq!(ChainId::Avax.conf_depth(), 5);
        assert_eq!(ChainId::Base.conf_depth(), 30);
        assert_eq!(ChainId::Pol.conf_depth(), 64);
        // GAIA 1: Tendermint instant finality.
        assert_eq!(ChainId::Gaia.conf_depth(), 1);
        // XRP 1: deterministic finality on validated ledgers.
        assert_eq!(ChainId::Xrp.conf_depth(), 1);
        // SOL 1: irreversible finalized-commitment slots.
        assert_eq!(ChainId::Sol.conf_depth(), 1);
        // TRON 19: SR super-representative finality (no single-block finality).
        assert_eq!(ChainId::Tron.conf_depth(), 19);
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
        // GAIA: memo lives in the tx memo field, not OP_RETURN.
        assert_eq!(ChainId::Gaia.op_return_max(), 0);
        // XRP: memo lives in the Memos array, not OP_RETURN.
        assert_eq!(ChainId::Xrp.op_return_max(), 0);
        // SOL: memo lives in an SPL-Memo instruction, not OP_RETURN.
        assert_eq!(ChainId::Sol.op_return_max(), 0);
        // TRON: memo lives in raw_data.data, not OP_RETURN.
        assert_eq!(ChainId::Tron.op_return_max(), 0);
    }

    /// M2b fee ceiling: a generous per-UTXO-chain bound on the implied
    /// miner fee (never rejects an honest redeem; caps a fee-burn grief);
    /// `u64::MAX` (no cap) for non-UTXO chains that never reach the PSBT
    /// fee check.
    #[test]
    fn max_redeem_fee_sats_per_chain() {
        assert_eq!(ChainId::Btc.max_redeem_fee_sats(), 1_000_000);
        assert_eq!(ChainId::Ltc.max_redeem_fee_sats(), 5_000_000);
        assert_eq!(ChainId::Bch.max_redeem_fee_sats(), 5_000_000);
        assert_eq!(ChainId::Doge.max_redeem_fee_sats(), 1_000_000_000);
        assert_eq!(ChainId::Zec.max_redeem_fee_sats(), 5_000_000);
        assert_eq!(ChainId::Eth.max_redeem_fee_sats(), u64::MAX);
        assert_eq!(ChainId::Gaia.max_redeem_fee_sats(), u64::MAX);
        assert_eq!(ChainId::Xrp.max_redeem_fee_sats(), u64::MAX);
        assert_eq!(ChainId::Sol.max_redeem_fee_sats(), u64::MAX);
        assert_eq!(ChainId::Tron.max_redeem_fee_sats(), u64::MAX);
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
        assert_eq!(ChainId::Gaia.fee_unit(), FeeUnit::PerCosmosGas);
        assert_eq!(ChainId::Xrp.fee_unit(), FeeUnit::FlatXrpDrops);
        assert_eq!(ChainId::Sol.fee_unit(), FeeUnit::SolanaComputeUnits);
        assert_eq!(ChainId::Tron.fee_unit(), FeeUnit::TronResource);
    }

    /// `asset_id_hash` is `keccak256(thor_asset.as_bytes())`. Both
    /// pinning the formula (mirror of Solidity) and verifying distinct
    /// chains produce distinct hashes (anti-collision sanity).
    /// Round-trip: `ChainId` ↔ string form (`Display` + `FromStr`).
    /// Used by JSON wire (`PsbtInputSignRequest`), `SQLite` TEXT columns,
    /// and CLI args. Mixed-case input is normalised to lowercase. All
    /// 13 chains round-trip cleanly.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn display_fromstr_round_trip_and_case_insensitive() {
        for &c in ALL_CHAINS {
            let s = c.to_string();
            let back: ChainId = s.parse().expect("parse");
            assert_eq!(back, c);
        }
        assert_eq!("BTC".parse::<ChainId>().expect("uppercase"), ChainId::Btc);
        assert_eq!("Ltc".parse::<ChainId>().expect("mixed"), ChainId::Ltc);
        assert_eq!("ETH".parse::<ChainId>().expect("evm upper"), ChainId::Eth);
        assert_eq!("Base".parse::<ChainId>().expect("evm mixed"), ChainId::Base);
        assert_eq!(
            "GAIA".parse::<ChainId>().expect("cosmos upper"),
            ChainId::Gaia
        );
        assert_eq!("XRP".parse::<ChainId>().expect("xrp upper"), ChainId::Xrp);
        assert_eq!("SOL".parse::<ChainId>().expect("sol upper"), ChainId::Sol);
        assert_eq!(
            "TRON".parse::<ChainId>().expect("tron upper"),
            ChainId::Tron
        );
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
    /// `from_asset_id`. Bogus hash returns `None`. Used by
    /// `xindex-attest-redeem` to route per-leg cross-checks. All 13
    /// chains covered.
    #[test]
    fn from_asset_id_round_trip_and_rejects_unknown() {
        for &c in ALL_CHAINS {
            assert_eq!(ChainId::from_asset_id(c.asset_id_hash()), Some(c));
        }
        // Unknown / bogus asset hash → None (not silently mapped to BTC).
        let bogus = B256::repeat_byte(0xff);
        assert_eq!(ChainId::from_asset_id(bogus), None);
    }

    #[test]
    fn asset_id_hash_matches_keccak256_of_thor_asset_bytes() {
        for &c in ALL_CHAINS {
            let expected = keccak256(c.thor_asset().as_bytes());
            assert_eq!(c.asset_id_hash(), expected);
        }
        // All 13 hashes are pairwise distinct (no UTXO/EVM/Cosmos/XRP/Solana collisions).
        let hashes: Vec<B256> = ALL_CHAINS
            .iter()
            .copied()
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
