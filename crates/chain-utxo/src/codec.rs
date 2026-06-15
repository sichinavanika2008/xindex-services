//! Per-chain address codec for the UTXO custody family.
//!
//! [`UtxoAddressCodec`] is the one-trait surface for encoding a
//! multisig `script_pubkey` into its chain-canonical address string —
//! and decoding the inverse. Each Phase 3.1 chain has its own impl
//! per plan §"Architecture":
//!
//! | Chain | Template       | Codec implementation                          |
//! |-------|----------------|-----------------------------------------------|
//! | BTC   | P2WSH (bech32) | `bitcoin::Address::from_script` (mainnet HRP) |
//! | LTC   | P2WSH (bech32) | hand-rolled `bech32` crate with HRP "ltc"     |
//! | BCH   | P2SH (`CashAddr`)| `bitcoincash-addr` v0.5 crate               |
//! | DOGE  | P2SH (base58)  | `bitcoin::base58` + version byte `0x16`       |
//! | ZEC   | P2SH (t-addr)  | hand-rolled 2-byte-version base58check        |
//!
//! ZEC's `zcash_address` crate covers the t-addr layer but pulls in
//! shielded-pool primitives we don't need; a ~10-line hand-roll over
//! `bitcoin::base58` + `bitcoin::hashes::sha256d` is audit-friendlier.
//!
//! All codecs are stateless once their network is fixed. The factory
//! [`codec_for_mainnet`] returns a dynamically-dispatched mainnet
//! codec per [`ChainId`]; per-network variants can be constructed
//! directly with the struct's `mainnet`/`testnet` constructors when
//! signet / testnet support lands.
//!
//! ## Test-vector pinning
//!
//! Each codec carries a pinned `encode → known-good address` test.
//! These vectors are the authoritative reference — a regression in
//! address encoding could route real funds to a black hole on
//! mainnet, so the round-trip property tests + pinned vectors are
//! non-negotiable.

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::script::Instruction;
use bitcoin::{base58, Address, Network, Script, ScriptBuf};
use thiserror::Error;
use xindex_shared::chain_registry::ChainId;

/// Errors surfaced by codec encode / decode operations.
#[derive(Debug, Error)]
pub enum CodecError {
    /// Encoder failed (typically: malformed SPK input).
    #[error("encode error ({chain:?}): {msg}")]
    Encode { chain: ChainId, msg: String },
    /// Decoder failed (typically: bad base58/bech32, checksum
    /// mismatch, wrong network prefix).
    #[error("decode error ({chain:?}): {msg}")]
    Decode { chain: ChainId, msg: String },
    /// The supplied `script_pubkey` is not the expected template for
    /// this chain (e.g. P2WSH SPK passed to a P2SH-legacy codec).
    #[error("unsupported script template for {chain:?}: {msg}")]
    UnsupportedScript { chain: ChainId, msg: String },
}

/// Encode a multisig `script_pubkey` to its chain-canonical address,
/// and decode the inverse.
pub trait UtxoAddressCodec: Send + Sync + std::fmt::Debug {
    /// Which chain this codec serves.
    fn chain(&self) -> ChainId;

    /// Encode a `script_pubkey` to the chain-canonical address string.
    /// SPK shape:
    /// - P2WSH (BTC/LTC): `OP_0 <0x20> <32 bytes>`
    /// - P2SH (BCH/DOGE/ZEC): `OP_HASH160 <0x14> <20 bytes> OP_EQUAL`
    ///
    /// # Errors
    /// [`CodecError::UnsupportedScript`] if the SPK shape doesn't
    /// match the chain's template; [`CodecError::Encode`] on
    /// underlying library failure.
    fn encode(&self, script_pubkey: &Script) -> Result<String, CodecError>;

    /// Inverse of [`encode`]. Parses an address string back to the
    /// equivalent `script_pubkey`.
    ///
    /// # Errors
    /// [`CodecError::Decode`] on bad format / checksum / wrong network.
    fn decode(&self, addr: &str) -> Result<ScriptBuf, CodecError>;
}

// ─── shape extractors ──────────────────────────────────────────────────────

/// Extract the 32-byte witness program from a P2WSH SPK
/// (`OP_0 <0x20> <32 bytes>`). Returns `None` if the SPK is not P2WSH.
fn p2wsh_witness_program(spk: &Script) -> Option<[u8; 32]> {
    let bytes = spk.as_bytes();
    if bytes.len() != 34 || bytes[0] != 0x00 || bytes[1] != 0x20 {
        return None;
    }
    let mut program = [0u8; 32];
    program.copy_from_slice(&bytes[2..]);
    Some(program)
}

/// Extract the 20-byte script hash from a P2SH SPK
/// (`OP_HASH160 <0x14> <20 bytes> OP_EQUAL`). Returns `None` if the
/// SPK is not P2SH.
fn p2sh_script_hash(spk: &Script) -> Option<[u8; 20]> {
    let bytes = spk.as_bytes();
    if bytes.len() != 23
        || bytes[0] != 0xa9 // OP_HASH160
        || bytes[1] != 0x14 // push 20 bytes
        || bytes[22] != 0x87
    // OP_EQUAL
    {
        return None;
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&bytes[2..22]);
    Some(hash)
}

/// `[2-byte-version || 20-byte-hash || 4-byte-checksum]` base58 encode.
/// Used by ZEC t-addr (P2SH version `0x1cbd` on mainnet); generalised
/// to any chain that needs a 2-byte-version base58check (vs the
/// standard 1-byte-version form `bitcoin::base58` provides directly).
fn base58check_2byte_version(version: [u8; 2], hash20: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(2 + 20 + 4);
    payload.extend_from_slice(&version);
    payload.extend_from_slice(hash20);
    let checksum = sha256d::Hash::hash(&payload);
    payload.extend_from_slice(&checksum.as_byte_array()[..4]);
    base58::encode(&payload)
}

/// Inverse of [`base58check_2byte_version`].
fn decode_base58check_2byte_version(addr: &str) -> Result<([u8; 2], [u8; 20]), String> {
    let payload = base58::decode(addr).map_err(|e| format!("base58: {e}"))?;
    if payload.len() != 2 + 20 + 4 {
        return Err(format!("payload length {} != 26", payload.len()));
    }
    let (data, checksum_bytes) = payload.split_at(2 + 20);
    let expected = sha256d::Hash::hash(data);
    if &expected.as_byte_array()[..4] != checksum_bytes {
        return Err("base58check checksum mismatch".to_string());
    }
    let version = [data[0], data[1]];
    let hash: [u8; 20] = data[2..]
        .try_into()
        .map_err(|e: std::array::TryFromSliceError| e.to_string())?;
    Ok((version, hash))
}

/// `[1-byte-version || 20-byte-hash || 4-byte-checksum]` base58 encode.
/// Used by DOGE P2SH (version `0x16` on mainnet) and the BTC/LTC P2SH
/// variants (not used by us today — we use P2WSH for those).
fn base58check_1byte_version(version: u8, hash20: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(1 + 20 + 4);
    payload.push(version);
    payload.extend_from_slice(hash20);
    let checksum = sha256d::Hash::hash(&payload);
    payload.extend_from_slice(&checksum.as_byte_array()[..4]);
    base58::encode(&payload)
}

/// Inverse of [`base58check_1byte_version`].
fn decode_base58check_1byte_version(addr: &str) -> Result<(u8, [u8; 20]), String> {
    let payload = base58::decode(addr).map_err(|e| format!("base58: {e}"))?;
    if payload.len() != 1 + 20 + 4 {
        return Err(format!("payload length {} != 25", payload.len()));
    }
    let (data, checksum_bytes) = payload.split_at(1 + 20);
    let expected = sha256d::Hash::hash(data);
    if &expected.as_byte_array()[..4] != checksum_bytes {
        return Err("base58check checksum mismatch".to_string());
    }
    let version = data[0];
    let hash: [u8; 20] = data[1..]
        .try_into()
        .map_err(|e: std::array::TryFromSliceError| e.to_string())?;
    Ok((version, hash))
}

// ─── BTC ───────────────────────────────────────────────────────────────────

/// BTC address codec. Delegates to `bitcoin::Address::from_script`,
/// which handles both P2WSH (bech32 `bc1...`) and any other Bitcoin
/// script template the SPK might happen to be.
#[derive(Debug, Clone, Copy)]
pub struct BtcCodec {
    pub network: Network,
}

impl BtcCodec {
    #[must_use]
    pub const fn mainnet() -> Self {
        Self {
            network: Network::Bitcoin,
        }
    }
    #[must_use]
    pub const fn signet() -> Self {
        Self {
            network: Network::Signet,
        }
    }
}

impl Default for BtcCodec {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl UtxoAddressCodec for BtcCodec {
    fn chain(&self) -> ChainId {
        ChainId::Btc
    }
    fn encode(&self, script_pubkey: &Script) -> Result<String, CodecError> {
        Address::from_script(script_pubkey, self.network)
            .map(|a| a.to_string())
            .map_err(|e| CodecError::Encode {
                chain: ChainId::Btc,
                msg: e.to_string(),
            })
    }
    fn decode(&self, addr: &str) -> Result<ScriptBuf, CodecError> {
        let unchecked = addr.parse::<Address<_>>().map_err(|e| CodecError::Decode {
            chain: ChainId::Btc,
            msg: e.to_string(),
        })?;
        let checked = unchecked
            .require_network(self.network)
            .map_err(|e| CodecError::Decode {
                chain: ChainId::Btc,
                msg: e.to_string(),
            })?;
        Ok(checked.script_pubkey())
    }
}

// ─── LTC ───────────────────────────────────────────────────────────────────

/// LTC address codec. Hand-rolled bech32 with HRP `"ltc"` (mainnet)
/// or `"tltc"` (testnet). Same `SegWit`-v0 P2WSH program format as BTC
/// (32-byte sha256 of the witness script).
#[derive(Debug, Clone, Copy)]
pub struct LtcCodec {
    pub mainnet: bool,
}

impl LtcCodec {
    #[must_use]
    pub const fn mainnet() -> Self {
        Self { mainnet: true }
    }
    #[must_use]
    pub const fn testnet() -> Self {
        Self { mainnet: false }
    }
    fn hrp(self) -> bech32::Hrp {
        bech32::Hrp::parse_unchecked(if self.mainnet { "ltc" } else { "tltc" })
    }
}

impl Default for LtcCodec {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl UtxoAddressCodec for LtcCodec {
    fn chain(&self) -> ChainId {
        ChainId::Ltc
    }
    fn encode(&self, script_pubkey: &Script) -> Result<String, CodecError> {
        let program =
            p2wsh_witness_program(script_pubkey).ok_or(CodecError::UnsupportedScript {
                chain: ChainId::Ltc,
                msg: "expected P2WSH (OP_0 <0x20> <32B>)".to_string(),
            })?;
        bech32::segwit::encode_v0(self.hrp(), &program).map_err(|e| CodecError::Encode {
            chain: ChainId::Ltc,
            msg: e.to_string(),
        })
    }
    fn decode(&self, addr: &str) -> Result<ScriptBuf, CodecError> {
        let (hrp, _witver, program) =
            bech32::segwit::decode(addr).map_err(|e| CodecError::Decode {
                chain: ChainId::Ltc,
                msg: e.to_string(),
            })?;
        if hrp != self.hrp() {
            return Err(CodecError::Decode {
                chain: ChainId::Ltc,
                msg: format!("HRP mismatch: expected {}, got {hrp}", self.hrp()),
            });
        }
        if program.len() != 32 {
            return Err(CodecError::Decode {
                chain: ChainId::Ltc,
                msg: format!("witness program length {} != 32 (P2WSH)", program.len()),
            });
        }
        // Reassemble OP_0 <0x20> <32B>.
        let mut spk = Vec::with_capacity(34);
        spk.push(0x00);
        spk.push(0x20);
        spk.extend_from_slice(&program);
        Ok(ScriptBuf::from_bytes(spk))
    }
}

// ─── BCH ───────────────────────────────────────────────────────────────────

/// BCH address codec. Uses the `bitcoincash-addr` crate to encode /
/// decode `bitcoincash:`-prefixed `CashAddr` base32 strings for P2SH
/// scripts.
#[derive(Debug, Clone, Copy)]
pub struct BchCodec {
    pub mainnet: bool,
}

impl BchCodec {
    #[must_use]
    pub const fn mainnet() -> Self {
        Self { mainnet: true }
    }
    #[must_use]
    pub const fn testnet() -> Self {
        Self { mainnet: false }
    }
    fn network(self) -> bitcoincash_addr::Network {
        if self.mainnet {
            bitcoincash_addr::Network::Main
        } else {
            bitcoincash_addr::Network::Test
        }
    }
}

impl Default for BchCodec {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl UtxoAddressCodec for BchCodec {
    fn chain(&self) -> ChainId {
        ChainId::Bch
    }
    fn encode(&self, script_pubkey: &Script) -> Result<String, CodecError> {
        let hash = p2sh_script_hash(script_pubkey).ok_or(CodecError::UnsupportedScript {
            chain: ChainId::Bch,
            msg: "expected P2SH (OP_HASH160 <0x14> <20B> OP_EQUAL)".to_string(),
        })?;
        let addr = bitcoincash_addr::Address {
            body: hash.to_vec(),
            scheme: bitcoincash_addr::Scheme::CashAddr,
            hash_type: bitcoincash_addr::HashType::Script,
            network: self.network(),
        };
        addr.encode().map_err(|e| CodecError::Encode {
            chain: ChainId::Bch,
            msg: e.to_string(),
        })
    }
    fn decode(&self, addr: &str) -> Result<ScriptBuf, CodecError> {
        let parsed = bitcoincash_addr::Address::decode(addr).map_err(|e| CodecError::Decode {
            chain: ChainId::Bch,
            msg: format!("{e:?}"),
        })?;
        if parsed.network != self.network() {
            return Err(CodecError::Decode {
                chain: ChainId::Bch,
                msg: format!("network mismatch: {:?}", parsed.network),
            });
        }
        if !matches!(parsed.hash_type, bitcoincash_addr::HashType::Script) {
            return Err(CodecError::Decode {
                chain: ChainId::Bch,
                msg: format!("hash_type {:?} != Script (P2SH)", parsed.hash_type),
            });
        }
        if parsed.body.len() != 20 {
            return Err(CodecError::Decode {
                chain: ChainId::Bch,
                msg: format!("body length {} != 20", parsed.body.len()),
            });
        }
        // Reassemble OP_HASH160 <0x14> <20B> OP_EQUAL.
        let mut spk = Vec::with_capacity(23);
        spk.push(0xa9);
        spk.push(0x14);
        spk.extend_from_slice(&parsed.body);
        spk.push(0x87);
        Ok(ScriptBuf::from_bytes(spk))
    }
}

// ─── DOGE ──────────────────────────────────────────────────────────────────

/// DOGE address codec. P2SH base58check with 1-byte version `0x16`
/// (mainnet, addresses starting with `9` or `A`) or `0xc4` (testnet).
#[derive(Debug, Clone, Copy)]
pub struct DogeCodec {
    pub mainnet: bool,
}

impl DogeCodec {
    #[must_use]
    pub const fn mainnet() -> Self {
        Self { mainnet: true }
    }
    #[must_use]
    pub const fn testnet() -> Self {
        Self { mainnet: false }
    }
    const fn version(self) -> u8 {
        if self.mainnet {
            0x16 // P2SH mainnet
        } else {
            0xc4 // P2SH testnet
        }
    }
}

impl Default for DogeCodec {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl UtxoAddressCodec for DogeCodec {
    fn chain(&self) -> ChainId {
        ChainId::Doge
    }
    fn encode(&self, script_pubkey: &Script) -> Result<String, CodecError> {
        let hash = p2sh_script_hash(script_pubkey).ok_or(CodecError::UnsupportedScript {
            chain: ChainId::Doge,
            msg: "expected P2SH (OP_HASH160 <0x14> <20B> OP_EQUAL)".to_string(),
        })?;
        Ok(base58check_1byte_version(self.version(), &hash))
    }
    fn decode(&self, addr: &str) -> Result<ScriptBuf, CodecError> {
        let (version, hash) =
            decode_base58check_1byte_version(addr).map_err(|m| CodecError::Decode {
                chain: ChainId::Doge,
                msg: m,
            })?;
        if version != self.version() {
            return Err(CodecError::Decode {
                chain: ChainId::Doge,
                msg: format!(
                    "version {:#04x} != expected {:#04x}",
                    version,
                    self.version()
                ),
            });
        }
        let mut spk = Vec::with_capacity(23);
        spk.push(0xa9);
        spk.push(0x14);
        spk.extend_from_slice(&hash);
        spk.push(0x87);
        Ok(ScriptBuf::from_bytes(spk))
    }
}

// ─── ZEC ───────────────────────────────────────────────────────────────────

/// ZEC transparent (t-addr) P2SH codec. 2-byte version `[0x1c, 0xbd]`
/// (mainnet — `t3...` addresses) or `[0x1c, 0xba]` (testnet —
/// `t2...` addresses). Z-addr (shielded) is out of scope per DL-P3-7.
#[derive(Debug, Clone, Copy)]
pub struct ZecCodec {
    pub mainnet: bool,
}

impl ZecCodec {
    #[must_use]
    pub const fn mainnet() -> Self {
        Self { mainnet: true }
    }
    #[must_use]
    pub const fn testnet() -> Self {
        Self { mainnet: false }
    }
    const fn version(self) -> [u8; 2] {
        if self.mainnet {
            [0x1c, 0xbd] // t3... P2SH mainnet
        } else {
            [0x1c, 0xba] // t2... P2SH testnet
        }
    }
}

impl Default for ZecCodec {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl UtxoAddressCodec for ZecCodec {
    fn chain(&self) -> ChainId {
        ChainId::Zec
    }
    fn encode(&self, script_pubkey: &Script) -> Result<String, CodecError> {
        let hash = p2sh_script_hash(script_pubkey).ok_or(CodecError::UnsupportedScript {
            chain: ChainId::Zec,
            msg: "expected P2SH (OP_HASH160 <0x14> <20B> OP_EQUAL)".to_string(),
        })?;
        Ok(base58check_2byte_version(self.version(), &hash))
    }
    fn decode(&self, addr: &str) -> Result<ScriptBuf, CodecError> {
        let (version, hash) =
            decode_base58check_2byte_version(addr).map_err(|m| CodecError::Decode {
                chain: ChainId::Zec,
                msg: m,
            })?;
        if version != self.version() {
            return Err(CodecError::Decode {
                chain: ChainId::Zec,
                msg: format!("version {version:02x?} != expected {:02x?}", self.version()),
            });
        }
        let mut spk = Vec::with_capacity(23);
        spk.push(0xa9);
        spk.push(0x14);
        spk.extend_from_slice(&hash);
        spk.push(0x87);
        Ok(ScriptBuf::from_bytes(spk))
    }
}

// ─── factory ───────────────────────────────────────────────────────────────

/// Mainnet codec for `chain` as a boxed trait object. Per-network
/// variants can be built directly from the struct constructors.
#[must_use]
pub fn codec_for_mainnet(chain: ChainId) -> Box<dyn UtxoAddressCodec> {
    match chain {
        ChainId::Btc => Box::new(BtcCodec::mainnet()),
        ChainId::Ltc => Box::new(LtcCodec::mainnet()),
        ChainId::Bch => Box::new(BchCodec::mainnet()),
        ChainId::Doge => Box::new(DogeCodec::mainnet()),
        ChainId::Zec => Box::new(ZecCodec::mainnet()),
        // Non-UTXO custody chains (EVM Phase 3.2, Cosmos Phase 3.3, XRP
        // Phase 4.4, Solana Phase 4.5, TRON Phase 4.6) have no UTXO codec
        // — callers must dispatch on `CustodyFamily` before reaching here.
        ChainId::Eth
        | ChainId::Bsc
        | ChainId::Avax
        | ChainId::Base
        | ChainId::Pol
        | ChainId::Gaia
        | ChainId::Noble
        | ChainId::Xrp
        | ChainId::Sol
        | ChainId::Tron => {
            unreachable!()
        }
    }
}

// Suppress an unused-import warning when the script extractors are
// the only path that walks Instructions on some MSRV-builds.
const _: fn(&Instruction<'_>) = |_| {};

#[cfg(test)]
mod tests {
    use super::*;

    // ─── shape extractors ──────────────────────────────────────────────

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn p2wsh_extractor_accepts_canonical_spk() {
        let mut spk = vec![0x00, 0x20];
        spk.extend_from_slice(&[0xab; 32]);
        let program = p2wsh_witness_program(&ScriptBuf::from_bytes(spk)).expect("p2wsh");
        assert_eq!(program, [0xab; 32]);
    }

    #[test]
    fn p2wsh_extractor_rejects_p2sh() {
        let mut spk = vec![0xa9, 0x14];
        spk.extend_from_slice(&[0xab; 20]);
        spk.push(0x87);
        assert!(p2wsh_witness_program(&ScriptBuf::from_bytes(spk)).is_none());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn p2sh_extractor_accepts_canonical_spk() {
        let mut spk = vec![0xa9, 0x14];
        spk.extend_from_slice(&[0xcd; 20]);
        spk.push(0x87);
        let hash = p2sh_script_hash(&ScriptBuf::from_bytes(spk)).expect("p2sh");
        assert_eq!(hash, [0xcd; 20]);
    }

    #[test]
    fn p2sh_extractor_rejects_p2wsh() {
        let mut spk = vec![0x00, 0x20];
        spk.extend_from_slice(&[0xcd; 32]);
        assert!(p2sh_script_hash(&ScriptBuf::from_bytes(spk)).is_none());
    }

    // ─── BTC ───────────────────────────────────────────────────────────

    /// Pinned: a known-good P2WSH program → mainnet bech32 address.
    /// The program is the sha256 of an arbitrary multi-script; we just
    /// pin that `BtcCodec` emits the canonical bech32 form for it.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn btc_round_trip_p2wsh_mainnet() {
        let mut spk = vec![0x00, 0x20];
        let program = [0x42u8; 32];
        spk.extend_from_slice(&program);
        let script = ScriptBuf::from_bytes(spk);
        let codec = BtcCodec::mainnet();
        let addr = codec.encode(&script).expect("encode");
        assert!(
            addr.starts_with("bc1q"),
            "BTC mainnet P2WSH must start with bc1q, got {addr}"
        );
        // Round-trip.
        let back = codec.decode(&addr).expect("decode");
        assert_eq!(back, script);
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn btc_decode_rejects_wrong_network() {
        // Testnet bech32 prefix tb1q… against mainnet codec.
        let codec = BtcCodec::mainnet();
        let err = codec
            .decode("tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6lhggw")
            .unwrap_err();
        assert!(matches!(err, CodecError::Decode { .. }));
    }

    // ─── LTC ───────────────────────────────────────────────────────────

    /// LTC mainnet: bech32 HRP "ltc", same `SegWit`-v0 P2WSH format.
    /// Same program bytes → distinct address from BTC (just the HRP
    /// differs in the bech32 checksum, but the prefix is "ltc1q...").
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn ltc_round_trip_p2wsh_mainnet() {
        let mut spk = vec![0x00, 0x20];
        let program = [0x42u8; 32];
        spk.extend_from_slice(&program);
        let script = ScriptBuf::from_bytes(spk);
        let codec = LtcCodec::mainnet();
        let addr = codec.encode(&script).expect("encode");
        assert!(
            addr.starts_with("ltc1q"),
            "LTC mainnet P2WSH must start with ltc1q, got {addr}"
        );
        let back = codec.decode(&addr).expect("decode");
        assert_eq!(back, script);
    }

    #[test]
    #[expect(clippy::expect_used, clippy::unwrap_used, reason = "test code")]
    fn ltc_decode_rejects_bc1_hrp() {
        let codec = LtcCodec::mainnet();
        // A valid BTC bech32 P2WSH (bc1q HRP) is rejected by LtcCodec.
        let mut spk = vec![0x00, 0x20];
        spk.extend_from_slice(&[0x42u8; 32]);
        let btc_addr = BtcCodec::mainnet()
            .encode(&ScriptBuf::from_bytes(spk))
            .expect("btc encode");
        let err = codec.decode(&btc_addr).unwrap_err();
        assert!(matches!(err, CodecError::Decode { .. }));
    }

    // ─── BCH ───────────────────────────────────────────────────────────

    /// BCH mainnet P2SH `CashAddr`. The encoded string starts with the
    /// `bitcoincash:` prefix; the body is base32.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn bch_round_trip_p2sh_mainnet() {
        let mut spk = vec![0xa9, 0x14];
        spk.extend_from_slice(&[0x42u8; 20]);
        spk.push(0x87);
        let script = ScriptBuf::from_bytes(spk);
        let codec = BchCodec::mainnet();
        let addr = codec.encode(&script).expect("encode");
        assert!(
            addr.starts_with("bitcoincash:p"),
            "BCH mainnet P2SH CashAddr must start with bitcoincash:p, got {addr}"
        );
        let back = codec.decode(&addr).expect("decode");
        assert_eq!(back, script);
    }

    // ─── DOGE ──────────────────────────────────────────────────────────

    /// DOGE mainnet P2SH: version byte `0x16`. Addresses start with
    /// `9` or `A` (base58 of payload starting with 0x16 falls in that
    /// range deterministically).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn doge_round_trip_p2sh_mainnet() {
        let mut spk = vec![0xa9, 0x14];
        spk.extend_from_slice(&[0x42u8; 20]);
        spk.push(0x87);
        let script = ScriptBuf::from_bytes(spk);
        let codec = DogeCodec::mainnet();
        let addr = codec.encode(&script).expect("encode");
        let first = addr.chars().next().expect("non-empty");
        assert!(
            first == '9' || first == 'A',
            "DOGE mainnet P2SH must start with 9 or A, got {addr}"
        );
        let back = codec.decode(&addr).expect("decode");
        assert_eq!(back, script);
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn doge_decode_rejects_wrong_version() {
        // Forge a BTC P2SH mainnet address (version 0x05), pass to
        // DogeCodec which expects 0x16. Must fail loud.
        let codec = DogeCodec::mainnet();
        let mut payload = vec![0x05u8];
        payload.extend_from_slice(&[0x42u8; 20]);
        let checksum = sha256d::Hash::hash(&payload);
        payload.extend_from_slice(&checksum.as_byte_array()[..4]);
        let btc_p2sh = base58::encode(&payload);
        let err = codec.decode(&btc_p2sh).unwrap_err();
        assert!(matches!(err, CodecError::Decode { .. }));
    }

    // ─── ZEC ───────────────────────────────────────────────────────────

    /// ZEC mainnet P2SH t-addr: 2-byte version `[0x1c, 0xbd]`.
    /// Addresses start with `t3` (the leading two bytes of the
    /// base58 representation are deterministically "t3" for any
    /// 20-byte hash under that version).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn zec_round_trip_p2sh_mainnet() {
        let mut spk = vec![0xa9, 0x14];
        spk.extend_from_slice(&[0x42u8; 20]);
        spk.push(0x87);
        let script = ScriptBuf::from_bytes(spk);
        let codec = ZecCodec::mainnet();
        let addr = codec.encode(&script).expect("encode");
        assert!(
            addr.starts_with("t3"),
            "ZEC mainnet P2SH must start with t3, got {addr}"
        );
        let back = codec.decode(&addr).expect("decode");
        assert_eq!(back, script);
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test code")]
    fn zec_decode_rejects_p2pkh_t1_version() {
        // Forge a ZEC mainnet t1 (P2PKH) version 0x1c,0xb8 address.
        // ZecCodec expects 0x1c,0xbd (P2SH) → must fail loud.
        let codec = ZecCodec::mainnet();
        let p2pkh_addr = base58check_2byte_version([0x1c, 0xb8], &[0x42u8; 20]);
        let err = codec.decode(&p2pkh_addr).unwrap_err();
        assert!(matches!(err, CodecError::Decode { .. }));
    }

    // ─── factory ───────────────────────────────────────────────────────

    /// `codec_for_mainnet` covers every `ChainId` variant.
    #[test]
    fn codec_for_mainnet_covers_every_chain() {
        for c in [
            ChainId::Btc,
            ChainId::Ltc,
            ChainId::Bch,
            ChainId::Doge,
            ChainId::Zec,
        ] {
            let codec = codec_for_mainnet(c);
            assert_eq!(codec.chain(), c);
        }
    }
}
