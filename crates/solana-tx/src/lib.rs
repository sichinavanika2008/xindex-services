//! Solana hand-rolled transaction + Squads V4 instruction codec (Phase
//! 4.5).
//!
//! Pure-logic primitives for the Solana custody family (SOL / SOL.SOL).
//! This crate is the Solana analogue of `cosmos-tx` / `xrp-tx`: every
//! byte-exact, deterministic, **network-free** primitive needed to build,
//! sign, and assemble the transactions a Squads V4 redemption broadcasts:
//!
//! 1. [`base58`] — base58 (Bitcoin alphabet) codec for the 32/64-byte
//!    quantities (pubkeys, blockhashes, signatures).
//! 2. [`shortvec`] — Solana compact-u16 length prefix.
//! 3. [`message`] — legacy message compilation + serialization +
//!    transaction wrapping (mirrors `@solana/web3.js` so the bytes
//!    byte-match the Squads JS SDK).
//! 4. [`pda`] — `create_program_address` / `find_program_address` (the
//!    ed25519 on-curve check).
//! 5. [`sigs`] — ed25519 sign / strict-verify.
//! 6. [`squads`] — the Squads V4 instruction + PDA encoders.
//!
//! No `solana-sdk`/`anchor` dependency — the byte surface we need (a
//! handful of System / Memo / `ComputeBudget` / Squads instructions) is
//! narrow and hand-encoded, the same rationale as `cosmos-tx` and
//! `xrp-tx`. Signing is **ed25519**, not secp256k1 — the first such family.
//!
//! ## Mainnet gate
//!
//! The Squads instruction layouts have no thornode reference (`THORChain`'s
//! Solana client is single-sign / TSS) and are gated on a Squads-JS-SDK
//! byte-match before mainnet (`KNOWN_FINDINGS` P-SOL-1).

pub mod base58;
pub mod message;
pub mod pda;
pub mod shortvec;
pub mod sigs;
pub mod squads;

use std::fmt;

/// A 32-byte Solana public key. Also used for account addresses, program
/// ids, and program-derived addresses — every 32-byte base58 quantity at
/// the wire. Ordering is lexicographic over the raw bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pubkey([u8; 32]);

impl Pubkey {
    /// Wrap 32 raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Decode a base58 public key. Rejects anything that is not exactly
    /// 32 bytes.
    ///
    /// # Errors
    /// Returns [`SolanaTxError::Base58`] on invalid base58 and
    /// [`SolanaTxError::BadLength`] if the decoded length is not 32.
    pub fn from_base58(s: &str) -> Result<Self, SolanaTxError> {
        Ok(Self(base58::decode_32(s)?))
    }

    /// The raw 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The raw 32 bytes by value.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Base58 string form.
    #[must_use]
    pub fn to_base58(self) -> String {
        base58::encode(&self.0)
    }

    /// The System Program id (32 zero bytes).
    #[must_use]
    pub const fn system_program() -> Self {
        Self([0u8; 32])
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pubkey({})", self.to_base58())
    }
}

/// Errors building or encoding a Solana transaction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SolanaTxError {
    /// Base58 decoding failed.
    #[error("base58 decode: {0}")]
    Base58(String),
    /// A decoded byte string had the wrong fixed length.
    #[error("expected {expected} bytes, got {got}")]
    BadLength {
        /// The required length.
        expected: usize,
        /// The actual decoded length.
        got: usize,
    },
    /// The compiled message has more than 255 accounts (an account index
    /// must fit a `u8`).
    #[error("too many accounts in message: {0} (max 255)")]
    TooManyAccounts(usize),
    /// A length prefix exceeds the compact-u16 maximum (`u16::MAX`).
    #[error("compact-u16 length {0} exceeds u16::MAX")]
    ShortVecOverflow(usize),
    /// An instruction referenced an account absent from the compiled key
    /// set (a programming error — `new_legacy` adds every account).
    #[error("instruction references account {0} absent from the message")]
    MissingAccount(String),
    /// No bump in `255..=0` produced an off-curve program-derived address.
    #[error("no off-curve program-derived address found for the given seeds")]
    PdaNotFound,
    /// ed25519 key parse / signature verification failure.
    #[error("ed25519: {0}")]
    Ed25519(String),
}
