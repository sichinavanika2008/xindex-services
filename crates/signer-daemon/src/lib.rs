//! `xindex-signer-daemon` — production k-of-n signing daemon (PART 5).
//!
//! Each of the 5 signer parties runs one instance per key role
//! (mint-/redemption-/refund-attestation on the Ethereum side; PSBT-
//! input partial sigs on the Bitcoin side). The daemon:
//!
//! 1. Authenticates the coordinator (mTLS + per-daemon coordinator-cert
//!    pin allowlist — DL-M5-5).
//! 2. Parses the request into exactly one of four typed shapes from
//!    [`xindex_shared::signer_wire`] (type-level separation — DL-M5-3).
//! 3. Consults its **local replay/slashing DB** (this module —
//!    DL-M5-4): identical-payload retry returns the cached signature
//!    idempotently; same-tuple-different-payload is a 409 Conflict and
//!    NEVER reaches the HSM. Defense in depth on top of the on-chain
//!    `SlotAlreadyAttested` / delivery-XOR-refund guards.
//! 4. Computes the EIP-712 digest (or PSBT input sighash) itself — it
//!    never trusts a coordinator-supplied digest. Typehash constants
//!    are pinned at compile time against
//!    [`xindex_shared::eip712`].
//! 5. Asks its locally-fronting `Web3Signer` instance (which fronts the
//!    physical `YubiHSM2` — DL-M5-2) to sign the digest raw.
//! 6. Records the signature in the replay DB **before** returning, so
//!    the next replay query sees it.
//!
//! Coordinators hold ZERO key material; their failure mode is "lose a
//! coordinator host" not "leak a signing key" (DL-M5-1).

pub mod cosmos_tx;
pub mod evm_safe;
pub mod intent;
pub mod price_sign;
pub mod price_venue;
pub mod psbt;
pub mod replay;
pub mod server;
mod sig_norm;
pub mod solana_tx;
pub mod tron_tx;
pub mod web3signer;
pub mod xrp_tx;

#[cfg(test)]
mod test_support;
