//! `xindex-multisig` — 3-of-5 UTXO multisig descriptor + PSBT
//! coordination primitives for the Phase 3.1 UTXO custody family.
//!
//! Used by:
//! - `xindex-executor` to construct redemption transactions when a user
//!   burns shares and the adapter emits `RedeemDispatched`.
//! - The N independent signer daemons (M5) that each hold one private
//!   key in `YubiHSM2` and sign their assigned PSBT input.
//! - The deploy / key-ceremony tooling that generates the multisig
//!   descriptor from N pubkeys.
//!
//! ## Descriptor shapes
//!
//! - `wsh(multi(K, pk_1, ..., pk_N))` — P2WSH for `SegWit` chains
//!   (BTC, LTC). BIP-143 sighash.
//! - `sh(multi(K, pk_1, ..., pk_N))` — P2SH-legacy for chains without
//!   `SegWit` (BCH, DOGE, ZEC). Legacy sighash (pre-BIP-143).
//!
//! Both built via [`MultisigDescriptor::new_p2wsh`] /
//! [`MultisigDescriptor::new_p2sh_legacy`]. The descriptor uses `multi`
//! (vs `sortedmulti`) because pubkey order in our key ceremony is
//! deterministic.
//!
//! ## PSBT lifecycle
//!
//! 1. Executor builds an unsigned PSBT spending one of our multisig UTXOs
//!    to the user's native-chain address (output amount + recipient
//!    derived from the on-chain `RedeemDispatched` event).
//! 2. Executor distributes the PSBT to the N signer daemons.
//! 3. Each signer daemon validates the PSBT against the policy
//!    (right destination, right amount, right input) and either signs or
//!    refuses.
//! 4. Executor aggregates ≥ K partial signatures → finalizes the PSBT.
//! 5. Executor extracts the finalized transaction and broadcasts it via
//!    `xindex-chain-btc::broadcast`.

pub mod descriptor;
pub mod psbt;

pub use descriptor::{MultisigDescriptor, MultisigError};
pub use psbt::{
    build_spending_psbt, finalize_psbt, sign_psbt_input, MultisigUtxo, MultisigUtxoSpend,
    SignError, MAX_OP_RETURN_BYTES,
};
