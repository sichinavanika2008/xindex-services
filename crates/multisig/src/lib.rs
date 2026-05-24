//! `xindex-multisig` — Bitcoin 3-of-5 P2WSH multisig descriptor + PSBT
//! coordination primitives.
//!
//! Used by:
//! - `xindex-executor` to construct redemption transactions when a user
//!   calls `IndexToken.burnAsync` and the adapter emits `RedeemDispatched`.
//! - The N independent signer daemons (M5) that each hold one private
//!   key in `YubiHSM2` and sign their assigned PSBT input.
//! - The deploy / key-ceremony tooling that generates the multisig
//!   descriptor from N pubkeys.
//!
//! ## Descriptor shape
//!
//! `wsh(multi(K, pk_1, pk_2, ..., pk_N))` — a Bitcoin Output Script
//! Descriptor (BIP 380) for a K-of-N P2WSH multisig. Sorted by pubkey
//! within the descriptor for deterministic address derivation
//! (`sortedmulti` would be the alternate; we use `multi` because pubkey
//! order in our key ceremony is deterministic).
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
    build_spending_psbt, finalize_psbt, sign_psbt_input, MultisigUtxo, SignError,
    MAX_OP_RETURN_BYTES,
};
