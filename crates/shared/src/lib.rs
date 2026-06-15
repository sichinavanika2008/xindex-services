//! `xindex-shared` — domain types shared across the off-chain stack.
//!
//! Exports the EIP-712 typed-data definitions used by the attestation
//! signers (mint / redemption / refund — three separate typehashes) and
//! the F2 redemption-dispatch correlation store shared by the executor
//! (writer) and signer (reader).

pub mod chain_registry;
pub mod eip712;
pub mod price_aggregate;
pub mod redemption_dispatch;
pub mod ric_relay;
pub mod signer_wire;
pub mod thorchain_router;
