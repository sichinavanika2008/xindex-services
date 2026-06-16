//! `xindex-chain-thor` — minimal `THORNode` REST client.
//!
//! Used by:
//! - The off-chain attestation signer to verify, before signing, that
//!   `THORChain`'s Bifrost validators have observed the inbound deposit
//!   AND broadcast the corresponding outbound to our native multisig.
//! - The vault-update bot to refresh `ThorchainVaultRegistry` whenever
//!   `THORChain` churns to a new Asgard vault.
//! - Future relayer logic that retries Router calls when `THORChain`
//!   reports a partner-side failure.
//!
//! Endpoints implemented (`THORNode` REST, mainnet defaults to
//! `thornode.thorchain.network`; stagenet defaults to
//! `stagenet-thornode.ninerealms.com`):
//!
//! | Endpoint | Purpose |
//! |---|---|
//! | `GET /thorchain/inbound_addresses` | Per-chain Asgard vault + halt flags |
//! | `GET /thorchain/tx/{hash}` | Inbound observation status |
//! | `GET /thorchain/queue/outbound` | Pending outbound queue |
//! | `GET /thorchain/pools` | Pool depth (for slip estimates) |
//!
//! Field shapes pinned against `~/refs/thornode/openapi/openapi.yaml`. The
//! types here cover the subset we need; `THORChain`'s full response surface
//! is much larger.

pub mod agreement;
pub mod client;
pub mod types;

pub use agreement::{AgreementError, AsgardAgreement, HaltOutcome, MIN_AGREEING_SOURCES};
pub use client::{ThorClient, ThorError};
pub use types::{InboundAddress, OutboundEntry, Pool, TxResponse};
