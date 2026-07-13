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
pub mod policy;
pub mod source;
pub mod types;

pub use agreement::{AgreementError, AsgardAgreement, HaltOutcome, MIN_AGREEING_SOURCES};
pub use client::{RawResponse, ThorClient, ThorConsensusClient, ThorError};
pub use policy::{
    derive_inbound, evaluate_quote, evm_raw_to_thor, thor_to_evm_raw, validate_common_inbound,
    validate_common_quote, validate_independent_inbound, validate_independent_quote,
    CanonicalSourceBundle, DerivedInbound, ExternalPriceObservation, InboundCandidate,
    InboundPolicy, QuoteCandidate, QuoteDecision, QuoteEvidence, QuotePolicy, SourceResponseHashes,
    SourceSnapshot, ThorPolicyError, TipCheckpoint, PAUSE_CHAIN_HALTED, PAUSE_CHAIN_TRADING,
    PAUSE_GLOBAL_TRADING, PAUSE_SIGNING, PAUSE_STALE_CONSENSUS, PAUSE_STREAMING,
    PAUSE_TARGET_OR_POOL,
};
pub use source::{RawSourcePoll, ThorSourceClient};
pub use types::{
    ConsensusTip, InboundAddress, Mimir, OutboundEntry, OutboundTx, Pool, SwapQuoteFees,
    SwapQuoteRequest, SwapQuoteResponse, TxDetailsResponse, TxResponse, TxStatusResponse,
};
