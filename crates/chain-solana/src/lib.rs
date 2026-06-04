//! Solana chain client (Phase 4.5 S4).
//!
//! The Solana analogue of `chain-xrp` / `chain-cosmos`: the
//! [`SolanaChainClient`] trait the executor (S5) and the inbound observer
//! program against, plus a production [`ReqwestSolanaChainClient`] over the
//! Solana JSON-RPC and the pure parsers it delegates to. Parsing is split
//! into network-free functions so it is unit-testable without a node, and
//! the on-chain Squads `Multisig` / `Proposal` account decoders are pinned
//! to the program's Borsh layout.

pub mod client;

pub use client::{
    parse_balance, parse_blockhash, parse_get_transaction, parse_multisig_account,
    parse_proposal_state, parse_send_transaction, parse_signature_status,
    parse_signatures_for_address, MultisigAccount, ProposalState, ReqwestSolanaChainClient,
    SignatureRef, SignatureStatus, SolanaChainClient, SolanaChainError, SolanaTransfer,
};
