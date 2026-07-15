//! Type-safe Solidity bindings for the Xindex contracts the off-chain
//! services interact with on Ethereum. ABIs are vendored at
//! `crates/shared/abi/` (re-pull via `just sync-abi`).
//!
//! `alloy::sol!` reads the Forge artifact JSON directly — events, errors,
//! and function selectors are generated at compile time. Decoding any
//! `Log` against `Contract::Event::SIGNATURE_HASH` is then statically
//! checked against the on-chain ABI.

use alloy::sol;

sol!(
    #[sol(rpc)]
    IntentQueue,
    "../shared/abi/IntentQueue.json"
);

sol!(
    #[sol(rpc)]
    IndexToken,
    "../shared/abi/IndexToken.json"
);

#[expect(
    clippy::too_many_arguments,
    reason = "the audited settlement ABI deliberately binds the complete source/freshness context"
)]
mod attestation_oracle_binding {
    use alloy::sol;
    sol!(
        #[sol(rpc)]
        AttestationOracle,
        "../shared/abi/AttestationOracle.json"
    );
}
pub use attestation_oracle_binding::{AttestationOracle, IAttestationOracle};

/// Convert the shared EIP-712 plaintext into the exact Solidity ABI tuple.
/// Keeping this conversion beside the generated binding prevents posters from
/// reordering or omitting rollback/freshness fields.
#[must_use]
pub fn settlement_context_to_contract(
    context: xindex_shared::eip712::SettlementContext,
) -> IAttestationOracle::SettlementContext {
    IAttestationOracle::SettlementContext {
        evidenceHash: context.evidence_hash,
        observedAt: context.observed_at,
        validUntil: context.valid_until,
        sourceChainId: context.source_chain_id,
        sourceBlockNumber: context.source_block_number,
        sourceBlockHash: context.source_block_hash,
        observationEpoch: context.observation_epoch,
    }
}

sol!(
    #[sol(rpc)]
    IndexFactory,
    "../shared/abi/IndexFactory.json"
);

sol!(
    #[sol(rpc)]
    CustodyGuard,
    "../shared/abi/CustodyGuard.json"
);

sol!(
    #[sol(rpc)]
    PriceAttestationOracle,
    "../shared/abi/PriceAttestationOracle.json"
);

#[expect(
    clippy::too_many_arguments,
    reason = "the exact quote authorization ABI deliberately binds thirteen independent fields"
)]
mod thorchain_vault_registry_binding {
    use alloy::sol;
    sol!(
        #[sol(rpc)]
        ThorchainVaultRegistry,
        "../shared/abi/ThorchainVaultRegistry.json"
    );
}
pub use thorchain_vault_registry_binding::ThorchainVaultRegistry;

mod thorchain_adapter_binding {
    use alloy::sol;
    sol!(
        #[sol(rpc)]
        ThorchainAdapter,
        "../shared/abi/ThorchainAdapter.json"
    );
}
pub use thorchain_adapter_binding::ThorchainAdapter;
