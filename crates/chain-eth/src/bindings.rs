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

sol!(
    #[sol(rpc)]
    AttestationOracle,
    "../shared/abi/AttestationOracle.json"
);

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

#[expect(
    clippy::too_many_arguments,
    reason = "ThorchainAdapter constructor has 8 args; the sol! macro expansion exposes them"
)]
mod thorchain_adapter_binding {
    use alloy::sol;
    sol!(
        #[sol(rpc)]
        ThorchainAdapter,
        "../shared/abi/ThorchainAdapter.json"
    );
}
pub use thorchain_adapter_binding::ThorchainAdapter;
