//! Type-safe Solidity bindings for the four Xindex contracts the off-chain
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
