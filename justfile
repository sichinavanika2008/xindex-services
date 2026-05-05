set shell := ["bash", "-uc"]

# ── Local Anvil chain ─────────────────────────────────────────────────────────

# Start a local Anvil node with deterministic accounts. Runs in foreground;
# use a separate terminal.
anvil:
    anvil --chain-id 31337

# ── Solidity deployment (against running Anvil) ───────────────────────────────

XINDEX := "../Xindex"
RPC := "http://127.0.0.1:8545"
WS_RPC := "ws://127.0.0.1:8545"
# Anvil's first deterministic key (account 0).
DEPLOYER_KEY := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Phase 1: deploys IndexFactory + V4SwapAdapter + IndexToken implementation.
deploy-phase1:
    cd {{XINDEX}} && forge script script/DeployPhase1.s.sol \
        --rpc-url {{RPC}} \
        --private-key {{DEPLOYER_KEY}} \
        --broadcast

# Phase 2: deploys IntentQueue + AttestationOracle + ThorchainVaultRegistry +
# ThorchainAdapter; wires everything into the Phase 1 factory. Requires
# Phase 1 to have been deployed (extracts the factory address from the
# Phase 1 broadcast JSON).
deploy-phase2:
    #!/usr/bin/env bash
    set -euo pipefail
    INDEX_FACTORY=$(jq -r '.transactions[] | select(.contractName=="IndexFactory") | .contractAddress' \
        {{XINDEX}}/broadcast/DeployPhase1.s.sol/31337/run-latest.json | head -n1)
    if [ -z "$INDEX_FACTORY" ] || [ "$INDEX_FACTORY" = "null" ]; then
        echo "ERROR: could not extract IndexFactory address from Phase 1 broadcast." >&2
        echo "Run 'just deploy-phase1' first." >&2
        exit 1
    fi
    export INDEX_FACTORY
    export INITIAL_ASGARD_VAULT=0xdEaDbeEFdeAdbeefDEAdBeefDeadBEefDEadbeEf
    export BTC_NATIVE_CUSTODY=bc1qtestmultisigaddressforanvilonly
    # SIGNERS: Anvil accounts 1, 2, 3 (avoid account 0 which is the deployer).
    export SIGNERS=0x70997970C51812dc3A010C7d01b50e0d17dc79C8,0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC,0x90F79bf6EB2c4f870365E785982E1f101E93b906
    export THRESHOLD=2
    cd {{XINDEX}} && forge script script/DeployPhase2.s.sol \
        --rpc-url {{RPC}} \
        --private-key {{DEPLOYER_KEY}} \
        --broadcast

# ── Watcher (M1 deliverable) ──────────────────────────────────────────────────

# Run xindex-watch against the deployed IntentQueue. Extracts the address
# from the Phase 2 broadcast JSON.
watch:
    #!/usr/bin/env bash
    set -euo pipefail
    INTENT_QUEUE=$(jq -r '.transactions[] | select(.contractName=="IntentQueue") | .contractAddress' \
        {{XINDEX}}/broadcast/DeployPhase2.s.sol/31337/run-latest.json | head -n1)
    if [ -z "$INTENT_QUEUE" ] || [ "$INTENT_QUEUE" = "null" ]; then
        echo "ERROR: could not extract IntentQueue address from Phase 2 broadcast." >&2
        echo "Run 'just deploy-phase2' first." >&2
        exit 1
    fi
    INTENT_QUEUE_ADDR=$INTENT_QUEUE \
    ETH_RPC_URL={{WS_RPC}} \
    cargo run -p xindex-chain-eth --bin xindex-watch

# Full M1 verification chain (you must `just anvil` in a separate terminal first).
e2e-anvil: deploy-phase1 deploy-phase2 watch

# ── Maintenance ───────────────────────────────────────────────────────────────

# Re-pull vendored ABIs from the Solidity build output.
sync-abi:
    cd {{XINDEX}} && forge build
    cp {{XINDEX}}/out/IntentQueue.sol/IntentQueue.json crates/shared/abi/
    cp {{XINDEX}}/out/IndexToken.sol/IndexToken.json crates/shared/abi/
    cp {{XINDEX}}/out/AttestationOracle.sol/AttestationOracle.json crates/shared/abi/
    cp {{XINDEX}}/out/IndexFactory.sol/IndexFactory.json crates/shared/abi/
    @echo "ABIs vendored to crates/shared/abi/"

# Strict gate: matches CI exactly. Run before every commit.
gate:
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --workspace
    cargo deny check
    cargo audit
