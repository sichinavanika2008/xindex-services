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
# Anvil's deterministic accounts.
DEPLOYER_KEY := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
# Signer keys (Anvil accounts 1, 2, 3) — match the SIGNERS env in deploy-phase2.
SIGNER_KEY_1 := "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
SIGNER_KEY_2 := "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
SIGNER_KEY_3 := "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"

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

# ── M2: signer + attest pipeline ──────────────────────────────────────────────

# After Phase 1+2 are deployed, build the test fixture: deploy MockERC20 USDT,
# deploy MockAsyncAdapter, allowlist, create an async basket, mintAsync.
# Captures the resulting intentId in /tmp/xindex-m2-intent.txt.
m2-fixture:
    #!/usr/bin/env bash
    set -euo pipefail
    INDEX_FACTORY=$(jq -r '.transactions[] | select(.contractName=="IndexFactory") | .contractAddress' \
        {{XINDEX}}/broadcast/DeployPhase1.s.sol/31337/run-latest.json | head -n1)
    if [ -z "$INDEX_FACTORY" ] || [ "$INDEX_FACTORY" = "null" ]; then
        echo "ERROR: Phase 1 not deployed; run 'just deploy-phase1' first." >&2
        exit 1
    fi
    export INDEX_FACTORY
    export DEPLOYER_KEY={{DEPLOYER_KEY}}
    cd {{XINDEX}} && forge script script/AnvilM2Fixture.s.sol \
        --rpc-url {{RPC}} \
        --private-key {{DEPLOYER_KEY}} \
        --broadcast \
        2>&1 | tee /tmp/xindex-m2-fixture.log
    # The script logs the intentId via `console.logBytes32`; grep it out.
    grep -oE '0x[0-9a-fA-F]{64}' /tmp/xindex-m2-fixture.log \
        | tail -n1 > /tmp/xindex-m2-intent.txt
    echo "intentId saved to /tmp/xindex-m2-intent.txt"

# Run xindex-attest. Holds 3 signer keys; threshold=2 matches deploy-phase2.
# Posts attestations for every observed MintIntentCreated event.
attest:
    #!/usr/bin/env bash
    set -euo pipefail
    INTENT_QUEUE=$(jq -r '.transactions[] | select(.contractName=="IntentQueue") | .contractAddress' \
        {{XINDEX}}/broadcast/DeployPhase2.s.sol/31337/run-latest.json | head -n1)
    ORACLE=$(jq -r '.transactions[] | select(.contractName=="AttestationOracle") | .contractAddress' \
        {{XINDEX}}/broadcast/DeployPhase2.s.sol/31337/run-latest.json | head -n1)
    INTENT_QUEUE_ADDR=$INTENT_QUEUE \
    ATTESTATION_ORACLE_ADDR=$ORACLE \
    SIGNER_KEYS={{SIGNER_KEY_1}},{{SIGNER_KEY_2}},{{SIGNER_KEY_3}} \
    THRESHOLD=2 \
    POSTER_KEY={{DEPLOYER_KEY}} \
    ETH_RPC_URL={{WS_RPC}} \
    cargo run -p xindex-chain-eth --bin xindex-attest

# Verify: read IntentQueue.getIntent(intentId).state and assert FINALIZED (== 2).
# Run AFTER the attest binary has had time to post all slot attestations
# AND someone has called finalizeMint on the IndexToken.
verify:
    #!/usr/bin/env bash
    set -euo pipefail
    INTENT_QUEUE=$(jq -r '.transactions[] | select(.contractName=="IntentQueue") | .contractAddress' \
        {{XINDEX}}/broadcast/DeployPhase2.s.sol/31337/run-latest.json | head -n1)
    INTENT_ID=$(cat /tmp/xindex-m2-intent.txt)
    echo "querying IntentQueue at $INTENT_QUEUE for intent $INTENT_ID"
    STATE=$(cast call $INTENT_QUEUE \
        "getIntent(bytes32)((uint8,address,address,address,uint256,uint64,uint64,(bytes32,uint256,uint256,bool)[]))" \
        $INTENT_ID --rpc-url {{RPC}})
    echo "intent state tuple: $STATE"
    # The tuple's first field is `IntentState` enum: 0=NONE, 1=PENDING, 2=FINALIZED, 3=CANCELLED.
    if echo "$STATE" | grep -q "^(2,"; then
        echo "✓ FINALIZED"
    else
        echo "✗ expected state=2 (FINALIZED); got $STATE" >&2
        exit 1
    fi

# Trigger finalizeMint on the IndexToken once all slots are attested.
# The originator/poster key (DEPLOYER_KEY) calls; minSharesOut=0 for testing.
finalize-m2:
    #!/usr/bin/env bash
    set -euo pipefail
    INTENT_ID=$(cat /tmp/xindex-m2-intent.txt)
    INDEX_TOKEN=$(grep -oE 'IndexToken:\s+0x[0-9a-fA-F]{40}' /tmp/xindex-m2-fixture.log \
        | grep -oE '0x[0-9a-fA-F]{40}' | head -n1)
    cast send $INDEX_TOKEN "finalizeMint(bytes32,uint256)" $INTENT_ID 0 \
        --rpc-url {{RPC}} --private-key {{DEPLOYER_KEY}}

# ── Maintenance ───────────────────────────────────────────────────────────────

# Re-pull vendored ABIs from the Solidity build output.
#
# Most contracts are vendored as full Foundry artifacts (abi + bytecode).
# `IndexToken` is the exception: post-P3-1 (EIP-170 refactor) it delegatecalls
# the external `AsyncMintLib`, so its artifact contains unlinked bytecode
# with a `__$..$__` placeholder which alloy's `sol!` macro refuses to parse.
# The off-chain stack never deploys IndexToken (no `::deploy` use), so we
# vendor only the `.abi` array for that one contract.
sync-abi:
    cd {{XINDEX}} && forge build
    cp {{XINDEX}}/out/IntentQueue.sol/IntentQueue.json crates/shared/abi/
    python3 -c 'import json,sys; json.dump(json.load(open(sys.argv[1]))["abi"], open(sys.argv[2],"w"))' \
        {{XINDEX}}/out/IndexToken.sol/IndexToken.json crates/shared/abi/IndexToken.json
    cp {{XINDEX}}/out/AttestationOracle.sol/AttestationOracle.json crates/shared/abi/
    cp {{XINDEX}}/out/IndexFactory.sol/IndexFactory.json crates/shared/abi/
    cp {{XINDEX}}/out/ThorchainAdapter.sol/ThorchainAdapter.json crates/shared/abi/
    cp {{XINDEX}}/out/CustodyGuard.sol/CustodyGuard.json crates/shared/abi/
    @echo "ABIs vendored to crates/shared/abi/"

# Strict gate: matches CI exactly. Run before every commit.
#
# `--ignore RUSTSEC-2023-0071`: rsa 0.9.x Marvin timing-sidechannel.
# rsa is pulled by sqlx-mysql which sqlx 0.8 lists as an optional
# transitive in its lockfile entry even with `default-features = false`
# + sqlite-only features. We do not compile mysql; the vulnerable code
# is not reachable. No upstream fix available. Documented in deny.toml.
gate:
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --workspace
    cargo deny check
    cargo audit --ignore RUSTSEC-2023-0071
