#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/crates/shared/abi/manifest.json"
solidity_root=""

if [[ "${1:-}" == "--solidity-root" ]]; then
    if [[ $# -ne 2 ]]; then
        echo "usage: $0 [--solidity-root PATH]" >&2
        exit 2
    fi
    solidity_root="$(cd "$2" && pwd)"
elif [[ $# -ne 0 ]]; then
    echo "usage: $0 [--solidity-root PATH]" >&2
    exit 2
fi

contracts=(
    AttestationOracle
    CustodyGuard
    IndexFactory
    IndexToken
    IntentQueue
    MultiRailAsyncAdapter
    NativeRouteRegistry
    PriceAttestationOracle
    ThorchainAdapter
    ThorchainVaultRegistry
)

canonical_hash() {
    jq -cS 'if type == "array" then . else .abi end' "$1" \
        | shasum -a 256 \
        | awk '{print $1}'
}

for contract in "${contracts[@]}"; do
    expected="$(jq -er --arg contract "$contract" '.contracts[$contract]' "$manifest")"
    vendored="$repo_root/crates/shared/abi/$contract.json"
    actual="$(canonical_hash "$vendored")"
    if [[ "$actual" != "$expected" ]]; then
        echo "ABI manifest mismatch for $contract: expected $expected, vendored $actual" >&2
        exit 1
    fi

    if [[ -n "$solidity_root" ]]; then
        artifact="$solidity_root/out/$contract.sol/$contract.json"
        if [[ ! -f "$artifact" ]]; then
            echo "missing Solidity artifact for $contract: $artifact" >&2
            exit 1
        fi
        source_hash="$(canonical_hash "$artifact")"
        if [[ "$source_hash" != "$expected" ]]; then
            echo "Solidity ABI drift for $contract: expected $expected, artifact $source_hash" >&2
            exit 1
        fi
    fi
done

echo "ABI manifest verified for ${#contracts[@]} contracts"
