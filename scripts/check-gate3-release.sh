#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "Gate-3 release check failed: $*" >&2
    exit 1
}

[[ $# -ge 2 ]] || fail "usage: $0 OWNER_ONLY_TOPOLOGY.json EVIDENCE_DIR [EVIDENCE_DIR ...]"

topology=$1
shift

command -v promtool >/dev/null 2>&1 \
    || fail "promtool is required to validate the production alert rules"

./scripts/check-abi.sh --solidity-root ..
./scripts/check-production-profile.sh
promtool check rules ops/prometheus/gate3-alerts.yml

RUSTUP_TOOLCHAIN=1.95.0-aarch64-apple-darwin \
    cargo run --offline --locked -p xindex-ops \
    --bin xindex-topology-check -- "$topology"

for evidence_dir in "$@"; do
    RUSTUP_TOOLCHAIN=1.95.0-aarch64-apple-darwin \
        cargo run --offline --locked -p xindex-shared \
        --bin xindex-evidence-check -- "$evidence_dir"
done

echo "Gate-3 static, topology, alert-rule, and evidence checks: OK"
