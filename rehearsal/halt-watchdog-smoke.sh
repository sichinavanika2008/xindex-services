#!/usr/bin/env bash
# Smoke test for xindex-halt-watchdog (docs/runbooks/halt-watchdog.md).
#
# Boots the watchdog in --dry-run and confirms it wires together end-to-end:
# builds the >=2-source AsgardAgreement, connects the ETH provider, polls the
# multi-source halt signal, and logs a verdict -- WITHOUT ever submitting a
# halt() tx. By default it points at two UNREACHABLE loopback THORNode URLs, so
# the run is hermetic and exercises the FAIL-SAFE path (sub-quorum ->
# Indeterminate -> never halts). Override THORNODE_URLS with real endpoints for
# a live-liveness check (expect "Live").
#
# This is a binary smoke test, NOT a full halt drill. A full drill additionally
# needs a deployed + IntentQueue-wired CustodyGuard with the operator EOA in its
# roster, and a THORNode (or mock) that can toggle the halt flag. CustodyGuard
# has no deploy script yet (DL-CTD-E wiring is the production deploy's job) --
# documented gap (docs/runbooks/halt-watchdog.md).
#
# Prereq: an ETH JSON-RPC at ETH_RPC_URL (anvil; e.g. ./rehearsal/up-onchain.sh).
# Usage: halt-watchdog-smoke.sh [seconds=8]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
secs="${1:-8}"
out="${XINDEX_REHEARSAL_DIR:-/tmp/xindex-rehearsal}"
mkdir -p "$out"
log="$out/halt-watchdog-smoke.log"

export ETH_RPC_URL="${ETH_RPC_URL:-ws://127.0.0.1:8545}"
# Two distinct loopback URLs nothing is serving -> both transport-fail -> the
# poll returns Indeterminate (sub-quorum), the fail-safe no-halt path.
export THORNODE_URLS="${THORNODE_URLS:-http://127.0.0.1:19651,http://127.0.0.1:19652}"
# --dry-run never calls halt(), so the guard addr + key are placeholders; the
# provider still connects, so the ETH RPC must be reachable.
export CUSTODY_GUARD_ADDR="${CUSTODY_GUARD_ADDR:-0x000000000000000000000000000000000000c0de}"
export OPERATOR_KEY="${OPERATOR_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
export POLL_INTERVAL_SECS="${POLL_INTERVAL_SECS:-2}"

# ETH RPC reachability (only meaningful for the default loopback RPC).
if [ "$ETH_RPC_URL" = "ws://127.0.0.1:8545" ] && ! curl -s -o /dev/null http://127.0.0.1:8545; then
  echo "no ETH RPC at 127.0.0.1:8545 -- start anvil (e.g. ./rehearsal/up-onchain.sh) or set ETH_RPC_URL" >&2
  exit 1
fi

echo ">> building xindex-halt-watchdog"
cargo build -q --manifest-path "$repo/Cargo.toml" -p xindex-chain-eth --bin xindex-halt-watchdog

echo ">> smoke: watchdog --dry-run for ${secs}s (THORNODE_URLS=$THORNODE_URLS)"
"$repo/target/debug/xindex-halt-watchdog" --dry-run >"$log" 2>&1 &
pid=$!
sleep "$secs"
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

echo ">> watchdog log:"
sed 's/^/   /' "$log"

if grep -q "xindex-halt-watchdog starting" "$log" && grep -qi "indeterminate" "$log"; then
  echo ">> SMOKE OK: booted, polled the multi-source halt signal, took the fail-safe no-halt path (dry-run)"
else
  echo "!! SMOKE FAILED -- see $log" >&2
  exit 1
fi
