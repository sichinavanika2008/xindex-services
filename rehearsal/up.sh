#!/usr/bin/env bash
# Launch the 5-operator xindex-signer-daemon fleet for the one-box testnet
# rehearsal (docs/runbooks/testnet-rehearsal-localhost.md).
#
# DEV / TESTNET ONLY: software keys (XINDEX_ALLOW_SOFTWARE_KEYS=1), plain-HTTP
# loopback, one machine. This is the FUNCTIONAL rehearsal — NOT the CTD-1
# closure gate (which needs HSMs + 5 distinct hosts + real signet).
#
# Usage: up.sh <attestation_oracle_address> [chain_id=31337] [network=signet]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
oracle="${1:?usage: up.sh <attestation_oracle_address> [chain_id=31337] [network=signet]}"
chain_id="${2:-31337}"
network="${3:-signet}"
out="${XINDEX_REHEARSAL_DIR:-/tmp/xindex-rehearsal}"
pidfile="$out/daemons.pids"

export XINDEX_ALLOW_SOFTWARE_KEYS=1

echo ">> generating 5 daemon configs in $out"
cargo run -q --manifest-path "$repo/Cargo.toml" -p xindex-signer-daemon \
  --example rehearsal_gen -- "$out" "$oracle" "$chain_id" "$network"

bin="$repo/target/debug/xindex-signer-daemon"
if [ ! -x "$bin" ]; then
  echo ">> building xindex-signer-daemon"
  cargo build -q --manifest-path "$repo/Cargo.toml" -p xindex-signer-daemon
fi

: >"$pidfile"
for i in 0 1 2 3 4; do
  log="$out/daemon-$i.log"
  "$bin" "$out/daemon-$i.json" --dev >"$log" 2>&1 &
  pid=$!
  echo "$pid" >>"$pidfile"
  echo "   operator $i: pid $pid  port $((8551 + i))  log $log"
done

sleep 2
echo ">> health"
for i in 0 1 2 3 4; do
  port=$((8551 + i))
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/api/v1/health" || echo ERR)"
  echo "   operator $i (port $port): $code"
done
echo ">> fleet up — stop with $here/down.sh"
