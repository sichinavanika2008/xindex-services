#!/usr/bin/env bash
# Full halt drill (docs/runbooks/halt-watchdog.md): prove the watchdog engages
# CustodyGuard.halt() on a THORChain halt, fail-closing new mint + burn.
#
#   up-onchain.sh (anvil + deploy + guard wired) -> THIS:
#     1. start 2 mock THORNodes (live)
#     2. start xindex-halt-watchdog signing as roster operator 0 (Set-B)
#     3. toggle the mocks to halted (touch the flag file)
#     4. watchdog detects the sustained halt -> broadcasts CustodyGuard.halt()
#     5. assert guard.isHalted()==true AND requireNotHalted() reverts -- the
#        exact gate IntentQueue.createMintIntent hits, so new mint (and burn via
#        checkDispatch) fail closed.
#
# DEV / TESTNET ONLY. Prereq: ./rehearsal/up-onchain.sh has run.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
out="${XINDEX_REHEARSAL_DIR:-/tmp/xindex-rehearsal}"
rpc="http://127.0.0.1:8545"
deployer="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
halt_flag="$out/thor-halt"
m1=18551
m2=18552
pids=()

cleanup() {
  if [ "${#pids[@]}" -gt 0 ]; then
    for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  fi
  rm -f "$halt_flag"
}
trap cleanup EXIT

for t in forge cast cargo python3 curl; do
  command -v "$t" >/dev/null || {
    echo "missing tool: $t" >&2
    exit 1
  }
done
[ -f "$out/onchain.env" ] || {
  echo "run ./rehearsal/up-onchain.sh first (no $out/onchain.env)" >&2
  exit 1
}
# shellcheck disable=SC1090,SC1091
. "$out/onchain.env"
: "${CUSTODY_GUARD_ADDR:?onchain.env has no CUSTODY_GUARD_ADDR (re-run up-onchain.sh)}"
guard="$CUSTODY_GUARD_ADDR"

# Roster operator 0 (Set-B): up-onchain.sh set the guard roster to these
# addresses; the ETH key lives in the generated daemon-0.json. halt() is a
# single-operator power, so one roster key suffices.
op_key="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['hsm']['software']['eth_secret_key'])" "$out/daemon-0.json")"
op_addr="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['eth_address'])" "$out/daemon-0.json")"
echo ">> roster operator 0: $op_addr (isOperator=$(cast call "$guard" 'isOperator(address)(bool)' "$op_addr" --rpc-url "$rpc"))"

# Fund the operator EOA so it can pay gas for halt() (anvil funds only its own accounts).
cast send "$op_addr" --value 1ether --private-key "$deployer" --rpc-url "$rpc" >/dev/null
echo "   funded op0 with 1 ETH for gas"

# 1. two mock THORNodes, live (no flag file).
rm -f "$halt_flag"
python3 "$here/mock-thornode.py" "$m1" "$halt_flag" &
pids+=("$!")
python3 "$here/mock-thornode.py" "$m2" "$halt_flag" &
pids+=("$!")
# wait for both mocks to bind before proceeding (python http startup race).
for port in "$m1" "$m2"; do
  for _ in $(seq 1 30); do
    curl -sf "http://127.0.0.1:$port/thorchain/inbound_addresses" >/dev/null 2>&1 && break
    sleep 0.3
  done
done
live_halted="$(curl -s "http://127.0.0.1:$m1/thorchain/inbound_addresses" | python3 -c "import json,sys; print(str(json.load(sys.stdin)[0]['halted']).lower())")"
echo ">> mocks up on :$m1,:$m2 (halted=$live_halted)"

# 2. build + start the watchdog as op0 against the 2 mocks + the deployed guard.
cargo build -q --manifest-path "$repo/Cargo.toml" -p xindex-chain-eth --bin xindex-halt-watchdog
wlog="$out/halt-drill-watchdog.log"
CUSTODY_GUARD_ADDR="$guard" OPERATOR_KEY="$op_key" \
  THORNODE_URLS="http://127.0.0.1:$m1,http://127.0.0.1:$m2" \
  ETH_RPC_URL="ws://127.0.0.1:8545" POLL_INTERVAL_SECS=2 HALT_CONFIRMATIONS=2 \
  "$repo/target/debug/xindex-halt-watchdog" >"$wlog" 2>&1 &
pids+=("$!")
sleep 6
grep -q "xindex-halt-watchdog starting" "$wlog" || {
  echo "watchdog did not start" >&2
  sed 's/^/   /' "$wlog" >&2
  exit 1
}
echo ">> watchdog up; pre-halt isHalted=$(cast call "$guard" 'isHalted()(bool)' --rpc-url "$rpc")"
cast call "$guard" 'requireNotHalted()' --rpc-url "$rpc" >/dev/null && echo "   requireNotHalted() OK (mint gate open)"

# 3. TOGGLE the halt.
echo ">> toggling THORChain HALT (touch $halt_flag)"
touch "$halt_flag"

# 4. wait for the watchdog to detect (>=2 polls) + broadcast + mine.
echo ">> waiting for the watchdog to engage CustodyGuard.halt() ..."
halted=false
for _ in $(seq 1 20); do
  if [ "$(cast call "$guard" 'isHalted()(bool)' --rpc-url "$rpc")" = "true" ]; then
    halted=true
    break
  fi
  sleep 1
done

echo ""
echo "=== RESULT ==="
echo "watchdog (tail):"
grep -E 'HALTED|halt\(\)|mined|engaging' "$wlog" | tail -4 | sed 's/^/   /'
echo "guard.isHalted() = $(cast call "$guard" 'isHalted()(bool)' --rpc-url "$rpc")"
if [ "$halted" = true ] && ! cast call "$guard" 'requireNotHalted()' --rpc-url "$rpc" >/dev/null 2>&1; then
  echo "✅ DRILL PASSED: watchdog engaged the halt; requireNotHalted() now reverts (new mint + burn fail-closed)"
else
  echo "❌ DRILL FAILED -- see $wlog"
  exit 1
fi
