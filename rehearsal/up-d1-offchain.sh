#!/usr/bin/env bash
# A's last step: drive the RedeemDispatched (from up-d1.sh) through the
# per-operator OBSERVERS + the COORDINATOR to COLLECT the 3-of-5 Redemption
# Intent Certificate. Launches the mock THORNode + 3 observers, then runs
# xindex-redeem, which collects the RIC and then stops at the PSBT UTXO fetch
# (no Bitcoin backend here — the documented wall in
# docs/runbooks/testnet-rehearsal-localhost.md).
#
# Prereq: ./rehearsal/up-onchain.sh (fleet up) AND ./rehearsal/up-d1.sh (burn
# done) have run. DEV / TESTNET ONLY.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
out="${XINDEX_REHEARSAL_DIR:-/tmp/xindex-rehearsal}"
rpc="ws://127.0.0.1:8545"
# A valid testnet/signet (BIP173) bech32 — the mock Asgard inbound the
# observers resolve + the coordinator pays to.
asgard="tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"

[ -f "$out/onchain.env" ] || {
  echo "run ./rehearsal/up-onchain.sh + ./rehearsal/up-d1.sh first (no $out/onchain.env)"
  exit 1
}
# shellcheck disable=SC1090,SC1091
. "$out/onchain.env"
export XINDEX_ALLOW_SOFTWARE_KEYS=1

signers="$(cargo run -q --manifest-path "$repo/Cargo.toml" \
  -p xindex-signer-daemon --example rehearsal_gen -- --signers-only)"
IFS=',' read -r s0 s1 s2 _rest <<<"$signers"
pubkeys="$(python3 -c "import json;print(','.join(json.load(open('$out/daemon-0.json'))['utxo']['pubkeys']))")"

obs="$repo/target/debug/xindex-observe-redeem"
red="$repo/target/debug/xindex-redeem"
mock="$repo/target/debug/examples/mock_thornode"
for b in "$obs" "$red" "$mock"; do
  [ -x "$b" ] || {
    echo "missing binary $b — build with: cargo build -p xindex-chain-eth --bin xindex-observe-redeem -p xindex-executor --bin xindex-redeem --example mock_thornode"
    exit 1
  }
done

pids=""
cleanup() {
  for p in $pids; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

# 1. mock THORNode on 2 ports.
"$mock" "$asgard" 26659 26660 26661 >"$out/mock-thornode.log" 2>&1 &
pids="$pids $!"
sleep 1

# 2. three observers (9101-9103 → daemons 8551-8553), --from-block 1 backfills
#    the burn's RedeemDispatched.
i=0
for trip in "9101 8551 $s0" "9102 8552 $s1" "9103 8553 $s2"; do
  # shellcheck disable=SC2086
  set -- $trip
  RUST_LOG=info "$obs" \
    --rpc-url "$rpc" --thorchain-adapter "$THORCHAIN_ADAPTER_ADDR" \
    --attestation-oracle "$ATTESTATION_ORACLE_ADDR" \
    --thornode-urls http://127.0.0.1:26659,http://127.0.0.1:26660,http://127.0.0.1:26661 \
    --chain btc --btc-network signet --signer-mode remote \
    --signer-daemon-url "http://127.0.0.1:$2" --signer-daemon-address "$3" \
    --from-block 1 --listen-addr "127.0.0.1:$1" >"$out/observer-$i.log" 2>&1 &
  pids="$pids $!"
  i=$((i + 1))
done
sleep 3
echo ">> observer health"
for port in 9101 9102 9103; do
  echo "   $port: $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/api/v1/health" || echo ERR)"
done

# 3. coordinator — collects the 3-of-5 RIC, then stops at the Esplora UTXO
#    fetch (dummy esplora url ⇒ the documented BTC wall).
echo ">> running coordinator (collects RIC, then the BTC/Esplora wall)"
daemons="http://127.0.0.1:8551,http://127.0.0.1:8552,http://127.0.0.1:8553,http://127.0.0.1:8554,http://127.0.0.1:8555"
RUST_LOG=info "$red" \
  --rpc-url "$rpc" --thorchain-adapter "$THORCHAIN_ADAPTER_ADDR" \
  --thornode-url http://127.0.0.1:26659 --esplora-url http://127.0.0.1:39999 \
  --btc-network signet --chain btc \
  --multisig-pubkeys "$pubkeys" --multisig-threshold 3 --signer-mode remote \
  --cosigner-daemon-urls "$daemons" --cosigner-pubkeys "$pubkeys" \
  --observer-urls http://127.0.0.1:9101,http://127.0.0.1:9102,http://127.0.0.1:9103 \
  --intent-quorum 3 --from-block 1 >"$out/coordinator.log" 2>&1 &
coord=$!
pids="$pids $coord"
sleep 15
kill "$coord" 2>/dev/null || true

echo "=== coordinator: RIC collection + the wall ==="
grep -iE "RIC collector enabled|executing reverse|RIC collection failed|BTC.Asgard broadcast|utxo|esplora|fetch|connection|error" \
  "$out/coordinator.log" | head -25 || true
echo "=== observer-0: certify path ==="
grep -iE "certif|ric|asgard|resolved|sign|error|warn" "$out/observer-0.log" | head -15 || true
