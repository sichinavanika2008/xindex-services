#!/usr/bin/env bash
# Wire the ON-CHAIN leg of the one-box rehearsal: start anvil, deploy Phase 1 +
# Phase 2 with the AttestationOracle signer set = the 5 rehearsal daemons, then
# launch the daemon fleet against the REAL deployed oracle.
#
# DEV / TESTNET ONLY (anvil, software keys, plain-HTTP). This reaches the
# integration milestone "the daemon fleet runs against a real on-chain oracle
# whose signer set is the daemons' own Set-B keys". The full burn-driven D1
# (mint→attest→burn→certify→sign→broadcast) has remaining gaps documented in
# docs/runbooks/testnet-rehearsal-localhost.md (mock THORNode, mint/attest, BTC
# node) — this script does NOT claim to run them.
#
# Usage: up-onchain.sh   (uses anvil + the ../Xindex deploy scripts)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
xindex="${XINDEX_SOLIDITY_DIR:-$repo/../Xindex}"
rpc="http://127.0.0.1:8545"
deployer="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
out="${XINDEX_REHEARSAL_DIR:-/tmp/xindex-rehearsal}"
mkdir -p "$out"

for t in anvil forge cast cargo; do
  command -v "$t" >/dev/null || {
    echo "missing required tool: $t"
    exit 1
  }
done
[ -d "$xindex" ] || {
  echo "Solidity repo not found at $xindex (set XINDEX_SOLIDITY_DIR)"
  exit 1
}

export XINDEX_ALLOW_SOFTWARE_KEYS=1

# 1. anvil — start if nothing is listening on the RPC yet.
if ! cast block-number --rpc-url "$rpc" >/dev/null 2>&1; then
  echo ">> starting anvil (chain 31337)"
  anvil --chain-id 31337 >"$out/anvil.log" 2>&1 &
  echo "$!" >"$out/anvil.pid"
  for _ in $(seq 1 20); do
    cast block-number --rpc-url "$rpc" >/dev/null 2>&1 && break
    sleep 0.5
  done
fi

# 2. mock funding + underlying tokens. Anvil has no real WETH/USDC/USDT, and the
# factory's funding/underlying allowlist requires a token WITH code
# (IndexFactory.sol:342). MockERC20(name, symbol, decimals).
echo ">> deploying mock tokens (WETH/USDC/USDT)"
deploy_mock() {
  (cd "$xindex" && forge create test/mocks/MockERC20.sol:MockERC20 \
    --rpc-url "$rpc" --private-key "$deployer" --broadcast \
    --constructor-args "$1" "$2" "$3" 2>&1) | grep 'Deployed to:' | awk '{print $NF}'
}
weth="$(deploy_mock 'Wrapped Ether' WETH 18)" || true
usdc="$(deploy_mock 'USD Coin' USDC 6)" || true
usdt="$(deploy_mock 'Tether USD' USDT 6)" || true
{ [ -n "$weth" ] && [ -n "$usdc" ] && [ -n "$usdt" ]; } || {
  echo "mock token deploy failed (weth=$weth usdc=$usdc usdt=$usdt)"
  exit 1
}
echo "   WETH=$weth USDC=$usdc USDT=$usdt"

# 2b. mock THORChain router. The BTC mint `acquire` calls
# `router.depositWithExpiry`; the mainnet placeholder is code-less on anvil
# and would revert. MockThorchainRouter records deposits instead.
router="$(cd "$xindex" && forge create test/mocks/MockThorchainRouter.sol:MockThorchainRouter \
  --rpc-url "$rpc" --private-key "$deployer" --broadcast 2>&1 |
  grep 'Deployed to:' | awk '{print $NF}')" || true
[ -n "$router" ] || {
  echo "mock THORChain router deploy failed"
  exit 1
}
echo "   MockThorchainRouter=$router"

# 3. the 5 deterministic Set-B addresses (oracle-independent).
signers="$(cargo run -q --manifest-path "$repo/Cargo.toml" \
  -p xindex-signer-daemon --example rehearsal_gen -- --signers-only)"
echo ">> rehearsal Set-B signer set: $signers"

# 3. deploy phase 1.
echo ">> deploy phase 1"
p1="$(cd "$xindex" && WETH="$weth" USDC="$usdc" USDT="$usdt" \
  forge script script/DeployPhase1.s.sol \
  --rpc-url "$rpc" --private-key "$deployer" --broadcast 2>&1)" || {
  echo "$p1"
  exit 1
}
factory="$(echo "$p1" | grep 'IndexFactory:' | awk '{print $NF}' | tail -n1)" || true
[ -n "$factory" ] || {
  echo "could not extract IndexFactory address"
  echo "$p1" | tail -n 20
  exit 1
}
echo "   IndexFactory: $factory"

# 4. deploy phase 2 — AttestationOracle signer set = the rehearsal daemons.
echo ">> deploy phase 2 (oracle signers = rehearsal Set-B, threshold 3)"
p2="$(cd "$xindex" &&
  INDEX_FACTORY="$factory" \
    INITIAL_ASGARD_VAULT="0xdEaDbeEFdeAdbeefDEAdBeefDeadBEefDEadbeEf" \
    BTC_NATIVE_CUSTODY="bc1qtestmultisigaddressforanvilonly" \
    THORCHAIN_ROUTER="$router" \
    SIGNERS="$signers" THRESHOLD="3" \
    forge script script/DeployPhase2.s.sol \
    --rpc-url "$rpc" --private-key "$deployer" --broadcast 2>&1)" || {
  echo "$p2"
  exit 1
}
oracle="$(echo "$p2" | grep 'AttestationOracle:' | awk '{print $NF}' | tail -n1)" || true
adapter="$(echo "$p2" | grep 'ThorchainAdapter' | awk '{print $NF}' | tail -n1)" || true
queue="$(echo "$p2" | grep 'IntentQueue:' | awk '{print $NF}' | tail -n1)" || true
[ -n "$oracle" ] || {
  echo "could not extract AttestationOracle address"
  echo "$p2" | tail -n 30
  exit 1
}
echo "   AttestationOracle: $oracle"
echo "   ThorchainAdapter:  $adapter"
echo "   IntentQueue:       $queue"

# 5. record the deployed addresses for the observer / coordinator steps.
cat >"$out/onchain.env" <<EOF
ATTESTATION_ORACLE_ADDR=$oracle
THORCHAIN_ADAPTER_ADDR=$adapter
INTENT_QUEUE_ADDR=$queue
INDEX_FACTORY_ADDR=$factory
USDT_ADDR=$usdt
THORCHAIN_ROUTER_ADDR=$router
ETH_RPC_URL=ws://127.0.0.1:8545
EOF
echo ">> wrote $out/onchain.env"

# 6. launch the daemon fleet against the REAL oracle.
echo ">> launching daemon fleet against the deployed oracle"
"$here/up.sh" "$oracle" 31337 signet

echo ">> on-chain leg + fleet up."
echo ">> observers + coordinator + burn: docs/runbooks/testnet-rehearsal-localhost.md"
