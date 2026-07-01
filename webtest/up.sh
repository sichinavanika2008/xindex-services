#!/usr/bin/env bash
# Web testbed: one-command local-anvil bring-up so the founder can exercise
# the protocol from a browser. Deploys Phase 1 + Phase 2 (BTC) + a
# ThorchainAdapter for every other THORChain chain, launches the 5-daemon
# signer fleet, the attestation keeper (off-chain SIMULATION), and serves the
# throwaway dApp. Cross-chain custody is SIMULATED (the keeper mints USDT to
# stand in for native delivery) — NO real funds, NOT a mainnet step.
#
# Usage: ./webtest/up.sh        then open the printed dApp URL.
# Stop:  ./webtest/down.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
xindex="${XINDEX_SOLIDITY_DIR:-$repo/../Xindex}"
rpc="http://127.0.0.1:8545"
chain_id="31337"
# anvil account 0 — factory owner, funds every deploy + the dApp's default
# test wallet. PUBLIC dev key.
deployer="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
# anvil account 9 — DEDICATED keeper account so the keeper's attest/mint posts
# never race the dApp user's (account 0) nonces. PUBLIC dev key.
keeper_key="0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"
out="${WEBTEST_DIR:-/tmp/xindex-webtest}"
http_port="${WEBTEST_HTTP_PORT:-8080}"
mkdir -p "$out"

for t in anvil forge cast cargo python3; do
  command -v "$t" >/dev/null || { echo "missing required tool: $t"; exit 1; }
done
[ -d "$xindex" ] || { echo "Solidity repo not found at $xindex (set XINDEX_SOLIDITY_DIR)"; exit 1; }

export XINDEX_ALLOW_SOFTWARE_KEYS=1

# 1. anvil.
if ! cast block-number --rpc-url "$rpc" >/dev/null 2>&1; then
  echo ">> starting anvil (chain $chain_id)"
  anvil --chain-id "$chain_id" >"$out/anvil.log" 2>&1 &
  echo "$!" >"$out/anvil.pid"
  for _ in $(seq 1 20); do cast block-number --rpc-url "$rpc" >/dev/null 2>&1 && break; sleep 0.5; done
fi

# 2. mock funding/underlying tokens + THORChain router (anvil has no real ones).
echo ">> deploying mock tokens + router"
deploy_mock() {
  (cd "$xindex" && forge create test/mocks/MockERC20.sol:MockERC20 \
    --rpc-url "$rpc" --private-key "$deployer" --broadcast \
    --constructor-args "$1" "$2" "$3" 2>&1) | grep 'Deployed to:' | awk '{print $NF}'
}
weth="$(deploy_mock 'Wrapped Ether' WETH 18)"
usdc="$(deploy_mock 'USD Coin' USDC 6)"
usdt="$(deploy_mock 'Tether USD' USDT 6)"
router="$(cd "$xindex" && forge create test/mocks/MockThorchainRouter.sol:MockThorchainRouter \
  --rpc-url "$rpc" --private-key "$deployer" --broadcast 2>&1 | grep 'Deployed to:' | awk '{print $NF}')"
{ [ -n "$weth" ] && [ -n "$usdc" ] && [ -n "$usdt" ] && [ -n "$router" ]; } || { echo "mock deploy failed"; exit 1; }
echo "   WETH=$weth USDC=$usdc USDT=$usdt router=$router"

# 3. the 5 deterministic Set-B daemon addresses (oracle signer set).
signers="$(cargo run -q --manifest-path "$repo/Cargo.toml" \
  -p xindex-signer-daemon --example rehearsal_gen -- --signers-only)"
IFS=',' read -r s0 s1 s2 s3 s4 <<<"$signers"
echo ">> Set-B signers: $signers"

# 4. Phase 1.
echo ">> deploy Phase 1"
p1="$(cd "$xindex" && WETH="$weth" USDC="$usdc" USDT="$usdt" \
  forge script script/DeployPhase1.s.sol --rpc-url "$rpc" --private-key "$deployer" --broadcast 2>&1)"
factory="$(echo "$p1" | grep 'IndexFactory:' | awk '{print $NF}' | tail -n1)"
[ -n "$factory" ] || { echo "Phase 1 failed"; echo "$p1" | tail -20; exit 1; }
echo "   IndexFactory=$factory"

# 5. Phase 2 — AttestationOracle signer set = the 5 daemons, threshold 3.
echo ">> deploy Phase 2 (BTC; oracle signers = Set-B, threshold 3)"
p2="$(cd "$xindex" &&
  INDEX_FACTORY="$factory" \
  INITIAL_ASGARD_VAULT="0xdEaDbeEFdeAdbeefDEAdBeefDeadBEefDEadbeEf" \
  BTC_NATIVE_CUSTODY="bc1qwebtestmultisigforanvilonly00000000000" \
  THORCHAIN_ROUTER="$router" SIGNERS="$signers" THRESHOLD="3" \
  forge script script/DeployPhase2.s.sol --rpc-url "$rpc" --private-key "$deployer" --broadcast 2>&1)"
oracle="$(echo "$p2" | grep 'AttestationOracle:' | awk '{print $NF}' | tail -n1)"
btc_adapter="$(echo "$p2" | grep 'ThorchainAdapter' | awk '{print $NF}' | tail -n1)"
queue="$(echo "$p2" | grep 'IntentQueue:' | awk '{print $NF}' | tail -n1)"
{ [ -n "$oracle" ] && [ -n "$btc_adapter" ] && [ -n "$queue" ]; } || { echo "Phase 2 failed"; echo "$p2" | tail -30; exit 1; }
btc_sentinel="0x$(cast keccak 'xindex.sentinel.BTC.BTC' | sed 's/^0x//' | tail -c 41)"
echo "   AttestationOracle=$oracle IntentQueue=$queue btcAdapter=$btc_adapter"

# 5b. Hand the THORChain vault registry to the keeper account (2-step Ownable)
# so the keeper can keep the vault fresh — the adapter rejects a vault older
# than MAX_VAULT_AGE (4h), which would otherwise block mintAsync over time.
registry="$(cast call "$btc_adapter" 'VAULT_REGISTRY()(address)' --rpc-url "$rpc")"
keeper_addr="$(cast wallet address --private-key "$keeper_key")"
cast send "$registry" "transferOwnership(address)" "$keeper_addr" --rpc-url "$rpc" --private-key "$deployer" >/dev/null
cast send "$registry" "acceptOwnership()" --rpc-url "$rpc" --private-key "$keeper_key" >/dev/null
echo "   VaultRegistry:     $registry (owner → keeper, auto-refreshed)"

# 6. a ThorchainAdapter for every other THORChain chain (Stage 1 script).
echo ">> deploy all other THORChain chain adapters"
allc="$(cd "$xindex" &&
  INDEX_FACTORY="$factory" THOR_ROUTER="$router" THOR_VAULT_REGISTRY="$registry" \
  forge script script/DeployAllChainAdapters.s.sol --rpc-url "$rpc" --private-key "$deployer" --broadcast 2>&1)"
echo "$allc" | grep -q 'WEBTEST_CHAIN ' || { echo "all-chain adapters failed"; echo "$allc" | tail -30; exit 1; }

# Build the chains[] JS array: BTC first, then every parsed WEBTEST_CHAIN line.
chains_js="    { asset: \"BTC.BTC\", adapter: \"$btc_adapter\", sentinel: \"$btc_sentinel\" },"
while read -r _tag asset adapter sentinel; do
  [ "$_tag" = "WEBTEST_CHAIN" ] || continue
  chains_js="$chains_js
    { asset: \"$asset\", adapter: \"$adapter\", sentinel: \"$sentinel\" },"
done <<<"$(echo "$allc" | grep 'WEBTEST_CHAIN ')"

# 7. addresses.js for the dApp.
cat >"$here/addresses.js" <<EOF
// Generated by webtest/up.sh — local anvil testbed only.
window.XINDEX = {
  rpc: "$rpc",
  chainId: $chain_id,
  deployerKey: "$deployer",
  factory: "$factory",
  usdt: "$usdt",
  oracle: "$oracle",
  queue: "$queue",
  chains: [
$chains_js
  ],
};
EOF
echo ">> wrote $here/addresses.js"

# 8. launch the daemon fleet against the deployed oracle.
echo ">> launching 5-daemon fleet"
"$repo/rehearsal/up.sh" "$oracle" "$chain_id" signet

# 9. launch the keeper (off-chain attestation SIMULATION).
echo ">> launching attestation keeper"
WEBTEST_RPC="$rpc" WEBTEST_KEEPER_KEY="$keeper_key" \
  WEBTEST_ORACLE="$oracle" WEBTEST_QUEUE="$queue" WEBTEST_USDT="$usdt" WEBTEST_REGISTRY="$registry" \
  WEBTEST_D0_URL="http://127.0.0.1:8551" WEBTEST_D0_ADDR="$s0" \
  WEBTEST_D1_URL="http://127.0.0.1:8552" WEBTEST_D1_ADDR="$s1" \
  WEBTEST_D2_URL="http://127.0.0.1:8553" WEBTEST_D2_ADDR="$s2" \
  python3 "$here/keeper.py" >"$out/keeper.log" 2>&1 &
echo "$!" >"$out/keeper.pid"

# 10. serve the throwaway dApp.
echo ">> serving dApp"
(cd "$here" && python3 -m http.server "$http_port" >"$out/http.log" 2>&1 &
 echo "$!" >"$out/http.pid")

cat <<EOF

================================================================
  Xindex web testbed is UP (local anvil — simulated cross-chain)
================================================================
  dApp:        http://127.0.0.1:$http_port/
  RPC:         $rpc   (chainId $chain_id)
  Test wallet: import anvil account 0 into MetaMask:
               0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
               $deployer
  Logs:        $out/{anvil,keeper,http}.log
  Stop:        $here/down.sh
================================================================
EOF
