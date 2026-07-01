#!/usr/bin/env bash
# Web testbed on a LOCAL ANVIL FORK of Ethereum mainnet. The dApp runs against
# REAL USDT / Uniswap V4 / THORChain Router (forked mainnet state), and the
# 3-of-5 daemon fleet does REAL mint + redemption-delivery attestation. The
# cross-chain DELIVERY leg is still keeper-SIMULATED — THORChain validators do
# not watch a fork — so the keeper transfers REAL forked USDT from an
# impersonated whale to stand in for the native->USDT leg. NO real funds,
# NOT a mainnet step.
#
# Why a fork (vs. webtest/up.sh's plain anvil): exercises the protocol against
# the real Tether contract (no-return approve, non-zero->non-zero revert) and
# the real V4 PoolManager / THORChain Router, i.e. a high-fidelity environment.
#
# Usage: ./webtest/up-fork-web.sh        then open the printed dApp URL.
# Stop:  pkill -f 'anvil --fork-url|xindex-signer-daemon|webtest/keeper.py|http.server 8080'
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
xindex="${XINDEX_SOLIDITY_DIR:-$repo/../Xindex}"
rpc="http://127.0.0.1:8545"
chain_id="1"
# Archive-capable fork RPC is REQUIRED: anvil pins the fork block and queries
# the backend for state at THAT block. A free "latest-128-only" endpoint (e.g.
# publicnode) starts 403-ing ("Archive requests require a personal token") once
# real mainnet advances >128 blocks past the fork, breaking every fresh-account
# read (new createIndex clones in particular). These public archive endpoints
# serve old-block state without a key; override with FORK_URL=<your archive RPC>.
fork_url="${FORK_URL:-https://eth-mainnet.public.blastapi.io}"  # fallback: https://1rpc.io/eth

# Real mainnet addresses (present in the fork).
USDT=0xdAC17F958D2ee523a2206206994597C13D831ec7        # real Tether (6dp)
WHALE=0xF977814e90dA44bFA03b6295A0616a897441aceC       # Binance hot wallet, ~17B USDT
ROUTER=0xD37BbE5744D730a1d98d8DC97c42F0Ca46aD7146      # THORChain ETH Router

# anvil account 0 — factory owner + every deploy + the dApp's default test
# wallet. PUBLIC dev key.
deployer="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
deployer_addr="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
# anvil account 9 — DEDICATED keeper account so the keeper's posts never race
# the dApp user's (account 0) nonces. PUBLIC dev key.
keeper_key="0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"
out="${WEBTEST_DIR:-/tmp/xindex-fork}"
http_port="${WEBTEST_HTTP_PORT:-8080}"
mkdir -p "$out"

for t in anvil forge cast python3 curl; do
  command -v "$t" >/dev/null || { echo "missing required tool: $t"; exit 1; }
done
[ -d "$xindex" ] || { echo "Solidity repo not found at $xindex (set XINDEX_SOLIDITY_DIR)"; exit 1; }
# PREBUILT binaries only — never `cargo run` here (Spotlight indexing the
# churning target/ wedges rustc codegen in uninterruptible I/O wait).
bin="$repo/target/debug/xindex-signer-daemon"
gen="$repo/target/debug/examples/rehearsal_gen"
[ -x "$bin" ] || { echo "prebuilt daemon missing: $bin  (cargo build -p xindex-signer-daemon)"; exit 1; }
[ -x "$gen" ] || { echo "prebuilt rehearsal_gen missing: $gen  (cargo build -p xindex-signer-daemon --example rehearsal_gen)"; exit 1; }

export XINDEX_ALLOW_SOFTWARE_KEYS=1

# 1. anvil mainnet-fork (reuse if one is already serving chain 1).
if ! cast chain-id --rpc-url "$rpc" 2>/dev/null | grep -qx 1; then
  echo ">> starting anvil mainnet-fork (chain 1, :8545) — pulls real state, ~10-20s"
  pkill -f 'anvil --fork-url' 2>/dev/null || true
  sleep 1
  nohup anvil --fork-url "$fork_url" --chain-id 1 --port 8545 \
    --accounts 10 --balance 10000 --disable-block-gas-limit --auto-impersonate \
    >"$out/anvil.log" 2>&1 &
  disown 2>/dev/null || true
  for _ in $(seq 1 30); do cast chain-id --rpc-url "$rpc" 2>/dev/null | grep -qx 1 && break; sleep 1; done
fi
cast chain-id --rpc-url "$rpc" 2>/dev/null | grep -qx 1 || { echo "anvil fork not up on $rpc"; exit 1; }
echo "   fork up: block $(cast block-number --rpc-url "$rpc")"

# 2. give the whale ETH so it can pay gas for impersonated USDT transfers.
cast rpc anvil_setBalance "$WHALE" 0x56BC75E2D63100000 --rpc-url "$rpc" >/dev/null  # 100 ETH

# 3. the 5 deterministic Set-B daemon addresses (oracle signer set).
signers="$("$gen" --signers-only)"
IFS=',' read -r s0 s1 s2 s3 s4 <<<"$signers"
echo ">> Set-B signers: $signers"

# 4. Phase 1 — REAL USDT/V4/WETH/USDC (DeployPhase1 mainnet defaults, no overrides).
echo ">> deploy Phase 1 (real USDT/V4; slow on a fork)"
p1="$(cd "$xindex" && forge script script/DeployPhase1.s.sol \
  --rpc-url "$rpc" --private-key "$deployer" --broadcast 2>&1)"
factory="$(echo "$p1" | grep 'IndexFactory:' | awk '{print $NF}' | tail -n1)"
[ -n "$factory" ] || { echo "Phase 1 failed"; echo "$p1" | tail -20; exit 1; }
cast call "$factory" 'isFundingAllowed(address)(bool)' "$USDT" --rpc-url "$rpc" | grep -qx true \
  || { echo "Phase 1 wired wrong: USDT not funding-allowed"; exit 1; }
echo "   IndexFactory=$factory  isFundingAllowed(USDT)=true"

# 5. Phase 2 — oracle signers = Set-B, threshold 3; seed the live ETH Asgard vault.
asgard="$(curl -s --max-time 12 https://thornode.thorchain.network/thorchain/inbound_addresses 2>/dev/null \
  | python3 -c "import json,sys;d=json.load(sys.stdin);e=[x for x in d if x.get('chain')=='ETH'];print(e[0]['address'] if e else '')" 2>/dev/null || true)"
[ -n "$asgard" ] || asgard=0x9fc30541611132c5ac38318e8eee044d2d36996f  # fallback if thornode is unreachable
echo ">> deploy Phase 2 (BTC; Asgard=$asgard)"
p2="$(cd "$xindex" &&
  INDEX_FACTORY="$factory" INITIAL_ASGARD_VAULT="$asgard" \
  BTC_NATIVE_CUSTODY="bc1qwebtestmultisigforanvilonly00000000000" \
  THORCHAIN_ROUTER="$ROUTER" SIGNERS="$signers" THRESHOLD="3" \
  forge script script/DeployPhase2.s.sol --rpc-url "$rpc" --private-key "$deployer" --broadcast 2>&1)"
oracle="$(echo "$p2" | grep 'AttestationOracle:' | awk '{print $NF}' | tail -n1)"
queue="$(echo "$p2" | grep 'IntentQueue:' | awk '{print $NF}' | tail -n1)"
btc_adapter="$(echo "$p2" | grep 'ThorchainAdapter' | awk '{print $NF}' | tail -n1)"
{ [ -n "$oracle" ] && [ -n "$queue" ] && [ -n "$btc_adapter" ]; } || { echo "Phase 2 failed"; echo "$p2" | tail -30; exit 1; }
btc_sentinel="0x$(cast keccak 'xindex.sentinel.BTC.BTC' | sed 's/^0x//' | tail -c 41)"
echo "   AttestationOracle=$oracle IntentQueue=$queue btcAdapter=$btc_adapter"

# 5b. hand the THORChain vault registry to the keeper (2-step Ownable) so it
#     stays fresh (the adapter rejects a vault older than MAX_VAULT_AGE = 4h).
registry="$(cast call "$btc_adapter" 'VAULT_REGISTRY()(address)' --rpc-url "$rpc")"
keeper_addr="$(cast wallet address --private-key "$keeper_key")"
cast send "$registry" "transferOwnership(address)" "$keeper_addr" --rpc-url "$rpc" --private-key "$deployer" >/dev/null
cast send "$registry" "acceptOwnership()" --rpc-url "$rpc" --private-key "$keeper_key" >/dev/null
echo "   VaultRegistry=$registry (owner → keeper, auto-refreshed)"

# 6. a ThorchainAdapter for every other THORChain chain (15-asset catalog).
echo ">> deploy all other THORChain chain adapters"
allc="$(cd "$xindex" &&
  INDEX_FACTORY="$factory" THOR_ROUTER="$ROUTER" THOR_VAULT_REGISTRY="$registry" \
  forge script script/DeployAllChainAdapters.s.sol --rpc-url "$rpc" --private-key "$deployer" --broadcast 2>&1)"
echo "$allc" | grep -q 'WEBTEST_CHAIN ' || { echo "all-chain adapters failed"; echo "$allc" | tail -30; exit 1; }
chains_js="    { asset: \"BTC.BTC\", adapter: \"$btc_adapter\", sentinel: \"$btc_sentinel\" },"
while read -r _tag asset adapter sentinel; do
  [ "$_tag" = "WEBTEST_CHAIN" ] || continue
  chains_js="$chains_js
    { asset: \"$asset\", adapter: \"$adapter\", sentinel: \"$sentinel\" },"
done <<<"$(echo "$allc" | grep 'WEBTEST_CHAIN ')"

# 7. addresses.js — the dApp talks DIRECTLY to anvil (it serves permissive CORS,
#    unlike a public RPC), and `usdtWhale` makes the faucet impersonate the whale
#    to hand out REAL forked USDT (no mock mint).
cat >"$here/addresses.js" <<EOF
// Generated by webtest/up-fork-web.sh — local ANVIL FORK of Ethereum mainnet.
// REAL USDT/V4/Router (forked state); cross-chain DELIVERY is keeper-SIMULATED.
// NOT a mainnet deploy.
window.XINDEX = {
  rpc: "$rpc",
  chainId: $chain_id,
  deployerKey: "$deployer",
  factory: "$factory",
  usdt: "$USDT",
  usdtWhale: "$WHALE",
  oracle: "$oracle",
  queue: "$queue",
  chains: [
$chains_js
  ],
};
EOF
echo ">> wrote $here/addresses.js"

# 8. launch the 5-daemon fleet against the deployed oracle (chain 1).
echo ">> launching 5-daemon fleet"
pkill -f 'xindex-signer-daemon' 2>/dev/null || true
sleep 1
"$gen" "$out" "$oracle" "$chain_id" signet
: >"$out/daemons.pids"
for i in 0 1 2 3 4; do
  XINDEX_ALLOW_SOFTWARE_KEYS=1 nohup "$bin" "$out/daemon-$i.json" --dev >"$out/daemon-$i.log" 2>&1 &
  echo "$!" >>"$out/daemons.pids"
  disown 2>/dev/null || true
done
sleep 3
echo ">> fleet health"
for i in 0 1 2 3 4; do
  port=$((8551 + i))
  echo "   operator $i (port $port): $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/api/v1/health" || echo ERR)"
done

# 9. keeper — REAL mint attestation via the daemons; redemption DELIVERY transfers
#    REAL forked USDT from the impersonated whale (WEBTEST_USDT_WHALE). Start the
#    log scan at the current head so it never queries below the fork block.
start_block="$(cast block-number --rpc-url "$rpc")"
echo ">> launching attestation keeper (fork mode: whale delivery, from block $start_block)"
pkill -f 'webtest/keeper.py' 2>/dev/null || true
sleep 1
WEBTEST_RPC="$rpc" WEBTEST_KEEPER_KEY="$keeper_key" \
  WEBTEST_ORACLE="$oracle" WEBTEST_QUEUE="$queue" WEBTEST_USDT="$USDT" WEBTEST_USDT_WHALE="$WHALE" \
  WEBTEST_REGISTRY="$registry" WEBTEST_START_BLOCK="$start_block" WEBTEST_LOG_WINDOW=1000000 \
  WEBTEST_D0_URL="http://127.0.0.1:8551" WEBTEST_D0_ADDR="$s0" \
  WEBTEST_D1_URL="http://127.0.0.1:8552" WEBTEST_D1_ADDR="$s1" \
  WEBTEST_D2_URL="http://127.0.0.1:8553" WEBTEST_D2_ADDR="$s2" \
  nohup python3 "$here/keeper.py" >"$out/keeper.log" 2>&1 &
echo "$!" >"$out/keeper.pid"
disown 2>/dev/null || true

# 10. serve the dApp.
echo ">> serving dApp on $http_port"
pkill -f "http.server $http_port" 2>/dev/null || true
sleep 1
(cd "$here" && nohup python3 -m http.server "$http_port" >"$out/http.log" 2>&1 & echo "$!" >"$out/http.pid"; disown 2>/dev/null || true)
sleep 2

cat <<EOF

================================================================
  Xindex dApp on a LOCAL ANVIL FORK of Ethereum mainnet
================================================================
  dApp:        http://127.0.0.1:$http_port/
  RPC:         $rpc   (chain 1; REAL USDT/V4/Router, forked)
  USDT:        $USDT  (real Tether; faucet impersonates whale)
  dApp wallet: $deployer_addr  (anvil acct0)
  Logs:        $out/{anvil,keeper,http,daemon-*}.log
  Stop:        pkill -f 'anvil --fork-url|xindex-signer-daemon|webtest/keeper.py|http.server $http_port'
================================================================
EOF
