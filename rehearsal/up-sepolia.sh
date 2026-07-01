#!/usr/bin/env bash
# Sepolia bring-up — deploy the suite to REAL Sepolia with the encrypted keystore
# (xindex-sepolia-deployer + password file). AttestationOracle signer set = the 5
# rehearsal Set-B daemons; BTC custody = the real signet P2WSH; mock funding tokens
# + mock THORChain router (the swap leg is mocked for the functional rehearsal).
# Writes $out/onchain.env. Does NOT launch the fleet (done separately after the
# on-chain wiring is verified). DEV/TESTNET ONLY (software-key fleet). Adapted
# from up-onchain.sh (which is anvil-only).
#
# Env: SEPOLIA (rpc), BTC_CUSTODY (signet P2WSH), XINDEX_SOLIDITY_DIR;
#      KS (keystore, default ~/.foundry/keystores/xindex-sepolia-deployer),
#      KSPASS (password file, default /tmp/xindex-ks-pass).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
xindex="${XINDEX_SOLIDITY_DIR:-$repo/../Xindex}"
out="${XINDEX_REHEARSAL_DIR:-/tmp/xindex-sepolia}"
ks="${KS:-$HOME/.foundry/keystores/xindex-sepolia-deployer}"
kspass="${KSPASS:-/tmp/xindex-ks-pass}"
btc_custody="${BTC_CUSTODY:?set BTC_CUSTODY=signet P2WSH custody address}"
: "${SEPOLIA:?set SEPOLIA=rpc url}"
mkdir -p "$out"
auth=(--keystore "$ks" --password-file "$kspass")
# forge runs the SCRIPT SIMULATION as --sender (default 0x1804..1f38) unless set;
# the Phase2 owner precondition checks msg.sender, so pin it to the keystore addr.
sender="$(cast wallet address "${auth[@]}")"

for t in forge cast cargo; do command -v "$t" >/dev/null || { echo "missing tool: $t"; exit 1; }; done
[ -f "$kspass" ] || { echo "password file $kspass not found — stage it first"; exit 1; }
[ -d "$xindex" ] || { echo "Xindex repo not at $xindex (set XINDEX_SOLIDITY_DIR)"; exit 1; }
export XINDEX_ALLOW_SOFTWARE_KEYS=1

# 1. mock funding/underlying tokens — we control minting for the rehearsal, so we
#    do not depend on third-party Sepolia test tokens. MockERC20(name,symbol,dp).
echo ">> deploying mock tokens (WETH/USDC/USDT)"
deploy_mock() {
  (cd "$xindex" && forge create test/mocks/MockERC20.sol:MockERC20 \
    --rpc-url "$SEPOLIA" "${auth[@]}" --broadcast \
    --constructor-args "$1" "$2" "$3" 2>&1) | grep 'Deployed to:' | awk '{print $NF}'
}
weth="$(deploy_mock 'Wrapped Ether' WETH 18)"; echo "   WETH=$weth"
usdc="$(deploy_mock 'USD Coin' USDC 6)"; echo "   USDC=$usdc"
usdt="$(deploy_mock 'Tether USD' USDT 6)"; echo "   USDT=$usdt"
{ [ -n "$weth" ] && [ -n "$usdc" ] && [ -n "$usdt" ]; } || { echo "mock token deploy failed"; exit 1; }

# 2. mock THORChain router (the BTC mint acquire calls router.depositWithExpiry).
echo ">> deploying MockThorchainRouter"
router="$(cd "$xindex" && forge create test/mocks/MockThorchainRouter.sol:MockThorchainRouter \
  --rpc-url "$SEPOLIA" "${auth[@]}" --broadcast 2>&1 | grep 'Deployed to:' | awk '{print $NF}')"
[ -n "$router" ] || { echo "router deploy failed"; exit 1; }
echo "   MockThorchainRouter=$router"

# 3. the 5 deterministic Set-B addresses (oracle signer set).
signers="$(cargo run -q --manifest-path "$repo/Cargo.toml" \
  -p xindex-signer-daemon --example rehearsal_gen -- --signers-only)"
echo ">> Set-B signer set: $signers"

# 4. Phase 1.
echo ">> DeployPhase1"
p1="$(cd "$xindex" && WETH="$weth" USDC="$usdc" USDT="$usdt" \
  forge script script/DeployPhase1.s.sol --rpc-url "$SEPOLIA" "${auth[@]}" --sender "$sender" --broadcast 2>&1)" || {
  echo "$p1" | tail -30; exit 1; }
factory="$(echo "$p1" | grep 'IndexFactory:' | awk '{print $NF}' | tail -n1)"
[ -n "$factory" ] || { echo "could not extract IndexFactory"; echo "$p1" | tail -20; exit 1; }
echo "   IndexFactory=$factory"

# 5. Phase 2 — oracle signers = Set-B, threshold 3, BTC custody = real signet P2WSH.
echo ">> DeployPhase2 (oracle signers = Set-B, threshold 3)"
p2="$(cd "$xindex" && \
  INDEX_FACTORY="$factory" \
  INITIAL_ASGARD_VAULT="0xdEaDbeEFdeAdbeefDEAdBeefDeadBEefDEadbeEf" \
  BTC_NATIVE_CUSTODY="$btc_custody" \
  THORCHAIN_ROUTER="$router" \
  SIGNERS="$signers" THRESHOLD="3" \
  forge script script/DeployPhase2.s.sol --rpc-url "$SEPOLIA" "${auth[@]}" --sender "$sender" --broadcast 2>&1)" || {
  echo "$p2" | tail -30; exit 1; }
oracle="$(echo "$p2" | grep 'AttestationOracle:' | awk '{print $NF}' | tail -n1)"
adapter="$(echo "$p2" | grep 'ThorchainAdapter' | awk '{print $NF}' | tail -n1)"
queue="$(echo "$p2" | grep 'IntentQueue:' | awk '{print $NF}' | tail -n1)"
[ -n "$oracle" ] || { echo "could not extract AttestationOracle"; echo "$p2" | tail -30; exit 1; }
echo "   AttestationOracle=$oracle"
echo "   ThorchainAdapter=$adapter"
echo "   IntentQueue=$queue"

# 6. CustodyGuard — roster = Set-B, quorum 3, generous caps (transparent to D1).
echo ">> DeployCustodyGuard"
cg="$(cd "$xindex" && \
  INTENT_QUEUE="$queue" CUSTODY_OPERATORS="$signers" CUSTODY_QUORUM="3" \
  BTC_DISPATCH_CAP="10000000000" BTC_ATTEST_CAP="10000000000" \
  forge script script/DeployCustodyGuard.s.sol --rpc-url "$SEPOLIA" "${auth[@]}" --sender "$sender" --broadcast 2>&1)" || {
  echo "$cg" | tail -30; exit 1; }
guard="$(echo "$cg" | grep 'CustodyGuard:' | awk '{print $NF}' | tail -n1)"
[ -n "$guard" ] || { echo "could not extract CustodyGuard"; echo "$cg" | tail -30; exit 1; }
echo "   CustodyGuard=$guard"

# 7. record deployed addresses for the fleet / drill steps.
cat >"$out/onchain.env" <<EOF
ATTESTATION_ORACLE_ADDR=$oracle
THORCHAIN_ADAPTER_ADDR=$adapter
INTENT_QUEUE_ADDR=$queue
INDEX_FACTORY_ADDR=$factory
USDT_ADDR=$usdt
THORCHAIN_ROUTER_ADDR=$router
CUSTODY_GUARD_ADDR=$guard
ETH_RPC_URL=$SEPOLIA
EOF
echo ">> wrote $out/onchain.env"
echo ">> deploy complete — next: verify wiring on-chain, then rehearsal/up.sh $oracle 11155111 signet"
