#!/usr/bin/env bash
# Stand up the webtest dApp on the LIVE, VERIFIED Sepolia deploy (2026-06-24),
# repointed to the FRESH deployer-owned vault registry + non-bricked adapters.
#
# vs the old up-sepolia-web.sh: (1) new registry 0xce800C (deployer-owned) +
# fresh adapters, (2) NO ephemeral keeper-owns-registry transfer (that bricked
# the last one when its cast-wallet-new key died) — instead the registry stays
# deployer-owned and is refreshed via the KEYSTORE by a background loop; the
# keeper runs with a throwaway key and only attests + simulates delivery
# (WEBTEST_REGISTRY unset, so it never needs to own anything).
#
# REAL contracts + REAL 3-of-5 daemon MINT attestation; cross-chain DELIVERY is
# keeper-SIMULATED (USDT round-trip). Prereq: the 5-daemon fleet is up (8551-5).
set -euo pipefail
here=/Users/imac/Movies/xindex-services/webtest
repo=/Users/imac/Movies/xindex-services
out=/tmp/xindex-webtest-sepolia
mkdir -p "$out"

UPSTREAM=https://ethereum-sepolia-rpc.publicnode.com
PROXY=http://127.0.0.1:3003
CHAINID=11155111
FACTORY=0x3799b8896d4453fb2Ab128D5B5eA4BE62fA35D2c
ORACLE=0x76E4D678cbf14588Ce64D8ec17B6BFf0101a6A23
QUEUE=0xd4AEd373f7653592741B4Fcd2f6CE975ACd63875
USDT=0x90c89749e968B454b36eecA0B342bEd9943872e7
REGISTRY=0xce800CCC9eEac881bf094B4253fFacB8F00608c1
BTC_ADAPTER=0x17C70669972C2E38723ddEEE6e5b2010901C2d7a
BTC_SENTINEL=0x3dC17db546616BA4F8E0Cf0e6084e2ab948fdA77
ALLCHAINS_LOG=/tmp/xindex-sepolia/allchains.log
KS="$HOME/.foundry/keystores/xindex-sepolia-3"
KSPASS=/tmp/xindex-redeploy-pass
DEP=(--keystore "$KS" --password-file "$KSPASS")

[ -f "$ALLCHAINS_LOG" ] || { echo "missing $ALLCHAINS_LOG (run DeployAllChainAdapters first)"; exit 1; }

echo ">> generate dApp + keeper wallets (throwaway; own nothing)"
tw=$(cast wallet new); TW_PK=$(echo "$tw" | awk '/[Pp]rivate/{print $NF}'); TW_ADDR=$(echo "$tw" | awk '/[Aa]ddress/{print $NF}')
kw=$(cast wallet new); KW_PK=$(echo "$kw" | awk '/[Pp]rivate/{print $NF}'); KW_ADDR=$(echo "$kw" | awk '/[Aa]ddress/{print $NF}')
echo "   dApp wallet: $TW_ADDR"
echo "   keeper:      $KW_ADDR"

echo ">> fund dApp (0.15 ETH) + keeper (0.3 ETH) from deployer"
cast send "$TW_ADDR" --value 150000000000000000 --rpc-url "$UPSTREAM" "${DEP[@]}" >/dev/null
cast send "$KW_ADDR" --value 300000000000000000 --rpc-url "$UPSTREAM" "${DEP[@]}" >/dev/null

echo ">> mint 100k mock USDT to the dApp wallet"
cast send "$USDT" "mint(address,uint256)" "$TW_ADDR" 100000000000 --rpc-url "$UPSTREAM" "${DEP[@]}" >/dev/null

echo ">> refresh the vault registry now (deployer keystore; good for 4h)"
VAULT=$(cast call "$REGISTRY" "currentVault()(address)" --rpc-url "$UPSTREAM")
cast send "$REGISTRY" "setVault(address)" "$VAULT" --rpc-url "$UPSTREAM" "${DEP[@]}" >/dev/null

echo ">> write addresses.js (15 chains, all on the fresh registry)"
python3 - "$ALLCHAINS_LOG" >"$here/addresses.js" <<PY
import sys
log=open(sys.argv[1]).read().splitlines()
rows=[("BTC.BTC","$BTC_ADAPTER","$BTC_SENTINEL")]
for ln in log:
    if ln.strip().startswith("WEBTEST_CHAIN"):
        _,asset,adapter,sentinel=ln.split()
        rows.append((asset,adapter,sentinel))
print("// LIVE Sepolia deploy (2026-06-24, verified). Cross-chain DELIVERY is keeper-SIMULATED.")
print("window.XINDEX = {")
print('  rpc: "$PROXY",')
print("  chainId: $CHAINID,")
print('  deployerKey: "$TW_PK",')
print('  factory: "$FACTORY",')
print('  usdt: "$USDT",')
print('  oracle: "$ORACLE",')
print('  queue: "$QUEUE",')
print("  chains: [")
for a,ad,se in rows:
    print(f'    {{ asset: "{a}", adapter: "{ad}", sentinel: "{se}" }},')
print("  ],")
print("};")
PY
echo "   wrote $(grep -c 'asset:' "$here/addresses.js") chains"

echo ">> launch CORS RPC proxy (3003 -> publicnode)"
pkill -9 -f 'eth-rpc-proxy' 2>/dev/null || true; sleep 1
nohup python3 "$here/eth-rpc-proxy.py" 3003 "$UPSTREAM" >"$out/rpc-proxy.log" 2>&1 &
disown 2>/dev/null || true

echo ">> background registry refresher (keystore; every 1h so the 4h window never lapses)"
pkill -9 -f 'xindex-registry-refresh' 2>/dev/null || true
nohup bash -c 'while true; do sleep 3600; cast send '"$REGISTRY"' "setVault(address)" '"$VAULT"' --rpc-url '"$UPSTREAM"' --keystore '"$KS"' --password-file '"$KSPASS"' >/dev/null 2>&1 || true; done # xindex-registry-refresh' >"$out/refresh.log" 2>&1 &
disown 2>/dev/null || true

echo ">> launch keeper (REAL 3-of-5 mint attestation; delivery simulated; registry refresh handled by keystore loop)"
signers="$("$repo/target/debug/examples/rehearsal_gen" --signers-only)"
IFS=',' read -r s0 s1 s2 _ <<<"$signers"
START=$(cast block-number --rpc-url "$UPSTREAM")
pkill -9 -f 'webtest/keeper.py' 2>/dev/null || true; sleep 1
WEBTEST_RPC="$UPSTREAM" WEBTEST_KEEPER_KEY="$KW_PK" \
  WEBTEST_ORACLE="$ORACLE" WEBTEST_QUEUE="$QUEUE" WEBTEST_USDT="$USDT" \
  WEBTEST_D0_URL=http://127.0.0.1:8551 WEBTEST_D0_ADDR="$s0" \
  WEBTEST_D1_URL=http://127.0.0.1:8552 WEBTEST_D1_ADDR="$s1" \
  WEBTEST_D2_URL=http://127.0.0.1:8553 WEBTEST_D2_ADDR="$s2" \
  WEBTEST_START_BLOCK="$START" WEBTEST_POLL_SECS=4 \
  nohup python3 "$here/keeper.py" >"$out/keeper.log" 2>&1 &
disown 2>/dev/null || true

echo ">> serve dApp (the standalone design, wired to live Sepolia) on 8081"
cp "$here/addresses.js" "$here/../webtest-app/addresses.js"
pkill -9 -f 'http.server 808' 2>/dev/null || true; sleep 1
(cd "$here/../webtest-app" && nohup python3 -m http.server 8081 >"$out/http.log" 2>&1 & disown 2>/dev/null || true)
sleep 3
echo "   proxy=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3003/ 2>/dev/null) dApp=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/ 2>/dev/null)"
echo ""
echo "================================================================"
echo "  Xindex dApp on LIVE Sepolia (cross-chain delivery SIMULATED):"
echo "     http://127.0.0.1:8081/"
echo "  dApp signs as: $TW_ADDR  (0.15 ETH + 100k mock USDT)"
echo "  stop: pkill -f 'eth-rpc-proxy|webtest/keeper.py|http.server 808|xindex-registry-refresh'"
echo "================================================================"
