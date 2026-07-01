#!/usr/bin/env bash
# Repoint the webtest dApp at the LIVE Sepolia deploy (reuse, not rebuild).
# REAL contracts + REAL 3-of-5 daemon MINT attestation; cross-chain DELIVERY is
# keeper-SIMULATED (USDT round-trip) — a flow/UX testbed, NOT the real redemption
# pipeline (that's the observer/coordinator signet path, proven separately).
# Prereq: the 5-daemon fleet is up (ports 8551-8555).
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
BTC_ADAPTER=0x3151a7cb0ede18CA8f2beEE35B2Fb913540A4848
REGISTRY=0xf7e92953e7a7C8B1aB6CACF5e32DD6B006D9710d
DEP=(--keystore "$HOME/.foundry/keystores/xindex-sepolia-3" --password-file /tmp/xindex-redeploy-pass)

echo ">> generate test wallet (dApp user) + keeper wallet"
tw=$(cast wallet new); TW_PK=$(echo "$tw" | awk '/[Pp]rivate/{print $NF}'); TW_ADDR=$(echo "$tw" | awk '/[Aa]ddress/{print $NF}')
kw=$(cast wallet new); KW_PK=$(echo "$kw" | awk '/[Pp]rivate/{print $NF}'); KW_ADDR=$(echo "$kw" | awk '/[Aa]ddress/{print $NF}')
echo "   test wallet: $TW_ADDR"
echo "   keeper:      $KW_ADDR"

echo ">> fund both from deployer (0.15 ETH each)"
cast send "$TW_ADDR" --value 150000000000000000 --rpc-url "$UPSTREAM" "${DEP[@]}" >/dev/null
cast send "$KW_ADDR" --value 150000000000000000 --rpc-url "$UPSTREAM" "${DEP[@]}" >/dev/null

echo ">> hand the vault registry to the keeper (2-step Ownable; keeps the vault fresh)"
cast send "$REGISTRY" "transferOwnership(address)" "$KW_ADDR" --rpc-url "$UPSTREAM" "${DEP[@]}" >/dev/null
cast send "$REGISTRY" "acceptOwnership()" --rpc-url "$UPSTREAM" --private-key "$KW_PK" >/dev/null

btc_sentinel=0x$(cast keccak 'xindex.sentinel.BTC.BTC' | sed 's/^0x//' | tail -c 41)

echo ">> write addresses.js (rpc -> CORS proxy)"
cat >"$here/addresses.js" <<EOF
// LIVE Sepolia deploy — testnet rehearsal. Cross-chain DELIVERY is keeper-SIMULATED.
window.XINDEX = {
  rpc: "$PROXY",
  chainId: $CHAINID,
  deployerKey: "$TW_PK",
  factory: "$FACTORY",
  usdt: "$USDT",
  oracle: "$ORACLE",
  queue: "$QUEUE",
  chains: [
    { asset: "BTC.BTC", adapter: "$BTC_ADAPTER", sentinel: "$btc_sentinel" },
    { asset: "ETH.ETH", adapter: "0xf5F6eB503c7824ff6fbD32D41837c2Be58f6F0bD", sentinel: "0x01A898E3ab063a02530BC9029c85F2Bb8a1a9Ea5" },
    { asset: "BCH.BCH", adapter: "0xc83bf4e6d258cAAfdEaEc4093364BAF878d132D1", sentinel: "0xd810FA29FF6281B9A275dC80dd8fB416427DDba5" },
    { asset: "LTC.LTC", adapter: "0xd736c0746b370dDB53347bC090833E4687dc8E36", sentinel: "0x7ea93514dda4aa0a378f2F59bD9B0caEc79a0711" },
    { asset: "DOGE.DOGE", adapter: "0x898497D6D87c0AC6abF60adc7B10F430fa2953bC", sentinel: "0xA74892aFf6E2c21e3Cd52a126f74DBBED5f57fD3" },
    { asset: "AVAX.AVAX", adapter: "0xEAd30060feB6BEE09d778C86367806CC18dBC5Ad", sentinel: "0x953290D5761536E33b6B4C704aeb9Aa444Af3c53" },
    { asset: "BSC.BNB", adapter: "0xca0a3aFC41400d505748d54CAb3f93F99186f103", sentinel: "0xA37bED3Cc2eb20A3cAaD30051C2371dd1dc758da" },
    { asset: "GAIA.ATOM", adapter: "0x8917e9FDA15c465850d52DefeedD4c620116268B", sentinel: "0x71B5C3020fB5d3d33eC1A6D5342Cf1f3D57F00b8" },
    { asset: "BASE.ETH", adapter: "0x941bC34c35400F5a632a43e8583cb6715AeADAFD", sentinel: "0xAFdcd13995EB6A244c7E7255C9F428DBd2EeEcA6" },
    { asset: "XRP.XRP", adapter: "0x274b222F366d802b17a6351852DAE29662b7d3A0", sentinel: "0x9272c48AD6B2363954a3F92e434F07d38fA92434" },
    { asset: "ZEC.ZEC", adapter: "0xdDB29D964f0F760828f70928Cfc70A6D1Dbdc865", sentinel: "0x75728899c058174F2cc0aEf424adf6d4940Ba18D" },
    { asset: "POL.MATIC", adapter: "0x00C4aFE27871C982E180a98E08fEceb730ACB675", sentinel: "0x4322148D5af3F8c69E32eA3230C6c9f248fD9829" },
    { asset: "NOBLE.USDC", adapter: "0x927Ed4aeeA7866247A4f75364158294235498D09", sentinel: "0x83c8802e1bdf95a367101550a5b52bFEc56dc601" },
    { asset: "SOL.SOL", adapter: "0x7b3Dc62CE0fd40a977F7CAE74Ba8442a64556a4D", sentinel: "0x5A0aABCE787CFaE6616fb1ad7C14bD13b315a1ab" },
    { asset: "TRON.TRX", adapter: "0x3B2B266C5Df54304bd1E221ca20Cd5aa08e1446f", sentinel: "0x42Ee84F594287828177BcFb8dC76093422B07A96" },
  ],
};
EOF

echo ">> launch CORS RPC proxy (3003 -> publicnode)"
pkill -9 -f 'eth-rpc-proxy' 2>/dev/null || true
sleep 1
nohup python3 "$out/eth-rpc-proxy.py" 3003 "$UPSTREAM" >"$out/rpc-proxy.log" 2>&1 &
disown 2>/dev/null || true

echo ">> launch keeper (mint attestation REAL via daemons; redemption delivery SIMULATED)"
signers="$("$repo/target/debug/examples/rehearsal_gen" --signers-only)"
IFS=',' read -r s0 s1 s2 _ <<<"$signers"
START=$(cast block-number --rpc-url "$UPSTREAM")
pkill -9 -f 'webtest/keeper.py' 2>/dev/null || true
sleep 1
WEBTEST_RPC="$UPSTREAM" WEBTEST_KEEPER_KEY="$KW_PK" \
  WEBTEST_ORACLE="$ORACLE" WEBTEST_QUEUE="$QUEUE" WEBTEST_USDT="$USDT" WEBTEST_REGISTRY="$REGISTRY" \
  WEBTEST_D0_URL=http://127.0.0.1:8551 WEBTEST_D0_ADDR="$s0" \
  WEBTEST_D1_URL=http://127.0.0.1:8552 WEBTEST_D1_ADDR="$s1" \
  WEBTEST_D2_URL=http://127.0.0.1:8553 WEBTEST_D2_ADDR="$s2" \
  WEBTEST_START_BLOCK="$START" WEBTEST_POLL_SECS=4 \
  nohup python3 "$here/keeper.py" >"$out/keeper.log" 2>&1 &
disown 2>/dev/null || true

echo ">> serve dApp (8080)"
pkill -9 -f 'http.server 8080' 2>/dev/null || true
sleep 1
(cd "$here" && nohup python3 -m http.server 8080 >"$out/http.log" 2>&1 & disown 2>/dev/null || true)
sleep 3
echo "   proxy=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3003/ 2>/dev/null) dApp=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ 2>/dev/null)"
echo ""
echo "================================================================"
echo "  Xindex dApp on LIVE Sepolia (cross-chain delivery SIMULATED):"
echo "     http://127.0.0.1:8080/"
echo "  funded test wallet (dApp signs as this): $TW_ADDR"
echo "  stop: pkill -f 'eth-rpc-proxy|webtest/keeper.py|http.server 8080'"
echo "================================================================"
