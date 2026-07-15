#!/usr/bin/env bash
# D1 driver for REAL Sepolia (chain 11155111): drive a real burn → RedeemDispatched
# against the up-sepolia.sh deploy, with the 3-of-5 MINT attestation produced by the
# LIVE software-key daemon fleet (rehearsal/up.sh <oracle> 11155111 signet).
#
# vs up-d1.sh (anvil): uses $SEPOLIA + the encrypted keystore (xindex-sepolia-2,
# the funded deployer 0x674aDC..) instead of localhost:8545 + a raw anvil key.
# AnvilD1.s.sol broadcasts via the forge --keystore/--sender signer when
# DEPLOYER_KEY is unset, and already allows chainid 11155111.
#
# Prereq:
#   - rehearsal/up-sepolia.sh deployed the suite ($out/onchain.env present)
#   - rehearsal/up.sh <oracle> 11155111 signet  has the 5 daemons up (8551-8555)
#   - staged secrets: /tmp/xindex-sepolia.env (export SEPOLIA=<rpc>) + KSPASS file
#
# Env: SEPOLIA (rpc; usually `source /tmp/xindex-sepolia.env`);
#      KS (keystore, default ~/.foundry/keystores/xindex-sepolia-2);
#      KSPASS (password file, default /tmp/xindex-ks-pass);
#      XINDEX_REHEARSAL_DIR (default /tmp/xindex-sepolia).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
xindex="${XINDEX_SOLIDITY_DIR:-$repo/../Xindex}"
out="${XINDEX_REHEARSAL_DIR:-/tmp/xindex-sepolia}"
ks="${KS:-$HOME/.foundry/keystores/xindex-sepolia-2}"
kspass="${KSPASS:-/tmp/xindex-ks-pass}"
attested_sats=800000

: "${SEPOLIA:?set SEPOLIA=rpc url (e.g. source /tmp/xindex-sepolia.env)}"
[ -f "$out/onchain.env" ] || { echo "no $out/onchain.env — run rehearsal/up-sepolia.sh first"; exit 1; }
[ -f "$kspass" ] || { echo "password file $kspass not found — stage it first"; exit 1; }
# shellcheck disable=SC1090,SC1091
. "$out/onchain.env"
export XINDEX_ALLOW_SOFTWARE_KEYS=1

rpc="$SEPOLIA"
auth=(--keystore "$ks" --password-file "$kspass")
creator="$(cast wallet address "${auth[@]}")"
echo ">> deployer/creator=$creator on Sepolia"

# 1. createIndex + mintAsync (forge script; keystore signs — DEPLOYER_KEY unset).
echo ">> createIndex + mintAsync"
d1="$(cd "$xindex" &&
  INDEX_FACTORY_ADDR="$INDEX_FACTORY_ADDR" USDT_ADDR="$USDT_ADDR" \
    THORCHAIN_ADAPTER_ADDR="$THORCHAIN_ADAPTER_ADDR" \
    forge script script/AnvilD1.s.sol --rpc-url "$rpc" "${auth[@]}" --sender "$creator" --broadcast 2>&1)" || {
  echo "$d1" | tail -40
  exit 1
}
clone="$(echo "$d1" | grep 'INDEX_TOKEN_ADDR=' | tail -n1 | sed 's/.*INDEX_TOKEN_ADDR=//')"
intent="$(echo "$d1" | grep 'INTENT_ID=' | tail -n1 | sed 's/.*INTENT_ID=//')"
{ [ -n "$clone" ] && [ -n "$intent" ]; } || {
  echo "could not extract clone/intent"
  echo "$d1" | tail -40
  exit 1
}
echo "   IndexToken=$clone  intentId=$intent"

# 2. 3-of-5 MINT attestation from the LIVE daemons (async slot 0 = the single BTC leg).
echo ">> collecting 3-of-5 attestation from daemons (ports 8551-8553)"
source_chain_id=11155111
source_block="$(cast block-number --rpc-url "$rpc")"
source_block_hash="$(cast block "$source_block" --field hash --rpc-url "$rpc")"
evidence_hash="$source_block_hash"
observed_at="$(date +%s)"
valid_until="$((observed_at + 120))"
observation_epoch="$(cast call "$ATTESTATION_ORACLE_ADDR" \
  "observationEpoch(uint256)(uint64)" "$source_chain_id" --rpc-url "$rpc")"
observation_epoch="${observation_epoch%% *}"
context="($evidence_hash,$observed_at,$valid_until,$source_chain_id,$source_block,$source_block_hash,$observation_epoch)"
signers="$("$repo/target/debug/examples/rehearsal_gen" --signers-only)"
IFS=',' read -r s0 s1 s2 _rest <<<"$signers"
sigs_raw="$("$repo/target/debug/examples/attest_mint" \
  "$source_chain_id" "$ATTESTATION_ORACLE_ADDR" "$intent" 0 "$attested_sats" \
  "$evidence_hash" "$observed_at" "$valid_until" "$source_block" \
  "$source_block_hash" "$observation_epoch" \
  http://127.0.0.1:8551 "$s0" http://127.0.0.1:8552 "$s1" http://127.0.0.1:8553 "$s2")"
sig0="$(echo "$sigs_raw" | sed -n '1p')"
sig1="$(echo "$sigs_raw" | sed -n '2p')"
sig2="$(echo "$sigs_raw" | sed -n '3p')"
{ [ -n "$sig0" ] && [ -n "$sig1" ] && [ -n "$sig2" ]; } || {
  echo "expected 3 signatures; got:"
  echo "$sigs_raw"
  exit 1
}
echo "   collected 3 signatures"

# 3. post the attestation on-chain (async slot 0).
echo ">> oracle.attest(intent, 0, $attested_sats, [3 sigs])"
cast send "$ATTESTATION_ORACLE_ADDR" \
  "attest(bytes32,uint256,uint256,(bytes32,uint64,uint64,uint256,uint64,bytes32,uint64),bytes[])" \
  "$intent" 0 "$attested_sats" "$context" "[$sig0,$sig1,$sig2]" \
  --rpc-url "$rpc" "${auth[@]}" >/dev/null
echo "   isFullyAttested=$(cast call "$INTENT_QUEUE_ADDR" "isFullyAttested(bytes32)(bool)" "$intent" --rpc-url "$rpc")"

# 4. finalizeMint → shares to the creator (minSharesOut=1).
echo ">> finalizeMint"
cast send "$clone" "finalizeMint(bytes32,uint256)" "$intent" 1 \
  --rpc-url "$rpc" "${auth[@]}" >/dev/null
shares="$(cast call "$clone" "balanceOf(address)(uint256)" "$creator" --rpc-url "$rpc")"
shares="${shares%% *}" # strip any "[1e18]"-style annotation
echo "   creator shares=$shares"
[ "$shares" != "0" ] || {
  echo "finalizeMint minted 0 shares"
  exit 1
}

# 5. burn half → RedeemDispatched (opens an active redemption).
burn="$(python3 -c "print(int('$shares') // ${BURN_DIV:-2})")"
deadline="$(($(date +%s) + 7200))"
echo ">> burn $burn shares (minOut ${MINOUT:-1000000})"
cast send "$clone" "burn(uint256,uint256,uint64)" "$burn" "${MINOUT:-1000000}" "$deadline" \
  --rpc-url "$rpc" "${auth[@]}" >/dev/null
redemption="$(cast call "$INTENT_QUEUE_ADDR" "activeRedemption(address)(bytes32)" "$clone" --rpc-url "$rpc")"
redemption="${redemption%% *}"
case "$redemption" in
0x0000000000000000000000000000000000000000000000000000000000000000 | "")
  echo "!! no active redemption — burn did not open one"
  exit 1
  ;;
*)
  echo ">> D1 REACHED on Sepolia: real burn opened redemption $redemption (ThorchainAdapter emitted RedeemDispatched)"
  ;;
esac
echo "BURN_BLOCK=$(cast block-number --rpc-url "$rpc")"
echo ">> next: observers + coordinator collect the 3-of-5 RIC; BTC payout = Stage 2 (signet backend)"
