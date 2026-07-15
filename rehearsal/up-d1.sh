#!/usr/bin/env bash
# D1 driver: drive a REAL burn → RedeemDispatched on the anvil deploy from
# up-onchain.sh, with the 3-of-5 MINT attestation produced by the LIVE daemon
# fleet. Reaches "real burn opened a redemption (RedeemDispatched emitted)".
# The observer/coordinator RIC collection + BTC payout are separate (the
# payout needs a Bitcoin backend — see docs/runbooks/testnet-rehearsal-localhost.md).
#
# Prereq: ./rehearsal/up-onchain.sh has run (anvil + deploy + fleet up).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
xindex="${XINDEX_SOLIDITY_DIR:-$repo/../Xindex}"
out="${XINDEX_REHEARSAL_DIR:-/tmp/xindex-rehearsal}"
rpc="http://127.0.0.1:8545"
deployer="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
creator="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" # anvil account 0 (the deployer)
attested_sats=800000

[ -f "$out/onchain.env" ] || {
  echo "run ./rehearsal/up-onchain.sh first (no $out/onchain.env)"
  exit 1
}
# shellcheck disable=SC1090,SC1091
. "$out/onchain.env"
export XINDEX_ALLOW_SOFTWARE_KEYS=1

# 1. createIndex + mintAsync (forge script — struct/hints heavy).
echo ">> createIndex + mintAsync"
d1="$(cd "$xindex" &&
  DEPLOYER_KEY="$deployer" \
    INDEX_FACTORY_ADDR="$INDEX_FACTORY_ADDR" USDT_ADDR="$USDT_ADDR" \
    THORCHAIN_ADAPTER_ADDR="$THORCHAIN_ADAPTER_ADDR" \
    forge script script/AnvilD1.s.sol --rpc-url "$rpc" --private-key "$deployer" --broadcast 2>&1)" || {
  echo "$d1" | tail -30
  exit 1
}
clone="$(echo "$d1" | grep 'INDEX_TOKEN_ADDR=' | tail -n1 | sed 's/.*INDEX_TOKEN_ADDR=//')"
intent="$(echo "$d1" | grep 'INTENT_ID=' | tail -n1 | sed 's/.*INTENT_ID=//')"
{ [ -n "$clone" ] && [ -n "$intent" ]; } || {
  echo "could not extract clone/intent"
  echo "$d1" | tail -30
  exit 1
}
echo "   IndexToken=$clone  intentId=$intent"

# 2. 3-of-5 MINT attestation from the LIVE daemons (slot 0 = queue async index).
echo ">> collecting 3-of-5 attestation from daemons (ports 8551-8553)"
source_chain_id=31337
source_block="$(cast block-number --rpc-url "$rpc")"
source_block_hash="$(cast block "$source_block" --field hash --rpc-url "$rpc")"
evidence_hash="$source_block_hash"
observed_at="$(date +%s)"
valid_until="$((observed_at + 120))"
observation_epoch="$(cast call "$ATTESTATION_ORACLE_ADDR" \
  "observationEpoch(uint256)(uint64)" "$source_chain_id" --rpc-url "$rpc")"
observation_epoch="${observation_epoch%% *}"
context="($evidence_hash,$observed_at,$valid_until,$source_chain_id,$source_block,$source_block_hash,$observation_epoch)"
signers="$(cargo run -q --manifest-path "$repo/Cargo.toml" \
  -p xindex-signer-daemon --example rehearsal_gen -- --signers-only)"
IFS=',' read -r s0 s1 s2 _rest <<<"$signers"
sigs_raw="$(cargo run -q --manifest-path "$repo/Cargo.toml" \
  -p xindex-signer-daemon --example attest_mint -- \
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

# 3. post the attestation on-chain.
echo ">> oracle.attest(intent, 0, $attested_sats, [3 sigs])"
cast send "$ATTESTATION_ORACLE_ADDR" \
  "attest(bytes32,uint256,uint256,(bytes32,uint64,uint64,uint256,uint64,bytes32,uint64),bytes[])" \
  "$intent" 0 "$attested_sats" "$context" "[$sig0,$sig1,$sig2]" \
  --rpc-url "$rpc" --private-key "$deployer" >/dev/null
echo "   isFullyAttested=$(cast call "$INTENT_QUEUE_ADDR" "isFullyAttested(bytes32)(bool)" "$intent" --rpc-url "$rpc")"

# 4. finalizeMint → shares to the creator.
echo ">> finalizeMint"
cast send "$clone" "finalizeMint(bytes32,uint256)" "$intent" 1 \
  --rpc-url "$rpc" --private-key "$deployer" >/dev/null
shares="$(cast call "$clone" "balanceOf(address)(uint256)" "$creator" --rpc-url "$rpc")"
shares="${shares%% *}" # strip any "[1e18]"-style annotation
echo "   creator shares=$shares"
[ "$shares" != "0" ] || {
  echo "finalizeMint minted 0 shares"
  exit 1
}

# 5. burn half → RedeemDispatched (opens an active redemption).
burn="$(python3 -c "print(int('$shares') // 2)")"
deadline="$(($(date +%s) + 7200))"
echo ">> burn $burn shares"
cast send "$clone" "burn(uint256,uint256,uint64)" "$burn" 1000000 "$deadline" \
  --rpc-url "$rpc" --private-key "$deployer" >/dev/null
redemption="$(cast call "$INTENT_QUEUE_ADDR" "activeRedemption(address)(bytes32)" "$clone" --rpc-url "$rpc")"
redemption="${redemption%% *}"
case "$redemption" in
0x0000000000000000000000000000000000000000000000000000000000000000 | "")
  echo "!! no active redemption — burn did not open one"
  exit 1
  ;;
*)
  echo ">> D1 REACHED: real burn opened redemption $redemption (ThorchainAdapter emitted RedeemDispatched)"
  ;;
esac
echo ">> next: observers + coordinator collect the 3-of-5 RIC; BTC payout needs a Bitcoin backend (runbook)"
