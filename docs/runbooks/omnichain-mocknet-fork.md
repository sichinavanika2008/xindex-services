# Omnichain environment — THORChain mocknet + forked mainnet ETH

> Goal: a **genuinely omnichain** Xindex environment where the cross-chain leg is a
> **real THORChain swap** (THORChain's actual Go code), against a **forked mainnet
> Ethereum** chain (real USDC/V4) and a **real regtest Bitcoin** node — with **no
> real funds**. This is the only way to get a real swap without crossing the
> "no real funds pre-audit" lock (stagenet uses real assets; a local anvil fork
> can't run THORChain).
>
> **Status: NOT YET RUN.** Stages 1–2 are THORChain's own tooling (well-defined).
> Stages 3–6 are Xindex↔THORChain integration with real unknowns flagged inline —
> expect on-box iteration. Drive them interactively (paste output back) or follow
> the notes.

## Why this shape (the constraint chain)
- You can't fork THORChain like you fork Ethereum — it's a separate validator
  network with its own pools. So a real swap needs a real THORChain network.
- **Stagenet** = real mainnet assets (`thorchain-docs/thornodes/developing.md`:
  "mirroring mainnet … with real assets"). Crosses the no-funds lock.
- **Mocknet/Devnet** = THORChain's real code, locally controlled, seeded/fake funds.
- THORChain ships `make reset-mocknet-fork-eth` (`tools/evm/run-mocknet-fork.sh`):
  full mocknet stack + a **hardhat fork of real ETH** wired into Bifrost via
  `ETH_HOST`. That preserves the real-USDC/V4 fork fidelity AND gives a real swap.

## Prerequisites (the box)
- **Linux, ≥16 GB RAM, ≥4 CPU, ~100 GB disk.** (Mocknet is many containers;
  native Docker on Linux — NOT colima/QEMU on an 8 GB Mac, which OOMs.)
- Docker Engine + Docker Compose v2, Node ≥18 (hardhat), Go ≥1.22 (builds the
  thornode image), `git`, `jq`, Foundry (`forge`/`cast`), Python 3.
- Repos cloned side by side: `thornode/` (THORChain), `Xindex/` (Solidity),
  `xindex-services/` (Rust off-chain).
- Build the Rust binaries once: `cargo build -p xindex-signer-daemon` (+ the
  observer/attest bins used in stage 5).

---

## Stage 1 — bring up mocknet + forked ETH
The stock fork script hardcodes `rpc.ankr.com/eth` (now key-gated). Patch it to a
free **archive** endpoint (publicnode 403s on the aged fork block; blastapi serves
archive — verified):

```bash
cd thornode
sed -i 's#https://rpc.ankr.com/eth#https://eth-mainnet.public.blastapi.io#' tools/evm/run-mocknet-fork.sh
make build-mocknet            # slow first time (Go + multi-GB images)
make reset-mocknet-fork-eth   # starts mocknet (--profile mocknet --profile midgard) + hardhat fork :5458 + init.js (mints USDC)
```
**Verify:**
```bash
docker compose -f build/docker/docker-compose.yml --profile mocknet ps   # thornode, bifrost, bitcoin, midgard, … Up
curl -s localhost:1317/thorchain/ping                                     # thornode API
cast chain-id --rpc-url http://localhost:5458                            # 1 (forked mainnet)
cast call 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 'symbol()(string)' --rpc-url http://localhost:5458  # USDC (real, forked)
```
Ports: thornode API `1317`, tendermint `26657`, bifrost `5040`, regtest BTC RPC
`18443`, midgard `8080`, hardhat fork `5458`. Trim RAM by removing unneeded chain
services (gaia/ltc/doge/bch) from the compose if the box is tight.

## Stage 2 — discover mocknet facts (only knowable on-box)
```bash
curl -s localhost:1317/thorchain/inbound_addresses | jq '.[] | {chain,address,router,halted}'   # ETH Asgard + router (aggregator) + BTC inbound
curl -s localhost:1317/thorchain/pools | jq '.[] | {asset,balance_rune,balance_asset,status}'    # which pools exist
```
Expected ETH aggregator/router on the fork: `0xBd68cBe6c247e2c3a0e36B8F0e24964914f26Ee8`
(`tools/evm/README.md`). USD token = **ETH.USDC** `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`.
Master/funded account (mocknet "dog" mnemonic): `0x8db97c7cece249c2b98bdc0226cc4c2a57bf52fc`.

## Stage 3 — ensure the pools we need (ETH.USDC + BTC.BTC)
Mocknet pools are seeded by the bootstrap/smoke flow, but confirm both `ETH.USDC`
and `BTC.BTC` are `Available` (stage 2 output). If missing, add liquidity from the
funded master account (`tools/evm/README.md` shows the pattern), e.g.:
```bash
# inside the thornode container / via thornode CLI (dog mnemonic):
thornode tx thorchain deposit <rune> rune ADD:ETH.USDC:0x8db97c... --from dog $TX_FLAGS
# + the matching USDC side via build/scripts/evm/evm-tool.py (--action swap-in / add)
```
⚠ **Iterate on-box** — exact liquidity amounts + the USDC `ADD` leg depend on the
mocknet genesis; the smoke tests under `test/smoke` are the reference.

## Stage 4 — deploy Xindex onto the forked ETH chain
Same mechanics proven on the local anvil fork (`webtest/up-fork-web.sh`), but pointed
at the hardhat fork (`:5458`) and **mocknet's** router + Asgard, and **funded with
USDC** (mocknet's USD pool is USDC, not USDT):

```bash
cd Xindex
RPC=http://localhost:5458
KEY=<a hardhat-funded acct key>            # hardhat node prints 20 funded accounts
# Phase 1 — real USDC/V4 on the fork. USDC is allowlisted as an underlying by default;
# add it as a FUNDING token (DeployPhase1 only funds USDT out of the box):
forge script script/DeployPhase1.s.sol --rpc-url $RPC --private-key $KEY --broadcast
cast send <factory> 'setMinMint(address,uint256)'      0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 100000000 --rpc-url $RPC --private-key $KEY
cast send <factory> 'setFundingAllowed(address,bool)'  0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 true      --rpc-url $RPC --private-key $KEY
# Phase 2 — point the adapter at MOCKNET's router + Asgard; BTC custody = our 3-of-5 P2WSH (rehearsal_gen):
INDEX_FACTORY=<factory> THORCHAIN_ROUTER=0xBd68cBe6c247e2c3a0e36B8F0e24964914f26Ee8 \
  INITIAL_ASGARD_VAULT=<mocknet ETH inbound from stage 2> \
  BTC_NATIVE_CUSTODY=<our regtest P2WSH from rehearsal_gen> \
  SIGNERS=<Set-B from rehearsal_gen --signers-only> THRESHOLD=3 \
  forge script script/DeployPhase2.s.sol --rpc-url $RPC --private-key $KEY --broadcast
```
⚠ **USDT vs USDC redeem leg.** `ThorchainAdapter.REDEEM_MEMO_ASSET` is the constant
`"ETH.USDT"` (`src/adapters/ThorchainAdapter.sol:85`); the burn-back-to-USD leg
would route through an ETH.USDT pool that mocknet doesn't seed. **The MINT side is
funding-token-agnostic** (it deposits whatever the basket funds with → USDC here),
so mint→swap→BTC works unchanged. For the burn-back-to-USD leg, either (a) change
that constant to `"ETH.USDC"` for the mocknet build, or (b) add an ETH.USDT pool in
stage 3. (Xindex's native-return burn path does not need it; the swap-back path does.)

## Stage 5 — wire the REAL off-chain observers to regtest BTC
This is where it becomes genuinely omnichain: THORChain swaps USDC→BTC and sends
real (regtest) BTC to our 3-of-5 custody; our observers confirm the arrival and
attest. Reuse the CTD-1 pipeline (proven on signet) pointed at mocknet's regtest:
- Custody = the P2WSH from `xindex-services/.../rehearsal_gen` (Set-B 3-of-5).
- Point the UTXO observer/attester (`chain-utxo` / `xindex-attest-redeem`) at the
  regtest node (`localhost:18443`, cookie/userpass from the `bitcoin` container) or
  a regtest esplora. Confirm the swap output lands at custody, then attest the
  delivered amount → `oracle.attest` → `finalizeMint`.
- Fund/confirm regtest: `docker exec <bitcoin> bitcoin-cli -regtest generatetoaddress 6 <addr>`.

⚠ **Iterate on-box** — observer config (regtest RPC creds, esplora vs RPC, conf
depth) and confirming Bifrost honours our custody destination + memo are the main
unknowns. This replaces `webtest/keeper.py`'s simulated delivery with the real
observe→attest path.

## Stage 6 — end-to-end via the dApp
Point the dApp at the fork and exercise it:
```bash
# webtest/addresses.js: rpc=http://localhost:5458, chainId=1, usdt=<USDC addr>,
# factory/oracle/queue=<stage-4>, chains[0]=BTC adapter+sentinel. (No usdtWhale:
# mint funds from a hardhat-funded acct holding USDC minted in stage 1/3.)
```
Flow: invest USDC → adapter deposits to mocknet router (`=:BTC.BTC:<custody>:<lim>`)
→ **THORChain really swaps USDC→BTC** → regtest BTC to custody → observers attest →
`finalizeMint`. Burn → native BTC from custody to the user's regtest address
(3-of-5 PSBT, CTD-1).
**This is a real cross-chain swap** — the cross-chain leg is no longer simulated.

---

## Integration risks (resolve on first run)
1. **USDC vs USDT** (stage 4) — mint is fine; burn-back-to-USD needs the constant
   change or an ETH.USDT pool.
2. **Pool liquidity** (stage 3) — ETH.USDC + BTC.BTC must be `Available` with depth
   for the swap to fill; tiny pools → big slip / `LIM` failures.
3. **Bifrost destination/memo** — confirm mocknet honours an arbitrary custody
   destination + our memo grammar; THORChain caps memo length.
4. **Regtest BTC** (stage 5) — observer RPC creds + conf depth + block generation.
5. **Resources** — even on 16 GB, trim unused chain services if it swaps.
6. **Aggregator/router on the fork** — confirm `0xBd68…6Ee8` is the live router in
   stage 2 (init.js / mocknet genesis can change it).

## What's reused vs new
- Reused (proven): Xindex deploy on a fork (`webtest/up-fork-web.sh`), the CTD-1
  3-of-5 observe→attest→PSBT pipeline (signet rehearsal).
- New (this runbook): the THORChain mocknet-fork backend + USDC funding + wiring
  the observers to regtest instead of the simulated `keeper.py`.
