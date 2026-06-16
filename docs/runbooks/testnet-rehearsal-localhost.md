# One-box testnet rehearsal (localhost) — FUNCTIONAL, not the closure gate

> **What this is.** A single-machine functional rehearsal of the off-chain
> signing fleet: five `xindex-signer-daemon` instances + five observers +
> the coordinator, all on one Mac, with **software keys** and **plain-HTTP
> loopback**, against **anvil/Sepolia + signet (or a mock Asgard)**.
>
> **What this is NOT.** The CTD-1 **closure gate**
> ([`ctd1-signet-rehearsal.md`](./ctd1-signet-rehearsal.md)). That requires
> HSM-backed keys, five genuinely independent hosts, and a real signet
> broadcast — by definition it cannot be proven on one machine, because the
> property under test there is *infrastructure independence*. Passing this
> localhost rehearsal does **not** flip the `KNOWN_FINDINGS.md` CTD-1 entry.

## What it proves vs. does not prove

| Proven on one box | NOT proven here (→ closure gate) |
|---|---|
| 3-of-5 threshold crypto, k-of-n RIC aggregation/verification | 5 independent operators / hosts (shared fate, shared clock) |
| Per-family byte-exact encodings + the propose→certify→sign→broadcast flow | HSM-backed non-extractable keys (we use in-process software keys) |
| Replay / equivocation / mutex guards (drills D2, D3) | Real signet broadcast economics + Asgard liveness |
| The CTD-1 *logic* (forged-destination refusal) via injected divergence | Genuine observer data-source independence (mitigated, not proven — see below) |

**Independence on one box.** The whole point of per-operator observers is
that a lying coordinator cannot fake the destination because five
*independent* observers each resolve it. On one machine you preserve the
**data-source** independence — give each observer a **distinct ETH RPC + ≥2
distinct THORNode URLs** (the refinement-1 rule, `ctd1-signet-rehearsal.md`
§1) — but you cannot get host/operator independence. Tag every adversarial
drill below accordingly.

## Prerequisites

- Rust toolchain (workspace builds green).
- `curl` (health checks).
- For the on-chain leg: `anvil` (or a Sepolia RPC + funded key) and the
  Solidity repo's deploy scripts (`IndexFactory`/`IndexToken`/`IntentQueue`/
  `AttestationOracle`/`CustodyGuard`/`ThorchainAdapter`).
- For the cross-chain leg: a BTC **signet** Esplora endpoint, or a **mock
  Asgard inbound** where stagenet cannot serve a drill (acceptable per
  `ctd1-signet-rehearsal.md` §1).

## Quickstart — on-chain leg + fleet (verified end-to-end on anvil)

`up-onchain.sh` is the one-command on-chain bring-up. It starts anvil, deploys
mock funding/underlying tokens (anvil has no real WETH/USDC/USDT, and the
factory allowlist requires a token WITH code — `IndexFactory.sol:342`), deploys
Phase 1 + Phase 2 with the **`AttestationOracle` signer set = the 5 rehearsal
daemons** (`rehearsal_gen --signers-only` resolves the chicken-and-egg: the
Set-B addresses are deterministic and oracle-independent), then launches the
fleet against the real deployed oracle:

```sh
./rehearsal/up-onchain.sh    # anvil + deploy + 5 daemons; writes onchain.env
./rehearsal/down.sh          # stops the fleet AND anvil
```

VERIFIED: after `up-onchain.sh`, the deployed oracle reports `threshold() == 3`
and `isSigner() == true` for all five Set-B addresses, and all five daemons
serve `/health` 200 against it. The deployed addresses (oracle/adapter/queue)
land in `$XINDEX_REHEARSAL_DIR/onchain.env` for the observer/coordinator steps.

### D1 burn driver (mint→attest→burn) — automated + verified

`up-d1.sh` drives a REAL burn on the `up-onchain.sh` deploy, with the 3-of-5
MINT attestation produced by the LIVE daemon fleet:

```sh
./rehearsal/up-onchain.sh    # anvil + deploy (incl. a MockThorchainRouter) + fleet
./rehearsal/up-d1.sh         # createIndex → mintAsync → 3-of-5 daemon attest → finalizeMint → burn
```

`up-d1.sh` runs `script/AnvilD1.s.sol` (creates a 50/50 [sync mock / native-BTC]
basket like `IntegrationPhase2` and `mintAsync`s), then the `attest_mint`
example collects 3 attestation signatures from the daemons via the production
`RemoteHsmBackend` client, posts `oracle.attest`, `finalizeMint`s, then `burn`s.

VERIFIED end-to-end on anvil: `isFullyAttested=true` (the daemons' EIP-712 sigs
are accepted by the on-chain oracle — byte-match + signer-set alignment), and
the burn opens an active redemption (the `ThorchainAdapter` emits
`RedeemDispatched`). This exercises the entire EVM mint/burn + the live daemon
attestation path with REAL processes.

### Remaining for the rest of D1

- **observer + coordinator RIC collection** — launch the mock THORNode
  (`examples/mock_thornode.rs`, built) + observers (`xindex-observe-redeem`,
  `--from-block 0` to backfill the burn's `RedeemDispatched`) + the coordinator
  (`xindex-redeem --observer-urls … --intent-quorum 3`). The coordinator collects
  the 3-of-5 RIC, then stops at the PSBT UTXO fetch. Ready to wire; ends at the
  BTC wall below.
- **BTC payout (broadcast)** — the coordinator queries Esplora for a funded
  multisig UTXO + broadcasts. Needs signet (public Esplora + a funded multisig)
  or a local regtest + Esplora. NOT available in this sandbox.
- **`CustodyGuard`** — DeployPhase2 ships it deploy-disabled (CG-4); drills
  D4/D5/D6 need it deployed + `setOperators` + `IntentQueue.setCustodyGuard`.

The CTD-1 *logic* for D1–D8 is already proven in-process by
`crates/signer-daemon/tests/ctd1_adversarial_e2e.rs` (real daemons, real wire,
real ECDSA). The remaining work above is process-orchestration glue + a Bitcoin
backend, not new protocol logic.

## Quickstart — the signer-daemon fleet alone (verified)

The fleet launcher is self-contained. After you have a deployed
`AttestationOracle` address (from `up-onchain.sh` or the Sepolia deploy):

```sh
# Generates 5 --dev configs (shared 3-of-5 Set-B whitelist + 3-of-5 P2WSH
# custody descriptor; distinct ports 8551-8555, software keys, in-memory
# store) and launches all five daemons.
./rehearsal/up.sh <ATTESTATION_ORACLE_ADDR> [chain_id=31337] [network=signet]

# … run drills …

./rehearsal/down.sh
```

`up.sh` exports `XINDEX_ALLOW_SOFTWARE_KEYS=1` (the gate that lets the daemon
use in-process keys — it fails closed without it) and prints each operator's
Set-B address + health. Configs are written to `$XINDEX_REHEARSAL_DIR`
(default `/tmp/xindex-rehearsal`); regenerate alone with:

```sh
cargo run -p xindex-signer-daemon --example rehearsal_gen -- \
  /tmp/xindex-rehearsal <ATTESTATION_ORACLE_ADDR> 31337 signet
```

Keys are **deterministic** per operator (keccak of a fixed label) so a run is
reproducible and its evidence bundle regenerable; they are not the e2e test
trio and the production-safety gate blocks them from mainnet.

## Full procedure

1. **On-chain.** Start `anvil` (or target Sepolia). Deploy the protocol; note
   the `AttestationOracle`, `ThorchainAdapter`, `CustodyGuard` addresses. Wire
   `CustodyGuard.setOperators([the 5 Set-B addrs from up.sh], 3)` and the
   oracle signer set = those 5, threshold 3.
2. **Daemons.** `./rehearsal/up.sh <oracle_addr> <chain_id> <network>` →
   5 daemons healthy on 8551-8555.
3. **Observers.** One per operator, each pointing at its OWN daemon and
   DISTINCT sources (template — `xindex-observe-redeem` already exists):

   ```sh
   xindex-observe-redeem \
     --rpc-url ws://127.0.0.1:8545 \                   # operator-distinct in spirit
     --thorchain-adapter <ADAPTER> --attestation-oracle <ORACLE> \
     --thornode-urls <URL_A>,<URL_B> \                 # ≥2 distinct per operator
     --chain btc --btc-network signet \
     --signer-mode remote \
     --signer-daemon-url http://127.0.0.1:8551 \
     --signer-daemon-address <operator-0 Set-B addr from up.sh> \
     --custody-guard <GUARD> --eth-http-url http://127.0.0.1:8545 \
     --large-spend-threshold <≈2% custody> --large-spend-delay-secs 1800 \
     --cancel-recovery-dest <ops/treasury Safe> --swap-back-asset ETH.USDT
   ```
4. **Coordinator (untrusted).** Run `xindex-redeem` / `xindex-attest` /
   `xindex-swap-back` on the same box (they hold zero key material).

## Drills (adapted from `ctd1-signet-rehearsal.md` §3)

Tag: **[faithful]** = exercised as in production; **[simulated]** = logic
exercised, but a one-box limitation means it is not the real-world proof.

- **D1 honest redemption** — small burn → `RedeemDispatched` → 5 observers
  certify → 3-of-5 RIC → custody daemons sign → broadcast (signet or mock).
  **[faithful]** for crypto/encoding/flow; **[simulated]** for broadcast if
  the Asgard inbound is mocked.
- **D2 forged destination** — tampered coordinator presents a PSBT paying an
  attacker spk. PASS: every daemon refuses `422 psbt_unexpected_output`.
  **[faithful]** (the daemon code is identical).
- **D3 re-drive / equivocation** — re-present `(redemptionId, legIndex)` with
  a different certificate. PASS: Set-B `409` + custody `409`. **[faithful]**
  (replay store; use `database_url` for cross-restart persistence).
- **D4 halt** — `halt()` on `CustodyGuard`; new intents revert; observers
  refuse `observer_halted`; 3-of-5 un-halt. **[faithful]** (on-chain + observer).
- **D5 fraud window** — leg above the 2% threshold waits `1800s` then
  certifies. **[faithful]** (shorten via config to keep the drill short).
- **D6 volume cap** — drive certifications past the per-chain window cap
  (`rehearsal_gen` sets a small `btc` cap so this is reachable). PASS:
  `422 volume_cap_exceeded` + on-chain revert. **[faithful]**.
- **D7 mint-cancel swap-back** — `xindex-swap-back`; memo destination pinned
  to the recovery Safe; adversarial memo → `422 observer_memo_rejected`.
  **[faithful]** for the refusal; **[simulated]** for broadcast if mocked.
- **D8 operator-loss** — kill 2 daemons (k=3 succeeds), then 3 (fails CLOSED).
  **[faithful]** for the threshold; **[simulated]** for fault isolation
  (same host).
- **Adversarial independence** — to test the CTD-1 forged-destination
  property when sources are co-located, **inject divergent observations** into
  individual observer configs and confirm the assembled proof fails. This
  tests the *logic*; genuine independence is **[simulated]** here and is the
  reason the closure gate exists.

## mTLS (production bind — not used in this functional rehearsal)

The daemon serves plain HTTP under `--dev`. In production it serves **mTLS**:
add a `tls` block to the config (`server_cert`, `server_key`,
`pinned_client_certs`) and drop `--dev`. The daemon then requires
`assert_production_safe` to pass (HTTP HSM, every served chain metered) and
pins the coordinator's client certificate (`tls.rs`, `DL-M5-5`). Generating
the rehearsal PKI + wiring the coordinator's client-cert side is a follow-on;
it is intentionally out of scope for the localhost functional run.

## Closure

This rehearsal produces an evidence bundle for the FUNCTIONAL layer only. The
CTD-1 `Critical-Open` → `CLOSED` transition requires the
[`ctd1-signet-rehearsal.md`](./ctd1-signet-rehearsal.md) run with real
operators, HSMs, and signet. Keep them separate in the record.
