# Halt watchdog (`xindex-halt-watchdog`) — auto-engage CustodyGuard on a THORChain halt

> **What this is.** A per-operator daemon that polls THORChain liveness and,
> on a *sustained* halt, submits `CustodyGuard.halt()` so new mint AND burn
> custody lifecycles fail closed while THORChain is paused. It closes the
> mint-side halt asymmetry: the burn/redeem dispatch path already refuses to
> spend custody into a halted chain (the per-operator RIC agreement gate), but
> the on-chain mint deposit (`acquire`) only gates on vault *freshness* — there
> was no off-chain "stop minting into a halted chain" lever. This is it.
>
> **What it is NOT.** It does not detect a THORChain that is exploited while
> still reporting healthy, nor a failure that lands *after* your deposit is
> already in the Asgard vault (mid-swap capture). Those are the irreducible
> in-flight residual; the standing bound on them is the CustodyGuard volume
> breaker, not this halt. It never UN-halts — that is a deliberate quorum action.

## How it works

1. Each operator runs ONE instance, configured with that operator's OWN ≥3
   distinct THORNode sources (the refinement-1 rule — a single source is
   refused at startup, same posture as the RIC observers).
2. Every `--poll-interval-secs` it calls `AsgardAgreement::poll_chain_halt`,
   which reads the `/thorchain/inbound_addresses` halt/pause flags across all
   sources INDEPENDENT of the address-agreement check (so a halt landing during
   a vault churn is not masked by an address `Disagreement`):
   - `Halted` — ≥3 sources returned the chain and ≥1 reports
     `halted | chain_trading_paused | global_trading_paused`.
   - `Live` — that quorum responded, none halted.
   - `Indeterminate` — sub-quorum (transport failures / chain absent): **never**
     a trigger.
3. After `--halt-confirmations` (default 2) consecutive `Halted` reads it
   engages `CustodyGuard.halt()` (idempotent: re-reads `isHalted()` first).
   Any ONE operator firing is sufficient — `halt()` is a single-operator power.

**Fail-closed, bounded.** One hostile/flaky source can force a *bounded* (24h
auto-expiring, quorum-reversible) pause, but can never *suppress* a real halt.
A total outage already fails closed elsewhere (the on-chain vault-freshness gate
+ the RIC dispatch gate), so `Indeterminate` deliberately does not halt.

## Prerequisites for it to be EFFECTIVE

- `CustodyGuard` **deployed** and **wired** into the `IntentQueue`
  (`IntentQueue.setCustodyGuard(guard)`), with this operator's EOA in the guard
  roster (`CustodyGuard.setOperators`).
  > Deploy + wire with `Xindex/script/DeployCustodyGuard.s.sol` — it deploys
  > the guard, sets the roster + per-asset volume caps, and calls
  > `IntentQueue.setCustodyGuard`. The one-box rehearsal `up-onchain.sh` runs
  > it automatically and writes `CUSTODY_GUARD_ADDR` to `onchain.env`. Until
  > the guard is deployed + wired on a given network, the watchdog runs and
  > logs verdicts but has no guard to halt.
- This operator's ≥3 distinct THORNode REST endpoints.
- An ETH RPC (WS) and the operator's roster EOA key.

## Configuration

| Env | Flag | Default | Meaning |
|---|---|---|---|
| `ETH_RPC_URL` | `--eth-rpc-url` | `ws://127.0.0.1:8545` | WS RPC for the `halt()` tx |
| `CUSTODY_GUARD_ADDR` | `--custody-guard` | — | Deployed `CustodyGuard` |
| `OPERATOR_KEY` | `--operator-key` | — | Roster EOA (signs `halt()`) |
| `THORNODE_URLS` | `--thornode-urls` | — | ≥3 distinct THORNode base URLs (comma-sep) |
| `HALT_WATCH_CHAIN` | `--chain` | `BTC` | Chain symbol to watch |
| `POLL_INTERVAL_SECS` | `--poll-interval-secs` | `30` | Seconds between polls |
| `HALT_CONFIRMATIONS` | `--halt-confirmations` | `2` | Consecutive HALTED polls before engaging |
| — | `--dry-run` | off | Observe + log only; never submit `halt()` |

## Run (production, per operator)

```sh
CUSTODY_GUARD_ADDR=0x… OPERATOR_KEY=0x… \
  THORNODE_URLS=https://node-a.example,https://node-b.example \
  ETH_RPC_URL=wss://… \
  xindex-halt-watchdog
```

## Smoke test (hermetic)

```sh
./rehearsal/up-onchain.sh            # provides an ETH RPC (anvil)
./rehearsal/halt-watchdog-smoke.sh   # boots --dry-run, asserts the fail-safe path
```

Defaults to two UNREACHABLE loopback THORNode URLs, so the run is hermetic and
exercises the fail-safe path (sub-quorum → `Indeterminate` → never halts) while
proving the binary wires together (args → ≥3-source agreement → ETH provider →
poll loop). Override `THORNODE_URLS` with real endpoints for a live-liveness
check (expect `Live`).

## Full halt drill

`./rehearsal/halt-drill.sh` runs the complete chain end-to-end (after
`up-onchain.sh`):

1. starts two mock THORNodes (`rehearsal/mock-thornode.py`) serving
   `/thorchain/inbound_addresses`, live;
2. starts the watchdog signing as roster operator 0 (the Set-B key in
   `daemon-0.json`; it funds that EOA for gas);
3. toggles the halt (`touch $XINDEX_REHEARSAL_DIR/thor-halt` → both mocks report
   `halted: true`);
4. the watchdog detects the sustained halt and broadcasts `CustodyGuard.halt()`;
5. asserts `guard.isHalted() == true` AND that `requireNotHalted()` now reverts
   — the exact gate `IntentQueue.createMintIntent` hits, so new mint (and burn
   via `checkDispatch`) fail closed.

```sh
./rehearsal/up-onchain.sh     # anvil + deploy + guard wired
./rehearsal/halt-drill.sh     # -> "DRILL PASSED"
./rehearsal/down.sh
```

The contract-level halt gate is also covered by `Xindex/test/CustodyGuard.t.sol`;
a production drill swaps the mocks for a real stagenet halt.

## Operational notes

- `halt()` auto-expires after 24h; sustain with a quorum `voteExtendHalt`, or
  clear early with a quorum `voteUnhalt`. The watchdog **never** un-halts.
- Per-operator re-halt cooldown is 48h, so one operator cannot chain-freeze.
- A persistent `Indeterminate` in the logs means this operator cannot reach ≥3
  of its THORNode sources — page the operator. A blind watchdog is a silent gap
  (though the other gates remain fail-closed).
