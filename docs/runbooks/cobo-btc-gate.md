# Cobo BTC validation gate (the OP_RETURN / raw-sighash blocker)

> **Status: OPEN — founder-side. This gate blocks the Cobo BTC custody path.**
> Per `DL-CUSTODY-COBO-1` (memory `feedback_decision_locking.md`) and the
> custody build resume note, **no Cobo BTC wire code is written until this
> gate clears.** If the answer to §1 is "no native OP_RETURN *and* no
> raw-sighash signing", the BTC custody path must be rethought before any
> more code — a relayer cannot append the memo after signing, because the
> BTC signature commits to the full output set.

## Why this is a hard gate

THORChain BTC swaps are routed entirely by an `OP_RETURN` memo in the
funding transaction:

```
=:ETH.USDT:<recipient>:<minOut>
```

(`reference_thorchain.md`). The memo **must** be an output of the exact
transaction the custody key signs. Our whole CTD-1 destination-binding
(`custody-core::btc_bind::bind_outputs_to_cert`) is built around: exactly
one certified payout, exactly one zero-value `OP_RETURN` whose payload
`keccak == memo_hash`, everything else change-to-self.

From the 2026-06-27 web deep-dive, Cobo BTC is documented only as
*standard transfers* (`utxo_outputs` = address+amount, multi-output OK).
There is **no documented** OP_RETURN/nulldata output type, **no** PSBT
import, and **no** confirmed raw-sighash signing. Those gaps are exactly
what this gate must resolve.

## §1 — Questions for Cobo support (the <5-min ask)

Ask in this order; (1)/(2) are the blocker, the rest de-risk the build.

1. **Native OP_RETURN.** Does a BTC transfer (`create_transfer_transaction`)
   support an `OP_RETURN` / nulldata output? If yes: how is the payload
   supplied (raw hex?), and can a single transfer carry
   `[payout-address+amount] + [one zero-value OP_RETURN]` together?
2. **Raw-sighash / PSBT fallback (only if (1) is no).** Can we submit a
   raw unsigned BTC transaction *or* a PSBT we construct (with the
   OP_RETURN already in it) and have the MPC key produce a signature over
   the sighash we specify — i.e. drive the exact signed bytes? Is there a
   "raw signing" / "message signing" product for BTC?
3. **TSS Node Callback schema.** For a BTC KeySign, what fields does the
   callback's approval request carry (`request_detail` / `extra_info`)?
   Specifically: does it expose the unsigned tx / the per-input sighash /
   the full output set, so our callback can re-derive and bind
   destination+amount+memo **before** approving? (We fail-closed on any
   request we cannot re-derive.)
4. **No-single-key threshold.** Confirm a configuration where Cobo's
   share(s) **alone** cannot move funds — org-controlled 2-of-2 (org+Cobo)
   or co-managed 2-of-3 (us + Cobo + offline DR). Can we run multiple of
   our **own** TSS nodes to hold a majority independent of Cobo?
5. **Rotating destination.** THORChain's Asgard inbound address rotates.
   Does the transfer/whitelist model tolerate a frequently-changing
   destination (or does raw signing bypass any address allowlist)?
6. **Assurance.** SOC 2 Type II report + any TSS/crypto audit, for the
   pre-mainnet file.

## §2 — Dev-env test plan (`api.dev.cobo.com`, free test funds)

Reproducible proof to back the support answers. Each step is pass/fail.

1. **Provision.** Dev org + BTC MPC wallet at the no-single-key threshold
   from §1.4; fund from the test faucet.
2. **Capture the real callback schema.** Stand up the TSS Node Callback
   Server (`github.com/CoboGlobal/cobo-mpc-callback-server-v2-template`)
   with a handler that logs the full request and returns APPROVE. Trigger
   a BTC KeySign and **record the exact `request_detail`/`extra_info`
   fields** — this is the schema our wire adapter must reconcile against
   (currently non-public; do not guess it in code).
3. **OP_RETURN attempt (the gate).** `create_transfer_transaction` with a
   payout output **and** an `OP_RETURN` carrying a THORChain-style memo
   (`=:ETH.USDT:<dummy>:0`). Inspect the broadcast tx on a block explorer:
   does the `OP_RETURN` appear on-chain, zero-value, payload-exact?
   - **Pass** → §1.1 confirmed; BTC path proceeds on the native transfer.
   - **Fail** → run step 4.
4. **Raw/PSBT fallback.** Try the raw-signing / PSBT path from §1.2 with
   the OP_RETURN pre-placed. Pass → BTC path proceeds on raw signing
   (our callback re-derives the sighash, as already designed in
   `fb-cosigner`/`custody-node::btc`). Fail → **GATE FAILS, escalate.**
5. **Fail-closed proof.** Have the callback return REJECT and confirm no
   signature is produced (the request is denied end-to-end).

## §3 — Outcome routing

- **§3 pass (native OR raw):** unblocks the Cobo BTC wire adapter. Next:
  write the short Cobo-callback spec delta (reconcile the captured schema
  from §2.2 with the existing wire-independent `decide_redeem_spend`),
  then the JWT-RS256 callback server, then the executor reroute.
- **§3 fail:** BTC custody on Cobo is not viable as specified. Reopen the
  provider/path decision (memory `feedback_decision_locking.md`) before
  any further BTC code. EVM/Cosmos/XRP/TRON are unaffected (no OP_RETURN
  for EVM contract calls; account-family memos are tx fields, not
  nulldata outputs) — they can proceed independent of this gate.
