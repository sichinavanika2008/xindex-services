# Runbook — Stuck redemption (SD-B incident path)

> Locked decision SD-B (2026-05-17): a redemption that THORChain neither
> delivers nor refunds (vault halted, orphaned inbound, protocol incident)
> stays `PENDING` **forever** on-chain. There is **no** admin/timelock
> `forceCancel`. Resolution is this documented multi-party manual
> procedure. Do not add an on-chain backdoor "to fix this faster" — the
> absence of one is the security property.

## Why a redemption can get stuck

`burn()` moves BTC from our 3-of-5 P2WSH multisig to the THORChain
Asgard vault and opens a `RedemptionIntent` (the per-basket lock, R3).
Each async leg resolves through one of the signed settlement outcomes:

- **delivery** → `attestRedemption` → relayer `finalizeBurn`
- **refund** → `attestRefund` → relayer `finalizeBurn` with share re-minting
- **streamed** → `attestStreamedSettlement` → relayer `finalizeBurn`

THORChain ground truth (THORNode source): a halted vault produces
**neither** a delivery `out_tx` **nor** a `REFUND:<inbound_txid>`
outbound. Neither attestation can be honestly signed, so the basket lock
never clears and no further redemption on that basket can proceed. This
is correct behaviour, not a bug: signers must never attest an event that
did not happen.

## Detection (automated, no auto-action)

`xindex-finalize-redeem` copies every `RedemptionIntentCreated` from the
canonical finalized-observer journal into its durable local cursor/outbox. A
redemption with **no finalized delivery, refund, or streamed settlement at
`now >= deadline`** is flagged:

- Prometheus gauge `xindex_redeem_relayer_stuck` is set to the count.
- A `WARN` line is emitted per stuck `redemptionId`.
- **No terminal write is authorized by this timer.** The worker calls
  `finalizeBurn` only after a finalized signed settlement event; stuck
  detection itself is alert-only.

The checked-in alert uses
`xindex_redeem_relayer_stuck{job="xindex-finalize-redeem"} > 0 for 30m` and
separately fires if either the worker or this metric series is absent.

## Incident procedure (multi-party, manual)

Roles: **on-call** (declares + drives), **two signer operators**
(independent custody quorum), **protocol lead** (sign-off).

1. **Confirm the stuck condition.**
   - `redemptionId` from the alert. Query the F2 dispatch store for its
     `btc_txid` (`redemption_dispatch` table / `RedemptionDispatchStore`).
   - `GET /thorchain/tx/{btc_txid}` on ≥3 independent THORChain nodes.
   - Confirm: status not `done`; **no** outbound action with a delivery
     `out_tx` to the index token; **no** action with
     `memo == "REFUND:<btc_txid>"`. If a terminal state *does* exist, this
     is not SD-B — let the normal attest path run / investigate why the
     attest binary missed it.

2. **Classify the root cause** (determines the recovery, not whether to
   recover):
   - THORChain Asgard halt (network-wide / chain-specific). Check
     THORChain `/thorchain/mimir` halt flags and status pages.
   - Orphaned / dropped BTC inbound (the executor's BTC→Asgard tx never
     confirmed, or was reorged out). Check the broadcast registry +
     Bitcoin explorer for `btc_txid` confirmations.
   - THORChain refund issued but to an unexpected address (should be
     impossible — executor pins `vin[0]` = a multisig UTXO so
     `getSender` resolves to us; if violated, that is a separate
     executor bug, file it).

3. **Wait for THORChain to resolve where possible.** A halted vault
   eventually resumes; THORChain then either delivers or refunds with the
   `REFUND:` memo. The redemption is *locked but solvent* — the BTC is
   either still at Asgard or will return to our multisig. Patience is the
   default; **do not** improvise an on-chain unlock. The user's shares
   were burned but the basket value backing them is intact and the lock
   protects every other holder from a concurrent over-promise.

4. **If THORChain confirms permanent loss of the inbound** (genuinely
   orphaned, funds never reached Asgard and are still in our multisig, or
   THORChain support confirms the swap will never process):
   - Two signer operators independently verify on Bitcoin that the
     `btc_txid` UTXO is **either** spendable-back-by-us **or** the funds
     never left the multisig.
   - Manually construct and k-of-n co-sign a **refund-equivalent**: this
     is an *off-chain custody action that produces a real Bitcoin
     transaction returning BTC to the multisig*, after which the normal
     `ThorBtcRefundPolicy` path can be satisfied by a synthesized,
     operator-attested refund record — **only if** an actual BTC return
     to the multisig is observed on-chain with ≥ min confirmations.
     Signers attest the **observed on-chain sats**, never an asserted
     figure. This re-uses the verify-the-refund machinery; it does not
     bypass it.
   - `finalizeBurn` then runs through the ordinary refund-attested terminal
     (`attestRefund` → finalized journal → terminal worker), re-crediting the *attested* `refundedBtc`
     and re-minting the *dilution-safe* share count (SD-A: the user bears
     the round-trip fee; other holders' per-share NAV is non-decreasing).

5. **Document.** Append an incident record (date, `redemptionId`,
   `btc_txid`, root cause, resolution path, attestation txids) to the
   ops incident log and link it from the next `KNOWN_FINDINGS.md` audit
   pass. A new stuck *class* (not just an instance) gets a finding entry.

## Invariants this procedure must never violate

- No on-chain action authorized by time. Cancel = refund attestation.
- Signers attest only **observed** chain state (BTC sats actually back
  in the multisig; USDT actually delivered to the index token), never an
  asserted/expected amount.
- Re-mint on cancel uses the snapshot-pure dilution-safe share count, not
  `record.shares` (anti-dilution; user bears the THORChain fee).
- The basket lock stays held until exactly one of finalize / cancel
  resolves it. A stuck redemption blocking new redemptions on that
  basket is the *intended* fail-safe, not collateral damage to route
  around.
