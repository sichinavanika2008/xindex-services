# Mint-cancel make-whole procedure (DL-CTD-C-1)

> **Decision (founder-locked 2026-06-12, plan §14 DL-CTD-C-1).** When a
> mint intent is cancelled AFTER its USDT→native swap completed, the
> orphaned native asset is swapped back through THORChain to USDT, the
> proceeds land at the **protocol ops/treasury Safe** (the fleet-wide
> `CANCEL_RECOVERY_DEST` pin), and the **cancelled minter is made whole
> from those proceeds** per this procedure. Basket accrual was rejected
> (confiscatory); an on-chain claim path was rejected for v1.

## Scope

Applies only to the orphan case: the swap **succeeded** but the mint was
cancelled (deadline lapse, attestation miss). A swap that FAILED on
THORChain refunds the inbound USDT by itself — nothing to do here.

## Procedure

1. **Trigger.** An `AcquireCancelled` event whose intent has a matching
   custody arrival (the BTC UTXO bought by that mint's dispatch).
   Correlate via the same-mint-tx `Acquired` event and the custody
   wallet's UTXO history. Record `cancelId`, `intentId`, the minter's
   originator address, and the dispatched USDT value.
2. **Size the swap-back from custody observation** — the orphaned
   UTXO's actual sats. NEVER from `AcquireCancelled.amount` (it is the
   non-authoritative USDT allocation, A1/A5).
3. **Run the swap-back.** `xindex-swap-back --cancel-id … --amount-sats …
   --recovery-dest <ops Safe> …` (full args in the binary's `--help`).
   The observers pin the memo destination to the Safe; the custody
   daemons one-shot per `(chain, cancelId)`. Large amounts wait out the
   30-min fraud window — expected, not an error.
4. **Confirm receipt.** USDT arrives at the ops/treasury Safe via the
   THORChain outbound. Record the txids (signet/Bitcoin + Ethereum) in
   the ops ledger against `cancelId`.
5. **Reimburse the minter.** From the Safe (3-of-5), send the **full
   recovered USDT for this cancel** to the minter's originator address.
   Fee/slippage treatment (locked here per DL-CTD-C-1): the minter
   receives exactly what the swap-back recovered — favourable price
   movement is theirs, slippage/fees are theirs; the protocol takes
   nothing and tops up nothing. Record the Safe tx hash in the ledger.
6. **Close the ledger entry**: `cancelId → (swap-back txid, USDT-in
   txid, reimbursement txid, operator, date)`.

## Edge cases

- **Native asset arrives AFTER the cancel** (late THORChain delivery):
  same procedure — the trigger is the custody arrival, whenever it lands.
- **THORChain refunds the swap-back** (slip limit / halt): the BTC
  returns to custody (`vin[0]` refund-to-sender). Re-run step 3 when
  conditions clear; the IDENTICAL certificate re-drive is idempotent at
  the daemons, and a fresh round is fine — the one-shot keys on
  `cancelId`, so use a fresh certificate only if the spend parameters
  changed (different UTXO is fine; see CTD-E-R1 for why identical
  re-drives are bounded grief, not theft).
- **Dust**: below 2× the expected swap fees, recovery destroys value.
  Threshold and disposition (leave in custody, batch later) are ops
  discretion; record the decision in the ledger either way.
- **Multiple cancelled slots in one intent**: one swap-back per
  `cancelId` (the slot-scoped id), one ledger entry each.

## Trust note

This procedure is the one trust-bearing step in the cancel path: the
certificates guarantee recovered funds can ONLY reach the Safe, but
moving them from the Safe to the minter is an ops promise. Execute it
promptly and keep the ledger public to the team — the alternative
(trustless on-chain claims) is a documented post-v1 candidate.
