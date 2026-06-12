# CTD-1 signet rehearsal — the closure gate

> **Purpose.** CTD-1 (fleet-wide Critical: coordinator-trusted destination)
> is code-complete: Slices A–E + the Slice C production tail are built and
> tested. It stays **Critical-Open** until THIS rehearsal passes with
> **real operators** (DL-CTD-2). The rehearsal proves the deployment
> assumptions the unit/e2e tests simulate: 5 independent humans, distinct
> infrastructure, HSM-backed keys, real signet broadcast, and the
> containment actually wired (not deploy-disabled defaults).
>
> **Output.** An evidence bundle (§6). When it is archived and reviewed,
> flip the `KNOWN_FINDINGS.md` CTD-1 entry from Critical-Open to CLOSED,
> citing this runbook + the bundle.

## 1. Topology (what each of the 5 operators runs)

Per operator, on infrastructure the OTHER operators do not control:

| Component | Binary / thing | Key material |
|---|---|---|
| Signer daemon | `xindex-signer-daemon` | Set-A custody key + Set-B certification key, HSM-backed (never in process memory) |
| Observer | `xindex-observe-redeem` | none (asks its own daemon to sign) |
| Ethereum RPC | own WS + HTTP endpoint | — |
| THORChain sources | **≥2 distinct** THORNode REST endpoints (refinement 1 — a shared source collapses 5 observers into 1) | — |

Shared (untrusted — can fail rounds, can never steer them):
coordinator host running `xindex-redeem` / `xindex-attest` /
`xindex-swap-back`, plus the relay fan-out. One Bitcoin **signet**
node/Esplora; one Ethereum testnet deployment (Sepolia or a shared anvil)
of `IndexFactory`/`IndexToken`/`IntentQueue`/`AttestationOracle`/
`CustodyGuard`/`ThorchainAdapter`.

THORChain leg: stagenet where practical; where stagenet cannot serve a
drill, a mock Asgard inbound (the drill notes say which is acceptable).

## 2. Pre-rehearsal checklist (all MUST be checked before drill 1)

**Keys (ceremony per `key-ceremony.md`, Set-B disclosure included):**
- [ ] Set A (BTC custody 3-of-5) generated in-HSM, descriptors distributed,
      addresses disclosed and pinned in every coordinator config.
- [ ] Set B (attestation/certification 3-of-5) generated in-HSM, addresses
      disclosed; every daemon's `intent_policy` whitelist lists exactly
      these 5, quorum 3.
- [ ] The deterministic test trio appears NOWHERE in any config.

**On-chain wiring (closes CG-4):**
- [ ] `CustodyGuard(timelock, queue)` deployed; `setOperators([5 ops], 3)`;
      `setVolumeCaps` ≈10% of per-asset custody / 24h;
      `IntentQueue.setCustodyGuard(guard)` + back-pointer verified.
- [ ] `AttestationOracle` signer set = Set B, threshold 3.

**Daemon configs (closes P-CTD-E-1, daemon half):**
- [ ] `cert_volume`: per-chain absolute caps ≈10% of custody — `unmetered()`
      appears NOWHERE.
- [ ] `ric_max_age` agreed fleet-wide (default per repo config).

**Observer configs (closes P-CTD-E-1 observer half + P-CTD-C-1 wiring):**
- [ ] `CUSTODY_GUARD_ADDR` + `ETH_HTTP_URL` set (halt gate live).
- [ ] `LARGE_SPEND_THRESHOLD` ≈2% of custody; `LARGE_SPEND_DELAY_SECS=1800`.
- [ ] `CANCEL_RECOVERY_DEST` = the ops/treasury Safe (DL-CTD-C-1) — the
      SAME address on all 5.
- [ ] `THORNODE_URLS`: ≥2 per operator, and the 5 operators' source sets
      are not all identical.

## 3. Drills

Every drill records: command transcripts, daemon/observer JSON logs,
txids, and the operator who executed it. Adversarial drills use a
tampered coordinator (patched `xindex-redeem` or raw `curl`) — the
OPERATORS' software is never modified.

**D1 — honest redemption (the happy path).** Small burn on the testnet
deploy → `RedeemDispatched` → all 5 observers record it → coordinator
collects the 3-of-5 RIC → custody daemons sign → signet broadcast →
confirmations ≥ the per-chain floor → delivery attestation path runs.
PASS: USDT-side attestation recorded; every observer's certified
plaintext was byte-identical.

**D2 — forged destination (the CTD-1 vector).** Tampered coordinator
presents the honest RIC with a PSBT paying an attacker scriptPubKey.
PASS: every daemon refuses 422 `psbt_unexpected_output`; no partial
signature exists anywhere.

**D3 — re-drive / equivocation.** Re-present the same
`(redemptionId, legIndex)` with a DIFFERENT certificate.
PASS: Set-B daemons 409 (non-equivocation) AND custody daemons 409
`intent_already_signed`.

**D4 — halt drill.** One operator calls `halt()` on `CustodyGuard`.
PASS: new mint/redemption intents revert on-chain; every observer
refuses (`observer_halted`); 3-of-5 un-halt vote lifts it; the halter's
re-halt cooldown enforced.

**D5 — fraud window.** Dispatch a leg STRICTLY ABOVE the 2% threshold.
PASS: observers refuse 425 `observer_fraud_window` until
`observed_at + 1800`, then certify; the halt was re-checked on each
retry.

**D6 — volume cap.** Drive certifications past the per-chain window cap
(rehearsal MAY shorten the window via config to keep the drill <1 day).
PASS: the over-cap certification is refused 422 `volume_cap_exceeded`
at the Set-B daemons AND the on-chain `checkDispatch`/`checkAttest`
reverts past the on-chain cap.

**D7 — mint-cancel swap-back (Slice C end-to-end).** Cancel a mint whose
USDT→BTC swap completed on signet custody. Operator runs
`xindex-swap-back` with the amount read from the orphaned UTXO.
Sub-drill (adversarial): a memo paying anywhere except the recovery
Safe → every observer refuses 422 `observer_memo_rejected`.
PASS: honest run broadcasts; the payout output is the agreed Asgard;
the recovered USDT lands at the ops/treasury Safe; the make-whole
procedure (`cancel-make-whole.md`) is executed once end-to-end.

**D8 — operator-loss tolerance.** Re-run D1 with 2 operators offline
(k=3 succeeds), then with 3 offline (round fails CLOSED — no spend).

## 4. Abort criteria

Any unexplained signature, any daemon signing without a quorum
certificate, any observer certifying a destination it did not derive →
STOP, halt the guard, archive logs, treat as a finding. The rehearsal
restarts only after the finding is fixed-in-code or triaged.

## 5. Roles

| Role | Who (fill at scheduling) |
|---|---|
| Operators 1–5 | … |
| Tampered-coordinator driver (red team) | … |
| Scribe (evidence bundle owner) | … |

## 6. Evidence bundle → closure

`rehearsal-<date>/` containing per-drill transcripts, logs, txids, the
exact configs (keys REDACTED), and a signed (any 3-of-5 Set B) summary
of PASS/FAIL per drill. On all-PASS: update `KNOWN_FINDINGS.md` CTD-1 to
CLOSED citing the bundle path; mirror to plan §14 and memory. Anything
less than all-PASS keeps CTD-1 Critical-Open.
