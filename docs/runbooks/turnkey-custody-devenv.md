# Turnkey custody — dev-env reconcile + validation runbook

> Scope: how to validate the **provisional** Turnkey custody wire against a real
> Turnkey dev-env (sub-organization) before any chain family touches mainnet
> funds. The code (branch `feat/turnkey-custody`) is built BTC-first + EVM and
> is **gate-green but PROVISIONAL** — every wire shape is pinned from Turnkey's
> public docs/SDK and marked `// RECONCILE AT DEV-ENV`. This runbook is the
> checklist that turns "provisional" into "validated".
>
> Supersedes `cobo-btc-gate.md` (the Cobo provider was dropped, DL-CUSTODY-TURNKEY-1).

## What is built (branch `feat/turnkey-custody`)

| Piece | Crate / file | Role |
|---|---|---|
| P-256 client | `crates/turnkey-client` | `X-Stamp` auth, `SIGN_RAW_PAYLOAD`, `get/approve/reject_activity` |
| Decision pipeline | `crates/custody-node` (`dispatch`, `btc`/`evm`/`account` cores) | provider-neutral CTD-1 bind: dest/amount/memo ↔ k-of-n RIC |
| Approver-watcher | `crates/custody-node` bin `xindex-turnkey-approver` | observes `CONSENSUS_NEEDED` → decide → `approveActivity`/`rejectActivity`, fail-closed |
| BTC executor | `crates/executor/src/turnkey_btc_redeem.rs` | build P2WPKH+OP_RETURN → sighash → sign → assemble → return tx |
| EVM executor | `crates/executor/src/turnkey_evm_redeem.rs` | build `depositWithExpiry` → signing-hash → sign → assemble raw → return |
| BTC driver bin | `crates/executor` bin `xindex-redeem-turnkey-btc` | single-leg CLI: fetch UTXOs + broadcast (spawn_blocking) around the async sign |
| EVM driver | `crates/executor` bin `xindex-redeem-evm` `turnkey` subcommand | single-leg CLI: nonce via provider + `submit_raw` |

**Trust model (accepted, DL-CUSTODY-TURNKEY-1):** Turnkey holds ONE complete key
in an attested enclave (NOT MPC / no share-split). "No single party in normal
operation" = the 2-of-2 `CONSENSUS_NEEDED` flow — our approver fleet is a
required co-approver; Turnkey will not sign without `approveActivity`. A
fully-subverted enclave is the residual single point MPC did not have. The
README "no single key" wording must be corrected if/when Turnkey becomes THE
custody model (separate doc change, gated on this validation).

## 0. Provision the dev-env (founder-side)

1. Create a Turnkey **sub-organization** for custody dev.
2. Create a **wallet** with a secp256k1 account (BTC P2WPKH + the EVM EOA).
3. Register the **API P-256 public key** (the approver fleet's + the executor's
   stampers). Hand the private key to each process via `XINDEX_TURNKEY_API_KEY`
   (hex) — never argv.
4. Configure a **consensus policy** requiring `approveActivity` from the
   approver key(s) before a `SIGN_RAW_PAYLOAD` completes. Dev = 1 approver;
   production = M-of-N independent approvers (DL-CTD-2 — do not collapse to 1).
5. Configure the **root quorum** + key-export DR per Turnkey's guidance.

## 1. RECONCILE checklist (pin each against the real dev-env)

Each item is a `// RECONCILE AT DEV-ENV` marker in the code. Capture the REAL
request/response JSON and confirm or fix the pinned shape.

| # | Where | Pinned assumption | Validate |
|---|---|---|---|
| R1 | `turnkey-client/src/auth.rs` | `X-Stamp` = base64url(no-pad) `{publicKey,scheme=SIGNATURE_SCHEME_TK_API_P256,signature}`; signature is **DER** ECDSA-P256 over the **raw body** (SHA-256) | Confirm against `@turnkey/api-key-stamper`: raw body (not canonicalized), DER (not fixed r‖s). A 401 on the first real call ⇒ stamp shape wrong. |
| R2 | `turnkey-client/src/types.rs` (`HASH_FUNCTION_NO_OP`) | a pre-hashed sighash uses `HASH_FUNCTION_NO_OP` | Confirm `NO_OP` (sign the bytes as-given) vs `NOT_APPLICABLE`. Wrong value ⇒ Turnkey re-hashes our sighash ⇒ invalid signature. |
| R3 | `turnkey-client/src/types.rs` (`Activity::signed_payload`) | the signed payload is at `activity.intent.signRawPayloadIntentV2.payload` | Capture a real `SIGN_RAW_PAYLOAD` activity; confirm the intent field name + that `payload` echoes our submitted sighash hex. The approver's correlation key depends on this. |
| R4 | `turnkey-client/src/lib.rs` + approver bin | the approver discovers activities via CLI `--activity-id`; `ACTIVITY_UPDATES` webhook is the production push trigger | Capture the real `ACTIVITY_UPDATES` webhook payload; build the push path (see §3 follow-on). |
| R5 | `custody-node/src/dispatch.rs` | the family core binds dest/amount/memo to the RIC; it does NOT yet re-derive the sighash and assert it equals the activity `payload` | Implement the cross-check once R3 confirms the payload field: `sighash(prepared_tx) == activity.payload`. This closes the "coordinator prepared X, submitted Y" gap; until then the approver-watcher's `--dev` flag gates it (`xindex-turnkey-approver` refuses to start without `--dev`). |
| R6 | EVM (`value` / chain ids) | EIP-1559/legacy per `chain.tx_type`; nonce + `EvmTxFee` caller-supplied (DL-P3.2-7) | Confirm Turnkey's `r,s,v` parity maps to EIP-1559 `y_parity = v==1`; broadcast a real testnet tx and verify it confirms. |

## 2. BTC validation (the decisive gate — Phase 2.A's only mainnet chain)

This is the Turnkey equivalent of the old Cobo "OP_RETURN gate". The whole BTC
path rests on Turnkey signing an **arbitrary caller-computed sighash**.

1. Build an unsigned **signet** BTC tx with `[Asgard-style payout, OP_RETURN
   memo, change]` (the `xindex-redeem-turnkey-btc` bin does this).
2. Submit `SIGN_RAW_PAYLOAD(payload = sighash, NO_OP)` → expect a
   `CONSENSUS_NEEDED` activity.
3. Run `xindex-turnkey-approver --dev` against the SAME shared `--db`; confirm it
   reads the activity payload, looks up the prepared spend, runs the RIC bind,
   and casts `approveActivity` (honest) / `rejectActivity` (tampered).
4. Confirm Turnkey returns `r,s,v`; the bin assembles `[DER(sig)+SIGHASH_ALL,
   pubkey]` (low-S), broadcasts, and the signet tx **confirms with the OP_RETURN
   intact**.
5. Negative tests: tamper the payout amount / memo / destination in the prepared
   spend ⇒ the approver must `rejectActivity` ⇒ no signature ⇒ no broadcast.

**If Turnkey cannot sign a raw caller-computed sighash for a tx carrying an
OP_RETURN, STOP** — the BTC path is blocked (re-evaluate before any more code).

## 3. Follow-on (gated on §1–§2 passing — do NOT build before validation)

- **Sighash↔payload cross-check** (R5) — the one remaining security hardening;
  needed before dropping `--dev`.
- **`ACTIVITY_UPDATES` webhook** push-trigger for the approver (R4) — replaces
  the CLI `--activity-id` poll path for production.
- **Account-family reroutes** (Cosmos / XRP / TRON) + **Solana** — same
  build+sign+return shape as BTC/EVM; the `decide_account_send` decision core
  already exists. **Deliberately deferred until the BTC wire is validated** —
  building 4 more families on an unvalidated wire risks reworking all of them.
- **Retire the on-chain multisig crates** (`multisig`/`safe-evm`/`*-tx`/
  `signer-daemon`) once Turnkey is confirmed as THE custody model.
- README "no single key" honesty edit; mirror DL-CUSTODY-TURNKEY-1 → plan §14.
- SOC 2 Type II review + key-export DR rehearsal (founder procurement).

## Gate state (as of this branch)

`cargo fmt --all --check`, `cargo clippy --workspace -D warnings`,
`cargo test --workspace` (835 passed; one pre-existing signer-daemon loopback-e2e
flake that passes in isolation), `cargo deny check`, and
`cargo audit --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2026-0185` — all green.
The two `--ignore`s are documented non-reachable transitive lockfile entries
(rsa via sqlx-mysql; quinn-proto via an unused HTTP/3 feature).
