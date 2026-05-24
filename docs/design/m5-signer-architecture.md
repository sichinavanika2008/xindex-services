# M5 signing architecture — LOCKED design (daemon code gated)

> Status: **DESIGN LOCKED, implementation GATED.** This is the
> custody-critical lock-in the memory reference flags ("Before M5
> architecture lock-in → re-read Web3Signer pattern"). It is the code
> that produces the k-of-n attestation signatures and the 3-of-5
> Bitcoin-spend signatures — i.e. it spends real BTC and authorises
> real attestations. The daemon/wire code is **not** to be written
> until this spec is explicitly approved, mirroring the decision-lock
> discipline used for the burn→USDT pivot and the v2/CCIP design.
> Free-handing a custody signing protocol under "M5 done" is the single
> highest-severity process error available here; this document exists to
> prevent that.

## Why a design lock (not just "implement the YubiHSM backend")

`HsmBackend` (`crates/signer/src/lib.rs:48`) and `MultisigCosigner`
(`crates/executor/src/redeem.rs:146`) are already the right *trait*
seams. The locked decision is **how the production impls are
structured**, and that is an architecture choice with no safe default:

- Naive "client calls Web3Signer's generic `eth1/sign`" is **incorrect
  by construction**: Web3Signer's eth1 sign keccak-hashes the supplied
  data before signing, but our attestation flow already produces the
  final EIP-712 digest (`xindex_shared::eip712::*`) which must be signed
  *raw* with `v ∈ {27,28}`. Signing `keccak(digest)` makes on-chain
  `ecrecover` fail. The signing service must take our *typed message*
  and compute the EIP-712 digest itself, then raw-sign via the HSM.
- The k-of-n architecture is a **coordinator/daemon split with a
  per-daemon replay DB**, not an in-process key loop. This is the
  Web3Signer/Lighthouse "remote signer + slashing DB" pattern
  (`memory/reference_rust_protocol_patterns.md` §B).

## Locked architecture (DL-M5-1 … DL-M5-6)

- **DL-M5-1 — Coordinator/daemon split.** `xindex-attest` /
  `xindex-attest-redeem` become **key-less coordinators**: watch
  `IntentQueue`, build the typed message, request signatures over HTTP
  from N independent `xindex-attest-signer-daemon` processes, aggregate
  k-of-n exactly as `aggregate_signatures` does today. The coordinator
  holds **no key material**.
- **DL-M5-2 — One daemon per signer, key in YubiHSM2, fronted by
  Web3Signer.** Each daemon owns exactly one Set-B key (see
  `docs/runbooks/key-ceremony.md`). The daemon does **not** implement
  HSM crypto itself: it computes the EIP-712 digest from the typed
  message and asks a *local* Web3Signer (holding the YubiHSM2
  connection) to raw-sign that 32-byte digest. Rationale
  (`reference_rust_protocol_patterns.md` recommendation (c)): re-use
  Web3Signer-the-product as the HSM abstraction; minimise novel code in
  the most security-critical path. The daemon is a thin, audited
  digest-computation + replay-guard + transport shim.
- **DL-M5-3 — Daemon API is a typed EIP-712 endpoint, never a raw
  passthrough.** Shape (from `reference_rust_protocol_patterns.md` §B,
  pinned here):
  - `POST /api/v1/sign/eip712` body `{ domain, message }` where
    `message` is one of the three locked typed structs (attestation /
    redemption-delivery / refund — preserving the structural typehash
    separation). The daemon computes the digest with the *same*
    `xindex_shared::eip712` code the coordinator/contract use (shared
    crate ⇒ no drift), checks its replay DB, raw-signs via Web3Signer,
    returns `{ signature: 0x… 65 bytes, v∈{27,28} }`.
  - `409 Conflict` if the daemon already signed a *different* value for
    this `(typehash, key1, key2…)` replay key.
  - `503` if Web3Signer/YubiHSM2 is unreachable or the audit log is
    full (signing must never proceed un-audited).
  - `GET /api/v1/keys` → `[{ address, scheme: "secp256k1-eip712" }]`.
  - `GET /api/v1/health` → HSM connectivity report.
- **DL-M5-4 — Per-daemon replay DB (slashing-equivalent).** Each daemon
  has a local `sqlx` store: "have I signed `(message-replay-key)` and at
  what value". Refuse pre-flight on a conflicting re-sign rather than
  relying solely on the on-chain `SlotAlreadyAttested` revert
  (future-proofs against non-deterministic schemes; same `*Store` AFIT
  pattern as the rest of the stack). DB-level row lock so two daemon
  replicas of the same key can't double-sign (HA correctness).
- **DL-M5-5 — Bitcoin `RemoteMultisigCosigner` is the SAME shape.** The
  production `MultisigCosigner` impl is the identical coordinator/daemon
  pattern for the Set-A P2WSH key: the executor (coordinator, key-less)
  sends a PSBT + input index to N signer daemons; each daemon validates
  the PSBT (it spends *only* to the expected Asgard/​change outputs —
  the daemon independently re-derives and checks, never blind-signs),
  consults its replay DB, raw-signs the input via its Web3Signer/YubiHSM2,
  returns the partial signature. `InProcessExecutor` is retired in
  production (kept dev-only, already documented). The PSBT-validation
  rule on the daemon side is custody-critical and part of this lock: a
  cosigner that blind-signs whatever PSBT it is handed defeats the
  multisig.
- **DL-M5-6 — Implementation gate.** No daemon, wire-protocol, or
  replay-DB code is written until this spec is approved. When approved,
  build order: shared typed-message + digest reuse → daemon replay store
  (AFIT `*Store`, mirror existing) → `xindex-attest-signer-daemon`
  (axum, Web3Signer client, wiremock-tested) → coordinator refactor of
  `xindex-attest`/`-redeem` to call daemons → `RemoteMultisigCosigner`
  (same pattern) → integration test against a mocked Web3Signer +
  mocked daemons (no hardware) → staging against a real local
  Web3Signer+YubiHSM2 in the Sepolia/THORChain rehearsal.

## What is verifiable without hardware

Everything except the real YubiHSM2: the daemon's digest computation,
replay-DB conflict logic, PSBT-validation rule, and the coordinator
aggregation are fully unit/integration-testable with `wiremock`
(already a dev-dep, used in `crosscheck.rs`) mocking the Web3Signer HTTP
surface. Real-HSM verification belongs to the staged rehearsal, not the
in-sandbox gate. Mutation-test bar (≥70%, per global standard) applies
to the daemon digest + replay-guard + PSBT-validation paths — they are
the new #1 trust surface.

## Audit implication

This subsystem is in scope for the existing Rust audit budget and is
the highest-severity Rust surface (it authorises spends + attestations).
The audit must specifically cover: digest-computation parity between
daemon and contract (the keccak-double-hash hazard above), replay-DB
correctness under HA replicas, the cosigner PSBT-validation rule, and
Web3Signer mode configuration (must raw-sign the supplied 32 bytes, not
re-hash).

## Cross-references

- Trait seams: `crates/signer/src/lib.rs:48` (`HsmBackend`),
  `crates/executor/src/redeem.rs:146` (`MultisigCosigner`).
- Reference pattern: `memory/reference_rust_protocol_patterns.md` §B.
- Key material + disclosure: `docs/runbooks/key-ceremony.md`.
- Device hardening: `docs/runbooks/yubihsm2-provisioning.md`.
- Decision-lock: `memory/feedback_decision_locking.md` (M5 entry).
