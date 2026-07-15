# Assurance tooling (Rust)

The fast gate (`fmt` / `clippy -D warnings` / `test` / `deny` / `audit`) runs on
**every push and PR** via `.github/workflows/ci.yml` — equivalent to `just gate`.
Deeper, slower assurance runs in the **Assurance** workflow
(`.github/workflows/assurance.yml`, scheduled weekly + manual `workflow_dispatch`)
on GitHub runners rather than a local box that thrashes on full-workspace builds.
Both repositories consume the one reviewed `config/assurance-tools.json`
manifest in the Solidity repository. The services workflows fetch only that
manifest and its verifier, require their reviewed SHA-256 values, install exact
top-level versions, and verify reported versions before use.

## Declared MSRV

Rust 1.95.0 is the exact workspace `rust-version` and toolchain pin. It is the
lowest compiler installed and reproduced against this complete locked snapshot;
dependency metadata bottoms out at 1.90 but does not prove the workspace source
builds there. `scripts/check-msrv.sh` requires the manifest, toolchain file and
active `rustc` to match exactly, then runs
`cargo check --workspace --all-features --locked`. The dedicated CI `msrv` job
runs that gate on every push and pull request.

## Gate-3 release evidence

The compiled/static gate is necessary but does not prove the production trust
topology or evidence-retention controls. Its production-profile component runs
eight key-free startup-policy mutation matrices; source-string checks are
supplemental lint, not the behavioral proof. A release custodian must also run:

```bash
./scripts/check-gate3-release.sh \
  /secure/release/gate3-topology.json \
  /var/lib/xindex/evidence/price-signer \
  /var/lib/xindex/evidence/registry-signer \
  /var/lib/xindex/evidence/settlement-observer
```

The wrapper reruns ABI, production-profile, and declared-MSRV checks, validates
the checked-in Prometheus rules with `promtool`, rejects a collapsed or
placeholder operator topology, and verifies every evidence file plus its
inventory root. It requires real owner-only release artifacts and therefore is
not replaced by CI fixtures.
Alert routing, WORM export/reconciliation and incident-drill evidence remain
operator-controlled requirements described in
[`gate3-operations.md`](runbooks/gate3-operations.md).

## cargo-careful — UB + stdlib debug assertions

Runs the suite under a `std` built with debug assertions and extra UB checks.

```bash
cargo install --locked --version '=0.4.10' cargo-careful
cargo +nightly-2026-07-15 careful test --workspace
```

CI: `assurance.yml` → `careful` job.

## cargo-mutants — mutation testing

Mutates the source and re-runs the tests; surviving mutants reveal weak tests.

```bash
cargo install --locked --version '=27.1.0' cargo-mutants
cargo mutants --baseline=skip -p xindex-shared -p xindex-signer-daemon
```

CI scopes to the crypto + CTD-1 core (`xindex-shared` = eip712/RIC,
`xindex-signer-daemon` = intent/psbt gate). Drop the `-p` flags to mutate the
whole workspace (much longer). CI: `assurance.yml` → `mutants` job. The job is
`continue-on-error` (informational): a surviving mutant is a test-coverage
signal, not a regression, and a from-scratch run is multi-hour. Survivors still
surface as run annotations; the standing disposition is below.

> 8 GB box note: full-workspace builds thrash; run these in CI or scope to a
> single crate locally.

### Survivor triage (2026-06-15)

Baseline run: 615 candidates over `xindex-shared` + `xindex-signer-daemon`
(62 missed / 337 caught / 216 unviable).

**Excluded as universal noise** (`.cargo/mutants.toml`, 615 → 587): `Debug`/
`Display` `fmt` impls (no test asserts exact format output) and the wall-clock
`now_unix_secs` helpers (tests cannot pin `SystemTime::now()`; the recency/age
comparisons that consume the clock stay tested via injectable `now`).

**Closed** (golden vectors / boundary / record-then-check tests):

- `eip712`: the six `*_signing_hash` digests + the domain separator — these are
  the 32 bytes each k-of-n HSM signs; pinned golden vectors (`-> Default` died).
- `replay`: `record_*`/`check_*` idempotency **and Conflict** (divergent payload
  at the same identity) for safe / cosmos / xrp / tron on both the in-memory and
  Sqlite stores; `map_insert` non-unique-error classification.
- `server`: `hash_leg_payload` (layout-bound), `check_ric_sign_recency`
  future-skew + max-age boundaries (refactored to an injectable-`now` inner so
  the `>` is deterministically testable), `consume_cert_volume_gate` window-bucket
  arithmetic (extracted to `window_start_for`), fail-closed certificate-window
  conversion and 31-day maximum boundaries, `acc_error_code`.
- `cosmos_tx`: `bind_send_to_cert` native-denom mismatch (CTD bind cannot be a
  no-op). `intent`: `IntentPolicy::validate` quorum == whitelist boundary.
  `solana_tx`: `solana_kind_str`, forbidden-destination (`system_program`) arm.
- handler L10 race-recovery: the `if !matches!(e, Duplicate)` guard was
  duplicated across twelve signing handlers; extracted to one tested
  `must_propagate_record_error` helper. This removes the eight surviving
  `delete !` mutants and DRYs the recovery predicate — the attestation + psbt
  race tests confirm behaviour is unchanged. Same batch: `router` sol-route
  mount guard, `HsmError::into_response` (503, not a default 200), and
  `enforce_change_and_fee`'s fee == cap boundary (strict `>`).

**Equivalent / infeasible (won't-fix):**

- `validate_and_sign:272` `||`→`&&`: the two clauses (non-Solana family / chain
  ≠ configured chain) are perfectly correlated over the valid input domain (only
  one Solana chain exists), so the mutant is provably equivalent.
- `consume_cert_volume` `is_unique_violation` (×2): the unique-violation arm only
  fires on a concurrent INSERT race that is unreachable single-threaded (the
  in-memory test DB is per-connection); would require DB fault injection.
