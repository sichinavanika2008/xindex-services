# Assurance tooling (Rust)

The fast gate (`fmt` / `clippy -D warnings` / `test` / `deny` / `audit`) runs on
**every push and PR** via `.github/workflows/ci.yml` — equivalent to `just gate`.
Deeper, slower assurance runs in the **Assurance** workflow
(`.github/workflows/assurance.yml`, scheduled weekly + manual `workflow_dispatch`)
on GitHub runners rather than a local box that thrashes on full-workspace builds.

## cargo-careful — UB + stdlib debug assertions

Runs the suite under a `std` built with debug assertions and extra UB checks.

```bash
cargo install cargo-careful --locked
cargo +nightly careful test --workspace
```

CI: `assurance.yml` → `careful` job.

## cargo-mutants — mutation testing

Mutates the source and re-runs the tests; surviving mutants reveal weak tests.

```bash
cargo install cargo-mutants --locked
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
  arithmetic (extracted to `window_start_for`), `acc_error_code`.
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
