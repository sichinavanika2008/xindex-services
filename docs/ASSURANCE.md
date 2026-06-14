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
whole workspace (much longer). CI: `assurance.yml` → `mutants` job.

> 8 GB box note: full-workspace builds thrash; run these in CI or scope to a
> single crate locally.
