# xindex-services

Off-chain Rust services for the [Xindex](../) portfolio protocol. This is a
separate Git repository nested inside the Solidity workspace, with independent
history, CI and audit scope.

Read the [shared repository guide](../AGENTS.md), this repository's
[local guide](AGENTS.md), and the recent sections of [KNOWN_FINDINGS.md](KNOWN_FINDINGS.md)
before changing a security-sensitive path. Current source and reproduced tests
take precedence over historical milestone prose.

## Current status

The workspace contains 24 packages spanning shared protocol types, EVM and
native-chain clients, signers, custody, executors, relayers and operations.
The 2026-07-13 Gate-3 delta adds:

- eight manifested current Solidity ABIs and an exact drift gate;
- all seven current EIP-712 report types with Rust/Solidity vectors;
- durable registry signature reservation and quote-nonce state;
- exact inbound-state/quote signer and collector cores;
- fail-closed three-source THOR agreement;
- a multi-source price signer and exact untrusted collector/poster with raw
  evidence and anomaly refusal; and
- production-profile checks that require durable state, mTLS and an external
  HSM boundary while keeping software/raw-key paths dev-only.

Gate 3 nevertheless remains **FAIL/open**. The current tree does not provide a
complete live inbound/quote producer/poster, every current mint/redemption
observer/poster, finalized/reorg-safe state, a policy-complete native custody
executor, demonstrated production monitoring, independent operator/HSM/source
records, or an independent audit. Do not connect it to value-bearing systems.

## Historical milestone snapshot

| Milestone | Status |
|---|---|
| **M1** — workspace skeleton + `xindex-watch` binary | In progress |
| M2 — software-key signer + Anvil E2E | — |
| M3 — THORChain stagenet + Bitcoin signet | — |
| M4 — multi-signer + relayer + executor | — |
| M5 — YubiHSM2 + ops + adversarial | — |
| M6 — audits + mainnet | — |

This table is retained as historical context and can be stale. Use the current
guides, code, tests, and runbooks rather than an old planning document to judge
readiness or launch gates.

## Local development

```bash
# Static and compile-only no-key audit gate:
./scripts/check-abi.sh --solidity-root ..
./scripts/check-production-profile.sh
cargo fmt --all -- --check
cargo clippy --offline --locked --workspace --all-targets --all-features -- -D warnings
cargo test --offline --locked --workspace --all-features --no-run
cargo deny check
cargo audit --no-fetch --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2026-0185
```

`--no-run` compiles signer and custody tests but does not execute signature
operations. See `just gate` and CI for the full authorized test gate.

## End-to-end against local Anvil

```bash
just anvil      # separate terminal; deterministic local chain only
just e2e-anvil  # deploys local fixtures and runs xindex-watch
```

These recipes use public deterministic Anvil keys and `--dev` service paths.
They are local fixtures, not production evidence. See `justfile` for individual
recipes.

## Toolchain

Pinned to Rust 1.95.0 in `rust-toolchain.toml`; CI mirrors the same version and
pins action revisions to immutable SHAs.
