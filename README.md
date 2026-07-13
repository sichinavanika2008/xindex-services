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
The 2026-07-13 Gate-3 code candidate adds:

- eight manifested current Solidity ABIs and an exact drift gate;
- all seven current EIP-712 report types with Rust/Solidity vectors;
- live fail-closed inbound-state and exact-quote signer/coordinator services,
  with three-source THOR agreement, durable reservations and serialized nonce
  state;
- a finalized Ethereum observer journal with checkpoint continuity, rollback,
  exact same-transaction mint pairing and current mint/delivery/refund/streamed
  settlement certification;
- exact settlement and price collectors, pinned mutual TLS, threshold-roster
  checks, bounded raw evidence and anomaly refusal;
- a production-gated BTC custody executor that reserves before HSM work,
  validates the RIC/full transaction policy, persists the F2 correlation and
  exact transaction bytes before broadcast, and only rebroadcasts those bytes;
- one-to-one logical/physical native and ERC-20 inflow ledgers; and
- supervised metrics, checked-in Prometheus alerts, evidence verification,
  release topology validation and incident/retention runbooks.

The code-addressable Gate-3 findings are closed in the current uncommitted
candidate on top of `f22b71a`. This is not production approval: real independent
operator/HSM/source records, alert delivery and WORM-retention drills, testnet
rehearsal, a pinned clean release commit, and independent audit evidence do not
exist in this checkout. Do not connect it to value-bearing systems.

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

The release-evidence wrapper additionally requires a real owner-only topology
registry, one or more populated evidence directories, and `promtool`:

```bash
./scripts/check-gate3-release.sh \
  /secure/release/gate3-topology.json \
  /var/lib/xindex/evidence/ROLE
```

It intentionally cannot pass against placeholders or an empty evidence set.

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
