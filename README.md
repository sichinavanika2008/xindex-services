# xindex-services

Off-chain Rust services for the [Xindex](../) portfolio protocol. This is a
separate Git repository nested inside the Solidity workspace, with independent
history, CI and audit scope.

Read the [shared repository guide](../AGENTS.md), this repository's
[local guide](AGENTS.md), and the recent sections of [KNOWN_FINDINGS.md](KNOWN_FINDINGS.md)
before changing a security-sensitive path. Current source and reproduced tests
take precedence over historical milestone prose.

## Current status

The workspace contains 25 packages spanning shared protocol types, EVM and
native-chain clients, signers, custody, executors, relayers and operations.
The published 2026-07-13 historical remote-HSM Gate-3 code candidate adds:

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
- a retained, historical production-gated BTC custody executor that reserves before HSM work,
  validates the RIC/full transaction policy, persists the F2 correlation and
  exact transaction bytes before broadcast, and only rebroadcasts those bytes;
- one-to-one logical/physical native and ERC-20 inflow ledgers; and
- supervised metrics, checked-in Prometheus alerts, evidence verification,
  release topology validation and incident/retention runbooks.

The selected future BTC custody model is BitGo native P2WSH 2-of-3 (user, independently held offline backup, and BitGo); mainnet remains disabled and unapproved.
Observation, RIC, and settlement certification remain a separate 3-of-5 quorum; 3-of-5 is not BTC custody.
Turnkey and Cobo are prohibited as current, backup, emergency, or rehearsal custody providers.
The reusable key-free request/policy adapter, offline capture validator and
new `xindex-bitgo-client` transport/orchestration library and Testnet4-only
`xindex-bitgo-custody` runtime are present, while
the former provider implementations and operational runbooks have been
removed. The client fixes official origins and coin/environment pairing,
uses explicit BitGo Auth V2/V3 HMAC with a hashed bearer token, verifies and
retains bounded authenticated response envelopes, and stores content-addressed
artifacts plus a canonical validated wallet-topology snapshot in a durable
SQLite write-ahead workflow, and permits at most one final-sign-and-broadcast
POST per sequence. A send-reserved retry reconciles by `sequenceId`; a
pending approval is polled only through read-only approval/transfer endpoints,
rejection is terminal, and an approved final transaction must still equal the
original exact PSBT policy. The coordinator reuses the provider-neutral
RIC/output gate: the exact built PSBT must consume the durable redemption-leg
one-shot and enter `intent_authorized` before any user-signed transaction can
be retained; expired authorization fails closed. Pending approval never
reopens the reservation. Its schema-v2 canonical manifest binds the HMAC
version but is unsigned. Response HMAC authenticates the channel under the
shared access token; it is not asymmetric independent provider provenance.
No private-key or approval-mutation input exists. The dedicated runtime rejects
production/mainnet, requires owner-only files and durable databases, and keeps
every state-changing capability closed until an unexpired written authorization
record, satoshi cap and matching authorization ID enable it; submit also
requires the exact sequence acknowledgement. The legacy `xindex-redeem` binary
is not wired to this path. BitGo remains unapproved pending live Testnet4 and
controlled THORChain-devnet evidence, independent provenance/review and
production activation. Non-BTC production custody remains unselected and
disabled. The canonical cross-repository decision is
[`memory/BITGO-CUSTODY.md`](../memory/BITGO-CUSTODY.md).

Gate 4 now has a BitGo-aware closure runbook, a complete 23-drill evidence
template and the offline `xindex-gate4-check` structural validator. A valid
self-authored bundle is labeled `format_valid` and exits blocked, never passed.
These additions make
the open state auditable; they do not replace the missing live BitGo, Sepolia,
Bitcoin Testnet4, controlled THORChain devnet, independent-operator and alert/WORM
evidence.

The BitGo adapter and gate test the exact P2WSH Bitcoin input, request fields,
fee, signer roles and THORChain VOUT policy; the gate binds its report to the
exact evidence-file SHA-256. No live BitGo evidence exists. The key-free
preflight also found and locally fixed the
pre-deployment THORChain change/memo output-order defect recorded as
`BTC-ORDER-01`.

The code-addressable Gate-3 findings are closed through pushed checkpoint
`9954f1c`; the BitGo client is a later intentional uncommitted delta. This is
not production approval: real independent
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
# Compiled behavioral + static no-key audit gate:
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

`check-production-profile.sh` is narrower: it executes exactly eight compiled,
key-free startup-policy mutation tests (one per production entry point) before
its supplemental source/document lints. The tests use unreadable dummy secret
paths and fail unless policy rejection happens before secret I/O, network
construction, or listener binding. See
[`docs/runbooks/gate3-release.md`](docs/runbooks/gate3-release.md).

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

Rust 1.95.0 is both the declared MSRV and the exact pin in
`rust-toolchain.toml`. It is the lowest compiler reproduced for the complete
locked workspace in this snapshot; the dependency metadata alone has a lower
1.90 floor but is not a whole-workspace build proof. `scripts/check-msrv.sh`
requires manifest/toolchain/compiler equality and runs
`cargo check --workspace --all-features --locked`; CI has a dedicated job for
that gate. Action revisions remain pinned to immutable SHAs.
