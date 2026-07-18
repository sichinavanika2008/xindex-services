# xindex-services

Off-chain Rust services for the [Xindex](../) portfolio protocol. This is a
separate Git repository nested inside the Solidity workspace, with independent
history, CI and audit scope.

Read the [shared repository guide](../AGENTS.md), this repository's
[local guide](AGENTS.md), and the recent sections of [KNOWN_FINDINGS.md](KNOWN_FINDINGS.md)
before changing a security-sensitive path. Current source and reproduced tests
take precedence over historical milestone prose.

## Current status

The workspace contains 24 packages, 62 targets and 24 binaries spanning shared
protocol types, EVM and native-chain clients, signers, custody, executors,
relayers and operations.
The published 2026-07-13 historical remote-HSM Gate-3 candidate plus its
current local successors provide:

- ten manifested current Solidity ABIs and an exact drift gate;
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

The local 2026-07-16 delta adds `xindex-native-router`, a fail-closed library
core for the parent repository's new NativeRouteRegistry and
MultiRailAsyncAdapter. It represents all 17 current Chainflip assets with exact
contract IDs and dynamically catalogs every unambiguous Maya pool whose status
is `Available`, plus CACAO. Live discovery can disable eligibility but never
enable an Xindex asset. The core validates current provider state, quotes,
Chainflip DCA/Maya streams, quote-recommended Chainflip slippage/live-price and
retry bounds, zero broker commission, exact Vault/Router payloads,
provider/native decimal scaling, independent-reference cost, deterministic
lowest-cost selection, finalized multi-RPC registry state and exact Solidity
EIP-712/mint hints. It is not wired into a production signer daemon, custody
executor or broadcaster. Non-BTC custody and provider-specific native
redemption builders remain absent and disabled.

The selected future custody direction is Vultisig Wallet as a Service using DKLS threshold signing; no production vault, share, deployment, or key use is approved.
Observation, RIC, and settlement certification remain a separate 3-of-5 quorum; 3-of-5 is not BTC custody.
Turnkey and Cobo are prohibited as current, backup, emergency, or rehearsal custody providers.
The retired provider-specific adapter, client, runtime, qualification gate,
Gate-4 checker, evidence templates and runbooks are removed. Provider-neutral
RIC, replay, one-shot, exact transaction-binding, Bitcoin output-order and
containment controls remain. The first key-free `xindex-vultisig-adapter`
policy slice consumes the custody-node boundary; it is not a signer or custody
runtime. The canonical cross-repository decision is
[`memory/VULTISIG-CUSTODY.md`](../memory/VULTISIG-CUSTODY.md).

No Vultisig dependency is vendored yet. The adapter privately validates a v0
PSBT and exact ordered Bitcoin inputs/values, version, locktime, final sequence, explicit
`SIGHASH_ALL` and absolute fees, derives every BIP143 hash, then returns them
only after RIC/ACC output validation and one-shot consumption. Gate 4 remains
blocked on the upstream runtime, Testnet4 isolation, final-transaction checks,
finalized/reorg-aware UTXO-policy provenance, aggregate-signature evidence,
reshare epochs and failure-domain tests. See
[`memory/GATE-4-PREFLIGHT.md`](../memory/GATE-4-PREFLIGHT.md).

The code-addressable Gate-3 findings are published, while the Chainflip/Maya
router, ABI refresh and custody transition are later local work. This is
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
cargo test --offline --locked -p xindex-native-router
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
