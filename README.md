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
containment controls remain. The key-free `xindex-vultisig-adapter` policy,
finalization and aggregate-evidence slices consume the custody-node boundary;
they are not a signer or custody runtime. The canonical cross-repository decision is
[`memory/VULTISIG-CUSTODY.md`](../memory/VULTISIG-CUSTODY.md).

No Vultisig dependency is vendored yet. The adapter privately validates a v0
PSBT and exact ordered Bitcoin inputs/values, version, locktime, final sequence,
explicit `SIGHASH_ALL` and absolute fees, derives every BIP143 hash, then returns
them only after RIC/ACC output validation and one-shot consumption. The immutable
approval then revalidates the exact finalized body, strict two-item P2WPKH
witnesses, mandatory `SIGHASH_ALL`, canonical 33-byte compressed aggregate
public key and each ECDSA signature.

The finalized receipt can now be consumed into a non-cloneable
`VultisigBitcoinEvidence` handoff. Its domain-separated serialized record binds
the exact transaction, aggregate key, policy/provenance, custody certificate,
referenced upstream release-manifest digest, vault, canonical distinct
configured DKLS participant set, threshold, session and reshare epoch. It does
not claim configured participant roles are visible in the Bitcoin witness.

`VultisigBitcoinBroadcastRuntime::prepare` is now the integrated key-free
preparation boundary. It consumes the non-cloneable evidence, repeats exact
Testnet4/canonical-byte/txid/wtxid checks, and durably writes the complete
evidence plus exact bytes before returning a prepared handle. The same sealed
runtime owns a target- and observer-policy-bound file-backed SQLite
`prepared → submitting → accepted → finalized` state machine. Its production
target requires a normalized HTTPS DNS URL, reviewed operator identity record,
normal WebPKI validation and an exact leaf-certificate pin set; it also
authenticates exact Testnet4 genesis and POSTs lower hex derived directly from
persisted bytes. The broadcast store requires a canonical private parent and
owner-only regular database file and rejects symlinks, hard links, wrong modes,
unexpected sidecars and later path replacement. CAS admits one initial
`prepared → submitting` claimant, possible sends remain durable ambiguity,
byte-identical raw transactions are required for reconciliation, and a durable
prepared row can resume after restart even if the process failed after commit
but before returning its handle. Explicit recovery may idempotently resend only
the same stored bytes. Terminal finalization consumes the observer's opaque
final-transaction capability and atomically binds the expected source set,
exact transaction identities/bytes, confirmation arithmetic, canonical block
and observation evidence. There is no public raw-byte or generic-client
submission route. The audit evidence intentionally carries the signed bytes;
Rust types do not make them globally non-copyable or the wider system
non-bypassable. The initial generic-client broadcaster was rejected because it
did not authenticate Testnet4 or guarantee exact witness bytes.

The adapter's only public policy constructor now consumes an opaque capability
issued by `xindex-chain-utxo::finalized_inventory`, not caller-supplied UTXO
fields. That SQLite journal is Testnet4-only, enforces the protocol six-block
finality floor and exact custody script, records sequential block and
creation/spend facts transactionally, invalidates capabilities across rollback
epochs or spends, and commits a durable random journal ID so an independently
created matching database cannot substitute for the issuer through the normal
API. Authorization rechecks the capability immediately before custody and final
handoff rechecks it after validating the exact bytes.

The new `xindex-chain-utxo::trusted_observer` is the sole non-test journal
writer. It accepts at least two exact HTTPS DNS-host sources, authenticates the
Testnet4 genesis bytes before opening its owner-only/non-symlink SQLite file,
durably pins the source-set commitment, requires equal source tips, corroborates
canonical raw block bytes and local PoW/commitments, and resamples tips before
granting a two-minute policy-freshness lease. A source-pinned
`VultisigBitcoinPolicyRuntime` carries its read-only policy source through
issuance, authorization and final handoff. Coinbase outputs are deliberately
excluded until their 100-block maturity is modeled. The observer also issues a
non-forgeable final-transaction observation only after stable two-sample
status/tip/checkpoint corroboration, exact block/transaction-byte derivation,
the configured confirmation floor and a caught-up retained inventory all agree.

These remain library primitives: no workspace binary pins an approved endpoint
set, drives or monitors the observer, produces the evidence, or makes the
sealed runtime mandatory. Configured HTTPS sources are still trusted for
canonical-chain selection, transaction validity and difficulty transitions;
the single exact-pinned broadcast target is still trusted for availability and
its acceptance response. Distinct hostnames do not prove independent operators.
Owner-only storage does not prevent same-UID direct edits or copied-database
substitution. `accepted` means exact target response or exact raw
reconciliation; only a matching configured-source observation advances the row
to `finalized`, and that observation is not independent full-node consensus.
Gate 4 remains blocked on binary/mandatory runtime wiring, actual approved
endpoint/operator/certificate and source identities, full-node or independently
reviewed source topology, upstream integration and approved release manifest,
runtime evidence production/persistence, ongoing confirmation monitoring, real
participant/reshare topology and failure-domain tests. See
[`memory/GATE-4-PREFLIGHT.md`](../memory/GATE-4-PREFLIGHT.md).

The key-free Rust 1.95.0 gate passes format, 8/8 compiled production-profile
behaviors and supplemental lints, all ten ABI manifest/current-parent checks,
locked/offline strict whole-workspace all-target/all-feature Clippy, all-feature
test compilation and cargo-deny with configured warnings. Focused execution is
65/65 chain-utxo tests, 30/30 adapter tests, 28/28 executor Vultisig broadcast
tests and five adapter compile-fail doctests. The executor passes 104/104
library tests and 5/5 doctests offline/locked. The
unchanged production-profile wrapper passes directly.

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
