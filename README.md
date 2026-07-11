# xindex-services

Off-chain Rust services for the [Xindex](../Xindex/) omnichain portfolio
protocol. Sibling repo to the Solidity layer; independent git history,
CI, and audit scope.

The on-chain (Solidity) layer cannot finalize a single async mint or
settle a single redeem until the services in this repo ship. Read the
[shared Codex/GPT project guide](../Xindex/AGENTS.md) and this repository's
[local guide](AGENTS.md) before making changes. They replace prior AI-session
plans as the active operating context; current source, tests, the recent
findings, and the Turnkey runbook are authoritative.

## Crates

| Crate | Role |
|---|---|
| `shared` | Domain types: `IntentId`, `AttestationDigest`, EIP-712 typed-data structs mirroring `AttestationOracle.sol`; alloy `sol!` bindings re-exports. |
| `chain-eth` | Ethereum provider, log-stream, contract bindings. RPC redundancy + reorg handling. Hosts the `xindex-watch` binary. |
| `chain-thor` | THORChain Tendermint RPC client. Polls `/inbound_addresses`, `/pools`, `/tx/<hash>`. |
| `chain-btc` | Bitcoin Core RPC + Esplora fallback. UTXO watching, confirmation tracking, PSBT construction via `bdk`. |
| `signer` | 3-of-5 attestation signer daemon. `HsmBackend` trait with software-key impl (dev) and YubiHSM2 impl (prod). EIP-712 sign + post. |
| `multisig` | Bitcoin multisig signer. PSBT in, partially-signed PSBT out, HSM-backed key. |
| `relayer` | Watches `IntentQueue`. Retries THORChain Router calls on partner-side failure. Triggers `cancelMint` on deadline expiry. |
| `executor` | Watches `RedeemDispatched` events. Constructs Bitcoin PSBTs, coordinates 3-of-5 multisig signing rounds, broadcasts. |
| `ops` | Prometheus metrics, structured tracing/logging, alerting glue, on-call runbook. |

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
# Strict gate (matches CI):
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check
cargo audit
```

## End-to-end against local Anvil

```bash
just e2e-anvil  # spins up Anvil, deploys Phase 1+2, runs xindex-watch
```

See `justfile` for individual recipes.

## Toolchain

Pinned via `rust-toolchain.toml` (currently `stable`). Re-pin to a
specific version once M1 ships and audit reproducibility matters.
