# xindex-services — Codex Project Guide

## Role and entry point

This repository contains Xindex's off-chain Rust services: observers,
attestations, custody, native-chain execution, relaying, and operational tools.

Read the [shared protocol guide](../Xindex/AGENTS.md) first. This file is its
Rust-specific supplement and the active local working context for Codex/GPT
agents. Legacy AI plans, memories, and out-of-tree paths are archival context
only; they are not required to understand or work on this repository.

## Source of truth

1. Current Rust source, tests, and Git history.
2. The recent sections of this repository's KNOWN_FINDINGS.md.
3. docs/runbooks/turnkey-custody-devenv.md for the provisional Turnkey wire and
   its validation gates.
4. ../Xindex/AGENTS.md and this file.
5. Older README milestone tables and historical plans.

Code wins when documentation conflicts. Do not represent a historical custody
design, test count, or launch claim as current without checking the code and
the relevant runbook.

## Security-critical current state

- Turnkey holds one complete key in an attested enclave. It is not MPC and not
  a key-share split. Independent Xindex approvers must approve signing
  activity; compromise of the enclave remains an accepted residual risk.
- The xindex-turnkey-approver binary is deliberately --dev gated. Do not lift
  that gate, enable production wiring, or configure real custody addresses
  without explicit founder authorization after the listed validation gates.
- Before mainnet funds, reconcile the real Turnkey wire, prove BTC signet with
  the required OP_RETURN, prove EVM Sepolia and tamper rejection, complete the
  post-June custody audit, and rehearse operations and ceremonies.
- EVM-family THORChain router addresses in the chain registry are deliberately
  zero-address placeholders. They are not deployment configuration.

## Important implementation areas

- custody-node and turnkey-client implement the Turnkey signing and approver
  flow. Preserve reconstructed-payload binding, fee caps, replay protection,
  one-shot consumption, and fail-closed behavior.
- executor contains chain-family redemption construction. Native custody
  spends must remain bound to independently verified intent evidence.
- signer-daemon, observer, relayer, and shared contain the EIP-712 and
  cross-chain attestation paths. Preserve domain separation, quorum checks,
  finality handling, and replay defenses.
- The price-signing code has a production-completion gap: no implemented
  collector/poster submits attestPrice, signer output omits supply, and quorum
  signers need a deliberate byte-identical message-coordination mechanism.
  Treat that as a fail-closed functionality blocker.

## Working rules

- Read the relevant recent finding and preserve its regression coverage before
  changing custody, signing, or cross-chain settlement code.
- Use cargo fmt --all -- --check before handoff. Run focused custody tests when
  touching those crates; the full workspace can stall on this Mac during
  codegen/Spotlight indexing, so use CI or a non-Spotlight CARGO_TARGET_DIR for
  the full gate.
- Never introduce a silent fallback, a coordinator-trusted spending path, a
  real key, or a mainnet endpoint to make local development easier.
- Preserve user changes and do not reset, delete, broadcast, or run key
  ceremonies without explicit authorization.
