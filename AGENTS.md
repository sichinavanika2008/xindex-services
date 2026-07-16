# xindex-services — Codex Project Guide

## Role and entry point

This repository contains Xindex's off-chain Rust services: observers,
attestations, custody, native-chain execution, relaying, and operational tools.

Read the [shared protocol guide](../AGENTS.md) first. This file is its
Rust-specific supplement and the active local working context for Codex/GPT
agents. Legacy AI plans, memories, and out-of-tree paths are archival context
only; they are not required to understand or work on this repository.

## Source of truth

1. Current Rust source, tests, and Git history.
2. The recent sections of this repository's KNOWN_FINDINGS.md.
3. docs/runbooks/bitgo-custody-devenv.md for the selected future BTC custody
   model and its fail-closed qualification gates.
4. docs/runbooks/gate4-bitgo-rehearsal.md for the current testnet/failure-drill
   closure gate and evidence format.
5. ../AGENTS.md and this file.
6. Older README milestone tables and historical plans.

Code wins when documentation conflicts. Do not represent a historical custody
design, test count, or launch claim as current without checking the code and
the relevant runbook.

## Security-critical current state

The selected future BTC custody model is BitGo native P2WSH 2-of-3 (user, independently held offline backup, and BitGo); mainnet remains disabled and unapproved.
Observation, RIC, and settlement certification remain a separate 3-of-5 quorum; 3-of-5 is not BTC custody.
Turnkey and Cobo are prohibited as current, backup, emergency, or rehearsal custody providers.

- This native-P2WSH model is not MPC. The canonical cross-repository decision
  is [`memory/BITGO-CUSTODY.md`](../memory/BITGO-CUSTODY.md).
- The BitGo capture validator is offline-only and cannot authenticate
  caller-supplied provider provenance. It must remain blocked until a reviewed,
  independently pinned evidence envelope is implemented. Do not create an account,
  wallet or key, use credentials, configure real custody addresses, fund,
  sign, approve or broadcast without explicit user authorization.
- `xindex-bitgo-adapter` is the shared key-free request/policy core. Keep it
  free of HTTP tokens, private-key inputs, signing, approvals and broadcast;
  preserve exact build fields, native P2WSH, non-RBF, absolute fee, ordered
  outputs and cryptographic user/BitGo role checks.
- `xindex-bitgo-client` owns the fixed official origins, explicit Auth V2/V3
  HMAC requests, hashed bearer transport, HMAC/freshness-verified response
  envelopes and durable SQLite workflow. Request JSON must be serialized once
  and those exact bytes authenticated and sent. Keep
  private-key and approval-mutation inputs out of this crate. The irreversible
  `tx/send` call must remain private to `BitGoCoordinator`, after an atomic
  send reservation; retries reconcile by `sequenceId` and never blindly send
  again. Before build completion, retain the exact wallet response and one
  immutable canonical hot/on-chain 2-of-3 wallet snapshot. A pending approval
  must never release the reservation: reconciliation may use only read-only
  approval/transfer GETs, never an approval mutation; rejection is terminal,
  and any approved/rebuilt final transaction must pass the original exact
  policy and user/BitGo role-signature checks.
- Preserve the coordinator's
  `build -> intent_authorized -> user_signed` transition. The middle phase
  exists only after the exact retained PSBT passes the provider-neutral
  RIC/output bind and consumes the durable
  `(BTC, redemptionId, legIndex)` one-shot. Never expose public receipt
  injection, accept a user signature directly from `built`, or remove the
  authorization-expiry check.
- Its schema-v2 canonical evidence manifest is unsigned and tamper-detecting
  only. A response HMAC is symmetric under the token and is not independent
  provider provenance. Do not call the bundle authenticated until reviewer
  trust anchors, signature verification and independent raw-chain/provider
  corroboration are selected, pinned and independently reviewed.
- `xindex-bitgo-custody` is the only runtime activation of the new coordinator.
  Preserve its Testnet4-only/mainnet-refusal gate, owner-only single-link file
  checks, durable databases, capability-empty default, authorization ID/time
  window/satoshi cap checks and exact sequence acknowledgement before submit.
  Never add a private-key input or silently repoint historical `xindex-redeem`.
- No live BitGo account, wallet, key or transaction evidence exists. BitGo is
  selected with a disabled-by-default Testnet4 runtime, not production-approved.
- THORChain BTC output order is fund-critical: VOUT0 Asgard, optional VOUT1
  change to VIN0, final VOUT memo. Preserve `BTC-ORDER-01` regressions and gate
  every provider-returned unsigned transaction before signing.
- Before mainnet funds, prove the exact BitGo user/backup/provider key topology,
  explicit P2WSH and PSBT policy, BTC Testnet4 plus controlled THORChain-devnet
  execution, recovery and tamper rejection; then complete the custody re-audit,
  operational rehearsals and ceremonies. Non-BTC custody remains disabled.
- Gate 4 is not complete. The current BitGo-aware 23-drill
  `xindex-gate4-check` validates shape and local hashes only, reports
  `format_valid`, and exits blocked. Closure requires authenticated
  provider/reviewer provenance, commit resolution, independent review and
  explicit user acceptance. The older 3-of-5 custody rehearsal is historical
  and cannot substitute.
- EVM-family THORChain router addresses in the chain registry are deliberately
  zero-address placeholders. They are not deployment configuration.

## Important implementation areas

- custody-node contains the provider-neutral approval decision core. Preserve
  reconstructed-payload binding, fee caps, replay protection, one-shot
  consumption, and fail-closed behavior. bitgo-dev-gate qualifies the selected
  BTC transaction boundary without creating, signing or broadcasting.
- executor contains chain-family redemption construction. Native custody
  spends must remain bound to independently verified intent evidence.
- signer-daemon, observer, relayer, and shared contain the EIP-712 and
  cross-chain attestation paths. Preserve domain separation, quorum checks,
  finality handling, and replay defenses.
- The price path now includes supply, exact raw evidence, multi-source
  median/TWAP signing, byte-identical tuple collection and a permissionless
  `attestPrice` poster. Production operator/source independence, metrics/alerts,
  retention exercises and independent review remain gates.
- The current registry path has exact EIP-712 signer and collector cores plus
  durable signature/nonce state, but no complete live inbound-state/quote
  policy producer and poster. Treat that as a fail-closed functionality
  blocker.

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
