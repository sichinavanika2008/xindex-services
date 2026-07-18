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
3. ../memory/VULTISIG-CUSTODY.md for the selected Wallet-as-a-Service custody
   direction and its fail-closed qualification gates.
4. ../memory/GATE-4-PREFLIGHT.md for the current key-free redesign and later
   testnet/failure-drill boundary.
5. ../AGENTS.md and this file.
6. Older README milestone tables and historical plans.

Code wins when documentation conflicts. Do not represent a historical custody
design, test count, or launch claim as current without checking the code and
the relevant runbook.

## Security-critical current state

The selected future custody direction is Vultisig Wallet as a Service using DKLS threshold signing; no production vault, share, deployment, or key use is approved.
Observation, RIC, and settlement certification remain a separate 3-of-5 quorum; 3-of-5 is not BTC custody.
Turnkey and Cobo are prohibited as current, backup, emergency, or rehearsal custody providers.

- The canonical cross-repository decision is
  [`memory/VULTISIG-CUSTODY.md`](../memory/VULTISIG-CUSTODY.md).
- The retired provider-specific crates, runtime, qualification gate, Gate-4
  checker, evidence templates and runbooks are removed. Do not restore or
  silently repoint historical `xindex-redeem` behavior.
- No Vultisig SDK, Verifier, Recipes or DKLS package is vendored yet. Pin exact
  source, dependency, binary and licence identities before adding one.
- `xindex-vultisig-adapter` is the key-free Bitcoin policy core. Preserve its
  public boundary: signing hashes are returned only after
  `authorize_vultisig_btc_spend` crosses custody-node and consumes the RIC/ACC
  one-shot. Do not expose its pure validator/hash derivation or add transport,
  signing or broadcast behavior without an explicit reviewed design.
- `BitcoinSpendPolicy` is trusted policy input, not proof of observation. A
  future runtime must construct it from Xindex's finalized, reorg-aware custody
  UTXO inventory and bind the observation/policy identity into evidence. Never
  deserialize permitted outpoints or values from the signing request.
- A Vultisig signer must derive hashes from the complete decoded transaction,
  apply the installed Xindex policy and consume the RIC/custody one-shot before
  releasing a threshold share. Never expose arbitrary blind-hash signing.
- Bitcoin policy must bind exact inputs/values, sequence/RBF, mandatory
  `SIGHASH_ALL`, absolute fee, ordered outputs, canonical memo, change and final
  transaction. The reviewed upstream output policy does not yet cover all of
  these fields.
- Threshold ECDSA exposes an aggregate signature, not participant roles in the
  Bitcoin witness. Evidence must bind participant set, threshold, policy,
  session and reshare epoch without pretending those roles are on-chain.
- Do not create a vault, share, credential, custody address, fund, sign, reshare,
  recover or broadcast without explicit user authorization.
- THORChain BTC output order is fund-critical: VOUT0 Asgard, optional VOUT1
  change to VIN0, final VOUT memo. Preserve `BTC-ORDER-01` regressions and gate
  every provider-returned unsigned transaction before signing.
- Gate 4 is not complete. Its replacement begins with key-free Vultisig policy,
  aggregate-evidence and failure-domain tests; later key use and test-network
  rehearsal require separate authorization. The older 3-of-5 custody rehearsal
  is historical and cannot substitute.
- EVM-family THORChain router addresses in the chain registry are deliberately
  zero-address placeholders. They are not deployment configuration.

## Important implementation areas

- custody-node contains the provider-neutral approval decision core. Preserve
  reconstructed-payload binding, fee caps, replay protection, one-shot
  consumption, and fail-closed behavior. The policy adapter consumes this
  boundary; a future Vultisig runtime must preserve it and add final-transaction
  revalidation rather than replace it.
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
