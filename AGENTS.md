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
  public boundary: signing hashes are returned only after the source-pinned
  `VultisigBitcoinPolicyRuntime::authorize` path crosses custody-node and
  consumes the RIC/ACC one-shot. Its immutable approval provides exact
  finalized-transaction, P2WPKH-witness, canonical 33-byte compressed
  aggregate-public-key and ECDSA revalidation. The non-cloneable
  `VultisigBitcoinEvidence` capability can only be created by consuming
  `FinalizedBitcoinSpend`; it binds the reviewed-release manifest digest,
  configured participant topology, threshold, session, reshare epoch,
  policy/provenance, custody certificate, aggregate key and exact transaction.
  `VultisigBitcoinBroadcastRuntime::prepare` is the integrated key-free
  write-ahead boundary: it consumes that evidence, rechecks exact
  Testnet4/canonical bytes/txid/wtxid, durably writes the complete record and
  exact bytes, and only then returns a non-cloneable prepared capability with
  no byte extraction. The same sealed runtime owns a target- and finality-
  policy-bound file-backed SQLite
  `prepared → submitting → accepted → finalized` state machine. Production
  target construction requires a normalized HTTPS DNS URL, reviewed operator
  identity record and exact leaf-certificate pin set while retaining normal
  WebPKI validation; the runtime also authenticates exact Testnet4 genesis,
  submits persisted-byte lower hex, and reconciles only byte-identical raw
  bytes. The store requires canonical owner-only paths and rejects symlinks,
  hard links, wrong modes, unexpected sidecars and later path replacement. CAS
  admits one initial `prepared → submitting` claimant, possible sends remain
  ambiguous, and runtime-owned durable prepared rows resume after restart,
  including a commit completed before the in-memory handle returned. Explicit
  ambiguous recovery may idempotently resend only the same stored bytes.
  Terminal finalization consumes only
  `FinalizedBitcoinTransactionObservation`, requires its configured source-set
  identity, txid, wtxid, exact-byte digest and confirmation arithmetic to match
  the immutable row, and durably records the observation evidence. The first
  attempted generic-client broadcaster was rejected in review because checking
  the evidence chain hash does not authenticate the destination endpoint and a
  parsed-transaction API cannot prove exact-witness-byte submission. The
  runtime remains optional library composition, not binary/mandatory wiring or
  production approval. Do not expose the pure validator/hash derivation or a
  public raw-byte/generic-client submission path.
- `xindex-chain-utxo::{trusted_observer,finalized_inventory}` form the key-free
  observation/provenance boundary. The observer is the only non-test owner of
  journal mutation authority. It requires at least two exact HTTPS DNS-host
  sources, authenticates Testnet4 genesis before opening storage, pins their
  ordered URL/ID commitment durably, requires equal tip heights before sync,
  corroborates canonical raw block bytes from every source, and resamples equal
  tips before granting a two-minute policy lease. The journal records sequential
  checkpoints and exact non-coinbase custody UTXO creation/spend facts, rolls
  reorgs back atomically while advancing an epoch, and issues opaque capabilities
  only for exact six-confirmation-or-deeper unspent P2WPKH inputs. A durable
  random journal ID prevents a separately created matching database from
  substituting for the issuing journal through the API. The same observer can
  issue an opaque final-transaction observation only after two stable status,
  tip and checkpoint samples bind exact canonical bytes and the retained
  inventory remains caught up through the corroborated tip.
- `BitcoinSpendPolicy::new_testnet4` accepts only that opaque capability; raw
  outpoints, values, scripts and provenance fields have no public constructor or
  deserialization path. Authorization and finalized-transaction handoff both
  recheck the capability against current journal state. Preserve those checks
  immediately before custody one-shot consumption and after finalized-byte
  validation.
- The raw SQLite writer/source constructors are crate-private; only the observer
  yields a read-only source, and the Vultisig policy runtime pins that source for
  issuance, authorization, and final handoff. Preserve this authority boundary.
  The `test-utils` journal harness is feature-gated and must never be used by a
  deployed runtime.
- This is an authenticated configured-source library, not an independent full
  node or deployed production observer. HTTPS hostnames are not pinned operator
  identities, distinct hosts do not prove independent operators, and local
  checks do not validate Bitcoin scripts, all consensus rules, or difficulty
  transitions. No binary pins an approved endpoint set, runs the sync/freshness
  loop, or monitors it. Owner-only non-symlink SQLite handling does not protect
  against same-UID direct edits or copied database snapshots. Preserve these
  residuals, require equal source tips, keep coinbase outputs excluded until
  100-block maturity is modeled, and make the validated final receipt mandatory
  at a future broadcaster. Never deserialize permitted outpoints or values from
  a signing request or describe the current library as production chain proof.
- Preserve `BitcoinSpendPolicy::new_testnet4` as the only public policy
  constructor. It must reject every chain hash except Testnet4 and carry that
  identity through approval/finalization. The observer must continue deriving
  it from exact endpoint-returned genesis bytes; `tb` address encoding alone is
  not network evidence.
- A Vultisig signer must derive hashes from the complete decoded transaction,
  apply the installed Xindex policy and consume the RIC/custody one-shot before
  releasing a threshold share. Never expose arbitrary blind-hash signing.
- Bitcoin policy must bind exact inputs/values, sequence/RBF, mandatory
  `SIGHASH_ALL`, absolute fee, ordered outputs, canonical memo, change and final
  transaction. Preserve the local pre-signing and final-transaction checks; the
  reviewed upstream output policy does not yet cover all of these fields.
- Threshold ECDSA exposes an aggregate signature, not participant roles in the
  Bitcoin witness. Evidence must bind participant set, threshold, policy,
  session and reshare epoch without pretending those roles are on-chain. The
  local evidence schema enforces that distinction, but no upstream runtime
  populates or persists it yet.
- Do not create a vault, share, credential, custody address, fund, sign, reshare,
  recover or broadcast without explicit user authorization.
- THORChain BTC output order is fund-critical: VOUT0 Asgard, optional VOUT1
  change to VIN0, final VOUT memo. Preserve `BTC-ORDER-01` regressions and gate
  every provider-returned unsigned transaction before signing.
- Gate 4 is not complete. The key-free policy, local aggregate-evidence schema,
  integrated target/finality-bound durable state machine, exact-pinned
  Testnet4 transport, secure broadcast-store metadata checks and local
  configured-source finality transition exist. Binary/mandatory upstream
  wiring, actual approved endpoint/operator/certificate and source identities,
  independent consensus evidence, upstream runtime population, ongoing
  confirmation monitoring, failure-domain tests and independent review remain.
  Later key use and
  test-network rehearsal require separate authorization. The older 3-of-5
  custody rehearsal is historical and cannot substitute.
- EVM-family THORChain router addresses in the chain registry are deliberately
  zero-address placeholders. They are not deployment configuration.

## Important implementation areas

- custody-node contains the provider-neutral approval decision core. Preserve
  reconstructed-payload binding, fee caps, replay protection, one-shot
  consumption, and fail-closed behavior. The policy adapter consumes this
  boundary; a future Vultisig runtime must preserve it and call the adapter's
  final-transaction revalidation before broadcast rather than replace it.
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
