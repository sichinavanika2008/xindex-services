# Known findings — xindex-services

Mirror of the Solidity-side `Xindex/KNOWN_FINDINGS.md` discipline:
every audit finding is either fixed in code or documented here with
verdict and reasoning. No silent suppressions.

Audit log: 2026-05-09 (two-pass internal audit covering ~5,000 LOC).

## Status legend

- ✅ **Closed in code** — fix shipped this commit / earlier
- ⏳ **Deferred to M5** — explicitly part of plan §15 production
  hardening; subsystem-scale, not a single-file fix
- 📝 **Operational** — not a code fix; runbook / on-call concern
- ❌ **Accepted** — known limitation with documented rationale

## First-pass findings (2026-05-09)

| ID | Severity | Status | Note |
|---|---|---|---|
| M-R1 | Medium | ✅ Closed in code | `xindex-attest` rejects multi-slot intents with a hard error until Phase-3 per-slot chain-aware cross-check refactor lands. Phase 2.A invariant is exactly one async slot per intent (BTC.BTC). |
| M-R2 | Medium | ✅ Closed in code | `try_into().unwrap_or(u64::MAX)` replaced with explicit `Err` log + skip. Overflow now signals "Phase-3 non-BTC slot — wrong policy" rather than silently capping. |
| M-R3 | Medium | ✅ Closed in code | Added prominent type-level "DEV/TEST USE ONLY" doc on `InProcessExecutor` mirroring the `SoftwareSigner` warning. Defined `MultisigCosigner` trait stub for the M5 wire-protocol-backed cosigner. |
| L-R1 | Low | ❌ Accepted | `select_utxo` requires a single UTXO ≥ needed; rejects when total ≥ needed but no single one covers. Acceptable for v1 (one redemption ≈ one UTXO). Document inline; smarter coin-selection lands when bundle redemptions appear. |
| L-R2 | Low | ✅ Closed in code (2026-05-11) | New `BroadcastRegistry` trait + `InMemoryBroadcastRegistry`/`SqliteBroadcastRegistry` impls in `crates/executor/`. `xindex-redeem` registers every broadcast (txid + serialized tx_bytes + recipient + amount); a background `run_watcher` task polls Esplora every 60 s and re-broadcasts any stuck tx (`now - last_attempt > 1 h` by default). Mark-confirmed at ≥ 3 confirmations. Schema in `crates/executor/migrations/`. 12 new tests covering both registry impls + 5 watcher scenarios (confirmed, within-window, stuck-rebroadcast, already-known no-op, transport-error defer). |
| L-R3 | Low | ✅ Partially closed in code (2026-05-13) | **Connection-time fallover shipped.** `WsEndpointList` (`crates/chain-eth/src/rpc.rs`) accepts CSV of WS URLs; `connect_first_working` tries each in priority order with `is_transient_rpc_error` classifier (transport failures, 5xx, 429, WS close → fallover; 401/403/malformed → propagate as permanent). Wired into `xindex-cancel`; pattern available for the other 3 binaries. 12 new unit tests covering parse/classify/fallover/propagate-permanent/exhaust. **In-flight subscription fallover NOT addressed** — alloy WS holds a single connection; transparent swap requires bespoke `Transport` impl. Operator restart-on-failure + `--from-block` backfill remains the recovery path for subscription death. THORChain HTTP + Bitcoin Esplora fallover deferred (smaller surface, simpler retry pattern). |
| L-R4 | Low | ✅ Closed in code (2026-05-11) | New `IntentTrackerStore` trait with two impls: `InMemoryIntentTracker` (legacy behaviour, dev/tests) and `SqliteIntentTracker` (sqlx-backed, prod). `xindex-cancel` selects via `DATABASE_URL` env var. Schema in `crates/relayer/migrations/`. 4 new SQLite tests pass against `sqlite::memory:`. |
| L-R5 | Low | ✅ Closed in code (2026-05-19) | Dynamic fee estimation shipped. `BitcoinChainClient::estimate_fee_rate_sat_vb(target_blocks)` (default-impl errors so test fakes need no boilerplate; `EsploraClient` queries `/fee-estimates` via `esplora_client::get_fee_estimates`). Pure, mutation-targeted `pick_fee_estimate` (greatest key ≤ target = lowest sufficient rate; falls back to most-aggressive bucket; `None` only on empty). `xindex-redeem` derives the absolute fee at startup via pure `derive_fee_sats` (ceil(rate·vsize), clamped to `[floor,cap]`, garbage/NaN rate ⇒ floor) with the old 5 000-sat constant as the floor + the verbatim fallback on any estimator error (a fee-oracle hiccup never blocks a redemption). 5 `pick_fee_estimate` + 3 `derive_fee_sats` unit tests. **Scope note:** this lands the live-estimate *primitive* + startup wiring; per-broadcast re-estimation + RBF fee-bumping remains the tracked follow-on (`rebroadcast.rs:39`), now unblocked by this primitive. Verified 2026-05-19: full `just gate` green (fmt/clippy `-D warnings`/24 test binaries 0 failed/`cargo deny check` ok); `cargo mutants` **100%** on both new pure paths (`pick_fee_estimate` 11/11, `derive_fee_sats` 7/7). |
| I-R1 | Info | ✅ Closed in code (2026-05-13) | `crates/ops` now exposes three modules: `tracing_init::init_tracing()` (hoists the JSON subscriber pattern out of every binary), `metrics::Metrics` (13 Prometheus counters/gauges covering relayer + signer + executor + RPC fallover), `http::serve_metrics()` (axum server at `/metrics` + `/health`). Wired into `xindex-cancel` as the canonical demo; the other binaries adopt the same `init_tracing()` + spawn-serve-metrics pattern. 6 unit tests including end-to-end HTTP smoke. OTLP / OpenTelemetry deliberately deferred to v2 (no Grafana stack to point at yet); histograms deferred (cardinality cost without a specific SLO). |

## Third-pass findings (2026-05-15)

Audit pass focused on the executor + binaries — areas added since the
two earlier passes.

| ID | Severity | Status | Note |
|---|---|---|---|
| H-R1 | **High** | ✅ Closed in code (2026-05-15) | **Double-pay via `xindex-redeem` backfill.** Replaying a `RedeemDispatched` event whose original tx is in mempool (but not yet confirmed) caused `executor.execute_capturing_tx` to pick a *different* UTXO (Esplora marks the original as spent the moment its consuming tx hits the mempool) and broadcast a second valid payout. Both txs confirm → user receives 2× pro-rata for one share burn. The binary's NatSpec ("Bitcoin chain rejects double-spends") was wrong — Bitcoin only rejects same-UTXO double-spends. Fix: added `BroadcastRegistry::has_record(intent_id)` (covers pending AND confirmed entries); `process_event` skips when `has_record == true`. Failed lookups also skip (fail-safe: better to defer a redemption than risk double-pay). Loud startup warn when running with `InMemoryBroadcastRegistry`, since the defense relies on persistence across restarts. Tests: 2 new tests for `has_record` against both registry impls. Rewrote the misleading NatSpec header. |
| L-R6 | Low | ✅ Closed in code (2026-05-15) | `xindex-redeem` registered freshly-broadcast txs with `now_unix_secs().unwrap_or(0)` on clock failure — last_attempt=0 would mark the tx as stuck the moment the watcher ticked, triggering a no-op re-broadcast spam. Replaced with explicit skip-the-register-step (the watcher's own `now_unix_secs` path already does this). Operator must monitor the txid manually until the clock recovers; documented in the warn log. |

## Second-pass findings (2026-05-09)

| ID | Severity | Status | Note |
|---|---|---|---|
| M-R4 | Low | ✅ Closed in code | `ThorClient::with_timeout` now returns `Result<Self, ThorError>`; was silently swallowing reqwest builder errors. |
| M-R5 | Low | ✅ Closed in code | Added `MAX_RESPONSE_BODY_BYTES = 16 MiB` cap with chunk-streaming bail-out. Both success and error paths use `read_body_capped`. New `ThorError::ResponseTooLarge` variant. Requires `reqwest`'s `stream` feature (enabled in workspace `Cargo.toml`). |
| M-R6 | Info | ✅ Closed in code | Replaced `resp.text().await.unwrap_or_default()` on the error path with the same streaming reader, so chunk-read failures surface their underlying `reqwest::Error` instead of silently producing an empty body. |
| M-R7 | Low | ✅ Closed in code | `confirmations_from` now uses `saturating_sub` + `saturating_add`. Theoretical `+1` overflow on a 4-billion-block reorg is no longer a release-build wraparound. |
| M-R8 | Low | ✅ Closed in code | `require_network` probes the four canonical Bitcoin networks to determine the actual network of a mismatched address; reports it in `BitcoinError::AddressNetworkMismatch::actual` rather than the previous `Network::Bitcoin` placeholder. |
| M-R9 | Low | ✅ Closed in code | Esplora pagination size hoisted to `ESPLORA_PAGE_SIZE` constant (= 25 per upstream docs). Loop exit condition now references the named constant. |
| M-R10 | Low | ⏳ Deferred to M5 | N+1 `get_output_status` queries in UTXO discovery. Bounded by Esplora's API shape (no bulk endpoint). Pruning spent UTXOs proactively (via M5's persistent tracker state) is the operational mitigation. |
| M-R11 | Low | ✅ Closed in code | `now_unix_secs()` returns `Option<u64>`; clock failure (pre-1970) now skips the scan tick with a warning instead of returning 0 (which previously would have marked every intent as expired and spammed the chain with reverting `cancelMint` txs). |
| M-R12 | — | (= L-R4 → ✅ closed 2026-05-11) | Same finding. |
| M-R13 | Info | 📝 Operational | Keeper EOA pays gas for every `cancelMint` with no on-chain reward. Not a code bug — `cancelMint` is permissionless by design; we run a keeper for users. Operator runbook: budget keeper gas; if keeper down, users (or any third party) can call `cancelMint` themselves. |

## Burn→USDT redemption mirror (2026-05-19)

Off-chain mirror of the Solidity burn→single-token-USDT pivot (plan §19,
verify-the-refund PART 3). New surface: `RedemptionAttestation` /
`RefundAttestation` EIP-712 (separate typehashes), F2 dispatch store,
`ThorBtcToUsdtPolicy` / `ThorBtcRefundPolicy` cross-checks,
`xindex-attest-redeem`, `xindex-finalize-redeem`, executor reverse
direction + OP_RETURN memo. No new bug *classes* vs. the mint side — the
same shapes (replay, units/precision, double-pay, clock failure,
ordering) were re-examined against the new code.

| ID | Severity | Status | Note |
|---|---|---|---|
| R-T1 | **High** | ✅ Closed in code | **Typehash-separation boundary.** A mint `Attestation` signature must never satisfy `attestRedemption`/`attestRefund` and vice-versa. Enforced structurally: three distinct EIP-712 type strings ⇒ three distinct `_hashTypedDataV4` digests; no runtime `kind` discriminator to forget. `crates/shared/src/eip712.rs` pins all three typehash byte-arrays as compile-time tests (`redemption_typehash_matches_solidity_source`, refund equivalent) and asserts `three_typehashes_pairwise_distinct`. Mirrors the on-chain negative invariant. |
| R-T2 | **High** | ✅ Closed in code | **USDT 1e8↔1e6 precision.** THORChain reports *all* asset amounts in 1e8 fixed precision regardless of native decimals; on-chain USDT is 1e6. `ThorBtcToUsdtPolicy` divides the THORChain figure by `THOR_TO_USDT_SCALE = 100` and treats the **on-chain observed** ERC20 `Transfer` value as authoritative for the attestation (the THORChain figure is only a scaled cross-check, within tolerance) — same posture as the mint side attesting observed BTC sats. THORChain's 1e8 truncation can drop < 1e-6 USDT, absorbed by tolerance. BTC is 1e8 both sides (aligned, no scaling), which is why the mint-side `ThorBtcPolicy` never needed this. |
| R-T3 | **High** | ✅ Closed in code | **Delivery/refund mutual exclusion.** A redemption resolving as *both* delivered and refunded would double-credit. Mirrored on-chain (`IntentQueue` rejects refund-attest if delivery-attested and vice-versa) **and** off-chain: `xindex-attest-redeem` polls THORChain to a *single* terminal outcome per `redemptionId` and signs exactly one of `RedemptionAttestation` / `RefundAttestation`; never both. Refund is identified **only** by the `REFUND:<inbound_txid>` memo, never by time (verify-the-refund). |
| R-T4 | Medium | ✅ Closed in code | **Executor refund-address invariant.** THORChain's `getSender` resolves a refund to the inbound tx's `vin[0]` prev-out address. If the BTC→Asgard tx's first input were not a multisig UTXO, a refund would go elsewhere (loss). `redeem.rs` `debug_assert`s `vin[0]` belongs to the multisig descriptor and the coin-selection only draws multisig UTXOs; unit-tested. |
| R-T5 | Medium | 📝 Operational | **F2 ordering dependency (accepted, by design).** The signer's cross-check needs the exact `btc_txid` the executor broadcast; it reads the F2 `RedemptionDispatchStore`, which the executor writes *after* broadcast. `xindex-attest-redeem` retries until the record is present — no attestation before broadcast (the safe order). Hard failure mode: executor down after `burn` but before broadcast ⇒ redemption stuck ⇒ SD-B runbook. Not a code fix; the ordering is the correctness property. |
| R-T6 | Low | ❌ Accepted (F1) | **Config-static swapHints.** The relayer supplies operator-configured fixed V4 paths (ERC20 slot → USDT) at `finalizeBurn`; no live quoter. Stale-path risk is operator-maintained and bounded: the end-to-end `minUsdtOut` is re-checked **on-chain** at `finalizeBurn` (the binding protection), exactly matching the Solidity audit-slippage stance. A stale path makes a finalize *revert*, not lose funds. Smaller attack surface, deterministic. |
| R-T7 | Medium | 📝 Operational | **Stuck redemption (SD-B).** Halted vault ⇒ no delivery, no refund ⇒ redemption `PENDING` forever; no on-chain `forceCancel` by deliberate design (no admin-trust escape). `xindex-finalize-redeem` raises `redeem_relayer_stuck` gauge + `WARN` after `STUCK_AFTER_BLOCKS` (alert-only, **no** auto-action). Resolution: [`docs/runbooks/redemption-stuck-SD-B.md`](docs/runbooks/redemption-stuck-SD-B.md) — multi-party manual reconciliation; signers attest only observed chain state. |

Analyzer re-triage: `cargo clippy --all-targets --all-features -D warnings`
clean on the full new surface (no `#[allow]`, `allow_attributes = deny`);
all new doc identifiers backticked to codebase convention rather than
suppressed. No new `cargo deny` advisory/license/ban hits.

## M5 / M6 production-hardening (2026-05-19)

| ID | Severity | Status | Note |
|---|---|---|---|
| M-R3 | — | ✅ Daemon code shipped + gate-green (2026-05-20); remaining slices tracked below | The production coordinator/daemon split is now CODE, not spec. New crate `xindex-signer-daemon` (axum HTTP server, sqlx replay/slashing DB, four signing endpoints, identity/health) implementing the full PART 5 / DL-M5-1..6 architecture. The replay/slashing DB (`InMemoryReplayStore` + `SqliteReplayStore` over the established `*Store` AFIT pattern) enforces the daemon-side mutex: idempotent on same `(tuple, payload_hash)`, 409 `Conflict` on different payload, 409 `MutexViolation` on delivery↔refund crossover (mirrors `IntentQueue` queue-side mutex). The four endpoints: `eip712-attestation` / `eip712-redemption-delivery` / `eip712-refund` (mirror the three on-chain typehashes, type-level routing, no runtime `kind` discriminator) + `psbt-input` (parses base64 PSBT, validates the input's witness_script matches the configured `MultisigDescriptor` — refuses unknown scripts with `wrong_descriptor`, validates `vin[0]` is itself a multisig UTXO — refuses with `vin0_not_multisig` (Part-3 refund-address invariant), computes BIP-143 P2WSH sighash, verifies HSM-returned secp256k1 signature against the configured pubkey before serializing DER+sighash). HSM frontend abstracted via `HsmDigestSigner` trait (`HttpHsmClient` for production; the daemon owns the digest, never trusts coordinator-supplied — defuses Web3Signer's `eth1/sign` keccak-double-hash hazard). Coordinator side: `HsmBackend` trait extended with typed `sign_*_msg` default methods; `RemoteHsmBackend` (HTTP client, pins daemon's `eth_address` per response — wrong-signer is a hard fail); `AnyHsmBackend` enum unifying `SoftwareSigner` + `RemoteHsmBackend`; `RemoteMultisigCosigner` (mirror for the BTC path, pins compressed pubkey per response). Both `xindex-attest` and `xindex-attest-redeem` binaries now take `--signer-mode {software,remote}` with `--signer-daemon-urls` + `--signer-daemon-addresses` (pinned address list); the SoftwareSigner path stays the Anvil/dev default. Daemon test coverage: 22 unit tests (replay lifecycles across 3 message kinds, HSM frontend wiremock round-trip + 5xx + bad-sig, EIP-712 endpoints incl. typehash-separation digest-correctness via CapturingSigner, PSBT endpoint with real ECDSA via `SoftHsm` + idempotency + 409 different-sighash + 422 wrong-descriptor). Coordinator tests: 5 `RemoteHsmBackend` wiremock + 3 `RemoteMultisigCosigner` wiremock. Workspace: 26 binaries / 0 failed; fmt clean; `clippy --all-targets --all-features -D warnings` clean; `cargo deny check` advisories/bans/licenses ok. **Updates 2026-05-21:** (a) `xindex-redeem` binary wiring shipped — `InProcessExecutor` refactored to a `SigningBackend` enum (`LocalKeys` for dev / `Cosigners` for production); new `with_cosigners` constructor; `xindex-redeem` accepts `--signer-mode {software,remote}` with `--cosigner-daemon-urls` + `--cosigner-pubkeys` (per-daemon pubkey pin); existing local-keys tests unchanged. (b) Loopback-daemon end-to-end integration test shipped — `crates/signer-daemon/tests/loopback.rs` spins up a real axum daemon on an ephemeral loopback port with a software-keyed `HsmDigestSigner` and drives the production `RemoteHsmBackend` + `RemoteMultisigCosigner` clients against it. 4 tests: (i) Ethereum attestation produces a 65-byte sig that recovers to the daemon's configured signer + idempotent re-request does NOT re-invoke the HSM; (ii) same-tuple-different-amount → daemon 409 Conflict surfaced; (iii) delivery-then-refund on the same redemption → daemon 409 Mutex surfaced; (iv) PSBT-input produces a partial signature that verifies under the disclosed pubkey against the BIP-143 sighash + inserts cleanly into the PSBT's `partial_sigs`. Full HTTP wire, real JSON, real ECDSA, real secp256k1 verify — no mocks at any layer except the HSM frontend itself. (c) `cargo mutants` on `replay.rs` (the #1 trust surface): **96.3% (26/27 caught, 7 unviable, 1 missed = `Debug::fmt` logging-only — same accepted class as existing crate-mutation logs).** Far above the ≥80% target. Workspace: **27 binaries / 0 failed**, fmt + `clippy -D warnings` clean, `cargo deny check` ok. **Sole remaining gated slice: mTLS server + coordinator-cert pin allowlist (DL-M5-5).** The daemon currently serves plain HTTP — wiremock-test-grade, not production-grade. Production deployment is still gated on: (1) mTLS code, (2) the focused signer-architecture audit pass, (3) Sepolia/signet rehearsal with the full 3-of-5 daemon mesh. Full spec: plan file `~/.claude/plans/mossy-splashing-castle.md` **PART 5**; decision-lock entries `DL-M5-1..6`. |
| M6-runbooks | — | ✅ Shipped (2026-05-19) | Operational docs that govern the two distinct 3-of-5 key sets (Bitcoin P2WSH custody + Ethereum EIP-712 attestation) and HSM hardening: [`docs/runbooks/key-ceremony.md`](docs/runbooks/key-ceremony.md) (invariants: no-extraction, no-threshold-concentration, deterministic descriptor ordering, independent verification, air-gapped generation, public signer-set disclosure, rotation reference) and [`docs/runbooks/yubihsm2-provisioning.md`](docs/runbooks/yubihsm2-provisioning.md) (non-exportable keys, default auth deleted, application auth sign-only + single-domain, audit-log forced, anti-patterns). Protocol-independent — they govern key material, not the gated wire protocol. |

## Phase 3.0 Rust sync (2026-05-23)

Re-vendor of the Solidity ABIs after the Phase 3.0 chain-generic rename
(2026-05-21) and the P3-1 EIP-170 `AsyncMintLib` extraction (2026-05-22).
The `sync-abi` re-pull also rolled the pinned `REFUND_ATTESTATION` typehash
in `crates/shared/src/eip712.rs` from `0x3611da03…` to `0xb33012bd…` to
match the renamed `refundedAmount` field; `three_typehashes_pairwise_distinct`
preserved.

Surfaced one build-time defect against the Rust binding crate; fixed
in-place; gate re-green (fmt / clippy `-D warnings` / 167 tests / `cargo
deny check`).

| ID | Severity | Status | Note |
|---|---|---|---|
| P3-S1 | Medium | ✅ Closed in code | **Unlinked-bytecode break in `IndexToken` bindings (P3-1 side-effect).** P3-1 moved the async-mint lifecycle into the external (delegatecalled) `AsyncMintLib`; the Foundry artifact for `IndexToken` now ships with unlinked bytecode containing a `__$d5a322c9…$__` library-link placeholder. alloy's `sol!` macro refuses to parse unlinked bytecode (`error: invalid JSON: expected bytecode, found unlinked bytecode with placeholder`), breaking `crates/chain-eth/src/bindings.rs`. The Rust gate was not re-run after P3-1 (Solidity-only commit) so the regression sat undetected until today's `just sync-abi`. Fix: the `sync-abi` recipe now vendors `.abi`-only for `IndexToken` via a one-line `python3` extraction (`jq` not present in the dev shell). The off-chain stack never `::deploy`s — verified by `rg -n "::deploy"` — so bytecode is dead weight for the Rust side. The four other contracts continue as full Foundry artifacts. |

**Follow-on (out of Phase 3.0 scope, tracked here for visibility):**
BTC-specific identifiers remain on the Rust side outside the EIP-712
typehash: `signer_wire::RefundSignRequest.btc_refunded` (HTTP wire schema),
`ThorBtcRefundPolicy` / `ThorBtcToUsdtPolicy` (cross-check struct names),
and the `btc_refunded` request fields in `signer-daemon`. A chain-generic
Rust rename paralleling the Solidity Phase 3.0 work is required for true
UTXO-family genericism; folded into Phase 3.1 (`crates/chain-utxo`).

## Verification

```
cd /Users/imac/Movies/xindex-services
cargo fmt --all -- --check                                   # exits 0
cargo clippy --all-targets --all-features -- -D warnings     # exits 0
cargo test --workspace                                       # all pass
cargo deny check                                             # advisories/bans/licenses ok
```

`cargo audit` is part of the per-PR CI matrix (see
`.github/workflows/ci.yml`). Locally in this sandboxed environment the
RustSec advisory-db git fetch is blocked and the on-disk cache uses
cargo-deny's layout (not cargo-audit's), so `cargo audit` cannot run
here; **`cargo deny check` covers the same RustSec advisory database and
reports `advisories ok`**, so supply-chain advisory coverage is satisfied
for this gate. CI runs the canonical `cargo audit` with network access.

## Mutation testing (cargo mutants)

Per-crate mutation-testing pass; mutations that "live" (pass tests despite
behavior change) reveal test-suite gaps. Each gap is either closed with a
targeted test or documented here as acceptable.

| Crate | Date | Score | Real gaps fixed |
|---|---|---|---|
| **`xindex-signer`** | 2026-05-13 | **86.4%** (19/22 caught, 1 unviable) | `sign_attestation` had no recovery-verifying test (mutation `Ok([0;65])` slipped through); `ThorBtcPolicy` cross-check `&&` filter had no asymmetric test (mutation `&&` → `\|\|` slipped through). Both closed by new tests in `lib.rs` and `crosscheck.rs`. |
| **`xindex-signer`** (redemption/refund/erc20 paths) | 2026-05-19 | **95.8%** (46/48 caught, 1 unviable) | Initial run 54% (26/48). Gaps closed: `sign_redemption_attestation`/`sign_refund_attestation`/`aggregate_*` had no recovery-verifying tests (`Ok([0;65])`/`Ok(vec![..])` stubs slipped) → added recovery + order-preserving + cross-typehash-negative tests in `lib.rs`; `ThorBtcToUsdtPolicy::verify` / `ThorBtcRefundPolicy::verify` `&&` filters and the refund `abs_diff > tolerance` gate had no asymmetric/boundary tests → added 8 decoy/boundary tests in `crosscheck.rs`. Remaining 2 misses = `Debug::fmt` on the two policies (logging-only, same accepted class as `SoftwareSigner`/`ThorBtcPolicy`). |
| **`xindex-executor`** (`redeem.rs` reverse path) | 2026-05-19 | **100%** (10/10 caught, 4 unviable) | Initial run 50% (5/10). Gaps closed: `decode_redeem_event` had no exact-`MAX_OP_RETURN_BYTES` test (`>`→`>=` slipped) and `select_utxo` had no smallest-covering / equal-value / sub-needed boundary tests (`&&`→`\|\|`, `<`→`>`/`==`/`<=` slipped). Added `decode_accepts_exact_max_memo` + `select_utxo_picks_smallest_covering` + `select_utxo_keeps_first_of_equal_value`. |
| **`xindex-chain-btc`** (fee-estimate path: `pick_fee_estimate` + trait default + `EsploraClient` override) | 2026-05-19 | **100%** (11/11 caught) | Initial run 45.5% (5/11). The pure `pick_fee_estimate` picker was already fully caught by its 5 boundary tests; the 6 misses were the trait DEFAULT (`Ok(0.0)`/`Ok(1.0)`/`Ok(-1.0)`) and the `EsploraClient` impl override (same 3 stubs) — no integration tests exercised them. Closed: added a `DefaultFeeChain` minimal impl asserting the default-impl path returns `BitcoinError::Upstream` (kills the default-impl mutants); added a `wiremock`-mounted `/fee-estimates` test that builds a real `EsploraClient::with_url` against the mock and asserts the returned rate equals the picker's exact output for the same map (kills the impl-override mutants — no network, runs in 3 m). |
| **`xindex-executor`** (`derive_fee_sats` clamp/ceil/NaN-safety) | 2026-05-19 | **100%** (7/7 caught) | Initial run already at 100%; the 3 ceil/clamp tests + 2 garbage-rate-yields-floor tests + 1 cap-below-floor test covered every mutation directly. |

**Remaining acceptable misses (signer):**
- `Debug::fmt` impls on `SoftwareSigner` and `ThorBtcPolicy<C>`: logging-only, not security-relevant.
- `PassThroughPolicy::verify` returning `Ok(())`: tautology — the policy by name always returns `Ok(())`; mutation is semantically identical.

**`xindex-shared`** (`redemption_dispatch.rs`, F2 store) | 2026-05-19 |
**75%** (9/12 caught, 5 unviable) | Initial 58%; added an
`AnyRedemptionDispatch` delegate round-trip test (the path the binaries
actually use). Remaining 3 misses = `Debug::fmt` (logging-only) + 2×
`now_unix_secs` constant-replacement on a best-effort wall clock (not
deterministically pinnable without freezing time — same accepted class
as the mint-side `now_unix_secs`).

**Pending crates** (run in future sessions; same pattern):
- `xindex-multisig` (Bitcoin PSBT signing — HIGH priority)
- `xindex-shared` EIP-712 typed-data module (separate from the F2 store
  above — HIGH but small)
- Others (relayer, chain-eth/btc/thor, ops): MEDIUM/LOW priority

Reproduce: `cargo mutants --package xindex-signer --baseline=skip --timeout 120`

## Phase 3.1 — UTXO custody-chain family (2026-05-24)

Multi-chain expansion of the UTXO custody surface. Five chains: BTC,
LTC, BCH, DOGE, ZEC. All share `xindex-chain-utxo` (renamed from
`xindex-chain-btc`) + `xindex-multisig` (now serves both P2WSH SegWit
and P2SH-legacy templates). 11 commits on `feat/phase-3-1-utxo`.

### P3.1-1: DOGE 40-conf depth (accepted — Bifrost heuristic)

`xindex-shared::chain_registry::ChainId::Doge::conf_depth() == 40`,
vs. BTC/BCH = 6, LTC = 12, ZEC = 10. DOGE has 1-min blocks + a
historical reorg vulnerability; the 40-conf depth is the THORChain
Bifrost (`bifrost/pkg/chainclients/dogecoin`) production heuristic
ported verbatim. Pinned in unit test
`conf_depths_match_bifrost_heuristics`.

**Status:** ✅ Accepted as-is. Per-chain key-ceremony rollout (DL-P3-7)
will reverify under operator sign-off.

### P3.1-2: BCH OP_RETURN 220-byte policy (accepted — relay-policy fact)

`ChainId::Bch::op_return_max() == 220`, vs. 80 for BTC/LTC/DOGE/ZEC.
BCH raised the OP_RETURN standard-relay limit to 220 bytes in the 2019
relay-policy bump. THORChain affiliate-fee memos can exceed 80 bytes
on BCH; the executor must allow up to 220 to avoid non-relay errors.
The 80-byte default for BTC/LTC/DOGE/ZEC is the unchanged Bitcoin Core
standard. Pinned in unit test `op_return_max_per_relay_policy`.

**Status:** ✅ Accepted.

### P3.1-3: ZEC t-addr only — z-addr (shielded) explicitly unsupported

`ChainId::Zec` codec encodes the transparent (t-addr P2SH, `t3…`
prefix) layer only. Shielded (z-addr, Sapling/Orchard) addresses are
out of scope per DL-P3-7 — supporting them requires a different
trust + cryptography surface (shielded notes, viewing keys, prover
performance) that is not in the Phase 3.1 scope.

**Status:** ✅ Accepted; documented in `ZecCodec` module doc + the
plan's "Out of scope (deferred)" section.

### P3.1-4: Per-chain fee unit (sat/vB vs sat/B) (accepted — chain fact)

`ChainId::*::fee_unit()` returns `PerVbyte` for BTC/LTC (SegWit) and
`PerByte` for BCH/DOGE/ZEC (no SegWit). Mixing units underpays a
legacy-chain tx by up to 4× because the SegWit virtual-byte unit is
witness-discounted. Pinned in `fee_unit_per_segwit_status`. Executor
fee-derivation today is BTC-only (`derive_fee_sats` reads sat/vB); the
per-chain wiring of `fee_unit` into the fee derivation lands when the
non-BTC executor binaries ship (operational rollout per DL-P3-7).

**Status:** ⏳ Plumbing exists; per-chain fee math is operational
rollout work.

### P3.1-5: H1 / per-leg DispatchRecord backfill default `leg_index = 0`

Phase 3.0 went per-leg on-chain but the Rust mirror was per-rid; a
multi-leg redemption's second leg's `record_dispatch()` hit
`INSERT OR IGNORE` and was silently dropped. H1 reshapes the PK to
`(redemption_id, leg_index)`. Existing in-flight rows are backfilled
`leg_index = 0` (the current single-async-slot rail's value).
Backfill is correct because at the time of the migration there is
exactly one leg per rid in flight.

**Status:** ✅ Fixed in H1; in-memory + SQLite tests cover both
single-leg + 2-leg non-collision paths.

### P3.1-6: U9 per-chain dispatch column backfill default `chain = 'btc'`

`redemption_dispatch.chain` added in U9 migration
(`20260524000000_dispatch_multichain.sql`). Existing rows backfill
`'btc'` — correct under the current BTC-only operational state. Once
non-BTC executor instances start writing rows, they will tag their
own chain via the `--chain` CLI arg (U10).

**Status:** ✅ Migration applied + CHECK-constrained to the Phase 3.1
chain set; tested in `redemption_dispatch.rs`.

### P3.1-7: ZEC codec hand-rolled vs `zcash_address` crate (deviation from plan)

The plan suggested using the ECC `zcash_address` crate for ZEC t-addr
encoding. The implementation uses a ~10-line hand-roll over
`bitcoin::base58` + `bitcoin::hashes::sha256d` instead, because
`zcash_address` pulls in shielded-pool primitives we don't need for
the transparent t-addr layer. The hand-roll is audit-friendlier — the
full code path is one file + two helper functions, fully covered by
the U6 round-trip + bad-version negative tests.

**Status:** ✅ Accepted deviation; documented in `ZecCodec` module
comment.

### P3.1-8: `RUSTSEC-2023-0071` (rsa via sqlx-mysql; ignored)

`cargo audit` flags the `rsa` 0.9.x Marvin timing sidechannel. Pulled
transitively via `sqlx-mysql`, which sqlx 0.8 keeps in its lockfile
entry even with `default-features = false` + sqlite-only features.
We do not compile the mysql driver — the vulnerable code is not
reachable from the workspace's binary outputs. No upstream fix
available.

**Status:** ⏳ Ignored in `deny.toml` + `cargo audit --ignore`.
Revisit when either sqlx-mysql moves off rsa 0.9 or a patched rsa
release lands.

### P3.1-9: Per-chain end-to-end PSBT test modules (deferred)

The plan called for 4 per-chain E2E test modules (LTC + BCH + DOGE +
ZEC). The implementation ships the building blocks (U4 descriptor
templates, U5 PSBT BIP-143 + legacy sighash, U6 codec round-trips)
fully unit-tested. The combined per-chain E2E harnesses are deferred
to a follow-up — they add concentration coverage but no NEW
security-critical surface beyond the unit tests.

**Status:** ⏳ Deferred. Pre-mainnet (per DL-P3-7) audit + per-chain
key ceremony will require at least one per-chain mainnet rehearsal,
which the per-chain E2E test should mirror.

### P3.1-10: 2-chain loopback (BTC + LTC) deferred

The plan called for the `signer-daemon` loopback test to be extended
to a parametrized 2-chain harness exercising the multi-role HashMap
routing. The U8 commit ships the multi-role machinery; the
integration-level 2-chain loopback is deferred to the same follow-up
as P3.1-9.

**Status:** ⏳ Deferred.

## Phase 3.2 — EVM custody family (2026-05-26)

EVM custody via Safe v1.4.1 k-of-n direct, destination chains
ETH / BSC / AVAX / BASE / POL. Decisions DL-P3.2-1..8 locked in
`~/.claude/projects/-Users-imac-Movies-Xindex/memory/feedback_decision_locking.md`.
See `docs/runbooks/safe-key-ceremony.md` for the per-chain Safe
deployment + signer-set composition procedure.

| ID | Severity | Status | Note |
|---|---|---|---|
| P3.2-1 | Info | ❌ Accepted (DL-P3.2-3) | **Safe version pin: v1.4.1, not 1.5.x.** Safe v1.5 (released 2026-Q1) ships a fee-payer module + transient-storage execution path; both are out of scope for our minimum-surface custody (DL-P3.2-6 `enabledModules() == []` invariant). EIP-712 digest is byte-identical across v1.3 / v1.4 / v1.5 (same `SAFE_TX_TYPEHASH` + non-standard `chainId + verifyingContract`-only domain), so a future migration is digest-stable. `crates/safe-evm/src/digest.rs` pins the typehash bytes at compile time. |
| P3.2-2 | Info | ❌ Accepted (DL-P3.2-4) | **Tx envelope per chain.** EIP-1559 on ETH / AVAX / BASE / POL; type-0 legacy on BSC. BSC's mempool long resisted 1559 — validators still route legacy txs preferentially. Codified in `xindex_shared::chain_registry::tx_type()`; `xindex_chain_evm::build_safe_exec_tx_request` consults it before populating fee fields. |
| P3.2-3 | **High** | 📝 Operational | **Per-chain Safe key ceremony required before mainnet funds.** Each Phase 3.2 chain has its own 3-of-5 Safe with no cross-chain key sharing (DL-P3-7). Disclosed signer addresses must be set as Safe owners via the Safe Transaction Service or direct factory deploy before V10 lands on mainnet. The deploy script accepts the Safe address as env (`SAFE_ADDRESS_<CHAIN>`); the factory's `setAdapterAllowed` flag MUST be flipped only after the ceremony's signer-set disclosure is independently verified. See `docs/runbooks/safe-key-ceremony.md`. |
| P3.2-4 | Medium | ❌ Accepted (DL-P3.2-7) | **No gas-price oracle in v1.** Operators supply `EvmTxFee { gas_limit, max_fee_per_gas, max_priority_fee_per_gas, gas_price }` per leg via the `xindex-redeem-evm --max-fee-per-gas …` CLI args (or env). `chain-evm` does NOT run `eth_estimateGas`, does NOT poll a fee-oracle HTTP API. A stale fee setting makes a wrapper-tx revert (Safe nonce stays unconsumed; replay-safe), never burns funds at the wrong rate. Live fee estimation is a v2 follow-on once we see operator pain. |
| P3.2-5 | **High** | ❌ Accepted (DL-P3.2-6) | **No Safe modules + no Safe guard installed.** `enabledModules() == []` invariant: the Safe is configured as a plain k-of-n multisig with no module hooks and no transaction guard. This eliminates the entire upgrade-path + module-compromise attack surface (e.g. `setGuard` / `enableModule` would let a single signer in a malicious module bypass `checkSignatures`). v11 ops checklist will verify this on every chain via `Safe.getModulesPaginated(SENTINEL_OWNERS, 10)`. |
| P3.2-6 | Medium | 📝 Operational | **BASE sequencer single-point + L2 reorg risk.** BASE is a centralised-sequencer L2; finality assumptions on Phase 3.2 BASE are weaker than the L1 chains. We compensate with `conf_depth = 30` (≈10 min L2 + L1-anchoring buffer) — see `chain_registry::conf_depth`. Long sequencer downtime (>1 hr) blocks BASE redeems; no on-chain auto-cancel — operators escalate to SD-B equivalent (redemption-stuck runbook). |
| P3.2-7 | Low | ❌ Accepted | **Per-Safe lock is in-process, not SQLite.** The plan §V7 called for a SQLite advisory lock around `safe_nonce → build → submit`; we ship an in-process `tokio::Mutex` map (`crates/executor/src/evm_redeem.rs::SafeLockTable`). DL-P3.2-6 deployment policy is one `xindex-redeem-evm` binary per Safe per chain (operational isolation); cross-process concurrency against the same Safe is forbidden by policy, so an in-process lock covers every observable race. A future multi-process variant would need to upgrade to a SQLite advisory lock + a leader-election step. |
| P3.2-8 | Medium | ✅ Closed in code | **Daemon never blind-signs.** V2's `EvmSafeTxSignRequest` carries the 10 SafeTransaction ABI inputs (`to`, `value`, `data`, `operation`, `safe_tx_gas`, `base_gas`, `gas_price`, `gas_token`, `refund_receiver`, `nonce`) **plus** the coordinator's claimed `safe_tx_hash`. V5 daemon recomputes the digest from the inputs via `xindex_safe_evm::digest::safe_tx_hash` and rejects mismatch with `error_codes::SAFE_TX_HASH_MISMATCH` (422). Mirror of the daemon-side principle in `crates/signer-daemon/src/lib.rs:17` ("Computes the EIP-712 digest … itself — it never trusts a coordinator-supplied digest"). |
| P3.2-9 | Medium | ✅ Closed in code | **Cosigner signer-pinning + Safe owner-set check.** `EvmRedeemExecutor` rejects cosigners whose configured `signer_address` is not in `config.safe_owners` (the Safe's owner-set as disclosed at ceremony). Defends against a deploy-time misconfiguration where a cosigner points at a key that's not in the Safe — `Safe.checkSignatures` would reject the aggregated blob on-chain, but the off-chain check fails loudly + earlier. `RemoteEvmCosigner` (binary) additionally verifies the daemon's response `signer_address` matches the pinned address (defence against a misdirected daemon). |
| P3.2-10 | Info | ❌ Accepted | **Cross-chain replay defence by Safe digest construction.** Safe's EIP-712 domain is `chainId + verifyingContract` (non-standard — no `name`/`version`). A signature over the safeTxHash for Safe X on chain A cannot satisfy `checkSignatures` on Safe X on chain B (different `chainId` → different domain separator → different digest). The signer-daemon's replay key `(ChainId, safe_address, nonce)` is therefore over-keyed by design; this is defence-in-depth, not a correctness gap. |
| P3.2-11 | Low | ❌ Accepted | **`fee_wei` carried in V2 wire but ignored by daemon.** The `EvmSafeTxSignRequest.fee_wei` field travels the wire but is NOT part of the Safe digest (the digest's `gas_price` field is always 0 in Phase 3.2 — no Safe-side refund). Daemon ignores `fee_wei` during signing; it's transport convenience for the coordinator → executor → daemon bundle. A coordinator that lies about `fee_wei` cannot corrupt the digest. |
| P3.2-12 | Info | ❌ Accepted | **Anvil-fork V9 e2e: on-chain submission deferred.** V9 ships off-chain integration coverage (3 real daemons + 3-of-3 sig collection + replay/conflict detection via real HTTP) but stubs out the actual anvil-fork tx submission to a `#[ignore]`-d placeholder. Submitting requires (1) deploying Safe v1.4.1 via the canonical proxy factory at the fork block, (2) funding the submitter EOA, (3) wiring the wrapper-tx signer. Next pass adds that against a forked mainnet block where a known Safe is configured. Per-chain fork tests on non-ETH chains gated behind `FORK_RPC_BSC` / `…AVAX` / `…BASE` / `…POL`. |
| P3.2-13 | Info | ⏳ Deferred | **`xindex-redeem-evm` long-running event loop.** Current binary drives a single redeem leg per invocation (operators feed CLI args). Production needs the same WS-subscription event loop pattern `xindex-redeem` already has — watch the EVM-family ThorchainAdapter for `RedeemDispatched`, decode, `build_leg`, sign + submit, record. The library (`EvmRedeemExecutor`) is loop-ready; only the binary wrapper is single-shot. Follow-on once V10 mainnet Safes are live + per-chain RedeemDispatched is being emitted. |
| P3.2-14 | Info | ⏳ Deferred | **Cancel-stuck escrow formal review (carry-over from 2026-05-25 red-team).** Same SD-B class applies to EVM legs — a halted Safe (signer-party compromise + threshold not reached) leaves a redemption permanently pending. Mirror of the BTC SD-B runbook needed for Phase 3.2 chains; formal/symbolic review of the cancel-stuck escrow path covers both families. Tracked in next-steps memory as a mainnet gate. |
| P3.2-15 | Info | 📝 Operational | **Solidity registration ceremony is config-only.** V10 ships zero Solidity contract code changes (DL-P3.2-1 — adapter is chain-generic). Per-chain mainnet deploy is a separate operational step: (1) deploy Safe ceremony per `safe-key-ceremony.md`; (2) operator runs `forge script DeployPhase32Adapters --rpc-url <chain>` with `SAFE_ADDRESS_<CHAIN>` env; (3) operator flips `factory.setAdapterAllowed(newAdapter, true)` only after independent verification of step (1)'s signer-set disclosure. |

## When this file gets updated

- New audit pass (internal or external) → add a section
- M5 milestone closes a `⏳ Deferred` item → flip to ✅ + describe fix
- Any analyzer (clippy / cargo-deny / cargo-audit) flags something we
  decide to accept → entry here with reasoning
