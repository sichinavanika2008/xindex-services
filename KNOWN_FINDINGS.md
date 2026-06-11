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

`cargo audit` is the **authoritative** advisory gate and runs both
locally (`just gate` → `cargo audit --ignore RUSTSEC-2023-0071`, against
the `~/.cargo/advisory-db` cache) and in the per-PR CI matrix
(`.github/workflows/ci.yml`, `rustsec/audit-check` with network access).
`cargo deny check` is **complementary, NOT a superset** (corrected per
the 2026-06-01 audit, L14): deny scans a *feature-resolved* dependency
graph (`[graph] all-features = false`), so a crate reachable only through
a non-default feature — e.g. `lru` via alloy (RUSTSEC-2026-0002), or
`rsa` via the `sqlx-mysql` lockfile entry we never compile
(RUSTSEC-2023-0071) — is absent from deny's graph (deny emits
`advisory-not-detected` for those `ignore` ids) yet present in
`cargo audit`'s full `Cargo.lock` scan. Advisory coverage is therefore
satisfied by `cargo audit`; `cargo deny` additionally enforces
license / bans / sources plus advisories on the compiled graph.
(cargo-deny 0.18 removed the `[advisories] vulnerability/unsound/notice`
severity keys — every non-ignored advisory on its graph is now an error —
so there is no `unsound = "all"` knob to add on the installed 0.19.x.)

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
| P3.2-13 | Info | ⏳ Deferred | **`xindex-redeem-evm` long-running event loop.** Current binary drives a single redeem leg per invocation (operators feed CLI args). Production needs the same WS-subscription event loop pattern `xindex-redeem` already has — watch the EVM-family ThorchainAdapter for `RedeemDispatched`, decode, `build_leg`, sign + submit, record. The library (`EvmRedeemExecutor`) is loop-ready; only the binary wrapper is single-shot. Follow-on once V10 mainnet Safes are live + per-chain RedeemDispatched is being emitted. **The in-process `SafeLockTable` is NOT a cross-invocation double-pay defense — it drops at `build_leg` return, and `build_leg` reads the Safe `nonce()` fresh, so a re-driven `RedeemDispatched` after a confirmed payout builds a SECOND valid tx at the advanced nonce (audit 2026-06-01 M3). Mainnet readiness REQUIRES a persistent dispatch-dedup guard — the `BroadcastRegistry::has_record` analogue keyed on the real `dispatch_id`, not `B256::ZERO` — added to the DL-P3-7 per-family gate.** |
| P3.2-14 | Info | ⏳ Deferred | **Cancel-stuck escrow formal review (carry-over from 2026-05-25 red-team).** Same SD-B class applies to EVM legs — a halted Safe (signer-party compromise + threshold not reached) leaves a redemption permanently pending. Mirror of the BTC SD-B runbook needed for Phase 3.2 chains; formal/symbolic review of the cancel-stuck escrow path covers both families. Tracked in next-steps memory as a mainnet gate. |
| P3.2-15 | Info | 📝 Operational | **Solidity registration ceremony is config-only.** V10 ships zero Solidity contract code changes (DL-P3.2-1 — adapter is chain-generic). Per-chain mainnet deploy is a separate operational step: (1) deploy Safe ceremony per `safe-key-ceremony.md`; (2) operator runs `forge script DeployPhase32Adapters --rpc-url <chain>` with `SAFE_ADDRESS_<CHAIN>` env; (3) operator flips `factory.setAdapterAllowed(newAdapter, true)` only after independent verification of step (1)'s signer-set disclosure. |

## 2026-05-27 red-team — Phase-1 signer-daemon hardening (2026-05-28)

Continuation of the 15-agent red-team sprint (Solidity Phase-1 + most of
Phase-2 landed on the `Xindex` repo). The Rust signer-daemon Phase-1
items:

| ID | Severity | Status | Note |
|---|---|---|---|
| 1.5 (H11) | **High** | ✅ Closed in code | **Recover-verify on the HSM EIP-712 signature.** `handle_evm_safe_tx` now recovers the signer address from the HSM's returned 65-byte signature over the recomputed `safeTxHash` and refuses (`signer_recover_mismatch`, 500) unless it equals the configured `my_signer_address`. Catches an HSM key-mapping bug, a wrong-key signature, or a corrupted signing response BEFORE it is recorded or returned as a valid owner signature. `crates/signer-daemon/src/evm_safe.rs` step 5a; new `error_codes::SIGNER_RECOVER_MISMATCH`. Test: `server::tests::evm_safe_tx_tests::rejects_signature_recovering_to_wrong_signer`. The `evm_safe_tx_tests` HSM mock was upgraded from a fixed-bytes stub (`CapturingSigner`) to a real ECDSA signer (`RealEvmSigner`) whose key's address is the configured signer, so its signatures recover. |
| 1.13 | Medium | ✅ Closed in code (2026-06-05) | **Low-S normalization on the HSM signature.** `Web3Signer` / alloy `PrivateKeySigner` already emit canonical low-S (EIP-2), so this is defense-in-depth against a non-canonical signing response (Safe's `checkSignatures` rejects high-S). **Fix**: `evm_safe::normalize_low_s` parses the HSM's `r‖s` via `k256`, and if `s` is in the upper half-order replaces it with `n - s` and flips the recovery byte (27↔28 / 0↔1) — preserving the HSM's `v` convention rather than reconstructing it (the original deferral risk). Applied immediately after the HSM call; the 5a recover-verify then re-checks the NORMALIZED bytes, so a mis-normalization fails closed (`signer_recover_mismatch`, never recorded). Tests: `low_s_signature_unchanged`, `high_s_signature_is_normalized_and_recovers`. **Residual gate (unchanged):** confirming the HSM's BASE `v` convention (27/28 vs 0/1) against a live Web3Signer + Safe `checkSignatures` stays a pre-mainnet operational check — orthogonal to this normalization, which only flips within whatever convention the HSM emits. |
| 1.14 | Low | ⏳ Deferred | **Refuse `PassThroughPolicy` at signer-daemon startup.** No implementation site exists: `signer-daemon` is a library crate with no binary `main`, and `PassThroughPolicy` (`crates/signer/src/crosscheck.rs`) is not wired into any production startup path — it is a dev/test-only `CrossCheck` that already `warn!`s on every call. The "startup gate" has no home until the daemon gets a binary entrypoint that selects the policy from config; implement it there (compile-time feature-gate, or a runtime refuse-on-`PassThrough` in that main). |

## Phase 3.3 — Cosmos custody family (2026-05-31)

GAIA / ATOM. `LegacyAminoPubKey` 3-of-5 multisig custody, off-chain only
(no Solidity change — GAIA.ATOM is recognised as an async-leg asset by
the chain-generic adapter, gated behind the off-chain path landing).
Steps C1–C9 (no C10 — that is a Solidity-only gate, like V10). A 6-lens
red-team over the committed C1–C8 produced the hardening pass below; its
verify layer is folded into these entries.

See `docs/runbooks/cosmos-key-ceremony.md` for the per-chain Set-D
multisig ceremony.

| ID | Severity | Status | Note |
|---|---|---|---|
| P3.3-1 | Info | ❌ Accepted (DL-P3-7) | **Cosmos custody = `LegacyAminoPubKey` 3-of-5 (Set D).** A new secp256k1 key set, per Cosmos chain, no cross-chain key sharing (a separate ceremony from Sets A/B/C). `chain_registry::CustodyFamily::Cosmos`; `thor_asset()=="GAIA.ATOM"`, `decimals()==6`, `scale()==1_000_000`. |
| P3.3-2 | Info | ❌ Accepted (DL-P3.3-3) | **`SIGN_MODE_LEGACY_AMINO_JSON`, not `SIGN_MODE_DIRECT`.** Members sign the canonical amino `StdSignDoc` (recursively key-sorted, no whitespace, numbers-as-strings) — amino-json excludes the signer-set/bitarray, so every member of the positional `LegacyAminoPubKey` multisig signs byte-identical sign-bytes independently (THORChain's own gaia client signs `SIGN_MODE_DIRECT` — a single-signer path that does NOT apply to our k-of-n custody; the byte-match ground truth is gaiad, per P3.3-3, not THORChain). `crates/cosmos-tx/src/amino.rs`. The broadcast envelope is still the proto `Tx` (`ModeInfo` records the amino mode). |
| P3.3-3 | **High** | 📝 Operational | **Amino + `TxRaw` byte-exactness is a mandatory pre-mainnet gate.** `crates/cosmos-tx/src/{amino,addr,tx}.rs` hand-roll the canonical JSON sign-bytes, the `LegacyAminoPubKey` address, and the proto `TxRaw`. The unit tests pin OUR encoding (field numbers / wire types / layout), NOT gaiad ground truth. Before any mainnet funds: assert byte equivalence against `gaiad tx bank send --generate-only` + `gaiad keys add --multisig` for the target Gaia SDK version, and re-run after every Gaia upgrade. A single divergent byte = a network-rejected tx (stuck funds) or a wrong-spend. DL-P3.3-8. |
| P3.3-4 | **High** | ✅ Closed in code | **Consensus chain-id pinned in `CosmosSignerConfig`.** The chain-id is bound into the sign-bytes; the daemon refuses a request whose `cosmos_chain_id` differs from the pinned value (`WRONG_COSMOS_CHAIN_ID`, 422), blocking replay of a custody-move signature onto another Cosmos chain the same key controls. `crates/signer-daemon/src/cosmos_tx.rs`. Mirror of the EVM handler's chain pin. |
| P3.3-5 | Medium | ✅ Closed in code | **Canonical-decimal validation of numeric sign-doc fields.** `amino::canonical_json` rejects non-canonical `account_number` / `fee_amount` / `gas` / `amount` / `sequence` (leading zero, non-digit). The daemon recomputes the digest over the same strings, so a value like `"07"` would otherwise pass the self-check yet broadcast as network-invalid bytes (stuck funds). |
| P3.3-6 | Medium | ✅ Closed in code | **Member-pubkey validity check.** `CosmosMultisig::new` rejects any member key that is not a valid compressed secp256k1 point, so a ceremony typo can't bake an unspendable address. `crates/cosmos-tx/src/lib.rs`. |
| P3.3-7 | Medium | ✅ Closed in code | **`chain-cosmos` RPC timeouts.** `ReqwestCosmosChainClient` sets request (30s) + connect (10s) timeouts (matching `chain-utxo`); a stalled/black-holed Cosmos RPC can no longer wedge the signer cross-check / executor. |
| P3.3-8 | Low | ✅ Closed in code | **Verify-by-construction aggregation.** `sigs::aggregate` is `pub(crate)`; the only public entry, `aggregate_verified`, takes the `CosmosMultisig` descriptor + the sign-bytes digest and verifies every partial against the member pubkey at its claimed index (low-S enforced) before encoding — a foreign, misplaced, high-S, or duplicated partial fails at assembly. The `CompactBitArray` width + threshold derive from the descriptor, never from caller scalars. |
| P3.3-9 | Medium | ✅ Closed in code | **Refund cross-check binds the Asgard sender + applies the 1e8→1e6 scaling.** C6 `ThorCosmosRefundPolicy` requires the on-chain `transfer.sender` to equal the live GAIA Asgard vault (`ThorClient::vault_for_chain("GAIA")` via `/thorchain/inbound_addresses`), refuses while GAIA trading is halted, and divides the THORChain refund amount by 100 (THORChain 1e8 → uatom 1e6 — the R-T2 analogue). `CosmosTransfer` now captures `sender` (a recipient+amount match alone is forgeable on a public multisig address). `crates/signer/src/crosscheck.rs` (cosmos module) + `crates/chain-cosmos/src/client.rs`. |
| P3.3-10 | Medium | ✅ Closed in code | **`xindex-attest-redeem` custody-family gate.** Adding `ChainId::Gaia` (C1) made `from_asset_id` resolve Gaia, weakening the prior "unknown-asset → skip" safety net; the binary now explicitly skips any non-UTXO leg instead of routing a Gaia leg into the BTC/UTXO delivery cross-check. `crates/chain-eth/src/bin/xindex-attest-redeem.rs`. |
| P3.3-11 | Low | ❌ Accepted | **HTTP 500 + `bad_request` code on the daemon's replay-DB error paths.** The cosmos-tx handler pairs `error_codes::BAD_REQUEST` with `StatusCode::INTERNAL_SERVER_ERROR` on a transient sqlite failure — but this is **identical** to the established EVM-safe handler (`crates/signer-daemon/src/evm_safe.rs`). Left as-is to keep the two sibling handlers consistent; a status/code rename is a cross-handler v2 refactor, not a Cosmos-only change. |
| P3.3-12 | Medium | ❌ Accepted (DL-P3.2-7 analogue) | **No fee / gas-price oracle in v1.** Operators supply `fee_amount` + `gas_limit` per leg via `xindex-redeem-cosmos` CLI args. No `simulate` / fee-oracle call. A stale fee makes a broadcast fail `CheckTx` (sequence stays unconsumed; replay-safe), never burns funds at the wrong rate. |
| P3.3-13 | Info | ⏳ Deferred | **`xindex-redeem-cosmos` single-leg skeleton.** Drives one leg per invocation (parity with `xindex-redeem-evm`). The WS-subscription event loop (RedeemDispatched → build → broadcast → record the F2 `gaia` dispatch row C8 admits) is a follow-on; `CosmosRedeemExecutor` is loop-ready, only the binary wrapper is single-shot. **The in-process account lock is NOT a cross-invocation double-pay defense — `build_leg` reads `{account_number, sequence}` fresh from chain, so a re-driven `RedeemDispatched` after a confirmed payout builds a SECOND valid tx at the advanced sequence (audit 2026-06-01 M3). Mainnet readiness REQUIRES a persistent dispatch-dedup guard keyed on the real `dispatch_id`, not `B256::ZERO` (DL-P3-7 per-family gate).** |
| P3.3-14 | Info | ❌ Accepted | **C9 e2e: on-chain broadcast deferred.** C9 ships off-chain coverage (3 real daemons + 3-of-3 collection + replay/conflict via real HTTP). Live `broadcast_tx_sync` + the gaiad byte-match (P3.3-3) are a `#[ignore]`-d signet-rehearsal placeholder — same posture as P3.2-12. |
| P3.3-15 | Low | ❌ Accepted | **`transfers_to` single-page + URI-query broadcast.** The Cosmos client fetches one `/tx_search` page (`per_page=100`, asc) and broadcasts via `?tx=0x{hex}` in the URI. GAIA custody is a low-volume account, so a >100-inbound deep-history miss and a URI-length-limited large multisig tx are bounded operability risks. A pagination loop + a JSON-RPC POST-body broadcast are documented follow-ons; revisit at scale / rehearsal. |
| P3.3-16 | Info | ⏳ Deferred | **Cancel-stuck escrow (SD-B) applies to Cosmos legs.** A halted multisig (signer-party compromise + threshold not reached) leaves a Cosmos redemption permanently pending — same class as P3.2-14 / the BTC SD-B runbook. Formal/symbolic review of the cancel-stuck escrow path covers all three families; tracked as a mainnet gate. |
| P3.3-17 | **High** | 📝 Operational | **Per-(Cosmos-chain) Set-D key ceremony required before mainnet funds.** Each Cosmos chain has its own 3-of-5 `LegacyAminoPubKey` multisig, no cross-chain key sharing (DL-P3-7). Generate Set D air-gapped, derive the bech32 multisig address, byte-match it against `gaiad keys add --multisig` (P3.3-3), and run a signet rehearsal before mainnet. See `docs/runbooks/cosmos-key-ceremony.md`. Mirror of P3.2-3. |

## Phase 4.4 — XRP custody family (2026-05-31)

XRP / XRP.XRP. Native `SignerList` k-of-3-of-5 multisig custody, off-chain
only (no Solidity change — `XRP.XRP` is recognised as an async-leg asset
by the chain-generic adapter, gated behind the off-chain path landing).
Steps C1–C9 + a dedicated C10 red-team hardening pass. A 6-lens
adversarial red-team (find → independent verify) over the committed
C1–C9 produced the C10 fixes below; its verify layer CONFIRMED the
boundary defences (no daemon TOCTOU, DER malleability closed, per-signer
cross-member/duplicate/overflow all defended, replay key correct).

**The load-bearing divergence from Cosmos:** XRPL native multisign has
each member sign a DIFFERENT message —
`SHA512Half(SMT\0 ‖ body ‖ that-member's-own-AccountID)` — and the XRP
account is NOT derived from the member set (it is a separately-funded
account whose `SignerList` is configured on-chain). THORChain's own XRP
client is single-sign (TSS), so the native-multisign byte layout has **no
upstream reference** and is the highest-risk surface.

See `docs/runbooks/xrp-key-ceremony.md` for the per-chain Set-E multisig
ceremony.

| ID | Severity | Status | Note |
|---|---|---|---|
| P4.4-1 | **High** | 📝 Operational | **Native-multisign byte-exactness is a mandatory pre-mainnet gate.** `crates/xrp-tx/src/{st,signing,tx}.rs` hand-roll the canonical `STObject` serialization, the `SMT\0`-prefixed per-signer multi-signing blob, the AccountID-sorted `Signers` assembly, and `SignerListSet`. Unit tests pin OUR encoding + the §9.3 SOURCED thornode single-sign vector (which the serializer reproduces byte-for-byte AND whose real DER signature verifies against our `SHA512Half` digest). But thornode is single-sign only — there is **no sourced native-multisign vector**. Before any mainnet funds: byte-match `build_signed_multisig_tx` + `multisign_blob` + `serialize_signer_list_set` against `xrpl.js` `encodeForMultisigning` / `multisign` (or `rippled sign_for`) for the pinned amendment set. A single divergent byte = a network-rejected tx (stuck funds) or a wrong-spend. |
| P4.4-2 | Medium | ✅ Closed in code | **`LastLedgerSequence` deadline / replay nuance.** The deadline is bound into the body → into the per-signer digest. A retry at the same `Sequence` with a different deadline yields a different body → the daemon returns 409 (`check_xrp_tx` Conflict). The executor computes ONE deadline per leg; an expired-unbroadcast leg is terminal-for-that-sequence and may only be re-driven after `account_info` shows the `Sequence` advanced. `crates/executor/src/xrp_redeem.rs` + the C9 test `same_sequence_different_deadline_is_409`. The replay key stays `(chain, account, sequence)`; `payload_hash` is the per-signer digest (each member legitimately stores a different one — own AccountID suffix). |
| P4.4-3 | Info | ❌ Accepted (DL-P3-7) | **XRP custody = native `SignerList` k-of-3-of-5 (Set E).** A new secp256k1 key set, per XRP chain, no cross-chain key sharing. `chain_registry::CustodyFamily::Xrp`; `thor_asset()=="XRP.XRP"`, `decimals()==6`, `scale()==1_000_000`, `conf_depth()==1`. Unlike Cosmos, the account address is NOT member-derived — it is a separately funded XRPL account whose `SignerList` is established by `SignerListSet` + `AccountSet asfDisableMaster` (P4.4-16). |
| P4.4-4 | **High** | ✅ Closed in code | **Refund observation reads `delivered_amount`, never `Amount`.** XRPL `tfPartialPayment` can deliver far less than `Amount`; `chain-xrp::parse_delivered_drops` sources the value from `meta.delivered_amount` only (a missing / `"unavailable"` / issued-currency value yields an unverifiable transfer that is DROPPED, not up-counted), and the C6 `ThorXrpRefundPolicy` measures the refund by `delivered_drops`. Without this, a 1-drop partial payment could be attested as full value. Tests: `partial_payment_counts_delivered_not_amount`, `missing_delivered_amount_is_dropped`, `refund_rejects_partial_payment_under_floor`. |
| P4.4-5 | **High** | ✅ Closed in code | **Daemon never blind-signs; per-signer digest derived locally.** `handle_xrp_tx` re-serializes the `STObject` body from the semantic fields and refuses (`xrp_tx_mismatch`, 422) if it differs from `signing_blob`, then computes ITS OWN digest `SHA512Half(SMT\0 ‖ body ‖ my_account_id)` where `my_account_id` is derived from the configured member pubkey (never transmitted). The red-team confirmed no TOCTOU — the same re-derived `body` is both compared and signed. |
| P4.4-6 | Medium | ✅ Closed in code | **DER + low-S enforced; non-canonical re-encodings rejected.** `sigs::verify_der` parses strict canonical DER (k256 rejects trailing bytes, long-form lengths, non-minimal INTEGERs — regression test `der_rejects_noncanonical_reencodings`) and refuses high-S (rippled's `RequireFullyCanonicalSig`). `aggregate_verified` re-checks every partial against its OWN multi-signing digest, dedups by AccountID, and enforces the weight quorum before assembly. |
| P4.4-7 | **High** | ✅ Closed in code (C10) | **`Amount` / `Fee` bounded to the XRP supply cap.** `st::amount_payload` returns `None` above `MAX_XRP_DROPS` (1e17) and the tx builders reject it (`TxError::AmountOutOfRange`). A drops value with the type-flag bits (`0x80` issued / `0x40` positive / `0x20` MPT) set would otherwise silently encode a non-XRP amount; the bound (≪ 2^61) guarantees the drops never collide with the flags. The daemon path is covered (a bad amount makes `serialize_for_multisign` error → `bad_request`). |
| P4.4-8 | Medium | ✅ Closed in code (C10) | **Verify-as-collected: one bad daemon cannot DoS a leg.** `collect_signatures` verifies each partial against its own per-signer digest AS IT IS COLLECTED, skipping a malformed/garbage signature and trying the next cosigner, instead of counting weight on any `Ok` response and only failing at the final aggregate. Test: `build_leg_skips_garbage_partial_and_succeeds`. |
| P4.4-9 | Low | ✅ Closed in code (C10) | **Empty memo omits the `Memos` field.** rippled / thornode emit no `Memos` array for an empty memo (not an empty array); `payment_fields` skips the field when `memo.is_empty()`. The custody redeem memo is never empty, so this is byte-match correctness. |
| P4.4-10 | Medium | 📝 Operational | **`SignerList` ↔ descriptor drift is not re-verified on-chain in v1.** The executor's `XrpMultisig` descriptor is off-chain config; it is ASSUMED to equal the account's on-chain `SignerList` (established by the P4.4-16 ceremony). A drift produces a network-rejected tx (fail-closed, no fund loss) — a stale lower-quorum on-chain list still validates an over-signed tx, and a different-member list rejects ours. An `account_info` `signer_lists` cross-check before signing is a documented follow-on; the ceremony + disclosure artefact is the v1 guarantee. |
| P4.4-11 | Medium | ❌ Accepted | **`xindex-redeem-xrp` single-shot CLI limits.** The per-account lock is in-process only (two concurrent operator invocations against the same account could both consume the same `Sequence`), and there is no 409/retry handling (a re-run recomputes a new deadline → 409 → `InsufficientCosigners`). Operators run one leg at a time; a failed leg is replay-safe (the `Sequence` stays unconsumed). Same posture as `xindex-redeem-cosmos` (P3.3-13). The WS event-loop (RedeemDispatched → build → submit → record the `xrp` dispatch row C8 admits) is a follow-on; `XrpRedeemExecutor` is loop-ready. **The "replay-safe / `Sequence` stays unconsumed" property holds ONLY for a not-yet-broadcast leg — after a SUCCESSFUL broadcast, `build_leg` reads `account_info.Sequence` fresh, so a re-driven event builds a SECOND valid tx at the advanced sequence (audit 2026-06-01 M3). Mainnet readiness REQUIRES a persistent dispatch-dedup guard keyed on the real `dispatch_id`, not `B256::ZERO` (DL-P3-7 per-family gate).** |
| P4.4-12 | Low | 📝 Operational | **Cross-check `min_confirmations` must be ≥ 1.** A policy constructed with `0` would count a same-tip transfer (and, via saturating math, a future-ledger one). Operators construct `ThorXrpRefundPolicy` with `chain_registry::conf_depth(Xrp) == 1`. The `chain-xrp` parser's `validated == true` filter already bounds `ledger_index ≤ validated tip`, so a future-ledger arrival cannot occur. |
| P4.4-13 | Info | ❌ Accepted | **Delivery policy does no XRP-side observation.** `ThorXrpToUsdtPolicy` trusts THORChain `done` + the ETH-side USDT arrival (on-chain authoritative), mirroring the Cosmos/UTXO delivery policy — the refund leg is the one that binds the XRP sender to the live Asgard vault. The on-chain USDT value (not THORChain's figure) is attested. |
| P4.4-14 | Info | ❌ Accepted (DL-P3.2-7 analogue) | **No fee oracle in v1.** Operators supply `fee_drops` (`base_fee × (1 + signer_count)`) per leg via the `xindex-redeem-xrp` CLI. A stale fee fails `submit` (the `Sequence` stays unconsumed; replay-safe), never burns funds at the wrong rate. |
| P4.4-15 | Info | ❌ Accepted | **C9 e2e: on-chain broadcast deferred.** C9 ships off-chain coverage (3 real daemons + the per-signer divergence proof + 3-of-3 collection + replay/conflict via real HTTP). Live `submit` + the rippled byte-match (P4.4-1) are a `#[ignore]`-d signet-rehearsal placeholder — same posture as P3.3-14 / P3.2-12. |
| P4.4-16 | **High** | 📝 Operational | **Per-(XRP-chain) Set-E key ceremony + on-chain bootstrap required before mainnet funds.** Each XRP chain has its own 3-of-5 Set E (DL-P3-7). Generate Set E air-gapped, fund the account, establish the 3-of-5 via `SignerListSet`, disable the master key via `AccountSet asfDisableMaster`, byte-match the serialization against `rippled`/`xrpl.js` (P4.4-1), and run a testnet rehearsal before mainnet. See `docs/runbooks/xrp-key-ceremony.md`. Mirror of P3.3-17. |
| P4.4-17 | Low | ❌ Accepted | **`MAX_SIGNERS == 32` assumes the `ExpandedSignerList` amendment; no standard 8-entry cap.** A standard (non-expanded) XRPL `SignerList` / `Signers` array caps at **8**; `XrpMultisig::new` rejects only `> 32`, and the assembly path does not bound the effective signer count. Not attacker-reachable — the assembled count is fixed by operator deploy-time `--member-pubkeys` + `--quorum`, no redeem-task input influences it, and a misconfigured >8-signer blob fails CLOSED at broadcast (`temMALFORMED`), never mis-sending funds. Our 3-of-5 model is well under 8. The rippled byte-match (P4.4-1) + the key ceremony pin the real on-chain `SignerList`; an explicit configurable cap (8 standard / 32 expanded) is a documented follow-on. Red-team C10 LOW-1. |
| P4.4-18 | Info | ❌ Accepted | **`transfers_to` refund observation is single-page (no `marker` pagination).** `ReqwestXrpChainClient::transfers_to` (`crates/chain-xrp/src/client.rs`) issues one `account_tx` (`forward:true`, `limit:100`, `ledger_index_min = tip - lookback`) and `parse_account_tx` never follows `result.marker`. On a high-traffic XRP custody account, a THORChain refund `Payment` landing after >100 in-window inbound txs falls on page 2+ → `find_xrp_arrival` returns `None` indefinitely → the signer never attests. FAIL-CLOSED: the value is sourced from `meta.delivered_amount` (P4.4-4) and bound to the live Asgard `sender`, so no false attestation / no fund loss — a bounded stuck-redemption (liveness) risk only, mirroring the Cosmos twin P3.3-15. v1 mitigation: low-volume custody + an operator alert when a redemption is stuck > N ledgers. A `marker`-loop in `transfers_to` (mirroring the M-R9 Esplora pagination pattern) is a documented follow-on; revisit at scale / signet rehearsal. Audit 2026-06-01 I1. |

## 2026-06-01 deep Rust audit — 36 confirmed findings

65-agent workflow (tool battery → 22 crate×vuln-class auditors → adversarial
verify → report) over `feat/phase-4-4-xrp`. Confirmed: 2 High, 9 Medium, 14
Low, 12 Info; 4 refuted. **No live fund-loss path** — every cross-chain custody
path fails closed; failures are liveness / availability / defense-in-depth.
**H1 was the only finding live on today's BTC mainnet rail.** Remediation landed
on `feat/rust-audit-2026-06-01`. **Follow-up (2026-06-07, `feat/rust-audit-followup-2026-06-06`):**
the deferred code-fixable findings M2 + I3, M4/L7, L8/L12, L5, L10, L1, L3, I5 are now
closed in code (rows below); `just gate` green (515 tests, clippy `-D warnings`,
deny, audit). The remaining `⏳`/`❌` rows are operational mainnet-gates (M3) or
cross-repo ABI re-sync (L13), not code defects.

| ID | Sev | Status | Note |
|---|---|---|---|
| H1 | High | ✅ Fixed in code | **Reserve-before-broadcast.** `BroadcastRegistry::reserve` writes a 'reserved' write-ahead row before the irreversible BTC broadcast; `register` promotes it. Migration adds the status. Closes the H-R1 double-pay ordering. Tests: `*_reserve_dedups_then_register_promotes`. |
| H2 / L9 / I7 / I8 | High | ✅ Fixed in code | **Per-leg replay key.** Redemption replay store keyed on `(redemption_id, leg_index)` (trait + InMemory + SQLite + migration), mirroring the on-chain per-leg mutex. Fixes the latent multi-leg brick + the inverted M5/I7 comments. Test: multi-leg `run_redemption_lifecycle`. |
| M1 / L11 | Med | ✅ Fixed in code | **Verify-as-collected** in EVM + Cosmos `collect_signatures` (mirrors XRP C10). A Byzantine cosigner can't DoS a leg. |
| M6 | Med | ✅ Fixed in code | **Recover-verify** added to the 3 EIP-712 daemon handlers (attestation/delivery/refund) — extends the 1.5/H11 backstop. |
| M7 | Med | ✅ Fixed in code | `parse_secret_keys` no longer echoes raw secret-key hex (CWE-532); index-only errors. |
| M8 | Med | ✅ Fixed in code (2026-06-10) | **Deep-reorg re-validation of confirmed broadcasts.** Was partial (default 3→6). The deferred slice is now closed: `mark_confirmed` records the confirming `block_hash`/`block_height`; the watcher's new `revalidate_confirmed` pass re-checks every `Confirmed` row each tick (`list_confirmed`) — an orphaned payout (tx no longer confirmed, recorded block re-orged out) is demoted via `mark_pending` (zeroes `last_attempt`) so the next tick re-broadcasts the SAME tx (idempotent on Bitcoin); a tx re-confirmed in a different block updates the recorded block; and a row buried `final_depth` deep (default 100, beyond any plausible re-org) graduates to a new terminal `Final` status so the re-validated set stays bounded (operator sweep now targets `Final`). Trait + InMemory + Sqlite + migration `20260610000000_add_final_status_and_block.sql` + `WatcherConfig.final_depth` (CLI `--rebroadcast-final-depth`). Tests: `tick_demotes_orphaned_confirmed_to_pending`, `tick_marks_final_when_deep`, `tick_updates_block_on_survived_reorg`, `run_reorg_lifecycle` (InMemory + Sqlite). |
| M9 / I11 | Med | ✅ Fixed in code (2026-06-10) | **Per-leg confirmation depth + under-confirmation floor (attest binary).** Was partial (defaults aligned). Now closed: `xindex-attest-redeem` enforces a **startup hard floor** (`enforce_confirmation_floors`) rejecting `--eth-min-confirmations < ChainId::Eth.conf_depth()` (12) or `--btc-min-confirmations < ChainId::Btc.conf_depth()` (6) in `thor-btc-usdt` mode (the line-143 "rejected at startup" comment was previously aspirational — now true), and a **per-leg depth gate** (`leg_depth_satisfied`) in `process` that refuses to attest a leg whose chain `conf_depth` (BTC 6, LTC 12, DOGE 40, ZEC 10) exceeds the configured threshold — a no-op for BTC, fail-closed for a deeper-finality leg before its per-chain rollout. Tests: `confirmation_floors_reject_under_depth`, `per_leg_depth_gate`. |
| I2 | Info | ✅ Fixed in code | P3.3-2 corrected — THORChain's gaia client signs `SIGN_MODE_DIRECT`; gaiad (not THORChain) is the amino byte-match ground truth. |
| I4 | Info | ✅ Fixed in code | `SafeLockTable` comment corrected — the lock spans `nonce-read → build`, submit is outside it. |
| L2 | Low | ✅ Fixed in code | Sub-dust BTC change folded into the fee (gives `UtxoParams::dust_sats` a consumer). |
| L4 | Low | ✅ Fixed in code | A malformed coin in a Cosmos `tx_search` transfer is skipped, not propagated. |
| L6 | Low | ✅ Fixed in code | `decode_router_transfer_out` re-asserts `to == safe` client-side. |
| L14 | Low | ✅ Fixed in code | `cargo deny` ⊉ `cargo audit` claim corrected (verified on deny 0.19.4: `lru` absent from deny's feature-resolved graph); `cargo audit` is the authoritative gate; added valid `unmaintained = "all"` (report's `unsound` key was removed in deny 0.18). |
| I1 | Info | ❌ Accepted | **P4.4-18** added — XRP `transfers_to` single-page (fail-closed liveness, mirrors P3.3-15). |
| I6 | Info | ✅ Fixed in code | `erc20` confirmations `saturating_add(1)`. |
| I9 | Info | ✅ Fixed in code | `parse_broadcast` strictly decodes `result.code` (no fail-open default-0). |
| I12 | Info | ✅ Fixed in code | ETH redemption-attestation default confirmations 6→12. |
| M3 | Med | ❌ Accepted | Account redeem binaries' in-process lock is NOT a cross-invocation double-pay defense (`build_leg` reads nonce/sequence fresh). Acceptance text on P3.2-13 / P3.3-13 / P4.4-11 amended; mainnet REQUIRES a persistent dispatch-dedup guard keyed on the real `dispatch_id` (DL-P3-7 per-family gate). |
| M2 | Med | ✅ Fixed in code | **BTC daemon PSBT output veto.** `PsbtInputSignRequest` now carries optional `expected_destination_spk` / `expected_amount_sats` / `expected_memo`; `veto_outputs` (psbt.rs) refuses with `PSBT_OUTPUTS_MISMATCH` (422) **before any HSM call** unless an output pays the pinned destination+amount and an `OP_RETURN` pushes the memo. The pinned values come from the decoded `RedeemDispatched` event (NOT the PSBT). Tests: `output_veto_passes_when_expected_match`, `output_veto_rejects_wrong_{destination,amount,memo}`. Folded I3 in (see below). **Scope caveat:** this is a PRESENCE check — it binds that the Asgard payout + memo are present, NOT that the rest of the tx is honest. The change output / fee are unconstrained — see **M2b**. |
| M2b | **High** | 🟡 Partially mitigated in code (Option 1 floor); residual folded into **CTD-1** | **PSBT veto binds payout PRESENCE, not total spend (change/fee unbounded).** `veto_outputs` confirms SOME output pays Asgard+amount and SOME `OP_RETURN` carries the memo, but the daemon signs `SIGHASH_ALL` (psbt.rs:247) which authorizes the ENTIRE output set. A compromised/malicious coordinator can build `[Asgard(amount), OP_RETURN(memo), change→ATTACKER]` (or omit change → residue burned as fee); the veto passes, 3-of-5 sign, the residue is stolen. Not live (BTC mainnet-gated, DL-P3-7). **Floor shipped (2026-06-07, DL-M2B-1 Branch B):** `enforce_change_and_fee` (psbt.rs) — two daemon-LOCAL checks that need no trusted intent: (1) **change-to-self** — when the payout is pinned, every output must be ∈ {pinned payout spk, **zero-value** `OP_RETURN`, the daemon's own descriptor P2WSH} (`PSBT_UNEXPECTED_OUTPUT`, 422), so change cannot reach an attacker and a funded `OP_RETURN` cannot burn value; (2) **fee cap** — `Σ inputs − Σ outputs ≤ ChainId::max_redeem_fee_sats` (`PSBT_FEE_EXCEEDS_CAP`, 422), bounding fee-burn. Tests: `m2b_change_to_self_is_accepted`, `m2b_change_to_attacker_is_rejected`, `m2b_excessive_fee_is_rejected`, `m2b_funded_op_return_is_rejected` + `max_redeem_fee_sats_per_chain`. **This is NOT a full fix:** the pinned payout destination/amount/memo are still coordinator-supplied and the change-to-self check is skipped when the payout is absent — the residual (and the identical gap on the other 5 families) is **CTD-1** below. Found by the 2026-06-07 read-only adversarial review (1 HIGH confirmed; 3 refuted). |
| M4 / L7 | Med | ✅ Fixed in code | **UTXO live-Asgard sender binding.** New `UtxoChainClient::tx_input_addresses` (Esplora `get_tx_info` → vin prevout `scriptPubKey` → address) + `expected_sender` binding in the UTXO cross-check (crosscheck.rs), back-porting P3.3-9 to UTXO. +tests in crosscheck.rs / chain-utxo client.rs. |
| L8 / L12 | Low | ✅ Fixed in code | **UTXO + EVM halt gate.** Both policies now call `vault_for_chain(thor_chain_label)` and gate `verify()` on the THORChain halt/trading-paused flag (parity with Cosmos/XRP). +re-mocked policy tests. |
| L5 | Low | ✅ Fixed in code | **EVM native-delivery asset binding.** `RouterTransferOut.asset` decoded + `expected_asset: Option` on `ThorEvmPolicy::new`; cross-check binds the delivered asset. Still latent (no production EVM-attest caller yet) but the binding ships with the policy. |
| L13 | Low | ⏳ Deferred | **`xindex-finalize-redeem` doesn't observe `RedemptionStuckCancelled`** → orphaned tracker row re-fires a false SD-B alert. Observation-only (cancel settles correctly on-chain). Needs an ABI re-sync (`just sync-abi`, a cross-repo `forge build`) to expose the event, then subscribe + add a `mark_resolved` arm. |
| L10 | Low | ✅ Fixed in code | **Replay check→sign→record TOCTOU idempotent recovery.** New `ReplayError::Duplicate` (InMemory raises it directly; SQLite maps the UNIQUE violation via `map_insert`). All **7** handlers (attestation, redemption, psbt-input, safe-tx, cosmos, xrp, tron) now recover on the write-race: re-read via `check_*` and return the cached signature (deterministic ECDSA → byte-identical), mapping Conflict/MutexViolation/FirstTime to the correct HTTP code instead of a 4xx/5xx to the race-loser. Tests: `psbt_record_race_recovers_cached_signature`, `attestation_record_race_recovers_cached_signature` (+ `test_support::RaceReplayStore`). The other 5 recoveries share the identical pattern (record/check arg + stored-bytes consistency verified by review); a dedicated `RacePath` per chain is a follow-on. |
| L1 | Low | ✅ Fixed in code | **Legacy sighash fail-loud** (`e89f7a2`). `SighashFlavor` discriminant rejects pre-BIP-143 / non-witness spends loudly. BCH FORKID / ZEC BLAKE2b sighash *algorithms* remain U10 multi-chain-gated (unreachable today: executor hardcodes Witness spends, daemon accepts only P2WSH, BTC-only mainnet). |
| L3 | Low | ✅ Fixed in code | **Per-chain `OP_RETURN` cap** (`e89f7a2`). `UtxoParams::op_return_max` threaded into `build_spending_psbt` (80 BTC/LTC/DOGE/ZEC, 220 BCH) instead of the hard-coded 80; executor passes BTC's 80. |
| I3 | Info | ✅ Fixed in code | PSBT handler binds `witness_utxo.script_pubkey` to the descriptor P2WSH program before signing (`WRONG_DESCRIPTOR`, 422). Folded into M2. Test: `forged_witness_utxo_spk_is_rejected`. |
| I5 | Info | ✅ Fixed in code | `decode_transfer_log` (chain-eth) + `decode_router_transfer_out` / `decode_erc20_transfer` (crosscheck) now re-assert `log.address == token`/`router` client-side. +negative tests. |
| **Refuted (4)** | — | — | Amino memo HTML-escape (the contract-built memo provably can't contain `<>&`); BTC PSBT low-S (k256 `verify_ecdsa` rejects high-S, fails closed before record — I10 is the same); UTXO `min_confirmations==0` lower bound (operator-config-only, no production binary sets 0). |

Full report: `~/.claude/projects/-Users-imac-Movies-Xindex/audit-rust-report.md`.

---

## CTD-1 — Coordinator-trusted destination (fleet-wide) — **Critical, Open**

**Status:** ⏳ Open (design fix scheduled; DL-gated before any native-chain mainnet). Found 2026-06-07 by an 8-agent cross-family verification (per-family read-only probe → adversarial default-refute → synthesis), corroborated by direct reads of `server.rs`, `psbt.rs`, `evm_safe.rs`, `cosmos_tx.rs`, `xrp_tx.rs`, `solana_tx.rs`, `tron_tx.rs`, `web3signer.rs`, `redeem.rs`.

**Finding.** Every signer-daemon family — UTXO/BTC, EVM-Safe, Cosmos, XRP, Solana, TRON — derives the destination/amount/memo it signs over from the **coordinator's HTTP request**, never from a channel the coordinator cannot forge. Each daemon independently proves only *what* is spent (the input is one of our own custody UTXOs/accounts: descriptor/`safe_address`/account match), prevents replay/double-sign, and verifies its own signature — i.e. it constrains the **source**, not the **destination**. `DaemonState` (`server.rs:83-120`) holds only static per-chain signer configs + replay store + HSM client; the daemon's sole outbound client is the HSM frontend (`web3signer.rs:90`). There is **no** ThorClient / VaultRegistry / Ethereum-event reader anywhere in `signer-daemon`. The one `redemption_id`-bearing request (`RedemptionDeliverySignRequest`) feeds only the after-the-fact EIP-712 delivery attestation + the replay key — it is never wired into the six transaction-signing handlers.

**Impact.** A single fully-compromised coordinator (the exact actor the 3-of-5 / never-blind-sign architecture is advertised to defend against) builds a spend of our custody to an attacker address, sends it to each daemon (optionally with `expected_*` omitted, since the BTC veto is enforce-if-present), and all *k* honest HSMs rebuild from the same poisoned request and sign. Funds reach the attacker or are burned; the redeemer is re-credited on Ethereum (no delivery → no delivery-attestation → refund), so the loss is **socialized across all index holders** as a shortfall in the basket's reserves. k-of-n + HSM key-isolation provide **zero** protection on destination. **Not live today** — all native custody is mainnet-gated (DL-P3-7).

**Corrects the prior record.** This consolidates and re-rates **M2b** (BTC), **P-SOL-7**, **P-TRON-7**, and the XRP/Cosmos cases, which were logged as per-chain Medium/High "Deferred" with the rationale *"binding the destination to the burn event is the attestation/cross-check layer's job."* That rationale does **not** hold: the attestation/cross-check layer confirms *delivery after the fact* — it does not authorize the destination *before* the spend and does not prevent the drain. The correct class is one **fleet-wide Critical**, not five deferred mediums. BTC is **not** uniquely weak; after the M2b floor it is the *least* weak (only family with even change/fee binding).

**Decision (DL-M2B-1 / DL-CTD-1, 2026-06-07): coordinator is OUT of the trusted computing base — fix fleet-wide.** Required before any native-chain (incl. BTC) touches mainnet:
1. **Independent intent channel.** Carry `redemption_id` in every transaction-sign request; each daemon resolves canonical `(destination, amount, memo)` from its OWN Ethereum RPC reading the `RedeemDispatched`/burn event (the signers already attest these events — natural root of trust), cross-checked against a locally-pinned per-chain Asgard/vault resolution. Sign only if the rebuilt destination/amount/memo equal the on-chain intent.
2. **Mandatory vetoes.** Reject when `expected_*`/intent is absent (never enforce-if-present); on BTC additionally assert no non-whitelisted material output (the M2b floor, now mandatory).
3. **Floor shipped** — the M2b local change-to-self + fee cap (and per-family equivalents) are the minimum, understood to be necessary-but-not-sufficient.
4. **Gate.** Until (1)-(2) land, CTD-1 is Critical-open and **all** native-chain mainnet redemption — BTC included — is DL-gated on it, not just the non-BTC families.

**Fix architecture LOCKED (DL-CTD-2, 2026-06-10)** — supersedes the mechanism sketch in (1) above (a daemon-side Ethereum RPC would break the RPC-free daemon boundary, DL-M5-5/RA-6): **per-operator observer + Redemption Intent Certificate (RIC)**. Each of the 5 operators runs its OWN observer that independently resolves the Asgard inbound + verifies the amount from diverse, ≥2-source cross-confirmed THORChain endpoints, then has its Set-B daemon sign a RIC (5th EIP-712 typed-data on `attestation_oracle_domain`, off-chain only). The RPC-free custody daemon verifies the k-of-n RIC signatures STATELESSLY against a static ceremony-disclosed whitelist and binds the spend's destination/amount/memo to the certified values; one-shot per `(chain, redemptionId, legIndex)`; recency via `vaultResolvedAt` + `ric_max_age` (no on-chain vault epoch exists, RA-5). Honest ceiling = k-of-n operator honesty on diverse sources (no THORChain light-client vault proof exists); containment (per-period volume circuit-breaker + fraud-proof window) lands alongside, not after. Solana stays hard-gated (RA-2). Plan: `~/.claude/plans/moonlit-marinating-boot.md` (Slices A–E).

**Slice A progress (2026-06-10, commits `f22cfd5`, `2a958eb`, + A.7):**
- **A.1** `RedemptionIntentCertificate` 5th typed-data (`shared/src/eip712.rs`): pinned type-string test (cross-operator digest consistency — no Solidity counterpart by design) + 5-way pairwise-distinct.
- **A.2** custody one-shot replay arm keyed `(chain, redemptionId, legIndex)` (`ric_intents`, migration 0010): identical retry idempotent, DIFFERENT RIC for the same leg = 409 — the RA-1 anti-re-drive guard.
- **A.3a** `IntentProof` wire struct (plaintext RIC fields + k-of-n Set-B sigs) + 5 error codes (`intent_proof_required`/`intent_proof_invalid`/`intent_mismatch`/`intent_vault_stale`/`intent_already_signed`).
- **A.4** pure `validate_intent_proof` (`signer-daemon/src/intent.rs`): recomputes the RIC digest on the daemon-pinned domain (never trusts the coordinator's); STRICT signature-set verification — any malformed/duplicate/non-whitelisted signature rejects the WHOLE proof; ≥ `intent_quorum` DISTINCT static-whitelist signers; recency window incl. a future-dating guard; fail-closed on a misconfigured policy. 18 unit tests incl. tamper-a-field and wrong-domain/wrong-oracle replay.
- **A.7** Set-B signing endpoint `POST /api/v1/sign/eip712-ric` + `ric_certs` NON-EQUIVOCATION arm (migration 0011 — deliberately SEPARATE from `ric_intents` so a multi-role daemon can never conflate "I certified this intent" with "I authorized the spend"): digest recomputed from plaintext fields; Solana refused (`ric_chain_forbidden`, RA-2); stale/future `vault_resolved_at` refused at the source (hardcoded 600 s signing window + 60 s skew); a second, different certificate for the same leg = 409 and never reaches the HSM; M6 recover-verify before record/return. Client: `RemoteHsmBackend::sign_ric`.
- **Handler gates WIRED (2026-06-11, the breaking-wire commit):** all five custody handlers (PSBT / EVM-Safe / Cosmos / XRP / TRON) now REQUIRE a k-of-n `IntentProof` (`intent_proof_required`, 422 — no proof-less carve-out), verify it statelessly against the mandatory `DaemonConfig.intent_policy` whitelist, bind the certified asset to the chain's native `asset_id_hash` + registry decimals (a BTC cert can never authorize an LTC spend), CONSUME the `(chain, redemptionId, legIndex)` one-shot BEFORE the HSM (same-cert retry passes idempotently; a different cert is a 409 `intent_already_signed`), and bind the spend bytes to the certified values: BTC = exactly-one payout output whose `keccak(scriptPubKey)` matches + exact amount + exactly ONE zero-value `OP_RETURN` hashing to the certified memo (RA-3 exact-set) + change-to-self unconditional; EVM = registry-pinned Router `to` + `depositWithExpiry` decode (shared `thorchain_router` sol! — builder and verifier share ONE ABI) with `asset == address(0)`, `keccak(vault)`, calldata-amount == Safe-value == certified amount, memo hash; Cosmos = native-denom pin (`uatom`) + destination/amount/memo binds; XRP/TRON = destination/amount/memo binds, TRON `Usdt` kind refused (not registry-mapped). Executor/coordinator side threads `intent_proof` through every task struct, `MultisigCosigner::sign_input`, `EvmCosigner::sign_safe_tx`, and the remote cosigners; binaries currently attach `None` (daemons fail closed) until Slice B supplies real certificates.
- **KNOWN CONSEQUENCE (Slice C blocker):** the PSBT gate is unconditional, so the **mint-cancel BTC swap-back** (`AcquireCancelled`) path CANNOT be signed until the Acquire-Cancel sibling certificate lands (Slice C: psbt gate accepts RIC XOR AC-cert). Deliberate fail-closed ordering — a no-RIC carve-out would re-open CTD-1.

**Slice B BUILT (2026-06-11) — per-operator observer + RA-6 + diverse ≥2-source Asgard ("the teeth"):**
- **≥2-source Asgard agreement gate** (`chain-thor/src/agreement.rs`, `AsgardAgreement`): resolves the inbound from each operator's OWN distinct THORChain sources concurrently and requires UNANIMITY among the ≥2 responders on `(address, router)` + OR'd halt flags (refinement 1 — the k-of-n floor is illusory on a single shared source). A disagreement is a hard refusal, NEVER majority-voted away; a single poisoned/MITM'd endpoint cannot drive a sign. 8 tests (agree / disagree / 2-of-3-no-override / sub-minimum / halt / chain-absent / gas-rate-differs-OK).
- **Per-operator observer** (`chain-eth/src/observer.rs`, `Observer` + `xindex-observe-redeem` binary): each operator independently reads `RedeemDispatched` leg facts from its OWN Ethereum RPC, resolves Asgard via its own agreement gate, rebuilds the canonical RIC, and asks its OWN Set-B daemon to sign it (`POST /api/v1/certify-ric`). `immediate_target_hash` is derived family-exactly to match the daemon bind (UTXO `keccak(scriptPubKey)`, EVM `keccak(20-byte addr)`, account-string `keccak(utf8)`). Solana always refused (RA-2). 9 + binary tests incl. an end-to-end recover-the-signature-over-the-rebuilt-digest assertion and source-disagreement / halt / stale-stamp / wrong-chain refusals.
- **Thin relay collection** (`shared/src/ric_relay.rs` `assemble_intent_proof` + `executor/src/ric_collector.rs` `RicCollector`): fans certify out to the operators, groups responses by certified plaintext, dedups by signer, and assembles the k-of-n `IntentProof` for the plaintext ≥ quorum observers agree on — a poisoned minority lands in its own group and never reaches quorum; tolerates `n - quorum` failures. The relay is UNTRUSTED (no crypto; the custody daemon re-verifies statelessly). `xindex-redeem` collects the RIC before dispatch, pays to the observers' AGREED Asgard (not its own resolution), and attaches the proof — replacing the Slice-A `None`. 14 tests (relay 9 + collector 5).
- **CTD-1 still Critical-Open** — closes only after Slice B's **signet rehearsal with real operators** AND Slice C (mint-cancel) + containment (Slice E). Slice B is prevention-built, not yet rehearsed.

## Phase 4.5 — Solana custody family (2026-06-04)

Native SOL custody via Squads V4 program multisig (the first **ed25519**
family). Core Solana has no account-level k-of-n for native SOL and
FROST/TSS is deferred, so a program multisig is required (DL-2026-05-09).
A redemption is a `1 + threshold + 1` on-chain choreography (propose →
approve×T → execute), NOT a single assembled tx. No live fund-loss path:
every step fails closed; the open items are pre-mainnet gates / liveness.

| ID | Sev | Status | Note |
|---|---|---|---|
| P-SOL-1 | **High** | 📝 Operational | **Squads-JS byte-exactness is a mandatory pre-mainnet gate.** `crates/solana-tx/src/{message,squads}.rs` hand-roll the legacy message compilation, the `SmallVec` inner `TransactionMessage`, the Anchor discriminators, and the 5 Squads instruction encoders. Unit tests pin OUR encoding (a hand-computed inner-message vector + per-instruction account/arg layout) + the account orderings/arg layouts taken from the Squads V4 IDL/source — but there is **no thornode native-multisig reference** (THORChain's SOL client is single-sign/TSS). Before any mainnet funds: byte-match each of `multisig_create_v2` / `vault_transaction_create` (incl. inner message) / `proposal_create` / `proposal_approve` / `vault_transaction_execute` against the `@sqds/multisig` JS SDK on devnet. A single divergent byte = a network-rejected tx (stuck funds) or a wrong-spend. Mirror of P4.4-1 / P3.3-3. |
| P-SOL-2 | **High** | 📝 Operational | **Per-(Solana-chain) Set-F key ceremony + `multisig_create_v2` bootstrap required before mainnet funds.** Each Solana chain has its own 3-of-5 Set F (DL-P3-7). Generate Set F (**ed25519**) air-gapped, establish the multisig via `multisig_create_v2` (`threshold 3`, `config_authority None`, `time_lock 0`, `PERMISSION_ALL` each, `vault_index 0`), byte-match against `@sqds/multisig` (P-SOL-1), and run a devnet rehearsal. See `docs/runbooks/solana-key-ceremony.md`. Mirror of P4.4-16 / P3.3-17. |
| P-SOL-3 | Info | ❌ Accepted | **e2e on-chain broadcast deferred.** S7 ships off-chain coverage: the executor drives the full propose/approve×3/execute choreography through the REAL daemon `validate_and_sign` (`crates/signer-daemon/tests/solana_e2e.rs`) against a stub chain. Live `sendTransaction` + the Squads-JS byte-match (P-SOL-1) are devnet-rehearsal territory — same posture as P4.4-15 / P3.3-14. |
| P-SOL-4 | **High** | 📝 Operational | **ed25519 HSM is net-new and NOT yet wired.** Every other family signs secp256k1 via the HSM digest signer (`HsmDigestSigner`); Solana signs ed25519 over the full message. Until the HSM front-end (Web3Signer / YubiHSM2) supports ed25519, the member key is a **software seed** held in `SolSignerConfig.member_seed`. This is the same HSM-deferred posture all families carry (DL-M5-2), but the key material is LOCAL here — mainnet REQUIRES ed25519 HSM provisioning (the Set-F prerequisite). `crates/signer-daemon/src/solana_tx.rs`. |
| P-SOL-5 | Medium | ❌ Accepted | **Proposer + executor are `cosigner[0]` with no fallback.** `solana_redeem` uses `cosigner[0]` to propose (tx1) and execute (final tx); only the approve loop is fault-tolerant. If `cosigner[0]`'s daemon is down, the leg stalls (fail-closed liveness, no fund loss — the index is reserved, recovery resumes). Proposer/executor fallback (with per-member cache keying for the create/execute steps) is a documented follow-on. |
| P-SOL-6 | Medium | ✅ Fixed in code (2026-06-10) | **Daemon replay-DB keyed for Solana.** New `(check\|record)_solana_tx` arm on `ReplayStore` (InMemory + Sqlite + migration `0009_create_signed_solana_txs.sql`), keyed `(chain, multisig, transaction_index, kind, member)` and wired into `handle_solana_tx`. The `payload_hash` is the SEMANTIC intent (kind + transaction_index + destination + amount + memo), deliberately EXCLUDING the volatile `recent_blockhash`: a re-sign of the same intent with a fresh blockhash is `Idempotent` (the handler re-signs the fresh message — ed25519 is deterministic and local, so no stale cached sig is returned), while a DIFFERENT destination/amount at an already-used step is a 409 `Conflict`. Defense-in-depth on top of the on-chain Squads guards (duplicate create/approve/execute already rejected). Tests: `in_memory_solana_tx_lifecycle` + `sqlite_solana_tx_lifecycle_matches_in_memory` (replay store) + `handler_records_then_idempotent_replay` + `handler_conflicts_on_different_intent_same_step` (handler). **Note:** Solana stays hard-gated out of mainnet v1 (CTD-1-OPEN per DL-CTD-RIC-V2 / RA-2); this closes the replay defense-in-depth regardless. |
| P-SOL-7 | Medium | ⏳ Deferred (mainnet gate) | **Daemon does not independently bind the destination to the burn event.** The never-blind-sign rebuild guarantees the transfer **source is our re-derived vault**, the programs are allowlisted (Squads/System/Memo), the sole signer is this member, and the destination is not the vault/multisig/a member/a program. But the daemon trusts the coordinator's `inner_destination` (it rebuilds from it and byte-matches `message_hex`) — the same posture as the XRP/Cosmos daemons (they also trust the coordinator's destination; the binding to the user's burn-event address is the attestation/cross-check layer's job). A compromised coordinator therefore needs `threshold` honest daemons to sign a transfer to an arbitrary non-member address. Cross-repo follow-on: observe the Ethereum `RedeemDispatched` event in the daemon and bind `inner_destination` to it. `crates/signer-daemon/src/solana_tx.rs`. |
| P-SOL-8 | Info | ❌ Accepted | **`xindex-redeem-solana` single-shot CLI.** The per-multisig lock is in-process only; `dispatch_id`/`redemption_id` default to `B256::ZERO`. The event loop (RedeemDispatched → execute_redeem → record the `sol` dispatch row) is a follow-on; `SolanaRedeemExecutor` is loop-ready and its write-ahead `transaction_index` reserve + on-chain-status recovery make a re-driven event idempotent (unlike the XRP/Cosmos single-tx binaries — P4.4-11 / M3). Mainnet still requires the real `dispatch_id` wired (DL-P3-7). |
| P-SOL-9 | Info | ❌ Accepted (DL-P3-7) | **Solana custody = Squads V4 program multisig (Set F).** `chain_registry::CustodyFamily::Solana`; `thor_asset()=="SOL.SOL"`, `decimals()==9`, `scale()==1_000_000_000`, `conf_depth()==1` (the `chain-solana` client reads at commitment `finalized`), `fee_unit()==SolanaComputeUnits`. The multisig + vault PDAs are functions of the one-time `create_key` (config, not member-derived). |
| P-SOL-10 | Low | 📝 Operational | **`transfers_to` inbound observer is single-page.** `ReqwestSolanaChainClient::transfers_to` issues one `getSignaturesForAddress` (`limit 100`) and does not follow `before`-pagination. On a high-traffic vault a delivery beyond the first 100 signatures is missed → the signer never attests (fail-closed liveness, no fund loss — same shape as P4.4-18 / P3.3-15). v1 mitigation: low-volume custody + a stuck-redemption alert; a pagination loop is a documented follow-on. |

## Phase 4.6 — TRON custody family (2026-06-05)

Native TRX + TRC20-USDT custody via a TRON account-permission k-of-n
multisig (an `Active` `Permission` with weighted keys + a threshold).
secp256k1 + keccak256 (reuses the existing `HsmDigestSigner` — NOT net-new
like Solana's ed25519). Unlike XRP's per-signer blob, every member signs
the IDENTICAL `txID = sha256(raw_data)`; the 65-byte recoverable sigs append
to `Transaction.signature[]` and the node sums weights. The redeem leg sends
to the THORChain Asgard inbound with the swap memo (same routing as
Cosmos / XRP). No live fund-loss path: every step fails closed; the open
items are pre-mainnet gates / liveness. TRON is the 6th and last THORChain
chain family.

| ID | Sev | Status | Note |
|---|---|---|---|
| P-TRON-1 | **High** | 📝 Operational | **Protobuf / txID byte-exactness is a mandatory pre-mainnet gate (PARTIALLY pinned).** `crates/tron-tx/src/{proto,tx}.rs` hand-roll the proto-3 `raw_data` wire encoding + the `txID = sha256(raw_data)`. The native-TRX `TransferContract` path is pinned byte-for-byte against a SOURCED thornode vector — `trx_txid_matches_thornode_sourced_vector` reproduces `createtransaction.json`'s `9908eed5…` exactly (stronger than P4.4-1 / P-SOL-1, which had no sourced vector). But the TRC20 `TriggerSmartContract` path, the `AccountPermissionUpdateContract` bootstrap, and the multi-sig `Transaction.signature[]` assembly have **no sourced vector**. Before any mainnet funds: byte-match `build_usdt_raw_data` + `build_signed_transaction` + the ceremony's permission-update tx against `tronweb` / `java-tron` (build the same tx, compare `raw_data_hex` + `txID`). A single divergent byte = a network-rejected tx (stuck funds) or a wrong-spend. Mirror of P4.4-1 / P3.3-3. |
| P-TRON-2 | **High** | 📝 Operational | **Per-(TRON-chain) Set-G key ceremony + `AccountPermissionUpdateContract` bootstrap required before mainnet funds.** Each TRON chain has its own 3-of-5 Set G (DL-P3-7). Generate Set G (secp256k1) air-gapped, fund the account, establish the 3-of-5 via `AccountPermissionUpdateContract` (an `Active` `Permission` with `id ≥ 2`, `threshold 3`, five `{key, weight 1}` entries, `operations` bitmap covering `TransferContract` bit 1 + `TriggerSmartContract` bit 31), byte-match against `tronweb` (P-TRON-1), and run a Nile-testnet rehearsal. `AccountPermissionUpdateContract` OVERWRITES owner+witness+actives wholesale (query `getaccount` first; restate everything; costs 100 TRX). See `docs/runbooks/tron-key-ceremony.md`. Mirror of P-SOL-2 / P4.4-16. |
| P-TRON-3 | Info | ❌ Accepted | **e2e on-chain broadcast deferred.** Ships off-chain coverage: the executor collects 3-of-3 partials through THREE real daemon `/sign/tron-tx` endpoints over HTTP, plus the convergence proof (all daemons sign the IDENTICAL `txID`, each sig recovering to its own member) + idempotent replay (`crates/signer-daemon/tests/tron_redeem_e2e.rs`) against a stub chain. Live `broadcasthex` + the `tronweb` byte-match (P-TRON-1) are testnet-rehearsal territory — same posture as P-SOL-3 / P4.4-15. |
| P-TRON-4 | Info | ❌ Accepted (DL-P3-7) | **TRON custody = native account-permission multisig (Set G).** `chain_registry::CustodyFamily::Tron`; `thor_asset()=="TRON.TRX"`, `decimals()==6` (`sun`; TRC20 USDT is also 6-dec), `scale()==1_000_000`, `conf_depth()==19` (SR super-representative finality — TRON has NO single-block deterministic finality, unlike GAIA/XRP/SOL), `fee_unit()==TronResource`. The account address is NOT member-derived — it is a separately-funded account whose `Active` `Permission` is configured by `AccountPermissionUpdateContract` (P-TRON-2). |
| P-TRON-5 | **High** | ✅ Closed in code | **Daemon never blind-signs; txID recomputed locally.** `handle_tron_tx` rebuilds the `raw_data` protobuf from the semantic fields (`asset` / `owner` / `to` / `amount` / `contract_address` / `permission_id` / `ref_block_*` / `expiration` / `timestamp` / `fee_limit` / `memo`), recomputes `txID = sha256(raw_data)`, and refuses (`tron_tx_mismatch`, 422) if it differs from the caller-supplied `txid` — the destination / amount / memo / `permission_id` are all bound into the `txID`. It then HSM-signs the recomputed `txID`, normalizes `v` to the TRON 0/1 form, and **verifies the 65-byte sig recovers to the configured signer address** (`signer_recover_mismatch`, 500) before recording. Tests: `rejects_tampered_txid`, `tampered_amount_changes_txid_and_is_rejected`, `signs_and_recovers_under_signer_address`. |
| P-TRON-6 | Medium | ✅ Closed in code | **Replay-DB keyed for TRON** (unlike Solana P-SOL-6, which deferred it). `ReplayStore::check_tron_tx` / `record_tron_tx` key on `(chain_id, owner_address, txid)` (`signed_tron_txs`, migration `0006`). TRON has NO account nonce, so the `txID` IS the whole payload identity — an identical retry is `Idempotent` (returns the cached sig, no second HSM hit); distinct redemptions have distinct `txID`s. Because the key includes the whole-payload `txID`, a `Conflict` cannot arise. Tests: `in_memory_tron_tx_lifecycle`, `sqlite_tron_tx_lifecycle_matches_in_memory`, `idempotent_replay_returns_cached_signature`. |
| P-TRON-7 | Medium | ⏳ Deferred (mainnet gate) | **Daemon does not independently bind the destination to the burn event.** The never-blind-sign rebuild binds the destination into the `txID`, but the daemon trusts the coordinator's `to_address` (the Asgard inbound) — the same posture as the XRP / Cosmos / Solana daemons (P-SOL-7). A compromised coordinator therefore needs `threshold` honest daemons to sign a transfer to an arbitrary address. Cross-repo follow-on: observe the Ethereum `RedeemDispatched` event in the daemon and bind `to_address` / `memo` to it. `crates/signer-daemon/src/tron_tx.rs`. |
| P-TRON-8 | Info | ❌ Accepted | **`xindex-redeem-tron` single-shot CLI.** `dispatch_id` / `redemption_id` default to `B256::ZERO`. The event loop (RedeemDispatched → build → broadcast → record the `tron` dispatch row) is a follow-on; `TronRedeemExecutor` is loop-ready. Because TRON has NO nonce, a re-driven leg within the TAPOS window rebuilds the IDENTICAL `raw_data` → same `txID` → the node de-dups (`DUP_TRANSACTION_ERROR`, treated as success by `broadcast.accepted()`) and each daemon returns its cached signature — idempotent without a nonce advance (better than the XRP / Cosmos single-tx binaries P4.4-11 / M3). After expiry a fresh `now_block` yields a new `txID`. Mainnet still requires the real `dispatch_id` wired (DL-P3-7). |
| P-TRON-9 | Medium | ⏳ Deferred (mainnet gate) | **No TRON-side inbound observer / refund cross-check in v1.** `chain-tron` implements the redeem essentials (`now_block` for the TAPOS reference, `broadcast_hex`, `transaction_info`) but NOT a `transfers_to` inbound scanner, and there is no `ThorTron` refund/delivery cross-check policy (the XRP/Cosmos C6 analogue). TRON is redeem-only in our flow (mint is USDT-on-Ethereum), so no inbound-deposit scan is needed; the gap is the THORChain **refund** path (a bounced swap returning native TRON to our multisig), which the attestation layer cannot yet observe on TRON. FAIL-CLOSED — a refund that cannot be observed simply does not get attested (a bounded stuck-redemption / liveness risk, no false attestation, no fund loss), the same shape as P4.4-18 / P-SOL-10. Cross-repo follow-on: add a TronGrid-backed `transfers_to` + a `ThorTron` policy before TRON refunds are relied on. The generic delivery cross-check (THORChain → USDT on Ethereum) already covers TRON via `from_asset_id` routing. |
| P-TRON-10 | Info | ❌ Accepted | **No fee oracle in v1; TAPOS replay/expiry, not a nonce.** Operators supply `fee_limit` (the TRC20 energy cap, in `sun`) per leg via the `xindex-redeem-tron` CLI; native TRX legs pay bandwidth only (`fee_limit` omitted). A stale `ref_block_*` / `expiration` fails closed at broadcast (`TRANSACTION_EXPIRATION_ERROR`, `broadcast.accepted()==false`), never burning resources at the wrong rate. `Permission_id` is bound INSIDE `raw_data` (hashed into the `txID`), so all signers agree on it by construction. Mirror of P4.4-14 / DL-P3.2-7. |

## Streaming swaps — burn-side off-chain (Part B2 + A2) (2026-06-09)

Off-chain support for THORChain **streaming** redeem swaps (re-audit-gated;
see the Solidity-repo KNOWN_FINDINGS for the on-chain combined-settlement
state machine). A streaming redeem can partially fill — delivering USDT to the
IndexToken AND refunding native to our custody on ONE leg — settled by a FOURTH
EIP-712 typehash.

| ID | Severity | Status | Resolution |
|---|---|---|---|
| **STREAM-B2-EIP712** | Info | ✅ Done | `crates/shared/src/eip712.rs`: `AsyncLegStreamedSettlement` typed-data + `streamed_settlement_typehash()`. A pinned-value test asserts the Rust typehash byte-matches the Solidity `ASYNC_LEG_STREAMED_SETTLEMENT_TYPEHASH`, plus a 4-way pairwise-distinct test (mint/delivery/refund/streamed). Drift = signers produce digests the oracle rejects. |
| **STREAM-B2-SIGNER** | Info | ✅ Done | `crates/signer/src/lib.rs`: `HsmBackend::sign_streamed_settlement_msg` + `sign_streamed_settlement` + `aggregate_streamed_settlement_signatures`. Recover-to-signer test + cross-typehash negative (a delivery sig must NOT verify under the streamed digest). |
| **STREAM-B2-CROSSCHECK** | Info | ✅ Done | `crates/signer/src/crosscheck.rs`: `ThorUtxoStreamedSettlementPolicy` + `StreamedSettlementCrossCheck` trait, returning the AUTHORITATIVE on-chain `StreamedOutcome { delivered_usdt_1e6, refunded_sats }`. Unlike the XOR delivery/refund policies it accepts BOTH (or either) on one `btc_txid`; verifies the ERC20 arrival AND the vault-bound BTC UTXO independently. wiremock tests: partial-fill (both legs), full-delivery (zero refund), no-outbound (`NoSettlement`). |
| **STREAM-B2-REPLAY** | Info | ✅ Done | `crates/signer-daemon/src/replay.rs`: `RedemptionKind::Streamed` (third kind) + migration `0007_redemptions_allow_streamed.sql` (widen the `kind` CHECK). The per-leg `(redemption_id, leg_index)` one-shot mutex now rejects a delivery/refund after a streamed settlement (and vice versa). InMemory + Sqlite lifecycle tests assert the mutex. |
| **STREAM-A2-HINTS** | Info | ✅ Done | `crates/relayer/src/hint_builder.rs` + `xindex-hint-builder` binary. Pure `plan_stream` computes `(interval, quantity)` from live pool depth: size-gate (don't stream below `min_slip_bps`), the on-chain `MAX_STREAM_BLOCKS` bound, and the **mandatory deadline-margin gate** (the worst-case stream must finish inside the intent deadline with confirmation+attestation headroom). 7 unit tests. The binary pulls `ThorClient::pools()` and prints the hint JSON. |
| **STREAM-B2-COORD** | — | ⏳ **Deferred (audit-gated integration)** | The coordinator finality-gate branch (`xindex-attest-redeem`: poll until the streaming swap is FULLY finalised, then call the combined policy → `aggregate_streamed_settlement_signatures` → `attestStreamedSettlement`), the daemon streamed-settlement HTTP endpoint, and the `AttestationOracle.json` ABI entry. The verified primitives above wire together here. **Central risk: the partial-fill finality race** — settle ONLY after both outbounds are final; settling on the first observed outbound would under-credit the other leg. Mainnet-gated behind the fresh focused audit the plan requires for the whole burn-streaming path. |

**Gate (2026-06-09):** `cargo fmt --all --check` clean; `cargo clippy --workspace
--all-targets --all-features -- -D warnings` clean; `cargo test --workspace` all
green (incl. the new eip712 / signer / crosscheck / replay / hint_builder tests).
`cargo audit` rsa advisory is pre-existing (unchanged).

## 2026-06-09 whole-stack adversarial audit (12-finder workflow)

Adversarial red-team over the freshest/highest-risk off-chain code (streaming
cross-check, CTD-1 floor, EIP-712 byte-match, replay, TRON, per-family signers).
Highest-value result: the daemon-local CTD-1 **floor** is shipped for BTC (M2b)
but was **missing on the EVM-Safe family**, and the EVM-Safe attack surface is
strictly worse than a destination drain.

| ID | Severity | Status | Resolution |
|---|---|---|---|
| **AUD-EVMSAFE-1** | **High** | ✅ **Fixed in code** | The EVM-Safe daemon (`signer-daemon/src/evm_safe.rs`) recomputed `safeTxHash` (never blind-signs the *hash*) but applied NO daemon-local floor on the Safe-tx fields. `parse_operation` accepts `DelegateCall`, and `gas_price`/`gas_token`/`refund_receiver` were unbounded. Under coordinator compromise (UNTRUSTED per DL-CTD-1) the 3-of-5 could be made to sign a Safe **`DelegateCall`** = arbitrary code in the Safe's context (owner takeover / full asset sweep — beyond a drain), or a non-zero Safe **gas-refund** (`gasPrice·gasUsed` of `gasToken` to `refundReceiver`) = a value-extraction channel orthogonal to `to`/`value`/`data`. Neither is covered by the BTC change-to-self/fee-cap floor nor by CTD-1's "destination/amount/memo" framing. **Fix:** `enforce_evm_safe_floor` rejects `operation != Call` (`evm_safe_operation_forbidden`, 422) and any non-zero `gas_price`/`gas_token`/`refund_receiver` (`evm_safe_gas_refund_forbidden`, 422) before the HSM is consulted — matching the honest executor's fixed template (`evm_redeem.rs`: always `Call`, all gas/refund fields zero), so no trusted intent is needed. `to`/`value`/`data` remain the CTD-1 destination residual (RIC's job). Tests: `floor_accepts_honest_template`, `floor_rejects_delegatecall`, `floor_rejects_nonzero_gas_price`, `floor_rejects_nonzero_refund_receiver`. |
| **AUD-TRON-LOWS** | Low | ✅ Fixed in code (2026-06-10) | `signer-daemon/src/tron_tx.rs` (the HSM-sign block) normalized the recovery byte (`tron_recovery_v`) and recover-verified, but unlike `evm_safe.rs` did NOT EIP-2 low-S-normalize `s`. TRON was the only secp256k1 family without canonical-S enforcement. Impact is defense-in-depth (the Web3Signer HSM already emits low-S, so a no-op in practice; whether java-tron rejects high-S is version-dependent; multisig members sign independently over a fixed txID so malleating one share does not change the txID). **Fix:** the `evm_safe::normalize_low_s` primitive was factored into a shared `signer-daemon/src/sig_norm.rs` helper (used by both `evm_safe` and `tron_tx`); the TRON path applies it while `v` is still in the HSM 27/28 convention (the helper flips `v` on normalize), before `tron_recovery_v` + the existing recover-verify (so a mis-normalization fails closed). Tests: `high_s_hsm_signature_is_normalized` (a high-S HSM response is normalized and accepted) + the moved `sig_norm` low-S unit tests. |
| **AUD-EVMSAFE-AGG-LOWS** | Info | ✅ Fixed in code (2026-06-10) | `safe-evm/src/sigs.rs` `aggregate_signatures` did not itself enforce EIP-2 low-S — it relied on the daemon having normalized (1.13). **Fix:** `recover_signer` (the single recovery point used by BOTH the bulk aggregator AND verify-as-collected) now parses `r‖s` with `k256` and rejects high-S with a new `AggregateError::HighS` before recovery, so a future non-normalizing signer path cannot assemble a Safe-rejected bundle. Added `"arithmetic"` to safe-evm's `k256` features for `normalize_s`. Test: `recover_signer_rejects_high_s`. |
| **AUD-HINT-SENTINEL** | Low | ✅ Fixed in code (2026-06-10) | `relayer/src/bin/xindex-hint-builder.rs` `pool_depth` returns `Ok(0)` for a non-Available/empty pool; `hint_builder::slip_bps` mapped depth 0 → 100% slip, which `plan_stream` turned into MAXIMAL streaming — the opposite of the logged "streaming disabled" intent. Advisory only (the on-chain `minSharesOut`/`LIM` is the real protection), so no fund-loss path — but a clear inverted-sentinel logic bug. **Fix:** `plan_stream` now returns `NON_STREAMING` up-front when `pool_depth == 0` (a single plain swap). Test: `zero_depth_does_not_stream`. |
| **AUD-PSBT-REPLAY-CHAINID** | Low | ✅ Fixed in code (2026-06-10) | The PSBT replay table (`signed_psbt_inputs`) was keyed by outpoint without `chain_id`. One daemon serving multiple UTXO chains (BTC/LTC/…) could false-conflict on a same-outpoint collision across chains → a spurious 409 (stuck redemption), not theft. **Fix:** `chain_id` added to the `(check|record)_psbt_input` trait + both impls + the `psbt.rs` call sites; migration `0008_psbt_inputs_chain_id.sql` recreates the table with `chain_id` first in the PK (existing rows backfilled `'BTC.BTC'`). Test: the PSBT lifecycle now asserts the same outpoint on a different UTXO chain is an independent slot, not a Conflict. |
| **AUD-PSBT-FEECAP-MULTIINPUT** | Low | ✅ Fixed in code (2026-06-10) | The M2b fee cap (`psbt.rs` `enforce_change_and_fee`) summed `witness_utxo.value` across ALL inputs, but only the signed input's prevout `scriptPubKey` was descriptor-bound (I3). A coordinator-forged `witness_utxo.value` on a non-signed input could weaken the `Σin−Σout ≤ max_redeem_fee_sats` bound. **Fix:** the fee loop now rejects (`wrong_descriptor`, 422) any input whose `witness_utxo.script_pubkey` is not the daemon descriptor P2WSH program — the redeem coin-selection only ever draws our own multisig UTXOs, so requiring it is exact and also strengthens the Part-3 vin-is-multisig invariant from `vin[0]` to ALL inputs. Test: `foreign_second_input_is_rejected`. |

**Already-known residuals (NOT new — confirmed still tracked):** the M2b
"payout-absent path skips change-to-self" item a finder re-raised is the
**documented CTD-1 residual** (M2b note: change-to-self is skipped when the
payout is absent → folded into CTD-1; RIC closes it). The "streamed-settlement
has no daemon endpoint / `RemoteHsmBackend` errors / `RedemptionKind::Streamed`
unreachable / combined policy has no finality plumbing" items are
**STREAM-B2-COORD** (deferred, audit-gated; the path is fail-closed today — it
errors rather than signing a wrong digest). No mainnet path is live; all
native-chain redemption is DL-gated on CTD-1 + per-family ceremonies.

**Gate (2026-06-10):** all six rows above (`AUD-EVMSAFE-1` + the five
`AUD-*` follow-ups) are now closed in code together with **P-SOL-6** (the Solana
daemon replay arm, below). `cargo fmt --all --check` clean; `cargo clippy
--workspace --all-targets --all-features -- -D warnings` clean; `cargo test
--workspace` green (57 binaries; the single `evm_redeem_e2e` loopback flake
under max parallelism passes in isolation — pre-existing harness race, not these
changes); `cargo deny` bans/licenses/sources ok (the `RUSTSEC-2026-0002`
`advisory-not-detected` is the pre-existing L14 wart — `Cargo.lock` unchanged);
`cargo audit` pass (4 pre-existing accepted advisories). Shared `sig_norm`
helper + `safe-evm` `arithmetic` feature are the only cross-cutting additions.

## When this file gets updated

- New audit pass (internal or external) → add a section
- M5 milestone closes a `⏳ Deferred` item → flip to ✅ + describe fix
- Any analyzer (clippy / cargo-deny / cargo-audit) flags something we
  decide to accept → entry here with reasoning
