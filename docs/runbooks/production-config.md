# Production configuration template + safety checklist

> Workstream F. The deploy-time settings the key ceremony fills in. Every
> value here is **ceremony/ops-owned** (founder + operators); this file is the
> scaffolding, not the values. The fail-closed startup checks referenced below
> mean a mis-filled config refuses to boot rather than running with a safety
> feature silently off.

> **Custody status: historical / disabled.** The custody portions of this runbook describe the historical remote-HSM 3-of-5 baseline and are not the selected BTC custody architecture. The selected-but-unimplemented Vultisig Wallet-as-a-Service direction and its external gates are canonical in [`../../../memory/VULTISIG-CUSTODY.md`](../../../memory/VULTISIG-CUSTODY.md). Registry, observation, RIC, settlement-certification, and price quorum material below remains a separate non-custody domain.

The historical Gate-3 baseline assumed five signer operators, one signer daemon
per key role, and one observer per chain. Do not populate or launch its custody
role as a substitute for the selected Vultisig boundary. Production
custody remains unselected and disabled.

## 0. Startup checks (already enforced in code)

| Setting | Validator | Fails closed when |
|---|---|---|
| `IntentPolicy` | `IntentPolicy::validate()` + `DaemonState::assert_production_safe()` | empty/duplicate Set-B whitelist, zero quorum, quorum > whitelist, zero `ric_max_age_secs`, or a production roster other than exact 3-of-5 |
| `CertVolumePolicy` | `CertVolumePolicy::try_new()` + `validate()` | `window_secs == 0`, unsigned→signed conversion failure, `window_secs > 2,678,400` (31 days), or any cap `== 0` |
| **Production metering** | `DaemonState::assert_production_safe()` → `CertVolumePolicy::assert_metered_for(served)` | **any served RIC-gated chain (BTC/EVM/Cosmos/XRP/TRON) has no positive cap** — `unmetered()` is dev/test ONLY |
| **Durable replay** | binary startup | `database_url` is absent outside `--dev`, is not an absolute SQLite path under an owner-only non-symlink directory, or names an existing unsafe/symlinked/hard-linked database |
| **Historical signer perimeter** | binary startup | the retained remote-HSM baseline sees software HSM, missing outer mTLS, a non-loopback/credential-bearing HSM URL, an unsafe config/TLS-key file, a zero identity, or a custody descriptor other than its exact historical 3-of-5 shape |

A production launcher MUST call `DaemonState::assert_production_safe()` after
constructing state and before serving. `unmetered()` + an in-process HSM stub
are the dev/test opt-out and must never reach mainnet.

The checked-in binary now performs these launcher checks itself before opening
the database or binding a socket. The database, HSM frontend and TLS files are
operator-provisioned ceremony inputs; none is populated in this repository.

## 1. Signer daemon (per operator, per key role)

```
# ── EIP-712 domain (the on-chain AttestationOracle) ──
oracle_chain_id        = 1                         # Ethereum mainnet
attestation_oracle     = 0x____________________     # deployed AttestationOracle (DL-P3-7)
eth_address            = 0x____________________     # THIS operator's Set-B signer (ceremony disclosure)
hsm_url                = https://127.0.0.1:9000     # Web3Signer/YubiHSM2 frontend, loopback inside the mTLS perimeter

# ── CTD-1 RIC gate (IntentPolicy) ──
signer_whitelist       = [0x.., 0x.., 0x.., 0x.., 0x..]  # all 5 Set-B addresses (ceremony)
intent_quorum          = 3                          # k of the k-of-n (3-of-5)
ric_max_age_secs       = 5400                        # < THORChain vault-retirement window (~hours)

# ── CTD-1 Slice E containment (CertVolumePolicy) — MANDATORY in prod ──
cert_window_secs       = 86400                        # 24h bucket; valid range 1..=2,678,400s (31 days)
cert_caps = {                                         # ≈10% of per-chain custody / 24h; re-tune as custody grows
  "btc":  ____,  "ltc": ____, "bch": ____, "doge": ____, "zec": ____,
  "eth":  ____,  "avax": ____, "bsc": ____, "base": ____, "pol": ____,
  "gaia": ____,  "noble": ____, "xrp": ____, "tron": ____,
}                                                     # one positive cap per chain THIS daemon serves

# ── mTLS (DL-M5-5) — the coordinator-cert pin allowlist ──
tls_server_cert        = /etc/xindex/tls/server.pem   # this daemon's server cert chain
tls_server_key         = /etc/xindex/tls/server.key
tls_pinned_client_cert = /etc/xindex/tls/coordinator.pem  # leaf-first exact coordinator peer bundle

# ── durable anti-replay/equivocation state ──
database_url            = sqlite:///var/lib/xindex/signer-daemon.db
metrics_bind             = 127.0.0.1:9090
```

- Build the rustls server via `signer-daemon::tls::server_config(load_cert_chain(server), load_private_key(key), pinned_cert_store([coordinator]))` and serve with `serve_mtls`. Each configured entry is leaf-first: the first certificate is the exact SHA-256 peer pin and the last is its explicit WebPKI trust anchor. The peer presents any intermediates. A CA-only entry pins that CA certificate itself and does not authorize sibling leaves. Use separate entries for an intentional certificate-rotation overlap; an unpinned client is dropped at the handshake.
- `cert_caps` must contain a positive cap for **every** chain this daemon has a signing role for, or `assert_production_safe()` refuses to boot.
- `hsm_url` may name only `localhost` or a literal loopback address and may not
  contain URL userinfo, a query or a fragment. Keep HSM authentication out of
  the URL and inside the local HSM perimeter.
- The current concrete `xindex-signer-daemon` launcher accepts only the BTC
  UTXO role in `parse_chain_id`; other family libraries are not evidence of a
  production-wired daemon. Do not mark those families enabled until their
  launchers and rehearsals land.

## 2. Current coordinator / observer / custody services

The production path uses `xindex-finalized-observer`,
`xindex-settlement-collector`, `xindex-registry-signer`,
`xindex-registry-coordinator`, `xindex-price-signer`,
`xindex-price-collector`, the Bitcoin-only custody executor `xindex-redeem`,
and the permissionless terminal worker `xindex-finalize-redeem`. The historical
`xindex-observe-redeem` and centralized `xindex-attest*` binaries are dev-only
and are not production alternatives.

```
--signer-mode remote                                 # mainnet MUST be remote (HSM-backed daemons)
--signer-daemon-urls   https://op1:9443,https://op2:9443,...   # the 5 daemons (mTLS)
--signer-daemon-addresses 0x..,0x..,0x..,0x..,0x..   # pinned per-(url,address) — Set-B disclosure
--threshold            3
--large-spend-threshold ____                          # alert/extra-scrutiny ceiling (native units)
--cancel-recovery-dest  ____                          # mint-cancel make-whole destination (cancel-make-whole.md)
--cross-check-mode     thor-btc-usdt                  # NEVER pass-through on mainnet
--eth-min-confirmations 12                            # >= ETH conf_depth (enforced at startup, audit M9)
--btc-min-confirmations 6                             # >= the leg chain's conf_depth (enforced per-leg)
```

Every service uses a distinct durable SQLite database/evidence directory and a
distinct loopback metrics port. Service-to-service traffic uses explicit mTLS
client identities and leaf-first exact peer bundles with system roots disabled.
The standard chain, time, purpose and server-hostname checks run before the
exact end-entity certificate comparison. Some legacy JSON/CLI keys still say
`ca_pem`; those paths must contain the exact peer bundle described above, not a
generic CA allowlist. The
finalized observer, event journal, source pollers, API, poster, metrics and
exact-byte rebroadcast tasks are supervised; an unexpected exit terminates the
owning process.

`xindex-finalize-redeem` is mandatory, not a best-effort keeper. It consumes
the canonical block journal written by one local `xindex-finalized-observer`,
mirrors every block into a dedicated transactional cursor/outbox, and retains
each `finalizeBurn` responsibility until a finalized terminal event is
journaled. Its source and outbox databases are required absolute owner-only
SQLite files; in-memory state and websocket ingestion are rejected.

```sh
ETH_RPC_URL=https://execution.example.invalid \
EXPECTED_CHAIN_ID=1 \
INTENT_QUEUE_ADDR=0x____________________ \
POSTER_ADDRESS=0x____________________ \
OBSERVER_DATABASE_URL=sqlite:///var/lib/xindex/finalized-observer-op1.db \
OBSERVER_ID=op1-btc \
DATABASE_URL=sqlite:///var/lib/xindex/finalize-redeem.db \
START_BLOCK=________ \
POLL_INTERVAL_MILLIS=1000 \
RETRY_BASE_MILLIS=1000 \
RETRY_MAX_MILLIS=60000 \
METRICS_ADDR=127.0.0.1:9092 \
  /usr/local/bin/xindex-finalize-redeem
```

`START_BLOCK` is the deployment-era first block retained by the named source
observer, not the current head. A missing creation event fails closed instead
of advancing the terminal cursor. Use the checked-in
[`xindex-finalize-redeem.service`](../../ops/systemd/xindex-finalize-redeem.service)
and [`gate3-scrape.example.yml`](../../ops/prometheus/gate3-scrape.example.yml)
as inventory templates; replace file-discovery paths with the operator's
reviewed local target files.

The price collector additionally requires the approved 7-of-11 roster.
Registry, settlement observation, RIC, and settlement certification use
separate 3-of-5 quorums. The retained remote-HSM custody role is also shaped
3-of-5 in code but is historical and prohibited as a fallback; future custody
uses a distinct, still-unselected Vultisig participant set. Validate any real
dual-reviewed operator/source registry with `xindex-topology-check`; see
[`gate3-operations.md`](gate3-operations.md). A checked-in example roster is
intentionally absent because placeholders are not production evidence.

The coordinator presents its client cert to each daemon through the shared
`exact_pinned_async_client_builder`; the configured leaf-first peer bundle
performs normal WebPKI validation followed by an exact end-entity pin.

## 3. On-chain (deploy script / governance timelock)

| Call | Value | Note |
|---|---|---|
| `CustodyGuard.setVolumeCaps(dispatchCap, attestCap)` | ____ | the on-chain per-period breaker; set BEFORE funds flow, re-tune via timelock |
| `AttestationOracle` signer set + threshold | the 5 Set-B addresses, 3 | matches §1 `signer_whitelist` / `intent_quorum` |
| `AttestationOracle.observationEpoch(sourceChainId)` | `0` at launch; governed compare-and-swap advance after each reviewed finalized rollback | must equal every operator's durable local epoch before settlement signing or collection resumes |
| `PriceAttestationOracle` L1 bounds / L2 Chainlink feed / deviation cap | ____ | per `DL-INDEX-METHOD-ORACLE-1`; the off-chain `xindex-price-signer` feeds it |

The price path is configured separately in
[`price-oracle-pipeline.md`](price-oracle-pipeline.md). All independent price
signers must share the exact epoch/canonicalization policy; the collector must
boot with the complete on-chain signer set and matching threshold. A code-green
pipeline does not replace the Sepolia rehearsal and external-audit gates.

All evidence directories must pass `xindex-evidence-check` and be reconciled
to an independently administered WORM copy under the retention/incident policy
in [`gate3-operations.md`](gate3-operations.md).

## 4. Per-family gate (none live on mainnet until ALL are checked)

For every chain, before it touches mainnet funds: per-family external audit ·
key ceremony (`*-key-ceremony.md`) · testnet/signet rehearsal · the byte-match
gate green · `cert_caps` + on-chain `CustodyGuard` caps filled · the daemon
boots past `assert_production_safe()`. Cosmos additionally: `--nosort-pubkeys`
at the ceremony (the gaiad multisig-address fund-safety fix).

Vultisig Wallet as a Service using DKLS threshold signing is the selected
future custody direction. Its exact participant set, threshold, hosted versus
self-hosted boundary and Bitcoin address policy are not selected. The retired
provider-specific code is removed. A first key-free Bitcoin policy adapter
exists, but no Vultisig SDK/runtime, vault or share exists; Testnet4 isolation,
finalized-transaction revalidation, durable orchestration, aggregate evidence,
reshare/recovery ceremonies and independent custody review must pass.
Production custody remains disabled pending a reviewed design
and qualification.
