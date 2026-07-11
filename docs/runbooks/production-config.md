# Production configuration template + safety checklist

> Workstream F. The deploy-time settings the key ceremony fills in. Every
> value here is **ceremony/ops-owned** (founder + operators); this file is the
> scaffolding, not the values. The fail-closed startup checks referenced below
> mean a mis-filled config refuses to boot rather than running with a safety
> feature silently off.

Each of the 5 signer operators runs one signer daemon per key role + an
observer per chain. Solana is **excluded** from v1 (CTD-1-OPEN, RA-2) — do not
fill Solana values for mainnet.

## 0. Startup checks (already enforced in code)

| Setting | Validator | Fails closed when |
|---|---|---|
| `IntentPolicy` | `IntentPolicy::validate()` | empty/duplicate Set-B whitelist, zero quorum, quorum > whitelist, zero `ric_max_age_secs` |
| `CertVolumePolicy` | `CertVolumePolicy::validate()` | `window_secs == 0`, any cap `== 0` |
| **Production metering** | `DaemonState::assert_production_safe()` → `CertVolumePolicy::assert_metered_for(served)` | **any served RIC-gated chain (BTC/EVM/Cosmos/XRP/TRON) has no positive cap** — `unmetered()` is dev/test ONLY |

A production launcher MUST call `DaemonState::assert_production_safe()` after
constructing state and before serving. `unmetered()` + an in-process HSM stub
are the dev/test opt-out and must never reach mainnet.

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
cert_window_secs       = 86400                        # 24h bucket
cert_caps = {                                         # ≈10% of per-chain custody / 24h; re-tune as custody grows
  "btc":  ____,  "ltc": ____, "bch": ____, "doge": ____, "zec": ____,
  "eth":  ____,  "avax": ____, "bsc": ____, "base": ____, "pol": ____,
  "gaia": ____,  "noble": ____, "xrp": ____, "tron": ____,
}                                                     # one positive cap per chain THIS daemon serves

# ── mTLS (DL-M5-5) — the coordinator-cert pin allowlist ──
tls_server_cert        = /etc/xindex/tls/server.pem   # this daemon's server cert chain
tls_server_key         = /etc/xindex/tls/server.key
tls_pinned_client_cert = /etc/xindex/tls/coordinator.pem  # the SELF-SIGNED coordinator cert(s) to pin
```

- Build the rustls server via `signer-daemon::tls::server_config(load_cert_chain(server), load_private_key(key), pinned_root_store([coordinator]))` and serve with `serve_mtls`. An unpinned client is dropped at the handshake.
- `cert_caps` must contain a positive cap for **every** chain this daemon has a signing role for, or `assert_production_safe()` refuses to boot.

## 2. Coordinator / observer (`xindex-observe-redeem`, `xindex-attest*`, `xindex-redeem-*`)

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

The coordinator presents its client cert to each daemon:
`reqwest::Client::builder().use_preconfigured_tls(signer-daemon::tls::client_config(client_chain, client_key, pinned_server_root))` — the pinned coordinator identity from §1's `tls_pinned_client_cert`.

## 3. On-chain (deploy script / governance timelock)

| Call | Value | Note |
|---|---|---|
| `CustodyGuard.setVolumeCaps(dispatchCap, attestCap)` | ____ | the on-chain per-period breaker; set BEFORE funds flow, re-tune via timelock |
| `AttestationOracle` signer set + threshold | the 5 Set-B addresses, 3 | matches §1 `signer_whitelist` / `intent_quorum` |
| `PriceAttestationOracle` L1 bounds / L2 Chainlink feed / deviation cap | ____ | per `DL-INDEX-METHOD-ORACLE-1`; the off-chain `xindex-price-signer` feeds it |

The price path is configured separately in
[`price-oracle-pipeline.md`](price-oracle-pipeline.md). All independent price
signers must share the exact epoch/canonicalization policy; the collector must
boot with the complete on-chain signer set and matching threshold. A code-green
pipeline does not replace the Sepolia rehearsal and external-audit gates.

## 4. Per-family gate (none live on mainnet until ALL are checked)

For every chain, before it touches mainnet funds: per-family external audit ·
key ceremony (`*-key-ceremony.md`) · testnet/signet rehearsal · the byte-match
gate green · `cert_caps` + on-chain `CustodyGuard` caps filled · the daemon
boots past `assert_production_safe()`. Cosmos additionally: `--nosort-pubkeys`
at the ceremony (the gaiad multisig-address fund-safety fix).
