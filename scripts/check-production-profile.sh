#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "production-profile check failed: $*" >&2
    exit 1
}

require_text() {
    local file=$1
    local text=$2
    rg --quiet --fixed-strings -- "$text" "$file" \
        || fail "$file is missing required guard: $text"
}

reject_text() {
    local file=$1
    local pattern=$2
    if rg --line-number -- "$pattern" "$file"; then
        fail "$file contains production-prohibited key material interface"
    fi
}

# Authoritative behavior gate: compiled startup validators are exercised with
# prohibited configurations before any secret read, listener bind, or network
# operation. The literal scans below remain defense-in-depth documentation and
# call-site lints; they are not the primary proof of production fail-closure.
./scripts/check-production-profile-behavior.sh

# Active entry points must distinguish the selected future BTC custody model
# from the independent observation/certification quorum and removed providers.
for file in README.md AGENTS.md; do
    require_text "$file" \
        'The selected future BTC custody model is BitGo native P2WSH 2-of-3 (user, independently held offline backup, and BitGo); it is disabled and not production-wired.'
    require_text "$file" \
        'Observation, RIC, and settlement certification remain a separate 3-of-5 quorum; 3-of-5 is not BTC custody.'
    require_text "$file" \
        'Turnkey and Cobo are prohibited as current, backup, emergency, or rehearsal custody providers.'
done
require_text docs/runbooks/production-config.md \
    'The custody portions of this runbook describe the historical remote-HSM 3-of-5 baseline and are not the selected BTC custody architecture.'

# The retained historical remote-HSM signer profile must remain fail-closed
# while it exists in source, even though it is not the selected BTC custody
# boundary. Software keys remain available only behind --dev.
require_text crates/signer-daemon/src/main.rs \
    'database_url is required outside --dev'
require_text crates/signer-daemon/src/main.rs \
    'mTLS config (`tls`) is required outside --dev'
require_text crates/signer-daemon/src/main.rs \
    'hsm.url must terminate on loopback inside the HSM perimeter'
require_text crates/signer-daemon/src/main.rs \
    'a production daemon must front an HSM'
require_text crates/signer-daemon/src/main.rs \
    'metrics_bind must be a distinct non-zero loopback listener'
require_text crates/signer-daemon/src/main.rs \
    'signer metrics server exited unexpectedly'
require_text crates/signer-daemon/src/main.rs \
    'database_url must resolve to an absolute durable path'
require_text crates/signer-daemon/src/main.rs \
    'existing replay database must be a non-symlink regular file'
require_text crates/signer-daemon/src/main.rs \
    'mTLS server key'
require_text crates/signer-daemon/src/main.rs \
    'production certification topology must be exactly 3-of-5'
require_text crates/signer-daemon/src/main.rs \
    'production custody topology must be exactly 3-of-5'
require_text crates/signer-daemon/src/server.rs \
    'production intent policy must be exactly 3-of-5'

# The independent price path is HSM-only, source-independent, pinned-mTLS to
# collectors, observable, and fixed to the approved 7-of-11 production roster.
require_text crates/signer-daemon/src/bin/xindex-price-signer.rs \
    'collector endpoints must use HTTPS for pinned mTLS'
require_text crates/signer-daemon/src/bin/xindex-price-signer.rs \
    'exact_pinned_async_client_builder'
require_text crates/signer-daemon/src/bin/xindex-price-signer.rs \
    'price signer metrics server exited unexpectedly'
require_text crates/signer-daemon/src/bin/xindex-price-signer.rs \
    'state parent must be owner-only'
require_text crates/signer-daemon/src/bin/xindex-price-signer.rs \
    'existing state must be a non-symlink regular file'
require_text crates/signer-daemon/src/bin/xindex-price-signer.rs \
    'evidence path must be a non-symlink directory'
require_text crates/relayer/src/bin/xindex-price-collector.rs \
    'production price topology must be exactly 7-of-11'
require_text crates/relayer/src/bin/xindex-price-collector.rs \
    'at least one pinned price-signer client certificate is required'
require_text crates/relayer/src/bin/xindex-price-collector.rs \
    'price collector metrics server exited unexpectedly'

# The reviewed BTC executor production profile is remote-HSM only and requires
# durable replay stores plus the reviewed exact observer fleet.
require_text crates/executor/src/bin/xindex-redeem.rs \
    'production requires remote HSM cosigners and prohibits raw secret keys'
require_text crates/executor/src/bin/xindex-redeem.rs \
    'production requires durable broadcast and redemption SQLite stores'
require_text crates/executor/src/bin/xindex-redeem.rs \
    'production observer topology must be exactly 3-of-5'
require_text crates/executor/src/bin/xindex-redeem.rs \
    'production requires a bounded, canonical finalized-observer journal source'
require_text crates/executor/src/bin/xindex-redeem.rs \
    'production remote-cosigner topology must be exactly 3-of-5'
require_text crates/executor/src/bin/xindex-redeem.rs \
    'production custody topology must be exactly 3-of-5'
require_text crates/executor/src/bin/xindex-redeem.rs \
    'transport private key must be owner-only and single-link'
require_text crates/executor/src/bin/xindex-redeem.rs \
    'custody metrics server exited unexpectedly'

# Current registry, finalized-observer, and exact settlement services must keep
# all long-lived safety workers supervised and their trust roots pinned.
require_text crates/signer-daemon/src/bin/xindex-registry-signer.rs \
    'registry signer metrics server exited unexpectedly'
require_text crates/signer-daemon/src/bin/xindex-registry-signer.rs \
    'exact_pinned_async_client_builder'
require_text crates/signer-daemon/src/bin/xindex-registry-signer.rs \
    'production registry topology must be exactly 3-of-5'
require_text crates/signer-daemon/src/bin/xindex-registry-signer.rs \
    'secret/config file must be owner-only and single-link'
require_text crates/relayer/src/bin/xindex-registry-coordinator.rs \
    'registry inbound producer exited unexpectedly'
require_text crates/relayer/src/bin/xindex-registry-coordinator.rs \
    'exact_pinned_async_client_builder'
require_text crates/relayer/src/bin/xindex-registry-coordinator.rs \
    'registry topology must be exactly 3-of-5'
require_text crates/relayer/src/bin/xindex-registry-coordinator.rs \
    'secret/config file must be owner-only and single-link'
require_text crates/chain-eth/src/bin/xindex-finalized-observer.rs \
    'production finalized observer supports Bitcoin mainnet only'
require_text crates/chain-eth/src/bin/xindex-finalized-observer.rs \
    'observer, THOR state, and settlement databases must be separate files'
require_text crates/chain-eth/src/bin/xindex-finalized-observer.rs \
    'attestation topology must be exactly 3-of-5'
require_text crates/chain-eth/src/bin/xindex-finalized-observer.rs \
    'secret/config file must be owner-only and single-link'
require_text crates/relayer/src/bin/xindex-settlement-collector.rs \
    'pinned mTLS exact-peer allowlists must not be empty'
require_text crates/relayer/src/bin/xindex-settlement-collector.rs \
    'exact_pinned_async_client_builder'
require_text crates/relayer/src/bin/xindex-settlement-collector.rs \
    'settlement topology must be exactly 3-of-5'
require_text crates/relayer/src/bin/xindex-settlement-collector.rs \
    'secret-bearing files must be owner-only and single-link'
require_text crates/relayer/src/bin/xindex-price-collector.rs \
    'TLS private key must be owner-only and single-link'

# M-06: normal WebPKI checks must be followed by an exact end-entity pin on
# both sides of every shared mTLS connection. CA-only trust is not sufficient.
require_text crates/ops/src/tls.rs 'struct ExactClientCertVerifier'
require_text crates/ops/src/tls.rs 'struct ExactServerCertVerifier'
require_text crates/ops/src/tls.rs 'WebPkiClientVerifier'
require_text crates/ops/src/tls.rs 'WebPkiServerVerifier'
require_text crates/ops/src/tls.rs 'exact_leaf_matches'
require_text crates/ops/src/tls.rs 'exact_pinned_async_client_builder'
require_text crates/ops/src/tls.rs 'exact_pinned_blocking_client_builder'

# Release-time operational controls exist as executable validation, alert rules
# and an evidence/incident runbook. Real populated inputs remain external.
require_text crates/ops/src/topology.rs \
    '("price_signer", 11, 7)'
require_text crates/ops/src/bin/xindex-topology-check.rs \
    'topology registry must be an absolute non-symlink regular file'
require_text crates/shared/src/evidence.rs \
    'inventory_hash_keccak256'
require_text ops/prometheus/gate3-alerts.yml \
    'XindexCustodyOneShotConflict'
require_text docs/runbooks/gate3-operations.md \
    'Code and synthetic checks cannot supply real operator independence'

# Centralized legacy attesters and the non-durable observer are rehearsal-only.
require_text crates/chain-eth/src/bin/xindex-attest.rs \
    'legacy quorum-collapsing scaffolding and refuses to run without --dev'
require_text crates/chain-eth/src/bin/xindex-attest-redeem.rs \
    'central-observation coordinator and refuses to run without --dev'
require_text crates/chain-eth/src/bin/xindex-observe-redeem.rs \
    'development-only until finalized checkpoints, reorg rollback, and durable event facts replace its in-memory source'

# BitGo is the selected future BTC custody provider. Refuse reintroduction of
# either removed Turnkey or Cobo crate, executable source or lockfile package.
if find crates -iname '*turnkey*' -print -quit | rg --quiet '.'; then
    fail 'Turnkey-named source path reintroduced under crates/'
fi
if rg --ignore-case --quiet 'turnkey' Cargo.toml Cargo.lock crates; then
    fail 'Turnkey dependency or executable source reintroduced'
fi
if find crates -iname '*cobo*' -print -quit | rg --quiet '.'; then
    fail 'Cobo-named source path reintroduced under crates/'
fi
if rg --ignore-case --quiet 'cobo' Cargo.toml Cargo.lock crates; then
    fail 'Cobo dependency or executable source reintroduced'
fi
for removed in \
    docs/runbooks/cobo-custody-devenv.md \
    docs/runbooks/cobo-gate-evidence.example.json \
    docs/runbooks/gate4-cobo-rehearsal.md; do
    if [[ -e "$removed" ]]; then
        fail "removed Cobo runbook reintroduced: $removed"
    fi
done

# Gate 4 must use the selected BitGo native BTC 2-of-3 model and strict evidence
# verifier. The historical 3-of-5 custody rehearsal cannot become an implicit
# fallback or be cited as current closure evidence.
require_text docs/runbooks/bitgo-custody-devenv.md 'Selected for future BTC custody; disabled and not production-wired'
require_text docs/runbooks/gate4-bitgo-rehearsal.md 'Status: BLOCKED / not complete'
require_text docs/runbooks/gate4-bitgo-rehearsal.md 'xindex-gate4-check'
require_text docs/runbooks/ctd1-signet-rehearsal.md 'Historical custody baseline'
require_text crates/ops/src/bin/xindex-gate4-check.rs \
    'const REQUIRED_DRILLS: [&str; 23]'
require_text crates/ops/src/bin/xindex-gate4-check.rs \
    'environment must equal sepolia+thorchain-devnet+btc-testnet4'
require_text crates/ops/src/bin/xindex-gate4-check.rs \
    'overall: "format_valid"'
require_text crates/ops/src/bin/xindex-gate4-check.rs \
    'Ok(()) => ExitCode::from(2)'
require_text crates/bitgo-dev-gate/src/main.rs \
    'evidence_sha256'
require_text crates/bitgo-dev-gate/src/main.rs \
    'validate_adapter_unsigned'
require_text crates/bitgo-dev-gate/src/main.rs \
    'lack authenticated provider provenance'
require_text crates/bitgo-adapter/src/lib.rs \
    'This crate deliberately contains no HTTP client, access token, private-key'
require_text crates/bitgo-adapter/src/lib.rs \
    'pub fn validate_unsigned'
require_text crates/bitgo-adapter/src/lib.rs \
    'pub fn validate_user_signed_transaction'
require_text crates/bitgo-adapter/src/lib.rs \
    'pub fn validate_final_transaction'

# Permissionless posters use node/HSM-managed accounts. These production
# binaries must not regress to parsing a local signer or accepting a key env.
for file in \
    crates/relayer/src/bin/xindex-cancel.rs \
    crates/relayer/src/bin/xindex-finalize-redeem.rs \
    crates/relayer/src/bin/xindex-price-collector.rs \
    crates/chain-eth/src/bin/xindex-halt-watchdog.rs; do
    reject_text "$file" 'PrivateKeySigner|POSTER_KEY|OPERATOR_KEY|PRIVATE_KEY'
done

echo "production-profile supplemental lints: OK"
