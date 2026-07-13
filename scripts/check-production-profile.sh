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

# The production signer must use durable replay state, outer mTLS, and a
# loopback HSM frontend. Software keys remain available only behind --dev.
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
    '.tls_built_in_root_certs(false)'
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
    '.tls_built_in_root_certs(false)'
require_text crates/signer-daemon/src/bin/xindex-registry-signer.rs \
    'production registry topology must be exactly 3-of-5'
require_text crates/signer-daemon/src/bin/xindex-registry-signer.rs \
    'secret/config file must be owner-only and single-link'
require_text crates/relayer/src/bin/xindex-registry-coordinator.rs \
    'registry inbound producer exited unexpectedly'
require_text crates/relayer/src/bin/xindex-registry-coordinator.rs \
    '.tls_built_in_root_certs(false)'
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
    'pinned mTLS trust roots must not be empty'
require_text crates/relayer/src/bin/xindex-settlement-collector.rs \
    '.tls_built_in_root_certs(false)'
require_text crates/relayer/src/bin/xindex-settlement-collector.rs \
    'settlement topology must be exactly 3-of-5'
require_text crates/relayer/src/bin/xindex-settlement-collector.rs \
    'secret-bearing files must be owner-only and single-link'
require_text crates/relayer/src/bin/xindex-price-collector.rs \
    'TLS private key must be owner-only and single-link'

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

# Turnkey rehearsal drivers ingest a software API-stamping private key. Until
# an HSM/remote stamper replaces it, every such entry point must fail before
# reading the environment unless --dev is explicit.
for file in \
    crates/executor/src/bin/xindex-redeem-turnkey-btc.rs \
    crates/executor/src/bin/xindex-redeem-turnkey-cosmos.rs \
    crates/executor/src/bin/xindex-redeem-turnkey-solana.rs \
    crates/executor/src/bin/xindex-redeem-turnkey-tron.rs \
    crates/executor/src/bin/xindex-redeem-turnkey-xrp.rs; do
    require_text "$file" 'if !args.dev {'
    require_text "$file" 'the standalone Turnkey driver reads a software API stamping key'
done
require_text crates/executor/src/bin/xindex-redeem-evm.rs 'if !args.dev {'
require_text crates/executor/src/bin/xindex-redeem-evm.rs \
    'the Turnkey backend reads a software API stamping key'
require_text crates/custody-node/src/bin/xindex-turnkey-approver.rs \
    'assert_dev_only(args.dev)?'

# Permissionless posters use node/HSM-managed accounts. These production
# binaries must not regress to parsing a local signer or accepting a key env.
for file in \
    crates/relayer/src/bin/xindex-cancel.rs \
    crates/relayer/src/bin/xindex-finalize-redeem.rs \
    crates/relayer/src/bin/xindex-price-collector.rs \
    crates/chain-eth/src/bin/xindex-halt-watchdog.rs; do
    reject_text "$file" 'PrivateKeySigner|POSTER_KEY|OPERATOR_KEY|PRIVATE_KEY'
done

echo "production-profile guards: OK"
