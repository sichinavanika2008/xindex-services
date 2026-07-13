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

# The reviewed BTC executor production profile is remote-HSM only and requires
# durable replay stores plus a strict-majority observer fleet.
require_text crates/executor/src/bin/xindex-redeem.rs \
    'production requires remote HSM cosigners and prohibits raw secret keys'
require_text crates/executor/src/bin/xindex-redeem.rs \
    'production requires durable broadcast and redemption SQLite stores'
require_text crates/executor/src/bin/xindex-redeem.rs \
    'production requires at least five observer endpoints and a strict-majority quorum'

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
