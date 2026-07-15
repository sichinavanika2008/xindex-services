#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "compiled production-profile check failed: $*" >&2
    exit 1
}

# One table-driven negative test lives in each production entry point below.
# The filter is deliberately unique: it executes no signer/custody operation,
# parses no secret key, opens no listener, and performs no network request.
# Each test mutates the same startup validator its binary calls before I/O.
expected=8
output=$(mktemp "${TMPDIR:-/tmp}/xindex-production-profile.XXXXXX")
trap 'rm -f "$output"' EXIT

if ! CARGO_TERM_COLOR=never cargo test --locked \
    -p xindex-signer-daemon \
    -p xindex-executor \
    -p xindex-chain-eth \
    -p xindex-relayer \
    production_profile_behavior -- --nocapture >"$output" 2>&1; then
    cat "$output" >&2
    fail "a compiled startup-policy mutation was accepted"
fi

actual=$(rg --count-matches '^test .*production_profile_behavior.* \.\.\. ok$' "$output" || true)
actual=${actual:-0}
if [[ "$actual" -ne "$expected" ]]; then
    cat "$output" >&2
    fail "expected $expected compiled startup-policy tests, observed $actual"
fi

echo "compiled production-profile behaviors: OK ($actual/$expected)"
