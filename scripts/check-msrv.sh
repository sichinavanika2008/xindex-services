#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "declared-MSRV check failed: $*" >&2
    exit 1
}

manifest_msrv=$(awk -F'"' '/^rust-version = / { print $2; exit }' Cargo.toml)
toolchain_pin=$(awk -F'"' '/^channel = / { print $2; exit }' rust-toolchain.toml)

[[ -n "$manifest_msrv" ]] || fail "Cargo.toml has no workspace rust-version"
[[ -n "$toolchain_pin" ]] || fail "rust-toolchain.toml has no channel"
[[ "$manifest_msrv" == "$toolchain_pin" ]] ||
    fail "Cargo.toml rust-version $manifest_msrv != rust-toolchain.toml channel $toolchain_pin"

actual_rustc=$(rustc --version | awk '{ print $2 }')
[[ "$actual_rustc" == "$manifest_msrv" ]] ||
    fail "active rustc $actual_rustc != declared MSRV $manifest_msrv"

cargo check --workspace --all-features --locked

echo "declared MSRV: OK ($manifest_msrv)"
