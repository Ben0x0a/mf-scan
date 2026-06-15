#!/usr/bin/env bash
# Local mirror of the CI release gate (.github/workflows/release.yml `check` job),
# extended to catch platform-specific breakage BEFORE a tag push.
#
# WHY this exists: CI runs clippy on a Linux runner, so it compiles the
# `#[cfg(target_os = "linux")]` code paths (e.g. `is_remote_path`'s statfs magic).
# Running `cargo clippy` on a macOS dev box compiles the *macOS* cfg branch instead,
# so a Linux-only lint/build error sails through locally and only fails in CI. This
# script runs clippy for every release target, so cfg-gated code is linted here.
#
# Clippy/check do NOT link, so cross-target runs need only the target's std
# (`rustup target add ...`), not a cross-linker. Missing targets are reported with
# the command to add them, and skipped (so the script still runs what it can).
#
# Usage:  ./scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# The targets CI builds (release.yml build matrix). Host-equivalent targets are
# covered by the plain host clippy run below; these are the cross ones worth linting.
CROSS_TARGETS=(
  x86_64-unknown-linux-gnu
  x86_64-pc-windows-msvc
)

echo "==> rustfmt (--check)"
cargo fmt --all -- --check

echo "==> clippy: host target"
cargo clippy --all-targets --locked -- -D warnings

installed="$(rustup target list --installed)"
for t in "${CROSS_TARGETS[@]}"; do
  if grep -qx "$t" <<<"$installed"; then
    echo "==> clippy: $t"
    cargo clippy --target "$t" --all-targets --locked -- -D warnings
  else
    echo "==> clippy: $t  SKIPPED (run: rustup target add $t)"
  fi
done

echo "==> tests"
cargo test --all --locked

echo "All checks passed."
