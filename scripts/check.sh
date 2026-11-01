#!/usr/bin/env bash
# Runs the same checks as CI (.github/workflows/ci.yml) on any build host.
#
# Usage: scripts/check.sh [step...]
#   steps: fmt clippy hack arch machete images deny doc test contracts unsupported (default: all)
#
# Needs the toolchain from rust-toolchain.toml plus cargo-nextest, cargo-deny, cargo-hack and cargo-machete. The test step uses
# DATABASE_URL for PostgreSQL-backed tests; with CI=true such tests fail when it is missing.
set -euo pipefail

cd "$(dirname "$0")/.."

all_steps=(fmt clippy hack arch machete images deny doc test contracts unsupported)
steps=("$@")
if [ "${#steps[@]}" -eq 0 ]; then
  steps=("${all_steps[@]}")
fi

need() {
  if ! cargo "$1" --version >/dev/null 2>&1; then
    echo "error: cargo $1 is not installed (cargo install --locked $2)" >&2
    exit 1
  fi
}

run() {
  echo "+ $*"
  "$@"
}

for step in "${steps[@]}"; do
  echo "==> ${step}"
  case "${step}" in
    fmt)
      run cargo fmt --all -- --check
      ;;
    clippy)
      run cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
      run cargo clippy --workspace --all-targets --no-default-features --locked -- -D warnings
      ;;
    hack)
      need hack cargo-hack
      run cargo hack check -p davhaven-server --each-feature --locked
      ;;
    arch)
      run cargo xtask arch-check
      ;;
    machete)
      need machete cargo-machete
      run cargo machete --with-metadata . crates/ical/fuzz crates/dav/fuzz
      ;;
    images)
      run bash scripts/image-pins.sh --self-test
      run bash scripts/image-pins.sh agree
      ;;
    deny)
      need deny cargo-deny
      run cargo deny --all-features --locked check
      ;;
    doc)
      run env RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --no-deps --all-features --locked
      ;;
    test)
      need nextest cargo-nextest
      run cargo nextest run --workspace --all-features --locked
      run cargo test --workspace --all-features --locked --doc
      ;;
    contracts)
      run cargo xtask contracts --check
      run cargo xtask matrix --check
      run cargo xtask config-docs --check
      run cargo xtask problems-docs --check
      ;;
    unsupported)
      run cargo xtask unsupported
      ;;
    *)
      echo "error: unknown step '${step}' (known: ${all_steps[*]})" >&2
      exit 2
      ;;
  esac
done
echo "==> all requested checks passed"
