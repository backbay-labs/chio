#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! cargo creusot version >/dev/null 2>&1; then
  echo "Creusot core check requires cargo-creusot" >&2
  exit 1
fi

(
  cd formal/rust-verification/creusot-core
  rustflags="${RUSTFLAGS:-}"
  if [[ -n "${rustflags}" ]]; then
    rustflags+=" "
  fi
  rustflags+="--cfg chio_creusot_contracts"
  RUSTFLAGS="${rustflags}" cargo creusot prove
)

echo "Creusot core contracts passed"
