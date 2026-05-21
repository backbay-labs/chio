#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

SCHEMA="$ROOT/spec/schemas/chio-attest/v1/buyer-proof-negative-fixture-corpus.schema.json"
NEGATIVE_FIXTURE="$ROOT/examples/chio-3vendor/fixtures/negative-cases.json"

if rg -n 'chio\.chiodos|chiodos_|chiodos:' "$NEGATIVE_FIXTURE"; then
  echo "active Chio attest negative corpus must not contain Chiodos schema IDs or names" >&2
  exit 1
fi

if [[ ! -f "$SCHEMA" ]]; then
  echo "missing Chio attest negative corpus schema: $SCHEMA" >&2
  exit 1
fi

if [[ -n "${CHIO_SPEC_VALIDATE_BIN:-}" ]]; then
  "$CHIO_SPEC_VALIDATE_BIN" "$SCHEMA" "$NEGATIVE_FIXTURE" >/dev/null
else
  cargo run -p chio-spec-validate -- "$SCHEMA" "$NEGATIVE_FIXTURE" >/dev/null
fi
