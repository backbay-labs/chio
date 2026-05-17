#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="all"
case "${1:-}" in
  "")
    ;;
  "--schema-only")
    MODE="schema-only"
    shift
    ;;
  "--negative-only")
    MODE="negative-only"
    shift
    ;;
  "--regenerate-only")
    MODE="regenerate-only"
    shift
    ;;
  "--parity-only")
    MODE="parity-only"
    shift
    ;;
  "--fixtures-only")
    MODE="fixtures-only"
    shift
    ;;
  *)
    echo "usage: check-chiodos-runtime-proof-parity.sh [--schema-only|--negative-only|--regenerate-only|--parity-only|--fixtures-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chiodos-runtime-proof-parity.sh [--schema-only|--negative-only|--regenerate-only|--parity-only|--fixtures-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

case "$MODE" in
  "schema-only")
    bash "$ROOT/scripts/check-chiodos-runtime-spine.sh" --schema-only
    ;;
  "negative-only")
    bash "$ROOT/scripts/check-chiodos-runtime-spine.sh" --negative-only
    ;;
  "regenerate-only")
    bash "$ROOT/scripts/check-chiodos-runtime-spine.sh"
    ;;
  "parity-only")
    cargo test -p chio-chiodos-runtime runtime_proof_regeneration
    bash "$ROOT/scripts/check-chiodos-runtime-spine.sh" --schema-only
    ;;
  "fixtures-only")
    cargo test -p chiodos-three-vendor-example
    ;;
  "all")
    cargo test -p chio-chiodos-runtime runtime_workflow_report
    cargo test -p chio-chiodos-runtime proof_regeneration_report
    cargo test -p chio-chiodos-runtime runtime_proof_regeneration
    cargo test -p chiodos-three-vendor-example
    cargo test -p chio-cli --bin chio chiodos_runtime
    bash "$ROOT/scripts/check-chiodos-runtime-spine.sh"
    ;;
esac
