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
  *)
    echo "usage: check-chio-pheromone-relay-alert-assurance-archive-hardening.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-pheromone-relay-alert-assurance-archive-hardening.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

SCHEMA_DIR="$ROOT/spec/schemas/chio-pheromone/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"
ASSURANCE_DIR="$ROOT/examples/chio-3vendor/fixtures/pheromone/relay/alert-assurance"

python3 - "$SCHEMA_DIR" "$SCHEMA_REGISTRY" "$ASSURANCE_DIR" <<'PY'
import json
import pathlib
import sys

schema_dir, registry_path, fixture_dir = map(pathlib.Path, sys.argv[1:])
registry = json.loads(registry_path.read_text(encoding="utf-8"))
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
expected = {
    "chio.pheromone.relay-alert-assurance-archive-restore-profile.v1": "relay-alert-assurance-archive-restore-profile.schema.json",
    "chio.pheromone.relay-alert-assurance-archive-restore-drill-report.v1": "relay-alert-assurance-archive-restore-drill-report.schema.json",
    "chio.pheromone.relay-alert-assurance-archive-restore-negative-fixture-corpus.v1": "relay-alert-assurance-archive-restore-negative-fixture-corpus.schema.json",
}
for schema_id, filename in expected.items():
    path = schema_dir / filename
    if not path.is_file():
        raise SystemExit(f"missing schema {filename}")
    schema = json.loads(path.read_text(encoding="utf-8"))
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        raise SystemExit(f"schema {filename} is not strict")
    want = f"spec/schemas/chio-pheromone/v1/{filename}"
    if registered.get(schema_id) != want:
        raise SystemExit(f"schema {schema_id} is not registered at {want}")

negative = json.loads((fixture_dir / "relay-alert-assurance-archive-restore-negative-cases.json").read_text(encoding="utf-8"))
case_ids = {case.get("caseId") for case in negative.get("cases", [])}
required = {
    "generation_gap",
    "duplicate_generation",
    "previous_hash_mismatch",
    "missing_readback",
    "retention_handoff_not_ready",
    "wrong_expected_code",
}
missing = sorted(required - case_ids)
if missing:
    raise SystemExit(f"archive restore negative corpus missing cases: {missing}")
print("OK Chio relay alert assurance archive hardening metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/relay-alert-assurance-archive-restore-profile.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-archive-restore-profile.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-archive-restore-negative-fixture-corpus.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-archive-restore-negative-cases.json"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

if [[ "$MODE" == "all" || "$MODE" == "negative-only" ]]; then
  cargo test -p chio-cli guard_archive_hardening
  cargo test -p chio-cli conformance_archive_hardening
  cargo test -p chio-pheromone-relay relay_alert_assurance_archive --test relay
fi
