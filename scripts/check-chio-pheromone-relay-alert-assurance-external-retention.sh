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
    echo "usage: check-chio-pheromone-relay-alert-assurance-external-retention.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-pheromone-relay-alert-assurance-external-retention.sh [--schema-only|--negative-only]" >&2
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
    "chio.pheromone.relay-alert-assurance-external-retention-profile.v1": "relay-alert-assurance-external-retention-profile.schema.json",
    "chio.pheromone.relay-alert-assurance-external-retention-review-report.v1": "relay-alert-assurance-external-retention-review-report.schema.json",
    "chio.pheromone.relay-alert-assurance-external-retention-negative-fixture-corpus.v1": "relay-alert-assurance-external-retention-negative-fixture-corpus.schema.json",
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

negative = json.loads((fixture_dir / "relay-alert-assurance-external-retention-negative-cases.json").read_text(encoding="utf-8"))
expected_codes = {
    "untrusted_packager": "external_retention_blocked",
    "untrusted_exporter": "external_retention_blocked",
    "source_report_mismatch": "external_retention_blocked",
    "stale_profile": "archive_package_invalid",
    "stale_evidence": "external_retention_blocked",
    "local_kernel_mismatch": "external_retention_blocked",
    "generation_gap": "external_retention_blocked",
    "previous_manifest_mismatch": "external_retention_blocked",
    "missing_restore_drill": "external_retention_blocked",
    "rejected_restore_drill": "external_retention_blocked",
    "missing_physical_readback": "external_retention_blocked",
    "insufficient_sample": "external_retention_blocked",
    "missing_retention_handoff": "external_retention_blocked",
    "unknown_retention_alias": "external_retention_blocked",
    "alias_drift": "external_retention_blocked",
    "wrong_expected_code": "negative_corpus_mismatch",
}
actual_codes = {case.get("caseId"): case.get("expectedCode") for case in negative.get("cases", [])}
missing = sorted(set(expected_codes) - set(actual_codes))
if missing:
    raise SystemExit(f"external retention negative corpus missing cases: {missing}")
unexpected = sorted(set(actual_codes) - set(expected_codes))
if unexpected:
    raise SystemExit(f"external retention negative corpus has unexpected cases: {unexpected}")
mismatched = {
    case_id: {"want": want, "got": actual_codes.get(case_id)}
    for case_id, want in expected_codes.items()
    if actual_codes.get(case_id) != want
}
if mismatched:
    raise SystemExit(f"external retention negative corpus expectedCode mismatch: {mismatched}")
print("OK Chio relay alert assurance external retention metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/relay-alert-assurance-external-retention-profile.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-external-retention-profile.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-external-retention-review-report.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-external-retention-review-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-external-retention-negative-fixture-corpus.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-external-retention-negative-cases.json"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

if [[ "$MODE" == "all" || "$MODE" == "negative-only" ]]; then
  cargo test -p chio-pheromone-relay external_retention_review --test relay
  cargo test -p chio-cli --bin chio chio_pheromone_relay_alert_assurance
fi
