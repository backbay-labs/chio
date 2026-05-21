#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
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
    echo "usage: check-chio-pheromone-relay-alert-handoff.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-pheromone-relay-alert-handoff.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

SCHEMA_DIR="$ROOT/spec/schemas/chio-pheromone/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"
FIXTURE_DIR="$ROOT/examples/chio-3vendor/fixtures/pheromone/relay"
NOW_UNIX_MS=1766000060000
SINCE_UNIX_MS=1765999900000
TMP_DIRS=()
cleanup() {
  if [[ ${#TMP_DIRS[@]} -gt 0 ]]; then
    rm -rf "${TMP_DIRS[@]}"
  fi
}
trap cleanup EXIT

python3 - "$SCHEMA_DIR" "$SCHEMA_REGISTRY" "$FIXTURE_DIR" <<'PY'
import json
import pathlib
import re
import sys

schema_dir, registry_path, fixture_dir = map(pathlib.Path, sys.argv[1:])
registry = json.loads(registry_path.read_text(encoding="utf-8"))
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
expected = {
    "chio.pheromone.relay-alert-handoff-profile.v1": "relay-alert-handoff-profile.schema.json",
    "chio.pheromone.relay-alert-handoff-report.v1": "relay-alert-handoff-report.schema.json",
    "chio.pheromone.relay-alert-drill-report.v1": "relay-alert-drill-report.schema.json",
    "chio.pheromone.relay-alert-handoff-negative-fixture-corpus.v1": "relay-alert-handoff-negative-fixture-corpus.schema.json",
}
for schema_id, filename in expected.items():
    path = schema_dir / filename
    if not path.is_file():
        raise SystemExit(f"missing schema {filename}")
    schema = json.loads(path.read_text(encoding="utf-8"))
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        raise SystemExit(f"schema {filename} is not a strict object schema")
    want = f"spec/schemas/chio-pheromone/v1/{filename}"
    if registered.get(schema_id) != want:
        raise SystemExit(f"schema {schema_id} is not registered at {want}")

profile = json.loads((fixture_dir / "relay-alert-handoff-profile.json").read_text(encoding="utf-8"))
if profile.get("schema") != "chio.pheromone.relay-alert-handoff-profile.v1":
    raise SystemExit("handoff profile schema mismatch")
receiver_targets = set()
route_pairs = set()
for receiver in profile.get("receivers", []):
    encoded = json.dumps(receiver)
    if re.search(r"(?i)(token|secret|password|bearer|api[_-]?key)", encoded):
        raise SystemExit(f"handoff receiver may contain inline secret material: {receiver.get('receiverId')}")
    if "://" in receiver.get("targetRef", ""):
        raise SystemExit(f"handoff receiver uses dynamic endpoint: {receiver.get('receiverId')}")
    target = receiver.get("targetRef")
    if target in receiver_targets:
        raise SystemExit(f"duplicate handoff target: {target}")
    receiver_targets.add(target)
    pair = (receiver.get("notificationRoute"), receiver.get("opsgenie"))
    if pair in route_pairs:
        raise SystemExit(f"duplicate handoff route coverage: {pair}")
    route_pairs.add(pair)

report = json.loads((fixture_dir / "relay-alert-handoff-report.json").read_text(encoding="utf-8"))
if report.get("accepted") is not True or report.get("code") != "accepted":
    raise SystemExit("handoff fixture report must be dry-run accepted")
if report.get("criticalFiringCount", 0) < 1:
    raise SystemExit("handoff fixture report must preserve critical firing alert visibility")
if not any(route.get("targetRef") == "alertmanager:pagerduty-primary" for route in report.get("routes", [])):
    raise SystemExit("handoff fixture report missing primary downstream route")

negative = json.loads((fixture_dir / "relay-alert-handoff-negative-cases.json").read_text(encoding="utf-8"))
case_ids = {case.get("id") for case in negative.get("cases", [])}
required = {
    "inline-token",
    "dynamic-url",
    "credential-target-ref",
    "bearer-target-ref",
    "unbounded-label",
    "unknown-sink-kind",
    "duplicate-route",
    "route-collision",
    "stale-alert-report",
    "stale-trend-report",
    "source-hash-mismatch",
    "bad-source-hash-shape",
    "missing-runbook",
    "alert-runbook-mismatch",
    "critical-hidden-by-suppression",
    "missing-event-evidence",
    "weak-escalation-mapping",
    "unknown-alert-code",
    "trend-code-missing",
    "downstream-route-missing",
}
missing = sorted(required - case_ids)
if missing:
    raise SystemExit(f"handoff negative corpus missing cases: {missing}")
print("OK Chio pheromone relay alert handoff metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/relay-alert-handoff-profile.schema.json" "$FIXTURE_DIR/relay-alert-handoff-profile.json"
validate_schema "$SCHEMA_DIR/relay-alert-handoff-report.schema.json" "$FIXTURE_DIR/relay-alert-handoff-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-drill-report.schema.json" "$FIXTURE_DIR/relay-alert-drill-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-handoff-negative-fixture-corpus.schema.json" "$FIXTURE_DIR/relay-alert-handoff-negative-cases.json"
validate_schema "$SCHEMA_DIR/relay-alert-report.schema.json" "$FIXTURE_DIR/relay-alert-report.json"
validate_schema "$SCHEMA_DIR/relay-trend-report.schema.json" "$FIXTURE_DIR/relay-trend-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-routing-profile.schema.json" "$FIXTURE_DIR/relay-alert-routing-profile.json"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

GENERATED_DIR="$(mktemp -d)"
TMP_DIRS+=("$GENERATED_DIR")

cargo run -p chio-cli -- pheromone relay alert evaluate \
  --observability-report "$FIXTURE_DIR/relay-observability-degraded-report.json" \
  --event-dir "$FIXTURE_DIR" \
  --routing-profile "$FIXTURE_DIR/relay-alert-routing-profile.json" \
  --suppression-state "$FIXTURE_DIR/relay-alert-suppression-state.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-report.schema.json" "$GENERATED_DIR/relay-alert-report.json"

cargo run -p chio-cli -- pheromone relay trend \
  --reports-dir "$FIXTURE_DIR" \
  --event-dir "$FIXTURE_DIR" \
  --routing-profile "$FIXTURE_DIR/relay-alert-routing-profile.json" \
  --since-unix-ms "$SINCE_UNIX_MS" \
  --until-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-trend-report.json"
validate_schema "$SCHEMA_DIR/relay-trend-report.schema.json" "$GENERATED_DIR/relay-trend-report.json"

cargo run -p chio-cli -- pheromone relay alert handoff \
  --alert-report "$GENERATED_DIR/relay-alert-report.json" \
  --trend-report "$GENERATED_DIR/relay-trend-report.json" \
  --routing-profile "$FIXTURE_DIR/relay-alert-routing-profile.json" \
  --handoff-profile "$FIXTURE_DIR/relay-alert-handoff-profile.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-handoff-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-handoff-report.schema.json" "$GENERATED_DIR/relay-alert-handoff-report.json"

python3 - "$GENERATED_DIR" <<'PY'
import json
import pathlib
import sys

generated_dir = pathlib.Path(sys.argv[1])
handoff = json.loads((generated_dir / "relay-alert-handoff-report.json").read_text(encoding="utf-8"))
if handoff.get("accepted") is not True or handoff.get("code") != "accepted":
    raise SystemExit("generated handoff report must be accepted")
if handoff.get("criticalFiringCount", 0) < 1:
    raise SystemExit("generated handoff report hid critical firing alerts")
routes = handoff.get("routes", [])
if not any(route.get("targetRef") == "alertmanager:pagerduty-primary" for route in routes):
    raise SystemExit("generated handoff report missing primary downstream route")
print("OK generated relay alert handoff report")
PY

cargo test -p chio-pheromone-relay alert_handoff --test relay
cargo test -p chio-cli --bin chio chio_pheromone

if [[ "$MODE" == "negative-only" ]]; then
  exit 0
fi

pushd "$ROOT/crates/chio-cli/dashboard" >/dev/null
npm test -- RelayAlertRoutingSummary
npm run build
popd >/dev/null

bash "$ROOT/scripts/check-chio-pheromone-relay-alert-routing.sh" --schema-only
bash "$ROOT/scripts/check-chio-pheromone-relay-observability.sh" --schema-only
bash "$ROOT/scripts/check-chio-pheromone-directory-lifecycle.sh" --schema-only
bash "$ROOT/scripts/check-chio-pheromone-relay-ops.sh" --schema-only
bash "$ROOT/scripts/check-chio-pheromone-relay.sh" --schema-only
