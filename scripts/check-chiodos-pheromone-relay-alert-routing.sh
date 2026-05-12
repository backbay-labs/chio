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
    echo "usage: check-chiodos-pheromone-relay-alert-routing.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chiodos-pheromone-relay-alert-routing.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

SCHEMA_DIR="$ROOT/spec/schemas/chio-pheromone/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"
FIXTURE_DIR="$ROOT/examples/chiodos-3vendor/fixtures/pheromone/relay"
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
    "chio.pheromone.relay-alert-routing-profile.v1": "relay-alert-routing-profile.schema.json",
    "chio.pheromone.relay-alert-report.v1": "relay-alert-report.schema.json",
    "chio.pheromone.relay-alert-suppression-state.v1": "relay-alert-suppression-state.schema.json",
    "chio.pheromone.relay-trend-report.v1": "relay-trend-report.schema.json",
    "chio.pheromone.relay-alert-negative-fixture-corpus.v1": "relay-alert-negative-fixture-corpus.schema.json",
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

negative = json.loads((fixture_dir / "relay-alert-negative-cases.json").read_text(encoding="utf-8"))
case_ids = {case.get("id") for case in negative.get("cases", [])}
required_cases = {
    "inline-token",
    "dynamic-url",
    "stale-report",
    "kernel-mismatch",
    "source-hash-mismatch",
    "overlong-suppression",
    "critical-suppression",
    "dedupe-collision",
    "missing-evidence",
    "timestamp-regression",
    "unknown-code-default-allow",
    "unbounded-label-leakage",
    "missing-metrics-false-all-clear",
}
missing = sorted(required_cases - case_ids)
if missing:
    raise SystemExit(f"relay alert negative corpus missing cases: {missing}")

profile = json.loads((fixture_dir / "relay-alert-routing-profile.json").read_text(encoding="utf-8"))
if "notification_route" not in profile.get("allowedLabelNames", []):
    raise SystemExit("routing profile does not declare notification_route label")
for route in profile.get("routes", []):
    target = route.get("targetRef", "")
    if "://" in target:
        raise SystemExit(f"routing profile contains dynamic URL target: {target}")
    if re.search(r"(?i)(token|secret|password|bearer|api[_-]?key)", json.dumps(route)):
        raise SystemExit(f"routing profile route may contain inline secret material: {route.get('routeId')}")

alert_report = json.loads((fixture_dir / "relay-alert-report.json").read_text(encoding="utf-8"))
alerts = alert_report.get("alerts", [])
if alert_report.get("accepted") is not False or alert_report.get("code") != "alerts_firing":
    raise SystemExit("degraded alert report must remain firing")
dead_letter = next((alert for alert in alerts if alert.get("code") == "dead_letters_present"), None)
if not dead_letter or dead_letter.get("state") != "firing" or dead_letter.get("severity") != "critical":
    raise SystemExit("critical dead-letter alert must remain visible")
stale_lease = next((alert for alert in alerts if alert.get("code") == "stale_leases_present"), None)
if not stale_lease or stale_lease.get("state") != "suppressed":
    raise SystemExit("stale lease alert should exercise capped suppression")
allowed_labels = {"notification_route", "opsgenie", "service", "severity"}
leaky_value = re.compile(r"did:chio|treaty:|[0-9a-f]{32,}|nonce|cursor|outbox", re.IGNORECASE)
for alert in alerts:
    labels = alert.get("labels", {})
    extra = sorted(set(labels) - allowed_labels)
    if extra:
        raise SystemExit(f"alert {alert.get('code')} has unbounded labels: {extra}")
    for name, value in labels.items():
        if leaky_value.search(str(value)):
            raise SystemExit(f"alert {alert.get('code')} leaks unbounded label {name}={value}")

trend = json.loads((fixture_dir / "relay-trend-report.json").read_text(encoding="utf-8"))
codes = {point.get("code") for point in trend.get("points", [])}
for required in {"dead_letters_present", "relay_nonce_replay", "endpoint_denied"}:
    if required not in codes:
        raise SystemExit(f"trend report missing {required}")
print("OK Chiodos pheromone relay alert routing metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/relay-alert-routing-profile.schema.json" "$FIXTURE_DIR/relay-alert-routing-profile.json"
validate_schema "$SCHEMA_DIR/relay-alert-suppression-state.schema.json" "$FIXTURE_DIR/relay-alert-suppression-state.json"
validate_schema "$SCHEMA_DIR/relay-alert-report.schema.json" "$FIXTURE_DIR/relay-alert-report.json"
validate_schema "$SCHEMA_DIR/relay-trend-report.schema.json" "$FIXTURE_DIR/relay-trend-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-negative-fixture-corpus.schema.json" "$FIXTURE_DIR/relay-alert-negative-cases.json"
validate_schema "$SCHEMA_DIR/relay-event-report.schema.json" "$FIXTURE_DIR/relay-event-dead-letter-report.json"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

GENERATED_DIR="$(mktemp -d)"
TMP_DIRS+=("$GENERATED_DIR")

cargo run -p chio-cli -- chiodos pheromone relay alert evaluate \
  --observability-report "$FIXTURE_DIR/relay-observability-degraded-report.json" \
  --event-dir "$FIXTURE_DIR" \
  --routing-profile "$FIXTURE_DIR/relay-alert-routing-profile.json" \
  --suppression-state "$FIXTURE_DIR/relay-alert-suppression-state.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-report.schema.json" "$GENERATED_DIR/relay-alert-report.json"

cargo run -p chio-cli -- chiodos pheromone relay trend \
  --reports-dir "$FIXTURE_DIR" \
  --event-dir "$FIXTURE_DIR" \
  --routing-profile "$FIXTURE_DIR/relay-alert-routing-profile.json" \
  --since-unix-ms "$SINCE_UNIX_MS" \
  --until-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-trend-report.json"
validate_schema "$SCHEMA_DIR/relay-trend-report.schema.json" "$GENERATED_DIR/relay-trend-report.json"

python3 - "$GENERATED_DIR" <<'PY'
import json
import pathlib
import sys

generated_dir = pathlib.Path(sys.argv[1])
alert_report = json.loads((generated_dir / "relay-alert-report.json").read_text(encoding="utf-8"))
trend_report = json.loads((generated_dir / "relay-trend-report.json").read_text(encoding="utf-8"))
if alert_report.get("code") != "alerts_firing":
    raise SystemExit("generated alert report must preserve firing relay alerts")
if not any(alert.get("code") == "dead_letters_present" for alert in alert_report.get("alerts", [])):
    raise SystemExit("generated alert report omitted dead-letter alert")
if trend_report.get("sourceReportCount", 0) < 1:
    raise SystemExit("generated trend report did not aggregate report evidence")
print("OK generated relay alert and trend reports")
PY

cargo test -p chio-pheromone-relay alert
cargo test -p chio-cli --bin chio chiodos_pheromone_relay
cargo test -p chio-metrics-spec
bash "$ROOT/scripts/check-sre-metrics-registry.sh"

if [[ "$MODE" == "negative-only" ]]; then
  exit 0
fi

pushd "$ROOT/crates/chio-cli/dashboard" >/dev/null
npm test
npm run build
popd >/dev/null

bash "$ROOT/scripts/check-chiodos-pheromone-relay-observability.sh" --schema-only
bash "$ROOT/scripts/check-chiodos-pheromone-directory-lifecycle.sh" --schema-only
bash "$ROOT/scripts/check-chiodos-pheromone-relay-ops.sh" --schema-only
bash "$ROOT/scripts/check-chiodos-pheromone-relay.sh" --schema-only
