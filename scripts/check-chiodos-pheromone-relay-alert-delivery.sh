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
    echo "usage: check-chiodos-pheromone-relay-alert-delivery.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chiodos-pheromone-relay-alert-delivery.sh [--schema-only|--negative-only]" >&2
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
    "chio.pheromone.relay-alert-delivery-profile.v1": "relay-alert-delivery-profile.schema.json",
    "chio.pheromone.relay-alert-delivery-evidence.v1": "relay-alert-delivery-evidence.schema.json",
    "chio.pheromone.relay-alert-delivery-report.v1": "relay-alert-delivery-report.schema.json",
    "chio.pheromone.relay-alert-acknowledgement-report.v1": "relay-alert-acknowledgement-report.schema.json",
    "chio.pheromone.relay-alert-handoff-drift-report.v1": "relay-alert-handoff-drift-report.schema.json",
    "chio.pheromone.relay-alert-delivery-negative-fixture-corpus.v1": "relay-alert-delivery-negative-fixture-corpus.schema.json",
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

secret_re = re.compile(r"(?i)(token|secret|password|bearer|api[_-]?key)")
profile = json.loads((fixture_dir / "relay-alert-delivery-profile.json").read_text(encoding="utf-8"))
if profile.get("schema") != "chio.pheromone.relay-alert-delivery-profile.v1":
    raise SystemExit("delivery profile schema mismatch")
receiver_ids = set()
targets = set()
for receiver in profile.get("receivers", []):
    encoded = json.dumps(receiver)
    if secret_re.search(encoded):
        raise SystemExit(f"delivery receiver may contain secret material: {receiver.get('receiverId')}")
    if "://" in receiver.get("targetRef", ""):
        raise SystemExit(f"delivery receiver uses dynamic endpoint: {receiver.get('receiverId')}")
    if receiver.get("receiverId") in receiver_ids:
        raise SystemExit(f"duplicate delivery receiver: {receiver.get('receiverId')}")
    receiver_ids.add(receiver.get("receiverId"))
    if receiver.get("targetRef") in targets:
        raise SystemExit(f"duplicate delivery target: {receiver.get('targetRef')}")
    targets.add(receiver.get("targetRef"))

allowed_labels = {"notification_route", "opsgenie", "service", "severity", "status", "receiver"}
for evidence_path in sorted(fixture_dir.glob("relay-alert-delivery-evidence-*.json")):
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    if evidence.get("schema") != "chio.pheromone.relay-alert-delivery-evidence.v1":
        raise SystemExit(f"delivery evidence schema mismatch: {evidence_path.name}")
    encoded = json.dumps(evidence)
    if secret_re.search(encoded):
        raise SystemExit(f"delivery evidence may contain secret material: {evidence_path.name}")
    labels = evidence.get("labels", {})
    if set(labels) - allowed_labels:
        raise SystemExit(f"delivery evidence has unbounded labels: {evidence_path.name}")
    for forbidden in ("peer", "treaty", "hash", "nonce", "cursor", "endpoint"):
        if any(forbidden in name for name in labels):
            raise SystemExit(f"delivery evidence leaks forbidden label class: {evidence_path.name}")

delivery = json.loads((fixture_dir / "relay-alert-delivery-report.json").read_text(encoding="utf-8"))
if delivery.get("accepted") is not True or delivery.get("code") != "accepted":
    raise SystemExit("delivery fixture report must be accepted")
if delivery.get("deliveredCount", 0) < 1:
    raise SystemExit("delivery fixture report must include downstream delivery evidence")

ack = json.loads((fixture_dir / "relay-alert-acknowledgement-report.json").read_text(encoding="utf-8"))
if ack.get("accepted") is not True or ack.get("acknowledgedCount", 0) < 1:
    raise SystemExit("acknowledgement fixture report must summarize downstream outcomes")

drift = json.loads((fixture_dir / "relay-alert-handoff-drift-report.json").read_text(encoding="utf-8"))
if drift.get("accepted") is not True or drift.get("driftCount") != 0:
    raise SystemExit("drift fixture report must be accepted")

negative = json.loads((fixture_dir / "relay-alert-delivery-negative-cases.json").read_text(encoding="utf-8"))
case_ids = {case.get("id") for case in negative.get("cases", [])}
required = {
    "live-url",
    "inline-token",
    "unbounded-label",
    "unknown-receiver",
    "route-mismatch",
    "dedupe-missing",
    "stale-handoff",
    "source-hash-mismatch",
    "duplicate-result",
    "missing-critical-delivery",
    "severity-weakened",
    "runbook-drift",
    "wrong-expected-code",
}
missing = sorted(required - case_ids)
if missing:
    raise SystemExit(f"delivery negative corpus missing cases: {missing}")
print("OK Chiodos pheromone relay alert delivery metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/relay-alert-delivery-profile.schema.json" "$FIXTURE_DIR/relay-alert-delivery-profile.json"
for evidence in "$FIXTURE_DIR"/relay-alert-delivery-evidence-*.json; do
  validate_schema "$SCHEMA_DIR/relay-alert-delivery-evidence.schema.json" "$evidence"
done
validate_schema "$SCHEMA_DIR/relay-alert-delivery-report.schema.json" "$FIXTURE_DIR/relay-alert-delivery-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-acknowledgement-report.schema.json" "$FIXTURE_DIR/relay-alert-acknowledgement-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-handoff-drift-report.schema.json" "$FIXTURE_DIR/relay-alert-handoff-drift-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-delivery-negative-fixture-corpus.schema.json" "$FIXTURE_DIR/relay-alert-delivery-negative-cases.json"
validate_schema "$SCHEMA_DIR/relay-alert-handoff-report.schema.json" "$FIXTURE_DIR/relay-alert-handoff-report.json"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

GENERATED_DIR="$(mktemp -d)"
TMP_DIRS+=("$GENERATED_DIR")

cargo run -p chio-cli -- chiodos pheromone relay alert delivery import \
  --handoff-report "$FIXTURE_DIR/relay-alert-handoff-report.json" \
  --delivery-profile "$FIXTURE_DIR/relay-alert-delivery-profile.json" \
  --evidence-dir "$FIXTURE_DIR" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-delivery-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-delivery-report.schema.json" "$GENERATED_DIR/relay-alert-delivery-report.json"

cargo run -p chio-cli -- chiodos pheromone relay alert delivery acknowledge \
  --handoff-report "$FIXTURE_DIR/relay-alert-handoff-report.json" \
  --delivery-report "$GENERATED_DIR/relay-alert-delivery-report.json" \
  --delivery-profile "$FIXTURE_DIR/relay-alert-delivery-profile.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-acknowledgement-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-acknowledgement-report.schema.json" "$GENERATED_DIR/relay-alert-acknowledgement-report.json"

cargo run -p chio-cli -- chiodos pheromone relay alert delivery drift \
  --handoff-reports-dir "$FIXTURE_DIR" \
  --delivery-reports-dir "$GENERATED_DIR" \
  --delivery-profile "$FIXTURE_DIR/relay-alert-delivery-profile.json" \
  --since-unix-ms "$SINCE_UNIX_MS" \
  --until-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-handoff-drift-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-handoff-drift-report.schema.json" "$GENERATED_DIR/relay-alert-handoff-drift-report.json"

python3 - "$GENERATED_DIR" <<'PY'
import json
import pathlib
import sys

generated_dir = pathlib.Path(sys.argv[1])
delivery = json.loads((generated_dir / "relay-alert-delivery-report.json").read_text(encoding="utf-8"))
if delivery.get("accepted") is not True or delivery.get("deliveredCount", 0) < 1:
    raise SystemExit("generated delivery report must be accepted with delivery evidence")
ack = json.loads((generated_dir / "relay-alert-acknowledgement-report.json").read_text(encoding="utf-8"))
if ack.get("accepted") is not True or ack.get("acknowledgedCount", 0) < 1:
    raise SystemExit("generated acknowledgement report must be accepted")
drift = json.loads((generated_dir / "relay-alert-handoff-drift-report.json").read_text(encoding="utf-8"))
if drift.get("accepted") is not True or drift.get("driftCount") != 0:
    raise SystemExit("generated drift report must be accepted")
print("OK generated relay alert delivery reports")
PY

cargo test -p chio-pheromone-relay alert_delivery --test relay
cargo test -p chio-cli --bin chio chiodos_pheromone_relay_alert_delivery

if [[ "$MODE" == "negative-only" ]]; then
  exit 0
fi

pushd "$ROOT/crates/chio-cli/dashboard" >/dev/null
npm test -- RelayAlertDeliverySummary RelayAlertRoutingSummary
npm run build
popd >/dev/null

bash "$ROOT/scripts/check-chiodos-pheromone-relay-alert-handoff.sh" --schema-only
bash "$ROOT/scripts/check-chiodos-pheromone-relay-alert-routing.sh" --schema-only
bash "$ROOT/scripts/check-chiodos-pheromone-relay-observability.sh" --schema-only
bash "$ROOT/scripts/check-chiodos-pheromone-directory-lifecycle.sh" --schema-only
bash "$ROOT/scripts/check-chiodos-pheromone-relay-ops.sh" --schema-only
bash "$ROOT/scripts/check-chiodos-pheromone-relay.sh" --schema-only
