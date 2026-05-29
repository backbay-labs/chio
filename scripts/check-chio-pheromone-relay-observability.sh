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
    echo "usage: check-chio-pheromone-relay-observability.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-pheromone-relay-observability.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

SCHEMA_DIR="$ROOT/spec/schemas/chio-pheromone/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"
FIXTURE_DIR="$ROOT/examples/chio-3vendor/fixtures/pheromone/relay"

python3 - "$SCHEMA_DIR" "$SCHEMA_REGISTRY" "$FIXTURE_DIR" <<'PY'
import json
import pathlib
import sys

schema_dir, registry_path, fixture_dir = map(pathlib.Path, sys.argv[1:])
registry = json.loads(registry_path.read_text(encoding="utf-8"))
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
expected = {
    "chio.pheromone.relay-observability-report.v1": "relay-observability-report.schema.json",
    "chio.pheromone.relay-metrics-snapshot.v1": "relay-metrics-snapshot.schema.json",
    "chio.pheromone.relay-event-report.v1": "relay-event-report.schema.json",
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

negative = json.loads((fixture_dir / "negative-cases.json").read_text(encoding="utf-8"))
codes = {case.get("expectedFailureCode") for case in negative.get("cases", [])}
required = {
    "directory_expiring",
    "dead_letters_present",
    "relay_nonce_replay",
    "schema_validation_failed",
}
missing = sorted(required - codes)
if missing:
    raise SystemExit(f"relay observability negative corpus missing codes: {missing}")

metrics = json.loads((fixture_dir / "relay-metrics-snapshot.json").read_text(encoding="utf-8"))
for sample in metrics.get("samples", []):
    labels = sample.get("labels", {})
    disallowed = {"peer", "peer_id", "treaty", "treaty_id", "hash", "nonce", "cursor", "outbox_id"}
    overlap = sorted(disallowed.intersection(labels.keys()))
    if overlap:
        raise SystemExit(f"relay metrics fixture uses unbounded labels: {overlap}")
print("OK Chio pheromone relay observability metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/relay-observability-report.schema.json" "$FIXTURE_DIR/relay-observability-report.json"
validate_schema "$SCHEMA_DIR/relay-observability-report.schema.json" "$FIXTURE_DIR/relay-observability-degraded-report.json"
validate_schema "$SCHEMA_DIR/relay-metrics-snapshot.schema.json" "$FIXTURE_DIR/relay-metrics-snapshot.json"
validate_schema "$SCHEMA_DIR/relay-event-report.schema.json" "$FIXTURE_DIR/relay-event-report.json"
validate_schema "$SCHEMA_DIR/relay-negative-fixture-corpus.schema.json" "$FIXTURE_DIR/negative-cases.json"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

cargo test -p chio-pheromone-relay observability
cargo test -p chio-cli --bin chio chio_pheromone
cargo test -p chio-metrics-spec
bash "$ROOT/scripts/check-sre-metrics-registry.sh"

pushd "$ROOT/crates/chio-cli/dashboard" >/dev/null
npm test
npm run build
popd >/dev/null

if [[ "$MODE" == "negative-only" ]]; then
  python3 - "$FIXTURE_DIR/relay-observability-degraded-report.json" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
codes = {item.get("code") for item in report.get("recommendations", [])}
required = {"dead_letters_present", "stale_leases_present"}
missing = sorted(required - codes)
if missing:
    raise SystemExit(f"degraded relay observability fixture missing recommendations: {missing}")
PY
  exit 0
fi

bash "$ROOT/scripts/check-chio-pheromone-directory-lifecycle.sh" --schema-only
bash "$ROOT/scripts/check-chio-pheromone-relay-ops.sh" --schema-only
bash "$ROOT/scripts/check-chio-pheromone-relay.sh" --schema-only
