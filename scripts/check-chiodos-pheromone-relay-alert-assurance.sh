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
    echo "usage: check-chiodos-pheromone-relay-alert-assurance.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chiodos-pheromone-relay-alert-assurance.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

SCHEMA_DIR="$ROOT/spec/schemas/chio-pheromone/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"
FIXTURE_DIR="$ROOT/examples/chiodos-3vendor/fixtures/pheromone/relay"
ASSURANCE_DIR="$FIXTURE_DIR/alert-assurance"
NOW_UNIX_MS=1766000090000
NORMALIZE_UNIX_MS=1766000070000
ACK_UNIX_MS=1766000080000
SINCE_UNIX_MS=1765999900000
TMP_DIRS=()
cleanup() {
  if [[ ${#TMP_DIRS[@]} -gt 0 ]]; then
    rm -rf "${TMP_DIRS[@]}"
  fi
}
trap cleanup EXIT

python3 - "$SCHEMA_DIR" "$SCHEMA_REGISTRY" "$ASSURANCE_DIR" <<'PY'
import json
import pathlib
import re
import sys

schema_dir, registry_path, fixture_dir = map(pathlib.Path, sys.argv[1:])
registry = json.loads(registry_path.read_text(encoding="utf-8"))
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
expected = {
    "chio.pheromone.relay-alert-normalization-profile.v1": "relay-alert-normalization-profile.schema.json",
    "chio.pheromone.relay-alert-normalization-report.v1": "relay-alert-normalization-report.schema.json",
    "chio.pheromone.relay-alert-delivery-drift-report.v2": "relay-alert-delivery-drift-report-v2.schema.json",
    "chio.pheromone.relay-alert-route-owner-profile.v1": "relay-alert-route-owner-profile.schema.json",
    "chio.pheromone.relay-alert-route-review-packet.v1": "relay-alert-route-review-packet.schema.json",
    "chio.pheromone.relay-alert-assurance-package.v1": "relay-alert-assurance-package.schema.json",
    "chio.pheromone.relay-alert-assurance-negative-fixture-corpus.v1": "relay-alert-assurance-negative-fixture-corpus.schema.json",
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
profile = json.loads((fixture_dir / "relay-alert-normalization-profile.json").read_text(encoding="utf-8"))
receiver_ids = set()
for receiver in profile.get("receivers", []):
    encoded = json.dumps(receiver)
    if secret_re.search(encoded):
        raise SystemExit(f"normalization receiver may contain secret material: {receiver.get('receiverId')}")
    if "://" in receiver.get("targetRef", ""):
        raise SystemExit(f"normalization receiver uses dynamic endpoint: {receiver.get('receiverId')}")
    if receiver.get("receiverId") in receiver_ids:
        raise SystemExit(f"duplicate normalization receiver: {receiver.get('receiverId')}")
    receiver_ids.add(receiver.get("receiverId"))

owner_profile = json.loads((fixture_dir / "relay-alert-route-owner-profile.json").read_text(encoding="utf-8"))
owner_aliases = set()
for owner in owner_profile.get("owners", []):
    encoded = json.dumps(owner)
    if secret_re.search(encoded):
        raise SystemExit(f"route owner may contain contact or secret material: {owner.get('ownerAlias')}")
    if "://" in encoded or "@" in encoded:
        raise SystemExit(f"route owner uses contact material: {owner.get('ownerAlias')}")
    if owner.get("ownerAlias") in owner_aliases:
        raise SystemExit(f"duplicate route owner: {owner.get('ownerAlias')}")
    owner_aliases.add(owner.get("ownerAlias"))

assurance = json.loads((fixture_dir / "relay-alert-assurance-package.json").read_text(encoding="utf-8"))
if assurance.get("schema") != "chio.pheromone.relay-alert-assurance-package.v1":
    raise SystemExit("assurance package schema mismatch")
if assurance.get("accepted") is not False:
    raise SystemExit("fixture assurance package must preserve unhealthy active-alert state")
if "active_alerts_present" not in assurance.get("operatorActionCodes", []):
    raise SystemExit("assurance package missing active alert action code")

negative = json.loads((fixture_dir / "relay-alert-assurance-negative-cases.json").read_text(encoding="utf-8"))
case_ids = {case.get("caseId") for case in negative.get("cases", [])}
required = {
    "stale-source",
    "ambiguous-mapping",
    "secret-looking-field",
    "source-hash-mismatch",
    "later-delivery-masking",
    "route-owner-missing",
}
missing = sorted(required - case_ids)
if missing:
    raise SystemExit(f"assurance negative corpus missing cases: {missing}")
print("OK Chiodos relay alert assurance metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/relay-alert-normalization-profile.schema.json" "$ASSURANCE_DIR/relay-alert-normalization-profile.json"
validate_schema "$SCHEMA_DIR/relay-alert-normalization-report.schema.json" "$ASSURANCE_DIR/relay-alert-normalization-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-delivery-drift-report-v2.schema.json" "$ASSURANCE_DIR/relay-alert-delivery-drift-report-v2.json"
validate_schema "$SCHEMA_DIR/relay-alert-route-owner-profile.schema.json" "$ASSURANCE_DIR/relay-alert-route-owner-profile.json"
validate_schema "$SCHEMA_DIR/relay-alert-route-review-packet.schema.json" "$ASSURANCE_DIR/relay-alert-route-review-packet.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-package.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-package.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-negative-fixture-corpus.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-negative-cases.json"
for evidence in "$ASSURANCE_DIR"/normalized/*.json; do
  validate_schema "$SCHEMA_DIR/relay-alert-delivery-evidence.schema.json" "$evidence"
done

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

GENERATED_DIR="$(mktemp -d)"
TMP_DIRS+=("$GENERATED_DIR")
mkdir -p "$GENERATED_DIR/normalized"

cargo run -p chio-cli -- chiodos pheromone relay alert evaluate \
  --observability-report "$FIXTURE_DIR/relay-observability-degraded-report.json" \
  --event-dir "$FIXTURE_DIR" \
  --routing-profile "$FIXTURE_DIR/relay-alert-routing-profile.json" \
  --suppression-state "$FIXTURE_DIR/relay-alert-suppression-state.json" \
  --now-unix-ms 1766000060000 \
  --report "$GENERATED_DIR/relay-alert-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-report.schema.json" "$GENERATED_DIR/relay-alert-report.json"

cargo run -p chio-cli -- chiodos pheromone relay trend \
  --reports-dir "$FIXTURE_DIR" \
  --event-dir "$FIXTURE_DIR" \
  --routing-profile "$FIXTURE_DIR/relay-alert-routing-profile.json" \
  --since-unix-ms "$SINCE_UNIX_MS" \
  --until-unix-ms 1766000060000 \
  --report "$GENERATED_DIR/relay-trend-report.json"
validate_schema "$SCHEMA_DIR/relay-trend-report.schema.json" "$GENERATED_DIR/relay-trend-report.json"

cargo run -p chio-cli -- chiodos pheromone relay alert handoff \
  --alert-report "$GENERATED_DIR/relay-alert-report.json" \
  --trend-report "$GENERATED_DIR/relay-trend-report.json" \
  --routing-profile "$FIXTURE_DIR/relay-alert-routing-profile.json" \
  --handoff-profile "$FIXTURE_DIR/relay-alert-handoff-profile.json" \
  --now-unix-ms 1766000060000 \
  --report "$GENERATED_DIR/relay-alert-handoff-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-handoff-report.schema.json" "$GENERATED_DIR/relay-alert-handoff-report.json"

cargo run -p chio-cli -- chiodos pheromone relay alert normalize \
  --profile "$ASSURANCE_DIR/relay-alert-normalization-profile.json" \
  --input-dir "$ASSURANCE_DIR/downstream" \
  --now-unix-ms "$NORMALIZE_UNIX_MS" \
  --out-dir "$GENERATED_DIR/normalized" \
  --report "$GENERATED_DIR/relay-alert-normalization-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-normalization-report.schema.json" "$GENERATED_DIR/relay-alert-normalization-report.json"
for evidence in "$GENERATED_DIR"/normalized/*.json; do
  validate_schema "$SCHEMA_DIR/relay-alert-delivery-evidence.schema.json" "$evidence"
done

cargo run -p chio-cli -- chiodos pheromone relay alert delivery import \
  --handoff-report "$GENERATED_DIR/relay-alert-handoff-report.json" \
  --delivery-profile "$ASSURANCE_DIR/relay-alert-delivery-profile.json" \
  --evidence-dir "$GENERATED_DIR/normalized" \
  --now-unix-ms "$NORMALIZE_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-delivery-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-delivery-report.schema.json" "$GENERATED_DIR/relay-alert-delivery-report.json"

cargo run -p chio-cli -- chiodos pheromone relay alert delivery acknowledge \
  --handoff-report "$GENERATED_DIR/relay-alert-handoff-report.json" \
  --delivery-report "$GENERATED_DIR/relay-alert-delivery-report.json" \
  --delivery-profile "$ASSURANCE_DIR/relay-alert-delivery-profile.json" \
  --now-unix-ms "$ACK_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-acknowledgement-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-acknowledgement-report.schema.json" "$GENERATED_DIR/relay-alert-acknowledgement-report.json"

cargo run -p chio-cli -- chiodos pheromone relay alert delivery drift-window \
  --handoff-reports-dir "$GENERATED_DIR" \
  --delivery-reports-dir "$GENERATED_DIR" \
  --delivery-profile "$ASSURANCE_DIR/relay-alert-delivery-profile.json" \
  --since-unix-ms "$SINCE_UNIX_MS" \
  --until-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-delivery-drift-report-v2.json"
validate_schema "$SCHEMA_DIR/relay-alert-delivery-drift-report-v2.schema.json" "$GENERATED_DIR/relay-alert-delivery-drift-report-v2.json"

cargo run -p chio-cli -- chiodos pheromone relay alert review \
  --handoff-report "$GENERATED_DIR/relay-alert-handoff-report.json" \
  --delivery-report "$GENERATED_DIR/relay-alert-delivery-report.json" \
  --acknowledgement-report "$GENERATED_DIR/relay-alert-acknowledgement-report.json" \
  --drift-report "$GENERATED_DIR/relay-alert-delivery-drift-report-v2.json" \
  --route-owner-profile "$ASSURANCE_DIR/relay-alert-route-owner-profile.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-route-review-packet.json"
validate_schema "$SCHEMA_DIR/relay-alert-route-review-packet.schema.json" "$GENERATED_DIR/relay-alert-route-review-packet.json"

cargo run -p chio-cli -- chiodos pheromone relay alert assurance package \
  --alert-report "$GENERATED_DIR/relay-alert-report.json" \
  --trend-report "$GENERATED_DIR/relay-trend-report.json" \
  --handoff-report "$GENERATED_DIR/relay-alert-handoff-report.json" \
  --normalization-report "$GENERATED_DIR/relay-alert-normalization-report.json" \
  --delivery-report "$GENERATED_DIR/relay-alert-delivery-report.json" \
  --acknowledgement-report "$GENERATED_DIR/relay-alert-acknowledgement-report.json" \
  --drift-report "$GENERATED_DIR/relay-alert-delivery-drift-report-v2.json" \
  --review-packet "$GENERATED_DIR/relay-alert-route-review-packet.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-assurance-package.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-package.schema.json" "$GENERATED_DIR/relay-alert-assurance-package.json"

python3 - "$GENERATED_DIR" <<'PY'
import json
import pathlib
import sys

generated_dir = pathlib.Path(sys.argv[1])
normalization = json.loads((generated_dir / "relay-alert-normalization-report.json").read_text(encoding="utf-8"))
if normalization.get("accepted") is not True or normalization.get("normalizedCount") != 3:
    raise SystemExit("generated normalization report must normalize all downstream drops")
drift = json.loads((generated_dir / "relay-alert-delivery-drift-report-v2.json").read_text(encoding="utf-8"))
if drift.get("accepted") is not True or drift.get("driftCount") != 0:
    raise SystemExit("generated source-bound delivery drift report must be accepted")
assurance = json.loads((generated_dir / "relay-alert-assurance-package.json").read_text(encoding="utf-8"))
if assurance.get("accepted") is not False:
    raise SystemExit("generated assurance package must preserve unhealthy state")
if "active_alerts_present" not in assurance.get("operatorActionCodes", []):
    raise SystemExit("generated assurance package missing active-alert action")
print("OK generated relay alert assurance reports")
PY

cargo test -p chio-pheromone-relay alert_assurance --test relay
cargo test -p chio-cli --bin chio chiodos_pheromone_relay_alert_assurance

NEGATIVE_DIR="$(mktemp -d)"
TMP_DIRS+=("$NEGATIVE_DIR")
mkdir -p "$NEGATIVE_DIR/input" "$NEGATIVE_DIR/normalized"
cat >"$NEGATIVE_DIR/input/inline-token.json" <<'JSON'
{
  "receiverId": "alertmanager-pagerduty-primary",
  "alertCode": "dead_letters_present",
  "severity": "critical",
  "status": "delivered",
  "observedAtUnixMs": 1766000065000,
  "sourceHandoffReportSha256": "7c1d1ed0df1b7557e17c0c849313e14801382cf8d183f22e95d1139392b9f0e9",
  "apiToken": "not-allowed"
}
JSON
if cargo run -p chio-cli -- chiodos pheromone relay alert normalize \
  --profile "$ASSURANCE_DIR/relay-alert-normalization-profile.json" \
  --input-dir "$NEGATIVE_DIR/input" \
  --now-unix-ms "$NORMALIZE_UNIX_MS" \
  --out-dir "$NEGATIVE_DIR/normalized" \
  --report "$NEGATIVE_DIR/report.json" >/dev/null 2>&1; then
  echo "expected inline-token normalization negative to fail" >&2
  exit 1
fi

if [[ "$MODE" == "negative-only" ]]; then
  exit 0
fi

bash "$ROOT/scripts/check-chiodos-pheromone-relay-alert-delivery.sh" --schema-only
bash "$ROOT/scripts/check-chiodos-pheromone-relay-alert-handoff.sh" --schema-only
bash "$ROOT/scripts/check-chiodos-pheromone-relay-alert-routing.sh" --schema-only

pushd "$ROOT/crates/chio-cli/dashboard" >/dev/null
npm test -- RelayAlertAssuranceSummary api App
npm run build
popd >/dev/null
