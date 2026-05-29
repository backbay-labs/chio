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
    echo "usage: check-chio-pheromone-relay-alert-assurance-archive.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-pheromone-relay-alert-assurance-archive.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

SCHEMA_DIR="$ROOT/spec/schemas/chio-pheromone/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"
ASSURANCE_DIR="$ROOT/examples/chio-3vendor/fixtures/pheromone/relay/alert-assurance"
EXPORT_DIR="$ASSURANCE_DIR/export-bundle"
NOW_UNIX_MS=1766000100000
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
import sys

schema_dir, registry_path, fixture_dir = map(pathlib.Path, sys.argv[1:])
registry = json.loads(registry_path.read_text(encoding="utf-8"))
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
expected = {
    "chio.pheromone.relay-alert-assurance-archive-profile.v1": "relay-alert-assurance-archive-profile.schema.json",
    "chio.pheromone.relay-alert-assurance-archive-report.v1": "relay-alert-assurance-archive-report.schema.json",
    "chio.pheromone.relay-alert-assurance-closeout-profile.v1": "relay-alert-assurance-closeout-profile.schema.json",
    "chio.pheromone.relay-alert-assurance-closeout-report.v1": "relay-alert-assurance-closeout-report.schema.json",
    "chio.pheromone.relay-alert-assurance-archive-negative-fixture-corpus.v1": "relay-alert-assurance-archive-negative-fixture-corpus.schema.json",
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

negative = json.loads((fixture_dir / "relay-alert-assurance-archive-negative-cases.json").read_text(encoding="utf-8"))
case_ids = {case.get("caseId") for case in negative.get("cases", [])}
required = {
    "untrusted_exporter",
    "missing_file",
    "legal_hold_closeout",
    "wrong_expected_code",
}
missing = sorted(required - case_ids)
if missing:
    raise SystemExit(f"archive negative corpus missing cases: {missing}")
print("OK Chio relay alert assurance archive metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/relay-alert-assurance-archive-profile.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-archive-profile.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-closeout-profile.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-closeout-profile.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-archive-report.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-archive-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-closeout-report.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-closeout-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-archive-negative-fixture-corpus.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-archive-negative-cases.json"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

GENERATED_DIR="$(mktemp -d)"
TMP_DIRS+=("$GENERATED_DIR")
mkdir -p "$GENERATED_DIR/export-bundle"

cargo run -p chio-cli -- pheromone relay alert assurance export \
  --package "$ASSURANCE_DIR/relay-alert-assurance-package.json" \
  --alert-report "$ASSURANCE_DIR/relay-alert-report.json" \
  --trend-report "$ASSURANCE_DIR/relay-trend-report.json" \
  --handoff-report "$ASSURANCE_DIR/relay-alert-handoff-report.json" \
  --normalization-report "$ASSURANCE_DIR/relay-alert-normalization-report.json" \
  --delivery-report "$ASSURANCE_DIR/relay-alert-delivery-report.json" \
  --acknowledgement-report "$ASSURANCE_DIR/relay-alert-acknowledgement-report.json" \
  --drift-report "$ASSURANCE_DIR/relay-alert-delivery-drift-report.json" \
  --review-packet "$ASSURANCE_DIR/relay-alert-route-review-packet.json" \
  --retention-profile "$ASSURANCE_DIR/relay-alert-assurance-retention-profile.json" \
  --signing-key "$ASSURANCE_DIR/relay-alert-assurance-export-signing-key.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --out-dir "$GENERATED_DIR/export-bundle" \
  --report "$GENERATED_DIR/relay-alert-assurance-export-report.json"

cargo run -p chio-cli -- pheromone relay alert assurance archive plan \
  --bundle-root "$GENERATED_DIR/export-bundle" \
  --trusted-exporters "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" \
  --archive-profile "$ASSURANCE_DIR/relay-alert-assurance-archive-profile.json" \
  --retention-profile "$ASSURANCE_DIR/relay-alert-assurance-retention-profile.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-assurance-archive-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-archive-report.schema.json" "$GENERATED_DIR/relay-alert-assurance-archive-report.json"

cargo run -p chio-cli -- pheromone relay alert assurance closeout review \
  --bundle-root "$GENERATED_DIR/export-bundle" \
  --trusted-exporters "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" \
  --closeout-profile "$ASSURANCE_DIR/relay-alert-assurance-closeout-profile.json" \
  --retention-profile "$ASSURANCE_DIR/relay-alert-assurance-retention-profile.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-assurance-closeout-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-closeout-report.schema.json" "$GENERATED_DIR/relay-alert-assurance-closeout-report.json"

python3 - "$GENERATED_DIR" <<'PY'
import json
import pathlib
import sys

generated = pathlib.Path(sys.argv[1])
archive = json.loads((generated / "relay-alert-assurance-archive-report.json").read_text(encoding="utf-8"))
closeout = json.loads((generated / "relay-alert-assurance-closeout-report.json").read_text(encoding="utf-8"))
if archive.get("accepted") is not True or archive.get("archiveReadyCount") != 1:
    raise SystemExit("archive report must accept the verified export bundle")
if archive.get("reviews", [{}])[0].get("trustedExporterVerified") is not True:
    raise SystemExit("archive report must verify trusted exporter before retention claims")
if closeout.get("accepted") is not False:
    raise SystemExit("closeout report must remain blocked while legal hold is present")
if closeout.get("reviews", [{}])[0].get("code") != "legal_hold_blocked":
    raise SystemExit("closeout report must expose legal hold blocker")
print("OK generated relay alert assurance archive reports")
PY

cargo test -p chio-pheromone-relay alert_assurance_archive --test relay
cargo test -p chio-cli --bin chio chio_pheromone

NEGATIVE_DIR="$(mktemp -d)"
TMP_DIRS+=("$NEGATIVE_DIR")
cp -R "$GENERATED_DIR/export-bundle" "$NEGATIVE_DIR/missing-file-bundle"
rm "$NEGATIVE_DIR/missing-file-bundle/reports/relay-alert-report.json"
python3 - "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" "$NEGATIVE_DIR/untrusted-exporters.json" <<'PY'
import json
import pathlib
import sys

trusted_path, untrusted_path = map(pathlib.Path, sys.argv[1:])
trusted = json.loads(trusted_path.read_text(encoding="utf-8"))
trusted["exporters"][0]["publicKey"] = "0" * 64
untrusted_path.write_text(json.dumps(trusted, indent=2) + "\n", encoding="utf-8")
PY

cargo run -p chio-cli -- pheromone relay alert assurance archive plan \
  --bundle-root "$GENERATED_DIR/export-bundle" \
  --trusted-exporters "$NEGATIVE_DIR/untrusted-exporters.json" \
  --archive-profile "$ASSURANCE_DIR/relay-alert-assurance-archive-profile.json" \
  --retention-profile "$ASSURANCE_DIR/relay-alert-assurance-retention-profile.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$NEGATIVE_DIR/untrusted-archive-report.json"

cargo run -p chio-cli -- pheromone relay alert assurance archive plan \
  --bundle-root "$NEGATIVE_DIR/missing-file-bundle" \
  --trusted-exporters "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" \
  --archive-profile "$ASSURANCE_DIR/relay-alert-assurance-archive-profile.json" \
  --retention-profile "$ASSURANCE_DIR/relay-alert-assurance-retention-profile.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$NEGATIVE_DIR/missing-file-archive-report.json"

python3 - "$NEGATIVE_DIR" "$GENERATED_DIR/relay-alert-assurance-closeout-report.json" <<'PY'
import json
import pathlib
import sys

negative_dir = pathlib.Path(sys.argv[1])
closeout_path = pathlib.Path(sys.argv[2])
untrusted = json.loads((negative_dir / "untrusted-archive-report.json").read_text(encoding="utf-8"))
missing = json.loads((negative_dir / "missing-file-archive-report.json").read_text(encoding="utf-8"))
closeout = json.loads(closeout_path.read_text(encoding="utf-8"))
actual = {
    "untrusted_exporter": untrusted["reviews"][0]["code"],
    "missing_file": missing["reviews"][0]["code"],
    "legal_hold_closeout": closeout["reviews"][0]["code"],
}
expected = {
    "untrusted_exporter": "signature_invalid",
    "missing_file": "bundle_read_failed",
    "legal_hold_closeout": "legal_hold_blocked",
}
for case_id, code in expected.items():
    if actual.get(case_id) != code:
        raise SystemExit(f"{case_id} expected {code}, got {actual.get(case_id)}")
if actual["untrusted_exporter"] == "body_hash_mismatch":
    raise SystemExit("wrong expected code detector did not trip")
print("OK relay alert assurance archive negative cases")
PY

if [[ "$MODE" == "negative-only" ]]; then
  exit 0
fi

bash "$ROOT/scripts/check-chio-pheromone-relay-alert-assurance-export.sh" --schema-only
