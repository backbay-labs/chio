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
    echo "usage: check-chiodos-pheromone-relay-alert-assurance-export.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chiodos-pheromone-relay-alert-assurance-export.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

SCHEMA_DIR="$ROOT/spec/schemas/chio-pheromone/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"
FIXTURE_DIR="$ROOT/examples/chiodos-3vendor/fixtures/pheromone/relay"
ASSURANCE_DIR="$FIXTURE_DIR/alert-assurance"
EXPORT_DIR="$ASSURANCE_DIR/export-bundle"
NOW_UNIX_MS=1766000100000
TMP_DIRS=()
cleanup() {
  if [[ ${#TMP_DIRS[@]} -gt 0 ]]; then
    rm -rf "${TMP_DIRS[@]}"
  fi
}
trap cleanup EXIT

python3 - "$SCHEMA_DIR" "$SCHEMA_REGISTRY" "$ASSURANCE_DIR" "$EXPORT_DIR" <<'PY'
import json
import pathlib
import re
import sys

schema_dir, registry_path, fixture_dir, export_dir = map(pathlib.Path, sys.argv[1:])
registry = json.loads(registry_path.read_text(encoding="utf-8"))
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
expected = {
    "chio.pheromone.relay-alert-assurance-export-manifest.v1": "relay-alert-assurance-export-manifest.schema.json",
    "chio.pheromone.relay-alert-assurance-export-report.v1": "relay-alert-assurance-export-report.schema.json",
    "chio.pheromone.relay-alert-assurance-trusted-exporters.v1": "relay-alert-assurance-trusted-exporters.schema.json",
    "chio.pheromone.relay-alert-assurance-replay-report.v1": "relay-alert-assurance-replay-report.schema.json",
    "chio.pheromone.relay-alert-assurance-retention-profile.v1": "relay-alert-assurance-retention-profile.schema.json",
    "chio.pheromone.relay-alert-assurance-retention-report.v1": "relay-alert-assurance-retention-report.schema.json",
    "chio.pheromone.relay-alert-assurance-recovery-drill-report.v1": "relay-alert-assurance-recovery-drill-report.schema.json",
    "chio.pheromone.relay-alert-assurance-export-negative-fixture-corpus.v1": "relay-alert-assurance-export-negative-fixture-corpus.schema.json",
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

manifest = json.loads((export_dir / "manifest.json").read_text(encoding="utf-8"))
if manifest.get("schema") != "chio.pheromone.relay-alert-assurance-export-manifest.v1":
    raise SystemExit("export manifest schema mismatch")
body = manifest.get("body", {})
if not re.fullmatch(r"[0-9a-f]{64}", body.get("sourcePackageSha256", "")):
    raise SystemExit("export manifest source package hash is malformed")
for claim in body.get("safetyClaims", []):
    if claim in {"live_notification_delivery", "credentialed_dispatch"}:
        raise SystemExit("export manifest claims live notification delivery")
secret_re = re.compile(r"(?i)(token|secret|password|bearer|api[_-]?key)")
for artifact in body.get("artifacts", []):
    path = artifact.get("path", "")
    if path.startswith("/") or ".." in path or "\\" in path or ":" in path:
        raise SystemExit(f"unsafe export artifact path: {path}")
    if secret_re.search(json.dumps(artifact)):
        raise SystemExit(f"export manifest artifact contains secret marker: {artifact.get('role')}")

negative = json.loads((fixture_dir / "relay-alert-assurance-export-negative-cases.json").read_text(encoding="utf-8"))
case_ids = {case.get("caseId") for case in negative.get("cases", [])}
required = {
    "invalid_signature",
    "source_hash_mismatch",
    "path_traversal",
    "wrong_expected_code",
}
missing = sorted(required - case_ids)
if missing:
    raise SystemExit(f"export negative corpus missing cases: {missing}")
print("OK Chiodos relay alert assurance export metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/relay-alert-assurance-export-manifest.schema.json" "$EXPORT_DIR/manifest.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-export-report.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-export-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-export-report.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-export-verify-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-trusted-exporters.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-replay-report.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-replay-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-retention-profile.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-retention-profile.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-retention-report.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-retention-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-recovery-drill-report.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-recovery-drill-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-export-negative-fixture-corpus.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-export-negative-cases.json"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

GENERATED_DIR="$(mktemp -d)"
TMP_DIRS+=("$GENERATED_DIR")
mkdir -p "$GENERATED_DIR/export-bundle"

cargo run -p chio-cli -- chiodos pheromone relay alert assurance export \
  --package "$ASSURANCE_DIR/relay-alert-assurance-package.json" \
  --alert-report "$ASSURANCE_DIR/relay-alert-report.json" \
  --trend-report "$ASSURANCE_DIR/relay-trend-report.json" \
  --handoff-report "$ASSURANCE_DIR/relay-alert-handoff-report.json" \
  --normalization-report "$ASSURANCE_DIR/relay-alert-normalization-report.json" \
  --delivery-report "$ASSURANCE_DIR/relay-alert-delivery-report.json" \
  --acknowledgement-report "$ASSURANCE_DIR/relay-alert-acknowledgement-report.json" \
  --drift-report "$ASSURANCE_DIR/relay-alert-delivery-drift-report-v2.json" \
  --review-packet "$ASSURANCE_DIR/relay-alert-route-review-packet.json" \
  --retention-profile "$ASSURANCE_DIR/relay-alert-assurance-retention-profile.json" \
  --signing-key "$ASSURANCE_DIR/relay-alert-assurance-export-signing-key.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --out-dir "$GENERATED_DIR/export-bundle" \
  --report "$GENERATED_DIR/relay-alert-assurance-export-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-export-manifest.schema.json" "$GENERATED_DIR/export-bundle/manifest.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-export-report.schema.json" "$GENERATED_DIR/relay-alert-assurance-export-report.json"

cargo run -p chio-cli -- chiodos pheromone relay alert assurance verify \
  --bundle-dir "$GENERATED_DIR/export-bundle" \
  --trusted-exporters "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-assurance-export-verify-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-export-report.schema.json" "$GENERATED_DIR/relay-alert-assurance-export-verify-report.json"

cargo run -p chio-cli -- chiodos pheromone relay alert assurance replay \
  --bundle-dir "$GENERATED_DIR/export-bundle" \
  --trusted-exporters "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-assurance-replay-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-replay-report.schema.json" "$GENERATED_DIR/relay-alert-assurance-replay-report.json"

cargo run -p chio-cli -- chiodos pheromone relay alert assurance retention plan \
  --bundle-root "$GENERATED_DIR/export-bundle" \
  --retention-profile "$ASSURANCE_DIR/relay-alert-assurance-retention-profile.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-assurance-retention-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-retention-report.schema.json" "$GENERATED_DIR/relay-alert-assurance-retention-report.json"

cargo run -p chio-cli -- chiodos pheromone relay alert assurance recovery-drill \
  --bundle-dir "$GENERATED_DIR/export-bundle" \
  --trusted-exporters "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" \
  --case all \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-assurance-recovery-drill-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-recovery-drill-report.schema.json" "$GENERATED_DIR/relay-alert-assurance-recovery-drill-report.json"

python3 - "$GENERATED_DIR" <<'PY'
import json
import pathlib
import sys

generated = pathlib.Path(sys.argv[1])
verify = json.loads((generated / "relay-alert-assurance-export-verify-report.json").read_text(encoding="utf-8"))
replay = json.loads((generated / "relay-alert-assurance-replay-report.json").read_text(encoding="utf-8"))
retention = json.loads((generated / "relay-alert-assurance-retention-report.json").read_text(encoding="utf-8"))
drill = json.loads((generated / "relay-alert-assurance-recovery-drill-report.json").read_text(encoding="utf-8"))
if verify.get("accepted") is not True:
    raise SystemExit("generated export verify report must be accepted")
if replay.get("accepted") is not True or replay.get("sourcePackageSha256") != replay.get("replayedPackageSha256"):
    raise SystemExit("generated replay report must reproduce source package hash")
if not any(entry.get("state") == "blocked" and entry.get("artifactRole") == "assurance_package" for entry in retention.get("entries", [])):
    raise SystemExit("retention report must block assurance package pruning")
if "bad_export_signature" not in {case.get("caseId") for case in drill.get("drills", [])}:
    raise SystemExit("recovery drill report missing bad export signature case")
print("OK generated relay alert assurance export reports")
PY

cargo test -p chio-pheromone-relay alert_assurance_export --test relay
cargo test -p chio-cli --bin chio chiodos_pheromone_relay_alert_assurance

NEGATIVE_DIR="$(mktemp -d)"
TMP_DIRS+=("$NEGATIVE_DIR")
cp -R "$GENERATED_DIR/export-bundle" "$NEGATIVE_DIR/tampered-bundle"
python3 - "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" "$NEGATIVE_DIR/untrusted-exporters.json" "$NEGATIVE_DIR/tampered-bundle" <<'PY'
import json
import pathlib
import sys

trusted_path, untrusted_path, tampered_dir = map(pathlib.Path, sys.argv[1:])
trusted = json.loads(trusted_path.read_text(encoding="utf-8"))
trusted["exporters"][0]["publicKey"] = "0" * 64
untrusted_path.write_text(json.dumps(trusted, indent=2) + "\n", encoding="utf-8")
target = tampered_dir / "reports" / "relay-alert-report.json"
target.write_bytes(target.read_bytes() + b"\n")
PY

if cargo run -p chio-cli -- chiodos pheromone relay alert assurance verify \
  --bundle-dir "$GENERATED_DIR/export-bundle" \
  --trusted-exporters "$NEGATIVE_DIR/untrusted-exporters.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$NEGATIVE_DIR/untrusted-report.json" 2>"$NEGATIVE_DIR/untrusted.err"; then
  echo "expected untrusted exporter negative to fail" >&2
  exit 1
fi
if ! grep -q "signature_invalid" "$NEGATIVE_DIR/untrusted.err"; then
  echo "untrusted exporter negative did not report signature_invalid" >&2
  exit 1
fi

if cargo run -p chio-cli -- chiodos pheromone relay alert assurance verify \
  --bundle-dir "$NEGATIVE_DIR/tampered-bundle" \
  --trusted-exporters "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$NEGATIVE_DIR/tampered-report.json" 2>"$NEGATIVE_DIR/tampered.err"; then
  echo "expected tampered bundle negative to fail" >&2
  exit 1
fi
if ! grep -q "body_hash_mismatch" "$NEGATIVE_DIR/tampered.err"; then
  echo "tampered bundle negative did not report body_hash_mismatch" >&2
  exit 1
fi

if [[ "$MODE" == "negative-only" ]]; then
  exit 0
fi

bash "$ROOT/scripts/check-chiodos-pheromone-relay-alert-assurance.sh" --schema-only
