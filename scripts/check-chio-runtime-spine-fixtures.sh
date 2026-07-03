#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

FIXTURE_DIR="$ROOT/examples/chio-3vendor/fixtures/runtime-spine"
SCHEMA_DIR="$ROOT/spec/schemas/chio-runtime/v1"
PHEROMONE_SCHEMA_DIR="$ROOT/spec/schemas/chio-pheromone/v1"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

run_spec_validate() {
  if [[ -n "${CHIO_SPEC_VALIDATE_BIN:-}" ]]; then
    "$CHIO_SPEC_VALIDATE_BIN" "$@"
  else
    cargo run -p chio-spec-validate -- "$@"
  fi
}

validate_schema() {
  run_spec_validate "$1" "$2" >/dev/null
}

python3 - "$FIXTURE_DIR" "$tmpdir" <<'PY'
import json
import pathlib
import sys

fixture_dir = pathlib.Path(sys.argv[1])
tmpdir = pathlib.Path(sys.argv[2])


def load(name):
    return json.loads((fixture_dir / name).read_text(encoding="utf-8"))


def write_json(name, value):
    path = tmpdir / name
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def signed_body(name, output_name):
    body = load(name)
    if body.get("peerWeightsSha256") == "PEER_WEIGHTS_SHA256":
        body["peerWeightsSha256"] = "e" * 64
    write_json(
        output_name,
        {
            "body": body,
            "signerKey": "a" * 64,
            "signature": "b" * 128,
        },
    )


signed_body("runtime-trust-body.json", "runtime-trust-body.signed.json")
signed_body("runtime-peer-weights-body.json", "runtime-peer-weights-body.signed.json")
signed_body("runtime-policy-body.json", "runtime-policy-body.signed.json")

scenario = load("scenario.json")
for index, step in enumerate(scenario.get("steps", [])):
    profile = step.get("admissionProfile", {})
    bundle = step.get("admissionBundle", {})
    if profile.get("schema") != "chio.runtime.admission-profile.v1":
        raise SystemExit(f"scenario step {index} admission profile is not Chio-native")
    if bundle.get("schema") != "chio.runtime.admission-bundle.v1":
        raise SystemExit(f"scenario step {index} admission bundle is not Chio-native")
PY

validate_schema "$SCHEMA_DIR/admission-profile.schema.json" \
  "$FIXTURE_DIR/profile.json"
validate_schema "$SCHEMA_DIR/admission-bundle.schema.json" \
  "$FIXTURE_DIR/bundle.json"
validate_schema "$SCHEMA_DIR/verifier-trust-bundle.schema.json" \
  "$FIXTURE_DIR/runtime-trust-schema-only.json"
validate_schema "$SCHEMA_DIR/trusted-verifiers.schema.json" \
  "$FIXTURE_DIR/trusted-verifiers-schema-only.json"
validate_schema "$SCHEMA_DIR/verifier-trust-bundle.schema.json" \
  "$tmpdir/runtime-trust-body.signed.json"
validate_schema "$SCHEMA_DIR/peer-weights.schema.json" \
  "$tmpdir/runtime-peer-weights-body.signed.json"
validate_schema "$SCHEMA_DIR/pheromone-policy.schema.json" \
  "$tmpdir/runtime-policy-body.signed.json"
validate_schema "$PHEROMONE_SCHEMA_DIR/query-report.schema.json" \
  "$FIXTURE_DIR/pheromone-query-report.json"
validate_schema "$SCHEMA_DIR/step-evidence.schema.json" \
  "$FIXTURE_DIR/runtime-step-evidence.json"
validate_schema "$SCHEMA_DIR/evidence-manifest.schema.json" \
  "$FIXTURE_DIR/runtime-evidence-manifest.json"
validate_schema "$SCHEMA_DIR/proof-regeneration-input.schema.json" \
  "$FIXTURE_DIR/runtime-proof-regeneration-input.json"
validate_schema "$SCHEMA_DIR/proof-regeneration-report.schema.json" \
  "$FIXTURE_DIR/runtime-proof-regeneration-report.json"
validate_schema "$SCHEMA_DIR/proof-parity-report.schema.json" \
  "$FIXTURE_DIR/runtime-proof-parity-report.json"
