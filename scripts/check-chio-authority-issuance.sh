#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SCHEMA_DIR="$ROOT/spec/schemas/chio-federation/v1"
PACKAGE_FIXTURE="$ROOT/examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
TRUST_BUNDLE_FIXTURE="$ROOT/examples/chio-3vendor/fixtures/verifier-trust-bundle.json"
CONTEXT_FIXTURE="$ROOT/examples/chio-3vendor/fixtures/verification-context.json"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cargo test -p chio-federation-authority
cargo run -p chio-three-vendor-example --bin generate-chio-three-vendor-fixtures -- \
  --authority-input-package "$PACKAGE_FIXTURE" "$tmpdir/input"

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/authority-profile.schema.json" "$tmpdir/input/authority-profile.json"
validate_schema "$SCHEMA_DIR/issuance-request.schema.json" "$tmpdir/input/issuance-request.json"
validate_schema "$SCHEMA_DIR/local-signing-keys.schema.json" "$tmpdir/input/local-signing-keys.json"
validate_schema "$SCHEMA_DIR/peer-pins.schema.json" "$tmpdir/input/peer-pins.json"
validate_schema "$SCHEMA_DIR/revocation-publication-request.schema.json" \
  "$tmpdir/input/revocation-publication-request.json"

cargo run -p chio-cli -- federation authority issue \
  --profile "$tmpdir/input/authority-profile.json" \
  --request "$tmpdir/input/issuance-request.json" \
  --signing-keys "$tmpdir/input/local-signing-keys.json" \
  --out-dir "$tmpdir/issued"
validate_schema "$SCHEMA_DIR/issuance-bundle.schema.json" "$tmpdir/issued/issuance-bundle.json"

cargo run -p chio-cli -- federation authority checkpoint \
  --profile "$tmpdir/input/authority-profile.json" \
  --revocations "$tmpdir/input/revocation-publication-request.json" \
  --signing-keys "$tmpdir/input/local-signing-keys.json" \
  --out "$tmpdir/revocation-checkpoint.json"
python3 - "$tmpdir/revocation-checkpoint.json" "$tmpdir/revocation-checkpoint-body.json" <<'PY'
import json
import sys

source_path, output_path = sys.argv[1:]
with open(source_path, "r", encoding="utf-8") as handle:
    checkpoint = json.load(handle)
if not isinstance(checkpoint.get("body"), dict):
    raise SystemExit("signed revocation checkpoint is missing body")
for field in ("signerKey", "signature"):
    if not checkpoint.get(field):
        raise SystemExit(f"signed revocation checkpoint is missing {field}")
with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(checkpoint["body"], handle, sort_keys=True, indent=2)
    handle.write("\n")
PY
validate_schema "$SCHEMA_DIR/revocation-checkpoint.schema.json" "$tmpdir/revocation-checkpoint-body.json"

cargo run -p chio-cli -- federation authority trust-bundle assemble \
  --profile "$tmpdir/input/authority-profile.json" \
  --peer-pins "$tmpdir/input/peer-pins.json" \
  --workflow-intersection "$tmpdir/input/workflow-intersection.json" \
  --disclosure-policy "$tmpdir/input/disclosure-policy.json" \
  --checkpoint "$tmpdir/revocation-checkpoint.json" \
  --out "$tmpdir/verifier-trust-bundle.json"
validate_schema "$SCHEMA_DIR/verifier-trust-bundle.schema.json" "$tmpdir/verifier-trust-bundle.json"

python3 - "$PACKAGE_FIXTURE" "$TRUST_BUNDLE_FIXTURE" "$CONTEXT_FIXTURE" "$tmpdir" <<'PY'
import json
import pathlib
import sys

package_path, trust_bundle_path, context_path, tmpdir = sys.argv[1:]
tmp = pathlib.Path(tmpdir)
with open(package_path, "r", encoding="utf-8") as handle:
    package = json.load(handle)
with open(trust_bundle_path, "r", encoding="utf-8") as handle:
    committed_trust_bundle = json.load(handle)
with open(context_path, "r", encoding="utf-8") as handle:
    committed_context = json.load(handle)
with (tmp / "issued" / "issuance-bundle.json").open("r", encoding="utf-8") as handle:
    issued = json.load(handle)
with (tmp / "verifier-trust-bundle.json").open("r", encoding="utf-8") as handle:
    assembled_trust_bundle = json.load(handle)

if issued.get("capabilityLeases") != package.get("capabilityLeases"):
    raise SystemExit("runtime-issued capability leases differ from proof package")
if issued.get("leaseScopeBindings") != package.get("leaseScopeBindings"):
    raise SystemExit("runtime-issued lease scope bindings differ from proof package")
if issued.get("governanceReceipts") != package.get("governanceReceipts"):
    raise SystemExit("runtime-issued governance receipts differ from proof package")
if issued.get("verificationContext") != committed_context:
    raise SystemExit("runtime-issued verification context differs from committed context")
if assembled_trust_bundle != committed_trust_bundle:
    raise SystemExit("assembled verifier trust bundle differs from committed fixture")
if "workflow.grant_issue" not in {
    entry.get("actionClassId") for entry in assembled_trust_bundle.get("actionClasses", [])
}:
    raise SystemExit("assembled trust bundle is missing workflow grant class")
if "workflow.aggregate_publish" not in {
    entry.get("actionClassId") for entry in assembled_trust_bundle.get("actionClasses", [])
}:
    raise SystemExit("assembled trust bundle is missing workflow aggregate class")
print("OK Chio federation authority issuance artifacts")
PY

cargo run -p chio-cli -- attest buyer verify-proof \
  --package "$PACKAGE_FIXTURE" \
  --trust-bundle "$tmpdir/verifier-trust-bundle.json" \
  --context "$tmpdir/issued/verification-context.json" \
  --report "$tmpdir/verifier-report.json"
