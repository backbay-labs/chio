#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
lint="${repo_root}/scripts/check-chio-proof-room-release-truth.sh"
work="$(mktemp -d -t chio-release-truth-XXXXXX)"
trap 'rm -rf "$work"' EXIT
truth="$work/release-truth.json"
bundle_truth="$work/bundle-release-truth.json"

cat > "$truth" <<'EOF'
{
  "schema": "chio.proof.release-truth.v1",
  "id": "test-release-truth",
  "truth": {
    "public_release": false,
    "package_published": false,
    "docker_quickstart": false,
    "hosted_demo": false,
    "chain_evidence": false,
    "transparency_log": false
  },
  "allowed_copy": [
    "local fixture proof"
  ]
}
EOF
cp "$truth" "$bundle_truth"

cat > "$work/pass.md" <<'EOF'
The Docker quickstart command is present for local review, but release truth
marks Docker quickstart evidence unavailable until a Docker daemon run is
captured by release qualification.
EOF

cat > "$work/fail.md" <<'EOF'
The Docker quickstart is release-qualified for public proof.
EOF

cat > "$work/mixed-negation-fail.md" <<'EOF'
Docker quickstart evidence is not captured; the Docker image is published.
EOF

cat > "$work/launch-copy-fail.md" <<'EOF'
Chio has ACP support and makes x402 a universal Chio authority for every action.
EOF

mkdir -p "$work/json-docs"
cat > "$work/json-docs/standards.json" <<'EOF'
{
  "summary": "Chio ships ACP authority."
}
EOF

cat > "$work/hedged-launch-copy-fail.md" <<'EOF'
Chio ships autonomous insurer pricing, but not as a regulated insurer.
EOF

cat > "$work/autonomous-insurer-fail.md" <<'EOF'
Chio is an autonomous insurer.
Chio operates autonomous insurance for agent commerce.
EOF

cat > "$work/enterprise-overclaim-fail.md" <<'EOF'
Chio automatically propagates enterprise identity into every artifact.
Chio proves enterprise compliance automatically for governed workflows.
EOF

cat > "$work/hedged-stop-pattern-fail.md" <<'EOF'
Chio does not yet support public release claims, but x402 is universal authority for Chio actions.
EOF

cat > "$work/rejected-standards-fail.md" <<'EOF'
Chio is the universal agent protocol.
Every external agent protocol natively verifies Chio authority.
A2A task evidence is bound for version v0.3.0.
Chio provides OpenAPI 3.2 support.
SLSA v1.1 is the current source.
Sigstore proves runtime authorization.
A webhook signature proves Chio authorization.
OAuth tokens are Chio capabilities.
SPIFFE delegates agent authority.
Kubernetes admission proves business transaction authority.
OCI tags are trusted artifact references.
EOF

cat > "$work/generic-universal-protocol-fail.md" <<'EOF'
Chio is the universal protocol for autonomous agents.
Chio ships a universal-protocol bridge for all agent systems.
EOF

cat > "$work/chain-authority-overclaim-fail.md" <<'EOF'
On-chain evidence proves Chio settlement authority.
Chain evidence authorizes Chio settlement release decisions.
EOF

if ! grep -Fq '"spec/PROTOCOL.md"' "$lint"; then
  echo "release truth default docs do not include spec/PROTOCOL.md" >&2
  exit 1
fi

if ! grep -Fq '"docs"' "$lint"; then
  echo "release truth default docs do not include recursive docs" >&2
  exit 1
fi

CHIO_PROOF_ROOM_RELEASE_TRUTH="$truth" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$bundle_truth" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/pass.md" \
  "$lint"

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$truth" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$bundle_truth" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/fail.md" \
  "$lint" >"$work/fail.out" 2>&1; then
  echo "docker quickstart release claim accepted while release truth is false" >&2
  exit 1
fi
grep -q "proof-room.release.unavailable: docker_quickstart" "$work/fail.out"

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$truth" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$bundle_truth" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/mixed-negation-fail.md" \
  "$lint" >"$work/mixed-negation-fail.out" 2>&1; then
  echo "docker quickstart release claim accepted next to unrelated negation" >&2
  exit 1
fi
grep -q "proof-room.release.unavailable: docker_quickstart" "$work/mixed-negation-fail.out"

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$truth" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$bundle_truth" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/launch-copy-fail.md" \
  "$lint" >"$work/launch-copy-fail.out" 2>&1; then
  echo "launch copy overclaims unexpectedly passed" >&2
  exit 1
fi
grep -q "proof-room.release.copy-forbidden: bare_acp" "$work/launch-copy-fail.out"
grep -q "proof-room.release.copy-forbidden: ambient_external_authority" "$work/launch-copy-fail.out"
grep -q "proof-room.release.copy-forbidden: every_action_overclaim" "$work/launch-copy-fail.out"

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$truth" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$bundle_truth" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/json-docs" \
  "$lint" >"$work/json-standards-fail.out" 2>&1; then
  echo "JSON standards overclaims unexpectedly passed" >&2
  exit 1
fi
grep -q "proof-room.release.copy-forbidden: bare_acp" "$work/json-standards-fail.out"

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$truth" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$bundle_truth" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/hedged-launch-copy-fail.md" \
  "$lint" >"$work/hedged-launch-copy-fail.out" 2>&1; then
  echo "hedged launch copy overclaim unexpectedly passed" >&2
  exit 1
fi
grep -q "proof-room.release.copy-forbidden: insurance_pricing_overclaim" "$work/hedged-launch-copy-fail.out"

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$truth" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$bundle_truth" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/autonomous-insurer-fail.md" \
  "$lint" >"$work/autonomous-insurer-fail.out" 2>&1; then
  echo "autonomous insurer overclaim unexpectedly passed" >&2
  exit 1
fi
grep -q "proof-room.release.copy-forbidden: autonomous_insurer_overclaim" "$work/autonomous-insurer-fail.out"

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$truth" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$bundle_truth" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/enterprise-overclaim-fail.md" \
  "$lint" >"$work/enterprise-overclaim-fail.out" 2>&1; then
  echo "enterprise overclaim unexpectedly passed" >&2
  exit 1
fi
grep -q "proof-room.release.copy-forbidden: enterprise_overclaim" \
  "$work/enterprise-overclaim-fail.out"

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$truth" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$bundle_truth" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/hedged-stop-pattern-fail.md" \
  "$lint" >"$work/hedged-stop-pattern-fail.out" 2>&1; then
  echo "hedged ambient-authority overclaim unexpectedly passed" >&2
  exit 1
fi
grep -q "proof-room.release.copy-forbidden: ambient_external_authority" "$work/hedged-stop-pattern-fail.out"

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$truth" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$bundle_truth" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/rejected-standards-fail.md" \
  "$lint" >"$work/rejected-standards-fail.out" 2>&1; then
  echo "rejected standards overclaims unexpectedly passed" >&2
  exit 1
fi
grep -q "proof-room.release.copy-forbidden: universal_protocol_overclaim" "$work/rejected-standards-fail.out"
grep -q "proof-room.release.copy-forbidden: native_external_authority_overclaim" "$work/rejected-standards-fail.out"
grep -q "proof-room.release.copy-forbidden: stale_a2a_version" "$work/rejected-standards-fail.out"
grep -q "proof-room.release.copy-forbidden: unsupported_openapi_32" "$work/rejected-standards-fail.out"
grep -q "proof-room.release.copy-forbidden: stale_slsa_version" "$work/rejected-standards-fail.out"
grep -q "proof-room.release.copy-forbidden: sigstore_runtime_authority" "$work/rejected-standards-fail.out"
grep -q "proof-room.release.copy-forbidden: webhook_signature_authority" "$work/rejected-standards-fail.out"
grep -q "proof-room.release.copy-forbidden: oauth_token_capability" "$work/rejected-standards-fail.out"
grep -q "proof-room.release.copy-forbidden: spiffe_agent_authority" "$work/rejected-standards-fail.out"
grep -q "proof-room.release.copy-forbidden: kubernetes_business_authority" "$work/rejected-standards-fail.out"
grep -q "proof-room.release.copy-forbidden: oci_tag_trust" "$work/rejected-standards-fail.out"

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$truth" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$bundle_truth" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/generic-universal-protocol-fail.md" \
  "$lint" >"$work/generic-universal-protocol-fail.out" 2>&1; then
  echo "generic universal protocol overclaims unexpectedly passed" >&2
  exit 1
fi
grep -q "proof-room.release.copy-forbidden: universal_protocol_overclaim" \
  "$work/generic-universal-protocol-fail.out"

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$truth" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$bundle_truth" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/chain-authority-overclaim-fail.md" \
  "$lint" >"$work/chain-authority-overclaim-fail.out" 2>&1; then
  echo "chain-evidence authority overclaims unexpectedly passed" >&2
  exit 1
fi
grep -q "proof-room.release.copy-forbidden: chain_evidence_authority" \
  "$work/chain-authority-overclaim-fail.out"

grep -q \
  "Chio settlement authority comes from signed Chio receipts" \
  "$repo_root/docs/standards/CHIO_SETTLE_PROFILE.md"
grep -q \
  "Chain evidence is subordinate observation" \
  "$repo_root/docs/standards/CHIO_SETTLE_PROFILE.md"

cp "$truth" "$work/release-truth-extra-field.json"
python3 - "$work/release-truth-extra-field.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    truth = json.load(handle)
truth["hosted_demo_url"] = "https://example.invalid/proof-room"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(truth, handle, indent=2)
    handle.write("\n")
PY
cp "$work/release-truth-extra-field.json" "$work/bundle-release-truth-extra-field.json"

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$work/release-truth-extra-field.json" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$work/bundle-release-truth-extra-field.json" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/pass.md" \
  "$lint" >"$work/release-truth-schema-invalid.out" 2>&1; then
  echo "release truth accepted schema-forbidden fields" >&2
  exit 1
fi
grep -q \
  "proof-room.release.truth-schema-invalid" \
  "$work/release-truth-schema-invalid.out"

mkdir -p "$work/bundle/artifacts/release"
docker_bundle_release_truth="$work/bundle/artifacts/release/release-truth.json"
cat > "$work/docker-release-truth.json" <<'EOF'
{
  "schema": "chio.proof.release-truth.v1",
  "id": "test-release-truth",
  "truth": {
    "public_release": false,
    "package_published": false,
    "docker_quickstart": true,
    "hosted_demo": false,
    "chain_evidence": false,
    "transparency_log": false
  },
  "allowed_copy": [
    "Docker quickstart runtime smoke"
  ]
}
EOF
cp "$work/docker-release-truth.json" "$docker_bundle_release_truth"

cat > "$work/bundle/artifacts/release/docker-quickstart-evidence.json" <<'EOF'
{
  "schema": "chio.proof.docker-quickstart-evidence.v1",
  "id": "proof-room-docker-quickstart-test",
  "verdict": "verified",
  "target": "chio-proof-room-quickstart",
  "dockerfile": "deploy/docker/Dockerfile",
  "image_ref": "chio-proof-room:local",
  "server_binary": "/usr/local/bin/chio-proof-room",
  "bundle_path": "/opt/chio/fixtures/proof-room/first-run/single-call-authority/proof-room-bundle",
  "fixture_root": "/opt/chio/fixtures/proof-room",
  "doctor_report_path": "/opt/chio/proof-doctor-report.json",
  "evidence_source": "scripts/check-chio-proof-room-docker-quickstart.sh",
  "endpoints": [
    {
      "path": "/manifest.json",
      "expected": "chio.proof-room.bundle.v1"
    },
    {
      "path": "/ui/proof-room-static/load-report.json",
      "expected": "chio.proof-room.verifier-report.v1"
    },
    {
      "path": "/proof-room-fixture-catalog.json",
      "expected": "chio.proof-room.fixture-catalog.v1"
    },
    {
      "path": "/proof-room-fixtures/minimal-passport-valid/verifier-report.json",
      "expected": "chio.transaction.verifier-report.v1"
    },
    {
      "path": "/proof-room-fixtures/minimal-passport-valid/transaction-passport.json",
      "expected": "passport-minimal-valid"
    },
    {
      "path": "/proof-room-fixtures/commerce-offline-psp/verifier-report.json",
      "expected": "chio.commerce.order-passport.v1"
    },
    {
      "path": "/?view=proof-room",
      "expected": "Chio"
    }
  ]
}
EOF
cp \
  "$work/bundle/artifacts/release/docker-quickstart-evidence.json" \
  "$work/docker-quickstart-evidence.valid.json"

write_bundle_manifest() {
  docker_evidence_sha="$(
    python3 - "$work/bundle/artifacts/release/docker-quickstart-evidence.json" <<'PY'
import hashlib
import sys

with open(sys.argv[1], "rb") as handle:
    print(hashlib.sha256(handle.read()).hexdigest())
PY
  )"
  release_truth_sha="$(
    python3 - "$docker_bundle_release_truth" <<'PY'
import hashlib
import sys

with open(sys.argv[1], "rb") as handle:
    print(hashlib.sha256(handle.read()).hexdigest())
PY
  )"
  python3 - \
    "$repo_root/fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/manifest.json" \
    "$work/bundle/manifest.json" \
    "$docker_evidence_sha" \
    "$release_truth_sha" <<'PY'
import json
import sys

source, out, docker_evidence_sha, release_truth_sha = sys.argv[1:5]
with open(source, encoding="utf-8") as handle:
    manifest = json.load(handle)
bound_docker_evidence = False
bound_release_truth = False
for artifact in manifest["artifacts"]:
    if artifact["path"] == "artifacts/release/docker-quickstart-evidence.json":
        artifact["sha256"] = docker_evidence_sha
        bound_docker_evidence = True
    if artifact["path"] == "artifacts/release/release-truth.json":
        artifact["sha256"] = release_truth_sha
        bound_release_truth = True
if not bound_docker_evidence:
    raise SystemExit("test fixture manifest does not bind Docker evidence")
if not bound_release_truth:
    raise SystemExit("test fixture manifest does not bind release truth")
with open(out, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2)
    handle.write("\n")
PY
}

write_bundle_manifest

CHIO_PROOF_ROOM_RELEASE_TRUTH="$work/docker-release-truth.json" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$docker_bundle_release_truth" \
  CHIO_PROOF_ROOM_BUNDLE_MANIFEST="$work/bundle/manifest.json" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/pass.md" \
  "$lint"

python3 - "$work/bundle/manifest.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    manifest = json.load(handle)
for artifact in manifest["artifacts"]:
    if artifact["path"] == "artifacts/release/release-truth.json":
        artifact["sha256"] = "0" * 64
        break
else:
    raise SystemExit("test fixture manifest does not bind release truth")
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2)
    handle.write("\n")
PY

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$work/docker-release-truth.json" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$docker_bundle_release_truth" \
  CHIO_PROOF_ROOM_BUNDLE_MANIFEST="$work/bundle/manifest.json" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/pass.md" \
  "$lint" >"$work/bundle-release-truth-digest-mismatch.out" 2>&1; then
  echo "bundle release truth accepted with mismatched manifest digest" >&2
  exit 1
fi
grep -q \
  "proof-room.release.bundle-release-truth-digest-mismatch" \
  "$work/bundle-release-truth-digest-mismatch.out"

write_bundle_manifest

python3 - "$work/bundle/manifest.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["hosted_demo_url"] = "https://example.invalid/proof-room"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2)
    handle.write("\n")
PY

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$work/docker-release-truth.json" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$docker_bundle_release_truth" \
  CHIO_PROOF_ROOM_BUNDLE_MANIFEST="$work/bundle/manifest.json" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/pass.md" \
  "$lint" >"$work/bundle-manifest-schema-invalid.out" 2>&1; then
  echo "bundle manifest accepted schema-forbidden fields" >&2
  exit 1
fi
grep -q \
  "proof-room.release.bundle-manifest-schema-invalid" \
  "$work/bundle-manifest-schema-invalid.out"

write_bundle_manifest

cp \
  "$work/docker-quickstart-evidence.valid.json" \
  "$work/bundle/artifacts/release/docker-quickstart-evidence.json"
python3 - "$work/bundle/artifacts/release/docker-quickstart-evidence.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    evidence = json.load(handle)
evidence["image_digest"] = "sha256:test"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle, indent=2)
    handle.write("\n")
PY
write_bundle_manifest

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$work/docker-release-truth.json" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$docker_bundle_release_truth" \
  CHIO_PROOF_ROOM_BUNDLE_MANIFEST="$work/bundle/manifest.json" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/pass.md" \
  "$lint" >"$work/docker-evidence-schema-invalid.out" 2>&1; then
  echo "docker quickstart evidence accepted schema-forbidden fields" >&2
  exit 1
fi
grep -q \
  "proof-room.release.docker-evidence-schema-invalid" \
  "$work/docker-evidence-schema-invalid.out"

cp \
  "$work/docker-quickstart-evidence.valid.json" \
  "$work/bundle/artifacts/release/docker-quickstart-evidence.json"
python3 - "$work/bundle/artifacts/release/docker-quickstart-evidence.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    evidence = json.load(handle)
del evidence["fixture_root"]
with open(path, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle, indent=2)
    handle.write("\n")
PY
write_bundle_manifest

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$work/docker-release-truth.json" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$docker_bundle_release_truth" \
  CHIO_PROOF_ROOM_BUNDLE_MANIFEST="$work/bundle/manifest.json" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/pass.md" \
  "$lint" >"$work/docker-evidence-missing-root.out" 2>&1; then
  echo "docker quickstart evidence accepted without fixture root" >&2
  exit 1
fi
grep -q \
  "proof-room.release.docker-evidence-fixture-root-missing" \
  "$work/docker-evidence-missing-root.out"

cp \
  "$work/docker-quickstart-evidence.valid.json" \
  "$work/bundle/artifacts/release/docker-quickstart-evidence.json"
python3 - "$work/bundle/artifacts/release/docker-quickstart-evidence.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    evidence = json.load(handle)
del evidence["doctor_report_path"]
with open(path, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle, indent=2)
    handle.write("\n")
PY
write_bundle_manifest

if CHIO_PROOF_ROOM_RELEASE_TRUTH="$work/docker-release-truth.json" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$docker_bundle_release_truth" \
  CHIO_PROOF_ROOM_BUNDLE_MANIFEST="$work/bundle/manifest.json" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/pass.md" \
  "$lint" >"$work/docker-evidence-missing-doctor-report.out" 2>&1; then
  echo "docker quickstart evidence accepted without doctor report path" >&2
  exit 1
fi
grep -q \
  "proof-room.release.docker-evidence-doctor-report-missing" \
  "$work/docker-evidence-missing-doctor-report.out"

echo "check-chio-proof-room-release-truth.test.sh: release truth positives and negatives passed"
