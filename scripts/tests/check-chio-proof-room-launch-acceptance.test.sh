#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d -t chio-launch-acceptance-XXXXXX)"
trap 'rm -rf "$work"' EXIT

out="$work/public-bundle"

if ! grep -Fq "verify launch-acceptance" "$repo_root/.github/workflows/ci.yml"; then
  echo "launch-acceptance CI gate missing: cargo xtask verify launch-acceptance" >&2
  exit 1
fi

(
  cd "$repo_root"
  CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" \
    cargo run -p xtask -- verify launch-acceptance --schema-only --out "$out"
)

for path in \
  "$out/manifest.json" \
  "$out/bundle-signature.dsse.json" \
  "$out/claims/claim-registry.json" \
  "$out/claims/homepage-copy-map.json" \
  "$out/claims/non-claims.json" \
  "$out/roots/transaction-passport.json" \
  "$out/roots/evidence-graph.json" \
  "$out/verifier/report.json" \
  "$out/verifier/report.dsse.json" \
  "$out/verifier/tool-versions.json" \
  "$out/verifier/command-transcript.json" \
  "$out/ui/proof-room-static/index.html" \
  "$out/../public-bundle.tar.zst"; do
  if [[ ! -s "$path" ]]; then
    echo "launch-acceptance missing output: $path" >&2
    exit 1
  fi
done

for stage in \
  single-call-authority \
  commerce-transaction-passport \
  recursive-runtime-swarm \
  disclosure-and-agent-web-envelope; do
  if [[ ! -d "$out/stages/$stage/proof-room-bundle" ]]; then
    echo "launch-acceptance missing stage bundle: $stage" >&2
    exit 1
  fi
done

if [[ ! -s "$out/negatives/catalog.json" ]]; then
  echo "launch-acceptance missing negative catalog" >&2
  exit 1
fi

python3 - "$out" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
manifest = json.loads((root / "manifest.json").read_text())
report = json.loads((root / "verifier/report.json").read_text())
non_claims = json.loads((root / "claims/non-claims.json").read_text())
copy_map = json.loads((root / "claims/homepage-copy-map.json").read_text())
negative_catalog = json.loads((root / "negatives/catalog.json").read_text())
tool_versions = json.loads((root / "verifier/tool-versions.json").read_text())
claim_registry = json.loads((root / "claims/claim-registry.json").read_text())

expected_stages = {
    "single-call-authority",
    "commerce-transaction-passport",
    "recursive-runtime-swarm",
    "disclosure-and-agent-web-envelope",
}
expected_copy_claims = {
    "The trust network for autonomous commerce",
    "Proof layer",
    "Emerging agent web",
    "Every action",
    "Single agent call",
    "Multi-swarm coordination",
    "Verifiable authority",
    "Recursive delegation",
    "Lineage",
    "Selective disclosure",
    "Settlement context",
    "Across trust boundaries",
    "Autonomous commerce",
}
expected_agent_web_protocols = {
    "a2a",
    "acp-client",
    "acp-commerce",
    "ag-ui",
    "ap2",
    "asyncapi",
    "bbs",
    "browser-automation",
    "cloudevents",
    "dsse",
    "gmail-api",
    "google-calendar-api",
    "graphql-http",
    "in-toto",
    "kubernetes-admission",
    "mcp",
    "oauth2",
    "oci",
    "openapi",
    "openid-connect",
    "rpa",
    "scim",
    "sd-jwt-vc",
    "sigstore",
    "slack",
    "slsa-provenance",
    "spiffe",
    "standard-webhooks",
    "vc",
    "x402",
}
expected_agent_web_negative_ids = {
    "agent-web-external-digest-mismatch",
    "agent-web-missing-required-signature",
    "agent-web-unsupported-claim-not-limited",
    "agent-web-sidecar-claim-marked-native",
    "agent-web-x402-detached-from-order",
    "agent-web-ap2-detached-from-order",
    "agent-web-oci-tag-only-ref",
    "agent-web-slsa-unverified-provenance",
}
registered_claims = {
    claim["id"]
    for claim in claim_registry.get("claims", [])
    if isinstance(claim, dict) and isinstance(claim.get("id"), str)
}

if manifest.get("schema") != "chio.proof-room.launch-acceptance.v1":
    raise SystemExit("manifest schema mismatch")
if {stage["fixture_id"] for stage in manifest.get("stages", [])} != expected_stages:
    raise SystemExit("manifest stage set mismatch")
if report.get("verdict") != "verified":
    raise SystemExit("acceptance report did not verify")
if {stage["fixture_id"] for stage in report.get("stages", [])} != expected_stages:
    raise SystemExit("report stage set mismatch")
if not non_claims.get("non_claims"):
    raise SystemExit("non-claims are empty")
agent_web_gate = report.get("agent_web_exit_gate")
if not isinstance(agent_web_gate, dict):
    raise SystemExit("acceptance report missing Agent Web exit gate")
if agent_web_gate.get("verdict") != "verified":
    raise SystemExit("Agent Web exit gate did not verify")
if agent_web_gate.get("source_log_path") != "docs/superpowers/research/chio-launch/indices/external-standards-source-log.md":
    raise SystemExit("Agent Web exit gate missing refreshed source log path")
if agent_web_gate.get("source_log_status") != "refreshed source log":
    raise SystemExit("Agent Web exit gate source log was not refreshed")
if set(agent_web_gate.get("source_protocols", [])) < expected_agent_web_protocols:
    missing = expected_agent_web_protocols - set(agent_web_gate.get("source_protocols", []))
    raise SystemExit(f"Agent Web exit gate missing protocols: {sorted(missing)}")
if set(agent_web_gate.get("negative_case_ids", [])) < expected_agent_web_negative_ids:
    missing = expected_agent_web_negative_ids - set(agent_web_gate.get("negative_case_ids", []))
    raise SystemExit(f"Agent Web exit gate missing negatives: {sorted(missing)}")
if copy_map.get("schema") != "chio.proof-room.homepage-copy-map.v1":
    raise SystemExit("homepage copy map schema mismatch")
entries = copy_map.get("copy_claims", [])
if {entry.get("copy_claim") for entry in entries} != expected_copy_claims:
    raise SystemExit("homepage copy map claim set mismatch")
for entry in entries:
    claim_ids = entry.get("claim_ids", [])
    fixture_ids = entry.get("fixture_ids", [])
    if not claim_ids:
        raise SystemExit(f"homepage copy map has no claim ids: {entry.get('copy_claim')}")
    if not fixture_ids:
        raise SystemExit(f"homepage copy map has no fixture ids: {entry.get('copy_claim')}")
    unknown_claims = set(claim_ids) - registered_claims
    if unknown_claims:
        raise SystemExit(f"homepage copy map references unknown claims: {sorted(unknown_claims)}")
    unknown_fixtures = set(fixture_ids) - expected_stages
    if unknown_fixtures:
        raise SystemExit(f"homepage copy map references unknown fixtures: {sorted(unknown_fixtures)}")
    verified_by_fixtures = set()
    for fixture_id in fixture_ids:
        stage_report = json.loads(
            (root / "stages" / fixture_id / "proof-room-bundle" / "verifier/report.json").read_text()
        )
        stage_manifest = json.loads(
            (root / "stages" / fixture_id / "proof-room-bundle" / "manifest.json").read_text()
        )
        verified_by_fixtures.update(stage_report.get("verified_claims", []))
        verified_by_fixtures.update(
            claim.get("claim_id")
            for claim in stage_report.get("claimResults", [])
            if claim.get("status") == "verified"
        )
        verified_by_fixtures.update(
            claim.get("claim_id")
            for claim in stage_manifest.get("claims", [])
            if claim.get("result") == "verified"
        )
    unverified_claims = set(claim_ids) - verified_by_fixtures
    if unverified_claims:
        raise SystemExit(
            f"homepage copy map references claims not verified by listed fixtures: {sorted(unverified_claims)}"
        )
if len(negative_catalog.get("cases", [])) < 4:
    raise SystemExit("negative catalog is too thin")
if not tool_versions.get("git_commit"):
    raise SystemExit("tool versions missing git commit")
PY

echo "check-chio-proof-room-launch-acceptance.test.sh: launch acceptance package contract passed"
