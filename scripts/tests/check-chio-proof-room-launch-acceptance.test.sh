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

if ! grep -Fq "scripts/tests/check-chio-proof-room-launch-acceptance.test.sh" "$repo_root/.github/workflows/ci.yml"; then
  echo "launch-acceptance CI contract gate missing: check-chio-proof-room-launch-acceptance.test.sh" >&2
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
  "$out/claims/formal-claim-registry.md" \
  "$out/claims/homepage-copy-map.json" \
  "$out/claims/non-claims.json" \
  "$out/claims/proof-coverage.md" \
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
  for path in \
    "$out/stages/$stage/proof-room-bundle/claims/claim-registry.json" \
    "$out/stages/$stage/proof-room-bundle/claims/non-claims.json" \
    "$out/stages/$stage/proof-room-bundle/verifier/report.dsse.json"; do
    if [[ ! -s "$path" ]]; then
      echo "launch-acceptance stage bundle missing canonical companion: $path" >&2
      exit 1
    fi
  done
done

if [[ ! -s "$out/negatives/catalog.json" ]]; then
  echo "launch-acceptance missing negative catalog" >&2
  exit 1
fi

python3 - "$out" "$repo_root" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
repo = Path(sys.argv[2])
manifest = json.loads((root / "manifest.json").read_text())
report = json.loads((root / "verifier/report.json").read_text())
non_claims = json.loads((root / "claims/non-claims.json").read_text())
copy_map = json.loads((root / "claims/homepage-copy-map.json").read_text())
negative_catalog = json.loads((root / "negatives/catalog.json").read_text())
tool_versions = json.loads((root / "verifier/tool-versions.json").read_text())
claim_registry = json.loads((root / "claims/claim-registry.json").read_text())
proof_coverage = (root / "claims/proof-coverage.md").read_text()
formal_claim_registry = (root / "claims/formal-claim-registry.md").read_text()

nested_source_catalogs = sorted(
    repo.glob("fixtures/proof-room/**/negatives/catalog/*/negatives/catalog")
)
if nested_source_catalogs:
    print("launch-acceptance nested source negative catalogs:", file=sys.stderr)
    for path in nested_source_catalogs:
        print(f"- {path.relative_to(repo)}", file=sys.stderr)
    sys.exit(1)

nested_output_catalogs = sorted(root.glob("**/negatives/catalog/*/negatives/catalog"))
if nested_output_catalogs:
    print("launch-acceptance nested output negative catalogs:", file=sys.stderr)
    for path in nested_output_catalogs:
        print(f"- {path.relative_to(root)}", file=sys.stderr)
    sys.exit(1)

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
expected_disclosure_negative_ids = {
    "disclosure-lineage-forbidden-disclosed-field",
    "disclosure-lineage-undeclared-hidden-predicate",
    "disclosure-lineage-projection-manifest-id-mismatch",
    "disclosure-lineage-privacy-profile-not-bound-to-transaction",
    "disclosure-lineage-nonce-replay",
}
expected_swarm_negative_ids = {
    "recursive-runtime-swarm-route-plan-mismatch",
    "recursive-runtime-swarm-egress-constraint-unsupported",
}
expected_product_negative_ids = {
    "product-private-credential-required",
    "product-plugin-cached-verdict",
    "product-playground-unsupported-claim",
}
expected_commerce_trust_network_claims = {
    "claim.commerce.trust_market_context_bound",
    "claim.trust_market.provider_discovery_bound",
    "claim.trust_market.provider_selection_bound",
}
expected_negative_control_floor = {
    "NC-01 stale capability": ("catalog", "stale-capability"),
    "NC-02 policy hash mismatch": ("catalog", "policy-hash-mismatch"),
    "NC-03 stale continuation": ("catalog", "recursive-runtime-swarm-stale-continuation"),
    "NC-04 route plan mismatch": ("catalog", "recursive-runtime-swarm-route-plan-mismatch"),
    "NC-05 over disclosure": ("catalog", "disclosure-lineage-excess-disclosed-field"),
    "NC-06 settlement not binding order": ("catalog", "public-settlement-missing-commerce-order-binding"),
    "NC-07 unreconciled reserves": (
        "path",
        "fixtures/proof-room/enterprise-export/valid-autonomous-commerce/negatives/catalog/enterprise-risk-reserve-state-missing/transaction-passport.json",
    ),
    "NC-08 double reserve": (
        "path",
        "fixtures/proof-room/enterprise-export/valid-autonomous-commerce/negatives/catalog/enterprise-double-consumed-reserve/transaction-passport.json",
    ),
    "NC-09 open appeal blocks closure": (
        "path",
        "fixtures/proof-room/enterprise-export/valid-autonomous-commerce/negatives/catalog/enterprise-open-appeal-facility-closure/transaction-passport.json",
    ),
    "NC-10 projection digest mismatch": ("catalog", "agent-web-external-digest-mismatch"),
    "NC-11 missing execution lease": (
        "path",
        "fixtures/proof-room/runtime-security/negatives/missing-execution-lease.json",
    ),
    "NC-12 advisory as authorization": (
        "path",
        "fixtures/proof-room/runtime-security/advisory-used-as-authorization/transaction-passport.json",
    ),
    "NC-13 first run without denial": ("catalog", "missing-denial-receipt"),
    "NC-14 broader child scope in preflight": (
        "path",
        "fixtures/proof-room/workflow-preflight/broader-child-scope/preflight-plan.json",
    ),
    "NC-15 enterprise over discloses PII": (
        "path",
        "fixtures/proof-room/enterprise-export/valid-autonomous-commerce/negatives/catalog/enterprise-pii-overdisclosure/transaction-passport.json",
    ),
    "NC-16 webhook signature as authorization": ("catalog", "agent-web-unsupported-claim-not-limited"),
}
registered_claims = {
    claim["id"]
    for claim in claim_registry.get("claims", [])
    if isinstance(claim, dict) and isinstance(claim.get("id"), str)
}
negative_catalog_ids = {
    case["id"]
    for case in negative_catalog.get("cases", [])
    if isinstance(case, dict) and isinstance(case.get("id"), str)
}

if manifest.get("schema") != "chio.proof-room.launch-acceptance.v1":
    raise SystemExit("manifest schema mismatch")
if manifest.get("claims", {}).get("proof_coverage", {}).get("path") != "claims/proof-coverage.md":
    raise SystemExit("manifest proof coverage path mismatch")
if manifest.get("claims", {}).get("formal_claim_registry", {}).get("path") != "claims/formal-claim-registry.md":
    raise SystemExit("manifest formal claim registry path mismatch")
if manifest.get("git_commit") not in proof_coverage:
    raise SystemExit("proof coverage page missing package commit")
if "@GIT_COMMIT@" in proof_coverage:
    raise SystemExit("proof coverage page contains unresolved commit token")
if "(formal-claim-registry.md)" not in proof_coverage:
    raise SystemExit("proof coverage page missing bundle-local claim registry link")
if "../reference/CLAIM_REGISTRY.md" in proof_coverage:
    raise SystemExit("proof coverage page retains repository-local claim registry link")
for term in ["FORM-BOUNDARY", "FORM-IMPLEMENTATION-LINKED", "LEAN-4-VERIFIED"]:
    if term not in formal_claim_registry:
        raise SystemExit(f"formal claim registry missing governance term: {term}")
if {stage["fixture_id"] for stage in manifest.get("stages", [])} != expected_stages:
    raise SystemExit("manifest stage set mismatch")
# This contract test assembles the package with --schema-only, which skips
# the fixture verifier gate. A schema-only report must fail closed and never
# claim "verified"; the full-run "verified" verdict is exercised by the CI
# step that runs cargo xtask verify launch-acceptance without --schema-only.
if report.get("mode") != "schema-only":
    raise SystemExit("acceptance report mode mismatch: expected schema-only")
if report.get("verdict") == "verified":
    raise SystemExit("schema-only acceptance report must not claim verified")
if report.get("verdict") != "schema-only-unverified":
    raise SystemExit("schema-only acceptance report verdict mismatch")
if {stage["fixture_id"] for stage in report.get("stages", [])} != expected_stages:
    raise SystemExit("report stage set mismatch")
recursive_task_graph = json.loads(
    (
        root
        / "stages/recursive-runtime-swarm/proof-room-bundle/task-graph.json"
    ).read_text()
)
recursive_child_tasks = [
    node
    for node in recursive_task_graph.get("nodes", [])
    if isinstance(node, dict) and node.get("parentTaskId")
]
if len(recursive_child_tasks) < 3:
    raise SystemExit("recursive-runtime-swarm stage must include at least 3 child tasks")
commerce_stage_report = json.loads(
    (
        root
        / "stages/commerce-transaction-passport/proof-room-bundle/verifier/report.json"
    ).read_text()
)
commerce_stage_claims = set(commerce_stage_report.get("verified_claims", []))
commerce_stage_claims.update(
    claim.get("claim_id")
    for claim in commerce_stage_report.get("claimResults", [])
    if claim.get("status") == "verified"
)
if not expected_commerce_trust_network_claims <= commerce_stage_claims:
    missing = expected_commerce_trust_network_claims - commerce_stage_claims
    raise SystemExit(
        f"commerce-transaction-passport stage missing trust-network claims: {sorted(missing)}"
    )
for stage in report.get("stages", []):
    fixture_id = stage.get("fixture_id")
    if stage.get("verifier_report_verdict") != "verified":
        raise SystemExit(f"stage verifier verdict missing or unverified: {fixture_id}")
    if stage.get("proof_room_verdict") != "verified":
        raise SystemExit(f"stage Proof Room verdict missing or unverified: {fixture_id}")
    if stage.get("verdict_parity") != "verified":
        raise SystemExit(f"stage CLI-vs-Proof Room verdict parity missing: {fixture_id}")
if not non_claims.get("non_claims"):
    raise SystemExit("non-claims are empty")
agent_web_gate = report.get("agent_web_exit_gate")
if not isinstance(agent_web_gate, dict):
    raise SystemExit("acceptance report missing Agent Web exit gate")
if agent_web_gate.get("verdict") != "verified":
    raise SystemExit("Agent Web exit gate did not verify")
if agent_web_gate.get("standards_signoff_path") != "docs/standards/CHIO_AGENT_WEB_STANDARDS_SIGNOFF.json":
    raise SystemExit("Agent Web exit gate missing standards sign-off path")
if agent_web_gate.get("standards_signoff_status") != "approved":
    raise SystemExit("Agent Web exit gate standards sign-off was not approved")
if set(agent_web_gate.get("standards_signoff_terms", [])) != {"standard", "compatible", "native", "universal"}:
    raise SystemExit("Agent Web exit gate standards sign-off terms mismatch")
if set(agent_web_gate.get("source_protocols", [])) < expected_agent_web_protocols:
    missing = expected_agent_web_protocols - set(agent_web_gate.get("source_protocols", []))
    raise SystemExit(f"Agent Web exit gate missing protocols: {sorted(missing)}")
if set(agent_web_gate.get("negative_case_ids", [])) < expected_agent_web_negative_ids:
    missing = expected_agent_web_negative_ids - set(agent_web_gate.get("negative_case_ids", []))
    raise SystemExit(f"Agent Web exit gate missing negatives: {sorted(missing)}")
if not expected_disclosure_negative_ids <= negative_catalog_ids:
    missing = expected_disclosure_negative_ids - negative_catalog_ids
    raise SystemExit(f"launch acceptance missing disclosure negatives: {sorted(missing)}")
if not expected_swarm_negative_ids <= negative_catalog_ids:
    missing = expected_swarm_negative_ids - negative_catalog_ids
    raise SystemExit(f"launch acceptance missing swarm negatives: {sorted(missing)}")
if not expected_product_negative_ids <= negative_catalog_ids:
    missing = expected_product_negative_ids - negative_catalog_ids
    raise SystemExit(f"launch acceptance missing product-overlay negatives: {sorted(missing)}")
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
missing_negative_controls = []
for label, (kind, value) in expected_negative_control_floor.items():
    if kind == "catalog" and value not in negative_catalog_ids:
        missing_negative_controls.append(f"{label}: {value}")
    if kind == "path" and not (repo / value).is_file():
        missing_negative_controls.append(f"{label}: {value}")
if missing_negative_controls:
    raise SystemExit(f"negative-control floor missing cases: {missing_negative_controls}")
if not tool_versions.get("git_commit"):
    raise SystemExit("tool versions missing git commit")
PY

echo "check-chio-proof-room-launch-acceptance.test.sh: launch acceptance package contract passed"
