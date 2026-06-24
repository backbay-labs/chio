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
negative_catalog = json.loads((root / "negatives/catalog.json").read_text())
tool_versions = json.loads((root / "verifier/tool-versions.json").read_text())

expected_stages = {
    "single-call-authority",
    "commerce-transaction-passport",
    "recursive-runtime-swarm",
    "disclosure-and-agent-web-envelope",
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
if len(negative_catalog.get("cases", [])) < 4:
    raise SystemExit("negative catalog is too thin")
if not tool_versions.get("git_commit"):
    raise SystemExit("tool versions missing git commit")
PY

echo "check-chio-proof-room-launch-acceptance.test.sh: launch acceptance package contract passed"
