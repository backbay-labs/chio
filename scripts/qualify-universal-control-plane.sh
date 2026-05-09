#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null 2>&1; then
  echo "universal control-plane qualification requires cargo on PATH" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "universal control-plane qualification requires python3 on PATH" >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "universal control-plane qualification requires node on PATH" >&2
  exit 1
fi

output_root="target/release-qualification/universal-control-plane"
log_root="${output_root}/logs"
manifest_path="${output_root}/artifact-manifest.json"
checksum_path="${output_root}/SHA256SUMS"
report_path="${output_root}/qualification-report.md"
matrix_src="docs/standards/CHIO_UNIVERSAL_CONTROL_PLANE_QUALIFICATION_MATRIX.json"
matrix_snapshot="${output_root}/CHIO_UNIVERSAL_CONTROL_PLANE_QUALIFICATION_MATRIX.json"
runbook_src="docs/release/CHIO_UNIVERSAL_CONTROL_PLANE_RUNBOOK.md"
runbook_snapshot="${output_root}/CHIO_UNIVERSAL_CONTROL_PLANE_RUNBOOK.md"
partner_proof_src="docs/release/CHIO_UNIVERSAL_CONTROL_PLANE_PARTNER_PROOF.md"
partner_proof_snapshot="${output_root}/CHIO_UNIVERSAL_CONTROL_PLANE_PARTNER_PROOF.md"
cargo_target_dir="target/qualify-universal-control-plane-build"

rm -rf "${output_root}" "${cargo_target_dir}"
mkdir -p "${log_root}"

run_and_log() {
  local name="$1"
  shift
  local log_path="${log_root}/${name}.log"
  echo "==> ${name}"
  "$@" 2>&1 | tee "${log_path}"
}

python3 -m json.tool "${matrix_src}" >/dev/null
cp "${matrix_src}" "${matrix_snapshot}"
cp "${runbook_src}" "${runbook_snapshot}"
cp "${partner_proof_src}" "${partner_proof_snapshot}"

export CARGO_TARGET_DIR="${cargo_target_dir}"

run_and_log universal-fabric \
  cargo test -p chio-cross-protocol -p chio-mcp-edge -p chio-a2a-edge -p chio-acp-edge
run_and_log kernel-authority \
  cargo test -p chio-http-core -p chio-api-protect -p chio-tower
run_and_log control-plane-authority \
  cargo test -p chio-openai-adapter -p chio-acp-proxy
run_and_log planning-truth \
  node "/Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs" roadmap analyze

cat >"${report_path}" <<'EOF'
# Universal Control-Plane Qualification Gate

This artifact bundle captures the post-v3.16 technical control-plane
qualification evidence for Chio's strongest honest technical claim.

Decision:

- Chio now qualifies the stronger original technical control-plane thesis on the
  supported authoritative protocol surfaces.
- The qualified claim is: Chio ships a cryptographically signed, fail-closed,
  intent-aware governance control plane with shared executor registry
  resolution, signed route-selection evidence, receipt-bearing multi-hop route
  execution, and one shared lifecycle contract across HTTP APIs, MCP, OpenAI
  tool execution, A2A skills, and ACP capabilities.
- This gate builds on, rather than replaces, the bounded runtime substrate gate
  in `./scripts/qualify-cross-protocol-runtime.sh`.
- This gate is intentionally delta-focused and does not rerun the bounded
  runtime gate internally; run both commands for the full evidence package.

Still not qualified:

- a proved "comptroller of the agent economy" market position
- ecosystem-wide market dominance or universal partner adoption beyond the
  currently qualified authoritative surfaces and explicit operator/runbook
  proof

Executed command set:

- `cargo test -p chio-cross-protocol -p chio-mcp-edge -p chio-a2a-edge -p chio-acp-edge`
- `cargo test -p chio-http-core -p chio-api-protect -p chio-tower`
- `cargo test -p chio-openai-adapter -p chio-acp-proxy`
- `node "/Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs" roadmap analyze`

Supporting documents:

- `CHIO_UNIVERSAL_CONTROL_PLANE_QUALIFICATION_MATRIX.json`
- `CHIO_UNIVERSAL_CONTROL_PLANE_RUNBOOK.md`
- `CHIO_UNIVERSAL_CONTROL_PLANE_PARTNER_PROOF.md`
EOF

python3 - <<'PY' "${output_root}" "${checksum_path}" "${manifest_path}"
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

output_root = Path(sys.argv[1])
checksum_path = Path(sys.argv[2])
manifest_path = Path(sys.argv[3])

entries = []
for artifact in sorted(output_root.rglob("*")):
    if not artifact.is_file():
        continue
    if artifact in {checksum_path, manifest_path}:
        continue
    payload = artifact.read_bytes()
    entries.append(
        {
            "path": artifact.relative_to(output_root).as_posix(),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
        }
    )

checksum_path.write_text(
    "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in entries)
)

manifest = {
    "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "scope": "universal_control_plane_qualification",
    "claimLevel": "technical_control_plane_thesis",
    "decision": "technical_claim_qualified_market_thesis_not_yet_qualified",
    "claim": "cryptographically signed, fail-closed, intent-aware governance control plane across the qualified authoritative protocol surfaces",
    "prerequisiteGate": "./scripts/qualify-cross-protocol-runtime.sh",
    "artifacts": entries,
}

manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
PY
