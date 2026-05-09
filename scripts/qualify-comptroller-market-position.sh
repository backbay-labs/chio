#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "comptroller market-position qualification requires python3 on PATH" >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "comptroller market-position qualification requires node on PATH" >&2
  exit 1
fi

output_root="target/release-qualification/comptroller-market-position"
log_root="${output_root}/logs"
manifest_path="${output_root}/artifact-manifest.json"
checksum_path="${output_root}/SHA256SUMS"
report_path="${output_root}/qualification-report.md"
matrix_src="docs/standards/CHIO_COMPTROLLER_MARKET_POSITION_MATRIX.json"
matrix_snapshot="${output_root}/CHIO_COMPTROLLER_MARKET_POSITION_MATRIX.json"
proof_src="docs/release/CHIO_COMPTROLLER_MARKET_POSITION_PROOF.md"
proof_snapshot="${output_root}/CHIO_COMPTROLLER_MARKET_POSITION_PROOF.md"

rm -rf "${output_root}"
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
cp "${proof_src}" "${proof_snapshot}"

run_and_log universal-control-plane ./scripts/qualify-universal-control-plane.sh
run_and_log operator-surfaces ./scripts/qualify-comptroller-operator-surfaces.sh
run_and_log partner-contracts ./scripts/qualify-comptroller-partner-contracts.sh
run_and_log federation ./scripts/qualify-comptroller-federation.sh
run_and_log planning-truth node "/Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs" roadmap analyze

cat >"${report_path}" <<'EOF'
# Comptroller Market-Position Qualification Gate

This bundle records the strongest honest post-v3.17 decision.

Decision:

- Chio is now qualified as comptroller-capable software on the documented
  technical, operator, partner, and bounded federated proof surfaces.
- Chio is **not** yet qualified for the stronger claim of a proved
  comptroller-of-the-agent-economy market position.

Why not:

- the repo can prove software structure, bounded operator surfaces, partner
  contract packaging, and bounded federated proof
- it cannot prove independent external operator adoption, partner dependence,
  or ecosystem indispensability from repo-local qualification alone

Executed command set:

- `./scripts/qualify-universal-control-plane.sh`
- `./scripts/qualify-comptroller-operator-surfaces.sh`
- `./scripts/qualify-comptroller-partner-contracts.sh`
- `./scripts/qualify-comptroller-federation.sh`
- `node "/Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs" roadmap analyze`

Supporting documents:

- `CHIO_COMPTROLLER_MARKET_POSITION_MATRIX.json`
- `CHIO_COMPTROLLER_MARKET_POSITION_PROOF.md`
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
    "scope": "comptroller_market_position_qualification",
    "decision": "operator_partner_and_federated_proof_qualified_market_position_not_yet_qualified",
    "claimLevel": "comptroller_capable_not_market_position_qualified",
    "artifacts": entries,
}

manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
PY
