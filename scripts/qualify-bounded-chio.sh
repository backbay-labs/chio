#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "bounded Chio qualification requires python3 on PATH" >&2
  exit 1
fi

output_root="target/release-qualification/bounded-chio"
log_root="${output_root}/logs"
manifest_path="${output_root}/artifact-manifest.json"
checksum_path="${output_root}/SHA256SUMS"
report_path="${output_root}/qualification-report.md"
matrix_src="docs/standards/CHIO_BOUNDED_QUALIFICATION_MATRIX.json"
matrix_snapshot="${output_root}/CHIO_BOUNDED_QUALIFICATION_MATRIX.json"
profile_src="docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md"
profile_snapshot="${output_root}/CHIO_BOUNDED_OPERATIONAL_PROFILE.md"
checklist_snapshot="${output_root}/bounded-chio-pre-ship-checklist.md"

rm -rf "${output_root}"
mkdir -p "${log_root}"

python3 -m json.tool "${matrix_src}" >/dev/null
cp "${matrix_src}" "${matrix_snapshot}"
cp "${profile_src}" "${profile_snapshot}"

python3 - <<'PY' >"${log_root}/doc-claim-discipline.log"
from pathlib import Path

checks = {
    "README.md": [
        "docs/release/RELEASE_CANDIDATE.md",
        "docs/release/RELEASE_AUDIT.md",
        "docs/release/QUALIFICATION.md",
    ],
    "docs/release/QUALIFICATION.md": [
        "./scripts/qualify-bounded-chio.sh",
        "target/release-qualification/bounded-chio/",
    ],
    "docs/release/RELEASE_AUDIT.md": [
        "./scripts/qualify-bounded-chio.sh",
        "CHIO_BOUNDED_QUALIFICATION_MATRIX.json",
    ],
}

for rel_path, required in checks.items():
    text = Path(rel_path).read_text()
    for needle in required:
        if needle not in text:
            raise SystemExit(f"missing bounded qualification reference in {rel_path}: {needle}")
    print(f"ok: {rel_path}")
PY

python3 - <<'PY' >"${log_root}/planning-truth.log"
import json
from pathlib import Path

matrix = json.loads(Path("docs/standards/CHIO_BOUNDED_QUALIFICATION_MATRIX.json").read_text())
if matrix.get("entrypoint") != "./scripts/qualify-bounded-chio.sh":
    raise SystemExit("bounded qualification matrix entrypoint drifted")
if matrix.get("scope") != "bounded_chio_release_qualification":
    raise SystemExit("bounded qualification matrix scope drifted")
if not matrix.get("gateConditions"):
    raise SystemExit("bounded qualification matrix has no gate conditions")
print("ok: bounded qualification matrix remains the planning truth source")
PY

python3 - <<'PY' "${checklist_snapshot}"
import json
import sys
from pathlib import Path

matrix = json.loads(Path("docs/standards/CHIO_BOUNDED_QUALIFICATION_MATRIX.json").read_text())
lines = [
    "# Bounded Chio Pre-Ship Checklist",
    "",
    "Generated from `docs/standards/CHIO_BOUNDED_QUALIFICATION_MATRIX.json`.",
    "",
]
for condition in matrix["gateConditions"]:
    lines.append(f"- [ ] `{condition['id']}` {condition['summary']}")
Path(sys.argv[1]).write_text("\n".join(lines) + "\n")
PY

cat >"${report_path}" <<'EOF'
# Bounded Chio Qualification Gate

This bundle records the current ship-facing release boundary.

Decision:

- Chio is qualified locally as a bounded governance and evidence control plane.
- The bounded release excludes stronger recursive delegation, verifier-bound
  runtime, transparency-log, consensus-HA, and market-position claims.

Executed checks:

- JSON validation of `CHIO_BOUNDED_QUALIFICATION_MATRIX.json`
- bounded release reference checks over README and release docs
- bounded matrix scope and entrypoint checks

Supporting documents:

- `CHIO_BOUNDED_QUALIFICATION_MATRIX.json`
- `CHIO_BOUNDED_OPERATIONAL_PROFILE.md`
- `bounded-chio-pre-ship-checklist.md`
EOF

python3 - <<'PY' "${output_root}" "${checksum_path}" "${manifest_path}"
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
    if not artifact.is_file() or artifact in {checksum_path, manifest_path}:
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
    "scope": "bounded_chio_release_qualification",
    "decision": "bounded_chio_release_qualified_stronger_claims_demoted_to_addenda",
    "claimLevel": "bounded_chio_release_candidate",
    "artifacts": entries,
}
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
PY
