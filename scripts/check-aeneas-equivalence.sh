#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

work_dir="target/formal/aeneas-production"
if ! python3 - <<'PY'
import hashlib
import tomllib
from pathlib import Path

registry = tomllib.loads(Path("formal/aeneas/production.toml").read_text(encoding="utf-8"))
report = Path("target/formal/aeneas-production/toolchain.json")
if not report.is_file() or report.is_symlink():
    raise SystemExit(1)
for source in registry.get("sources", []):
    path = Path(source["path"])
    work = Path(source["work_dir"])
    required = [work / "lean/Funs.lean", work / "lean/Types.lean"]
    if not path.is_file() or any(not candidate.is_file() for candidate in required):
        raise SystemExit(1)
    stamp = work / "source.sha256"
    if not stamp.is_file():
        raise SystemExit(1)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if stamp.read_text(encoding="utf-8").strip() != actual:
        raise SystemExit(1)
PY
then
  ./scripts/check-aeneas-production.sh
  exit 0
fi

while IFS=$'\t' read -r generated_dir snapshot_dir; do
  ./scripts/snapshot-aeneas-generated.sh --check \
    --generated-dir "${generated_dir}" --snapshot-dir "${snapshot_dir}"
done < <(python3 - <<'PY'
import tomllib
from pathlib import Path

registry = tomllib.loads(Path("formal/aeneas/production.toml").read_text(encoding="utf-8"))
for source in registry["sources"]:
    print(f"{source['work_dir']}/lean\t{source['snapshot_dir']}")
PY
)

python3 - <<'PY'
import hashlib
import json
import platform
import re
import tomllib
from pathlib import Path

repo = Path(".")
registry_path = repo / "formal/aeneas/production.toml"
registry = tomllib.loads(registry_path.read_text(encoding="utf-8"))
if registry.get("schema") != "chio.aeneas-production.v1":
    raise SystemExit("Aeneas equivalence registry schema mismatch")
if "external_models" in registry:
    raise SystemExit("Aeneas equivalence must not depend on handwritten externals")

vendor_manifest_path = repo / registry["vendor_manifest"]
vendor = tomllib.loads(vendor_manifest_path.read_text(encoding="utf-8"))
if vendor.get("schema") != "chio.aeneas-vendor.v1":
    raise SystemExit("Aeneas vendor manifest schema mismatch")

workflow_tags = {}
for workflow_name in ("nightly.yml", "release-qualification.yml"):
    workflow_path = repo / ".github/workflows" / workflow_name
    workflow = workflow_path.read_text(encoding="utf-8")
    matches = re.findall(
        r"(?m)^\s*CHIO_AENEAS_RELEASE_TAG:\s*([^\s#]+)\s*$", workflow
    )
    if len(matches) != 1:
        raise SystemExit(f"Aeneas release tag missing or duplicated in {workflow_path}")
    workflow_tags[workflow_name] = matches[0]
declared_tag = registry.get("vendor_release_tag")
vendor_tag = vendor.get("release_tag")
if len({*workflow_tags.values(), declared_tag, vendor_tag}) != 1:
    raise SystemExit(
        "Aeneas release tag mismatch: "
        f"workflows={workflow_tags} registry={declared_tag} vendor={vendor_tag}"
    )

host_toolchain = (repo / "formal/lean4/Chio/lean-toolchain").read_text(encoding="utf-8").strip()
if vendor.get("host_lean_toolchain") != host_toolchain:
    raise SystemExit(
        "Aeneas vendor host toolchain mismatch: "
        f"vendor={vendor.get('host_lean_toolchain')} project={host_toolchain}"
    )

vendor_root = vendor_manifest_path.parent
vendor_digest = hashlib.sha256()
vendor_modules = {
    path.relative_to(vendor_root).with_suffix("").as_posix().replace("/", ".")
    for path in vendor_root.rglob("*.lean")
}
imported_vendor_modules = set()
for path in sorted(path for path in vendor_root.rglob("*") if path.is_file()):
    relative_path = path.relative_to(vendor_root)
    if path == vendor_manifest_path or path.name == "lake-manifest.json" or ".lake" in relative_path.parts:
        continue
    if path.suffix == ".lean":
        text = path.read_text(encoding="utf-8")
        if "\N{EM DASH}" in text:
            raise SystemExit(f"Aeneas vendored support contains non-ASCII dash: {path}")
        if not relative_path.parts[0].startswith("AeneasMeta") and re.search(r"\bsorry\b", text):
            raise SystemExit(f"Aeneas runtime support contains placeholder proof: {path}")
        for line in text.splitlines():
            if line.startswith("import "):
                imported_vendor_modules.update(
                    re.findall(r"\b(?:Aeneas|AeneasMeta)(?:\.[A-Za-z0-9_]+)+\b", line)
                )
    relative = relative_path.as_posix().encode("utf-8")
    vendor_digest.update(relative)
    vendor_digest.update(b"\0")
    vendor_digest.update(path.read_bytes())
    vendor_digest.update(b"\0")
missing_vendor_modules = sorted(imported_vendor_modules - vendor_modules)
if missing_vendor_modules:
    raise SystemExit(f"Aeneas vendor import closure is incomplete: {missing_vendor_modules}")
actual_vendor_digest = vendor_digest.hexdigest()
if actual_vendor_digest != vendor.get("content_sha256"):
    raise SystemExit(
        "Aeneas vendored support content hash mismatch: "
        f"expected={vendor.get('content_sha256')} actual={actual_vendor_digest}"
    )

project_manifest_path = repo / "formal/lean4/Chio/lake-manifest.json"
project_manifest = json.loads(project_manifest_path.read_text(encoding="utf-8"))
packages = project_manifest.get("packages", [])
aeneas_packages = [package for package in packages if package.get("name") == "aeneas"]
mathlib_packages = [package for package in packages if package.get("name") == "mathlib"]
if len(aeneas_packages) != 1 or any(
    aeneas_packages[0].get(key) != value
    for key, value in {
        "type": "path",
        "dir": "../vendor/aeneas",
        "configFile": "lakefile.lean",
    }.items()
):
    raise SystemExit("Lake manifest does not bind the vendored Aeneas path package")
if len(mathlib_packages) != 1 or any(
    mathlib_packages[0].get(key) != value
    for key, value in {
        "type": "git",
        "url": "https://github.com/leanprover-community/mathlib4.git",
        "rev": vendor.get("mathlib_revision"),
        "inputRev": vendor.get("mathlib_revision"),
    }.items()
):
    raise SystemExit("Lake manifest does not bind the vendored Aeneas Mathlib revision")

equivalence_module = repo / registry["equivalence_module"]
proof_text = equivalence_module.read_text(encoding="utf-8")
if re.search(r"\bsorry\b", proof_text):
    raise SystemExit("Generated equivalence module contains a placeholder proof")
declared_proofs = set(
    re.findall(r"(?m)^\s*(?:private\s+)?(?:theorem|lemma)\s+([A-Za-z0-9_']+)\b", proof_text)
)
axiom_reports = set(
    re.findall(r"(?m)^\s*#print\s+axioms\s+([A-Za-z0-9_']+)\s*$", proof_text)
)
if declared_proofs != axiom_reports:
    missing = sorted(declared_proofs - axiom_reports)
    extra = sorted(axiom_reports - declared_proofs)
    raise SystemExit(f"Generated equivalence axiom-report coverage mismatch; missing={missing} extra={extra}")

targets = registry.get("targets", [])
registered_theorems = {}
registered_functions = []
for target in targets:
    if target.get("status") != "generated_equivalence":
        raise SystemExit(f"Aeneas target is not equivalence-checked: {target.get('name')}")
    functions = target.get("functions", [])
    theorem_rows = target.get("equivalence_theorems", [])
    if len(functions) != len(theorem_rows):
        raise SystemExit(f"Aeneas theorem count mismatch for {target.get('name')}")
    for row in theorem_rows:
        symbol, separator, theorem = row.partition("|")
        if not separator or symbol in registered_theorems:
            raise SystemExit(f"Malformed or duplicate generated equivalence theorem row: {row}")
        short_name = theorem.rsplit(".", maxsplit=1)[-1]
        if short_name not in declared_proofs:
            raise SystemExit(f"Generated equivalence theorem missing for {symbol}: {theorem}")
        registered_theorems[symbol] = theorem
    registered_functions.extend(functions)
if set(registered_functions) != set(registered_theorems):
    raise SystemExit("Aeneas generated equivalence theorem inventory is incomplete")

root_import = "import Chio.Proofs.AeneasGeneratedEquivalence"
root_text = (repo / "formal/lean4/Chio/Chio.lean").read_text(encoding="utf-8")
if root_text.splitlines().count(root_import) != 1:
    raise SystemExit("Generated Aeneas equivalence module is not root-imported exactly once")
proof_manifest = tomllib.loads((repo / "formal/proof-manifest.toml").read_text(encoding="utf-8"))
if registry["equivalence_module"] not in proof_manifest.get("root_modules", []):
    raise SystemExit("Generated Aeneas equivalence module is absent from proof manifest roots")

architecture = platform.machine().lower()
architecture = {"amd64": "x86_64", "arm64": "aarch64"}.get(architecture, architecture)
toolchain_rows = [
    row for row in registry.get("toolchains", []) if row.get("architecture") == architecture
]
if len(toolchain_rows) != 1:
    raise SystemExit(f"Expected one Aeneas toolchain row for {architecture}")
toolchain = toolchain_rows[0]
toolchain_report_path = repo / "target/formal/aeneas-production/toolchain.json"
toolchain_report = json.loads(toolchain_report_path.read_text(encoding="utf-8"))
expected_runtime_hashes = {
    "aeneas": toolchain["aeneas_runtime_sha256"],
    "charon": toolchain["charon_runtime_sha256"],
    "charon-driver": toolchain["charon_driver_runtime_sha256"],
}
expected_report_fields = {
    "schema": "chio.aeneas-toolchain.v1",
    "architecture": architecture,
    "releaseTag": vendor_tag,
    "archiveAsset": toolchain["archive_asset"],
    "archiveSha256": toolchain["archive_sha256"],
    "interpreterRepair": toolchain["interpreter_repair"],
    "runtimeSha256": expected_runtime_hashes,
}
for key, value in expected_report_fields.items():
    if toolchain_report.get(key) != value:
        raise SystemExit(
            f"Aeneas generated output toolchain report mismatch for {key}: "
            f"expected={value} actual={toolchain_report.get(key)}"
        )

sources = registry.get("sources", [])
source_files = [repo / source["path"] for source in sources]
generated_files = [
    repo / source["work_dir"] / "lean" / name
    for source in sources
    for name in ("Funs.lean", "Types.lean")
]
snapshot_paths = [
    repo / source["snapshot_dir"] / name
    for source in sources
    for name in ("Funs.lean", "Types.lean")
]

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

hash_paths = [
    registry_path,
    repo / registry["negative_registry"],
    *source_files,
    repo / "scripts/install-aeneas-toolchain.py",
    repo / "scripts/snapshot-aeneas-generated.sh",
    repo / "scripts/tests/aeneas-equivalence.test.sh",
    repo / "scripts/tests/snapshot-aeneas-generated.test.sh",
    repo / "scripts/vendor-aeneas-lean.sh",
    *generated_files,
    *snapshot_paths,
    equivalence_module,
    vendor_manifest_path,
    repo / "formal/lean4/Chio/lakefile.lean",
    project_manifest_path,
    toolchain_report_path,
]
for path in hash_paths:
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"Aeneas equivalence artifact is not a regular file: {path}")

artifact_file = repo / registry["artifact_report"]
artifact_file.parent.mkdir(parents=True, exist_ok=True)
artifact_file.write_text(
    json.dumps(
        {
            "schema": "chio.aeneas-equivalence-artifacts.v1",
            "source": registry["source"],
            "sources": [
                {
                    "id": source["id"],
                    "path": source["path"],
                    "namespace": source["namespace"],
                    "workDir": source["work_dir"],
                    "snapshotDir": source["snapshot_dir"],
                }
                for source in sources
            ],
            "vendor": {
                "manifest": str(vendor_manifest_path),
                "releaseTag": vendor_tag,
                "revision": vendor["revision"],
                "contentSha256": actual_vendor_digest,
            },
            "toolchain": toolchain_report,
            "regenerated": {
                "funs": "target/formal/aeneas-production/lean/Funs.lean",
                "types": "target/formal/aeneas-production/lean/Types.lean",
            },
            "regeneratedSources": [
                {
                    "id": source["id"],
                    "funs": f"{source['work_dir']}/lean/Funs.lean",
                    "types": f"{source['work_dir']}/lean/Types.lean",
                }
                for source in sources
            ],
            "snapshots": [str(path) for path in snapshot_paths],
            "sha256": {str(path): digest(path) for path in hash_paths},
            "targets": [
                {
                    "name": target["name"],
                    "status": target["status"],
                    "functions": target.get("functions", []),
                    "types": target.get("types", []),
                    "equivalenceTheorems": target.get("equivalence_theorems", []),
                }
                for target in targets
            ],
            "registeredEquivalenceTheorems": registered_theorems,
        },
        indent=2,
        sort_keys=True,
    ) + "\n",
    encoding="utf-8",
)
PY

proof_log="${work_dir}/aeneas-generated-equivalence.lean.log"
(
  cd formal/lean4/Chio
  lake build Chio.Proofs.AeneasGeneratedEquivalence
  lake env lean Chio/Proofs/AeneasGeneratedEquivalence.lean
) 2>&1 | tee "${proof_log}"

if command -v rg >/dev/null 2>&1; then
  scan=(rg -n 'sorryAx|declaration uses .sorry.|declaration has metavariables' "${proof_log}")
else
  scan=(grep -nE 'sorryAx|declaration uses .sorry.|declaration has metavariables' "${proof_log}")
fi
"${scan[@]}" && scan_rc=0 || scan_rc=$?
if [[ "${scan_rc}" -eq 0 ]]; then
  echo "Aeneas generated equivalence depends on an incomplete proof" >&2
  exit 1
elif [[ "${scan_rc}" -ne 1 ]]; then
  echo "Aeneas generated equivalence scan failed with exit ${scan_rc}" >&2
  exit 1
fi

echo "Aeneas generated equivalence gate passed"
