#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

work_dir="target/formal/aeneas-production"
toolchain_report="${work_dir}/toolchain.json"

case "$(uname -m)" in
  x86_64 | amd64) architecture="x86_64" ;;
  aarch64 | arm64) architecture="aarch64" ;;
  *)
    echo "Unsupported Aeneas host architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

toolchain_root="target/formal/aeneas-toolchain/${architecture}"
toolchain_bin="${toolchain_root}/bin"
aeneas_bin="${toolchain_bin}/aeneas"
charon_bin="${toolchain_bin}/charon"
charon_driver_bin="${toolchain_bin}/charon-driver"
install_receipt="${toolchain_root}/receipt.json"

python3 - <<'PY'
import re
import tomllib
from pathlib import Path

registry = tomllib.loads(Path("formal/aeneas/production.toml").read_text(encoding="utf-8"))
if registry.get("schema") != "chio.aeneas-production.v1":
    raise SystemExit("Aeneas production registry schema mismatch")
if "external_models" in registry:
    raise SystemExit("Aeneas production registry must not declare handwritten externals")
negative_registry = Path(registry.get("negative_registry", ""))
if not negative_registry.is_file() or negative_registry.is_symlink():
    raise SystemExit("Aeneas negative-test registry is missing or invalid")

sources = registry.get("sources", [])
source_ids = [source.get("id") for source in sources]
if len(sources) < 2 or not all(source_ids) or len(source_ids) != len(set(source_ids)):
    raise SystemExit("Aeneas production source inventory is invalid")
required_source_fields = {
    "path", "namespace", "work_dir", "generated_module", "snapshot_dir"
}
for source in sources:
    missing = sorted(required_source_fields - source.keys())
    if missing:
        raise SystemExit(f"Aeneas source {source['id']} is missing fields: {missing}")
    path = Path(source["path"])
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"Aeneas production source missing or invalid: {path}")

targets = registry.get("targets", [])
target_names = [target.get("name") for target in targets]
if len(targets) < 2 or not all(target_names) or len(target_names) != len(set(target_names)):
    raise SystemExit("Aeneas production registry target inventory is invalid")

registered_theorems = []
for target in targets:
    if target.get("source") not in source_ids:
        raise SystemExit(f"Aeneas target has unknown source: {target.get('name')}")
    if target.get("status") != "generated_equivalence":
        raise SystemExit(f"Aeneas target is not equivalence-checked: {target.get('name')}")
    functions = target.get("functions", [])
    theorem_rows = target.get("equivalence_theorems", [])
    theorem_symbols = []
    for row in theorem_rows:
        symbol, separator, theorem = row.partition("|")
        if not separator or not symbol or not theorem:
            raise SystemExit(f"Malformed generated equivalence theorem row: {row}")
        theorem_symbols.append(symbol)
        registered_theorems.append(theorem.rsplit(".", maxsplit=1)[-1])
    if sorted(theorem_symbols) != sorted(functions):
        raise SystemExit(f"Generated equivalence inventory mismatch for target {target['name']}")

for source in sources:
    source_targets = [target for target in targets if target["source"] == source["id"]]
    registered_functions = [
        symbol for target in source_targets for symbol in target.get("functions", [])
    ]
    registered_types = [
        name for target in source_targets for name in target.get("types", [])
    ]
    if len(registered_functions) != len(set(registered_functions)):
        raise SystemExit(f"Aeneas source contains duplicate functions: {source['id']}")
    if len(registered_types) != len(set(registered_types)):
        raise SystemExit(f"Aeneas source contains duplicate types: {source['id']}")
    text = Path(source["path"]).read_text(encoding="utf-8")
    production_source = text.split("#[cfg(test)]", maxsplit=1)[0]
    source_functions = set(re.findall(
        r"(?m)^(?:pub(?:\([^)]*\))?\s+)?fn\s+([A-Za-z0-9_]+)\s*\(",
        production_source,
    ))
    source_types = set(re.findall(
        r"(?m)^pub\s+struct\s+([A-Za-z0-9_]+)\b", production_source
    ))
    if set(registered_functions) != source_functions:
        missing = sorted(source_functions - set(registered_functions))
        extra = sorted(set(registered_functions) - source_functions)
        raise SystemExit(
            f"Aeneas function inventory mismatch for {source['id']}; "
            f"missing={missing} extra={extra}"
        )
    if set(registered_types) != source_types:
        missing = sorted(source_types - set(registered_types))
        extra = sorted(set(registered_types) - source_types)
        raise SystemExit(
            f"Aeneas type inventory mismatch for {source['id']}; "
            f"missing={missing} extra={extra}"
        )

proof = Path(registry["equivalence_module"]).read_text(encoding="utf-8")
declared_proofs = set(
    re.findall(r"(?m)^\s*(?:private\s+)?(?:theorem|lemma)\s+([A-Za-z0-9_']+)\b", proof)
)
missing_proofs = sorted(set(registered_theorems) - declared_proofs)
if missing_proofs:
    raise SystemExit(f"Aeneas registered equivalence proofs are missing: {missing_proofs}")
PY

for path in "${aeneas_bin}" "${charon_bin}" "${charon_driver_bin}"; do
  if [[ ! -f "${path}" || -L "${path}" || ! -x "${path}" ]]; then
    echo "Authenticated Aeneas toolchain missing: ${path}" >&2
    echo "Run ./scripts/install-aeneas-toolchain.py" >&2
    exit 1
  fi
done
if [[ ! -f "${install_receipt}" || -L "${install_receipt}" ]]; then
  echo "Authenticated Aeneas install receipt missing: ${install_receipt}" >&2
  exit 1
fi

python3 - \
  "${architecture}" \
  "${aeneas_bin}" \
  "${charon_bin}" \
  "${charon_driver_bin}" \
  "${install_receipt}" <<'PY'
import hashlib
import json
import sys
import tomllib
from pathlib import Path

architecture, *arguments = sys.argv[1:]
aeneas, charon, charon_driver, receipt_path = map(Path, arguments)
registry_path = Path("formal/aeneas/production.toml")
registry_bytes = registry_path.read_bytes()
registry = tomllib.loads(registry_bytes.decode("utf-8"))
if registry.get("schema") != "chio.aeneas-production.v1":
    raise SystemExit("Aeneas production registry schema mismatch")

rows = registry.get("toolchains", [])
matches = [row for row in rows if row.get("architecture") == architecture]
if len(matches) != 1:
    raise SystemExit(f"Expected one Aeneas toolchain row for {architecture}")
toolchain = matches[0]

if toolchain.get("interpreter_repair") == "none":
    for name in ("aeneas", "charon", "charon_driver"):
        if toolchain.get(f"{name}_official_sha256") != toolchain.get(
            f"{name}_runtime_sha256"
        ):
            raise SystemExit(f"Unrepaired Aeneas tool has divergent hashes: {name}")
elif toolchain.get("interpreter_repair") == "replace_exact_bytes_v1":
    before = toolchain.get("interpreter_before", "")
    after = toolchain.get("interpreter_after", "")
    if not before or not after or len(after.encode("ascii")) > len(before.encode("ascii")):
        raise SystemExit("Invalid Aeneas interpreter repair declaration")
else:
    raise SystemExit("Unknown Aeneas interpreter repair declaration")

actual = {
    "aeneas": hashlib.sha256(aeneas.read_bytes()).hexdigest(),
    "charon": hashlib.sha256(charon.read_bytes()).hexdigest(),
    "charon-driver": hashlib.sha256(charon_driver.read_bytes()).hexdigest(),
}
expected = {
    "aeneas": toolchain["aeneas_runtime_sha256"],
    "charon": toolchain["charon_runtime_sha256"],
    "charon-driver": toolchain["charon_driver_runtime_sha256"],
}
if actual != expected:
    raise SystemExit(
        f"Aeneas runtime binary hash mismatch: expected={expected} actual={actual}"
    )

receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
expected_receipt = {
    "schema": "chio.aeneas-toolchain-install.v1",
    "architecture": architecture,
    "releaseTag": registry["vendor_release_tag"],
    "archiveAsset": toolchain["archive_asset"],
    "archiveSha256": toolchain["archive_sha256"],
    "interpreterRepair": toolchain["interpreter_repair"],
    "registrySha256": hashlib.sha256(registry_bytes).hexdigest(),
    "runtimeSha256": actual,
}
for key, value in expected_receipt.items():
    if receipt.get(key) != value:
        raise SystemExit(
            f"Aeneas install receipt mismatch for {key}: "
            f"expected={value} actual={receipt.get(key)}"
        )
PY

rm -rf "${work_dir}"
mkdir -p "${work_dir}"

while IFS=$'\t' read -r source_id source_file namespace source_work_dir; do
  llbc_dir="${source_work_dir}/llbc"
  lean_dir="${source_work_dir}/lean"
  source_stamp="${source_work_dir}/source.sha256"
  source_stem="$(basename "${source_file}" .rs)"
  llbc_file="${llbc_dir}/${source_stem}.llbc"
  mkdir -p "${llbc_dir}" "${lean_dir}"

  echo "==> Charon extraction for ${source_id}"
  env \
    -u CHIO_CHARON \
    -u CHIO_CHARON_DRIVER \
    -u CHARON_ARGS \
    -u CHARON_TOOLCHAIN_IS_IN_PATH \
    -u CHARON_USING_CARGO \
    -u RUSTC_WRAPPER \
    PATH="${PWD}/${toolchain_bin}:${PATH}" \
    "${charon_bin}" rustc --preset=aeneas --dest-file "${llbc_file}" -- \
      --crate-type lib "${source_file}"

  if [[ ! -f "${llbc_file}" || -L "${llbc_file}" ]]; then
    echo "Aeneas production check failed: Charon did not produce ${llbc_file}" >&2
    exit 1
  fi

  echo "==> Aeneas Lean extraction for ${source_id}"
  "${aeneas_bin}" -backend lean -split-files -namespace "${namespace}" \
    -dest "${lean_dir}" "${llbc_file}"

  if [[ ! -f "${lean_dir}/Funs.lean" || ! -f "${lean_dir}/Types.lean" ]]; then
    echo "Aeneas production check failed: output missing for ${source_id}" >&2
    exit 1
  fi
  sha256sum "${source_file}" | awk '{print $1}' >"${source_stamp}"
done < <(python3 - <<'PY'
import tomllib
from pathlib import Path

registry = tomllib.loads(Path("formal/aeneas/production.toml").read_text(encoding="utf-8"))
for source in registry["sources"]:
    print("\t".join((
        source["id"], source["path"], source["namespace"], source["work_dir"]
    )))
PY
)

python3 - <<'PY'
import re
import tomllib
from pathlib import Path

repo = Path(".")
registry = tomllib.loads((repo / "formal/aeneas/production.toml").read_text(encoding="utf-8"))
if registry.get("schema") != "chio.aeneas-production.v1":
    raise SystemExit("Aeneas production registry schema mismatch")
if "external_models" in registry:
    raise SystemExit("Aeneas production registry must not declare handwritten externals")

targets = registry.get("targets", [])
if len(targets) < 2:
    raise SystemExit("Aeneas production registry must declare each extraction target")
target_names = [target.get("name") for target in targets]
if not all(target_names) or len(target_names) != len(set(target_names)):
    raise SystemExit("Aeneas production registry target names must be unique")

for source in registry.get("sources", []):
    source_targets = [target for target in targets if target.get("source") == source["id"]]
    registered_functions = [
        symbol for target in source_targets for symbol in target.get("functions", [])
    ]
    registered_types = [
        name for target in source_targets for name in target.get("types", [])
    ]
    generated_dir = repo / source["work_dir"] / "lean"
    funs = (generated_dir / "Funs.lean").read_text(encoding="utf-8")
    types = (generated_dir / "Types.lean").read_text(encoding="utf-8")
    imports = re.findall(r"(?m)^import\s+([^\s]+)\s*$", funs)
    expected_imports = ["Aeneas", f"{source['generated_module']}.Types"]
    if imports != expected_imports:
        raise SystemExit(
            f"Aeneas generated imports mismatch for {source['id']}: "
            f"expected={expected_imports} actual={imports}"
        )
    missing_functions = [
        symbol for symbol in registered_functions
        if not re.search(rf"\bdef\s+{re.escape(symbol)}\b", funs)
    ]
    missing_types = [
        type_name for type_name in registered_types
        if not re.search(rf"\bstructure\s+{re.escape(type_name)}\b", types)
    ]
    if missing_functions:
        raise SystemExit(
            f"Aeneas generated functions missing for {source['id']}: {missing_functions}"
        )
    if missing_types:
        raise SystemExit(
            f"Aeneas generated types missing for {source['id']}: {missing_types}"
        )
PY

python3 - "${architecture}" "${toolchain_report}" <<'PY'
import hashlib
import json
import subprocess
import sys
import tomllib
from pathlib import Path

architecture, report_path = sys.argv[1:]
registry_path = Path("formal/aeneas/production.toml")
registry = tomllib.loads(registry_path.read_text(encoding="utf-8"))
toolchain = next(
    row for row in registry["toolchains"] if row["architecture"] == architecture
)
binary_dir = Path("target/formal/aeneas-toolchain") / architecture / "bin"
runtime_hashes = {
    name: hashlib.sha256((binary_dir / name).read_bytes()).hexdigest()
    for name in ("aeneas", "charon", "charon-driver")
}
charon_version = subprocess.run(
    [str(binary_dir / "charon"), "version"],
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()
Path(report_path).write_text(
    json.dumps(
        {
            "schema": "chio.aeneas-toolchain.v1",
            "architecture": architecture,
            "releaseTag": registry["vendor_release_tag"],
            "archiveAsset": toolchain["archive_asset"],
            "archiveSha256": toolchain["archive_sha256"],
            "interpreterRepair": toolchain["interpreter_repair"],
            "runtimeSha256": runtime_hashes,
            "charonVersion": charon_version,
        },
        indent=2,
        sort_keys=True,
    ) + "\n",
    encoding="utf-8",
)
PY

./scripts/check-aeneas-equivalence.sh

echo "Aeneas production extraction and equivalence passed"
