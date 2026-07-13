#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

registry="${CHIO_APALACHE_NEGATIVE_REGISTRY:-formal/apalache/_negative_tests/REGISTRY.toml}"
cargo_target_dir="${CARGO_TARGET_DIR:-target}"
output_root="${CHIO_APALACHE_NEGATIVE_OUTPUT_DIR:-${cargo_target_dir}/apalache-negative}"
apalache_bin="${APALACHE_BIN:-apalache-mc}"

if [[ -n "${TIMEOUT_BIN:-}" ]]; then
  timeout_bin="${TIMEOUT_BIN}"
elif command -v timeout >/dev/null 2>&1; then
  timeout_bin="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  timeout_bin="gtimeout"
else
  echo "check-apalache-negative: timeout command is required" >&2
  exit 2
fi

if ! command -v "${apalache_bin}" >/dev/null 2>&1 && [[ ! -x "${apalache_bin}" ]]; then
  echo "check-apalache-negative: Apalache executable not found: ${apalache_bin}" >&2
  exit 2
fi

set +e
apalache_version="$("${timeout_bin}" 30 "${apalache_bin}" version 2>&1)"
version_exit=$?
set -e
if [[ "${version_exit}" -ne 0 || "${apalache_version}" != "0.50.1" ]]; then
  echo "check-apalache-negative: Apalache 0.50.1 is required" >&2
  exit 2
fi

output_root="$(python3 - "${output_root}" "${repo_root}" "${cargo_target_dir}" <<'PY'
from pathlib import Path
import sys
import tempfile

raw = sys.argv[1]
repo = Path(sys.argv[2]).resolve()
cargo_target_requested = Path(sys.argv[3])
if not cargo_target_requested.is_absolute():
    cargo_target_requested = repo / cargo_target_requested
lexical_cargo_target = cargo_target_requested.absolute()
cargo_target = lexical_cargo_target.resolve()

if not raw or any(character in raw for character in "\r\n\t"):
    raise SystemExit("check-apalache-negative: refusing unsafe output directory")

requested = Path(raw)
if not requested.is_absolute():
    requested = repo / requested
lexical = requested.absolute()
lexical_target = (repo / "target").absolute()
requested_below_target = lexical_target in lexical.parents
managed_cargo_target = (
    cargo_target != repo
    and cargo_target != Path(cargo_target.anchor)
)
requested_below_cargo_target = (
    managed_cargo_target and lexical_cargo_target in lexical.parents
)
error = (
    "check-apalache-negative: output directory must be below target, "
    "CARGO_TARGET_DIR, or the system temporary directory outside the repository"
)

current = Path(lexical.anchor)
for part in lexical.parts[1:]:
    current /= part
    if current.is_symlink():
        raise SystemExit(error)

candidate = lexical.resolve()
target_root = (repo / "target").resolve()
temporary_root = Path(tempfile.gettempdir()).resolve()
below_target = (
    requested_below_target
    and repo in candidate.parents
    and target_root in candidate.parents
)
below_cargo_target = (
    requested_below_cargo_target
    and cargo_target in candidate.parents
)
outside_repo = candidate != repo and repo not in candidate.parents and candidate not in repo.parents
below_temporary = (
    not requested_below_target
    and not requested_below_cargo_target
    and temporary_root in candidate.parents
    and outside_repo
)

if not (below_target or below_cargo_target or below_temporary):
    raise SystemExit(error)

print(candidate)
PY
)"

entries_file="$(mktemp)"
trap 'rm -f "${entries_file}"' EXIT

python3 - "${registry}" "formal/MAPPING.md" "${repo_root}" >"${entries_file}" <<'PY'
from pathlib import Path
import re
import stat
import subprocess
import sys
import tomllib

repo = Path(sys.argv[3]).resolve()
registry_path = Path(sys.argv[1])
mapping_path = Path(sys.argv[2])
if not registry_path.is_absolute():
    registry_path = repo / registry_path
if not mapping_path.is_absolute():
    mapping_path = repo / mapping_path

NA_WITH_REASON = re.compile(r"^n/a \([^()]+\)$")
RUST_TEST_ANCHOR = re.compile(
    r"^(?P<path>[^:]+\.rs)::(?P<anchor>[A-Za-z_][A-Za-z0-9_]*)$"
)

def regular_repo_file(path: Path, label: str) -> Path:
    lexical = path if path.is_absolute() else repo / path
    try:
        relative = lexical.relative_to(repo)
    except ValueError as error:
        raise SystemExit(f"{label} escapes the repository: {path}") from error
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise SystemExit(f"{label} contains an invalid path component: {path}")
    current = repo
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise SystemExit(f"{label} contains a symlink component: {path}")
    try:
        mode = current.stat(follow_symlinks=False).st_mode
    except FileNotFoundError as error:
        raise SystemExit(f"{label} is missing: {path}") from error
    if not stat.S_ISREG(mode):
        raise SystemExit(f"{label} is not a regular file: {path}")
    try:
        current.resolve(strict=True).relative_to(repo)
    except ValueError as error:
        raise SystemExit(f"{label} escapes the repository: {path}") from error
    return current


registry_path = regular_repo_file(registry_path, "negative registry")
mapping_path = regular_repo_file(mapping_path, "formal mapping")
for sibling in sorted((repo / "formal/apalache").glob("*.tla")):
    regular_repo_file(sibling, "Apalache sibling module")
for sibling in sorted((repo / "formal/tla").glob("*.tla")):
    regular_repo_file(sibling, "TLA sibling module")

with registry_path.open("rb") as handle:
    registry = tomllib.load(handle)

if registry.get("schema") != "chio.apalache-negative.v1":
    raise SystemExit("negative registry schema must be chio.apalache-negative.v1")

entries = registry.get("negative")
if not isinstance(entries, list) or not entries:
    raise SystemExit("negative registry must contain at least one entry")

mapping_rows = [
    line for line in mapping_path.read_text(encoding="utf-8").splitlines()
    if line.lstrip().startswith("|") and not re.match(r"^\s*\|\s*-", line)
]
required = {
    "spec": str,
    "cfg": str,
    "falsifies": str,
    "production_commit": str,
    "runtime_test": str,
    "classification": str,
    "length": int,
    "timeout_secs": int,
    "notes": str,
}
seen_specs: set[str] = set()
seen_names: set[str] = set()
negative_root = Path("formal/apalache/_negative_tests")

for index, entry in enumerate(entries, start=1):
    if not isinstance(entry, dict):
        raise SystemExit(f"negative entry {index} must be a table")
    unknown = set(entry) - set(required)
    missing = set(required) - set(entry)
    if unknown or missing:
        raise SystemExit(
            f"negative entry {index} has missing={sorted(missing)} unknown={sorted(unknown)}"
        )
    for field, expected_type in required.items():
        value = entry[field]
        if type(value) is not expected_type:
            raise SystemExit(f"negative entry {index} field {field} has the wrong type")
        if isinstance(value, str) and (not value or "\t" in value or "\n" in value):
            raise SystemExit(f"negative entry {index} field {field} must be one non-empty line")
    if entry["classification"] not in {"spec-mutation", "claim-witness"}:
        raise SystemExit(f"negative entry {index} has unsupported classification")
    if entry["length"] < 1 or entry["timeout_secs"] < 1:
        raise SystemExit(f"negative entry {index} has a non-positive bound")
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", entry["falsifies"]) is None:
        raise SystemExit(f"negative entry {index} has an invalid invariant name")
    spec_relative = Path(entry["spec"])
    cfg_relative = Path(entry["cfg"])
    if (
        spec_relative.is_absolute()
        or spec_relative.parent != negative_root
        or spec_relative.suffix != ".tla"
        or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", spec_relative.stem) is None
    ):
        raise SystemExit(
            f"negative entry {index} spec must be an identifier-named .tla file in {negative_root}"
        )
    name = spec_relative.stem
    if (
        cfg_relative.is_absolute()
        or cfg_relative.parent != negative_root
        or cfg_relative.suffix != ".cfg"
        or cfg_relative.name != f"MC{name}.cfg"
    ):
        raise SystemExit(
            f"negative entry {index} cfg must be {negative_root / f'MC{name}.cfg'}"
        )
    if entry["spec"] in seen_specs:
        raise SystemExit(f"negative registry repeats spec: {entry['spec']}")
    seen_specs.add(entry["spec"])
    if name in seen_names:
        raise SystemExit(f"negative registry repeats module name: {name}")
    seen_names.add(name)
    for field in ("spec", "cfg"):
        relative = Path(entry[field])
        if relative.is_absolute():
            raise SystemExit(f"negative entry {index} has invalid {field}: {entry[field]}")
        regular_repo_file(repo / relative, f"negative entry {index} {field}")
    config_text = (repo / entry["cfg"]).read_text(encoding="utf-8")
    config_without_comments = re.sub(r"(?m)\\\*.*$", "", config_text)
    invariant_directives = re.findall(
        r"(?m)^\s*INVARIANTS?\b.*$", config_without_comments
    )
    selected_invariants = re.findall(
        r"(?m)^\s*INVARIANT\s*$\n^\s*([A-Za-z_][A-Za-z0-9_]*)\s*$",
        config_without_comments,
    )
    if (
        len(invariant_directives) != 1
        or selected_invariants != [entry["falsifies"]]
    ):
        raise SystemExit(
            f"negative entry {index} config must select exactly {entry['falsifies']}"
        )
    if not any(f"`{entry['falsifies']}`" in row for row in mapping_rows):
        raise SystemExit(
            f"negative entry {index} falsifies an unmapped property: {entry['falsifies']}"
        )
    runtime_test = entry["runtime_test"]
    if runtime_test.startswith("n/a"):
        if NA_WITH_REASON.fullmatch(runtime_test) is None:
            raise SystemExit(
                f"negative entry {index} runtime_test n/a value must include one parenthesized reason"
            )
    else:
        runtime_match = RUST_TEST_ANCHOR.fullmatch(runtime_test)
        if runtime_match is None:
            raise SystemExit(f"negative entry {index} has an invalid runtime_test anchor")
        runtime_path = runtime_match.group("path")
        anchor = runtime_match.group("anchor")
        relative = Path(runtime_path)
        if relative.is_absolute():
            raise SystemExit(f"negative entry {index} has an invalid runtime_test anchor")
        source = regular_repo_file(repo / relative, f"negative entry {index} runtime test")
        source_text = source.read_text(encoding="utf-8")
        test_declaration = re.compile(
            rf"(?m)^[ \t]*#\[(?:[A-Za-z_][A-Za-z0-9_]*::)*test"
            rf"(?:\([^\]\n]*\))?\][ \t]*\n"
            rf"(?:[ \t]*#\[[^\]\n]+\][ \t]*\n)*"
            rf"[ \t]*(?:pub(?:\([^\n)]+\))?[ \t]+)?"
            rf"(?:async[ \t]+)?fn[ \t]+{re.escape(anchor)}[ \t]*\("
        )
        if test_declaration.search(source_text) is None:
            raise SystemExit(
                f"negative entry {index} runtime test anchor is not a Rust test declaration"
            )
    commit = entry["production_commit"]
    if commit.startswith("n/a"):
        if NA_WITH_REASON.fullmatch(commit) is None:
            raise SystemExit(
                f"negative entry {index} production_commit n/a value must include one parenthesized reason"
            )
    else:
        if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
            raise SystemExit(f"negative entry {index} production_commit must be a full SHA")
        object_type = subprocess.run(
            ["git", "cat-file", "-t", commit],
            cwd=repo,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if object_type.returncode != 0 or object_type.stdout.strip() != "commit":
            raise SystemExit(
                f"negative entry {index} production_commit is not a commit object"
            )
    print(
        "\t".join(
            str(entry[field])
            for field in ("spec", "cfg", "falsifies", "length", "timeout_secs")
        )
    )
PY

rm -rf -- "${output_root}"
mkdir -p "${output_root}"

failures=0
checked=0
while IFS=$'\t' read -r spec cfg falsifies length timeout_secs; do
  checked=$((checked + 1))
  name="$(basename "${spec}" .tla)"
  entry_root="${output_root}/${name}"
  input_dir="${entry_root}/input"
  out_dir="${entry_root}/out"
  run_dir="${entry_root}/run"
  log_file="${entry_root}/apalache.log"

  mkdir -p "${input_dir}" "${out_dir}" "${run_dir}"
  cp formal/apalache/*.tla "${input_dir}/"
  cp formal/tla/*.tla "${input_dir}/"
  cp "${spec}" "${input_dir}/$(basename "${spec}")"
  cp "${cfg}" "${input_dir}/$(basename "${cfg}")"

  set +e
  "${timeout_bin}" "${timeout_secs}" \
    "${apalache_bin}" \
    --out-dir="${out_dir}" \
    --run-dir="${run_dir}" \
    check \
    --no-deadlock \
    --output-traces \
    --length="${length}" \
    --config="${input_dir}/$(basename "${cfg}")" \
    "${input_dir}/$(basename "${spec}")" >"${log_file}" 2>&1
  exit_code=$?
  set -e

  if [[ "${exit_code}" -eq 124 ]]; then
    echo "NEGATIVE-TEST TIMEOUT: ${spec} exceeded ${timeout_secs}s" >&2
    failures=$((failures + 1))
    continue
  fi

  if [[ "${exit_code}" -ne 0 && "${exit_code}" -ne 12 ]]; then
    echo "NEGATIVE-TEST TOOL ERROR: ${spec} exited ${exit_code}, expected 0 or violation exit 12" >&2
    failures=$((failures + 1))
    continue
  fi

  set +e
  outcome="$(python3 scripts/lib/apalache_evidence.py \
    outcome "${log_file}" "${falsifies}")"
  log_validation_exit=$?
  set -e
  if [[ "${log_validation_exit}" -ne 0 ]]; then
    echo "NEGATIVE-TEST TOOL ERROR: ${spec} has invalid invariant or outcome evidence" >&2
    failures=$((failures + 1))
    continue
  fi

  if [[ "${exit_code}" -eq 0 ]]; then
    if [[ "${outcome}" == "NoError" ]]; then
      echo "NEGATIVE-TEST FAILURE: ${spec} reported NoError for ${falsifies}" >&2
    else
      echo "NEGATIVE-TEST TOOL ERROR: ${spec} exited 0 with outcome ${outcome}" >&2
    fi
    failures=$((failures + 1))
    continue
  fi

  if [[ "${outcome}" != "Error" ]]; then
    echo "NEGATIVE-TEST TOOL ERROR: ${spec} exited 12 with outcome ${outcome}" >&2
    failures=$((failures + 1))
    continue
  fi

  set +e
  trace="$(python3 scripts/lib/apalache_evidence.py trace "${run_dir}")"
  trace_discovery_exit=$?
  set -e
  if [[ "${trace_discovery_exit}" -ne 0 ]]; then
    echo "NEGATIVE-TEST TOOL ERROR: ${spec} did not produce exactly one ITF violation trace" >&2
    failures=$((failures + 1))
    continue
  fi

  if ! python3 scripts/lib/apalache_evidence.py validate-trace "${trace}"
  then
    echo "NEGATIVE-TEST TOOL ERROR: ${spec} produced an invalid ITF violation trace" >&2
    failures=$((failures + 1))
    continue
  fi

  echo "ok: ${spec} falsified ${falsifies} with $(basename "${trace}")"
done <"${entries_file}"

if [[ "${checked}" -eq 0 ]]; then
  echo "check-apalache-negative: registry yielded no entries" >&2
  exit 2
fi

if [[ "${failures}" -ne 0 ]]; then
  echo "check-apalache-negative: ${failures} of ${checked} entries failed" >&2
  exit 1
fi

echo "check-apalache-negative: ${checked} counterexamples reproduced"
echo "check-apalache-negative: artifacts at ${output_root}"
