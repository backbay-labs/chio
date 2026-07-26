#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
chio_bin="${1:-${repo_root}/target/debug/chio}"
fixtures="${repo_root}/crates/guards/chio-policy/tests/fixtures/analyze"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-policy-analysis-check.XXXXXX")"
trap 'rm -rf "${work_dir}"' EXIT

if [[ ! -x "${chio_bin}" ]]; then
    echo "policy analyzer binary is not executable: ${chio_bin}" >&2
    exit 2
fi

(
    cd "${repo_root}"
    cargo tree -p chio-cli --edges normal --prefix none
) >"${work_dir}/dependency-tree.txt"
if grep -Eq '^(z3|z3-sys|cvc5)( |$)' "${work_dir}/dependency-tree.txt"; then
    echo "an SMT solver entered the default chio-cli dependency tree" >&2
    exit 1
fi

run_case() {
    local expected="$1"
    local name="$2"
    shift 2
    set +e
    "${chio_bin}" policy analyze "$@" --format json \
        >"${work_dir}/${name}.json" 2>"${work_dir}/${name}.err"
    local actual=$?
    set -e
    if [[ "${actual}" -ne "${expected}" ]]; then
        echo "${name}: expected exit ${expected}, got ${actual}" >&2
        cat "${work_dir}/${name}.err" >&2
        exit 1
    fi
}

run_case 0 clean "${fixtures}/clean.yaml"
sed 's/      - shell\.exec/      - repo.read/' \
    "${fixtures}/clean.yaml" >"${work_dir}/mutated.yaml"
run_case 1 mutated "${work_dir}/mutated.yaml"
run_case 1 contradictory "${fixtures}/contradictory.yaml"
run_case 1 widened --against "${fixtures}/old.yaml" "${fixtures}/new-widened.yaml"
run_case 0 narrowed --against "${fixtures}/old.yaml" "${fixtures}/new-narrowed.yaml"
run_case 2 invalid "${fixtures}/invalid.yaml"
run_case 2 atom-limit --max-atoms 1 "${fixtures}/new-widened.yaml"

{
    printf "hushspec: '0.1.0'\nrules:\n  tool_access:\n    enabled: true\n    allow:\n"
    for ((index = 0; index < 250; index++)); do
        printf '      - allow-%s\n' "${index}"
    done
    printf '    block:\n'
    for ((index = 0; index < 250; index++)); do
        printf '      - block-%s\n' "${index}"
    done
    printf '    default: block\n'
} >"${work_dir}/work-limit.yaml"
run_case 2 work-limit --max-atoms 500 "${work_dir}/work-limit.yaml"

for policy in "${repo_root}"/crates/guards/chio-policy/src/rulesets/*.yaml; do
    name="ruleset-$(basename "${policy}" .yaml)"
    run_case 0 "${name}" --fail-on warning "${policy}"
done

python3 - "${work_dir}" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])

def report(name):
    return json.loads((root / f"{name}.json").read_text())

for name in ("clean", "mutated", "contradictory", "widened", "narrowed"):
    if report(name).get("schema") != "chio.policy-analysis.v1":
        raise SystemExit(f"{name}: wrong analysis schema")

kinds = {finding["kind"] for finding in report("contradictory")["findings"]}
if not {"contradiction", "unreachable_rule"}.issubset(kinds):
    raise SystemExit("contradictory: calibrated findings were not detected")

mutated_kinds = {finding["kind"] for finding in report("mutated")["findings"]}
if "contradiction" not in mutated_kinds:
    raise SystemExit("mutated: allow/block collision survived analysis")

widened = report("widened")
if widened.get("refinement", {}).get("status") != "does_not_refine":
    raise SystemExit("widened: expected a non-refinement verdict")
failures = [
    finding for finding in widened["findings"]
    if finding["kind"] == "refinement_failure"
]
if len(failures) != 1 or not failures[0].get("witness"):
    raise SystemExit("widened: expected one concrete refinement witness")

if report("narrowed").get("refinement", {}).get("status") != "refines":
    raise SystemExit("narrowed: expected a refinement verdict")

for name in ("invalid", "atom-limit", "work-limit"):
    payload = json.loads((root / f"{name}.err").read_text())
    if payload.get("schema") != "chio.policy-analysis.error.v1" or not payload.get("error"):
        raise SystemExit(f"{name}: missing fail-closed error envelope")
work_limit_error = json.loads((root / "work-limit.err").read_text())["error"]
if "matcher comparisons" not in work_limit_error:
    raise SystemExit("work-limit: wrong aggregate-budget error")
PY

echo "Policy analysis self-check passed"
