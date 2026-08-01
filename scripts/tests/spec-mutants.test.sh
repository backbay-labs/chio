#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp_dir="$(mktemp -d)"
run_root="${repo_root}/target/formal/spec-mutants-selftest-$$"
report_path="${repo_root}/target/formal/spec-mutants-selftest-report-$$.json"
dirty_marker_rel=".spec-mutants-selftest-dirty-$$"
dirty_marker="${repo_root}/${dirty_marker_rel}"

cleanup() {
  rm -rf "${tmp_dir}" "${run_root}"
  rm -f "${report_path}" "${dirty_marker}"
}
trap cleanup EXIT

cd "${repo_root}"

python3 scripts/spec-mutants.py --list >"${tmp_dir}/list-one.json"
python3 scripts/spec-mutants.py --list >"${tmp_dir}/list-two.json"
cmp "${tmp_dir}/list-one.json" "${tmp_dir}/list-two.json"

python3 - "${tmp_dir}/list-one.json" <<'PY'
import json
from pathlib import Path
import tomllib
import sys

mutants = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
allowlist = tomllib.loads(
    Path("formal/apalache/spec-mutants-allowlist.toml").read_text(encoding="utf-8")
)
allowed = {
    spec["name"]: set(spec["actions"])
    for spec in allowlist["spec"]
}
if len(mutants) < 16:
    raise SystemExit("the allowlist enumerated fewer than 16 mutants")
if len({mutant["id"] for mutant in mutants}) != len(mutants):
    raise SystemExit("mutant identifiers are not unique")
for mutant in mutants:
    if mutant["action"] not in allowed[mutant["spec"]]:
        raise SystemExit(f"non-allowlisted action mutated: {mutant}")
    if mutant["action"] in {"Init", "Next", mutant["invariant"]}:
        raise SystemExit(f"protected operator mutated: {mutant}")
    if len(mutant["source_sha256"]) != 64:
        raise SystemExit(f"source hash is malformed: {mutant}")
seeds = {
    mutant.get("registered_seed")
    for mutant in mutants
    if "registered_seed" in mutant
}
if seeds != {"receipt-before-allow-guard", "revocation-transitive-cut"}:
    raise SystemExit(f"registered seed coverage mismatch: {seeds}")
if {mutant["classification"] for mutant in mutants} - {
    "guard-weakening",
    "post-state-corruption",
    "historical-regression",
}:
    raise SystemExit("mutation inventory contains an unclassified probe")
PY

python3 - <<'PY'
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile

script = Path("scripts/spec-mutants.py").resolve()
module_spec = importlib.util.spec_from_file_location("spec_mutants", script)
module = importlib.util.module_from_spec(module_spec)
assert module_spec.loader is not None
sys.modules[module_spec.name] = module
module_spec.loader.exec_module(module)

ci_names = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_RUN_NUMBER")
for name in ci_names:
    os.environ.pop(name, None)
if module.ci_run_evidence() is not None:
    raise SystemExit("local specification run unexpectedly has CI identity")
os.environ.update(
    GITHUB_RUN_ID="101",
    GITHUB_RUN_ATTEMPT="2",
    GITHUB_RUN_NUMBER="303",
)
if module.ci_run_evidence() != {
    "run_id": 101,
    "run_attempt": 2,
    "run_number": 303,
}:
    raise SystemExit("specification run identity was not parsed exactly")
os.environ.pop("GITHUB_RUN_ATTEMPT")
try:
    module.ci_run_evidence()
except module.MutationError:
    pass
else:
    raise SystemExit("partial specification run identity was accepted")
for name in ci_names:
    os.environ.pop(name, None)

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    model = root / "Synthetic.tla"
    cfg = root / "MCSynthetic.cfg"
    model.write_text(
        "---------------- MODULE Synthetic ----------------\n"
        "VARIABLE x\n"
        "Init ==\n"
        "  x = 0\n"
        "Action ==\n"
        "  /\\ x = 0\n"
        "  /\\ x' = 1\n"
        "Hidden ==\n"
        "  /\\ x = 0\n"
        "  /\\ x' = 2\n"
        "Protected ==\n"
        "  x = 0\n"
        "Next ==\n"
        "  Action \\/ Hidden\n"
        "SafetyInv ==\n"
        "  Protected\n"
        "===================================================\n",
        encoding="utf-8",
    )
    cfg.write_text("SPECIFICATION Spec\n\nINVARIANT\n  SafetyInv\n", encoding="utf-8")
    config = module.SpecConfig(
        "Synthetic",
        Path("Synthetic.tla"),
        Path("MCSynthetic.cfg"),
        "SafetyInv",
        4,
        ("Action",),
    )
    probe = module.ProbeConfig(
        "synthetic-action-guard",
        "Synthetic",
        "Action",
        "delete_conjunct",
        "/\\ x = 0",
        "",
        "guard-weakening",
        "The action guard constrains the synthetic transition.",
    )
    mutants, _ = module.enumerate_spec_mutations(root, config, (probe,), ())
    if not mutants or {mutant.action for mutant in mutants} != {"Action"}:
        raise SystemExit("synthetic rule-zero fixture escaped its allowlist")
    model.chmod(0o444)
    copied_spec, _ = module.copy_model_inputs(
        root,
        mutants[0],
        root / "read-only-source-copy",
        module.apply_mutation(root, mutants[0]),
    )
    if copied_spec.read_text(encoding="utf-8") == model.read_text(encoding="utf-8"):
        raise SystemExit("read-only source mutation copy did not contain the mutant")

    protected = module.SpecConfig(
        "Synthetic",
        Path("Synthetic.tla"),
        Path("MCSynthetic.cfg"),
        "SafetyInv",
        4,
        ("Protected",),
    )
    try:
        module.enumerate_spec_mutations(root, protected, (probe,), ())
    except module.MutationError:
        pass
    else:
        raise SystemExit("property dependency was accepted as a mutable action")

    short_log = root / "short.log"
    short_run = root / "short-run"
    short_run.mkdir()
    short_log.write_text(
        "> Set an invariant to SafetyInv\n"
        "The outcome is: ExecutionsTooShort\n"
        "Checker reports no error up to computation length 4\n",
        encoding="utf-8",
    )
    verdict, trace = module.classify_completed_run(
        log_path=short_log,
        expected_invariant="SafetyInv",
        expected_length=4,
        exit_code=0,
        run_root=short_run,
    )
    if verdict != "survived" or trace is not None:
        raise SystemExit("short no-error execution was not classified as survived")
    try:
        module.classify_completed_run(
            log_path=short_log,
            expected_invariant="SafetyInv",
            expected_length=4,
            exit_code=0,
            run_root=short_run,
            allow_executions_too_short=False,
        )
    except module.EvidenceError as error:
        if "clean positive baseline" not in str(error):
            raise
    else:
        raise SystemExit("short execution established a clean positive baseline")

root = Path.cwd().resolve()
settings = module.load_settings(root, module.DEFAULT_ALLOWLIST)
if settings.baseline_timeout_secs < 10800:
    raise SystemExit("positive baseline timeout is below the safety-lane bound")
invalid_allowlist = Path("target/formal/spec-mutants-invalid-baseline-timeout.toml")
invalid_allowlist.parent.mkdir(parents=True, exist_ok=True)
invalid_allowlist.write_text(
    (root / module.DEFAULT_ALLOWLIST)
    .read_text(encoding="utf-8")
    .replace("baseline_timeout_secs = 10800", "baseline_timeout_secs = 299"),
    encoding="utf-8",
)
try:
    try:
        module.load_settings(root, invalid_allowlist)
    except module.MutationError:
        pass
    else:
        raise SystemExit("baseline timeout below the mutant timeout was accepted")
finally:
    invalid_allowlist.unlink(missing_ok=True)
inventory, _ = module.enumerate_mutations(root, settings)
if len(module.inventory_sha256(inventory)) != 64:
    raise SystemExit("specification inventory digest is malformed")
first, first_seed = module.select_mutations(
    inventory, commit="a" * 40, sample_size=16, full=False, sample_epoch=1
)
second, second_seed = module.select_mutations(
    inventory, commit="a" * 40, sample_size=16, full=False, sample_epoch=2
)
if first_seed != second_seed or [item.id for item in first] == [item.id for item in second]:
    raise SystemExit("specification mutation sample epochs did not rotate the sample")
expected_sources = {item.spec for item in inventory}
expected_seeds = {item.seed for item in inventory if item.seed is not None}
for sample in (first, second):
    if {item.spec for item in sample} != expected_sources:
        raise SystemExit("stratified sample omitted a specification source")
    if {item.seed for item in sample if item.seed is not None} != expected_seeds:
        raise SystemExit("stratified sample omitted a registered seed")
    for source in expected_sources:
        if not any(item.spec == source and item.seed is None for item in sample):
            raise SystemExit(f"stratified sample omitted a non-seed probe for {source}")
cycle = {
    item.id
    for epoch in range(len(inventory))
    for item in module.select_mutations(
        inventory, commit="a" * 40, sample_size=16, full=False, sample_epoch=epoch
    )[0]
}
if cycle != {item.id for item in inventory}:
    raise SystemExit("specification mutation epochs did not cover the full inventory")

scored_results = [
    {"spec": source, "verdict": "killed"}
    for source in sorted(expected_sources)
]
scored_results.extend(
    {"spec": "DelegationDepthBound", "verdict": "killed"}
    for _ in range(12)
)
scored_results.append({"spec": "ReceiptBeforeAllow", "verdict": "survived"})
aggregate, source_aggregates = module.aggregate_scores(
    scored_results, settings.specs, 90.0
)
if aggregate["activation_ratio_percent"] < 90.0:
    raise SystemExit("source-score fixture did not meet the global target")
if aggregate["activation_met"] or aggregate["source_activation_met"]:
    raise SystemExit("a weak source was hidden by the global activation score")
if source_aggregates["ReceiptBeforeAllow"]["activation_met"]:
    raise SystemExit("weak source aggregate unexpectedly met the target")

with tempfile.TemporaryDirectory() as external:
    sentinel = Path(external) / "sentinel"
    sentinel.write_text("preserve", encoding="utf-8")
    link = root / "target/formal/spec-mutants-symlink-selftest"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(external, target_is_directory=True)
    try:
        try:
            module.resolve_output_root(root, str(link))
        except module.MutationError:
            pass
        else:
            raise SystemExit("symlinked specification mutation output was accepted")
        if sentinel.read_text(encoding="utf-8") != "preserve":
            raise SystemExit("symlink safety fixture was modified")
    finally:
        link.unlink(missing_ok=True)

    output = (root / "target/formal/spec-mutants-report-path-output").resolve()
    report_link = root / "target/formal/spec-mutants-report-path-link.json"
    report_link.symlink_to(sentinel)
    try:
        try:
            module.resolve_report_path(root, output, str(report_link))
        except module.MutationError:
            pass
        else:
            raise SystemExit("symlinked specification mutation report was accepted")
        if sentinel.read_text(encoding="utf-8") != "preserve":
            raise SystemExit("report symlink safety fixture was modified")
    finally:
        report_link.unlink(missing_ok=True)

with tempfile.TemporaryDirectory() as temporary:
    drift_root = Path(temporary)

    def git(*arguments: str) -> None:
        subprocess.run(
            ["git", *arguments],
            cwd=drift_root,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    git("init", "--quiet")
    git("config", "user.name", "Mutation Selftest")
    git("config", "user.email", "mutation-selftest@example.invalid")
    (drift_root / ".gitignore").write_text("ignored-*.txt\n", encoding="utf-8")
    unrelated = drift_root / "unrelated.txt"
    unrelated.write_text("stable\n", encoding="utf-8")
    evidence = drift_root / "ignored-evidence.txt"
    evidence.write_text("captured\n", encoding="utf-8")
    extra = drift_root / "ignored-extra.txt"
    extra.write_text("extra\n", encoding="utf-8")
    git("add", ".gitignore", "unrelated.txt")
    git("commit", "--quiet", "-m", "test: initialize drift fixture")

    snapshot = module.capture_execution_snapshot(
        drift_root, [Path("ignored-evidence.txt")], allow_dirty=True
    )
    module.verify_execution_snapshot(
        drift_root, snapshot, [Path("ignored-evidence.txt")], allow_dirty=True
    )
    if snapshot.report_inputs()[0]["sha256"] != module.sha256_file(evidence):
        raise SystemExit("specification snapshot did not retain its starting input hash")
    with module.materialized_execution_root(drift_root, snapshot) as frozen_root:
        frozen_evidence = frozen_root / "ignored-evidence.txt"
        evidence.write_text("transient main-tree edit\n", encoding="utf-8")
        if frozen_evidence.read_text(encoding="utf-8") != "captured\n":
            raise SystemExit("specification source snapshot followed a main-tree edit")
        if frozen_evidence.stat().st_mode & 0o222:
            raise SystemExit("specification source snapshot input remained writable")
        evidence.write_text("captured\n", encoding="utf-8")

    evidence.write_text("drifted\n", encoding="utf-8")
    try:
        module.verify_execution_snapshot(
            drift_root, snapshot, [Path("ignored-evidence.txt")], allow_dirty=True
        )
    except module.MutationError as error:
        if "evidence inputs drifted" not in str(error):
            raise
    else:
        raise SystemExit("specification input drift was accepted")
    evidence.write_text("captured\n", encoding="utf-8")

    try:
        module.verify_execution_snapshot(
            drift_root,
            snapshot,
            [Path("ignored-evidence.txt"), Path("ignored-extra.txt")],
            allow_dirty=True,
        )
    except module.MutationError as error:
        if "input path set drifted" not in str(error):
            raise
    else:
        raise SystemExit("specification input path-set drift was accepted")

    unrelated.write_text("dirty\n", encoding="utf-8")
    dirty_snapshot = module.capture_execution_snapshot(
        drift_root, [Path("ignored-evidence.txt")], allow_dirty=True
    )
    if dirty_snapshot.worktree.get("clean") is not False:
        raise SystemExit("allow-dirty snapshot did not preserve dirty evidence")
    module.verify_execution_snapshot(
        drift_root,
        dirty_snapshot,
        [Path("ignored-evidence.txt")],
        allow_dirty=True,
    )
    unrelated.write_text("stable\n", encoding="utf-8")
    clean_snapshot = module.capture_execution_snapshot(
        drift_root, [Path("ignored-evidence.txt")], allow_dirty=True
    )
    unrelated.write_text("committed drift\n", encoding="utf-8")
    try:
        module.verify_execution_snapshot(
            drift_root,
            clean_snapshot,
            [Path("ignored-evidence.txt")],
            allow_dirty=True,
        )
    except module.MutationError as error:
        if "worktree drifted" not in str(error):
            raise
    else:
        raise SystemExit("specification worktree drift was accepted")
    git("add", "unrelated.txt")
    git("commit", "--quiet", "-m", "test: move drift fixture head")
    try:
        module.verify_execution_snapshot(
            drift_root,
            clean_snapshot,
            [Path("ignored-evidence.txt")],
            allow_dirty=True,
        )
    except module.MutationError as error:
        if "Git HEAD drifted" not in str(error):
            raise
    else:
        raise SystemExit("specification Git HEAD drift was accepted")
PY

fake_apalache="${tmp_dir}/apalache-mc"
cat >"${fake_apalache}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "version" ]]; then
  printf '%s\n' "0.50.1"
  exit 0
fi

run_dir=""
config=""
spec=""
length=""
for argument in "$@"; do
  case "${argument}" in
    --run-dir=*) run_dir="${argument#--run-dir=}" ;;
    --config=*) config="${argument#--config=}" ;;
    --length=*) length="${argument#--length=}" ;;
    *.tla) spec="${argument}" ;;
  esac
done
invariant="$(awk '
  found { print $1; exit }
  /^[[:space:]]*INVARIANT[[:space:]]*$/ { found = 1 }
' "${config}")"
printf '%s\n' "> Set an invariant to ${invariant}"

if [[ -n "${FAKE_APALACHE_CALL_LOG:-}" ]]; then
  printf '%s\n' "${spec}" >>"${FAKE_APALACHE_CALL_LOG}"
fi

is_negative=0
if [[ "${spec}" == */registered-negative/* ]]; then
  is_negative=1
fi
is_baseline=0
if [[ "${spec}" == */positive-baselines/* ]]; then
  is_baseline=1
fi

if [[ "${is_negative}" -eq 0 && "${is_baseline}" -eq 1 && "${FAKE_BASELINE_OUTCOME:-noerror}" != "error" ]]; then
  if [[ "${FAKE_BASELINE_OUTCOME:-noerror}" == "short" ]]; then
    printf '%s\n' "The outcome is: ExecutionsTooShort"
  else
    printf '%s\n' "The outcome is: NoError"
  fi
  printf '%s\n' "Checker reports no error up to computation length ${length}"
  exit 0
fi

if [[ "${is_negative}" -eq 0 && "${is_baseline}" -eq 0 && "${FAKE_MUTANT_OUTCOME:-error}" == "noerror" ]]; then
  printf '%s\n' "The outcome is: NoError"
  printf '%s\n' "Checker reports no error up to computation length ${length}"
  exit 0
fi

if [[ "${is_negative}" -eq 0 && "${is_baseline}" -eq 0 && "${FAKE_MUTANT_OUTCOME:-error}" == "unviable" ]]; then
  printf '%s\n' "Typing error: replacement changed the expression type"
  exit 1
fi

mkdir -p "${run_dir}"
printf '%s\n' '{"#meta":{"format":"ITF","varTypes":{"witness":"Bool"}},"params":[],"vars":["witness"],"states":[{"#meta":{"index":0},"witness":false}]}' \
  >"${run_dir}/violation1.itf.json"
printf '%s\n' "The outcome is: Error"
printf '%s\n' "State 1: state invariant 0 violated."
printf '%s\n' "Checker has found an error"
exit 12
SH
chmod +x "${fake_apalache}"

printf '%s\n' "spec-mutants dirty-worktree self-test" >"${dirty_marker}"
marker_status="$(git status --porcelain=v1 --untracked-files=normal -- "${dirty_marker_rel}")"
if [[ "${marker_status}" != "?? ${dirty_marker_rel}" ]]; then
  echo "dirty-worktree marker is not an explicit nonignored untracked file: ${marker_status}" >&2
  exit 1
fi

set +e
APALACHE_BIN="${fake_apalache}" \
CHIO_SPEC_MUTANTS_OUTPUT_ROOT="${run_root}" \
CHIO_SPEC_MUTANTS_REPORT="${report_path}" \
  python3 scripts/spec-mutants.py --sample-from-head >"${tmp_dir}/dirty-rejected.log" 2>&1
dirty_exit=$?
set -e
if [[ "${dirty_exit}" -ne 2 ]]; then
  echo "expected dirty specification mutation execution to exit 2, found ${dirty_exit}" >&2
  exit 1
fi
grep -Fq "requires a clean worktree" "${tmp_dir}/dirty-rejected.log"

env -u CHIO_MUTATION_SAMPLE_EPOCH \
  APALACHE_BIN="${fake_apalache}" \
  CHIO_SPEC_MUTANTS_OUTPUT_ROOT="${run_root}" \
  CHIO_SPEC_MUTANTS_REPORT="${report_path}" \
  python3 scripts/spec-mutants.py --sample-from-head --allow-dirty

python3 - "${report_path}" <<'PY'
import json
from pathlib import Path
import re
import sys
import tomllib

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if report["schema"] != "chio.spec-mutants-report.v1":
    raise SystemExit("report schema mismatch")
if report["aggregate"]["sampled"] != 16:
    raise SystemExit("nightly sample is not exactly 16")
if report["aggregate"]["activation_ratio_percent"] != 100.0:
    raise SystemExit("all-killed fixture did not activate")
if report["aggregate"]["timeout_policy"] != "timeouts count as not killed":
    raise SystemExit("timeout scoring policy is missing")
if report["bounds"].get("positive_baseline_timeout_secs") != 10800:
    raise SystemExit("positive baseline timeout is absent from report bounds")
if not report["aggregate"]["global_activation_met"]:
    raise SystemExit("global activation result is missing")
if set(report["source_aggregates"]) != {
    "DelegationDepthBound",
    "KernelTransitionCancelSafe",
    "MonotoneLogApalache",
    "PostAdmissionDropGuard",
    "ReceiptBeforeAllow",
    "RevocationCutCompleteness",
    "RevocationPropagation",
}:
    raise SystemExit("report source aggregates do not cover every specification")
if not all(entry["activation_met"] for entry in report["source_aggregates"].values()):
    raise SystemExit("all-killed fixture has a weak source aggregate")
allowlist = tomllib.loads(
    Path("formal/apalache/spec-mutants-allowlist.toml").read_text(encoding="utf-8")
)
expected_baselines = {entry["name"]: entry for entry in allowlist["spec"]}
baselines = report.get("positive_baselines")
if not isinstance(baselines, list) or len(baselines) != len(expected_baselines):
    raise SystemExit("positive baseline evidence does not cover every specification")
baseline_fields = {
    "spec",
    "path",
    "cfg",
    "invariant",
    "length",
    "verdict",
    "apalache_exit",
    "wall_secs",
    "log_sha256",
}
if {entry["spec"] for entry in baselines} != set(expected_baselines):
    raise SystemExit("positive baseline evidence has the wrong specification set")
for baseline in baselines:
    expected = expected_baselines[baseline["spec"]]
    if set(baseline) != baseline_fields:
        raise SystemExit(f"positive baseline has the wrong fields: {baseline}")
    if (
        baseline["path"] != expected["path"]
        or baseline["cfg"] != expected["cfg"]
        or baseline["invariant"] != expected["invariant"]
        or baseline["length"] != expected["length"]
        or baseline["verdict"] != "survived"
        or baseline["apalache_exit"] != 0
        or not isinstance(baseline["wall_secs"], (int, float))
        or baseline["wall_secs"] < 0
        or len(baseline["log_sha256"]) != 64
    ):
        raise SystemExit(f"positive baseline evidence is invalid: {baseline}")
baseline_commands = [
    (index, entry)
    for index, entry in enumerate(report["commands"])
    if entry.get("kind") == "clean-baseline"
]
if len(baseline_commands) != len(expected_baselines):
    raise SystemExit("report omitted clean-baseline commands")
if {entry["spec"] for _, entry in baseline_commands} != set(expected_baselines):
    raise SystemExit("clean-baseline commands have the wrong specification set")
for _, entry in baseline_commands:
    command = entry["argv"]
    if (
        entry["exit_code"] != 0
        or len(entry["log_sha256"]) != 64
        or "--no-deadlock" not in command
        or "--output-traces" not in command
        or not any(value.startswith("--length=") for value in command)
        or not any(value.startswith("--config=") for value in command)
        or not any("/positive-baselines/" in value for value in command)
    ):
        raise SystemExit(f"clean-baseline command is incomplete: {entry}")
mutant_indexes = [
    index for index, entry in enumerate(report["commands"]) if "mutant_id" in entry
]
if not mutant_indexes or max(index for index, _ in baseline_commands) >= min(mutant_indexes):
    raise SystemExit("a generated mutation ran before all positive baselines")
registered = tomllib.loads(
    Path("formal/apalache/_negative_tests/REGISTRY.toml").read_text(encoding="utf-8")
)["negative"]
if len(report["registered_negative"]) != len(registered):
    raise SystemExit("registered negative preflight did not cover every entry")
if not all(len(entry.get("trace_sha256", "")) == 64 for entry in report["registered_negative"]):
    raise SystemExit("registered negative preflight omitted trace hashes")
if not report["commands"] or not report["inputs"] or not report["bounds"]["specs"]:
    raise SystemExit("report omitted commands, input hashes, or bounds")
mutant_commands = [entry["argv"] for entry in report["commands"] if "mutant_id" in entry]
if not mutant_commands or any("--no-deadlock" not in command for command in mutant_commands):
    raise SystemExit("generated mutation commands do not isolate invariant checking")
input_paths = {entry["path"] for entry in report["inputs"]}
if "formal/MAPPING.md" not in input_paths or "formal/apalache/_negative_tests/REGISTRY.toml" not in input_paths:
    raise SystemExit("report omitted negative-preflight inputs")
if report["tools"]["apalache"] != "0.50.1":
    raise SystemExit("report omitted the exact Apalache version")
if report["worktree"]["clean"] is not False:
    raise SystemExit("dirty self-test execution was not identified in the report")
for field in ("status_sha256", "tracked_diff_sha256"):
    if re.fullmatch(r"[0-9a-f]{64}", report["worktree"].get(field, "")) is None:
        raise SystemExit(f"dirty self-test report has malformed {field} evidence")
if report["sample_epoch"] != 0:
    raise SystemExit("default sample epoch changed")
if len(report.get("measured_at", "")) != 20 or not report["measured_at"].endswith("Z"):
    raise SystemExit("report omitted its UTC completion time")
PY

rm -rf "${run_root}"
rm -f "${report_path}"
baseline_call_log="${tmp_dir}/baseline-failure-calls.log"
set +e
FAKE_BASELINE_OUTCOME=error \
FAKE_APALACHE_CALL_LOG="${baseline_call_log}" \
APALACHE_BIN="${fake_apalache}" \
CHIO_SPEC_MUTANTS_OUTPUT_ROOT="${run_root}" \
CHIO_SPEC_MUTANTS_REPORT="${report_path}" \
  python3 scripts/spec-mutants.py --sample-from-head --allow-dirty >"${tmp_dir}/baseline-failed.log" 2>&1
baseline_exit=$?
set -e
if [[ "${baseline_exit}" -ne 2 ]]; then
  echo "expected a failing positive baseline to exit 2, found ${baseline_exit}" >&2
  exit 1
fi
grep -Fq "positive baseline" "${tmp_dir}/baseline-failed.log"
grep -Fq "did not survive its configured invariant" "${tmp_dir}/baseline-failed.log"
if [[ -e "${report_path}" ]]; then
  echo "failing positive baseline produced promotable evidence" >&2
  exit 1
fi
if grep -Fq "/generated/" "${baseline_call_log}"; then
  echo "generated mutation scoring started after a failing positive baseline" >&2
  exit 1
fi

rm -rf "${run_root}"
rm -f "${report_path}" "${baseline_call_log}"
set +e
FAKE_BASELINE_OUTCOME=short \
FAKE_APALACHE_CALL_LOG="${baseline_call_log}" \
APALACHE_BIN="${fake_apalache}" \
CHIO_SPEC_MUTANTS_OUTPUT_ROOT="${run_root}" \
CHIO_SPEC_MUTANTS_REPORT="${report_path}" \
  python3 scripts/spec-mutants.py --sample-from-head --allow-dirty >"${tmp_dir}/baseline-short.log" 2>&1
baseline_short_exit=$?
set -e
if [[ "${baseline_short_exit}" -ne 2 ]]; then
  echo "expected a short positive baseline to exit 2, found ${baseline_short_exit}" >&2
  exit 1
fi
grep -Fq "ExecutionsTooShort cannot establish a clean positive baseline" "${tmp_dir}/baseline-short.log"
if [[ -e "${report_path}" ]]; then
  echo "short positive baseline produced promotable evidence" >&2
  exit 1
fi
if grep -Fq "/generated/" "${baseline_call_log}"; then
  echo "generated mutation scoring started after a short positive baseline" >&2
  exit 1
fi

rm -rf "${run_root}"
set +e
FAKE_MUTANT_OUTCOME=noerror \
APALACHE_BIN="${fake_apalache}" \
CHIO_SPEC_MUTANTS_OUTPUT_ROOT="${run_root}" \
CHIO_SPEC_MUTANTS_REPORT="${report_path}" \
  python3 scripts/spec-mutants.py --sample-from-head --allow-dirty >"${tmp_dir}/survived.log" 2>&1
survived_exit=$?
set -e
if [[ "${survived_exit}" -ne 1 ]]; then
  echo "expected a below-target sample to exit 1, found ${survived_exit}" >&2
  exit 1
fi
python3 - "${report_path}" <<'PY'
import json
from pathlib import Path
import sys

aggregate = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["aggregate"]
if aggregate["survived"] != 16 or aggregate["activation_met"] is not False:
    raise SystemExit("surviving-mutant fixture was not scored below target")
PY

rm -f "${report_path}"
set +e
FAKE_MUTANT_OUTCOME=unviable \
APALACHE_BIN="${fake_apalache}" \
CHIO_SPEC_MUTANTS_OUTPUT_ROOT="${run_root}" \
CHIO_SPEC_MUTANTS_REPORT="${report_path}" \
  python3 scripts/spec-mutants.py --sample-from-head --allow-dirty >"${tmp_dir}/unviable.log" 2>&1
unviable_exit=$?
set -e
if [[ "${unviable_exit}" -ne 2 ]]; then
  echo "expected an unviable curated probe to exit 2, found ${unviable_exit}" >&2
  exit 1
fi
grep -Fq "is not type-valid Apalache input" "${tmp_dir}/unviable.log"
if [[ -e "${report_path}" ]]; then
  echo "unviable curated probe produced promotable evidence" >&2
  exit 1
fi

echo "PASS: spec mutation enumeration, rule zero, evidence, and scoring"
