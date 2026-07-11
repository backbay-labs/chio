#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
mkdir -p "${tmp_dir}/bin"

config="${tmp_dir}/releases.toml"
cat >"${config}" <<'TOML'
[gates.scheduled]
workflow = "nightly.yml"
job = "target job"
event = "schedule"
posture = "advisory"
required_streak = 2
evidence_after_run_id = 100
max_age_hours = 48

[gates.strict]
workflow = "nightly.yml"
job = "strict job"
event = "schedule"
posture = "advisory"
required_streak = 2
evidence_after_run_id = 100
max_age_hours = 48
strict_mode_required = true
strict_artifact_prefix = "formal-proof-report-strict-"

[gates.pull-request]
workflow = "formal-pr-smoke.yml"
job = "pull request job"
event = "pull_request"
posture = "advisory"
required_streak = 2
evidence_after_run_id = 200
max_age_hours = 168
base_branch = "target"
execution_artifact_prefix = "lane-executed-pull-request-"

[gates.frozen]
workflow = "temporal.yml"
job = "temporal job"
event = "schedule"
posture = "advisory"
required_streak = 2
evidence_after_run_id = 100
max_age_hours = 48
frozen = true
frozen_reason = "property is not reliable"
TOML

cat >"${tmp_dir}/bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${MOCK_GH_LOG}"
case "${MOCK_GH_ERROR:-none}" in
  rate-limit)
    printf '%s\n' "API rate limit exceeded" >&2
    exit 1
    ;;
  transport)
    printf '%s\n' "could not resolve host api.github.com" >&2
    exit 1
    ;;
  not-found)
    printf '%s\n' "HTTP 404: Not Found" >&2
    exit 1
    ;;
  malformed)
    printf '%s\n' '{not-json'
    exit 0
    ;;
  none) ;;
  *)
    printf 'unknown MOCK_GH_ERROR: %s\n' "${MOCK_GH_ERROR}" >&2
    exit 2
    ;;
esac
endpoint="${*: -1}"
case "${endpoint}" in
  *'/actions/workflows/nightly.yml/runs?'*)
    timestamp="${MOCK_RUN_TIMESTAMP:-2026-07-10T10:00:00Z}"
    printf '%s\n' "{\"workflow_runs\":[
  {\"id\":105,\"run_attempt\":2,\"event\":\"schedule\",\"conclusion\":\"success\",\"created_at\":\"${timestamp}\",\"html_url\":\"https://example.invalid/105\"},
  {\"id\":104,\"run_attempt\":2,\"event\":\"schedule\",\"conclusion\":\"success\",\"created_at\":\"2026-07-10T09:00:00Z\",\"html_url\":\"https://example.invalid/104\"},
  {\"id\":103,\"run_attempt\":1,\"event\":\"workflow_dispatch\",\"conclusion\":\"success\",\"created_at\":\"2026-07-10T08:00:00Z\",\"html_url\":\"https://example.invalid/103\"},
  {\"id\":102,\"run_attempt\":1,\"event\":\"schedule\",\"conclusion\":\"failure\",\"created_at\":\"2026-07-10T07:00:00Z\",\"html_url\":\"https://example.invalid/102\"},
  {\"id\":99,\"run_attempt\":1,\"event\":\"schedule\",\"conclusion\":\"success\",\"created_at\":\"2026-07-10T06:00:00Z\",\"html_url\":\"https://example.invalid/99\"}
]}"
    ;;
  *'/actions/workflows/formal-pr-smoke.yml/runs?'*)
    cat <<'JSON'
{"workflow_runs":[
  {"id":203,"run_attempt":1,"event":"pull_request","conclusion":"success","created_at":"2026-07-10T10:30:00Z","html_url":"https://example.invalid/203","pull_requests":[{"base":{"ref":"other"}}]},
  {"id":202,"run_attempt":3,"event":"pull_request","conclusion":"success","created_at":"2026-07-10T10:00:00Z","html_url":"https://example.invalid/202","pull_requests":[{"base":{"ref":"target"}}]},
  {"id":201,"run_attempt":1,"event":"workflow_dispatch","conclusion":"success","created_at":"2026-07-10T09:00:00Z","html_url":"https://example.invalid/201"}
]}
JSON
    ;;
  *'/actions/workflows/temporal.yml/runs?'*)
    printf '%s\n' '{"workflow_runs":[]}'
    ;;
  *'/actions/runs/105/jobs?'*)
    printf '%s\n' "{\"jobs\":[
  {\"name\":\"other job\",\"run_attempt\":2,\"conclusion\":\"failure\"},
  {\"name\":\"target job\",\"run_attempt\":${MOCK_JOB_ATTEMPT:-2},\"conclusion\":\"${MOCK_TARGET_CONCLUSION:-success}\"},
  {\"name\":\"strict job\",\"run_attempt\":2,\"conclusion\":\"success\"}
]}"
    ;;
  *'/actions/runs/104/jobs?'*)
    printf '%s\n' '{"jobs":[{"name":"target job","run_attempt":2,"conclusion":"success"},{"name":"strict job","run_attempt":2,"conclusion":"success"}]}'
    ;;
  *'/actions/runs/102/jobs?'*)
    printf '%s\n' '{"jobs":[{"name":"target job","run_attempt":1,"conclusion":"failure"},{"name":"strict job","run_attempt":1,"conclusion":"failure"}]}'
    ;;
  *'/actions/runs/202/jobs?'*)
    printf '%s\n' '{"jobs":[{"name":"pull request job","run_attempt":3,"conclusion":"success"}]}'
    ;;
  *'/actions/runs/202/artifacts?'*)
    printf '%s\n' "{\"artifacts\":[{\"name\":\"lane-executed-pull-request-202-${MOCK_EXECUTION_ATTEMPT:-3}\",\"expired\":false}]}"
    ;;
  *'/actions/runs/105/artifacts?'*)
    printf '%s\n' '{"artifacts":[{"name":"formal-proof-report-strict-105-1","expired":false},{"name":"formal-proof-report-strict-105-2","expired":false}]}'
    ;;
  *'/actions/runs/104/artifacts?'*)
    printf '%s\n' '{"artifacts":[{"name":"formal-proof-report-metadata_only-104-2","expired":false},{"name":"formal-proof-report-strict-104-1","expired":false}]}'
    ;;
  *)
    printf 'unexpected mocked endpoint: %s\n' "${endpoint}" >&2
    exit 2
    ;;
esac
SH
chmod +x "${tmp_dir}/bin/gh"

export PATH="${tmp_dir}/bin:${PATH}"
export MOCK_GH_LOG="${tmp_dir}/gh.log"
export LANE_GATE_CONFIG="${config}"
export LANE_GATE_REPOSITORY="owner/repo"
export LANE_GATE_NOW="2026-07-10T11:00:00Z"

scheduled="$(bash scripts/lane-gate.sh scheduled --report)"
grep -Fq 'streak=2/2' <<<"${scheduled}"
grep -Fq 'run_id=105' <<<"${scheduled}"
grep -Fq 'attempt=2' <<<"${scheduled}"
grep -Fq 'run_id=104' <<<"${scheduled}"
if grep -Fq 'run_id=103' <<<"${scheduled}"; then
  echo "manual dispatch run was counted" >&2
  exit 1
fi
if grep -Fq 'run_id=99' <<<"${scheduled}"; then
  echo "run before the evidence reset was counted" >&2
  exit 1
fi
grep -Fq 'event=schedule' "${MOCK_GH_LOG}"
if grep -Fq '/actions/runs/102/jobs?' "${MOCK_GH_LOG}"; then
  echo "lane gate queried jobs beyond the required streak" >&2
  exit 1
fi

strict="$(bash scripts/lane-gate.sh strict --report)"
grep -Fq 'streak=1/2' <<<"${strict}"
grep -Fq 'run_id=104 attempt=2' <<<"${strict}"
grep -Fq 'reason=non_strict' <<<"${strict}"

skipped="$(MOCK_TARGET_CONCLUSION=skipped bash scripts/lane-gate.sh scheduled --report)"
grep -Fq 'conclusion=skipped reason=job_not_successful' <<<"${skipped}"

pull_request="$(bash scripts/lane-gate.sh pull-request --report)"
grep -Fq 'streak=1/2' <<<"${pull_request}"
grep -Fq 'event=pull_request' "${MOCK_GH_LOG}"
grep -Fq 'real_execution=true' <<<"${pull_request}"
if grep -Fq '/actions/runs/203/jobs?' "${MOCK_GH_LOG}"; then
  echo "lane gate queried an unrelated PR base" >&2
  exit 1
fi

no_marker="$(MOCK_EXECUTION_ATTEMPT=2 bash scripts/lane-gate.sh pull-request --report)"
grep -Fq 'reason=execution_marker_missing' <<<"${no_marker}"

if MOCK_GH_ERROR=not-found bash scripts/lane-gate.sh scheduled --report \
  >"${tmp_dir}/api-fail.out" 2>&1; then
  echo "lane gate did not fail closed on an HTTP integrity error" >&2
  exit 1
fi
grep -Fq 'HTTP 404' "${tmp_dir}/api-fail.out"

MOCK_GH_ERROR=rate-limit LANE_GATE_RATE_LIMIT_MODE=warn \
  bash scripts/lane-gate.sh scheduled --report >"${tmp_dir}/api-warn.out" 2>&1
grep -Fq 'evidence=unavailable verdict=advisory' "${tmp_dir}/api-warn.out"

MOCK_GH_ERROR=transport LANE_GATE_RATE_LIMIT_MODE=warn \
  bash scripts/lane-gate.sh scheduled --report >"${tmp_dir}/transport-warn.out" 2>&1
grep -Fq 'evidence=unavailable verdict=advisory' "${tmp_dir}/transport-warn.out"

for error_mode in malformed not-found; do
  if MOCK_GH_ERROR="${error_mode}" LANE_GATE_RATE_LIMIT_MODE=warn \
    bash scripts/lane-gate.sh scheduled --report \
      >"${tmp_dir}/${error_mode}.out" 2>&1; then
    echo "lane gate warned on evidence-integrity failure: ${error_mode}" >&2
    exit 1
  fi
done

if MOCK_RUN_TIMESTAMP=invalid LANE_GATE_RATE_LIMIT_MODE=warn \
  bash scripts/lane-gate.sh scheduled --report \
    >"${tmp_dir}/timestamp.out" 2>&1; then
  echo "lane gate warned on an invalid timestamp" >&2
  exit 1
fi
grep -Fq 'invalid run timestamp' "${tmp_dir}/timestamp.out"

if MOCK_JOB_ATTEMPT=1 LANE_GATE_RATE_LIMIT_MODE=warn \
  bash scripts/lane-gate.sh scheduled --report \
    >"${tmp_dir}/attempt.out" 2>&1; then
  echo "lane gate warned on a run-attempt mismatch" >&2
  exit 1
fi
grep -Fq 'does not match' "${tmp_dir}/attempt.out"

set +e
env -u LANE_EXIT bash scripts/lane-gate.sh scheduled \
  >"${tmp_dir}/missing-lane-exit.out" 2>&1
missing_lane_exit_status=$?
set -e
if [[ "${missing_lane_exit_status}" -ne 2 ]]; then
  echo "lane gate did not reject a missing LANE_EXIT" >&2
  exit 1
fi
grep -Fq 'LANE_EXIT is required for a job-blocking invocation' \
  "${tmp_dir}/missing-lane-exit.out"

LANE_EXIT=1 bash scripts/lane-gate.sh scheduled >/dev/null

python3 - "${config}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace(
    "[gates.scheduled]\nworkflow = \"nightly.yml\"\njob = \"target job\"\nevent = \"schedule\"\nposture = \"advisory\"",
    "[gates.scheduled]\nworkflow = \"nightly.yml\"\njob = \"target job\"\nevent = \"schedule\"\nposture = \"required\"",
)
path.write_text(text, encoding="utf-8")
PY

if LANE_EXIT=1 bash scripts/lane-gate.sh scheduled \
  >"${tmp_dir}/missing-promotion-evidence.out" 2>&1; then
  echo "required lane accepted missing promotion evidence" >&2
  exit 1
fi
grep -Fq 'required posture needs promotion_evidence' \
  "${tmp_dir}/missing-promotion-evidence.out"

python3 - "${config}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
needle = 'posture = "required"\nrequired_streak = 2'
evidence = (
    'posture = "required"\n'
    'promotion_evidence = { run_ids = [105, 104], report_sha256 = "'
    + "a" * 64
    + '" }\nrequired_streak = 2'
)
if needle not in text:
    raise SystemExit("required scheduled lane fixture is missing")
path.write_text(text.replace(needle, evidence, 1), encoding="utf-8")
PY

invalid_promotion_config="${tmp_dir}/invalid-promotion.toml"
cp "${config}" "${invalid_promotion_config}"
sed -i 's/run_ids = \[105, 104\]/run_ids = [105]/' "${invalid_promotion_config}"
if LANE_GATE_CONFIG="${invalid_promotion_config}" \
  bash scripts/lane-gate.sh scheduled --report \
  >"${tmp_dir}/invalid-promotion.out" 2>&1; then
  echo "required lane accepted an incomplete promotion run set" >&2
  exit 1
fi
grep -Fq 'promotion_evidence.run_ids must contain exactly 2 runs' \
  "${tmp_dir}/invalid-promotion.out"

if LANE_EXIT=1 bash scripts/lane-gate.sh scheduled >"${tmp_dir}/required.out" 2>&1; then
  echo "required lane accepted a failed current run" >&2
  exit 1
fi
grep -Fq 'verdict=fail' "${tmp_dir}/required.out"

if MOCK_GH_ERROR=rate-limit LANE_GATE_RATE_LIMIT_MODE=warn \
  bash scripts/lane-gate.sh scheduled >"${tmp_dir}/required-api.out" 2>&1; then
  echo "required lane downgraded an API failure to a warning" >&2
  exit 1
fi
grep -Fq 'API rate limit exceeded' "${tmp_dir}/required-api.out"

python3 - "${config}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace(
    "[gates.frozen]\nworkflow = \"temporal.yml\"\njob = \"temporal job\"\nevent = \"schedule\"\nposture = \"advisory\"",
    "[gates.frozen]\nworkflow = \"temporal.yml\"\njob = \"temporal job\"\nevent = \"schedule\"\nposture = \"required\"",
)
path.write_text(text, encoding="utf-8")
PY

if bash scripts/lane-gate.sh frozen >"${tmp_dir}/frozen.out" 2>&1; then
  echo "frozen lane accepted required posture" >&2
  exit 1
fi
grep -Fq 'frozen lane cannot use required posture' "${tmp_dir}/frozen.out"

python3 - "${config}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace(
    "[gates.frozen]\nworkflow = \"temporal.yml\"\njob = \"temporal job\"\nevent = \"schedule\"\nposture = \"required\"",
    "[gates.frozen]\nworkflow = \"temporal.yml\"\njob = \"temporal job\"\nevent = \"schedule\"\nposture = \"advisory\"",
)
text = text.replace('max_age_hours = 48\n\n[gates.strict]', 'max_age_hours = 1\n\n[gates.strict]', 1)
path.write_text(text, encoding="utf-8")
PY

if LANE_GATE_NOW="2026-07-10T12:01:00Z" \
  bash scripts/lane-gate.sh --fleet >"${tmp_dir}/fleet.out" 2>&1; then
  echo "fleet accepted stale evidence for a required lane" >&2
  exit 1
fi
grep -Fq 'freshness=stale' "${tmp_dir}/fleet.out"

python3 - "${config}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8").replace(
    'max_age_hours = 1\n\n[gates.strict]',
    'max_age_hours = 48\n\n[gates.strict]',
    1,
)
path.write_text(text, encoding="utf-8")
PY
LANE_GATE_NOW="2026-07-10T11:00:00Z" bash scripts/lane-gate.sh --fleet \
  >"${tmp_dir}/fleet-pass.out"
grep -Fq 'fleet required=1 verdict=pass' "${tmp_dir}/fleet-pass.out"

if MOCK_TARGET_CONCLUSION=failure LANE_GATE_NOW="2026-07-10T11:00:00Z" \
  bash scripts/lane-gate.sh --fleet >"${tmp_dir}/fleet-failure.out" 2>&1; then
  echo "fleet accepted a failed latest job" >&2
  exit 1
fi
grep -Fq 'reason=job_not_successful' "${tmp_dir}/fleet-failure.out"

python3 - <<'PY'
from pathlib import Path
import re
import tomllib

expected = {
    "apalache-negative",
    "apalache-safety",
    "apalache-temporal",
    "formal-qualification",
    "fuzz-corpus-smoke-nightly",
    "fuzz-corpus-smoke-pr",
    "kani-manifest-pr",
    "kani-public-nightly",
    "kani-public-pr",
    "lean-build",
    "rust-verification-metadata",
}
document = tomllib.loads(Path("releases.toml").read_text(encoding="utf-8"))
gates = document.get("gates", {})
missing_baseline = expected - set(gates)
if missing_baseline:
    raise SystemExit(f"lane registry lacks baseline lanes: {sorted(missing_baseline)}")
for name, lane in gates.items():
    posture = lane.get("posture")
    if posture not in {"advisory", "required"}:
        raise SystemExit(f"lane {name} has invalid posture")
    promotion = lane.get("promotion_evidence")
    if posture == "advisory" and promotion is not None:
        raise SystemExit(f"advisory lane {name} claims promotion evidence")
    if posture == "required":
        if not isinstance(promotion, dict) or set(promotion) != {
            "run_ids",
            "report_sha256",
        }:
            raise SystemExit(f"required lane {name} lacks structured promotion evidence")
        run_ids = promotion.get("run_ids")
        if (
            not isinstance(run_ids, list)
            or len(run_ids) != lane.get("required_streak")
            or len(run_ids) != len(set(run_ids))
            or any(
                isinstance(run_id, bool)
                or not isinstance(run_id, int)
                or run_id <= lane.get("evidence_after_run_id", 0)
                for run_id in run_ids
            )
        ):
            raise SystemExit(f"required lane {name} has invalid promotion run IDs")
        if not re.fullmatch(r"[0-9a-f]{64}", promotion.get("report_sha256", "")):
            raise SystemExit(f"required lane {name} has invalid promotion report binding")
    if not lane.get("workflow") or not lane.get("job"):
        raise SystemExit(f"lane {name} lacks workflow or job identity")
    if lane.get("event") not in {"schedule", "pull_request"}:
        raise SystemExit(f"lane {name} has invalid event")
    if "evidence_after_run_id" not in lane or "max_age_hours" not in lane:
        raise SystemExit(f"lane {name} lacks reset or freshness policy")
    if lane.get("event") == "pull_request":
        if not lane.get("base_branch") or not lane.get("execution_artifact_prefix"):
            raise SystemExit(f"pull-request lane {name} lacks base or execution marker")
        if posture == "advisory" and lane.get("frozen") is not True:
            raise SystemExit(f"advisory pull-request lane {name} is not frozen")
        if posture == "required" and lane.get("frozen") is True:
            raise SystemExit(f"required pull-request lane {name} remains frozen")

def workflow_jobs(path):
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    try:
        jobs_index = lines.index("jobs:")
    except ValueError as exc:
        raise SystemExit(f"workflow lacks jobs mapping: {path}") from exc
    header = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
    starts = [
        (index, match.group(1))
        for index, line in enumerate(lines[jobs_index + 1 :], start=jobs_index + 1)
        if (match := header.match(line)) is not None
    ]
    jobs = []
    for position, (start, job_id) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        block = lines[start:end]
        names = [line.split(":", 1)[1].strip().strip("\"'") for line in block if line.startswith("    name:")]
        if len(names) != 1:
            raise SystemExit(f"workflow job {path}:{job_id} must have one static display name")
        jobs.append({"id": job_id, "name": names[0], "lines": block})
    return text, lines[:jobs_index], jobs


def steps(job, workflow_path):
    lines = job["lines"]
    try:
        start = next(index for index, line in enumerate(lines) if line == "    steps:") + 1
    except StopIteration as exc:
        raise SystemExit(f"workflow job {workflow_path}:{job['id']} lacks steps") from exc
    step_starts = [
        index for index in range(start, len(lines)) if lines[index].startswith("      - ")
    ]
    blocks = []
    for position, step_start in enumerate(step_starts):
        step_end = (
            step_starts[position + 1] if position + 1 < len(step_starts) else len(lines)
        )
        blocks.append(lines[step_start:step_end])
    return blocks


workflow_cache = {}
for name, lane in gates.items():
    workflow_path = Path(".github/workflows") / lane["workflow"]
    if not workflow_path.is_file():
        raise SystemExit(f"lane {name} references missing workflow {workflow_path}")
    if workflow_path not in workflow_cache:
        workflow_cache[workflow_path] = workflow_jobs(workflow_path)
    workflow, preamble, jobs = workflow_cache[workflow_path]
    command = f"bash scripts/lane-gate.sh {name}"
    matching_jobs = [job for job in jobs if job["name"] == lane["job"]]
    calls = []
    for job in jobs:
        for index, step in enumerate(steps(job, workflow_path)):
            if any(line.strip() == f"run: {command}" for line in step):
                calls.append((job, index, step, len(steps(job, workflow_path))))

    if len(matching_jobs) != 1:
        raise SystemExit(f"lane {name} does not resolve to one static workflow job")
    if len(calls) != 1 or calls[0][0]["id"] != matching_jobs[0]["id"]:
        raise SystemExit(f"lane {name} gate call is missing or in the wrong job block")
    job, step_index, step, step_count = calls[0]
    if step_index != step_count - 1:
        raise SystemExit(f"lane {name} gate call is not the terminal job step")
    required_step_lines = {
        "if: always()",
        "GH_TOKEN: ${{ github.token }}",
        "LANE_EXIT: ${{ job.status == 'success' && '0' || '1' }}",
        "LANE_GATE_RATE_LIMIT_MODE: warn",
        f"run: {command}",
    }
    actual_step_lines = {line.strip() for line in step}
    missing_step_lines = required_step_lines - actual_step_lines
    if missing_step_lines:
        raise SystemExit(
            f"lane {name} terminal gate step lacks {sorted(missing_step_lines)}"
        )
    try:
        steps_index = job["lines"].index("    steps:")
    except ValueError as exc:
        raise SystemExit(f"lane {name} job lacks steps") from exc
    permission_lines = preamble + job["lines"][:steps_index]
    if not any(line.strip() == "actions: read" for line in permission_lines):
        raise SystemExit(f"lane {name} workflow or job lacks actions read permission")

nightly = workflow_cache[Path(".github/workflows/nightly.yml")][0]
if "formal-proof-report-${{ steps.proof_report.outputs.mode }}-${{ github.run_id }}-${{ github.run_attempt }}" not in nightly:
    raise SystemExit("nightly proof artifact name does not expose mode, run id, and attempt")
if "Mode: \\`" not in nightly:
    raise SystemExit("nightly job summary does not expose proof mode")
if "target/formal/coverage.json" not in nightly or "if-no-files-found: error" not in nightly:
    raise SystemExit("nightly does not retain proof report and coverage fail-closed")

qualification = Path("scripts/qualify-release.sh").read_text(encoding="utf-8")
if "./scripts/lane-gate.sh --fleet" not in qualification:
    raise SystemExit("release qualification does not enforce the lane fleet")
for required in (
    "target/formal/proof-report.json",
    "target/formal/coverage.json",
    'formal_root="${output_root}/formal"',
):
    if required not in qualification:
        raise SystemExit(f"release qualification does not retain {required}")
release_workflow = Path(".github/workflows/release-qualification.yml").read_text(
    encoding="utf-8"
)
if "actions: read" not in release_workflow or "GH_TOKEN: ${{ github.token }}" not in release_workflow:
    raise SystemExit("release qualification lacks GitHub Actions read credentials")
for required in (
    "Retain formal proof evidence",
    "target/release-qualification/formal/proof-report.json",
    "target/release-qualification/formal/coverage.json",
    "if-no-files-found: error",
):
    if required not in release_workflow:
        raise SystemExit(f"release workflow does not retain formal evidence: {required}")

codeowners = {}
for line in Path(".github/CODEOWNERS").read_text(encoding="utf-8").splitlines():
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        continue
    pattern, *owners = stripped.split()
    codeowners[pattern] = owners
for protected in (
    "formal/**",
    "formal/proof-manifest.toml",
    "formal/apalache/**",
    "xtask/src/**",
    "crates/kernel/chio-kernel-core/src/**",
    "docs/formal/COVERAGE.md",
    "docs/reference/CLAIM_REGISTRY.md",
    "docs/release/RISK_REGISTER.md",
    "docs/start-here/VISION.md",
    "spec/PROTOCOL.md",
    "scripts/check-*.sh",
    "scripts/ci-workspace.sh",
    "scripts/lane-gate.sh",
    "scripts/generate-proof-report.sh",
    "scripts/check-proof-report.sh",
    "scripts/qualify-release.sh",
    "scripts/tests/**",
    "scripts/tests/check-proof-report.test.sh",
    "scripts/tests/lane-gate.test.sh",
    "xtask/src/proof_coverage.rs",
    ".github/workflows/formal-pr-smoke.yml",
    ".github/workflows/nightly.yml",
    ".github/workflows/apalache-safety.yml",
    ".github/workflows/apalache-temporal.yml",
    ".github/workflows/release-qualification.yml",
    "releases.toml",
):
    if codeowners.get(protected) != ["@backbay-labs/chio-maintainers"]:
        raise SystemExit(f"evidence TCB lacks CODEOWNERS protection: {protected}")
PY

echo "Lane gate contract passed"
