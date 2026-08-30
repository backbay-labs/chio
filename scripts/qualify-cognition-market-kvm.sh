#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
umask 022

for command_name in env python3 realpath sha256sum stat; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "cognition-market KVM qualification requires ${command_name} on PATH" >&2
    exit 1
  fi
done
if [[ "$(id -u)" -ne 0 ]]; then
  echo "cognition-market KVM qualification requires root for the Firecracker jailer" >&2
  exit 1
fi
if [[ ! -c /dev/kvm || ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo "cognition-market KVM qualification requires readable and writable /dev/kvm" >&2
  exit 1
fi

: "${CHIO_FINDING_HOSTED_PROFILE:?set CHIO_FINDING_HOSTED_PROFILE to the canonical private hosted profile}"
: "${CHIO_FINDING_CANARY_OBSERVATION:?set CHIO_FINDING_CANARY_OBSERVATION to the canonical private canary observation}"
: "${CHIO_FINDING_CANARY_JOB:?set CHIO_FINDING_CANARY_JOB to the canonical private exact-job request}"
: "${CHIO_FINDING_WORKER_ID:?set CHIO_FINDING_WORKER_ID to a unique worker identity}"
: "${CHIO_FINDING_CANARY_JOB_ID:?set CHIO_FINDING_CANARY_JOB_ID to the exact queued canary job}"
: "${CHIO_KVM_RUNNER_IMAGE_SHA256:?set CHIO_KVM_RUNNER_IMAGE_SHA256 to the measured runner image digest}"
: "${CHIO_KVM_RUNNER_ATTESTATION_SHA256:?set CHIO_KVM_RUNNER_ATTESTATION_SHA256 to the runner attestation digest}"

for digest_value in "${CHIO_KVM_RUNNER_IMAGE_SHA256}" "${CHIO_KVM_RUNNER_ATTESTATION_SHA256}"; do
  if [[ ! "${digest_value}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "cognition-market KVM runner identity digest is invalid" >&2
    exit 1
  fi
done

candidate_sha="$(git rev-parse --verify 'HEAD^{commit}')"
if [[ -n "${GITHUB_SHA:-}" && "${GITHUB_SHA}" != "${candidate_sha}" ]]; then
  echo "cognition-market KVM qualification GITHUB_SHA does not match HEAD" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "cognition-market KVM qualification requires a clean exact candidate" >&2
  exit 1
fi

cargo build --locked --release \
  -p chio-cli --bin chio \
  -p chio-finding-market-canary --bin chio-finding-market-canary \
  -p chio-finding-worker-daemon --bin chio-finding-worker
chio_bin="$(realpath -e target/release/chio)"
canary_bin="$(realpath -e target/release/chio-finding-market-canary)"
worker_bin="$(realpath -e target/release/chio-finding-worker)"

python3 - \
  "${CHIO_FINDING_HOSTED_PROFILE}" \
  "${CHIO_FINDING_CANARY_OBSERVATION}" \
  "${CHIO_FINDING_CANARY_JOB}" \
  "${worker_bin}" \
  "${canary_bin}" \
  "${chio_bin}" <<'PY'
import os
import stat
import sys

for raw_path in sys.argv[1:]:
    if not os.path.isabs(raw_path) or os.path.realpath(raw_path) != raw_path:
        raise SystemExit(f"qualification path is not absolute and canonical: {raw_path}")
    metadata = os.stat(raw_path, follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"qualification path is not a regular file: {raw_path}")
PY

output_root="target/release-qualification/cognition-market-kvm"
profile_log="${output_root}/hosted-profile.json"
worker_log="${output_root}/worker-canary.json"
provision_log="${output_root}/canary-provision.json"
terminal_log="${output_root}/canary-terminal.json"
decision_log="${output_root}/canary-decision.json"
report_path="${output_root}/qualification.json"
manifest_path="${output_root}/artifact-manifest.signed.json"
checksums_path="${output_root}/SHA256SUMS"
secret_root="$(mktemp -d "${TMPDIR:-/tmp}/chio-kvm-qualification.XXXXXX")"
chmod 0700 "${secret_root}"
signing_seed="${secret_root}/qualification.seed"
profile_snapshot="${secret_root}/hosted-profile.json"
observation_snapshot="${secret_root}/canary-observation.json"
job_snapshot="${secret_root}/canary-job.json"
cleanup_secrets() {
  rm -f "${signing_seed}" "${profile_snapshot}" "${observation_snapshot}" "${job_snapshot}"
  rmdir "${secret_root}" || true
}
trap cleanup_secrets EXIT

python3 - "${signing_seed}" <<'PY'
import os
import secrets
import sys

descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii") as seed_file:
    seed_file.write(secrets.token_hex(32) + "\n")
PY

python3 - \
  "${CHIO_FINDING_HOSTED_PROFILE}" \
  "${profile_snapshot}" \
  "${CHIO_FINDING_CANARY_OBSERVATION}" \
  "${observation_snapshot}" \
  "${CHIO_FINDING_CANARY_JOB}" \
  "${job_snapshot}" <<'PY'
import os
import stat
import sys

for source, destination in zip(sys.argv[1::2], sys.argv[2::2]):
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4 * 1024 * 1024:
            raise SystemExit(f"qualification input is not a bounded regular file: {source}")
        payload = b""
        while len(payload) <= 4 * 1024 * 1024:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            payload += chunk
        if len(payload) != metadata.st_size:
            raise SystemExit(f"qualification input changed while copied: {source}")
    finally:
        os.close(descriptor)
    output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(output, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
PY

rm -rf "${output_root}"
mkdir -p "${output_root}"

"${chio_bin}" --json finding operator validate-hosted \
  --profile "${profile_snapshot}" >"${profile_log}"

mapfile -t database_url_envs < <(python3 - "${profile_snapshot}" <<'PY'
import json
import re
import sys

with open(sys.argv[1], "r", encoding="utf-8") as profile_file:
    profile = json.load(profile_file)

database = profile.get("database")
if not isinstance(database, dict):
    raise SystemExit("hosted profile database configuration is invalid")
for field in ("runtimeUrlEnv", "workerUrlEnv"):
    value = database.get(field)
    if not isinstance(value, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", value) is None:
        raise SystemExit(f"hosted profile database binding {field} is invalid")
    print(value)
PY
)
if [[ "${#database_url_envs[@]}" -ne 2 ]]; then
  echo "cognition-market KVM qualification could not resolve database bindings" >&2
  exit 1
fi
runtime_database_url_env="${database_url_envs[0]}"
worker_database_url_env="${database_url_envs[1]}"
if [[ "${runtime_database_url_env}" == "${worker_database_url_env}" ]]; then
  echo "cognition-market KVM qualification requires isolated database bindings" >&2
  exit 1
fi

CHIO_FINDING_CANDIDATE_SHA="${candidate_sha}" \
  env --unset="${worker_database_url_env}" \
  "${canary_bin}" --profile "${profile_snapshot}" --job "${job_snapshot}" \
  provision >"${provision_log}"
env --unset="${runtime_database_url_env}" \
  "${worker_bin}" \
  --profile "${profile_snapshot}" \
  --worker-id "${CHIO_FINDING_WORKER_ID}" \
  --once >"${worker_log}"
CHIO_FINDING_CANDIDATE_SHA="${candidate_sha}" \
  env --unset="${worker_database_url_env}" \
  "${canary_bin}" --profile "${profile_snapshot}" --job "${job_snapshot}" \
  verify >"${terminal_log}"
"${chio_bin}" --json finding operator evaluate-canary \
  --profile "${profile_snapshot}" \
  --observation "${observation_snapshot}" >"${decision_log}"

python3 - \
  "${candidate_sha}" \
  "${profile_log}" \
  "${worker_log}" \
  "${provision_log}" \
  "${terminal_log}" \
  "${decision_log}" \
  "${profile_snapshot}" \
  "${observation_snapshot}" \
  "${worker_bin}" \
  "${report_path}" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

(
    candidate_sha,
    profile_log_raw,
    worker_log_raw,
    provision_log_raw,
    terminal_log_raw,
    decision_log_raw,
    profile_path_raw,
    observation_path_raw,
    worker_path_raw,
    report_path_raw,
) = sys.argv[1:]

profile_log = Path(profile_log_raw)
worker_log = Path(worker_log_raw)
decision_log = Path(decision_log_raw)
profile_result = json.loads(profile_log.read_text(encoding="utf-8"))
worker_result = json.loads(worker_log.read_text(encoding="utf-8"))
provision_result = json.loads(Path(provision_log_raw).read_text(encoding="utf-8"))
terminal_result = json.loads(Path(terminal_log_raw).read_text(encoding="utf-8"))
decision = json.loads(decision_log.read_text(encoding="utf-8"))

if profile_result.get("valid") is not True:
    raise SystemExit("hosted profile did not pass strict validation")
expected_worker = {
    "schema": "chio.finding.worker-tick.v1",
    "ready": True,
    "tenantCount": 1,
    "tenantsVisited": 1,
    "claimed": 1,
    "completed": 1,
    "guestRejected": 0,
    "retried": 0,
    "exhausted": 0,
    "cancelled": 0,
}
for field, expected in expected_worker.items():
    if worker_result.get(field) != expected:
        raise SystemExit(
            f"KVM worker canary field {field} is {worker_result.get(field)!r}, "
            f"expected {expected!r}"
        )
if worker_result.get("dependencyError") is not None:
    raise SystemExit("KVM worker canary reported a dependency error")
expected_job_id = os.environ["CHIO_FINDING_CANARY_JOB_ID"]
if worker_result.get("claimedJobIds") != [expected_job_id]:
    raise SystemExit("KVM worker canary claimed an unexpected job identity")
if worker_result.get("completedJobIds") != [expected_job_id]:
    raise SystemExit("KVM worker canary completed an unexpected job identity")
jobs = worker_result.get("jobs")
if not isinstance(jobs, list) or len(jobs) != 1:
    raise SystemExit("KVM worker canary did not report exactly one job evidence record")
worker_job = jobs[0]
if (
    worker_job.get("tenantId") != terminal_result.get("tenantId")
    or worker_job.get("jobId") != expected_job_id
    or worker_job.get("requestSha256") != terminal_result.get("requestSha256")
    or worker_job.get("leaseFence") != terminal_result.get("leaseFence")
    or worker_job.get("state") != "completed"
    or worker_job.get("resultSha256") != terminal_result.get("resultSha256")
    or worker_job.get("completedAt") != terminal_result.get("completedAt")
):
    raise SystemExit("KVM worker job evidence does not match the terminal database row")
for exact_result, operation, state in [
    (provision_result, "provision", "pending"),
    (terminal_result, "verify", "completed"),
]:
    if (
        exact_result.get("schema") != "chio.finding.kvm-canary-report.v1"
        or exact_result.get("operation") != operation
        or exact_result.get("candidateSha") != candidate_sha
        or exact_result.get("jobId") != expected_job_id
        or exact_result.get("terminalState") != state
    ):
        raise SystemExit(f"exact canary {operation} report does not bind the candidate job")
if terminal_result.get("leaseFence") != 1:
    raise SystemExit("exact canary was not completed under its first lease fence")
for field in ["requestSha256", "payloadSha256"]:
    if provision_result.get(field) != terminal_result.get(field):
        raise SystemExit(f"exact canary changed {field} across execution")
if terminal_result.get("resultSha256") != terminal_result.get("resultEnvelopeSha256"):
    raise SystemExit("terminal row does not retain the verified attested-result envelope")
if decision.get("decision") != "promote" or decision.get("reason") is not None:
    raise SystemExit("hosted canary decision is not promote")

def digest(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

kvm = os.stat("/dev/kvm", follow_symlinks=False)
if not stat.S_ISCHR(kvm.st_mode):
    raise SystemExit("/dev/kvm changed type during qualification")

report = {
    "schema": "chio.finding.kvm-qualification.v1",
    "candidateSha": candidate_sha,
    "generatedAt": datetime.now(timezone.utc)
    .replace(microsecond=0)
    .isoformat()
    .replace("+00:00", "Z"),
    "source": "github-actions"
    if os.environ.get("GITHUB_ACTIONS") == "true"
    else "local",
    "workflowRunId": os.environ.get("GITHUB_RUN_ID"),
    "workflowRunAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
    "decision": "promote",
    "profileSha256": digest(profile_path_raw),
    "observationSha256": digest(observation_path_raw),
    "workerBinarySha256": digest(worker_path_raw),
    "runnerImageSha256": os.environ["CHIO_KVM_RUNNER_IMAGE_SHA256"],
    "runnerAttestationSha256": os.environ["CHIO_KVM_RUNNER_ATTESTATION_SHA256"],
    "kvmDevice": {
        "major": os.major(kvm.st_rdev),
        "minor": os.minor(kvm.st_rdev),
    },
    "profileValidationSha256": digest(profile_log_raw),
    "workerCanarySha256": digest(worker_log_raw),
    "canaryProvisionSha256": digest(provision_log_raw),
    "canaryTerminalSha256": digest(terminal_log_raw),
    "canaryDecisionSha256": digest(decision_log_raw),
}
Path(report_path_raw).write_text(
    json.dumps(report, indent=2) + "\n", encoding="utf-8"
)
PY

cargo run -p chio-release-evidence \
  --bin chio-release-qualification-manifest -- \
  --repo-root . \
  --artifact-root "${output_root}" \
  --signing-seed "${signing_seed}" \
  --output "${manifest_path}" \
  --checksums "${checksums_path}" \
  --expected-candidate "${candidate_sha}"
cargo run -p chio-release-evidence \
  --bin chio-release-qualification-manifest -- \
  --verify \
  --repo-root . \
  --artifact-root "${output_root}" \
  --output "${manifest_path}" \
  --checksums "${checksums_path}" \
  --expected-candidate "${candidate_sha}"

printf 'cognition-market real KVM canary passed for %s; evidence: %s\n' \
  "${candidate_sha}" \
  "${manifest_path}"
