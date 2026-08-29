#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
umask 022

for command_name in python3 realpath sha256sum stat; do
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
: "${CHIO_FINDING_WORKER_ID:?set CHIO_FINDING_WORKER_ID to a unique worker identity}"

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
  -p chio-finding-worker-daemon --bin chio-finding-worker
chio_bin="$(realpath -e target/release/chio)"
worker_bin="$(realpath -e target/release/chio-finding-worker)"

python3 - \
  "${CHIO_FINDING_HOSTED_PROFILE}" \
  "${CHIO_FINDING_CANARY_OBSERVATION}" \
  "${worker_bin}" \
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
decision_log="${output_root}/canary-decision.json"
report_path="${output_root}/qualification.json"
manifest_path="${output_root}/artifact-manifest.signed.json"
checksums_path="${output_root}/SHA256SUMS"
secret_root="$(mktemp -d "${TMPDIR:-/tmp}/chio-kvm-qualification.XXXXXX")"
chmod 0700 "${secret_root}"
signing_seed="${secret_root}/qualification.seed"
cleanup_secrets() {
  rm -f "${signing_seed}"
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

rm -rf "${output_root}"
mkdir -p "${output_root}"

"${chio_bin}" --json finding operator validate-hosted \
  --profile "${CHIO_FINDING_HOSTED_PROFILE}" >"${profile_log}"
"${worker_bin}" \
  --profile "${CHIO_FINDING_HOSTED_PROFILE}" \
  --worker-id "${CHIO_FINDING_WORKER_ID}" \
  --once >"${worker_log}"
"${chio_bin}" --json finding operator evaluate-canary \
  --profile "${CHIO_FINDING_HOSTED_PROFILE}" \
  --observation "${CHIO_FINDING_CANARY_OBSERVATION}" >"${decision_log}"

python3 - \
  "${candidate_sha}" \
  "${profile_log}" \
  "${worker_log}" \
  "${decision_log}" \
  "${CHIO_FINDING_HOSTED_PROFILE}" \
  "${CHIO_FINDING_CANARY_OBSERVATION}" \
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
decision = json.loads(decision_log.read_text(encoding="utf-8"))

if profile_result.get("valid") is not True:
    raise SystemExit("hosted profile did not pass strict validation")
expected_worker = {
    "schema": "chio.finding.worker-tick.v1",
    "ready": True,
    "claimed": 1,
    "completed": 1,
    "guestRejected": 0,
    "retried": 0,
    "exhausted": 0,
}
for field, expected in expected_worker.items():
    if worker_result.get(field) != expected:
        raise SystemExit(
            f"KVM worker canary field {field} is {worker_result.get(field)!r}, "
            f"expected {expected!r}"
        )
if worker_result.get("dependencyError") is not None:
    raise SystemExit("KVM worker canary reported a dependency error")
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
    "kvmDevice": {
        "major": os.major(kvm.st_rdev),
        "minor": os.minor(kvm.st_rdev),
    },
    "profileValidationSha256": digest(profile_log_raw),
    "workerCanarySha256": digest(worker_log_raw),
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
