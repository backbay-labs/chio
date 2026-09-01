#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
hosted="${repo_root}/scripts/qualify-cognition-market-hosted.sh"
kvm="${repo_root}/scripts/qualify-cognition-market-kvm.sh"
network="${repo_root}/scripts/qualify-cognition-market-network.sh"
deployment="${repo_root}/scripts/check-cognition-market-deployment.sh"
release="${repo_root}/scripts/qualify-release.sh"
components="${repo_root}/config/cognition-market-components.json"
code_workflow="${repo_root}/.github/workflows/cognition-market-hosted.yml"
kvm_workflow="${repo_root}/.github/workflows/cognition-market-kvm-boundary.yml"
network_workflow="${repo_root}/.github/workflows/cognition-market-network-canary.yml"
old_promotion_workflow="${repo_root}/.github/workflows/cognition-market-promotion.yml"
report_generator="${repo_root}/scripts/generate-cognition-market-hosted-report.py"
report_schema="${repo_root}/spec/schemas/chio-finding/v1/hosted-qualification.schema.json"

bash -n "${hosted}" "${kvm}" "${network}" "${deployment}"

require_text() {
  local path="$1"
  local expected="$2"
  if ! grep -F -- "${expected}" "${path}" >/dev/null; then
    echo "hosted qualification contract missing from ${path}: ${expected}" >&2
    exit 1
  fi
}

require_text "${hosted}" 'qualification_mode="code-only"'
require_text "${hosted}" '--code-only'
require_text "${hosted}" '--kvm-boundary'
require_text "${hosted}" 'git status --porcelain=v1 --untracked-files=all'
require_text "${hosted}" 'run_gate patch-integrity git diff --check'
require_text "${hosted}" 'postgres-16-rls'
require_text "${hosted}" 'cargo metadata --locked --manifest-path fuzz/Cargo.toml'
require_text "${hosted}" 'cargo test -p chio-settle --all-targets'
require_text "${hosted}" 'cargo test -p chio-finding-market-server --all-targets'
require_text "${hosted}" 'scripts/check-cognition-market-deployment.sh'
require_text "${hosted}" 'tests/test_cognition_market.py'
require_text "${hosted}" 'npm --prefix sdks/typescript/chio-ts test'
require_text "${hosted}" '-p chio-finding-market-server'
require_text "${hosted}" 'cargo deny check'
require_text "${hosted}" 'cargo vet check --locked'
require_text "${hosted}" './scripts/qualify-cognition-market-kvm.sh'
require_text "${hosted}" 'scripts/generate-cognition-market-hosted-report.py'
require_text "${hosted}" 'spec/schemas/chio-finding/v1/hosted-qualification.schema.json'
require_text "${hosted}" 'artifact-manifest.signed.json'
require_text "${hosted}" "--expected-candidate \"\${candidate_sha}\""
require_text "${report_generator}" '"promotionReady": False'
require_text "${report_generator}" '"networkQualified": False'
require_text "${report_generator}" '"productionReady": False'
require_text "${report_generator}" 'chio.finding.hosted-qualification.v1'
if "${hosted}" --promotion >/dev/null 2>&1; then
  invalid_mode_status=0
else
  invalid_mode_status="$?"
fi
if [[ "${invalid_mode_status}" -ne 2 ]]; then
  echo "hosted qualification returned the wrong status for an invalid mode" >&2
  exit 1
fi

require_text "${kvm}" '[[ ! -c /dev/kvm || ! -r /dev/kvm || ! -w /dev/kvm ]]'
require_text "${kvm}" "[[ \"\$(id -u)\" -ne 0 ]]"
require_text "${kvm}" 'git status --porcelain=v1 --untracked-files=all'
require_text "${kvm}" 'cargo build --locked --release'
require_text "${kvm}" "worker_bin=\"\$(realpath -e target/release/chio-finding-worker)\""
require_text "${kvm}" 'unshare_bin="$(realpath -e "$(command -v unshare)")"'
require_text "${kvm}" '"claimed": 1'
require_text "${kvm}" '"completed": 1'
require_text "${kvm}" 'CHIO_FINDING_CANARY_JOB_ID'
require_text "${kvm}" 'CHIO_FINDING_CANARY_JOB'
require_text "${kvm}" 'profile_snapshot="${secret_root}/hosted-profile.json"'
require_text "${kvm}" 'os.O_RDONLY | os.O_NOFOLLOW'
require_text "${kvm}" 'runtime_database_url_env="${worker_secret_envs[0]}"'
require_text "${kvm}" 'worker_database_url_env="${worker_secret_envs[1]}"'
require_text "${kvm}" 'worker_signer_token_env="${worker_secret_envs[2]}"'
require_text "${kvm}" 'canary_environment=('
require_text "${kvm}" '"CHIO_FINDING_CANDIDATE_SHA=${candidate_sha}"'
require_text "${kvm}" '"${runtime_database_url_env}=${runtime_database_url}"'
require_text "${kvm}" 'worker_environment=('
require_text "${kvm}" '"${worker_database_url_env}=${worker_database_url}"'
require_text "${kvm}" '"${worker_signer_token_env}=${worker_signer_token}"'
if [[ "$(grep -Fc 'env -i "${canary_environment[@]}"' "${kvm}")" -ne 2 ]]; then
  echo "KVM canary invocations must use an allowlisted environment" >&2
  exit 1
fi
if [[ "$(grep -Fc 'env -i "${worker_environment[@]}"' "${kvm}")" -ne 1 ]]; then
  echo "KVM worker invocation must use an allowlisted environment" >&2
  exit 1
fi
if [[ "$(grep -Fc '"${unshare_bin}" --mount --pid --fork --mount-proc --kill-child=KILL --' "${kvm}")" -ne 3 ]]; then
  echo "KVM role subprocesses must run in isolated PID and proc namespaces" >&2
  exit 1
fi
require_text "${kvm}" 'worker_result.get("completedJobIds") != [expected_job_id]'
require_text "${kvm}" 'worker_result.get("jobs")'
require_text "${kvm}" 'worker_job.get("resultSha256") != terminal_result.get("resultSha256")'
require_text "${kvm}" 'chio-finding-market-canary'
require_text "${kvm}" 'terminal_result.get("resultSha256") != terminal_result.get("resultEnvelopeSha256")'
require_text "${kvm}" 'decision.get("decision") != "promote"'
require_text "${kvm}" '"workerBinarySha256": digest(worker_path_raw)'
require_text "${kvm}" 'artifact-manifest.signed.json'
require_text "${kvm}" "--expected-candidate \"\${candidate_sha}\""

require_text "${network}" 'git status --porcelain=v1 --untracked-files=all'
require_text "${network}" 'CHIO_FINDING_CANDIDATE_SHA'
require_text "${network}" 'cargo build --locked -p chio-finding-market-canary --bin chio-finding-market-canary'
require_text "${network}" 'canary_bin="$(realpath -e target/debug/chio-finding-market-canary)"'
require_text "${network}" 'env -i "${canary_environment[@]}" "${canary_bin}"'
require_text "${network}" 'unset \'
require_text "${network}" '--seller-key-secret-env CHIO_FINDING_NETWORK_SELLER_KEY_SECRET'
require_text "${network}" '--buyer-key-secret-env CHIO_FINDING_NETWORK_BUYER_KEY_SECRET'
require_text "${network}" 'retryOutcome") != "exact_replay"'
require_text "${network}" 'tenantIsolationDenied'
require_text "${network}" 'artifact-manifest.signed.json'
require_text "${network}" "--expected-candidate \"\${candidate_sha}\""
if grep -F -- '--seller-key-secret ' "${network}" >/dev/null \
  || grep -F -- '--buyer-key-secret ' "${network}" >/dev/null; then
  echo "network qualification passed a secret as a command argument" >&2
  exit 1
fi

require_text "${deployment}" 'image: [^[:space:]]+@sha256:[0-9a-f]{64}'
require_text "${deployment}" 'ConditionPathExists=/dev/kvm'
require_text "${deployment}" 'name: chio-finding-market-migrate'

require_text "${release}" './scripts/qualify-cognition-market-hosted.sh --code-only'
require_text "${code_workflow}" './scripts/qualify-cognition-market-hosted.sh --code-only'
require_text "${code_workflow}" 'astral-sh/setup-uv@caf0cab7a618c569241d31dcd442f54681755d39'
require_text "${code_workflow}" 'cargo install cargo-deny --locked --version 0.19.4'
require_text "${components}" '.github/workflows/release-qualification.yml'
require_text "${components}" '.github/workflows/cognition-market-kvm-boundary.yml'
require_text "${components}" '.github/workflows/cognition-market-network-canary.yml'
require_text "${components}" '.github/actionlint.yaml'
require_text "${components}" 'crates/products/chio-finding-market-server/**'
require_text "${components}" 'deploy/cognition-market/**'
require_text "${components}" 'sdks/python/chio-sdk-python/**'
require_text "${components}" 'sdks/typescript/chio-ts/**'
if [[ -e "${old_promotion_workflow}" ]]; then
  echo "legacy promotion workflow must not survive the KVM boundary rename" >&2
  exit 1
fi
if [[ "$(grep -Fc 'crates/core/chio-bounded/**' "${code_workflow}")" -ne 2 ]]; then
  echo "hosted workflow must qualify its Kani proof dependency on pull requests and main" >&2
  exit 1
fi
if [[ "$(grep -Fc 'crates/tooling/chio-release-evidence/**' "${code_workflow}")" -ne 2 ]]; then
  echo "hosted workflow must qualify release-evidence changes on pull requests and main" >&2
  exit 1
fi
if [[ "$(grep -Fc '.github/workflows/release-qualification.yml' "${code_workflow}")" -ne 2 ]]; then
  echo "hosted workflow must qualify release workflow changes on pull requests and main" >&2
  exit 1
fi
if [[ "$(grep -Fc 'crates/protocol/chio-egress-contract/**' "${code_workflow}")" -ne 2 ]]; then
  echo "hosted workflow must qualify egress-contract changes on pull requests and main" >&2
  exit 1
fi
if [[ "$(grep -Fc 'crates/protocol/chio-egress-contract/**' "${components}")" -ne 1 ]]; then
  echo "hosted component ownership must include the egress contract exactly once" >&2
  exit 1
fi
require_text "${kvm_workflow}" 'runs-on: [self-hosted, linux, x64, kvm, cognition-market, ephemeral, attested]'
require_text "${kvm_workflow}" 'name: cognition-market-kvm-qualification'
require_text "${kvm_workflow}" 'ephemeral, attested'
require_text "${kvm_workflow}" 'CHIO_KVM_RUNNER_IMAGE_SHA256'
require_text "${kvm_workflow}" 'CHIO_KVM_RUNNER_ATTESTATION_SHA256'
require_text "${kvm_workflow}" './scripts/qualify-cognition-market-hosted.sh --kvm-boundary'
require_text "${kvm_workflow}" 'Require bounded KVM claims and digest binding'
require_text "${kvm_workflow}" '"promotionReady": False'
require_text "${code_workflow}" 'Require bounded code-only claims'
require_text "${code_workflow}" 'crates/products/chio-finding-market-server/**'
require_text "${code_workflow}" 'deploy/cognition-market/**'
require_text "${code_workflow}" 'sdks/python/chio-sdk-python/**'
require_text "${code_workflow}" 'sdks/typescript/chio-ts/**'
require_text "${code_workflow}" '.github/workflows/cognition-market-network-canary.yml'
require_text "${code_workflow}" '"promotionReady": False'
require_text "${kvm_workflow}" 'cognition-market-hosted/artifact-manifest.signed.json'
require_text "${kvm_workflow}" 'cognition-market-kvm/artifact-manifest.signed.json'
require_text "${kvm_workflow}" 'cognition-market-kvm-boundary-sigstore'
require_text "${kvm_workflow}" 'cosign sign-blob --yes'
require_text "${kvm_workflow}" 'cosign verify-blob'
require_text "${kvm_workflow}" 'id-token: write'
require_text "${kvm_workflow}" 'DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}'
require_text "${kvm_workflow}" 'git check-ref-format --branch "${DEFAULT_BRANCH}"'
require_text "${kvm_workflow}" 'test "${candidate_sha}" = "${default_branch_sha}"'
require_text "${kvm_workflow}" 'test "${GITHUB_SHA}" = "${default_branch_sha}"'
if [[ "$(grep -Fc 'git fetch --no-tags --force origin' "${kvm_workflow}")" -ne 2 ]]; then
  echo "KVM workflow must re-fetch the default branch before qualification and signing" >&2
  exit 1
fi

require_text "${network_workflow}" 'workflow_dispatch:'
require_text "${network_workflow}" 'runs-on: [self-hosted, linux, x64, cognition-market, network, ephemeral, attested]'
require_text "${network_workflow}" 'environment: cognition-market-dark'
require_text "${network_workflow}" 'ref: ${{ github.sha }}'
require_text "${network_workflow}" 'test "${candidate_sha}" = "${GITHUB_SHA}"'
require_text "${network_workflow}" 'test "${candidate_sha}" = "${default_branch_sha}"'
require_text "${network_workflow}" './scripts/qualify-cognition-market-network.sh'
require_text "${network_workflow}" 'cognition-market-network-${{ github.sha }}'

test_root="$(mktemp -d "${TMPDIR:-/tmp}/chio-hosted-report.XXXXXX")"
trap 'rm -rf "${test_root}"' EXIT
mkdir -p "${test_root}/logs"
printf 'gate passed\n' >"${test_root}/logs/unit.log"
printf 'unit\tlogs/unit.log\tcargo test\n' >"${test_root}/gate-index.tsv"
candidate_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
kvm_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

python3 "${report_generator}" \
  --candidate-sha "${candidate_sha}" \
  --mode code-only \
  --gate-index "${test_root}/gate-index.tsv" \
  --report "${test_root}/qualification.json"
cargo run --quiet -p chio-spec-validate -- \
  "${report_schema}" "${test_root}/qualification.json"
python3 - "${test_root}/qualification.json" <<'PY'
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {
    "mode": "code-only",
    "decision": "qualified-code-boundary",
    "codeQualified": True,
    "kvmQualified": False,
    "networkQualified": False,
    "productionReady": False,
    "promotionReady": False,
    "kvmEvidenceSha256": None,
}
for field, value in expected.items():
    if report.get(field) != value:
        raise SystemExit(f"code-only report has unsafe {field}: {report.get(field)!r}")
PY

python3 "${report_generator}" \
  --candidate-sha "${candidate_sha}" \
  --mode kvm-boundary \
  --kvm-evidence-sha256 "${kvm_sha}" \
  --gate-index "${test_root}/gate-index.tsv" \
  --report "${test_root}/qualification.json"
cargo run --quiet -p chio-spec-validate -- \
  "${report_schema}" "${test_root}/qualification.json"
python3 - "${test_root}/qualification.json" "${kvm_sha}" <<'PY'
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if report.get("kvmQualified") is not True:
    raise SystemExit("KVM report did not qualify the KVM boundary")
if report.get("kvmEvidenceSha256") != sys.argv[2]:
    raise SystemExit("KVM report did not bind the KVM evidence digest")
for field in ("networkQualified", "productionReady", "promotionReady"):
    if report.get(field) is not False:
        raise SystemExit(f"KVM report made unsafe {field} claim")
PY

if python3 "${report_generator}" \
  --candidate-sha "${candidate_sha}" \
  --mode code-only \
  --kvm-evidence-sha256 "${kvm_sha}" \
  --gate-index "${test_root}/gate-index.tsv" \
  --report "${test_root}/qualification.json" >/dev/null 2>&1; then
  echo "code-only report accepted KVM evidence" >&2
  exit 1
fi
if python3 "${report_generator}" \
  --candidate-sha "${candidate_sha}" \
  --mode kvm-boundary \
  --gate-index "${test_root}/gate-index.tsv" \
  --report "${test_root}/qualification.json" >/dev/null 2>&1; then
  echo "KVM report accepted missing KVM evidence" >&2
  exit 1
fi

echo "qualify-cognition-market-hosted.test.sh: code and KVM claims remain bounded"
