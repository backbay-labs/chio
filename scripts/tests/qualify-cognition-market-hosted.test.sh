#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
hosted="${repo_root}/scripts/qualify-cognition-market-hosted.sh"
kvm="${repo_root}/scripts/qualify-cognition-market-kvm.sh"
release="${repo_root}/scripts/qualify-release.sh"
components="${repo_root}/config/cognition-market-components.json"
code_workflow="${repo_root}/.github/workflows/cognition-market-hosted.yml"
promotion_workflow="${repo_root}/.github/workflows/cognition-market-promotion.yml"

bash -n "${hosted}" "${kvm}"

require_text() {
  local path="$1"
  local expected="$2"
  if ! grep -F -- "${expected}" "${path}" >/dev/null; then
    echo "hosted qualification contract missing from ${path}: ${expected}" >&2
    exit 1
  fi
}

require_text "${hosted}" 'qualification_mode="promotion"'
require_text "${hosted}" '--code-only'
require_text "${hosted}" 'git status --porcelain=v1 --untracked-files=all'
require_text "${hosted}" 'run_gate patch-integrity git diff --check'
require_text "${hosted}" 'postgres-16-rls'
require_text "${hosted}" 'cargo metadata --locked --manifest-path fuzz/Cargo.toml'
require_text "${hosted}" 'cargo test -p chio-settle --all-targets'
require_text "${hosted}" 'cargo deny check'
require_text "${hosted}" 'cargo vet check --locked'
require_text "${hosted}" './scripts/qualify-cognition-market-kvm.sh'
require_text "${hosted}" 'artifact-manifest.signed.json'
require_text "${hosted}" "--expected-candidate \"\${candidate_sha}\""
require_text "${hosted}" '"promotionReady": promotion'

require_text "${kvm}" '[[ ! -c /dev/kvm || ! -r /dev/kvm || ! -w /dev/kvm ]]'
require_text "${kvm}" "[[ \"\$(id -u)\" -ne 0 ]]"
require_text "${kvm}" 'git status --porcelain=v1 --untracked-files=all'
require_text "${kvm}" 'cargo build --locked --release'
require_text "${kvm}" "worker_bin=\"\$(realpath -e target/release/chio-finding-worker)\""
require_text "${kvm}" '"claimed": 1'
require_text "${kvm}" '"completed": 1'
require_text "${kvm}" 'CHIO_FINDING_CANARY_JOB_ID'
require_text "${kvm}" 'CHIO_FINDING_CANARY_JOB'
require_text "${kvm}" 'profile_snapshot="${secret_root}/hosted-profile.json"'
require_text "${kvm}" 'os.O_RDONLY | os.O_NOFOLLOW'
require_text "${kvm}" 'worker_result.get("completedJobIds") != [expected_job_id]'
require_text "${kvm}" 'worker_result.get("jobs")'
require_text "${kvm}" 'worker_job.get("resultSha256") != terminal_result.get("resultSha256")'
require_text "${kvm}" 'chio-finding-market-canary'
require_text "${kvm}" 'terminal_result.get("resultSha256") != terminal_result.get("resultEnvelopeSha256")'
require_text "${kvm}" 'decision.get("decision") != "promote"'
require_text "${kvm}" '"workerBinarySha256": digest(worker_path_raw)'
require_text "${kvm}" 'artifact-manifest.signed.json'
require_text "${kvm}" "--expected-candidate \"\${candidate_sha}\""

require_text "${release}" './scripts/qualify-cognition-market-hosted.sh --code-only'
require_text "${code_workflow}" './scripts/qualify-cognition-market-hosted.sh --code-only'
require_text "${code_workflow}" 'astral-sh/setup-uv@caf0cab7a618c569241d31dcd442f54681755d39'
require_text "${code_workflow}" 'cargo install cargo-deny --locked --version 0.19.4'
require_text "${components}" '.github/workflows/release-qualification.yml'
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
require_text "${promotion_workflow}" 'runs-on: [self-hosted, linux, x64, kvm, cognition-market, ephemeral, attested]'
require_text "${promotion_workflow}" 'name: cognition-market-production'
require_text "${promotion_workflow}" 'ephemeral, attested'
require_text "${promotion_workflow}" 'CHIO_KVM_RUNNER_IMAGE_SHA256'
require_text "${promotion_workflow}" 'CHIO_KVM_RUNNER_ATTESTATION_SHA256'
require_text "${promotion_workflow}" './scripts/qualify-cognition-market-hosted.sh'
require_text "${promotion_workflow}" 'cognition-market-hosted/artifact-manifest.signed.json'
require_text "${promotion_workflow}" 'cognition-market-kvm/artifact-manifest.signed.json'
require_text "${promotion_workflow}" 'cognition-market-promotion-sigstore'
require_text "${promotion_workflow}" 'cosign sign-blob --yes'
require_text "${promotion_workflow}" 'cosign verify-blob'
require_text "${promotion_workflow}" 'id-token: write'
require_text "${promotion_workflow}" 'DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}'
require_text "${promotion_workflow}" 'git check-ref-format --branch "${DEFAULT_BRANCH}"'
require_text "${promotion_workflow}" 'test "${candidate_sha}" = "${default_branch_sha}"'
require_text "${promotion_workflow}" 'test "${GITHUB_SHA}" = "${default_branch_sha}"'
if [[ "$(grep -Fc 'git fetch --no-tags --force origin' "${promotion_workflow}")" -ne 2 ]]; then
  echo "promotion workflow must re-fetch the default branch before qualification and signing" >&2
  exit 1
fi

echo "qualify-cognition-market-hosted.test.sh: hosted code and KVM promotion gates are closed"
