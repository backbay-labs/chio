#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
umask 022
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_TEST_DEBUG=0

qualification_mode="code-only"
if [[ "$#" -gt 1 ]]; then
  echo "usage: $0 [--code-only|--kvm-boundary]" >&2
  exit 2
elif [[ "$#" -eq 1 ]]; then
  case "$1" in
    --code-only) ;;
    --kvm-boundary) qualification_mode="kvm-boundary" ;;
    *)
      echo "usage: $0 [--code-only|--kvm-boundary]" >&2
      exit 2
      ;;
  esac
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "hosted cognition-market qualification requires python3 on PATH" >&2
  exit 1
fi
if [[ -z "${CHIO_TEST_POSTGRES_URL:-}" || -z "${CHIO_TEST_POSTGRES_RUNTIME_URL:-}" ]]; then
  echo "hosted cognition-market qualification requires PostgreSQL test URLs" >&2
  exit 1
fi

candidate_sha="$(git rev-parse --verify 'HEAD^{commit}')"
if [[ -n "${GITHUB_SHA:-}" && "${GITHUB_SHA}" != "${candidate_sha}" ]]; then
  echo "hosted cognition-market qualification GITHUB_SHA does not match HEAD" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "hosted cognition-market qualification requires a clean exact candidate" >&2
  exit 1
fi
base_ref="${CHIO_QUALIFICATION_BASE_REF:-origin/main}"
if ! git rev-parse --verify "${base_ref}^{commit}" >/dev/null 2>&1; then
  echo "hosted cognition-market qualification cannot resolve ${base_ref}" >&2
  exit 1
fi
merge_base="$(git merge-base HEAD "${base_ref}")"

output_root="target/release-qualification/cognition-market-hosted"
log_root="${output_root}/logs"
gate_index="${output_root}/gate-index.tsv"
report_path="${output_root}/qualification.json"
manifest_path="${output_root}/artifact-manifest.signed.json"
checksums_path="${output_root}/SHA256SUMS"
secret_root="$(mktemp -d "${TMPDIR:-/tmp}/chio-hosted-qualification.XXXXXX")"
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

path = sys.argv[1]
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii") as seed_file:
    seed_file.write(secrets.token_hex(32) + "\n")
PY

rm -rf "${output_root}"
mkdir -p "${log_root}"
: >"${gate_index}"

run_gate() {
  local gate_id="$1"
  shift
  local log_path="${log_root}/${gate_id}.log"
  local command_display
  printf -v command_display '%q ' "$@"
  command_display="${command_display% }"
  printf '%s\t%s\t%s\n' \
    "${gate_id}" \
    "${log_path#"${output_root}"/}" \
    "${command_display}" >>"${gate_index}"
  printf 'hosted cognition-market gate %s: %s\n' \
    "${gate_id}" \
    "${command_display}" | tee "${log_path}"
  "$@" 2>&1 | tee -a "${log_path}"
}

run_gate format cargo fmt --all -- --check
run_gate patch-integrity git diff --check "${merge_base}...HEAD"
run_gate rust-hygiene python3 scripts/check-rust-file-hygiene.py
run_gate workspace-layering bash scripts/check-workspace-layering.sh
run_gate fuzz-lock \
  cargo metadata --locked --manifest-path fuzz/Cargo.toml --format-version 1 --no-deps
run_gate signing-remote cargo test -p chio-signing-remote --all-targets
run_gate isolated-worker cargo test -p chio-finding-worker --all-targets
run_gate worker-daemon cargo test -p chio-finding-worker-daemon --all-targets
run_gate database-migrator cargo test -p chio-finding-market-migrator --all-targets
run_gate exact-job-canary cargo test -p chio-finding-market-canary --all-targets
run_gate hosted-server cargo test -p chio-finding-market-server --all-targets
run_gate market-port cargo test -p chio-finding-market-port --all-targets
run_gate postgres-store cargo test -p chio-finding-market-store-postgres --all-targets
run_gate postgres-16-rls \
  cargo test -p chio-finding-market-store-postgres \
    --features postgres-integration --test postgres_store -- --test-threads=1
run_gate hosted-edge cargo test -p chio-finding-hosted-edge --all-targets
run_gate kernel-payment cargo test -p chio-kernel --lib payment
run_gate settlement cargo test -p chio-settle --all-targets
run_gate challenge-control \
  cargo test -p chio-control-plane --lib finding_challenge
run_gate purchase-control \
  cargo test -p chio-control-plane --lib finding_purchase
run_gate status-control \
  cargo test -p chio-control-plane --lib finding_status
run_gate hosted-profile \
  cargo test -p chio-control-plane --lib finding_hosted
run_gate hosted-cli cargo test -p chio-cli --bin chio hosted
run_gate hosted-secret-failure \
  cargo test -p chio-cli missing_secret_references_fail_closed
run_gate deployment-contract bash scripts/check-cognition-market-deployment.sh
run_gate python-hosted-sdk bash -lc \
  'cd sdks/python/chio-sdk-python && uv run --extra dev pytest tests/test_cognition_market.py'
run_gate typescript-hosted-sdk-install \
  npm --prefix sdks/typescript/chio-ts ci --no-fund --no-audit
run_gate typescript-hosted-sdk npm --prefix sdks/typescript/chio-ts test
run_gate typescript-hosted-sdk-lint npm --prefix sdks/typescript/chio-ts run lint
run_gate strict-clippy \
  cargo clippy \
    -p chio-signing-remote \
    -p chio-finding-worker \
    -p chio-finding-worker-daemon \
    -p chio-finding-market-migrator \
    -p chio-finding-market-canary \
    -p chio-finding-market-server \
    -p chio-finding-market-port \
    -p chio-finding-market-store-postgres \
    -p chio-finding-hosted-edge \
    -p chio-settle \
    -p chio-kernel \
    -p chio-control-plane \
    -p chio-cli \
    -p chio-release-evidence \
    --all-targets \
    --features chio-finding-market-store-postgres/postgres-integration \
    -- -D warnings
run_gate codegen make codegen-check
run_gate release-evidence cargo test -p chio-release-evidence --all-targets
run_gate dependency-policy cargo deny check
run_gate supply-chain cargo vet check --locked

kvm_evidence_sha256=""
if [[ "${qualification_mode}" == "kvm-boundary" ]]; then
  run_gate real-kvm-canary ./scripts/qualify-cognition-market-kvm.sh
  kvm_manifest="target/release-qualification/cognition-market-kvm/artifact-manifest.signed.json"
  if [[ ! -s "${kvm_manifest}" ]]; then
    echo "hosted cognition-market KVM qualification produced no signed manifest" >&2
    exit 1
  fi
  kvm_evidence_sha256="$(sha256sum "${kvm_manifest}" | cut -d' ' -f1)"
fi

python3 scripts/generate-cognition-market-hosted-report.py \
  --candidate-sha "${candidate_sha}" \
  --mode "${qualification_mode}" \
  --kvm-evidence-sha256 "${kvm_evidence_sha256}" \
  --gate-index "${gate_index}" \
  --report "${report_path}"
cargo run -p chio-spec-validate -- \
  spec/schemas/chio-finding/v1/hosted-qualification.schema.json \
  "${report_path}"

rm -f "${gate_index}"
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

printf 'hosted cognition-market %s qualification passed for %s; evidence: %s\n' \
  "${qualification_mode}" \
  "${candidate_sha}" \
  "${manifest_path}"
