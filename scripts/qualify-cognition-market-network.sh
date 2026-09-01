#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
umask 077

required_environment=(
  CHIO_FINDING_HOSTED_PROFILE
  CHIO_FINDING_NETWORK_CANARY_ARTIFACT
  CHIO_FINDING_NETWORK_TENANT_ID
  CHIO_FINDING_NETWORK_SELLER_KEY_ID
  CHIO_FINDING_NETWORK_SELLER_KEY_SECRET
  CHIO_FINDING_NETWORK_BUYER_KEY_ID
  CHIO_FINDING_NETWORK_BUYER_KEY_SECRET
)
for name in "${required_environment[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "hosted network qualification requires ${name}" >&2
    exit 1
  fi
done

candidate_sha="$(git rev-parse --verify 'HEAD^{commit}')"
if [[ -n "${GITHUB_SHA:-}" && "${GITHUB_SHA}" != "${candidate_sha}" ]]; then
  echo "hosted network qualification GITHUB_SHA does not match HEAD" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "hosted network qualification requires a clean exact candidate" >&2
  exit 1
fi
export CHIO_FINDING_CANDIDATE_SHA="${candidate_sha}"

output_root="target/release-qualification/cognition-market-network"
report_path="${output_root}/network-canary.json"
log_path="${output_root}/network-canary.log"
manifest_path="${output_root}/artifact-manifest.signed.json"
checksums_path="${output_root}/SHA256SUMS"
secret_root="$(mktemp -d "${TMPDIR:-/tmp}/chio-network-qualification.XXXXXX")"
signing_seed="${secret_root}/qualification.seed"
cleanup() {
  rm -f "${signing_seed}"
  rmdir "${secret_root}" || true
}
trap cleanup EXIT

rm -rf "${output_root}"
mkdir -p "${output_root}"
python3 - "${signing_seed}" <<'PY'
import os
import secrets
import sys

descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii") as stream:
    stream.write(secrets.token_hex(32) + "\n")
PY

env \
  -u CHIO_FINDING_HOSTED_PROFILE \
  -u CHIO_FINDING_NETWORK_CANARY_ARTIFACT \
  -u CHIO_FINDING_NETWORK_TENANT_ID \
  -u CHIO_FINDING_NETWORK_SELLER_KEY_ID \
  -u CHIO_FINDING_NETWORK_SELLER_KEY_SECRET \
  -u CHIO_FINDING_NETWORK_BUYER_KEY_ID \
  -u CHIO_FINDING_NETWORK_BUYER_KEY_SECRET \
  cargo build --locked -p chio-finding-market-canary --bin chio-finding-market-canary
canary_bin="$(realpath -e target/debug/chio-finding-market-canary)"
canary_environment=(
  "CHIO_FINDING_CANDIDATE_SHA=${candidate_sha}"
  "CHIO_FINDING_NETWORK_SELLER_KEY_ID=${CHIO_FINDING_NETWORK_SELLER_KEY_ID}"
  "CHIO_FINDING_NETWORK_SELLER_KEY_SECRET=${CHIO_FINDING_NETWORK_SELLER_KEY_SECRET}"
  "CHIO_FINDING_NETWORK_BUYER_KEY_ID=${CHIO_FINDING_NETWORK_BUYER_KEY_ID}"
  "CHIO_FINDING_NETWORK_BUYER_KEY_SECRET=${CHIO_FINDING_NETWORK_BUYER_KEY_SECRET}"
)
env -i "${canary_environment[@]}" "${canary_bin}" \
  --profile "${CHIO_FINDING_HOSTED_PROFILE}" \
  network \
  --finding "${CHIO_FINDING_NETWORK_CANARY_ARTIFACT}" \
  --tenant-id "${CHIO_FINDING_NETWORK_TENANT_ID}" \
  --seller-key-id-env CHIO_FINDING_NETWORK_SELLER_KEY_ID \
  --seller-key-secret-env CHIO_FINDING_NETWORK_SELLER_KEY_SECRET \
  --buyer-key-id-env CHIO_FINDING_NETWORK_BUYER_KEY_ID \
  --buyer-key-secret-env CHIO_FINDING_NETWORK_BUYER_KEY_SECRET \
  >"${report_path}" 2>"${log_path}"
unset \
  CHIO_FINDING_HOSTED_PROFILE \
  CHIO_FINDING_NETWORK_CANARY_ARTIFACT \
  CHIO_FINDING_NETWORK_TENANT_ID \
  CHIO_FINDING_NETWORK_SELLER_KEY_ID \
  CHIO_FINDING_NETWORK_SELLER_KEY_SECRET \
  CHIO_FINDING_NETWORK_BUYER_KEY_ID \
  CHIO_FINDING_NETWORK_BUYER_KEY_SECRET

python3 - "${report_path}" "${candidate_sha}" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
raw = path.read_bytes()
if not raw.endswith(b"\n"):
    raise SystemExit("network canary report is not newline terminated")
report = json.loads(raw)
canonical = json.dumps(
    report, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
).encode("utf-8") + b"\n"
if raw != canonical:
    raise SystemExit("network canary report is not canonical JSON")
expected_true = (
    "buyerPayloadMatched",
    "buyerCatalogMatched",
    "tenantIsolationDenied",
)
if (
    report.get("schema") != "chio.finding.hosted-network-canary-report.v1"
    or report.get("candidateSha") != sys.argv[2]
    or report.get("deployedCandidateSha") != sys.argv[2]
    or len(report.get("deployedArtifactSha256", "")) != 64
    or any(character not in "0123456789abcdef" for character in report.get("deployedArtifactSha256", ""))
    or report.get("retryOutcome") != "exact_replay"
    or any(report.get(field) is not True for field in expected_true)
):
    raise SystemExit("network canary report did not prove the bounded network contract")
PY

cargo run --locked -p chio-release-evidence \
  --bin chio-release-qualification-manifest -- \
  --repo-root . \
  --artifact-root "${output_root}" \
  --signing-seed "${signing_seed}" \
  --output "${manifest_path}" \
  --checksums "${checksums_path}" \
  --expected-candidate "${candidate_sha}"
cargo run --locked -p chio-release-evidence \
  --bin chio-release-qualification-manifest -- \
  --verify \
  --repo-root . \
  --artifact-root "${output_root}" \
  --output "${manifest_path}" \
  --checksums "${checksums_path}" \
  --expected-candidate "${candidate_sha}"

printf 'hosted cognition-market network qualification passed for %s; evidence: %s\n' \
  "${candidate_sha}" \
  "${manifest_path}"
