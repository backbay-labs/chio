#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

fixture="${tmp_dir}/repo"
mkdir -p "${fixture}/.kani" "${fixture}/formal/rust-verification" \
  "${fixture}/scripts" "${tmp_dir}/bin"
cp "${repo_root}/scripts/check-rust-verification-gates.sh" "${fixture}/scripts/"
cp "${repo_root}/.kani/harnesses.toml" "${fixture}/.kani/"
cp "${repo_root}"/formal/rust-verification/{creusot-contracts,kani-harnesses,kani-public-harnesses}.toml \
  "${fixture}/formal/rust-verification/"

log="${tmp_dir}/calls.log"
for script in \
  check-creusot-body-sync.sh \
  check-creusot-smoke.sh \
  check-kani-smoke.sh \
  check-creusot-core.sh \
  check-kani-core.sh \
  check-kani-public-core.sh \
  run-kani-manifest.sh
do
  cat >"${fixture}/scripts/${script}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$(basename "$0")" >>"${FAKE_VERIFICATION_LOG}"
printf ' %s' "$@" >>"${FAKE_VERIFICATION_LOG}"
printf '\n' >>"${FAKE_VERIFICATION_LOG}"
SH
  chmod +x "${fixture}/scripts/${script}"
done

for tool in creusot kani; do
  cat >"${tmp_dir}/bin/${tool}" <<'SH'
#!/usr/bin/env bash
exit 0
SH
  chmod +x "${tmp_dir}/bin/${tool}"
done

export FAKE_VERIFICATION_LOG="${log}"
export PATH="${tmp_dir}/bin:${PATH}"

: >"${log}"
CHIO_RUST_VERIFICATION_METADATA_ONLY=1 \
  bash "${fixture}/scripts/check-rust-verification-gates.sh"
if [[ "$(cat "${log}")" != "check-creusot-body-sync.sh " ]]; then
  echo "metadata-only Rust verification executed a strict proof command" >&2
  cat "${log}" >&2
  exit 1
fi

: >"${log}"
bash "${fixture}/scripts/check-rust-verification-gates.sh"
if [[ "$(grep -c '^run-kani-manifest.sh --lane pr --exclude-crate chio-kernel-core$' "${log}")" -ne 1 ]]; then
  echo "strict Rust verification did not execute the non-core manifest runner exactly once" >&2
  cat "${log}" >&2
  exit 1
fi
if [[ "$(grep -c '^check-kani-public-core.sh ' "${log}")" -ne 1 ]]; then
  echo "strict Rust verification did not own exactly one public-core invocation" >&2
  cat "${log}" >&2
  exit 1
fi

printf '\nunknown_entry = true\n' >>"${fixture}/.kani/harnesses.toml"
if CHIO_RUST_VERIFICATION_METADATA_ONLY=1 \
  bash "${fixture}/scripts/check-rust-verification-gates.sh" >/dev/null 2>&1; then
  echo "Rust verification accepted an unknown multi-crate harness key" >&2
  exit 1
fi

echo "Rust verification umbrella contract passed"
