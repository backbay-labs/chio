#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

fake_apalache="${tmp_dir}/apalache-mc"
config="${tmp_dir}/model.cfg"
spec="${tmp_dir}/Model.tla"
: >"${config}"
: >"${spec}"

cat >"${fake_apalache}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "version" ]]; then
  printf '%s\n' '0.50.1'
  exit 0
fi

run_dir=""
requested_length=""
requested_temporal=""
for argument in "$@"; do
  case "${argument}" in
    --run-dir=*) run_dir="${argument#*=}" ;;
    --length=*) requested_length="${argument#*=}" ;;
    --temporal=*) requested_temporal="${argument#*=}" ;;
  esac
done

marker_kind="${FAKE_MARKER_KIND:-invariant}"
marker_name="${FAKE_MARKER_NAME:-SafetyInv}"
if [[ "${marker_kind}" == "temporal" ]]; then
  marker_name="${FAKE_MARKER_NAME:-${requested_temporal}}"
  printf '> Set a temporal property to %s\n' "${marker_name}"
else
  printf '> Set an invariant to %s\n' "${marker_name}"
fi

outcome="${FAKE_OUTCOME:-NoError}"
reported_length="${FAKE_REPORTED_LENGTH:-${requested_length}}"
printf 'The outcome is: %s\n' "${outcome}"
printf 'Checker reports no error up to computation length %s\n' "${reported_length}"
if [[ "${FAKE_WRITE_TRACE:-0}" == "1" ]]; then
  printf '{}\n' >"${run_dir}/violation1.itf.json"
fi
exit "${FAKE_EXIT_CODE:-0}"
EOF
chmod +x "${fake_apalache}"

run_invariant() {
  APALACHE_BIN="${fake_apalache}" \
    ./scripts/check-apalache-positive.sh \
      --invariant SafetyInv \
      --length 6 \
      --timeout-seconds 10 \
      --config "${config}" \
      "${spec}"
}

run_temporal() {
  FAKE_MARKER_KIND=temporal \
    APALACHE_BIN="${fake_apalache}" \
    ./scripts/check-apalache-positive.sh \
      --temporal EventuallySafe \
      --length 8 \
      --timeout-seconds 10 \
      --config "${config}" \
      "${spec}"
}

expect_failure() {
  local description="$1"
  shift
  if "$@" >"${tmp_dir}/failure.log" 2>&1; then
    echo "expected failure: ${description}" >&2
    exit 1
  fi
}

run_invariant >/dev/null
run_temporal >/dev/null

expect_failure "ExecutionsTooShort exit zero" \
  env FAKE_OUTCOME=ExecutionsTooShort APALACHE_BIN="${fake_apalache}" \
  ./scripts/check-apalache-positive.sh --invariant SafetyInv --length 6 \
    --timeout-seconds 10 --config "${config}" "${spec}"

expect_failure "wrong computation length" \
  env FAKE_REPORTED_LENGTH=5 APALACHE_BIN="${fake_apalache}" \
  ./scripts/check-apalache-positive.sh --invariant SafetyInv --length 6 \
    --timeout-seconds 10 --config "${config}" "${spec}"

expect_failure "wrong invariant" \
  env FAKE_MARKER_NAME=OtherInv APALACHE_BIN="${fake_apalache}" \
  ./scripts/check-apalache-positive.sh --invariant SafetyInv --length 6 \
    --timeout-seconds 10 --config "${config}" "${spec}"

expect_failure "wrong temporal property" \
  env FAKE_MARKER_KIND=temporal FAKE_MARKER_NAME=OtherProperty \
    APALACHE_BIN="${fake_apalache}" \
  ./scripts/check-apalache-positive.sh --temporal EventuallySafe --length 8 \
    --timeout-seconds 10 --config "${config}" "${spec}"

expect_failure "nonzero tool exit" \
  env FAKE_EXIT_CODE=12 APALACHE_BIN="${fake_apalache}" \
  ./scripts/check-apalache-positive.sh --invariant SafetyInv --length 6 \
    --timeout-seconds 10 --config "${config}" "${spec}"

expect_failure "violation trace with NoError" \
  env FAKE_WRITE_TRACE=1 APALACHE_BIN="${fake_apalache}" \
  ./scripts/check-apalache-positive.sh --invariant SafetyInv --length 6 \
    --timeout-seconds 10 --config "${config}" "${spec}"

echo "check-apalache-positive tests passed"
