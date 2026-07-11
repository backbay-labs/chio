#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp_dir="$(mktemp -d)"
scratch_rel="target/check-apalache-negative-selftest-$$"
scratch_dir="${repo_root}/${scratch_rel}"
negative_rel="formal/apalache/_negative_tests"
fixture_spec_rel="${negative_rel}/SelfTestBroken.tla"
fixture_cfg_rel="${negative_rel}/MCSelfTestBroken.cfg"
multi_spec_rel="${negative_rel}/SelfTestMultipleBroken.tla"
multi_cfg_rel="${negative_rel}/MCSelfTestMultipleBroken.cfg"
invalid_spec_rel="${negative_rel}/escape-name.tla"
invalid_cfg_rel="${negative_rel}/MCescape-name.cfg"

cleanup() {
  rm -rf "${tmp_dir}" "${scratch_dir}"
  rm -f \
    "${repo_root}/${fixture_spec_rel}" \
    "${repo_root}/${fixture_cfg_rel}" \
    "${repo_root}/${multi_spec_rel}" \
    "${repo_root}/${multi_cfg_rel}" \
    "${repo_root}/${invalid_spec_rel}" \
    "${repo_root}/${invalid_cfg_rel}"
}
trap cleanup EXIT
mkdir -p "${scratch_dir}"
cp "${repo_root}/${negative_rel}/ReceiptBeforeAllowBroken.tla" \
  "${repo_root}/${fixture_spec_rel}"
cp "${repo_root}/${negative_rel}/MCReceiptBeforeAllowBroken.cfg" \
  "${repo_root}/${fixture_cfg_rel}"
cp "${repo_root}/${fixture_spec_rel}" "${repo_root}/${multi_spec_rel}"
printf '%s\n' "INVARIANT" "ReceiptBeforeAllow" >"${repo_root}/${multi_cfg_rel}"
cat "${repo_root}/${fixture_cfg_rel}" >>"${repo_root}/${multi_cfg_rel}"

fake_apalache="${tmp_dir}/apalache-mc"
cat >"${fake_apalache}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "version" ]]; then
  printf '%s\n' "${FAKE_APALACHE_VERSION:-0.50.1}"
  exit 0
fi

run_dir=""
spec=""
config=""
for arg in "$@"; do
  case "${arg}" in
    --run-dir=*) run_dir="${arg#--run-dir=}" ;;
    --config=*) config="${arg#--config=}" ;;
    *.tla) spec="${arg}" ;;
  esac
done

invariant="$(awk '
  found { print $1; exit }
  /^[[:space:]]*INVARIANT[[:space:]]*$/ { found = 1 }
' "${config}")"

write_invariant() {
  printf '%s\n' "> Set an invariant to ${1}"
}

write_error() {
  printf '%s\n' "The outcome is: Error"
}

write_valid_trace() {
  mkdir -p "${run_dir}"
  printf '%s\n' '{"#meta":{"format":"ITF","format-description":"https://apalache-mc.org/docs/adr/015adr-trace.html","varTypes":{"witness":"Bool"}},"params":[],"vars":["witness"],"states":[{"#meta":{"index":0},"witness":false}]}' >"${run_dir}/violation1.itf.json"
}

case "${FAKE_APALACHE_MODE:-pass}" in
  pass)
    write_invariant "${invariant}"
    write_error
    write_valid_trace
    exit 12
    ;;
  receipt-noerror)
    write_invariant "${invariant}"
    if [[ "$(basename "${spec}")" == "ReceiptBeforeAllowBroken.tla" ]]; then
      printf '%s\n' "The outcome is: NoError"
      exit 0
    fi
    write_error
    write_valid_trace
    exit 12
    ;;
  wrong-exit)
    write_invariant "${invariant}"
    write_error
    write_valid_trace
    exit 2
    ;;
  missing-outcome)
    write_invariant "${invariant}"
    write_valid_trace
    exit 12
    ;;
  duplicate-outcome)
    write_invariant "${invariant}"
    write_error
    write_error
    write_valid_trace
    exit 12
    ;;
  wrong-invariant)
    write_invariant "WrongInvariant"
    write_error
    write_valid_trace
    exit 12
    ;;
  missing-trace)
    write_invariant "${invariant}"
    write_error
    exit 12
    ;;
  duplicate-trace)
    write_invariant "${invariant}"
    write_error
    write_valid_trace
    cp "${run_dir}/violation1.itf.json" "${run_dir}/violation2.itf.json"
    exit 12
    ;;
  invalid-trace)
    write_invariant "${invariant}"
    write_error
    mkdir -p "${run_dir}"
    printf '%s\n' '{"states":[]}' >"${run_dir}/violation1.itf.json"
    exit 12
    ;;
  state-key-mismatch)
    write_invariant "${invariant}"
    write_error
    mkdir -p "${run_dir}"
    printf '%s\n' '{"#meta":{"format":"ITF","varTypes":{"witness":"Bool"}},"params":[],"vars":["witness"],"states":[{"#meta":{"index":0}}]}' >"${run_dir}/violation1.itf.json"
    exit 12
    ;;
  timeout)
    exit 124
    ;;
  *)
    exit 99
    ;;
esac
SH
chmod +x "${fake_apalache}"

run_gate() {
  local mode="$1"
  local output="$2"
  local artifacts="${3:-${tmp_dir}/artifacts-${mode}}"
  local registry="${4:-formal/apalache/_negative_tests/REGISTRY.toml}"
  local version="${5:-0.50.1}"
  set +e
  FAKE_APALACHE_MODE="${mode}" \
    FAKE_APALACHE_VERSION="${version}" \
    APALACHE_BIN="${fake_apalache}" \
    CHIO_APALACHE_NEGATIVE_REGISTRY="${registry}" \
    CHIO_APALACHE_NEGATIVE_OUTPUT_DIR="${artifacts}" \
    "${repo_root}/scripts/check-apalache-negative.sh" >"${output}" 2>&1
  local result=$?
  set -e
  return "${result}"
}

expect_gate_failure() {
  local mode="$1"
  local expected="$2"
  local label="$3"
  local log="${tmp_dir}/${label}.log"
  if run_gate "${mode}" "${log}"; then
    echo "expected ${label} to fail" >&2
    exit 1
  fi
  grep -Fq "${expected}" "${log}"
}

write_registry() {
  local destination="$1"
  local config="$2"
  local production_commit="$3"
  local runtime_test="$4"
  local spec="${5:-${fixture_spec_rel}}"
  cat >"${destination}" <<EOF
schema = "chio.apalache-negative.v1"

[[negative]]
spec = "${spec}"
cfg = "${config}"
falsifies = "ReceiptBeforeAllow"
production_commit = "${production_commit}"
runtime_test = "${runtime_test}"
classification = "spec-mutation"
length = 4
timeout_secs = 30
notes = "Self-test registry fixture."
EOF
}

pass_log="${tmp_dir}/pass.log"
run_gate pass "${pass_log}"
grep -Fq "check-apalache-negative: 10 counterexamples reproduced" "${pass_log}"

expect_gate_failure receipt-noerror \
  "reported NoError for ReceiptBeforeAllow" "restored-invariant"
expect_gate_failure wrong-exit \
  "expected 0 or violation exit 12" "unexpected-exit"
expect_gate_failure missing-outcome \
  "invalid invariant or outcome evidence" "missing-outcome"
expect_gate_failure duplicate-outcome \
  "invalid invariant or outcome evidence" "duplicate-outcome"
expect_gate_failure wrong-invariant \
  "invalid invariant or outcome evidence" "wrong-invariant"
expect_gate_failure missing-trace \
  "did not produce exactly one ITF violation trace" "missing-trace"
expect_gate_failure duplicate-trace \
  "did not produce exactly one ITF violation trace" "duplicate-trace"
expect_gate_failure invalid-trace \
  "produced an invalid ITF violation trace" "invalid-trace"
expect_gate_failure state-key-mismatch \
  "produced an invalid ITF violation trace" "state-key-mismatch"
expect_gate_failure timeout "NEGATIVE-TEST TIMEOUT" "timeout"

wrong_version_log="${tmp_dir}/wrong-version.log"
if run_gate pass "${wrong_version_log}" "${tmp_dir}/wrong-version-output" \
  "formal/apalache/_negative_tests/REGISTRY.toml" "0.50.10"; then
  echo "expected Apalache 0.50.10 to fail the exact version pin" >&2
  exit 1
fi
grep -Fq "Apalache 0.50.1 is required" "${wrong_version_log}"

temporary_root="$(python3 - <<'PY'
import tempfile
print(tempfile.gettempdir())
PY
)"
for unsafe_output in "${repo_root}" "${repo_root}/scripts" \
  "${repo_root}/target" "${temporary_root}"; do
  unsafe_log="${tmp_dir}/unsafe-$(printf '%s' "${unsafe_output}" | sha256sum | cut -d' ' -f1).log"
  if run_gate pass "${unsafe_log}" "${unsafe_output}"; then
    echo "expected unsafe output path ${unsafe_output} to fail" >&2
    exit 1
  fi
  grep -Fq "output directory must be below target or the system temporary directory outside the repository" "${unsafe_log}"
done

ln -s "${repo_root}" "${tmp_dir}/symlink-escape"
symlink_log="${tmp_dir}/symlink-escape.log"
if run_gate pass "${symlink_log}" "${tmp_dir}/symlink-escape"; then
  echo "expected an output symlink escaping the allowed roots to fail" >&2
  exit 1
fi
grep -Fq "output directory must be below target or the system temporary directory outside the repository" "${symlink_log}"
test -f "${repo_root}/scripts/check-apalache-negative.sh"

multi_registry="${scratch_dir}/multi-invariant.toml"
write_registry "${multi_registry}" "${multi_cfg_rel}" \
  "n/a (self-test has no production fix)" \
  "n/a (self-test has no runtime regression)" "${multi_spec_rel}"
multi_log="${tmp_dir}/multi-invariant.log"
if run_gate pass "${multi_log}" "${tmp_dir}/multi-output" "${multi_registry}"; then
  echo "expected a config selecting two invariants to fail" >&2
  exit 1
fi
grep -Fq "config must select exactly ReceiptBeforeAllow" "${multi_log}"

bad_na_registry="${scratch_dir}/bad-na.toml"
write_registry "${bad_na_registry}" "${fixture_cfg_rel}" \
  "n/a" "n/a (self-test has no runtime regression)"
bad_na_log="${tmp_dir}/bad-na.log"
if run_gate pass "${bad_na_log}" "${tmp_dir}/bad-na-output" "${bad_na_registry}"; then
  echo "expected an n/a value without a reason to fail" >&2
  exit 1
fi
grep -Fq "production_commit n/a value must include one parenthesized reason" "${bad_na_log}"

bad_runtime_na_registry="${scratch_dir}/bad-runtime-na.toml"
write_registry "${bad_runtime_na_registry}" "${fixture_cfg_rel}" \
  "n/a (self-test has no production fix)" "n/a"
bad_runtime_na_log="${tmp_dir}/bad-runtime-na.log"
if run_gate pass "${bad_runtime_na_log}" "${tmp_dir}/bad-runtime-na-output" \
  "${bad_runtime_na_registry}"; then
  echo "expected a runtime n/a value without a reason to fail" >&2
  exit 1
fi
grep -Fq "runtime_test n/a value must include one parenthesized reason" \
  "${bad_runtime_na_log}"

printf '%s\n' "// fn comment_only_anchor() {}" >"${scratch_dir}/comment-only.rs"
comment_registry="${scratch_dir}/comment-anchor.toml"
write_registry "${comment_registry}" "${fixture_cfg_rel}" \
  "n/a (self-test has no production fix)" \
  "${scratch_rel}/comment-only.rs::comment_only_anchor"
comment_log="${tmp_dir}/comment-anchor.log"
if run_gate pass "${comment_log}" "${tmp_dir}/comment-output" "${comment_registry}"; then
  echo "expected a comment-only Rust anchor to fail" >&2
  exit 1
fi
grep -Fq "runtime test anchor is not a Rust test declaration" "${comment_log}"

blob_sha="$(git -C "${repo_root}" rev-parse HEAD:Cargo.toml)"
blob_registry="${scratch_dir}/blob-commit.toml"
write_registry "${blob_registry}" "${fixture_cfg_rel}" \
  "${blob_sha}" "n/a (self-test has no runtime regression)"
blob_log="${tmp_dir}/blob-commit.log"
if run_gate pass "${blob_log}" "${tmp_dir}/blob-output" "${blob_registry}"; then
  echo "expected a blob SHA in production_commit to fail" >&2
  exit 1
fi
grep -Fq "production_commit is not a commit object" "${blob_log}"

cp "${repo_root}/${fixture_spec_rel}" "${repo_root}/${invalid_spec_rel}"
cp "${repo_root}/${fixture_cfg_rel}" "${repo_root}/${invalid_cfg_rel}"
invalid_spec_registry="${scratch_dir}/invalid-spec-name.toml"
write_registry "${invalid_spec_registry}" "${invalid_cfg_rel}" \
  "n/a (self-test has no production fix)" \
  "n/a (self-test has no runtime regression)" "${invalid_spec_rel}"
invalid_spec_log="${tmp_dir}/invalid-spec-name.log"
if run_gate pass "${invalid_spec_log}" "${tmp_dir}/invalid-spec-output" \
  "${invalid_spec_registry}"; then
  echo "expected a non-identifier spec stem to fail" >&2
  exit 1
fi
grep -Fq "spec must be an identifier-named .tla file" "${invalid_spec_log}"

traversal_registry="${scratch_dir}/traversal-spec.toml"
write_registry "${traversal_registry}" "${fixture_cfg_rel}" \
  "n/a (self-test has no production fix)" \
  "n/a (self-test has no runtime regression)" \
  "${negative_rel}/../_negative_tests/SelfTestBroken.tla"
traversal_log="${tmp_dir}/traversal-spec.log"
if run_gate pass "${traversal_log}" "${tmp_dir}/traversal-spec-output" \
  "${traversal_registry}"; then
  echo "expected a traversing spec path to fail" >&2
  exit 1
fi
grep -Fq "spec must be an identifier-named .tla file" "${traversal_log}"

echo "PASS: Apalache negative gate validates registry, tool evidence, traces, and paths"
