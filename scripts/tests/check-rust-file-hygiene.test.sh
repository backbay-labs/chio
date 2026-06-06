#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-rust-file-hygiene.py"

work="$(mktemp -d -t chio-rust-file-hygiene-XXXXXX)"
trap 'rm -rf "$work"' EXIT

write_lines() {
  local path="$1" count="$2"
  mkdir -p "$(dirname "$path")"
  awk -v count="$count" 'BEGIN { for (i = 1; i <= count; i++) print "pub fn marker_" i "() {}" }' > "$path"
}

init_case() {
  local root="$1"
  mkdir -p "$root"
  git -C "$root" init -q
}

track_case() {
  local root="$1"
  git -C "$root" add .
}

run_checker() {
  local root="$1" stdout="$2" stderr="$3"
  local rc=0
  python3 "$CHECKER" --root "$root" >"$stdout" 2>"$stderr" || rc=$?
  echo "$rc"
}

assert_rc() {
  local got="$1" want="$2" label="$3"
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $label: got rc=$got, want rc=$want" >&2
    exit 1
  fi
  echo "ok: $label (rc=$got)"
}

pass_case="$work/pass"
init_case "$pass_case"
write_lines "$pass_case/crates/chio-small/src/main.rs" 25
write_lines "$pass_case/crates/chio-small/tests/large.rs" 2501
write_lines "$pass_case/crates/chio-small/src/_generated/wire.rs" 3001
track_case "$pass_case"
assert_rc "$(run_checker "$pass_case" "$work/pass.out" "$work/pass.err")" 0 \
  "small production plus large test/generated files pass"
grep -F "generated top" "$work/pass.out" >/dev/null
grep -F "test top" "$work/pass.out" >/dev/null

large_production="$work/large-production"
init_case "$large_production"
write_lines "$large_production/crates/chio-small/src/main.rs" 2001
track_case "$large_production"
assert_rc "$(run_checker "$large_production" "$work/large-production.out" "$work/large-production.err")" 1 \
  "oversized production file fails"
grep -F "crates/chio-small/src/main.rs: production file has 2001 lines" \
  "$work/large-production.err" >/dev/null

large_lib="$work/large-lib"
init_case "$large_lib"
write_lines "$large_lib/crates/chio-small/src/lib.rs" 1001
track_case "$large_lib"
assert_rc "$(run_checker "$large_lib" "$work/large-lib.out" "$work/large-lib.err")" 1 \
  "oversized lib root fails"
grep -F "crates/chio-small/src/lib.rs: src/lib.rs has 1001 lines" \
  "$work/large-lib.err" >/dev/null

allowlisted_lib="$work/allowlisted-lib"
init_case "$allowlisted_lib"
write_lines "$allowlisted_lib/crates/chio-governance/src/lib.rs" 2101
track_case "$allowlisted_lib"
assert_rc "$(run_checker "$allowlisted_lib" "$work/allowlisted-lib.out" "$work/allowlisted-lib.err")" 0 \
  "baseline allowlisted lib root passes"
grep -F "allowlisted: crates/chio-governance/src/lib.rs" \
  "$work/allowlisted-lib.out" >/dev/null
grep -F "expires Phase 1.1" "$work/allowlisted-lib.out" >/dev/null

large_example="$work/large-example"
init_case "$large_example"
write_lines "$large_example/examples/oversized/src/main.rs" 3000
track_case "$large_example"
assert_rc "$(run_checker "$large_example" "$work/large-example.out" "$work/large-example.err")" 0 \
  "large example file is classified separately"
grep -F "example top" "$work/large-example.out" >/dev/null

echo "check-rust-file-hygiene.test.sh: all assertions passed"
