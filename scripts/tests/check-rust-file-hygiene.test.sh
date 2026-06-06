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

write_codegen_header_source() {
  local root="$1"
  mkdir -p "$root/crates/chio-spec-codegen/src"
  cat > "$root/crates/chio-spec-codegen/src/lib.rs" <<'EOF'
pub const GENERATED_HEADER: &str = "\
// DO NOT EDIT - test generated header.
//
// Source: test/schema.json
";
EOF
  cat > "$root/crates/chio-spec-codegen/src/errors_pass.rs" <<'EOF'
const ERROR_CODES_GENERATED_HEADER: &str = "\
// DO NOT EDIT - regenerate via 'cargo run -p chio-spec-codegen -- --errors-only'.
//
// Source: spec/errors/registry.yaml
";
EOF
}

write_generated_wire() {
  local path="$1" count="$2"
  mkdir -p "$(dirname "$path")"
  {
    cat <<'EOF'
// DO NOT EDIT - test generated header.
//
// Source: test/schema.json

EOF
    awk -v count="$count" 'BEGIN { for (i = 1; i <= count; i++) print "pub fn marker_" i "() {}" }'
  } > "$path"
}

write_generated_errors() {
  local path="$1" count="$2"
  mkdir -p "$(dirname "$path")"
  {
    cat <<'EOF'
// DO NOT EDIT - regenerate via 'cargo run -p chio-spec-codegen -- --errors-only'.
//
// Source: spec/errors/registry.yaml

EOF
    awk -v count="$count" 'BEGIN { for (i = 1; i <= count; i++) print "pub const ERROR_" i ": &str = \"E\";" }'
  } > "$path"
}

init_case() {
  local root="$1"
  mkdir -p "$root"
  git -C "$root" init -q
  write_codegen_header_source "$root"
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
write_generated_wire "$pass_case/crates/chio-core-types/src/_generated/chio_wire_v1.rs" 3001
write_generated_errors "$pass_case/crates/chio-errors/src/_generated/error_codes.rs" 2501
track_case "$pass_case"
assert_rc "$(run_checker "$pass_case" "$work/pass.out" "$work/pass.err")" 0 \
  "small production plus large test/generated files with canonical header pass"
grep -F "generated top" "$work/pass.out" >/dev/null
grep -F "test top" "$work/pass.out" >/dev/null

bad_generated="$work/bad-generated"
init_case "$bad_generated"
write_lines "$bad_generated/crates/chio-small/src/main.rs" 25
write_lines "$bad_generated/crates/chio-core-types/src/_generated/chio_wire_v1.rs" 25
track_case "$bad_generated"
assert_rc "$(run_checker "$bad_generated" "$work/bad-generated.out" "$work/bad-generated.err")" 1 \
  "generated wire file without canonical header fails"
grep -F "crates/chio-core-types/src/_generated/chio_wire_v1.rs: generated Rust file does not begin with chio_spec_codegen::GENERATED_HEADER" \
  "$work/bad-generated.err" >/dev/null

bad_error_generated="$work/bad-error-generated"
init_case "$bad_error_generated"
write_lines "$bad_error_generated/crates/chio-small/src/main.rs" 25
write_lines "$bad_error_generated/crates/chio-errors/src/_generated/error_codes.rs" 2501
track_case "$bad_error_generated"
assert_rc "$(run_checker "$bad_error_generated" "$work/bad-error-generated.out" "$work/bad-error-generated.err")" 1 \
  "generated error-code file without canonical header fails"
grep -F "crates/chio-errors/src/_generated/error_codes.rs: generated Rust file does not begin with chio_spec_codegen::errors_pass::ERROR_CODES_GENERATED_HEADER" \
  "$work/bad-error-generated.err" >/dev/null

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

expired_allowlist="$work/expired-allowlist"
init_case "$expired_allowlist"
write_lines "$expired_allowlist/crates/chio-governance/src/lib.rs" 2101
track_case "$expired_allowlist"
assert_rc "$(run_checker "$expired_allowlist" "$work/expired-allowlist.out" "$work/expired-allowlist.err")" 1 \
  "expired baseline allowlist entry fails"
grep -F "crates/chio-governance/src/lib.rs: production file has 2101 lines" \
  "$work/expired-allowlist.err" >/dev/null

large_example="$work/large-example"
init_case "$large_example"
write_lines "$large_example/examples/oversized/src/main.rs" 3000
track_case "$large_example"
assert_rc "$(run_checker "$large_example" "$work/large-example.out" "$work/large-example.err")" 0 \
  "large example file is classified separately"
grep -F "example top" "$work/large-example.out" >/dev/null

echo "check-rust-file-hygiene.test.sh: all assertions passed"
