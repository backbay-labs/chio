#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-stub-surfaces.py"

work="$(mktemp -d -t chio-stub-surfaces-XXXXXX)"
trap 'rm -rf "$work"' EXIT

init_case() {
  local root="$1"
  mkdir -p "$root"
  git -C "$root" init -q
}

track_case() {
  local root="$1"
  git -C "$root" add .
}

write_file() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  shift
  printf '%s\n' "$@" > "$path"
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

non_production="$work/non-production"
init_case "$non_production"
write_file "$non_production/docs/example.md" "TODO: documented follow-up"
write_file "$non_production/tests/replay.rs" "fn test_stub() {}"
write_file "$non_production/examples/demo/src/main.rs" "fn main() { /* placeholder */ }"
write_file "$non_production/scripts/example.sh" "# FIXME: script fixture"
write_file "$non_production/crates/chio-demo/src/_generated/wire.rs" "// not_yet_implemented generated fixture"
track_case "$non_production"
assert_rc "$(run_checker "$non_production" "$work/non-production.out" "$work/non-production.err")" 0 \
  "non-production stub-surface hits pass"
grep -F "Stub-surface check passed" "$work/non-production.out" >/dev/null

production_fail="$work/production-fail"
init_case "$production_fail"
write_file "$production_fail/crates/chio-demo/src/lib.rs" \
  "pub fn evaluate() {" \
  "    // TODO: replace placeholder implementation" \
  "}"
track_case "$production_fail"
assert_rc "$(run_checker "$production_fail" "$work/production-fail.out" "$work/production-fail.err")" 1 \
  "unallowlisted production stub hit fails"
grep -F "production stub-surface hit is not allowlisted" \
  "$work/production-fail.err" >/dev/null

lowercase_fail="$work/lowercase-fail"
init_case "$lowercase_fail"
write_file "$lowercase_fail/crates/chio-demo/src/lib.rs" \
  "pub fn evaluate() {" \
  "    todo!(\"wire production evaluator\");" \
  "}" \
  "pub fn parse() {" \
  "    unimplemented!(\"parse policy input\");" \
  "}"
track_case "$lowercase_fail"
assert_rc "$(run_checker "$lowercase_fail" "$work/lowercase-fail.out" "$work/lowercase-fail.err")" 1 \
  "lowercase Rust todo and unimplemented macros fail"
grep -F "production stub-surface hit is not allowlisted" \
  "$work/lowercase-fail.err" >/dev/null

tracked_non_prefix_fail="$work/tracked-non-prefix-fail"
init_case "$tracked_non_prefix_fail"
write_file "$tracked_non_prefix_fail/sdks/rust/chio-demo/src/lib.rs" \
  "pub fn adapter() {" \
  "    // TODO: replace placeholder SDK adapter" \
  "}"
track_case "$tracked_non_prefix_fail"
assert_rc "$(run_checker "$tracked_non_prefix_fail" "$work/tracked-non-prefix-fail.out" "$work/tracked-non-prefix-fail.err")" 1 \
  "tracked production files outside old prefixes fail"
grep -F "sdks/rust/chio-demo/src/lib.rs:2" \
  "$work/tracked-non-prefix-fail.err" >/dev/null

untracked_production_fail="$work/untracked-production-fail"
init_case "$untracked_production_fail"
write_file "$untracked_production_fail/crates/chio-demo/src/lib.rs" \
  "pub fn evaluate() {" \
  "    // TODO: untracked production placeholder" \
  "}"
assert_rc "$(run_checker "$untracked_production_fail" "$work/untracked-production-fail.out" "$work/untracked-production-fail.err")" 1 \
  "untracked production stub hit fails"
grep -F "crates/chio-demo/src/lib.rs:2" \
  "$work/untracked-production-fail.err" >/dev/null

session_split_allow="$work/session-split-allow"
init_case "$session_split_allow"
write_file "$session_split_allow/crates/products/chio-cli/src/cli/session/test_support.rs" \
  "serde_json::json!({" \
  "  \"stub\": true," \
  "})"
track_case "$session_split_allow"
assert_rc "$(run_checker "$session_split_allow" "$work/session-split-allow.out" "$work/session-split-allow.err")" 0 \
  "split session test support stub payload is allowlisted"
grep -F "Stub-surface check passed" "$work/session-split-allow.out" >/dev/null

federation_bbs_stub="$work/federation-bbs-stub"
init_case "$federation_bbs_stub"
write_file "$federation_bbs_stub/crates/trust/chio-federation/src/selective_disclosure.rs" \
  "#[cfg(feature = \"bbs-stub\")]" \
  "pub fn project() { /* bbs-stub placeholder projection */ }"
track_case "$federation_bbs_stub"
assert_rc "$(run_checker "$federation_bbs_stub" "$work/federation-bbs-stub.out" "$work/federation-bbs-stub.err")" 1 \
  "bbs-stub production feature surface fails"
grep -F "production stub-surface hit is not allowlisted" \
  "$work/federation-bbs-stub.err" >/dev/null

federation_unrelated="$work/federation-unrelated"
init_case "$federation_unrelated"
write_file "$federation_unrelated/crates/trust/chio-federation/src/selective_disclosure.rs" \
  "#[cfg(feature = \"bbs-stub\")]" \
  "pub fn project() { /* bbs-stub placeholder projection */ }" \
  "pub fn unrelated() { /* TODO: unrelated production work */ }"
track_case "$federation_unrelated"
assert_rc "$(run_checker "$federation_unrelated" "$work/federation-unrelated.out" "$work/federation-unrelated.err")" 1 \
  "bbs-stub federation file rejects unrelated production TODO"
grep -F "production stub-surface hit is not allowlisted" \
  "$work/federation-unrelated.err" >/dev/null

guard_unrelated="$work/guard-unrelated"
init_case "$guard_unrelated"
write_file "$guard_unrelated/crates/products/chio-cli/src/guard/new.rs" \
  "// Replace this stub with real policy logic before shipping." \
  "pub fn unrelated() { /* TODO: unrelated production work */ }"
track_case "$guard_unrelated"
assert_rc "$(run_checker "$guard_unrelated" "$work/guard-unrelated.out" "$work/guard-unrelated.err")" 1 \
  "allowlisted guard file rejects unrelated production TODO"
grep -F "does not match reviewed allowlist patterns" \
  "$work/guard-unrelated.err" >/dev/null

sidecar_deny="$work/sidecar-deny"
init_case "$sidecar_deny"
write_file "$sidecar_deny/crates/products/chio-api-protect/src/proxy/sidecar.rs" \
  "// Capability attenuation (501 not_yet_implemented stub)"
track_case "$sidecar_deny"
assert_rc "$(run_checker "$sidecar_deny" "$work/sidecar-deny.out" "$work/sidecar-deny.err")" 1 \
  "sidecar attenuation stub remains a hard failure"
grep -F "crates/products/chio-api-protect/src/proxy/sidecar.rs:1" "$work/sidecar-deny.err" >/dev/null
grep -F "production stub-surface hit is not allowlisted" "$work/sidecar-deny.err" >/dev/null

echo "check-stub-surfaces.test.sh: all assertions passed"
