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

federation_allow="$work/federation-allow"
init_case "$federation_allow"
write_file "$federation_allow/crates/chio-federation/src/selective_disclosure.rs" \
  "#[cfg(feature = \"bbs-stub\")]" \
  "pub fn project() { /* bbs-stub placeholder projection */ }"
track_case "$federation_allow"
assert_rc "$(run_checker "$federation_allow" "$work/federation-allow.out" "$work/federation-allow.err")" 0 \
  "bbs-stub allowlisted feature surface passes"
grep -F "allowlisted until Phase 2.2 review" "$work/federation-allow.out" >/dev/null

sidecar_deny="$work/sidecar-deny"
init_case "$sidecar_deny"
write_file "$sidecar_deny/crates/chio-api-protect/src/proxy/sidecar.rs" \
  "// Capability attenuation (501 not_yet_implemented stub)"
track_case "$sidecar_deny"
assert_rc "$(run_checker "$sidecar_deny" "$work/sidecar-deny.out" "$work/sidecar-deny.err")" 1 \
  "sidecar attenuation stub remains a hard failure"
grep -F "blocked production stub surface" "$work/sidecar-deny.err" >/dev/null
grep -F "Phase 5.3 resolves or fail-closes the route" "$work/sidecar-deny.err" >/dev/null

echo "check-stub-surfaces.test.sh: all assertions passed"
