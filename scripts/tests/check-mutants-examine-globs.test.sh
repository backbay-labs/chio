#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-mutants-examine-globs.py"

work="$(mktemp -d -t chio-mutants-globs-XXXXXX)"
trap 'rm -rf "$work"' EXIT

write_file() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  shift
  printf '%s\n' "$@" > "$path"
}

assert_passes() {
  local label="$1"
  shift
  if "$@" >"$work/out" 2>"$work/err"; then
    echo "ok: $label"
  else
    echo "FAIL: $label" >&2
    cat "$work/out" >&2
    cat "$work/err" >&2
    exit 1
  fi
}

assert_fails() {
  local label="$1"
  local expected="$2"
  shift 2
  if "$@" >"$work/out" 2>"$work/err"; then
    echo "FAIL: $label unexpectedly passed" >&2
    cat "$work/out" >&2
    exit 1
  fi
  grep -F "$expected" "$work/err" >/dev/null || {
    echo "FAIL: $label missing expected diagnostic: $expected" >&2
    cat "$work/err" >&2
    exit 1
  }
  echo "ok: $label"
}

root="$work/repo"
mkdir -p "$root/crates/trust/chio-attest-verify/src/sigstore"
touch "$root/crates/trust/chio-attest-verify/src/sigstore/core.rs"
touch "$root/crates/trust/chio-attest-verify/src/sigstore/tests.rs"

write_file "$root/good.toml" \
  'examine_globs = ["crates/trust/chio-attest-verify/src/sigstore/*.rs"]' \
  'exclude_globs = ["**/tests.rs"]'
assert_passes "active examine glob passes" \
  python3 "$CHECKER" --root "$root" --config good.toml

write_file "$root/missing.toml" \
  'examine_globs = ["crates/trust/chio-attest-verify/src/missing/*.rs"]'
assert_fails "missing examine glob fails" "matches no paths" \
  python3 "$CHECKER" --root "$root" --config missing.toml

write_file "$root/excluded.toml" \
  'examine_globs = ["crates/trust/chio-attest-verify/src/sigstore/tests.rs"]' \
  'exclude_globs = ["**/tests.rs"]'
assert_fails "excluded-only examine glob fails" "matches only excluded paths" \
  python3 "$CHECKER" --root "$root" --config excluded.toml

mkdir -p "$root/crates/guards/chio-policy/src/compiler"
write_file "$root/crates/guards/chio-policy/src/compiler.rs" \
  'mod rules;' \
  '#[cfg(test)]' \
  'mod tests {' \
  '    fn test_only() {}' \
  '}'
write_file "$root/crates/guards/chio-policy/src/compiler/rules.rs" \
  'pub fn compile_rule() -> bool {' \
  '    true' \
  '}'
write_file "$root/hollow-shim.toml" \
  'examine_globs = ["crates/guards/chio-policy/src/compiler.rs"]' \
  'exclude_globs = ["**/tests.rs"]'
assert_fails "hollow shim examine glob fails" "sibling module directory is not examined" \
  python3 "$CHECKER" --root "$root" --config hollow-shim.toml

write_file "$root/covered-shim.toml" \
  'examine_globs = [' \
  '  "crates/guards/chio-policy/src/compiler.rs",' \
  '  "crates/guards/chio-policy/src/compiler/*.rs",' \
  ']' \
  'exclude_globs = ["**/tests.rs"]'
assert_passes "covered shim examine glob passes" \
  python3 "$CHECKER" --root "$root" --config covered-shim.toml

missing_workspace_root="$work/missing-workspace-config"
mkdir -p "$missing_workspace_root"
assert_fails "missing workspace config fails closed" "config file is missing" \
  python3 "$CHECKER" --root "$missing_workspace_root"

echo "check-mutants-examine-globs.test.sh: all assertions passed"
