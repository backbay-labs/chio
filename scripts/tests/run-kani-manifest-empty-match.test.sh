#!/usr/bin/env bash
# Regression test for scripts/run-kani-manifest.sh empty-match exit policy.
#
# Asserts:
#   1. Normal run with no matches exits 1 (CI gate cannot silently pass).
#   2. `--allow-empty` opts in to exit 0 on empty match.
#   3. `--list` is informational and exits 0 on empty match.
#   4. `--dry-run` is informational and exits 0 on empty match.
#   5. A populated manifest with a matching lane does not exit 1 in
#      `--list` mode (sanity check that the empty-match path is the
#      thing under test, not a manifest parse error).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNNER="$REPO_ROOT/scripts/run-kani-manifest.sh"

if [[ ! -x "$RUNNER" ]]; then
  echo "run-kani-manifest-empty-match.test.sh: missing $RUNNER" >&2
  exit 1
fi

work="$(mktemp -d -t chio-kani-empty-XXXXXX)"
trap 'rm -rf "$work"' EXIT

# Synthetic empty manifest: schema is valid but the harness array is
# empty. Equivalent to the "lane typo / bad exclude / manifest bug"
# scenarios the empty-match regression calls out.
EMPTY_MANIFEST="$work/empty.toml"
cat > "$EMPTY_MANIFEST" <<'EOF'
schema = "chio.kani.multi-crate.v1"
harness = []
EOF

# Synthetic populated manifest with one pr-lane entry. Used to verify
# `--list` still exits 0 on a non-empty match (so the empty-match
# regression is genuinely about emptiness, not about the runner being
# globally broken).
POPULATED_MANIFEST="$work/populated.toml"
cat > "$POPULATED_MANIFEST" <<'EOF'
schema = "chio.kani.multi-crate.v1"

[[harness]]
crate = "fake-crate"
harness = "fake_harness"
default_unwind = 1
timeout_secs = 60
lane = "pr"
EOF

INVALID_UNWINDING_MANIFEST="$work/invalid-unwinding.toml"
cat > "$INVALID_UNWINDING_MANIFEST" <<'EOF'
schema = "chio.kani.multi-crate.v1"

[[harness]]
crate = "fake-crate"
harness = "fake_harness"
default_unwind = 1
timeout_secs = 60
lane = "pr"
unwinding_checks = "yes"
EOF

run_runner() {
  # Print the runner's exit code on stdout; suppress the runner's own
  # stderr so the test output stays focused on the assertion record.
  local rc=0
  KANI_MANIFEST="$1" "$RUNNER" "${@:2}" >/dev/null 2>&1 || rc=$?
  echo "$rc"
}

assert_eq() {
  local got="$1" want="$2" label="$3"
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $label: got rc=$got, want rc=$want" >&2
    exit 1
  fi
  echo "ok: $label (rc=$got)"
}

# Case 1: empty manifest, normal run -> rc=1 (the bug fix).
assert_eq "$(run_runner "$EMPTY_MANIFEST" --lane pr --dry-run)" 0 \
  "empty manifest + --dry-run exits 0 (informational)"

# --dry-run runs above before 1 because it does not require cargo-kani
# on PATH; the normal-run case below also avoids invoking cargo-kani
# because the empty-match exit happens before the cargo check.
assert_eq "$(run_runner "$EMPTY_MANIFEST" --lane pr)" 1 \
  "empty manifest + normal run exits 1"

# Case 2: --allow-empty opts in to exit 0.
assert_eq "$(run_runner "$EMPTY_MANIFEST" --lane pr --allow-empty)" 0 \
  "empty manifest + --allow-empty exits 0"

# Case 3: --list informational on empty match.
assert_eq "$(run_runner "$EMPTY_MANIFEST" --lane pr --list)" 0 \
  "empty manifest + --list exits 0 (informational)"

# Case 4: lane typo on a populated manifest. The
# runner validates the requested lane against the closed enum
# (`pr`, `nightly`) before considering empty-match policy, and rejects
# unknown lanes with exit 2 (fail-loud). `--allow-empty` does NOT
# rescue a lane-validation failure: validation runs before the
# empty-match check, so the runner still exits 2.
assert_eq "$(run_runner "$POPULATED_MANIFEST" --lane nightlee)" 2 \
  "lane typo on populated manifest exits 2 (lane validation)"

assert_eq "$(run_runner "$POPULATED_MANIFEST" --lane nightlee --allow-empty)" 2 \
  "lane typo on populated manifest + --allow-empty still exits 2 (lane validation runs first)"

# Case 5: sanity check that --list with a real match still works.
assert_eq "$(run_runner "$POPULATED_MANIFEST" --lane pr --list)" 0 \
  "populated manifest + --list exits 0"

dry_run_output="$(KANI_MANIFEST="$POPULATED_MANIFEST" "$RUNNER" --lane pr --dry-run)"
if ! grep -Eq -- '--harness kani_public_harnesses::fake_harness --exact([[:space:]]|$)' <<<"$dry_run_output"; then
  echo "FAIL: populated manifest dry-run did not select the harness exactly" >&2
  printf '%s\n' "$dry_run_output" >&2
  exit 1
fi
echo "ok: populated manifest dry-run uses --exact"

# Case 6: --exclude-crate that removes every entry is also a silent-
# skip scenario the audit calls out.
assert_eq "$(run_runner "$POPULATED_MANIFEST" --lane pr --exclude-crate fake-crate)" 1 \
  "exclude-crate that empties match set exits 1"

assert_eq "$(run_runner "$INVALID_UNWINDING_MANIFEST" --lane pr --dry-run)" 2 \
  "non-boolean unwinding-check posture exits 2"

echo "run-kani-manifest-empty-match.test.sh: all assertions passed"
