#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/check-cargo-vet-exemptions.py"

run_case() {
    local label="$1"
    local base="$2"
    local head="$3"
    local expect_code="$4"
    local expect_stderr="$5"

    local out err code=0
    out="$(mktemp)"
    err="$(mktemp)"
    if python3 "$SCRIPT" --base "$base" --head "$head" >"$out" 2>"$err"; then
        code=0
    else
        code=$?
    fi
    if [ "$code" -ne "$expect_code" ]; then
        echo "FAIL [$label]: expected exit $expect_code, got $code" >&2
        echo "--- stdout ---" >&2
        cat "$out" >&2
        echo "--- stderr ---" >&2
        cat "$err" >&2
        rm -f "$out" "$err"
        exit 1
    fi
    if [ -n "$expect_stderr" ] && ! grep -q -- "$expect_stderr" "$err"; then
        echo "FAIL [$label]: expected stderr to contain '$expect_stderr'" >&2
        echo "--- stderr ---" >&2
        cat "$err" >&2
        rm -f "$out" "$err"
        exit 1
    fi
    rm -f "$out" "$err"
    echo "PASS [$label]"
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cargo-vet-exemptions.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

# ---------------------------------------------------------------------------
# Case 1: existing exemption, head adds a new version row -> reject.
# ---------------------------------------------------------------------------
base="$TMP_DIR/case1-base.toml"
head="$TMP_DIR/case1-head.toml"
cat >"$base" <<'TOML'
[[exemptions.tokio]]
version = "1.50.0"
criteria = "safe-to-deploy"
TOML
cat >"$head" <<'TOML'
[[exemptions.tokio]]
version = "1.50.0"
criteria = "safe-to-deploy"

[[exemptions.tokio]]
version = "1.51.0"
criteria = "safe-to-deploy"
TOML
run_case "new-version-of-existing-name" "$base" "$head" 1 "tokio@1.51.0"

# ---------------------------------------------------------------------------
# Case 2: criteria escalated for the same name@version
# (safe-to-run -> safe-to-deploy) -> reject.
# ---------------------------------------------------------------------------
base="$TMP_DIR/case2-base.toml"
head="$TMP_DIR/case2-head.toml"
cat >"$base" <<'TOML'
[[exemptions.serde]]
version = "1.0.210"
criteria = "safe-to-run"
TOML
cat >"$head" <<'TOML'
[[exemptions.serde]]
version = "1.0.210"
criteria = "safe-to-deploy"
TOML
run_case "criteria-escalation-run-to-deploy" "$base" "$head" 1 \
    "serde@1.0.210#safe-to-deploy"

# ---------------------------------------------------------------------------
# Case 3: piggy-backing a new version under an already-exempt name
# (windows-targets 0.49.0 added while 0.48.5 is already exempt) -> reject.
# ---------------------------------------------------------------------------
base="$TMP_DIR/case3-base.toml"
head="$TMP_DIR/case3-head.toml"
cat >"$base" <<'TOML'
[[exemptions.windows-targets]]
version = "0.48.5"
criteria = "safe-to-deploy"
TOML
cat >"$head" <<'TOML'
[[exemptions.windows-targets]]
version = "0.48.5"
criteria = "safe-to-deploy"

[[exemptions.windows-targets]]
version = "0.49.0"
criteria = "safe-to-deploy"
TOML
run_case "piggy-back-new-version-of-existing-name" "$base" "$head" 1 \
    "windows-targets@0.49.0"

# ---------------------------------------------------------------------------
# Case 4: same exemption appearing twice with different criteria values
# in head (and only one row in base) -> reject.
# ---------------------------------------------------------------------------
base="$TMP_DIR/case4-base.toml"
head="$TMP_DIR/case4-head.toml"
cat >"$base" <<'TOML'
[[exemptions.regex]]
version = "1.10.6"
criteria = "safe-to-run"
TOML
cat >"$head" <<'TOML'
[[exemptions.regex]]
version = "1.10.6"
criteria = "safe-to-run"

[[exemptions.regex]]
version = "1.10.6"
criteria = "safe-to-deploy"
TOML
run_case "duplicate-name-version-different-criteria" "$base" "$head" 1 \
    "regex@1.10.6#safe-to-deploy"

# ---------------------------------------------------------------------------
# Case 5: identical configs -> exit 0.
# ---------------------------------------------------------------------------
base="$TMP_DIR/case5-base.toml"
head="$TMP_DIR/case5-head.toml"
cat >"$base" <<'TOML'
[[exemptions.anyhow]]
version = "1.0.86"
criteria = "safe-to-deploy"

[[exemptions.thiserror]]
version = "1.0.61"
criteria = "safe-to-run"
TOML
cp "$base" "$head"
run_case "identical-base-and-head" "$base" "$head" 0 ""

# ---------------------------------------------------------------------------
# Case 6: head removes an exemption -> exit 0 (no net-new entries).
# ---------------------------------------------------------------------------
base="$TMP_DIR/case6-base.toml"
head="$TMP_DIR/case6-head.toml"
cat >"$base" <<'TOML'
[[exemptions.foo]]
version = "1.0.0"
criteria = "safe-to-deploy"

[[exemptions.bar]]
version = "2.0.0"
criteria = "safe-to-deploy"
TOML
cat >"$head" <<'TOML'
[[exemptions.foo]]
version = "1.0.0"
criteria = "safe-to-deploy"
TOML
run_case "head-removes-an-exemption" "$base" "$head" 0 ""

echo "ALL PASS: cargo-vet exemption gate rejects net-new (name, version, criteria) tuples"
