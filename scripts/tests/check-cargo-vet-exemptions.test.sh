#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cargo-vet-exemptions.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

base="$TMP_DIR/base.toml"
head="$TMP_DIR/head.toml"

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

if python3 "$REPO_ROOT/scripts/check-cargo-vet-exemptions.py" \
    --base "$base" \
    --head "$head" >"$TMP_DIR/out" 2>"$TMP_DIR/err"; then
    echo "expected new version of existing exemption to fail" >&2
    cat "$TMP_DIR/out" >&2
    cat "$TMP_DIR/err" >&2
    exit 1
fi

grep -q 'tokio@1.51.0' "$TMP_DIR/err"
echo "PASS: cargo-vet exemption version increases are blocked"
