#!/usr/bin/env bash
# install-apalache-checksum.test.sh - Verify the SHA256 gate in
# tools/install-apalache.sh refuses a tampered tarball.
#
# Strategy: redirect the download to a local file via APALACHE_DOWNLOAD_URL,
# point HOME at a sandbox so the installer cannot touch real state, and
# assert the script exits 7 with a sha256 mismatch message. We do not run
# the happy path here because that would require the real 117 MiB upstream
# tarball. The mismatch path exercises the verification logic, which is the
# property the gate exists to protect.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALLER="$REPO_ROOT/tools/install-apalache.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Build a fake tarball with arbitrary content. The real installer never
# extracts this because the SHA256 gate fires first.
fake_asset="$TMP_DIR/apalache-fake.tgz"
printf 'not the real apalache tarball\n' > "$fake_asset"

# Sandbox HOME so ~/.local writes land inside the temp tree.
export HOME="$TMP_DIR/home"
mkdir -p "$HOME"

OUT="$TMP_DIR/out"
ERR="$TMP_DIR/err"
status=0
APALACHE_DOWNLOAD_URL="file://$fake_asset" \
    bash "$INSTALLER" >"$OUT" 2>"$ERR" || status=$?

if [[ "$status" -ne 7 ]]; then
    echo "FAIL: expected exit 7 (sha256 mismatch), got $status" >&2
    cat "$OUT" >&2
    cat "$ERR" >&2
    exit 1
fi

if ! grep -q "sha256 mismatch" "$ERR"; then
    echo "FAIL: stderr missing 'sha256 mismatch' marker" >&2
    cat "$ERR" >&2
    exit 1
fi

echo "PASS: install-apalache rejects tampered tarball"
