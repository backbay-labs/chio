#!/usr/bin/env bash
# install-apalache-checksum.test.sh - Verify the SHA256 gate in
# tools/install-apalache.sh refuses tampered tarballs and untrusted
# existing launchers.
#
# Strategy: redirect the download to a local file via APALACHE_DOWNLOAD_URL,
# point HOME at a sandbox so the installer cannot touch real state, and
# assert the script exits 7 with a sha256 mismatch message unless existing
# launcher trust is explicitly opted into. We do not run the happy path here
# because that would require the real 117 MiB upstream tarball. The mismatch
# path exercises the verification logic, which is the property the gate exists
# to protect.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALLER="$REPO_ROOT/tools/install-apalache.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Keep the test independent from the host Java installation. The installer
# only checks that java is present before reaching the checksum gate.
TEST_BIN="$TMP_DIR/bin"
mkdir -p "$TEST_BIN"
printf '#!/usr/bin/env bash\nexit 0\n' > "$TEST_BIN/java"
chmod +x "$TEST_BIN/java"
export PATH="$TEST_BIN:$PATH"

# Build a fake tarball with arbitrary content. The real installer never
# extracts this because the SHA256 gate fires first.
fake_asset="$TMP_DIR/apalache-fake.tgz"
printf 'not the real apalache tarball\n' > "$fake_asset"

RUN_HOME=""
RUN_OUT=""
RUN_ERR=""
RUN_STATUS=0

prepare_case() {
    local name="$1"
    RUN_HOME="$TMP_DIR/home-${name}"
    RUN_OUT="$TMP_DIR/${name}.out"
    RUN_ERR="$TMP_DIR/${name}.err"
    RUN_STATUS=0
    mkdir -p "$RUN_HOME"
}

invoke_installer() {
    RUN_STATUS=0
    env HOME="$RUN_HOME" APALACHE_DOWNLOAD_URL="file://$fake_asset" "$@" \
        bash "$INSTALLER" >"$RUN_OUT" 2>"$RUN_ERR" || RUN_STATUS=$?
}

install_spoofed_launcher() {
    mkdir -p "$RUN_HOME/.local/bin"
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        "if [[ \"\${1:-}\" == \"version\" ]]; then" \
        '    printf "%s\n" "apalache-mc version 0.50.1"' \
        '    exit 0' \
        'fi' \
        'exit 0' \
        > "$RUN_HOME/.local/bin/apalache-mc"
    chmod +x "$RUN_HOME/.local/bin/apalache-mc"
}

assert_status() {
    local expected="$1"
    local reason="$2"
    if [[ "$RUN_STATUS" -ne "$expected" ]]; then
        echo "FAIL: expected exit $expected ($reason), got $RUN_STATUS" >&2
        cat "$RUN_OUT" >&2
        cat "$RUN_ERR" >&2
        exit 1
    fi
}

assert_stderr_contains() {
    local marker="$1"
    if ! grep -q "$marker" "$RUN_ERR"; then
        echo "FAIL: stderr missing '$marker' marker" >&2
        cat "$RUN_ERR" >&2
        exit 1
    fi
}

assert_stdout_contains() {
    local marker="$1"
    if ! grep -q "$marker" "$RUN_OUT"; then
        echo "FAIL: stdout missing '$marker' marker" >&2
        cat "$RUN_OUT" >&2
        exit 1
    fi
}

prepare_case "tampered-download"
invoke_installer
assert_status 7 "sha256 mismatch"
assert_stderr_contains "sha256 mismatch"

prepare_case "spoofed-version-default"
install_spoofed_launcher
invoke_installer
assert_status 7 "spoofed launcher must not bypass checksum gate"
assert_stderr_contains "sha256 mismatch"

prepare_case "explicit-trust"
install_spoofed_launcher
invoke_installer APALACHE_TRUST_EXISTING=1
assert_status 0 "explicit trust allows existing launcher"
assert_stdout_contains "already installed"

prepare_case "ci-reinstall"
install_spoofed_launcher
invoke_installer APALACHE_TRUST_EXISTING=1 CI=true
assert_status 7 "CI must force reinstall through checksum gate"
assert_stderr_contains "sha256 mismatch"

echo "PASS: install-apalache rejects tampered tarballs and untrusted existing launchers"
