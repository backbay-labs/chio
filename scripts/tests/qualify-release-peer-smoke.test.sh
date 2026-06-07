#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
QUALIFY="$REPO_ROOT/scripts/qualify-release.sh"

grep -F 'expected_target = "x86_64-unknown-linux-gnu"' "$QUALIFY" >/dev/null
grep -F "conformance fetch-peers" "$QUALIFY" >/dev/null
grep -F -- "--language python" "$QUALIFY" >/dev/null
grep -F "conformance run" "$QUALIFY" >/dev/null
grep -F -- "--peer python" "$QUALIFY" >/dev/null
grep -F 'python-${peer_target}/${peer_binary}' "$QUALIFY" >/dev/null

echo "qualify-release-peer-smoke.test.sh: release qualification requires python peer fetch and run"
