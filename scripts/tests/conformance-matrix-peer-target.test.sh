#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORKFLOW="$REPO_ROOT/.github/workflows/conformance-matrix.yml"

grep -F 'expected_target = "x86_64-unknown-linux-gnu"' "$WORKFLOW" >/dev/null
grep -F 'peer.get("target") == expected_target' "$WORKFLOW" >/dev/null
grep -F 'python peer for ${{ steps.python-peer.outputs.expected_target }}' "$WORKFLOW" >/dev/null

echo "conformance-matrix-peer-target.test.sh: external smoke selects the runner target"
