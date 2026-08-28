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
grep -F 'print("source-pre-release\t\t")' "$QUALIFY" >/dev/null
grep -F -- "--check" "$QUALIFY" >/dev/null
grep -F -- "--allow-unpublished-only" "$QUALIFY" >/dev/null
grep -F -- '--lockfile "${release_peer_lock}"' "$QUALIFY" >/dev/null
grep -F 'len(matching) != 1' "$QUALIFY" >/dev/null
grep -F 'sorted(reported_ids) != sorted(expected_ids)' "$QUALIFY" >/dev/null
grep -F 'result.get("status") != "pass"' "$QUALIFY" >/dev/null
grep -F 'external consumer smoke has unexpected failures' "$QUALIFY" >/dev/null
grep -F 'external-consumer-smoke-mode.txt' "$QUALIFY" >/dev/null

if grep -F "requires a published python peer" "$QUALIFY" >/dev/null; then
  echo "pre-release source peer fallback regressed" >&2
  exit 1
fi

echo "qualify-release-peer-smoke.test.sh: release qualification covers published and source python peers"
