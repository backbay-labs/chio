#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNNER="$ROOT/scripts/demo/flagship-wall-stops-money.sh"
BUNDLE="$ROOT/fixtures/proof-room/public-stages/commerce-transaction-passport/proof-room-bundle"

# 1. Pristine bundle: runner exits 0 and narrates all four arcs plus the non-claims banner.
out="$(bash "$RUNNER" "$BUNDLE")"
for needle in "MANDATE / ALLOWANCE" "DENIED" "denied_guard_request" "ALLOWED" "allowed_executed" "SETTLED" "NON-CLAIMS"; do
  grep -q "$needle" <<<"$out" || { echo "FAIL: runner output missing '$needle'"; exit 1; }
done
# Honesty guard: the runner must NOT assert a same-mandate deny/allow linkage.
if grep -Eqi "same (mandate|order)|two occurrences|second occurrence of mandate-commerce-001" <<<"$out"; then
  echo "FAIL: runner overclaims a same-mandate allow/deny linkage the receipts do not carry"; exit 1
fi

# 2. Tampered bundle: runner is fail-closed (non-zero).
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp -R "$BUNDLE" "$tmp/bundle"
python3 - "$tmp/bundle/commerce-terminal-allow-receipt.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["terminal_status"] = "tampered_status"
json.dump(d, open(p, "w"))
PY
if bash "$RUNNER" "$tmp/bundle" >/dev/null 2>&1; then
  echo "FAIL: runner accepted a tampered bundle (not fail-closed)"; exit 1
fi
echo "OK flagship-wall-stops-money.test.sh"
