#!/usr/bin/env bash
set -euo pipefail
# NON-CLAIMS: this is a verifier-level proof over an OFFLINE projection. It is not a live
# money-stop, holds no funds, and asserts no public availability. Settlement is a verify-only
# x402/AP2/ACP projection over an offline PSP (stripe-shaped-offline).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUNDLE="${1:-$ROOT/fixtures/proof-room/public-stages/commerce-transaction-passport/proof-room-bundle}"

# shellcheck source=scripts/lib/chio-proof-trusted-keys.sh
source "$ROOT/scripts/lib/chio-proof-trusted-keys.sh"

if [[ -n "${CHIO_BIN:-}" ]]; then
  [[ -x "$CHIO_BIN" ]] || { echo "CHIO_BIN is not executable: $CHIO_BIN" >&2; exit 2; }
elif [[ -x "$ROOT/target/debug/chio" ]]; then
  CHIO_BIN="$ROOT/target/debug/chio"
else
  ( cd "$ROOT" && cargo build -p chio-cli --bin chio )
  CHIO_BIN="$ROOT/target/debug/chio"
fi

echo "== Chio flagship: the wall stops money (offline verifier proof) =="
"$CHIO_BIN" proof verify "$BUNDLE" \
  --require denials --require commerce --require settlement --require risk --require trust-market

echo
echo "-- MANDATE / ALLOWANCE --"
python3 - "$BUNDLE/mandate-allowance-ledger.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
m = d if isinstance(d, dict) and d.get("id") == "mandate-commerce-001" else None
if m is None:
    for cand in (d.get("mandates") or d.get("entries") or []):
        if isinstance(cand, dict) and cand.get("id") == "mandate-commerce-001":
            m = cand; break
if m is None:
    print("mandate-commerce-001 not found"); raise SystemExit(3)
print(f"mandate {m['id']}: max_amount_minor={m['max_amount_minor']} "
      f"max_occurrences={m['max_occurrences']} currency={m.get('currency')}")
PY

echo
echo "-- DENIED (kernel-signed terminal receipt) --"
python3 - "$BUNDLE/commerce-terminal-denial-receipt.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"terminal_status={d['terminal_status']} kernel_key={d['kernel_key'][:12]}...")
PY
echo "over-budget/over-limit corpus the verifier REJECTS (separate negative fixtures):"
echo "  commerce-payment-before-budget, commerce-mandate-occurrence-limit,"
echo "  commerce-expired-mandate, commerce-payment-amount-mismatch"

echo
echo "-- ALLOWED (kernel-signed terminal receipt) --"
python3 - "$BUNDLE/commerce-terminal-allow-receipt.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"terminal_status={d['terminal_status']} kernel_key={d['kernel_key'][:12]}...")
PY
echo "in-budget attempt authorized via x402/AP2/ACP verify-only protocol_projections"

echo
echo "-- SETTLED (offline projection) --"
python3 - "$BUNDLE/settlement-packet.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"schema={d.get('schema')} status={d.get('status')}")
PY

echo
echo "== NON-CLAIMS: offline verifier proof; no live money-stop, no fund custody, no availability claim. =="
