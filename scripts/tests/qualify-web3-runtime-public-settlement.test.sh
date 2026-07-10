#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
QUALIFY="$REPO_ROOT/scripts/qualify-web3-runtime.sh"

require_string() {
  local pattern="$1"
  local label="$2"
  if ! grep -F -- "$pattern" "$QUALIFY" >/dev/null; then
    echo "qualify-web3-runtime.public-settlement-gate-missing: ${label}" >&2
    exit 1
  fi
}

require_string "fixtures/proof-room/public-settlement/valid-offline-finality/transaction-passport.json" "passport"
require_string "proof verify" "proof verify"
require_string "--require settlement" "required settlement claim"
require_string "public-settlement-verifier-report.json" "verifier report"
require_string "CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS" "bundle signer keys"
require_string "CHIO_TRANSACTION_TRUSTED_ROOT_KEYS" "transaction trust roots"
require_string "CHIO_PUBLIC_SETTLEMENT_TRUSTED_CAPITAL_SIGNER_KEYS" "capital signer keys"
require_string "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BUNDLE_SIGNER_KEYS" "settlement bundle signer keys"
require_string "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ORACLE_KEYS" "oracle signer keys"
require_string "CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS" "allowed chain ids"
require_string "CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON" "independent chain head"
require_string "CHIO_PUBLIC_SETTLEMENT_VERIFIER_NOW_UNIX_SECONDS" "verifier time"

echo "qualify-web3-runtime-public-settlement.test.sh: public settlement verifier gate present"
