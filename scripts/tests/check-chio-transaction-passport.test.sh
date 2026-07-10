#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
script="$repo_root/scripts/check-chio-transaction-passport.sh"

if [[ ! -x "$script" ]]; then
  echo "check-chio-transaction-passport.test.sh: missing executable gate script" >&2
  exit 1
fi

output="$("$script" --schema-only)"
printf '%s\n' "$output"

if ! grep -Fq "proof-room" <<<"$output"; then
  echo "check-chio-transaction-passport.test.sh: gate must account for Proof Room catalog entries" >&2
  exit 1
fi

if ! grep -Fq "CHIO_ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS" "$script"; then
  echo "check-chio-transaction-passport.test.sh: gate must pin enterprise receipt kernel keys" >&2
  exit 1
fi

if ! grep -Fq "CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS" "$script"; then
  echo "check-chio-transaction-passport.test.sh: gate must pin commerce event authority receipt keys" >&2
  exit 1
fi

if ! grep -Fq "CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS" "$script"; then
  echo "check-chio-transaction-passport.test.sh: gate must pin commerce payment signer keys" >&2
  exit 1
fi

echo "check-chio-transaction-passport.test.sh: transaction passport gate contract passed"
