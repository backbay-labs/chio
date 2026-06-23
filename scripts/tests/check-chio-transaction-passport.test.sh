#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
script="$repo_root/scripts/check-chio-transaction-passport.sh"

if [[ ! -x "$script" ]]; then
  echo "check-chio-transaction-passport.test.sh: missing executable gate script" >&2
  exit 1
fi

"$script" --schema-only

echo "check-chio-transaction-passport.test.sh: transaction passport gate contract passed"
