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

lib="$repo_root/scripts/lib/chio-proof-trusted-keys.sh"
quickstart_env="$repo_root/scripts/proof-room-quickstart-env.sh"
flagship_runner="$repo_root/scripts/demo/flagship-wall-stops-money.sh"

canonical_agent_web_kernel_key="204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c21"
negative_sidecar_key="d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
before_source="$(date +%s)"
mapfile -t shared_values < <(
  # Expand fixture variables inside the clean child environment.
  # shellcheck disable=SC2016
  env -i PATH="$PATH" bash -c '
    source "$1"
    printf "%s\n%s\n%s\n%s\n" \
      "$CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS" \
      "$CHIO_AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS" \
      "$CHIO_AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS" \
      "$CHIO_AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS"
  ' _ "$lib"
)
after_source="$(date +%s)"

if [[ ",${shared_values[0]}," != *",$canonical_agent_web_kernel_key,"* ]]; then
  echo "check-chio-transaction-passport.test.sh: shared trust config must pin the fixture kernel key" >&2
  exit 1
fi
if [[ ",${shared_values[0]}," == *",$negative_sidecar_key,"* ]]; then
  echo "check-chio-transaction-passport.test.sh: invalid unbound-receipt sidecar key must not be trusted as a kernel key" >&2
  exit 1
fi
if [[ "${shared_values[1]}" != "$negative_sidecar_key" ]]; then
  echo "check-chio-transaction-passport.test.sh: shared trust config must keep the envelope sidecar key in its own trust class" >&2
  exit 1
fi
if (( shared_values[2] < before_source + 60 || shared_values[2] > after_source + 60 )); then
  echo "check-chio-transaction-passport.test.sh: shared verifier time must track the live clock" >&2
  exit 1
fi
if (( shared_values[3] != shared_values[2] - 1770508800 + 300 )); then
  echo "check-chio-transaction-passport.test.sh: shared fixture freshness window is inconsistent" >&2
  exit 1
fi

for consumer in "$script" "$quickstart_env" "$flagship_runner"; do
  if ! grep -Fq "chio-proof-trusted-keys.sh" "$consumer"; then
    echo "check-chio-transaction-passport.test.sh: $consumer must source the shared proof trust config" >&2
    exit 1
  fi
done

if ! grep -Fq "CHIO_ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS" "$script" && ! grep -Fq "CHIO_ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS" "$lib"; then
  echo "check-chio-transaction-passport.test.sh: gate must pin enterprise receipt kernel keys" >&2
  exit 1
fi

if ! grep -Fq "CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS" "$script" && ! grep -Fq "CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS" "$lib"; then
  echo "check-chio-transaction-passport.test.sh: gate must pin commerce event authority receipt keys" >&2
  exit 1
fi

if ! grep -Fq "CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS" "$script" && ! grep -Fq "CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS" "$lib"; then
  echo "check-chio-transaction-passport.test.sh: gate must pin commerce payment signer keys" >&2
  exit 1
fi

echo "check-chio-transaction-passport.test.sh: transaction passport gate contract passed"
