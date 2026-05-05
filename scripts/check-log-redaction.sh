#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

scope=(
  crates/chio-kernel/src
  crates/chio-siem/src
)

failed=0

if rg -n --pcre2 '(msg|reason|error|body|body_text)[[:space:]]*=[[:space:]]*%(?!(redacted!|redact_for_operator_log)\()[A-Za-z_][A-Za-z0-9_]*' "${scope[@]}"; then
  echo "raw sensitive log field found; wrap sensitive values with redacted!()" >&2
  failed=1
fi

if rg -n '%(msg|reason|error|body|body_text)\b' "${scope[@]}"; then
  echo "raw tracing shorthand for sensitive log field found; use field = %redacted!(value)" >&2
  failed=1
fi

if rg -n '(payload|body|prompt|tool_args|tool_output|user_message)[[:space:]]*=[[:space:]]*%[A-Za-z_]' "${scope[@]}"; then
  echo "raw sensitive log field found; wrap the field value with redacted!()" >&2
  failed=1
fi

if rg -n '(payload|body|prompt|tool_args|tool_output|user_message).*format!\(' "${scope[@]}"; then
  echo "raw format! near a sensitive arm found; pass sensitive values through redacted!()" >&2
  failed=1
fi

if [[ "${failed}" -ne 0 ]]; then
  exit 1
fi

echo "log redaction grep gate passed"
