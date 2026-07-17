#!/usr/bin/env bash
set -uo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <source-schema> <destination-schema> <report>" >&2
  exit 64
fi

source_schema="$1"
destination_schema="$2"
report="$3"
diff_bin="${SCHEMA_DIFF_BIN:-json-schema-diff-validator}"
stdout_file="$(mktemp)"
stderr_file="$(mktemp)"
trap 'rm -f "$stdout_file" "$stderr_file"' EXIT

"$diff_bin" "$source_schema" "$destination_schema" \
  >"$stdout_file" 2>"$stderr_file"
diff_status=$?

if [[ $diff_status -eq 0 ]]; then
  {
    cat "$stdout_file"
    cat "$stderr_file"
  } >"$report"
  exit 0
fi

if grep -Fq "The schema is not backward compatible." "$stdout_file" "$stderr_file"; then
  {
    cat "$stdout_file"
    cat "$stderr_file"
  } >"$report"
  exit 10
fi

{
  printf 'schema compatibility tool failed with exit status %s\n' "$diff_status"
  cat "$stdout_file"
  cat "$stderr_file"
} >"$report"
exit 20
