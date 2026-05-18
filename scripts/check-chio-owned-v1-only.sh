#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v rg >/dev/null 2>&1; then
  echo "ripgrep (rg) is required" >&2
  exit 2
fi

pattern='ReceiptV[2-9]|CapabilityTokenV[2-9]|CHIO_[A-Z0-9_]+_V[2-9]|ACCEPTS_[A-Z0-9_]+_V[2-9]|CapabilitySchemaVersion|KernelReceiptVersion|NegotiationDowngrade|chio_receipts_v[2-9]|chio\.[A-Za-z0-9_.-]+\.v[2-9][0-9]*\b|[A-Za-z0-9_-]+\.v[2-9][0-9]*\.schema\.json|receipt/v[2-9][0-9]*\.schema\.json|receipt_v[2-9]\b|capability_v[2-9]\b|token_v[2-9]\b|delegation_v[2-9]\b|lineage_statement_v[2-9]\b|\b[Aa] v[2-9] CapabilityToken\b|\b[Vv][2-9] tokens?\b|\b[Vv][2-9] schema\b|\b[Vv][2-9]-aware\b|\b[Vv][2-9]-only\b|schema[- ]ceiling|maximum capability-token schema'
normative_claim_pattern='\b[Cc]urrently v[2-9](\.[0-9]+)?\b|\b[Cc]urrent( Chio-owned)? (protocol|schema|runtime|SDK|wire|API|storage|receipt)( surface| surfaces)?( is| are| remains)? v[2-9](\.[0-9]+)?\b|\b[Cc]urrent( Chio)? release( line| version| surface)?( is| are| remains|:)? v[2-9](\.[0-9]+)?\b|\b[Cc]urrent[- ]release( line| version| surface)?( is| are| remains|:)? v[2-9](\.[0-9]+)?\b|\b[Cc]urrent boundary: v[2-9](\.[0-9]+)?\b|\b[Cc]urrent v[2-9](\.[0-9]+)? (Chio-owned )?(protocol|schema|runtime|SDK|wire|API|storage|receipt|surface)\b|\bextension of v[2-9](\.[0-9]+)?\b|\bextends v[2-9](\.[0-9]+)?\b'

normative_roots=(
  spec
  docs/adr
  docs/operations
  docs/protocols
  docs/reference
  docs/release
  docs/start-here
  docs/standards
)

existing_normative_roots=()
for root in "${normative_roots[@]}"; do
  if [[ -d "$root" ]]; then
    existing_normative_roots+=("$root")
  fi
done

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

rg -n --hidden \
  --glob '!target/**' \
  --glob '!audits/**' \
  --glob '!docs/research/protocol-strategy/**' \
  --glob '!docs/archive/**' \
  --glob '!**/node_modules/**' \
  --glob '!**/.git/**' \
  --glob '!scripts/check-chio-owned-v1-only.sh' \
  "$pattern" \
  crates spec sdks packages scripts docs formal xtask >"$tmp" || true

if ((${#existing_normative_roots[@]})); then
  rg -n --hidden \
    --glob '*.md' \
    --glob '!target/**' \
    --glob '!audits/**' \
    --glob '!docs/research/**' \
    --glob '!docs/archive/**' \
    --glob '!**/node_modules/**' \
    --glob '!**/.git/**' \
    "$normative_claim_pattern" \
    "${existing_normative_roots[@]}" >>"$tmp" || true
fi

failures=()
while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  path="${line%%:*}"
  rest="${line#*:}"
  text="${rest#*:}"

  # Future-version negative fixtures intentionally use .v9-style schema IDs.
  if [[ "$text" =~ chio\.[A-Za-z0-9_.-]+\.v9[0-9]* ]]; then
    continue
  fi

  # Negative fixture corpora may include forbidden Chio-owned versions by design.
  if [[ "$path" =~ (^|/)(negative-fixture|negative_fixtures|negative-fixtures|negative-fixture-corpus) ]]; then
    continue
  fi

  # External ecosystem/tool versions are not Chio-owned schema or API versions.
  if [[ "$text" =~ pydantic_v2|Pydantic\ v2|oapi-codegen\ v2|OpenAPI\ 3|IPv4|IPv6|UUID-v4|uuid-v4|uuid::now_v7|envoy\.service\.auth\.v3|Envoy\ ext_authz\ v3|PagerDuty\ Events\ API\ v2|Rekor\ v2|cosign\ at\ v2 ]]; then
    continue
  fi

  failures+=("$line")
done <"$tmp"

if ((${#failures[@]})); then
  printf '%s\n' "Chio-owned pre-release version remnants found:" >&2
  printf '  %s\n' "${failures[@]}" >&2
  exit 1
fi

echo "No Chio-owned pre-release version remnants found."
