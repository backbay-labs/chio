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

set +e
rg -n --hidden \
  --glob '!target/**' \
  --glob '!audits/**' \
  --glob '!docs/research/protocol-strategy/**' \
  --glob '!docs/archive/**' \
  --glob '!**/node_modules/**' \
  --glob '!**/.git/**' \
  --glob '!scripts/check-chio-owned-v1-only.sh' \
  --glob '!**/CHANGELOG.md' \
  --glob '!docs/adr/**' \
  --glob '!**/in-toto/**' \
  --glob '!**/runtime-trace/**' \
  --glob '!docs/superpowers/**' \
  "$pattern" \
  crates spec sdks scripts docs formal xtask >"$tmp"
rg_status=$?
set -e
if ((rg_status > 1)); then
  echo "ripgrep failed while scanning Chio-owned version remnants" >&2
  exit "$rg_status"
fi

if ((${#existing_normative_roots[@]})); then
  set +e
  rg -n --hidden \
    --glob '*.md' \
    --glob '!target/**' \
    --glob '!audits/**' \
    --glob '!docs/research/**' \
    --glob '!docs/superpowers/**' \
    --glob '!docs/archive/**' \
    --glob '!**/node_modules/**' \
    --glob '!**/.git/**' \
    "$normative_claim_pattern" \
    "${existing_normative_roots[@]}" >>"$tmp"
  rg_status=$?
  set -e
  if ((rg_status > 1)); then
    echo "ripgrep failed while scanning normative version claims" >&2
    exit "$rg_status"
  fi
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

  # Attest, federation, and pheromone are independently-versioned subsystems
  # that ship inside the Chio repo but are not the v1 Chio-owned wire / SDK /
  # receipt surface this scan is intended to gate. Their schema IDs use their
  # own version numbering (chio.attest.*.vN, chio.federation.*.vN,
  # chio.pheromone.*.vN) and may legitimately advance past v1 ahead of the v1
  # wire surface.
  if [[ "$text" =~ chio\.attest\.[A-Za-z0-9_.-]+\.v[2-9][0-9]* ]]; then
    continue
  fi
  if [[ "$text" =~ chio\.federation\.[A-Za-z0-9_.-]+\.v[2-9][0-9]* ]]; then
    continue
  fi
  if [[ "$text" =~ chio\.pheromone\.[A-Za-z0-9_.-]+\.v[2-9][0-9]* ]]; then
    continue
  fi

  # Attest bilateral-cosign / 3-vendor proof-package fixtures embed
  # workflow-receipt slices keyed at v2 as fixture data; the canonical
  # Chio-owned workflow-receipt schema (spec/WORKFLOW.md) remains v1.
  # Limit this exclusion to attest test/fixture/example surfaces.
  if [[ "$text" =~ chio\.workflow-receipt\.v[2-9][0-9]* ]] && \
     [[ "$path" =~ (^|/)(chio-attest-)|fixtures/|examples/chio- ]]; then
    continue
  fi

  # The Cargo feature `delegation_v2` is retained as a backward-compat
  # alias for external manifests; documentation and the Cargo.toml line
  # that defines the alias are intentional and not remnants.
  if [[ "$text" =~ feature\ \`delegation_v2\`|features\ =\ \[\"delegation_v2\"\]|delegation_v2\ =\ \[ ]]; then
    continue
  fi
  if [[ "$text" =~ delegation_v2 ]] && \
     [[ "$path" == "crates/core/chio-core-types/Cargo.toml" ]]; then
    continue
  fi

  # The launch disclosure surface intentionally ships a v2 BBS projection
  # manifest so typed message classes and per-slot sensitivity are explicit.
  # Keep this exemption limited to that exact manifest schema and its constants.
  if [[ "$text" =~ chio\.bbs-projection\.manifest\.v2|BBS_PROJECTION_MANIFEST_SCHEMA_V2|BBS_PROJECTION_MANIFEST_V2_SCHEMA ]]; then
    continue
  fi

  # Agent Web proof envelopes intentionally ship a scope-bound v2 projection
  # while retaining signed v1 envelope verification for compatibility. Limit
  # this exemption to the exact schema, its exported constant, and the contract
  # test diagnostic that names the v2 schema check.
  if [[ "$text" =~ chio\.agent-web-proof-envelope\.v2|CHIO_AGENT_WEB_PROOF_ENVELOPE_V2_SCHEMA|agent-web\.proof-envelope-schema\.contract-missing:\ scope-bound\ v2\ schema\ test ]]; then
    continue
  fi
  if [[ "$path" == "crates/platform/chio-agent-web-interop/tests/agent_web_interop/core_tests.rs" ]] && \
     [[ "$text" =~ v1\ proof\ envelope\ with\ a\ v2-only\ passport\ scope\ digest ]]; then
    continue
  fi

  # Public settlement intentionally publishes v2 dispatch and execution-receipt
  # artifacts while preserving v1 bundle verification.
  if [[ "$text" =~ chio\.web3-settlement-(dispatch|execution-receipt)\.v2|CHIO_WEB3_SETTLEMENT_(DISPATCH|RECEIPT|EXECUTION_RECEIPT)_V2_SCHEMA|WEB3_SETTLEMENT_EXECUTION_RECEIPT_SCHEMA ]]; then
    continue
  fi
  if [[ "$path" == "crates/economy/chio-web3/src/settlement.rs" ]] && \
     [[ "$text" =~ (dispatch_v2|receipt_v2) ]]; then
    continue
  fi

  # Checkpoint statements, consistency proofs, checkpoint-anchored inclusion
  # proofs, and bundles containing those proofs are security-interpreted
  # formats. Their v2 schemas prevent rolling readers from applying legacy v1
  # semantics to new commitments, paths, and hash constructions.
  if [[ "$text" =~ chio\.checkpoint_(statement|consistency_proof)\.v2|chio\.(anchor-inclusion-proof|anchor-proof-bundle|transparency\.inclusion-proof)\.v2|CHECKPOINT_(CONSISTENCY_PROOF_)?SCHEMA_V2|CHIO_CHECKPOINT_STATEMENT_SCHEMA_V2|CHIO_ANCHOR_PROOF_BUNDLE_(SCHEMA_)?V2|(ANCHOR|TRANSPARENCY)_INCLUSION_PROOF_(SCHEMA_V2|V2_SCHEMA) ]]; then
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
