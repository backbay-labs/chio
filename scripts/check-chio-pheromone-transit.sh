#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
MODE="all"
case "${1:-}" in
  "")
    ;;
  "--schema-only")
    MODE="schema-only"
    shift
    ;;
  "--negative-only")
    MODE="negative-only"
    shift
    ;;
  *)
    echo "usage: check-chio-pheromone-transit.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-pheromone-transit.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

SCHEMA_DIR="$ROOT/spec/schemas/chio-pheromone/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"
FIXTURE_DIR="$ROOT/examples/chio-3vendor/fixtures/pheromone"
SPEC_DOC="$ROOT/spec/CHIO_PHEROMONE.md"

DEPOSIT_FIXTURE="$FIXTURE_DIR/deposit.json"
BATCH_FIXTURE="$FIXTURE_DIR/gossip-batch.json"
POLICY_FIXTURE="$FIXTURE_DIR/transit-policy.json"
CONCENTRATION_FIXTURE="$FIXTURE_DIR/concentration.json"
NEGATIVE_FIXTURE="$FIXTURE_DIR/negative-cases.json"

retired_marker="$(printf '%s%s' 'chio' 'dos')"
if rg -n -i "$retired_marker" "$SPEC_DOC"; then
  echo "active Chio pheromone spec must not cite retired docs or labels" >&2
  exit 1
fi

python3 - "$SCHEMA_DIR" "$SCHEMA_REGISTRY" "$FIXTURE_DIR" <<'PY'
import json
import pathlib
import sys

schema_dir, registry_path, fixture_dir = map(pathlib.Path, sys.argv[1:])
registry = json.loads(registry_path.read_text(encoding="utf-8"))
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
for entry in registry.get("artifacts", []):
    schema_file = entry.get("schemaFile", "")
    if schema_file.startswith("spec/schemas/chio/"):
        raise SystemExit(f"Chio registry still points at retired schema root {schema_file}")
expected = {
    "deposit.schema.json": "chio.pheromone-deposit.v1",
    "cost-commitment.schema.json": "chio.pheromone-cost-commitment.v1",
    "scarcity-policy.schema.json": "chio.pheromone-scarcity-policy.v1",
    "workflow-context.schema.json": "chio.pheromone-workflow-context.v1",
    "gossip.schema.json": "chio.pheromone-deposit-gossip.v1",
    "batch.schema.json": "chio.pheromone-batch.v1",
    "concentration.schema.json": "chio.pheromone-concentration.v1",
    "transit-policy.schema.json": "chio.pheromone-transit-policy.v1",
    "negative-fixture-corpus.schema.json": "chio.pheromone.negative-fixture-corpus.v1",
}
for filename, schema_id in expected.items():
    path = schema_dir / filename
    if not path.is_file():
        raise SystemExit(f"missing schema {filename}")
    schema = json.loads(path.read_text(encoding="utf-8"))
    if schema.get("type") != "object" or "$id" not in schema:
        raise SystemExit(f"schema {filename} is not a frozen object schema")
    retired_schema_prefix = "chio." + "chio."
    if retired_schema_prefix in path.read_text(encoding="utf-8"):
        raise SystemExit(f"schema {schema_id} allows legacy Chio schema ids")
    want = f"spec/schemas/chio-pheromone/v1/{filename}"
    if registered.get(schema_id) != want:
        raise SystemExit(f"schema {schema_id} is not registered at {want}")

deposit = json.loads((fixture_dir / "deposit.json").read_text(encoding="utf-8"))
batch = json.loads((fixture_dir / "gossip-batch.json").read_text(encoding="utf-8"))
policy_envelope = json.loads((fixture_dir / "transit-policy.json").read_text(encoding="utf-8"))
policy = policy_envelope.get("body", {})
concentration = json.loads((fixture_dir / "concentration.json").read_text(encoding="utf-8"))
negative = json.loads((fixture_dir / "negative-cases.json").read_text(encoding="utf-8"))

if "body" not in policy_envelope or "signerKey" not in policy_envelope or "signature" not in policy_envelope:
    raise SystemExit("transit policy must be a signed runtime-policy envelope")
if deposit.get("schema") != "chio.pheromone-deposit.v1":
    raise SystemExit("deposit fixture has wrong schema")
if "workflow_context" not in deposit:
    raise SystemExit("deposit fixture must bind workflow context")
if "cost_commitment" not in deposit:
    raise SystemExit("deposit fixture must carry observation cost commitment")
commitment = deposit["cost_commitment"]
if commitment.get("schema") != "chio.pheromone-cost-commitment.v1":
    raise SystemExit("cost commitment fixture has wrong schema")
statement = commitment.get("statement", {})
for field in ("subjectClassNamespace", "subjectClass", "treatyId", "verifierId"):
    if field not in statement:
        raise SystemExit(f"cost commitment statement missing {field}")
if statement["subjectClassNamespace"] != deposit["subject_class_namespace"]:
    raise SystemExit("cost commitment namespace does not bind deposit subject namespace")
if statement["subjectClass"] != deposit["subject_class"]:
    raise SystemExit("cost commitment class does not bind deposit subject class")
if statement["treatyId"] not in deposit["treaty_scope"]:
    raise SystemExit("cost commitment treaty scope does not bind deposit treaty scope")
if deposit["workflow_context"].get("workflow_id") != "wf-chio-refund-001":
    raise SystemExit("deposit workflow context does not bind the reference workflow")
if batch.get("schema") != "chio.pheromone-batch.v1":
    raise SystemExit("batch fixture has wrong schema")
if len(batch.get("frames", [])) != 1:
    raise SystemExit("batch fixture must carry one relayed frame")
frame = batch["frames"][0]
chain = frame.get("transit_chain", {}).get("hops", [])
if len(chain) != 2:
    raise SystemExit("fixture must carry a two-hop transit chain")
if frame.get("treaty_id") == chain[0].get("treaty_id"):
    raise SystemExit("fixture must exercise downstream treaty relay, not direct gossip")
if frame.get("treaty_id") not in deposit.get("treaty_scope", []):
    raise SystemExit("frame treaty must be admitted in deposit treaty scope for scoped economics")
if chain[0].get("treaty_id") not in deposit.get("treaty_scope", []):
    raise SystemExit("first transit hop must use the origin treaty")
if chain[-1].get("treaty_id") != frame.get("treaty_id"):
    raise SystemExit("last transit hop must match the frame treaty")
if policy.get("max_hops") != 2:
    raise SystemExit("transit policy must cap the fixture at two hops")
scarcity = policy.get("admission", {}).get("scarcityPolicies", [])
if len(scarcity) != 1:
    raise SystemExit("transit policy must carry one scarcity policy fixture")
scarcity_policy = scarcity[0]
if scarcity_policy.get("schema") != "chio.pheromone-scarcity-policy.v1":
    raise SystemExit("scarcity policy fixture has wrong schema")
if scarcity_policy.get("newcomerHorizonEpochs") != 8:
    raise SystemExit("scarcity policy fixture must preserve the eight-epoch default")
for field in ("runtimePolicySha256", "policySha256"):
    value = scarcity_policy.get(field, "")
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise SystemExit(f"scarcity policy fixture missing canonical {field}")
if scarcity_policy.get("activePeersEpoch") != scarcity_policy.get("reputationEpoch"):
    raise SystemExit("scarcity policy fixture must carry explicit active peer epoch")
if scarcity_policy.get("observationCostVerification") != "required":
    raise SystemExit("scarcity policy fixture must require verified cost commitments")
if scarcity_policy.get("verifierId") != statement["verifierId"]:
    raise SystemExit("scarcity policy verifier must bind the cost commitment verifier")
if scarcity_policy.get("policySha256") != statement.get("scarcityPolicySha256"):
    raise SystemExit("scarcity policy hash must bind the cost commitment statement")
if scarcity_policy.get("runtimePolicySha256") != statement.get("runtimePolicySha256"):
    raise SystemExit("runtime policy hash must bind the cost commitment statement")
if concentration.get("schema") != "chio.pheromone-concentration.v1":
    raise SystemExit("concentration fixture has wrong schema")
case_ids = {case.get("id") for case in negative.get("cases", [])}
for required in {
    "workflow-receipt-hash-mismatch",
    "dsse-hash-mismatch",
    "missing-cost-commitment",
    "stale-transit-policy",
}:
    if required not in case_ids:
        raise SystemExit(f"negative corpus missing {required}")

print("OK Chio pheromone transit metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/deposit.schema.json" "$DEPOSIT_FIXTURE"
validate_schema "$SCHEMA_DIR/batch.schema.json" "$BATCH_FIXTURE"
validate_schema "$SCHEMA_DIR/transit-policy.schema.json" "$POLICY_FIXTURE"
validate_schema "$SCHEMA_DIR/concentration.schema.json" "$CONCENTRATION_FIXTURE"
validate_schema "$SCHEMA_DIR/negative-fixture-corpus.schema.json" "$NEGATIVE_FIXTURE"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

cargo test -p chio-pheromone
cargo test -p chio-federation pheromone

if [[ "$MODE" == "negative-only" ]]; then
  exit 0
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cargo run -p chio-three-vendor-example --bin generate-chio-three-vendor-fixtures -- \
  --pheromone-out-dir "$tmpdir/pheromone"

for filename in deposit.json gossip-batch.json transit-policy.json concentration.json negative-cases.json; do
  cmp "$FIXTURE_DIR/$filename" "$tmpdir/pheromone/$filename"
done
