#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
    echo "usage: check-chiodos-pheromone-transit.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chiodos-pheromone-transit.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

SCHEMA_DIR="$ROOT/spec/schemas/chio-pheromone/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"
FIXTURE_DIR="$ROOT/examples/chiodos-3vendor/fixtures/pheromone"

DEPOSIT_FIXTURE="$FIXTURE_DIR/deposit.json"
BATCH_FIXTURE="$FIXTURE_DIR/gossip-batch.json"
POLICY_FIXTURE="$FIXTURE_DIR/transit-policy.json"
CONCENTRATION_FIXTURE="$FIXTURE_DIR/concentration.json"
NEGATIVE_FIXTURE="$FIXTURE_DIR/negative-cases.json"

python3 - "$SCHEMA_DIR" "$SCHEMA_REGISTRY" "$FIXTURE_DIR" <<'PY'
import json
import pathlib
import sys

schema_dir, registry_path, fixture_dir = map(pathlib.Path, sys.argv[1:])
registry = json.loads(registry_path.read_text(encoding="utf-8"))
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
expected = {
    "deposit.schema.json": "chio.pheromone-deposit.v1",
    "cost-commitment.schema.json": "chio.pheromone-cost-commitment.v1",
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
    want = f"spec/schemas/chio-pheromone/v1/{filename}"
    if registered.get(schema_id) != want:
        raise SystemExit(f"schema {schema_id} is not registered at {want}")

deposit = json.loads((fixture_dir / "deposit.json").read_text(encoding="utf-8"))
batch = json.loads((fixture_dir / "gossip-batch.json").read_text(encoding="utf-8"))
policy = json.loads((fixture_dir / "transit-policy.json").read_text(encoding="utf-8"))
concentration = json.loads((fixture_dir / "concentration.json").read_text(encoding="utf-8"))
negative = json.loads((fixture_dir / "negative-cases.json").read_text(encoding="utf-8"))

if deposit.get("schema") != "chio.pheromone-deposit.v1":
    raise SystemExit("deposit fixture has wrong schema")
if "workflow_context" not in deposit:
    raise SystemExit("deposit fixture must bind workflow context")
if "cost_commitment" not in deposit:
    raise SystemExit("deposit fixture must carry observation cost commitment")
if deposit["workflow_context"].get("workflow_id") != "wf-chiodos-refund-001":
    raise SystemExit("deposit workflow context does not bind the reference workflow")
if batch.get("schema") != "chio.pheromone-batch.v1":
    raise SystemExit("batch fixture has wrong schema")
if len(batch.get("frames", [])) != 1:
    raise SystemExit("batch fixture must carry one relayed frame")
frame = batch["frames"][0]
if frame.get("treaty_id") in deposit.get("treaty_scope", []):
    raise SystemExit("fixture must exercise downstream treaty relay, not direct gossip")
chain = frame.get("transit_chain", {}).get("hops", [])
if len(chain) != 2:
    raise SystemExit("fixture must carry a two-hop transit chain")
if chain[0].get("treaty_id") not in deposit.get("treaty_scope", []):
    raise SystemExit("first transit hop must use the origin treaty")
if chain[-1].get("treaty_id") != frame.get("treaty_id"):
    raise SystemExit("last transit hop must match the frame treaty")
if policy.get("max_hops") != 2:
    raise SystemExit("transit policy must cap the fixture at two hops")
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

print("OK Chiodos pheromone transit metadata")
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

cargo run -p chiodos-three-vendor-example --bin generate-chiodos-proof-package -- \
  --pheromone-out-dir "$tmpdir/pheromone"

for filename in deposit.json gossip-batch.json transit-policy.json concentration.json negative-cases.json; do
  cmp "$FIXTURE_DIR/$filename" "$tmpdir/pheromone/$filename"
done

bash "$ROOT/scripts/check-chiodos-authority-issuance.sh"
