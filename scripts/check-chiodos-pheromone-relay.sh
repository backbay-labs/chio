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
    echo "usage: check-chiodos-pheromone-relay.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chiodos-pheromone-relay.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

SCHEMA_DIR="$ROOT/spec/schemas/chio-pheromone/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"
FIXTURE_DIR="$ROOT/examples/chiodos-3vendor/fixtures/pheromone/relay"

python3 - "$SCHEMA_DIR" "$SCHEMA_REGISTRY" "$FIXTURE_DIR" <<'PY'
import json
import pathlib
import sys

schema_dir, registry_path, fixture_dir = map(pathlib.Path, sys.argv[1:])
registry = json.loads(registry_path.read_text(encoding="utf-8"))
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
expected = {
    "chio.pheromone.peer-directory.v1": "peer-directory.schema.json",
    "chio.pheromone.relay-config.v1": "relay-config.schema.json",
    "chio.pheromone.relay-http-request.v1": "relay-http-request.schema.json",
    "chio.pheromone.relay-tick-report.v1": "relay-tick-report.schema.json",
    "chio.pheromone.relay-operator-report.v1": "relay-operator-report.schema.json",
    "chio.pheromone.catchup-request.v1": "catchup-request.schema.json",
    "chio.pheromone.catchup-response.v1": "catchup-response.schema.json",
    "chio.pheromone.relay-negative-fixture-corpus.v1": "relay-negative-fixture-corpus.schema.json",
}
for schema_id, filename in expected.items():
    path = schema_dir / filename
    if not path.is_file():
        raise SystemExit(f"missing schema {filename}")
    schema = json.loads(path.read_text(encoding="utf-8"))
    if schema.get("type") != "object" or "$id" not in schema:
        raise SystemExit(f"schema {filename} is not a frozen object schema")
    want = f"spec/schemas/chio-pheromone/v1/{filename}"
    if registered.get(schema_id) != want:
        raise SystemExit(f"schema {schema_id} is not registered at {want}")

peer_directory = json.loads((fixture_dir / "peer-directory.json").read_text(encoding="utf-8"))
if peer_directory.get("localKernelId") != "did:chio:dataco":
    raise SystemExit("relay peer directory local kernel is not verifier-owned dataco")
if peer_directory.get("schema") != "chio.pheromone.peer-directory.v1":
    raise SystemExit("relay peer directory schema mismatch")
if not peer_directory.get("peers"):
    raise SystemExit("relay peer directory has no pinned peers")

negative = json.loads((fixture_dir / "negative-cases.json").read_text(encoding="utf-8"))
codes = {case.get("expectedFailureCode") for case in negative.get("cases", [])}
required = {"unknown_peer", "body_hash_mismatch", "relay_nonce_replay", "endpoint_denied"}
missing = sorted(required - codes)
if missing:
    raise SystemExit(f"relay negative corpus missing codes: {missing}")
print("OK Chiodos pheromone relay metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/peer-directory.schema.json" "$FIXTURE_DIR/peer-directory.json"
validate_schema "$SCHEMA_DIR/relay-operator-report.schema.json" "$FIXTURE_DIR/operator-report.json"
validate_schema "$SCHEMA_DIR/relay-tick-report.schema.json" "$FIXTURE_DIR/tick-report.json"
validate_schema "$SCHEMA_DIR/catchup-request.schema.json" "$FIXTURE_DIR/catchup-request.json"
validate_schema "$SCHEMA_DIR/catchup-response.schema.json" "$FIXTURE_DIR/catchup-response.json"
validate_schema "$SCHEMA_DIR/relay-negative-fixture-corpus.schema.json" "$FIXTURE_DIR/negative-cases.json"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

cargo test -p chio-pheromone-relay
cargo test -p chio-cli chiodos_pheromone

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cargo run -p chio-cli --bin chio -- chiodos pheromone relay status \
  --store "$tmpdir/relay.sqlite3" \
  --report "$tmpdir/status.json"

validate_schema "$SCHEMA_DIR/relay-operator-report.schema.json" "$tmpdir/status.json"

cargo run -p chio-cli --bin chio -- chiodos pheromone relay tick \
  --store "$tmpdir/relay.sqlite3" \
  --peer-directory "$FIXTURE_DIR/peer-directory.json" \
  --now-unix-ms 1766000000500 \
  --max-batches 4 \
  --report "$tmpdir/tick.json"

validate_schema "$SCHEMA_DIR/relay-tick-report.schema.json" "$tmpdir/tick.json"

if [[ "$MODE" == "negative-only" ]]; then
  cargo test -p chio-pheromone-relay signed_relay_request_verifies_payload_hash_sender_and_replay_nonce
  exit 0
fi

bash "$ROOT/scripts/check-chiodos-pheromone-runtime.sh"
