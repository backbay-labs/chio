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
    echo "usage: check-chiodos-pheromone-relay-ops.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chiodos-pheromone-relay-ops.sh [--schema-only|--negative-only]" >&2
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
    "chio.pheromone.peer-directory-bundle.v1": "peer-directory-bundle.schema.json",
    "chio.pheromone.relay-health-report.v1": "relay-health-report.schema.json",
}
for schema_id, filename in expected.items():
    path = schema_dir / filename
    if not path.is_file():
        raise SystemExit(f"missing schema {filename}")
    schema = json.loads(path.read_text(encoding="utf-8"))
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        raise SystemExit(f"schema {filename} is not a strict object schema")
    want = f"spec/schemas/chio-pheromone/v1/{filename}"
    if registered.get(schema_id) != want:
        raise SystemExit(f"schema {schema_id} is not registered at {want}")

negative = json.loads((fixture_dir / "negative-cases.json").read_text(encoding="utf-8"))
codes = {case.get("expectedFailureCode") for case in negative.get("cases", [])}
required = {
    "peer_directory_stale",
    "peer_directory_rollback",
    "peer_directory_unsigned",
    "endpoint_denied",
    "sender_mismatch",
    "recipient_mismatch",
    "relay_request_stale",
    "relay_nonce_replay",
    "catchup_denied",
}
missing = sorted(required - codes)
if missing:
    raise SystemExit(f"relay ops negative corpus missing codes: {missing}")
print("OK Chiodos pheromone relay ops metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/peer-directory.schema.json" "$FIXTURE_DIR/peer-directory.json"
validate_schema "$SCHEMA_DIR/relay-operator-report.schema.json" "$FIXTURE_DIR/operator-report.json"
validate_schema "$SCHEMA_DIR/relay-health-report.schema.json" "$FIXTURE_DIR/health-report.json"
validate_schema "$SCHEMA_DIR/relay-tick-report.schema.json" "$FIXTURE_DIR/tick-report.json"
validate_schema "$SCHEMA_DIR/relay-negative-fixture-corpus.schema.json" "$FIXTURE_DIR/negative-cases.json"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

python3 - "$tmpdir/relay-signing-key.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "kernelId": "did:chio:dataco",
    "seedHex": "01" * 32,
}, indent=2) + "\n", encoding="utf-8")
PY

cargo run -p chio-cli --bin chio -- chiodos pheromone relay lint \
  --peer-directory "$FIXTURE_DIR/peer-directory.json" \
  --profile local-dev \
  --report "$tmpdir/lint.json"
validate_schema "$SCHEMA_DIR/relay-health-report.schema.json" "$tmpdir/lint.json"

cargo run -p chio-cli --bin chio -- chiodos pheromone relay lint \
  --peer-directory "$FIXTURE_DIR/peer-directory.json" \
  --profile production \
  --report "$tmpdir/lint-production.json"
validate_schema "$SCHEMA_DIR/relay-health-report.schema.json" "$tmpdir/lint-production.json"
python3 - "$tmpdir/lint-production.json" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if report.get("accepted") is not False or report.get("code") != "peer_directory_unsigned":
    raise SystemExit("production lint did not reject unsigned peer directory")
PY

cargo test -p chio-pheromone-relay signed_peer_directory_bundle_verifies_trust_and_rejects_rollback
cargo test -p chio-pheromone-relay relay_profiles_reject_unsafe_production_endpoints
cargo test -p chio-pheromone-relay relay_tick_delivers_leased_batches_with_real_request_signature
cargo test -p chio-cli --bin chio chiodos_pheromone

cargo run -p chio-cli --bin chio -- chiodos pheromone relay tick \
  --store "$tmpdir/relay.sqlite3" \
  --peer-directory "$FIXTURE_DIR/peer-directory.json" \
  --now-unix-ms 1766000000500 \
  --max-batches 4 \
  --signing-key "$tmpdir/relay-signing-key.json" \
  --report "$tmpdir/tick.json"
validate_schema "$SCHEMA_DIR/relay-tick-report.schema.json" "$tmpdir/tick.json"

if [[ "$MODE" == "negative-only" ]]; then
  cargo test -p chio-pheromone-relay signed_relay_request_verifies_payload_hash_sender_and_replay_nonce
  exit 0
fi

bash "$ROOT/scripts/check-chiodos-pheromone-relay.sh" --schema-only
