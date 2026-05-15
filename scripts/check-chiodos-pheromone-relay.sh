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

cargo run -p chio-cli --bin chio -- chiodos pheromone relay status \
  --store "$tmpdir/relay.sqlite3" \
  --report "$tmpdir/status.json"

validate_schema "$SCHEMA_DIR/relay-operator-report.schema.json" "$tmpdir/status.json"

cargo run -p chio-cli --bin chio -- chiodos pheromone relay tick \
  --store "$tmpdir/relay.sqlite3" \
  --peer-directory "$FIXTURE_DIR/peer-directory.json" \
  --now-unix-ms 1766000000500 \
  --max-batches 4 \
  --signing-key "$tmpdir/relay-signing-key.json" \
  --report "$tmpdir/tick.json"

validate_schema "$SCHEMA_DIR/relay-tick-report.schema.json" "$tmpdir/tick.json"

python3 - "$ROOT/examples/chiodos-3vendor/fixtures/pheromone/gossip-batch.json" "$tmpdir/auditor-catchup-batch.json" "$tmpdir/auditor-action-class-bad-batch.json" "$tmpdir/auditor-empty-batch.json" "$tmpdir/auditor-transit-policy.json" <<'PY'
import json
import pathlib
import sys

source_batch, batch_path, bad_batch_path, empty_batch_path, policy_path = map(pathlib.Path, sys.argv[1:])
batch = json.loads(source_batch.read_text(encoding="utf-8"))
batch["recipient_kernel_id"] = "did:chio:auditor-kernel"
batch["treaty_id"] = "treaty:auditor-dataco:support-ops"
batch["flushed_at_unix_ms"] = 1766000000500
frame = batch["frames"][0]
frame["gossiping_peer_kernel_id"] = "did:chio:dataco"
frame["treaty_id"] = batch["treaty_id"]
frame["ts_unix_ms"] = 1766000000500
frame["transit_chain"]["hops"].append({
    "from_kernel_id": "did:chio:dataco",
    "to_kernel_id": "did:chio:auditor-kernel",
    "treaty_id": "treaty:auditor-dataco:support-ops",
    "ladder_manifest_id": "ladder:auditor:review:v1",
    "ladder_manifest_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "ladder_manifest_expires_at_unix_ms": 1766000060500,
    "ladder_intersection_id": "intersection:dataco:auditor",
    "action_class_id": "whisker.pheromone_deposit",
    "emitted_at_unix_ms": 1766000000500,
})
batch_path.write_text(json.dumps(batch, indent=2) + "\n", encoding="utf-8")

bad_batch = json.loads(json.dumps(batch))
bad_batch["frames"][0]["transit_chain"]["hops"][-1]["action_class_id"] = "whisker.untrusted"
bad_batch_path.write_text(json.dumps(bad_batch, indent=2) + "\n", encoding="utf-8")

empty_batch = json.loads(json.dumps(batch))
empty_batch["frames"] = []
empty_batch_path.write_text(json.dumps(empty_batch, indent=2) + "\n", encoding="utf-8")

policy_path.write_text(json.dumps({
    "schema": "chio.pheromone-transit-policy.v1",
    "accepted_hubs": [
        "did:chio:buyer-kernel",
        "did:chio:dataco",
    ],
    "allowed_ingress_treaties": [
        "treaty:buyer-llamaworks:support-ops",
    ],
    "allowed_egress_treaties": [
        "treaty:auditor-dataco:support-ops",
    ],
    "allowed_subject_class_namespaces": [
        "dev.chio.support",
    ],
    "valid_from_unix_ms": 1765999940000,
    "valid_until_unix_ms": 1766000060000,
    "max_hops": 3,
    "required_action_class_id": "whisker.pheromone_deposit",
}, indent=2) + "\n", encoding="utf-8")
PY

cargo run -p chio-cli --bin chio -- chiodos pheromone relay enqueue \
  --store "$tmpdir/relay.sqlite3" \
  --batch "$tmpdir/auditor-catchup-batch.json" \
  --transit-policy "$tmpdir/auditor-transit-policy.json" \
  --peer-directory-state "$FIXTURE_DIR/peer-directory-state.json" \
  --trusted-issuers "$FIXTURE_DIR/trusted-peer-directory-issuers.json" \
  --now-unix-ms 1766000000500 \
  --report "$tmpdir/enqueue.json"

validate_schema "$SCHEMA_DIR/relay-operator-report.schema.json" "$tmpdir/enqueue.json"

python3 - "$tmpdir/enqueue.json" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if "pending=1" not in report.get("detail", ""):
    raise SystemExit(f"enqueue did not create a pending outbox row: {report}")
PY

if cargo run -p chio-cli --bin chio -- chiodos pheromone relay enqueue \
  --store "$tmpdir/relay.sqlite3" \
  --batch "$tmpdir/auditor-action-class-bad-batch.json" \
  --transit-policy "$tmpdir/auditor-transit-policy.json" \
  --peer-directory-state "$FIXTURE_DIR/peer-directory-state.json" \
  --trusted-issuers "$FIXTURE_DIR/trusted-peer-directory-issuers.json" \
  --now-unix-ms 1766000000500 \
  --report "$tmpdir/enqueue-bad-action-class.json" >/dev/null 2>&1; then
  echo "relay enqueue unexpectedly accepted an untrusted transit action class" >&2
  exit 1
fi

if cargo run -p chio-cli --bin chio -- chiodos pheromone relay enqueue \
  --store "$tmpdir/relay.sqlite3" \
  --batch "$tmpdir/auditor-empty-batch.json" \
  --transit-policy "$tmpdir/auditor-transit-policy.json" \
  --peer-directory-state "$FIXTURE_DIR/peer-directory-state.json" \
  --trusted-issuers "$FIXTURE_DIR/trusted-peer-directory-issuers.json" \
  --now-unix-ms 1766000000500 \
  --report "$tmpdir/enqueue-empty-batch.json" >/dev/null 2>&1; then
  echo "relay enqueue unexpectedly accepted an empty gossip batch" >&2
  exit 1
fi

if cargo run -p chio-cli --bin chio -- chiodos pheromone relay catchup \
  --store "$tmpdir/relay.sqlite3" \
  --peer did:chio:auditor-kernel \
  --treaty treaty:auditor-dataco:support-ops \
  --after-cursor 0 \
  --limit 16 \
  --report "$tmpdir/catchup-without-directory.json" >/dev/null 2>&1; then
  echo "relay catchup unexpectedly succeeded without peer-directory state" >&2
  exit 1
fi

if cargo run -p chio-cli --bin chio -- chiodos pheromone relay catchup \
  --store "$tmpdir/relay.sqlite3" \
  --peer did:chio:auditor-kernel \
  --peer-directory-state "$FIXTURE_DIR/peer-directory-state.json" \
  --trusted-issuers "$FIXTURE_DIR/trusted-peer-directory-issuers.json" \
  --now-unix-ms 1766000000500 \
  --treaty treaty:auditor-dataco:support-ops \
  --after-cursor 0 \
  --limit 17 \
  --report "$tmpdir/catchup-over-limit.json" >/dev/null 2>&1; then
  echo "relay catchup unexpectedly exceeded peer-directory frame bounds" >&2
  exit 1
fi

cargo run -p chio-cli --bin chio -- chiodos pheromone relay catchup \
  --store "$tmpdir/relay.sqlite3" \
  --peer did:chio:auditor-kernel \
  --peer-directory-state "$FIXTURE_DIR/peer-directory-state.json" \
  --trusted-issuers "$FIXTURE_DIR/trusted-peer-directory-issuers.json" \
  --now-unix-ms 1766000000500 \
  --treaty treaty:auditor-dataco:support-ops \
  --after-cursor 0 \
  --limit 16 \
  --report "$tmpdir/catchup.json"

validate_schema "$SCHEMA_DIR/catchup-response.schema.json" "$tmpdir/catchup.json"

python3 - "$tmpdir/catchup.json" <<'PY'
import json
import pathlib
import sys

response = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if len(response.get("frames", [])) != 1 or response.get("nextCursor") == "0":
    raise SystemExit(f"catchup did not return the queued frame: {response}")
PY

if [[ "$MODE" == "negative-only" ]]; then
  cargo test -p chio-pheromone-relay signed_relay_request_verifies_payload_hash_sender_and_replay_nonce
  exit 0
fi

bash "$ROOT/scripts/check-chiodos-pheromone-runtime.sh"
