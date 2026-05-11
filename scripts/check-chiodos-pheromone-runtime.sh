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
    echo "usage: check-chiodos-pheromone-runtime.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chiodos-pheromone-runtime.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

SCHEMA_DIR="$ROOT/spec/schemas/chio-pheromone/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"
FIXTURE_DIR="$ROOT/examples/chiodos-3vendor/fixtures/pheromone"
PACKAGE_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/buyer-auditor-proof-package.json"
TRUST_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/verifier-trust-bundle.json"
CONTEXT_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/verification-context.json"

python3 - "$SCHEMA_DIR" "$SCHEMA_REGISTRY" "$FIXTURE_DIR" <<'PY'
import json
import pathlib
import sys

schema_dir, registry_path, fixture_dir = map(pathlib.Path, sys.argv[1:])
registry = json.loads(registry_path.read_text(encoding="utf-8"))
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
expected = {
    "chio.pheromone.receive-report.v1": "receive-report.schema.json",
    "chio.pheromone.query-report.v1": "query-report.schema.json",
    "chio.pheromone.peer-weights.v1": "peer-weights.schema.json",
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

policy = json.loads((fixture_dir / "transit-policy.json").read_text(encoding="utf-8"))
receive = json.loads((fixture_dir / "receive-report.json").read_text(encoding="utf-8"))
query = json.loads((fixture_dir / "query-report.json").read_text(encoding="utf-8"))
weights = json.loads((fixture_dir / "peer-weights.json").read_text(encoding="utf-8"))

admission = policy.get("admission", {})
if admission.get("recipientKernelId") != "did:chio:dataco":
    raise SystemExit("runtime policy recipient is not verifier-owned")
if admission.get("authenticatedSenderKernelId") != "did:chio:buyer-kernel":
    raise SystemExit("runtime policy authenticated sender is not verifier-owned")
if not admission.get("passports"):
    raise SystemExit("runtime policy must carry admitted passport material")
if receive.get("schema") != "chio.pheromone.receive-report.v1" or not receive.get("accepted"):
    raise SystemExit("committed receive report must be accepted")
if query.get("schema") != "chio.pheromone.query-report.v1" or not query.get("accepted"):
    raise SystemExit("committed query report must be accepted")
if weights.get("schema") != "chio.pheromone.peer-weights.v1":
    raise SystemExit("peer weights fixture has wrong schema")
print("OK Chiodos pheromone runtime metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/transit-policy.schema.json" "$FIXTURE_DIR/transit-policy.json"
validate_schema "$SCHEMA_DIR/receive-report.schema.json" "$FIXTURE_DIR/receive-report.json"
validate_schema "$SCHEMA_DIR/query-report.schema.json" "$FIXTURE_DIR/query-report.json"
validate_schema "$SCHEMA_DIR/peer-weights.schema.json" "$FIXTURE_DIR/peer-weights.json"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

cargo test -p chio-pheromone-runtime
cargo test -p chio-cli chiodos_pheromone

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cargo run -p chiodos-three-vendor-example --bin generate-chiodos-proof-package -- \
  --pheromone-out-dir "$tmpdir/pheromone"

for filename in deposit.json gossip-batch.json transit-policy.json concentration.json negative-cases.json receive-report.json query-report.json peer-weights.json; do
  cmp "$FIXTURE_DIR/$filename" "$tmpdir/pheromone/$filename"
done

run_receive() {
  cargo run -p chio-cli --bin chio -- chiodos pheromone receive \
    --batch "$1" \
    --transit-policy "$FIXTURE_DIR/transit-policy.json" \
    --proof-package "$PACKAGE_FIXTURE" \
    --trust-bundle "$TRUST_FIXTURE" \
    --context "$CONTEXT_FIXTURE" \
    --store "$2" \
    --report "$3"
}

store="$tmpdir/runtime.sqlite3"
run_receive "$FIXTURE_DIR/gossip-batch.json" "$store" "$tmpdir/receive-report.json"
python3 - "$tmpdir/receive-report.json" <<'PY'
import json
import sys
report = json.loads(open(sys.argv[1], encoding="utf-8").read())
if not report.get("accepted"):
    raise SystemExit("CLI receive did not accept the fixture")
PY

cargo run -p chio-cli --bin chio -- chiodos pheromone query \
  --store "$store" \
  --subject-class support.prompt_injection \
  --namespace dev.chio.support \
  --reputation-epoch 42 \
  --peer-weights "$FIXTURE_DIR/peer-weights.json" \
  --report "$tmpdir/query-report.json"
python3 - "$tmpdir/query-report.json" <<'PY'
import json
import sys
report = json.loads(open(sys.argv[1], encoding="utf-8").read())
if not report.get("accepted"):
    raise SystemExit("CLI query did not accept the stored fixture")
PY

set +e
run_receive "$FIXTURE_DIR/gossip-batch.json" "$store" "$tmpdir/replay-report.json" >/tmp/chiodos-pheromone-replay.out 2>/tmp/chiodos-pheromone-replay.err
status=$?
set -e
if [[ "$status" -eq 0 ]]; then
  echo "replayed nonce was accepted" >&2
  exit 1
fi
python3 - "$tmpdir/replay-report.json" <<'PY'
import json
import sys
report = json.loads(open(sys.argv[1], encoding="utf-8").read())
codes = {frame.get("code") for frame in report.get("frames", [])}
if "replay_window_exceeded" not in codes:
    raise SystemExit(f"replay report missing replay_window_exceeded: {codes}")
PY

python3 - "$FIXTURE_DIR/gossip-batch.json" "$tmpdir/wrong-recipient-batch.json" <<'PY'
import json
import sys
src, dst = sys.argv[1:]
batch = json.loads(open(src, encoding="utf-8").read())
batch["recipient_kernel_id"] = "did:chio:wrong-recipient"
open(dst, "w", encoding="utf-8").write(json.dumps(batch, indent=2) + "\n")
PY

set +e
run_receive "$tmpdir/wrong-recipient-batch.json" "$tmpdir/wrong-recipient.sqlite3" "$tmpdir/wrong-recipient-report.json" >/tmp/chiodos-pheromone-recipient.out 2>/tmp/chiodos-pheromone-recipient.err
status=$?
set -e
if [[ "$status" -eq 0 ]]; then
  echo "wrong recipient batch was accepted" >&2
  exit 1
fi
python3 - "$tmpdir/wrong-recipient-report.json" <<'PY'
import json
import sys
report = json.loads(open(sys.argv[1], encoding="utf-8").read())
codes = {frame.get("code") for frame in report.get("frames", [])}
if "batch_recipient_mismatch" not in codes:
    raise SystemExit(f"wrong recipient report missing batch_recipient_mismatch: {codes}")
PY

if [[ "$MODE" == "negative-only" ]]; then
  exit 0
fi

bash "$ROOT/scripts/check-chiodos-pheromone-transit.sh"
