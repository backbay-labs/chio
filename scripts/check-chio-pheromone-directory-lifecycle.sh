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
    echo "usage: check-chio-pheromone-directory-lifecycle.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-pheromone-directory-lifecycle.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

SCHEMA_DIR="$ROOT/spec/schemas/chio-pheromone/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"
FIXTURE_DIR="$ROOT/examples/chio-3vendor/fixtures/pheromone/relay"

if rg -n "Chio|CHIO|chio" "$FIXTURE_DIR"; then
  echo "active Chio pheromone relay fixtures must not cite Chio-named docs or labels" >&2
  exit 1
fi

python3 - "$SCHEMA_DIR" "$SCHEMA_REGISTRY" "$FIXTURE_DIR" <<'PY'
import json
import pathlib
import sys

schema_dir, registry_path, fixture_dir = map(pathlib.Path, sys.argv[1:])
registry = json.loads(registry_path.read_text(encoding="utf-8"))
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
expected = {
    "chio.pheromone.peer-directory-state.v1": "peer-directory-state.schema.json",
    "chio.pheromone.peer-directory-rotation-report.v1": "peer-directory-rotation-report.schema.json",
    "chio.pheromone.relay-supervisor-profile.v1": "relay-supervisor-profile.schema.json",
    "chio.pheromone.relay-drill-report.v1": "relay-drill-report.schema.json",
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

state = json.loads((fixture_dir / "peer-directory-state.json").read_text(encoding="utf-8"))
active = state.get("active") or {}
if active.get("version") != 2:
    raise SystemExit("peer-directory state fixture is not at version 2")
if "did:chio:buyer-kernel" not in active.get("removedPeerIds", []):
    raise SystemExit("peer-directory state fixture does not quarantine the removed buyer peer")

negative = json.loads((fixture_dir / "negative-cases.json").read_text(encoding="utf-8"))
codes = {case.get("expectedFailureCode") for case in negative.get("cases", [])}
required = {
    "peer_directory_state_invalid",
    "peer_directory_rollback",
    "peer_removed",
    "supervisor_profile_invalid",
}
missing = sorted(required - codes)
if missing:
    raise SystemExit(f"directory lifecycle negative corpus missing codes: {missing}")
print("OK Chio pheromone directory lifecycle metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/peer-directory.schema.json" "$FIXTURE_DIR/peer-directory.json"
validate_schema "$SCHEMA_DIR/peer-directory-bundle.schema.json" "$FIXTURE_DIR/peer-directory-bundle.json"
validate_schema "$SCHEMA_DIR/peer-directory-bundle.schema.json" "$FIXTURE_DIR/peer-directory-candidate.json"
validate_schema "$SCHEMA_DIR/peer-directory-state.schema.json" "$FIXTURE_DIR/peer-directory-state.json"
validate_schema "$SCHEMA_DIR/peer-directory-rotation-report.schema.json" "$FIXTURE_DIR/peer-directory-rotation-report.json"
validate_schema "$SCHEMA_DIR/relay-supervisor-profile.schema.json" "$FIXTURE_DIR/relay-supervisor-profile.json"
validate_schema "$SCHEMA_DIR/relay-drill-report.schema.json" "$FIXTURE_DIR/relay-drill-report.json"
validate_schema "$SCHEMA_DIR/relay-negative-fixture-corpus.schema.json" "$FIXTURE_DIR/negative-cases.json"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cargo test -p chio-pheromone-relay directory
cargo test -p chio-cli --bin chio chio_pheromone

cargo run -p chio-cli --bin chio -- pheromone relay directory inspect \
  --state "$FIXTURE_DIR/peer-directory-state.json" \
  --report "$tmpdir/inspect-report.json"
validate_schema "$SCHEMA_DIR/peer-directory-rotation-report.schema.json" "$tmpdir/inspect-report.json"

cargo run -p chio-cli --bin chio -- pheromone relay directory promote \
  --state "$tmpdir/peer-directory-state.json" \
  --candidate "$FIXTURE_DIR/peer-directory-bundle.json" \
  --trusted-issuers "$FIXTURE_DIR/trusted-peer-directory-issuers.json" \
  --profile production \
  --now-unix-ms 1766000000500 \
  --report "$tmpdir/first-rotation-report.json"
validate_schema "$SCHEMA_DIR/peer-directory-state.schema.json" "$tmpdir/peer-directory-state.json"
validate_schema "$SCHEMA_DIR/peer-directory-rotation-report.schema.json" "$tmpdir/first-rotation-report.json"

python3 - "$FIXTURE_DIR/peer-directory-candidate.json" "$tmpdir/bad-candidate.json" <<'PY'
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
candidate = json.loads(source.read_text(encoding="utf-8"))
candidate["body"]["previousVersionSha256"] = "d" * 64
target.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
PY

if cargo run -p chio-cli --bin chio -- pheromone relay directory promote \
  --state "$tmpdir/peer-directory-state.json" \
  --candidate "$tmpdir/bad-candidate.json" \
  --trusted-issuers "$FIXTURE_DIR/trusted-peer-directory-issuers.json" \
  --profile production \
  --now-unix-ms 1766000000500 \
  --report "$tmpdir/rejected-rotation-report.json"; then
  echo "bad peer-directory candidate unexpectedly promoted" >&2
  exit 1
fi
validate_schema "$SCHEMA_DIR/peer-directory-state.schema.json" "$tmpdir/peer-directory-state.json"
validate_schema "$SCHEMA_DIR/peer-directory-rotation-report.schema.json" "$tmpdir/rejected-rotation-report.json"
python3 - "$tmpdir/rejected-rotation-report.json" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if report.get("accepted") is not False or report.get("code") != "peer_directory_rollback":
    raise SystemExit("bad candidate did not fail with peer_directory_rollback")
PY

cargo run -p chio-cli --bin chio -- pheromone relay directory promote \
  --state "$tmpdir/peer-directory-state.json" \
  --candidate "$FIXTURE_DIR/peer-directory-candidate.json" \
  --trusted-issuers "$FIXTURE_DIR/trusted-peer-directory-issuers.json" \
  --profile production \
  --now-unix-ms 1766000000500 \
  --report "$tmpdir/second-rotation-report.json"
validate_schema "$SCHEMA_DIR/peer-directory-state.schema.json" "$tmpdir/peer-directory-state.json"
validate_schema "$SCHEMA_DIR/peer-directory-rotation-report.schema.json" "$tmpdir/second-rotation-report.json"

python3 - "$tmpdir/peer-directory-state.json" "$tmpdir/second-rotation-report.json" <<'PY'
import json
import pathlib
import sys

state = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
report = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
if state["versionFloor"] != 2 or state["active"]["version"] != 2:
    raise SystemExit("promoted state did not advance to version 2")
if report.get("accepted") is not True or report.get("promotedVersion") != 2:
    raise SystemExit("second promotion report was not accepted")
if "did:chio:buyer-kernel" not in state["active"].get("removedPeerIds", []):
    raise SystemExit("removed peer was not quarantined")
PY

cargo run -p chio-cli --bin chio -- pheromone relay lint \
  --peer-directory-state "$tmpdir/peer-directory-state.json" \
  --profile production \
  --trusted-issuers "$FIXTURE_DIR/trusted-peer-directory-issuers.json" \
  --report "$tmpdir/lint-state.json"
validate_schema "$SCHEMA_DIR/relay-health-report.schema.json" "$tmpdir/lint-state.json"

cargo run -p chio-cli --bin chio -- pheromone relay supervisor lint \
  --profile "$FIXTURE_DIR/relay-supervisor-profile.json" \
  --report "$tmpdir/supervisor-report.json"
validate_schema "$SCHEMA_DIR/relay-drill-report.schema.json" "$tmpdir/supervisor-report.json"

if cargo run -p chio-cli --bin chio -- pheromone relay catchup \
  --store "$tmpdir/relay.sqlite3" \
  --peer did:chio:buyer-kernel \
  --peer-directory-state "$tmpdir/peer-directory-state.json" \
  --profile production \
  --trusted-issuers "$FIXTURE_DIR/trusted-peer-directory-issuers.json" \
  --now-unix-ms 1766000000500 \
  --treaty treaty:buyer-dataco:support-ops \
  --after-cursor start \
  --limit 1 \
  --report "$tmpdir/removed-peer-catchup.json"; then
  echo "removed peer catch-up unexpectedly succeeded" >&2
  exit 1
fi

if [[ "$MODE" == "negative-only" ]]; then
  exit 0
fi

bash "$ROOT/scripts/check-chio-pheromone-relay-ops.sh" --schema-only
